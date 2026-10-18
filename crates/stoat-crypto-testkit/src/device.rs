//! One virtual device: an account session + a `CryptoMachine` + its socket,
//! driven exactly by the host contract (`stoat_crypto` crate docs).
//!
//! The plain methods panic on any transport failure (scenarios on a healthy
//! stack); the `try_*` ones return it, after marking the request failed with
//! status 0 as a client does (chaos scenarios).

use std::path::PathBuf;
use std::time::Duration;

use rand::RngCore;
use serde_json::{Value, json};
use stoat_crypto::proto::api::{self, KeysCountResponse, ToDeviceFetchResponse, ToDeviceMessage};
use stoat_crypto::proto::{EncryptedEnvelope, MessagePayload, b64};
use stoat_crypto::{
    ChannelEncryptionSettings, CryptoError, CryptoMachine, DecryptError, DecryptedMessage, IncomingEncryptedMessage,
    OutgoingRequest, StoreConfig, StoreKey, Timing, ToDeviceResult,
};

use crate::account::Account;
use crate::http::{Http, HttpError};
use crate::ws::Socket;

/// Test policy: key requests at once, short retries of full mailboxes
pub fn timing() -> Timing {
    Timing {
        key_request_delay_ms: 0,
        to_device_retry_ms: 500,
        to_device_retry_attempts: 4,
        own_retry_ms: 500,
    }
}

/// Payload v1 of a text message with a fresh nonce
pub fn payload_text(text: &str) -> MessagePayload {
    MessagePayload::text(text, nonce(), now_ms())
}

fn nonce() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b64::encode(b)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// Milliseconds of a ULID
fn ulid_ms(id: &str) -> u64 {
    const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    id.chars()
        .take(10)
        .filter_map(|c| ALPHABET.find(c.to_ascii_uppercase()))
        .fold(0u64, |acc, d| acc * 32 + d as u64)
}

/// A store directory and its key, to reopen a device after a "crash"
#[derive(Clone, Debug)]
pub struct Persisted {
    pub dir: PathBuf,
    pub key: [u8; 32],
}

impl Persisted {
    /// A fresh directory under the system temp dir
    pub fn new() -> Self {
        let mut tag = [0u8; 8];
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut tag);
        rand::thread_rng().fill_bytes(&mut key);
        let dir = std::env::temp_dir().join(format!(
            "stoat-testkit-{}",
            tag.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        Self { dir, key }
    }

    fn config(&self) -> StoreConfig {
        StoreConfig::Sqlite {
            path: self.dir.clone(),
            key: StoreKey::new(self.key),
        }
    }
}

impl Default for Persisted {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Device {
    pub account: Account,
    pub machine: CryptoMachine,
    pub http: Http,
    socket: Option<Socket>,
    /// SQLite store of this device, if it can restart
    pub store: Option<Persisted>,
    /// Accumulated results of every mailbox pass
    pub received: ToDeviceResult,
    /// Errors `mark_request_failed` returned (MFA, backup replaced…)
    pub errors: Vec<CryptoError>,
    /// `Message` events of the socket (what an old client renders)
    pub message_events: Vec<Value>,
    /// Stop fetching the mailbox (a device that is offline)
    pub offline: bool,
}

impl Device {
    /// Machine in memory, socket connected, first request pass done
    pub async fn open(account: &Account) -> Self {
        Self::open_with(account, StoreConfig::Memory, None).await
    }

    /// Machine in a SQLite store that survives [`Device::restart`]
    pub async fn open_persistent(account: &Account) -> Self {
        let store = Persisted::new();
        Self::open_with(account, store.config(), Some(store)).await
    }

    async fn machine(account: &Account, store: StoreConfig) -> CryptoMachine {
        let machine = CryptoMachine::open(&account.user_id, &account.session_id, store)
            .await
            .unwrap_or_else(|e| panic!("open machine: {e}"));
        machine.set_server_limits(account.stack.limits).await;
        machine.set_timing(timing()).await;
        machine
    }

    async fn open_with(account: &Account, config: StoreConfig, store: Option<Persisted>) -> Self {
        let machine = Self::machine(account, config).await;
        let socket = Socket::connect(&account.stack.config.ws, &account.token).await;
        let mut d = Self {
            http: account.http(),
            account: account.clone(),
            machine,
            socket: Some(socket),
            store,
            received: ToDeviceResult::default(),
            errors: Vec::new(),
            message_events: Vec::new(),
            offline: false,
        };
        // contract 2: after Ready, always the mailbox and the key counts
        d.machine.receive_reconnect().await.unwrap_or_else(|e| panic!("{e}"));
        d.sync().await;
        d
    }

    /// Process killed and started again: the machine is dropped (its lock
    /// released) and reopened from the store; nothing is synced
    pub async fn restart(&mut self) {
        let store = self.store.clone().expect("a persistent device");
        self.socket = None;
        let placeholder = Self::machine(&self.account, StoreConfig::Memory).await;
        drop(std::mem::replace(&mut self.machine, placeholder));
        self.machine = Self::machine(&self.account, store.config()).await;
    }

    pub fn user(&self) -> &str {
        &self.account.user_id
    }

    pub fn device(&self) -> &str {
        &self.account.session_id
    }

    /// Run one request and mark it
    pub async fn execute(&mut self, r: &OutgoingRequest) -> Result<(), HttpError> {
        self.execute_with(r, None).await
    }

    /// A transport error is marked as status 0 and returned
    pub async fn execute_with(&mut self, r: &OutgoingRequest, mfa: Option<&str>) -> Result<(), HttpError> {
        let reply = match self.http.raw(r.method, &r.path, Some(&r.body), mfa).await {
            Ok(reply) => reply,
            Err(e) => {
                if let Err(e) = self.machine.mark_request_failed(&r.id, r.kind, 0).await {
                    self.errors.push(e);
                }
                return Err(e);
            }
        };
        if reply.ok() {
            self.machine
                .mark_request_sent(&r.id, r.kind, &reply.body)
                .await
                .unwrap_or_else(|e| panic!("mark {:?} sent: {e}", r.kind));
        } else if let Err(e) = self.machine.mark_request_failed(&r.id, r.kind, reply.status).await {
            self.errors.push(e);
        }
        Ok(())
    }

    /// One request pass; true if anything was sent
    pub async fn flush(&mut self) -> bool {
        self.try_flush().await.unwrap_or_else(|e| panic!("{e}"))
    }

    /// One request pass; every request is tried, the first transport error returned
    pub async fn try_flush(&mut self) -> Result<bool, HttpError> {
        let reqs = self
            .machine
            .outgoing_requests()
            .await
            .unwrap_or_else(|e| panic!("outgoing requests: {e}"));
        let mut first = None;
        for r in &reqs {
            if let Err(e) = self.execute(r).await {
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(!reqs.is_empty()), Err)
    }

    /// Socket events: device-list updates go to the machine, `Message`
    /// events are kept
    pub async fn receive_ws(&mut self) -> usize {
        let events = self.socket.as_ref().map(Socket::take).unwrap_or_default();
        let mut users: Vec<String> = events
            .iter()
            .filter(|e| e["type"] == "E2eeDeviceListUpdate")
            .filter_map(|e| e["user"].as_str().map(str::to_owned))
            .collect();
        users.sort();
        users.dedup();
        if !users.is_empty() {
            self.machine
                .receive_device_list_update(&users)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        }
        let e2ee = events.iter().filter(|e| e["type"] != "Message").count();
        self.message_events
            .extend(events.into_iter().filter(|e| e["type"] == "Message"));
        e2ee
    }

    /// One mailbox page, not processed
    pub async fn fetch_page(&self) -> Result<Vec<ToDeviceMessage>, HttpError> {
        let page: ToDeviceFetchResponse = serde_json::from_value(
            self.http
                .get(&api::paths::to_device_fetch(api::MAX_TO_DEVICE_FETCH))
                .await?,
        )
        .unwrap_or_else(|e| panic!("mailbox page: {e}"));
        Ok(page.messages)
    }

    /// Hand a page to the machine (in the given order) and, if `ack`,
    /// acknowledge what it committed
    pub async fn process(&mut self, page: Vec<ToDeviceMessage>, ack: bool) -> Result<ToDeviceResult, HttpError> {
        let r = self
            .machine
            .receive_to_device(page)
            .await
            .unwrap_or_else(|e| panic!("receive to-device: {e}"));
        if ack {
            for ids in r.ack_ids.chunks(api::MAX_TO_DEVICE_ACK) {
                self.http
                    .call("POST", api::paths::TO_DEVICE_ACK, Some(&json!({ "ids": ids })))
                    .await?;
                self.machine.mark_ack_sent(ids).await.unwrap_or_else(|e| panic!("{e}"));
            }
        }
        self.received.ack_ids.extend(r.ack_ids.iter().cloned());
        self.received.room_keys.extend(r.room_keys.iter().cloned());
        self.received.processed += r.processed;
        self.received.skipped_duplicates += r.skipped_duplicates;
        self.received.undecryptable += r.undecryptable;
        self.received.verifications.extend(r.verifications.iter().cloned());
        Ok(r)
    }

    /// Mailbox until a page is not full, then the key counts; true if
    /// anything arrived
    pub async fn receive(&mut self) -> bool {
        self.try_receive().await.unwrap_or_else(|e| panic!("{e}"))
    }

    pub async fn try_receive(&mut self) -> Result<bool, HttpError> {
        let events = self.receive_ws().await;
        if self.offline {
            return Ok(events > 0);
        }
        let mut got = false;
        loop {
            let page = self.fetch_page().await?;
            let n = page.len();
            if n == 0 {
                break;
            }
            got = true;
            self.process(page, true).await?;
            if n < api::MAX_TO_DEVICE_FETCH {
                break;
            }
        }
        let counts: KeysCountResponse = serde_json::from_value(self.http.get(api::paths::KEYS_COUNT).await?)
            .unwrap_or_else(|e| panic!("keys count: {e}"));
        self.machine
            .receive_otk_counts(&counts)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        Ok(got || events > 0)
    }

    /// Requests and mailbox until nothing moves
    pub async fn sync(&mut self) {
        self.try_sync().await.unwrap_or_else(|e| panic!("{e}"))
    }

    pub async fn try_sync(&mut self) -> Result<(), HttpError> {
        for _ in 0..32 {
            let sent = self.try_flush().await?;
            let received = self.try_receive().await?;
            if !sent && !received {
                return Ok(());
            }
        }
        panic!("sync of {} does not converge", self.device());
    }

    /// Full member list of a channel from the server → the machine
    pub async fn refresh_members(&mut self, channel: &str) {
        let members = self.account.members(channel).await.unwrap_or_else(|e| panic!("{e}"));
        self.set_members(channel, &members).await;
    }

    pub async fn set_members(&mut self, channel: &str, members: &[String]) {
        self.machine
            .set_channel_members(channel, members, ChannelEncryptionSettings::default())
            .await
            .unwrap_or_else(|e| panic!("set members: {e}"));
    }

    /// `prepare_send` until it has nothing left, then encrypt
    pub async fn encrypt(&mut self, channel: &str, payload: &MessagePayload) -> EncryptedEnvelope {
        self.try_encrypt(channel, payload)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
    }

    pub async fn try_encrypt(
        &mut self,
        channel: &str,
        payload: &MessagePayload,
    ) -> Result<EncryptedEnvelope, HttpError> {
        for _ in 0..16 {
            let reqs = self
                .machine
                .prepare_send(channel)
                .await
                .unwrap_or_else(|e| panic!("prepare send: {e}"));
            if reqs.is_empty() {
                return Ok(self
                    .machine
                    .encrypt(channel, payload)
                    .await
                    .unwrap_or_else(|e| panic!("encrypt: {e}")));
            }
            for r in &reqs {
                self.execute(r).await?;
            }
        }
        panic!("prepare_send does not converge");
    }

    /// Body of `POST /channels/{id}/messages` for an envelope
    pub fn send_body(payload: &MessagePayload, envelope: &EncryptedEnvelope) -> Value {
        json!({
            "nonce": payload.client_nonce,
            "encrypted": envelope.to_value(),
            "attachments": payload.file_ids(),
        })
    }

    /// Encrypt and `POST /channels/{id}/messages`; returns the message id
    pub async fn send(&mut self, channel: &str, payload: &MessagePayload) -> String {
        self.try_send(channel, payload)
            .await
            .unwrap_or_else(|e| panic!("send message: {e}"))
    }

    pub async fn try_send(&mut self, channel: &str, payload: &MessagePayload) -> Result<String, HttpError> {
        let envelope = self.try_encrypt(channel, payload).await?;
        let m = self
            .http
            .post(
                &format!("/channels/{channel}/messages"),
                &Self::send_body(payload, &envelope),
            )
            .await?;
        Ok(m["_id"].as_str().unwrap_or_default().to_owned())
    }

    pub async fn send_text(&mut self, channel: &str, text: &str) -> String {
        self.send(channel, &payload_text(text)).await
    }

    /// Encrypted messages of a channel as this device fetches them, oldest first
    pub async fn messages(&self, channel: &str) -> Vec<Value> {
        self.all_messages(channel)
            .await
            .into_iter()
            .filter(|m| m.get("encrypted").is_some())
            .collect()
    }

    /// Every message of a channel (system messages too), oldest first
    pub async fn all_messages(&self, channel: &str) -> Vec<Value> {
        let mut out: Vec<Value> = Vec::new();
        loop {
            let after = out
                .last()
                .and_then(|m| m["_id"].as_str())
                .map(|id| format!("&after={id}"))
                .unwrap_or_default();
            let page = self
                .http
                .get(&format!("/channels/{channel}/messages?limit=100&sort=Oldest{after}"))
                .await
                .unwrap_or_else(|e| panic!("fetch messages: {e}"));
            let page = page.as_array().cloned().unwrap_or_default();
            let n = page.len();
            out.extend(page);
            if n < 100 {
                return out;
            }
        }
    }

    pub fn incoming(m: &Value) -> Result<IncomingEncryptedMessage, DecryptError> {
        let id = m["_id"].as_str().unwrap_or_default().to_owned();
        Ok(IncomingEncryptedMessage {
            timestamp: ulid_ms(&id),
            message_id: id,
            channel_id: m["channel"].as_str().unwrap_or_default().to_owned(),
            author: m["author"].as_str().unwrap_or_default().to_owned(),
            envelope: EncryptedEnvelope::from_value(&m["encrypted"])?,
            replies: m["replies"]
                .as_array()
                .map(|r| r.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
                .unwrap_or_default(),
        })
    }

    pub async fn decrypt(&self, m: &Value) -> Result<DecryptedMessage, DecryptError> {
        self.machine.decrypt(&Self::incoming(m)?).await
    }

    /// Text of a message, or a panic naming why it does not decrypt
    pub async fn read(&self, m: &Value) -> String {
        let d = self
            .decrypt(m)
            .await
            .unwrap_or_else(|e| panic!("{} cannot read {}: {e:?}", self.device(), m["_id"]));
        d.payload.content.unwrap_or_default()
    }

    /// Texts of every encrypted message of the channel this device can read
    pub async fn read_all(&self, channel: &str) -> Vec<String> {
        let mut out = Vec::new();
        for m in self.messages(channel).await {
            if let Ok(d) = self.decrypt(&m).await {
                out.push(d.payload.content.unwrap_or_default());
            }
        }
        out
    }

    /// Close the socket (the machine stays usable)
    pub fn disconnect(&mut self) {
        self.socket = None;
    }

    /// The server closed the socket (bonfire restarted, network gone)
    pub fn socket_lost(&self) -> bool {
        self.socket.as_ref().is_none_or(Socket::is_closed)
    }

    /// New socket and the reconnect rule (contract 2: every tracked user
    /// dirty, then mailbox and key counts); an error while bonfire is away
    pub async fn reconnect(&mut self) -> Result<(), String> {
        self.socket = None;
        self.socket = Some(Socket::try_connect(&self.account.stack.config.ws, &self.account.token).await?);
        self.machine.receive_reconnect().await.map_err(|e| e.to_string())?;
        self.try_sync().await.map_err(|e| e.to_string())
    }

    /// `debug_report` (CR-22) as JSON
    pub async fn report(&self) -> Value {
        serde_json::from_str(
            &self
                .machine
                .debug_report()
                .await
                .unwrap_or_else(|e| panic!("report: {e}")),
        )
        .unwrap_or(Value::Null)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Some(s) = &self.store {
            let _ = std::fs::remove_dir_all(&s.dir);
        }
    }
}

/// Sync every device a few times with pauses for the socket events
pub async fn settle(devices: &mut [&mut Device]) {
    for _ in 0..3 {
        for d in devices.iter_mut() {
            d.sync().await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}
