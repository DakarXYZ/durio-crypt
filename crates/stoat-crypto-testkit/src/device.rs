//! One virtual device: an account session + a `CryptoMachine` + its socket,
//! driven exactly by the host contract (`stoat_crypto` crate docs).

use std::time::Duration;

use rand::RngCore;
use serde_json::{Value, json};
use stoat_crypto::proto::api::{self, KeysCountResponse, ToDeviceFetchResponse};
use stoat_crypto::proto::{EncryptedEnvelope, MessagePayload, b64};
use stoat_crypto::{
    ChannelEncryptionSettings, CryptoError, CryptoMachine, DecryptError, DecryptedMessage, IncomingEncryptedMessage,
    OutgoingRequest, StoreConfig, Timing, ToDeviceResult,
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

#[derive(Debug)]
pub struct Device {
    pub account: Account,
    pub machine: CryptoMachine,
    pub http: Http,
    socket: Option<Socket>,
    /// Accumulated results of every mailbox pass
    pub received: ToDeviceResult,
    /// Errors `mark_request_failed` returned (MFA, backup replaced…)
    pub errors: Vec<CryptoError>,
    /// Stop fetching the mailbox (a device that is offline)
    pub offline: bool,
}

impl Device {
    /// Machine in memory, socket connected, first request pass done
    pub async fn open(account: &Account) -> Self {
        Self::open_with(account, StoreConfig::Memory).await
    }

    pub async fn open_with(account: &Account, store: StoreConfig) -> Self {
        let machine = CryptoMachine::open(&account.user_id, &account.session_id, store)
            .await
            .unwrap_or_else(|e| panic!("open machine: {e}"));
        machine.set_server_limits(account.stack.limits).await;
        machine.set_timing(timing()).await;
        let socket = Socket::connect(&account.stack.config.ws, &account.token).await;
        let mut d = Self {
            http: account.http(),
            account: account.clone(),
            machine,
            socket: Some(socket),
            received: ToDeviceResult::default(),
            errors: Vec::new(),
            offline: false,
        };
        // contract 2: after Ready, always the mailbox and the key counts
        d.machine.receive_reconnect().await.unwrap_or_else(|e| panic!("{e}"));
        d.sync().await;
        d
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

    pub async fn execute_with(&mut self, r: &OutgoingRequest, mfa: Option<&str>) -> Result<(), HttpError> {
        let reply = self.http.raw(r.method, &r.path, Some(&r.body), mfa).await?;
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
        let reqs = self
            .machine
            .outgoing_requests()
            .await
            .unwrap_or_else(|e| panic!("outgoing requests: {e}"));
        for r in &reqs {
            self.execute(r).await.unwrap_or_else(|e| panic!("{e}"));
        }
        !reqs.is_empty()
    }

    /// Socket events: device-list updates go to the machine
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
        events.len()
    }

    /// Mailbox until a page is not full, then the key counts; true if
    /// anything arrived
    pub async fn receive(&mut self) -> bool {
        let events = self.receive_ws().await;
        if self.offline {
            return events > 0;
        }
        let mut got = false;
        loop {
            let page: ToDeviceFetchResponse = serde_json::from_value(
                self.http
                    .get(&api::paths::to_device_fetch(api::MAX_TO_DEVICE_FETCH))
                    .await
                    .unwrap_or_else(|e| panic!("{e}")),
            )
            .unwrap_or_else(|e| panic!("mailbox page: {e}"));
            let n = page.messages.len();
            if n == 0 {
                break;
            }
            got = true;
            let r = self
                .machine
                .receive_to_device(page.messages)
                .await
                .unwrap_or_else(|e| panic!("receive to-device: {e}"));
            for ids in r.ack_ids.chunks(api::MAX_TO_DEVICE_ACK) {
                self.http
                    .call("POST", api::paths::TO_DEVICE_ACK, Some(&json!({ "ids": ids })))
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
                self.machine.mark_ack_sent(ids).await.unwrap_or_else(|e| panic!("{e}"));
            }
            self.received.ack_ids.extend(r.ack_ids);
            self.received.room_keys.extend(r.room_keys);
            self.received.processed += r.processed;
            self.received.skipped_duplicates += r.skipped_duplicates;
            self.received.undecryptable += r.undecryptable;
            self.received.verifications.extend(r.verifications);
            if n < api::MAX_TO_DEVICE_FETCH {
                break;
            }
        }
        let counts: KeysCountResponse = serde_json::from_value(
            self.http
                .get(api::paths::KEYS_COUNT)
                .await
                .unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("keys count: {e}"));
        self.machine
            .receive_otk_counts(&counts)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        got || events > 0
    }

    /// Requests and mailbox until nothing moves
    pub async fn sync(&mut self) {
        for _ in 0..32 {
            let sent = self.flush().await;
            let received = self.receive().await;
            if !sent && !received {
                return;
            }
        }
        panic!("sync of {} does not converge", self.device());
    }

    /// Full member list of a channel from the server → the machine
    pub async fn refresh_members(&mut self, channel: &str) {
        let members = self.account.members(channel).await.unwrap_or_else(|e| panic!("{e}"));
        self.machine
            .set_channel_members(channel, &members, ChannelEncryptionSettings::default())
            .await
            .unwrap_or_else(|e| panic!("set members: {e}"));
    }

    /// `prepare_send` until it has nothing left, then encrypt
    pub async fn encrypt(&mut self, channel: &str, payload: &MessagePayload) -> EncryptedEnvelope {
        for _ in 0..16 {
            let reqs = self
                .machine
                .prepare_send(channel)
                .await
                .unwrap_or_else(|e| panic!("prepare send: {e}"));
            if reqs.is_empty() {
                return self
                    .machine
                    .encrypt(channel, payload)
                    .await
                    .unwrap_or_else(|e| panic!("encrypt: {e}"));
            }
            for r in &reqs {
                self.execute(r).await.unwrap_or_else(|e| panic!("{e}"));
            }
        }
        panic!("prepare_send does not converge");
    }

    /// Encrypt and `POST /channels/{id}/messages`; returns the message id
    pub async fn send(&mut self, channel: &str, payload: &MessagePayload) -> String {
        let envelope = self.encrypt(channel, payload).await;
        let body = json!({
            "nonce": payload.client_nonce,
            "encrypted": envelope.to_value(),
            "attachments": payload.file_ids(),
        });
        let m = self
            .http
            .post(&format!("/channels/{channel}/messages"), &body)
            .await
            .unwrap_or_else(|e| panic!("send message: {e}"));
        m["_id"].as_str().unwrap_or_default().to_owned()
    }

    pub async fn send_text(&mut self, channel: &str, text: &str) -> String {
        self.send(channel, &payload_text(text)).await
    }

    /// Encrypted messages of a channel as this device fetches them, oldest first
    pub async fn messages(&self, channel: &str) -> Vec<Value> {
        let page = self
            .http
            .get(&format!("/channels/{channel}/messages?limit=100&sort=Oldest"))
            .await
            .unwrap_or_else(|e| panic!("fetch messages: {e}"));
        page.as_array()
            .map(|a| a.iter().filter(|m| m.get("encrypted").is_some()).cloned().collect())
            .unwrap_or_default()
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
