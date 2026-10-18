//! Test driver: a "client" that runs a `CryptoMachine` against the fake
//! server through the same HTTP-shaped calls a real client makes (CR-18).
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde_json::Value;
use stoat_crypto::proto::api::{self, KeysCountResponse, ToDeviceFetchResponse};
use stoat_crypto::proto::{EncryptedEnvelope, MessagePayload};
use stoat_crypto::{
    ChannelEncryptionSettings, CryptoMachine, DecryptError, DecryptedMessage, IncomingEncryptedMessage,
    OutgoingRequest, StoreConfig, StoreKey, Timing, ToDeviceResult, Trust,
};
use stoat_crypto_fakeserver::{Auth, FakeServer, Server, StoredMessage};

/// Readable ULID-shaped ids: `ulid("A")` → `01KAAAA…`
pub fn ulid(tag: &str) -> String {
    let t = tag.to_ascii_uppercase();
    format!("01K{}", t.repeat(23 / t.len() + 1)).chars().take(26).collect()
}

/// Session (device) ids: `dev("A1")` → `01KDA1A1…`
pub fn dev(tag: &str) -> String {
    format!("01KD{}", tag.to_ascii_uppercase().repeat(22))
        .chars()
        .take(26)
        .collect()
}

pub fn server() -> Server {
    FakeServer::new().shared()
}

pub fn text(t: &str) -> MessagePayload {
    MessagePayload::text(t, "AAAAAAAAAAAAAAAAAAAAAA", 1_760_700_000_000)
}

/// Test policy (shortened delays)
pub fn fast() -> Timing {
    Timing::default()
}

pub struct Device {
    machine: Option<CryptoMachine>,
    pub auth: Auth,
    pub server: Server,
    store: StoreConfig,
    pub inbox_limit: usize,
    /// process the mailbox but "crash" before `ack` (S12)
    pub crash_before_ack: bool,
    /// accumulated results of every mailbox pass
    pub received: ToDeviceResult,
}

impl Device {
    pub async fn open(server: &Server, user: &str, device: &str, store: StoreConfig) -> Self {
        let mut d = Self::open_quiet(server, user, device, store).await;
        d.sync().await;
        d
    }

    /// Open without the first sync (nothing uploaded yet)
    pub async fn open_quiet(server: &Server, user: &str, device: &str, store: StoreConfig) -> Self {
        let auth = Auth::new(ulid(user), dev(device));
        let machine = CryptoMachine::open(&auth.user, &auth.device, store.clone())
            .await
            .unwrap();
        machine.set_timing(fast()).await;
        Self {
            machine: Some(machine),
            auth,
            server: server.clone(),
            store,
            inbox_limit: 100,
            crash_before_ack: false,
            received: ToDeviceResult::default(),
        }
    }

    /// In-memory store
    pub async fn login(server: &Server, user: &str, device: &str) -> Self {
        Self::open(server, user, device, StoreConfig::Memory).await
    }

    /// SQLite store in `dir`
    pub async fn login_sqlite(server: &Server, user: &str, device: &str, dir: &Path) -> Self {
        Self::open(server, user, device, sqlite(dir)).await
    }

    pub fn m(&self) -> &CryptoMachine {
        self.machine.as_ref().expect("machine open")
    }

    /// Close and reopen the machine from its store (crash/restart)
    pub async fn restart(&mut self) {
        drop(self.machine.take());
        let machine = CryptoMachine::open(&self.auth.user, &self.auth.device, self.store.clone())
            .await
            .unwrap();
        machine.set_timing(fast()).await;
        self.machine = Some(machine);
    }

    /// Mark `other` verified on this device (what SAS ends with, 3C)
    pub async fn trust(&self, other: &Device) {
        self.m()
            .set_device_trust(&other.auth.user, &other.auth.device, Trust::Verified)
            .await
            .unwrap();
    }

    /// Bodies of the successful requests of this device under `path_prefix`
    pub fn sent(&self, path_prefix: &str) -> Vec<Value> {
        let srv = self.server.lock().unwrap();
        srv.log
            .iter()
            .filter(|e| e.device == self.auth.device && e.path.starts_with(path_prefix) && e.status < 300)
            .filter_map(|e| e.request.clone())
            .collect()
    }

    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> stoat_crypto_fakeserver::Response {
        self.server.lock().unwrap().handle(&self.auth, method, path, body)
    }

    pub async fn execute(&self, r: &OutgoingRequest) {
        let body: Value = serde_json::from_str(&r.body).unwrap();
        let resp = self.call(r.method, &r.path, Some(&body));
        if resp.is_success() {
            self.m()
                .mark_request_sent(&r.id, r.kind, &resp.body.to_string())
                .await
                .unwrap();
        } else {
            self.m().mark_request_failed(&r.id, r.kind, resp.status).await.unwrap();
        }
    }

    /// Run `outgoing_requests` once; true if anything was sent
    pub async fn flush(&self) -> bool {
        let reqs = self.m().outgoing_requests().await.unwrap();
        for r in &reqs {
            self.execute(r).await;
        }
        !reqs.is_empty()
    }

    /// One pass over socket events, mailbox and key counts
    pub async fn receive(&mut self) -> bool {
        let changed = self.receive_ws().await;

        let inbox = self.call("GET", &api::paths::to_device_fetch(self.inbox_limit), None);
        let inbox: ToDeviceFetchResponse = serde_json::from_value(inbox.body).unwrap();
        let got = !inbox.messages.is_empty();
        if got {
            let r = self.m().receive_to_device(inbox.messages).await.unwrap();
            if !self.crash_before_ack {
                for ids in r.ack_ids.chunks(api::MAX_TO_DEVICE_ACK) {
                    let body = serde_json::json!({ "ids": ids });
                    assert_eq!(self.call("POST", api::paths::TO_DEVICE_ACK, Some(&body)).status, 204);
                    self.m().mark_ack_sent(ids).await.unwrap();
                }
            }
            self.received.ack_ids.extend(r.ack_ids);
            self.received.room_keys.extend(r.room_keys);
            self.received.processed += r.processed;
            self.received.skipped_duplicates += r.skipped_duplicates;
            self.received.undecryptable += r.undecryptable;
        }

        let counts = self.call("GET", api::paths::KEYS_COUNT, None);
        let counts: KeysCountResponse = serde_json::from_value(counts.body).unwrap();
        self.m().receive_otk_counts(&counts).await.unwrap();
        got || !changed.is_empty()
    }

    /// Socket events only: device list updates (returns the users)
    pub async fn receive_ws(&mut self) -> Vec<String> {
        let ws = self.server.lock().unwrap().ws_take(&self.auth);
        let mut changed: Vec<String> = ws
            .iter()
            .filter(|e| e["type"] == "E2eeDeviceListUpdate")
            .filter_map(|e| e["user"].as_str().map(str::to_owned))
            .collect();
        changed.sort();
        changed.dedup();
        if !changed.is_empty() {
            self.m().receive_device_list_update(&changed).await.unwrap();
        }
        changed
    }

    /// Requests and mailbox until nothing moves
    pub async fn sync(&mut self) {
        for _ in 0..32 {
            let sent = self.flush().await;
            let received = self.receive().await;
            if self.crash_before_ack && received {
                return; // a crashed client stops here
            }
            if !sent && !received {
                return;
            }
        }
        panic!("sync does not converge");
    }

    pub async fn join(&self, channel: &str, members: &[&str]) {
        let members: Vec<String> = members.iter().map(|m| ulid(m)).collect();
        self.m()
            .set_channel_members(channel, &members, ChannelEncryptionSettings::default())
            .await
            .unwrap();
    }

    /// `prepare_send` until it has nothing left
    pub async fn prepare(&self, channel: &str) {
        for _ in 0..16 {
            let reqs = self.m().prepare_send(channel).await.unwrap();
            if reqs.is_empty() {
                return;
            }
            for r in &reqs {
                self.execute(r).await;
            }
        }
        panic!("prepare_send does not converge");
    }

    pub async fn encrypt(&self, channel: &str, payload: &MessagePayload) -> EncryptedEnvelope {
        self.prepare(channel).await;
        self.m().encrypt(channel, payload).await.unwrap()
    }

    /// Full send: prepare, encrypt, `POST /channels/<id>/messages`
    pub async fn send(&self, channel: &str, payload: &MessagePayload) -> String {
        let envelope = self.encrypt(channel, payload).await;
        self.server
            .lock()
            .unwrap()
            .message_send(&self.auth, channel, envelope.to_value(), payload.in_reply_to.clone())
            .unwrap()
    }

    pub async fn decrypt(&self, m: &StoredMessage) -> Result<DecryptedMessage, DecryptError> {
        let envelope = EncryptedEnvelope::from_value(&m.encrypted)?;
        self.m()
            .decrypt(&IncomingEncryptedMessage {
                message_id: m.id.clone(),
                channel_id: m.channel.clone(),
                author: m.author.clone(),
                envelope,
                replies: m.replies.clone(),
                timestamp: m.ts,
            })
            .await
    }

    pub async fn read(&self, m: &StoredMessage) -> String {
        let d = self
            .decrypt(m)
            .await
            .unwrap_or_else(|e| panic!("{} cannot read {}: {e:?}", self.auth.device, m.id));
        d.payload.content.unwrap_or_default()
    }
}

pub fn sqlite(dir: &Path) -> StoreConfig {
    StoreConfig::Sqlite {
        path: PathBuf::from(dir),
        key: StoreKey::new([7u8; 32]),
    }
}

/// Create a DM/group on the server and tell every device its members
pub async fn channel(server: &Server, name: &str, devices: &[&Device]) -> String {
    let id = ulid(name);
    let mut members: Vec<String> = devices.iter().map(|d| d.auth.user.clone()).collect();
    members.sort();
    members.dedup();
    let refs: Vec<&str> = members.iter().map(String::as_str).collect();
    server.lock().unwrap().channel_set_members(&id, &refs);
    for d in devices {
        d.m()
            .set_channel_members(&id, &members, ChannelEncryptionSettings::default())
            .await
            .unwrap();
    }
    id
}

pub fn messages(server: &Server, channel: &str) -> Vec<StoredMessage> {
    server.lock().unwrap().messages(channel)
}

pub fn last(server: &Server, channel: &str) -> StoredMessage {
    messages(server, channel).pop().unwrap()
}

pub async fn sync_all(devices: &mut [&mut Device]) {
    for _ in 0..3 {
        for d in devices.iter_mut() {
            d.sync().await;
        }
    }
}
