//! In-memory fake of the dur.io `/e2ee/*` API, contract v1 (CR-18).
//!
//! Grown from the CR-01 spike fake and aligned with the real backend (branch
//! `durio/stage-2`, `crates/delta/src/routes/e2ee/`), including its deviations
//! from the plan text:
//!
//! * `keys/upload` and `keys/count` always answer `device_unused_fallback_key_types`;
//!   one-time or fallback keys of a device without device keys → 404; more than
//!   100 stored OTKs → 422; repeated device keys must be equal as JSON, else 409;
//!   at most one fallback key per upload;
//! * claim pops an OTK, else hands out the fallback key **again and again**
//!   (marking it used) until the client replaces it;
//! * `keys/query` answers every requested user, unknown and invisible ones with
//!   `{}`; only the canonical lowercase Matrix ids resolve;
//! * a device must belong to the user it is claimed or addressed under;
//! * `PUT /to_device/<txn>`: txn id `[A-Za-z0-9._-]{1,64}`, contents must be
//!   objects, explicitly addressed devices win over `*`, `*` skips the sending
//!   device, a retried `(sender device, txn, recipient)` is swallowed while the
//!   earlier copy is still in the mailbox, a full mailbox goes to `failed`;
//! * mailbox: `GET ?limit=1..=100` (default 100), `ack` takes 1..=100 ids → 204;
//! * limits (BE-21, BE-29): a body over `max_request_bytes` → 413 (Rocket's
//!   JSON limit), a `PUT /to_device` with more than `max_to_device_batch`
//!   messages (`*` counts as one) → 422 `PayloadTooLarge`;
//! * `E2eeToDevice` goes only to the recipient device, `sender` Matrix-shaped;
//!   `E2eeDeviceListUpdate` only on device key upload and device removal —
//!   joining or leaving a group does **not** publish it;
//! * backup: only `m.megolm_backup.v1.curve25519-aes-sha2`; a second version
//!   needs an MFA ticket (401 otherwise); keys go to the current version only
//!   (409 `BackupVersionMismatch` with `current_version`); the better key wins.
//!
//! Visibility (who may query, claim and message whom) is modelled as sharing a
//! channel; friendships are not modelled.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::{Map, Value, json};
use stoat_crypto_proto::api::{self, KeyBackupData, MAX_OTK_PER_DEVICE};
use stoat_crypto_proto::envelope::EncryptedEnvelope;
use stoat_crypto_proto::{BACKUP_ALGORITHM_MEGOLM_V1, KEY_ALGORITHM_SIGNED_CURVE25519, ids};

/// Shared handle, as tests drive several clients against one server
pub type Server = Arc<Mutex<FakeServer>>;

/// Backend default `max_pending_to_device`
pub const MAX_PENDING_TO_DEVICE: usize = 10_000;
/// Backend default `max_to_device_batch`
pub const MAX_TO_DEVICE_BATCH: usize = 1_000;
/// Backend default `max_request_bytes`
pub const MAX_REQUEST_BYTES: usize = 4_194_304;

/// Authenticated caller: the session token resolves to (user, session = device)
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Auth {
    pub user: String,
    pub device: String,
}

impl Auth {
    pub fn new(user: impl Into<String>, device: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            device: device.into(),
        }
    }
}

/// HTTP-like answer of [`FakeServer::handle`]
#[derive(Clone, Debug, PartialEq)]
pub struct Response {
    pub status: u16,
    /// `Value::Null` for 204
    pub body: Value,
}

impl Response {
    fn ok(body: Value) -> Self {
        Self { status: 200, body }
    }

    fn no_content() -> Self {
        Self {
            status: 204,
            body: Value::Null,
        }
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

fn error(status: u16, kind: &str) -> Response {
    Response {
        status,
        body: json!({ "type": kind }),
    }
}

fn invalid(field: &str) -> Response {
    Response {
        status: 400,
        body: json!({ "type": "FailedValidation", "error": format!("invalid {field}") }),
    }
}

#[derive(Clone, Debug)]
pub struct ToDeviceMsg {
    pub id: String,
    pub sender_user: String,
    pub sender_device: String,
    pub recipient_user: String,
    pub recipient_device: String,
    pub txn_id: String,
    pub event_type: String,
    pub content: Value,
}

/// A message in an encrypted channel, as the backend stores it
#[derive(Clone, Debug)]
pub struct StoredMessage {
    pub id: String,
    pub channel: String,
    pub author: String,
    pub encrypted: Value,
    /// Open metadata, compared with `in_reply_to` inside the payload (CR-19)
    pub replies: Vec<String>,
    pub ts: u64,
    pub edited: bool,
}

/// One request/response pair, recorded for fixtures and assertions
#[derive(Clone, Debug)]
pub struct Exchange {
    /// Calling device (session)
    pub device: String,
    pub method: String,
    pub path: String,
    pub request: Option<Value>,
    pub status: u16,
    pub response: Value,
}

type DropFilter = Box<dyn FnMut(&ToDeviceMsg) -> bool + Send>;

/// Failure modes (CR-18)
#[derive(Default)]
pub struct Faults {
    /// Drop each stored to-device message with probability p
    pub drop_to_device: f64,
    /// Store each to-device message twice (same id), probability p
    pub duplicate: f64,
    /// Shuffle the head of the mailbox within this window on each GET
    pub reorder_window: usize,
    /// Targeted drop: returns true → message is lost
    pub drop_filter: Option<DropFilter>,
    /// Devices whose one-time keys count as exhausted (claim gets the fallback)
    pub exhaust_otk: HashSet<String>,
    /// Next requests whose path starts with the prefix fail with the status
    pub fail_next: Vec<(String, u16)>,
}

impl std::fmt::Debug for Faults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Faults")
            .field("drop_to_device", &self.drop_to_device)
            .field("duplicate", &self.duplicate)
            .field("reorder_window", &self.reorder_window)
            .field("drop_filter", &self.drop_filter.is_some())
            .field("exhaust_otk", &self.exhaust_otk)
            .field("fail_next", &self.fail_next)
            .finish()
    }
}

#[derive(Clone, Debug)]
struct Fallback {
    key_id: String,
    key: Value,
    used: bool,
}

#[derive(Debug, Default)]
struct Backup {
    /// version → (algorithm, auth_data, deleted)
    versions: BTreeMap<String, (String, Value, bool)>,
    /// (version, room, session) → key
    keys: BTreeMap<(String, String, String), KeyBackupData>,
    etag: u64,
}

#[derive(Debug)]
pub struct FakeServer {
    /// user → device → signed device keys exactly as uploaded
    devices: BTreeMap<String, BTreeMap<String, Value>>,
    /// device → `signed_curve25519:<id>` → key
    otks: BTreeMap<String, BTreeMap<String, Value>>,
    /// device → fallback key
    fallback: BTreeMap<String, Fallback>,
    /// device → mailbox, oldest first
    inbox: BTreeMap<String, Vec<ToDeviceMsg>>,
    counter: u64,
    channels: BTreeMap<String, BTreeSet<String>>,
    messages: Vec<StoredMessage>,
    /// pending WebSocket events per device
    ws: BTreeMap<String, Vec<Value>>,
    backups: BTreeMap<String, Backup>,
    /// users holding an MFA ticket for the next backup version
    mfa: HashSet<String>,
    pub faults: Faults,
    rng: StdRng,
    pub log: Vec<Exchange>,
    /// every WS event ever published
    pub ws_log: Vec<Value>,
    pub record: bool,
    pub max_pending_to_device: usize,
    pub max_to_device_batch: usize,
    pub max_request_bytes: usize,
}

impl Default for FakeServer {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeServer {
    pub fn new() -> Self {
        Self::with_seed(0x5704)
    }

    pub fn with_seed(seed: u64) -> Self {
        Self {
            devices: Default::default(),
            otks: Default::default(),
            fallback: Default::default(),
            inbox: Default::default(),
            counter: 0,
            channels: Default::default(),
            messages: Default::default(),
            ws: Default::default(),
            backups: Default::default(),
            mfa: Default::default(),
            faults: Faults::default(),
            rng: StdRng::seed_from_u64(seed),
            log: Vec::new(),
            ws_log: Vec::new(),
            record: true,
            max_pending_to_device: MAX_PENDING_TO_DEVICE,
            max_to_device_batch: MAX_TO_DEVICE_BATCH,
            max_request_bytes: MAX_REQUEST_BYTES,
        }
    }

    pub fn shared(self) -> Server {
        Arc::new(Mutex::new(self))
    }

    /// Monotonic ULID-shaped id (26 characters)
    pub fn next_ulid(&mut self) -> String {
        self.counter += 1;
        format!("01KZ{:022}", self.counter)
    }

    // ------------------------------------------------------------ routing

    /// Serve one `/e2ee/*` request. `path` may carry a query string.
    pub fn handle(&mut self, auth: &Auth, method: &str, path: &str, body: Option<&Value>) -> Response {
        let response = self.route(auth, method, path, body);
        if self.record {
            self.log.push(Exchange {
                device: auth.device.clone(),
                method: method.to_owned(),
                path: path.to_owned(),
                request: body.cloned(),
                status: response.status,
                response: response.body.clone(),
            });
        }
        response
    }

    fn route(&mut self, auth: &Auth, method: &str, path: &str, body: Option<&Value>) -> Response {
        if let Some(i) = self
            .faults
            .fail_next
            .iter()
            .position(|(p, _)| path.starts_with(p.as_str()))
        {
            let (_, status) = self.faults.fail_next.remove(i);
            return error(status, "InjectedFailure");
        }
        if body.is_some_and(|b| b.to_string().len() > self.max_request_bytes) {
            return error(413, "PayloadTooLarge");
        }
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        let param = |name: &str| {
            query
                .split('&')
                .filter_map(|kv| kv.split_once('='))
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_owned())
        };
        let body = body.unwrap_or(&Value::Null);
        match (method, route) {
            ("POST", api::paths::KEYS_UPLOAD) => self.keys_upload(auth, body),
            ("POST", api::paths::KEYS_QUERY) => self.keys_query(auth, body),
            ("POST", api::paths::KEYS_CLAIM) => self.keys_claim(auth, body),
            ("GET", api::paths::KEYS_COUNT) => Response::ok(self.key_counts(&auth.device)),
            ("GET", api::paths::TO_DEVICE) => self.mailbox_fetch(auth, param("limit").as_deref()),
            ("POST", api::paths::TO_DEVICE_ACK) => self.mailbox_ack(auth, body),
            ("PUT", p) if p.starts_with("/e2ee/to_device/") => {
                self.mailbox_send(auth, &p["/e2ee/to_device/".len()..], body)
            }
            ("POST", api::paths::BACKUP_VERSION) => self.backup_version_create(auth, body),
            ("GET", api::paths::BACKUP_VERSION) => self.backup_version_get(auth),
            ("PUT", api::paths::BACKUP_KEYS) => self.backup_keys_put(auth, param("version").as_deref(), body),
            ("GET", api::paths::BACKUP_KEYS) => self.backup_keys_get(auth, param("version").as_deref()),
            _ => error(404, "NotFound"),
        }
    }

    // -------------------------------------------------------- visibility

    /// Users sharing a channel with `user`, `user` included
    fn contacts(&self, user: &str) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = [user.to_owned()].into();
        for members in self.channels.values() {
            if members.contains(user) {
                out.extend(members.iter().cloned());
            }
        }
        out
    }

    fn owner_of(&self, device: &str) -> Option<&str> {
        self.devices
            .iter()
            .find(|(_, devs)| devs.contains_key(device))
            .map(|(u, _)| u.as_str())
    }

    fn publish_ws(&mut self, device: &str, event: Value) {
        self.ws_log.push(event.clone());
        self.ws.entry(device.to_owned()).or_default().push(event);
    }

    /// `E2eeDeviceListUpdate` to every device of every contact of `user`
    pub fn device_list_update(&mut self, user: &str) {
        let event = json!({ "type": "E2eeDeviceListUpdate", "user": user });
        self.ws_log.push(event.clone());
        for c in self.contacts(user) {
            let devices: Vec<String> = self
                .devices
                .get(&c)
                .map(|d| d.keys().cloned().collect())
                .unwrap_or_default();
            for d in devices {
                self.ws.entry(d).or_default().push(event.clone());
            }
        }
    }

    // --------------------------------------------------------------- keys

    fn key_counts(&self, device: &str) -> Value {
        let n = self.otks.get(device).map_or(0, BTreeMap::len);
        let unused: Vec<&str> = match self.fallback.get(device) {
            Some(f) if !f.used => vec![KEY_ALGORITHM_SIGNED_CURVE25519],
            _ => vec![],
        };
        json!({
            "one_time_key_counts": { KEY_ALGORITHM_SIGNED_CURVE25519: n },
            "device_unused_fallback_key_types": unused,
        })
    }

    fn keys_upload(&mut self, auth: &Auth, body: &Value) -> Response {
        let Some(body) = body.as_object() else {
            return invalid("body");
        };
        let device_keys = body.get("device_keys").filter(|v| !v.is_null());
        if let Some(dk) = device_keys {
            let expect_user = ids::user_id(&auth.user).unwrap_or_default();
            let keys = dk.get("keys").and_then(Value::as_object);
            let valid = dk["user_id"] == json!(expect_user)
                && dk["device_id"] == json!(auth.device)
                && dk["algorithms"].as_array().is_some_and(|a| !a.is_empty())
                && keys.is_some_and(|k| {
                    ["curve25519", "ed25519"]
                        .iter()
                        .all(|alg| k.get(&format!("{alg}:{}", auth.device)).is_some_and(Value::is_string))
                });
            if !valid {
                return invalid("device_keys");
            }
        }
        let otks = body
            .get("one_time_keys")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if otks.len() > MAX_OTK_PER_DEVICE {
            return error(422, "PayloadTooLarge");
        }
        let fallback = body
            .get("fallback_keys")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if fallback.len() > 1 {
            return invalid("fallback_keys");
        }
        for name in otks.keys().chain(fallback.keys()) {
            if !name.starts_with("signed_curve25519:") {
                return invalid("one_time_keys");
            }
        }

        let known = self.devices.get(&auth.user).and_then(|d| d.get(&auth.device)).cloned();
        match (device_keys, known) {
            (Some(dk), Some(old)) if &old != dk => return error(409, "DeviceKeysMismatch"),
            (Some(_), Some(_)) => {}
            (Some(dk), None) => {
                self.devices
                    .entry(auth.user.clone())
                    .or_default()
                    .insert(auth.device.clone(), dk.clone());
                self.device_list_update(&auth.user.clone());
            }
            (None, None) if !otks.is_empty() || !fallback.is_empty() => return error(404, "NotFound"),
            (None, _) => {}
        }

        if !otks.is_empty() {
            let store = self.otks.entry(auth.device.clone()).or_default();
            if store.len() + otks.len() > MAX_OTK_PER_DEVICE {
                return error(422, "PayloadTooLarge");
            }
            for (id, k) in otks {
                store.entry(id).or_insert(k);
            }
        }
        if let Some((id, k)) = fallback.into_iter().next() {
            let key_id = id["signed_curve25519:".len()..].to_owned();
            if self.fallback.get(&auth.device).is_none_or(|f| f.key_id != key_id) {
                self.fallback.insert(
                    auth.device.clone(),
                    Fallback {
                        key_id,
                        key: k,
                        used: false,
                    },
                );
            }
        }
        Response::ok(self.key_counts(&auth.device))
    }

    fn keys_query(&mut self, auth: &Auth, body: &Value) -> Response {
        let Some(wanted) = body.get("device_keys").and_then(Value::as_object) else {
            return invalid("device_keys");
        };
        if wanted.len() > api::MAX_DEVICES_PER_REQUEST {
            return error(422, "PayloadTooLarge");
        }
        let visible = self.contacts(&auth.user);
        let mut device_keys = Map::new();
        for (muser, devices) in wanted {
            let filter: Vec<&str> = devices
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let mut out = Map::new();
            if let Some(ulid) = ids::user_ulid(muser).filter(|u| visible.contains(u)) {
                for (d, k) in self.devices.get(&ulid).into_iter().flatten() {
                    if filter.is_empty() || filter.contains(&d.as_str()) {
                        out.insert(d.clone(), k.clone());
                    }
                }
            }
            device_keys.insert(muser.clone(), Value::Object(out));
        }
        Response::ok(json!({
            "device_keys": device_keys,
            "failures": {},
            "master_keys": {},
            "self_signing_keys": {},
            "user_signing_keys": {},
        }))
    }

    fn keys_claim(&mut self, auth: &Auth, body: &Value) -> Response {
        let Some(wanted) = body.get("one_time_keys").and_then(Value::as_object) else {
            return invalid("one_time_keys");
        };
        let total: usize = wanted.values().filter_map(Value::as_object).map(Map::len).sum();
        if total > api::MAX_DEVICES_PER_REQUEST {
            return error(422, "PayloadTooLarge");
        }
        let visible = self.contacts(&auth.user);
        let mut out = Map::new();
        for (muser, devices) in wanted {
            let Some(ulid) = ids::user_ulid(muser).filter(|u| visible.contains(u)) else {
                continue;
            };
            let mut udevs = Map::new();
            for (dev, alg) in devices.as_object().into_iter().flatten() {
                if alg != KEY_ALGORITHM_SIGNED_CURVE25519 || self.owner_of(dev) != Some(ulid.as_str()) {
                    continue;
                }
                let otk = if self.faults.exhaust_otk.contains(dev) {
                    None
                } else {
                    self.otks.get_mut(dev).and_then(BTreeMap::pop_first)
                };
                let picked = otk.or_else(|| {
                    self.fallback.get_mut(dev).map(|f| {
                        f.used = true;
                        (format!("signed_curve25519:{}", f.key_id), f.key.clone())
                    })
                });
                if let Some((id, k)) = picked {
                    udevs.insert(dev.clone(), json!({ id: k }));
                }
            }
            if !udevs.is_empty() {
                out.insert(muser.clone(), Value::Object(udevs));
            }
        }
        Response::ok(json!({ "failures": {}, "one_time_keys": out }))
    }

    // ---------------------------------------------------------- to-device

    fn mailbox_send(&mut self, auth: &Auth, txn_id: &str, body: &Value) -> Response {
        if txn_id.is_empty()
            || txn_id.len() > 64
            || !txn_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return invalid("txn_id");
        }
        let Some(event_type) = body.get("type").and_then(Value::as_str).filter(|t| !t.is_empty()) else {
            return invalid("type");
        };
        let Some(messages) = body.get("messages").and_then(Value::as_object) else {
            return invalid("messages");
        };
        if messages
            .values()
            .flat_map(|d| d.as_object().into_iter().flatten())
            .any(|(_, c)| !c.is_object())
        {
            return invalid("messages");
        }
        let count: usize = messages.values().filter_map(Value::as_object).map(Map::len).sum();
        if count > self.max_to_device_batch {
            return error(422, "PayloadTooLarge");
        }

        let visible = self.contacts(&auth.user);
        let mut deliveries = Vec::new();
        for (muser, devices) in messages {
            let Some(ulid) = ids::user_ulid(muser).filter(|u| visible.contains(u)) else {
                continue;
            };
            let Some(user_devices) = self.devices.get(&ulid) else {
                continue;
            };
            let mut wildcard = None;
            let mut addressed = HashSet::new();
            for (dev, content) in devices.as_object().into_iter().flatten() {
                if dev == "*" {
                    wildcard = Some(content.clone());
                } else if user_devices.contains_key(dev) {
                    addressed.insert(dev.clone());
                    deliveries.push((ulid.clone(), muser.clone(), dev.clone(), content.clone()));
                }
            }
            if let Some(content) = wildcard {
                for dev in user_devices.keys() {
                    if dev != &auth.device && !addressed.contains(dev) {
                        deliveries.push((ulid.clone(), muser.clone(), dev.clone(), content.clone()));
                    }
                }
            }
        }

        let mut failed: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (ru, muser, rd, content) in deliveries {
            let inbox_len = self.inbox.get(&rd).map_or(0, Vec::len);
            if inbox_len >= self.max_pending_to_device {
                failed.entry(muser).or_default().push(rd);
                continue;
            }
            // retried PUT: unique (sender device, txn, recipient) while undelivered
            if self
                .inbox
                .get(&rd)
                .is_some_and(|b| b.iter().any(|m| m.sender_device == auth.device && m.txn_id == txn_id))
            {
                continue;
            }
            let msg = ToDeviceMsg {
                id: self.next_ulid(),
                sender_user: auth.user.clone(),
                sender_device: auth.device.clone(),
                recipient_user: ru,
                recipient_device: rd.clone(),
                txn_id: txn_id.to_owned(),
                event_type: event_type.to_owned(),
                content,
            };
            let mut lost = self.rng.gen_bool(self.faults.drop_to_device.clamp(0.0, 1.0));
            if let Some(f) = self.faults.drop_filter.as_mut() {
                lost |= f(&msg);
            }
            if lost {
                continue;
            }
            let dup = self.rng.gen_bool(self.faults.duplicate.clamp(0.0, 1.0));
            let doorbell = json!({
                "type": "E2eeToDevice",
                "id": msg.id,
                "recipient_device": rd,
                "sender": ids::user_id(&auth.user).unwrap_or_default(),
                "sender_device": auth.device,
                "event_type": event_type,
            });
            self.publish_ws(&rd, doorbell);
            let inbox = self.inbox.entry(rd).or_default();
            if dup {
                inbox.push(msg.clone());
            }
            inbox.push(msg);
        }
        let mut resp = Map::new();
        if !failed.is_empty() {
            resp.insert("failed".into(), json!(failed));
        }
        Response::ok(Value::Object(resp))
    }

    fn mailbox_fetch(&mut self, auth: &Auth, limit: Option<&str>) -> Response {
        let limit = match limit.map(str::parse::<usize>) {
            None => api::MAX_TO_DEVICE_FETCH,
            Some(Ok(n)) if (1..=api::MAX_TO_DEVICE_FETCH).contains(&n) => n,
            Some(_) => return invalid("limit"),
        };
        let mut head: Vec<ToDeviceMsg> = self
            .inbox
            .get(&auth.device)
            .map(|v| v.iter().take(limit).cloned().collect())
            .unwrap_or_default();
        let w = self.faults.reorder_window.min(head.len());
        if w > 1 {
            for i in (1..w).rev() {
                let j = self.rng.gen_range(0..=i);
                head.swap(i, j);
            }
        }
        let messages: Vec<Value> = head
            .iter()
            .map(|m| {
                json!({
                    "id": m.id,
                    "sender": ids::user_id(&m.sender_user).unwrap_or_default(),
                    "sender_device": m.sender_device,
                    "type": m.event_type,
                    "content": m.content,
                })
            })
            .collect();
        Response::ok(json!({ "messages": messages }))
    }

    fn mailbox_ack(&mut self, auth: &Auth, body: &Value) -> Response {
        let ids: Vec<&str> = body
            .get("ids")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if ids.is_empty() || ids.len() > api::MAX_TO_DEVICE_ACK {
            return invalid("ids");
        }
        if let Some(v) = self.inbox.get_mut(&auth.device) {
            v.retain(|m| !ids.contains(&m.id.as_str()));
        }
        Response::no_content()
    }

    // ------------------------------------------------------------- backup

    fn current_backup(&self, user: &str) -> Option<(&String, &(String, Value, bool))> {
        self.backups.get(user)?.versions.iter().rev().find(|(_, x)| !x.2)
    }

    fn backup_version_create(&mut self, auth: &Auth, body: &Value) -> Response {
        if body.get("algorithm").and_then(Value::as_str) != Some(BACKUP_ALGORITHM_MEGOLM_V1) {
            return invalid("algorithm");
        }
        if !body["auth_data"].get("public_key").is_some_and(Value::is_string) {
            return invalid("auth_data");
        }
        // a stolen session token must not be able to wipe the backup
        if self.current_backup(&auth.user).is_some() && !self.mfa.remove(&auth.user) {
            return error(401, "InvalidToken");
        }
        let version = self.next_ulid();
        let b = self.backups.entry(auth.user.clone()).or_default();
        for v in b.versions.values_mut() {
            v.2 = true;
        }
        b.versions.insert(
            version.clone(),
            (BACKUP_ALGORITHM_MEGOLM_V1.to_owned(), body["auth_data"].clone(), false),
        );
        Response::ok(json!({ "version": version }))
    }

    fn backup_version_get(&mut self, auth: &Auth) -> Response {
        let Some((version, (algorithm, auth_data, _))) = self.current_backup(&auth.user) else {
            return error(404, "NotFound");
        };
        let b = &self.backups[&auth.user];
        let count = b.keys.keys().filter(|k| &k.0 == version).count();
        Response::ok(json!({
            "algorithm": algorithm,
            "auth_data": auth_data,
            "count": count,
            "etag": b.etag.to_string(),
            "version": version,
        }))
    }

    fn backup_keys_put(&mut self, auth: &Auth, version: Option<&str>, body: &Value) -> Response {
        let Some(version) = version.filter(|v| !v.is_empty() && v.len() <= 64) else {
            return invalid("version");
        };
        let Some((current, _)) = self.current_backup(&auth.user) else {
            return error(404, "NotFound");
        };
        if current != version {
            return Response {
                status: 409,
                body: json!({ "type": "BackupVersionMismatch", "current_version": current }),
            };
        }
        let Ok(backup) = serde_json::from_value::<api::KeysBackup>(body.clone()) else {
            return invalid("rooms");
        };
        let mut keys = Vec::new();
        for (room, r) in backup.rooms {
            if ids::channel_ulid(&room).is_none() {
                return invalid("room_id");
            }
            for (session, data) in r.sessions {
                if session.is_empty() || session.len() > 128 {
                    return invalid("session_id");
                }
                if !data.session_data.is_object() {
                    return invalid("session_data");
                }
                keys.push(((version.to_owned(), room.clone(), session), data));
            }
        }
        let b = self.backups.entry(auth.user.clone()).or_default();
        let mut changed = false;
        for (id, data) in keys {
            if b.keys.get(&id).is_none_or(|old| data.is_better_than(old)) {
                b.keys.insert(id, data);
                changed = true;
            }
        }
        if changed {
            b.etag += 1;
        }
        let count = b.keys.keys().filter(|k| k.0 == version).count();
        Response::ok(json!({ "count": count, "etag": b.etag.to_string() }))
    }

    fn backup_keys_get(&mut self, auth: &Auth, version: Option<&str>) -> Response {
        let Some(version) = version else {
            return invalid("version");
        };
        match self.current_backup(&auth.user) {
            Some((current, _)) if current == version => {}
            Some((current, _)) => {
                return Response {
                    status: 409,
                    body: json!({ "type": "BackupVersionMismatch", "current_version": current }),
                };
            }
            None => return error(404, "NotFound"),
        }
        let mut rooms: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
        for ((v, room, session), data) in &self.backups[&auth.user].keys {
            if v == version {
                rooms
                    .entry(room.clone())
                    .or_default()
                    .insert(session.clone(), serde_json::to_value(data).expect("serializable"));
            }
        }
        let rooms: Map<String, Value> = rooms.into_iter().map(|(r, s)| (r, json!({ "sessions": s }))).collect();
        Response::ok(json!({ "rooms": rooms }))
    }

    /// Let the next `POST /backup/version` of `user` pass (MFA ticket)
    pub fn grant_mfa_ticket(&mut self, user: &str) {
        self.mfa.insert(user.to_owned());
    }

    // ----------------------------------------------------- Stoat side

    /// WebSocket events for the socket of this session
    pub fn ws_take(&mut self, auth: &Auth) -> Vec<Value> {
        self.ws.remove(&auth.device).unwrap_or_default()
    }

    /// Logout / session revoke: the device, its keys and mailbox go (BE-10)
    pub fn device_delete(&mut self, user: &str, device: &str) {
        if let Some(d) = self.devices.get_mut(user) {
            d.remove(device);
        }
        self.otks.remove(device);
        self.fallback.remove(device);
        self.inbox.remove(device);
        self.ws.remove(device);
        self.device_list_update(user);
    }

    /// Set the members of a DM or group. Like the backend, this publishes no
    /// `E2eeDeviceListUpdate`: clients refresh member keys themselves.
    pub fn channel_set_members(&mut self, channel: &str, members: &[&str]) {
        self.channels
            .insert(channel.to_owned(), members.iter().map(|s| s.to_string()).collect());
    }

    pub fn channel_members(&self, channel: &str) -> Vec<String> {
        self.channels
            .get(channel)
            .map(|m| m.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// `POST /channels/<id>/messages` with `encrypted` (BE-13): member only,
    /// strict envelope v1, `device_id` must be the sending session.
    pub fn message_send(
        &mut self,
        auth: &Auth,
        channel: &str,
        encrypted: Value,
        replies: Vec<String>,
    ) -> Result<String, Response> {
        self.check_envelope(auth, channel, &encrypted)?;
        let id = self.next_ulid();
        self.messages.push(StoredMessage {
            id: id.clone(),
            channel: channel.to_owned(),
            author: auth.user.clone(),
            encrypted,
            replies,
            ts: 1_760_700_000_000 + self.counter,
            edited: false,
        });
        Ok(id)
    }

    /// `PATCH /channels/<id>/messages/<msg>` with `encrypted` only
    pub fn message_edit(&mut self, auth: &Auth, channel: &str, id: &str, encrypted: Value) -> Result<(), Response> {
        self.check_envelope(auth, channel, &encrypted)?;
        let m = self
            .messages
            .iter_mut()
            .find(|m| m.id == id && m.channel == channel)
            .ok_or_else(|| error(404, "NotFound"))?;
        if m.author != auth.user {
            return Err(error(403, "CannotEditMessage"));
        }
        m.encrypted = encrypted;
        m.edited = true;
        Ok(())
    }

    fn check_envelope(&self, auth: &Auth, channel: &str, encrypted: &Value) -> Result<(), Response> {
        if !self.channels.get(channel).is_some_and(|m| m.contains(&auth.user)) {
            return Err(error(404, "NotFound"));
        }
        let envelope = EncryptedEnvelope::from_value(encrypted).map_err(|e| match e {
            stoat_crypto_proto::EnvelopeError::TooLarge => error(422, "PayloadTooLarge"),
            _ => invalid("encrypted"),
        })?;
        if envelope.device_id != auth.device {
            return Err(error(400, "EncryptedChannelViolation"));
        }
        Ok(())
    }

    pub fn messages(&self, channel: &str) -> Vec<StoredMessage> {
        self.messages.iter().filter(|m| m.channel == channel).cloned().collect()
    }

    /// Server-side tampering for tests (T8): direct access to stored messages
    pub fn messages_mut(&mut self) -> &mut Vec<StoredMessage> {
        &mut self.messages
    }

    pub fn inbox_len(&self, device: &str) -> usize {
        self.inbox.get(device).map_or(0, Vec::len)
    }

    pub fn otk_count(&self, device: &str) -> usize {
        self.otks.get(device).map_or(0, BTreeMap::len)
    }

    /// Really exhaust a device's one-time keys (claim then falls back)
    pub fn drain_otks(&mut self, device: &str) {
        self.otks.remove(device);
    }

    pub fn fallback_used(&self, device: &str) -> Option<bool> {
        self.fallback.get(device).map(|f| f.used)
    }

    pub fn device_keys(&self, user: &str, device: &str) -> Option<&Value> {
        self.devices.get(user)?.get(device)
    }

    /// Server-side tampering with stored device keys (CR-07 tests)
    pub fn device_keys_mut(&mut self, user: &str, device: &str) -> Option<&mut Value> {
        self.devices.get_mut(user)?.get_mut(device)
    }

    /// The mailbox of a device as stored, oldest first (redirect tests)
    pub fn inbox(&self, device: &str) -> Vec<ToDeviceMsg> {
        self.inbox.get(device).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
