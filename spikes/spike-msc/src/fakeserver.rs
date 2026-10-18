//! In-memory fake of the Stoat `/e2ee/*` API (spike CR-01, becomes CR-18).
//!
//! It speaks **JSON only** (`serde_json::Value` in, `Value` out), in the Matrix
//! CS API shape fixed by C1. It never sees ruma types, so whatever the adapter
//! sends here is exactly what the real backend (BE-02/06/07/08) has to accept.
//!
//! Internally users are stored by ULID (as the real backend does) and IDs in
//! bodies are translated with the C15 mapping.
//!
//! Inbox semantics follow C2: `GET /e2ee/to_device?limit=N` returns the oldest
//! N messages, `POST /e2ee/to_device/ack {ids}` deletes them.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex};

use rand::{Rng, SeedableRng, rngs::StdRng};
use serde_json::{Map, Value, json};

use crate::ids;

pub type Server = Arc<Mutex<FakeServer>>;

pub const MAX_OTK_PER_DEVICE: usize = 100;

/// Authenticated caller: `x-session-token` resolves to (user, session = device).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Auth {
    pub user: String,
    pub device: String,
}

#[derive(Clone, Debug)]
pub struct ToDeviceMsg {
    pub id: String,
    pub sender_user: String,
    pub sender_device: String,
    pub recipient_user: String,
    pub recipient_device: String,
    pub event_type: String,
    pub content: Value,
}

#[derive(Clone, Debug)]
pub struct StoredMessage {
    pub id: String,
    pub channel: String,
    pub author: String,
    pub encrypted: Value,
    /// open metadata (`replies`), compared with `in_reply_to` inside the payload
    pub replies: Vec<String>,
    pub ts: u64,
}

#[derive(Clone, Debug)]
pub struct Exchange {
    pub method: &'static str,
    pub path: String,
    pub request: Option<Value>,
    pub response: Value,
}

type DropFilter = Box<dyn FnMut(&ToDeviceMsg) -> bool + Send>;

/// Failure modes (CR-01 «Режимы сбоев»).
#[derive(Default)]
pub struct Faults {
    /// Drop each to-device message with probability p.
    pub drop_to_device: f64,
    /// Duplicate each to-device message (same id delivered twice in a batch,
    /// simulating a retry/at-least-once storage layer).
    pub duplicate: f64,
    /// Shuffle the head of the inbox within this window on each GET.
    pub reorder_window: usize,
    /// Targeted drop: returns true → message is lost.
    pub drop_filter: Option<DropFilter>,
    /// Devices whose one-time keys are treated as exhausted (claim gets fallback).
    pub exhaust_otk: HashSet<String>,
}

#[derive(Default)]
struct Backup {
    /// version → (algorithm, auth_data, deleted)
    versions: BTreeMap<String, (String, Value, bool)>,
    /// (version, room, session) → KeyBackupData
    keys: BTreeMap<(String, String, String), Value>,
    etag: u64,
}

pub struct FakeServer {
    /// user ulid → device → signed device_keys JSON exactly as uploaded
    devices: BTreeMap<String, BTreeMap<String, Value>>,
    /// (user, device) → key_id ("signed_curve25519:AAAAAQ") → key
    otks: BTreeMap<(String, String), BTreeMap<String, Value>>,
    /// (user, device) → (key_id, key, used)
    fallback: BTreeMap<(String, String), (String, Value, bool)>,
    inbox: BTreeMap<(String, String), Vec<ToDeviceMsg>>,
    /// unique (sender_device, txn_id, recipient_device) — idempotency (C5)
    txns: HashSet<(String, String, String)>,
    counter: u64,
    channels: BTreeMap<String, BTreeSet<String>>,
    pub messages: Vec<StoredMessage>,
    /// pending WebSocket events per (user, device)
    ws: BTreeMap<(String, String), Vec<Value>>,
    backups: BTreeMap<String, Backup>,
    pub faults: Faults,
    rng: StdRng,
    pub log: Vec<Exchange>,
    /// every WS event ever published (for fixtures)
    pub ws_log: Vec<Value>,
    pub record: bool,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub body: Value,
}

fn err(status: u16, kind: &str) -> ApiError {
    ApiError {
        status,
        body: json!({ "type": kind }),
    }
}

impl FakeServer {
    pub fn new() -> Server {
        Arc::new(Mutex::new(Self {
            devices: Default::default(),
            otks: Default::default(),
            fallback: Default::default(),
            inbox: Default::default(),
            txns: Default::default(),
            counter: 0,
            channels: Default::default(),
            messages: Default::default(),
            ws: Default::default(),
            backups: Default::default(),
            faults: Faults::default(),
            rng: StdRng::seed_from_u64(0x5704),
            log: Vec::new(),
            ws_log: Vec::new(),
            record: true,
        }))
    }

    /// Monotonic ULID-shaped id (26 Crockford chars).
    pub fn next_ulid(&mut self) -> String {
        self.counter += 1;
        format!("01KZ{:022}", self.counter)
    }

    fn rec(&mut self, method: &'static str, path: String, request: Option<&Value>, response: &Value) {
        if self.record {
            self.log.push(Exchange {
                method,
                path,
                request: request.cloned(),
                response: response.clone(),
            });
        }
    }

    fn matrix_user(ulid: &str) -> String {
        ids::user_id(ulid).to_string()
    }

    fn ulid_of(matrix_user: &str) -> Option<String> {
        ruma::UserId::parse(matrix_user).ok().and_then(|u| ids::user_ulid(&u))
    }

    /// Users who share a channel with `user` (incl. self) — recipients of
    /// `E2eeDeviceListUpdate` and the visibility set for `keys/query`.
    fn contacts(&self, user: &str) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = [user.to_owned()].into();
        for members in self.channels.values() {
            if members.contains(user) {
                out.extend(members.iter().cloned());
            }
        }
        out
    }

    fn push_ws_user(&mut self, user: &str, event: Value) {
        self.ws_log.push(event.clone());
        let devices: Vec<String> = self
            .devices
            .get(user)
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default();
        for d in devices {
            self.ws.entry((user.to_owned(), d)).or_default().push(event.clone());
        }
    }

    fn device_list_update(&mut self, user: &str) {
        let event = json!({ "type": "E2eeDeviceListUpdate", "user": user });
        for c in self.contacts(user) {
            self.push_ws_user(&c, event.clone());
        }
    }

    // ---------------------------------------------------------------- keys

    /// `POST /e2ee/keys/upload`
    pub fn keys_upload(&mut self, auth: &Auth, body: &Value) -> Result<Value, ApiError> {
        let key = (auth.user.clone(), auth.device.clone());
        if let Some(dk) = body.get("device_keys") {
            // BE-06: structure only, signature is not verified (Q14)
            let expect_user = Self::matrix_user(&auth.user);
            if dk["user_id"] != json!(expect_user) || dk["device_id"] != json!(auth.device) {
                return Err(err(400, "InvalidDeviceKeys"));
            }
            let existing = self.devices.get(&auth.user).and_then(|d| d.get(&auth.device));
            match existing {
                Some(old) if old != dk => return Err(err(409, "DeviceKeysImmutable")),
                Some(_) => {}
                None => {
                    self.devices
                        .entry(auth.user.clone())
                        .or_default()
                        .insert(auth.device.clone(), dk.clone());
                    self.device_list_update(&auth.user.clone());
                }
            }
        }
        if let Some(otks) = body.get("one_time_keys").and_then(Value::as_object) {
            let store = self.otks.entry(key.clone()).or_default();
            for (id, k) in otks {
                if store.len() >= MAX_OTK_PER_DEVICE {
                    break;
                }
                store.entry(id.clone()).or_insert_with(|| k.clone());
            }
        }
        if let Some(fb) = body.get("fallback_keys").and_then(Value::as_object)
            && let Some((id, k)) = fb.iter().next()
        {
            self.fallback.insert(key.clone(), (id.clone(), k.clone(), false));
        }
        let resp = json!({ "one_time_key_counts": self.otk_counts(&key) });
        self.rec("POST", "/e2ee/keys/upload".into(), Some(body), &resp);
        Ok(resp)
    }

    fn otk_counts(&self, key: &(String, String)) -> Value {
        let mut counts = Map::new();
        let n = self.otks.get(key).map(|m| m.len()).unwrap_or(0);
        counts.insert("signed_curve25519".into(), json!(n));
        Value::Object(counts)
    }

    /// `GET /e2ee/keys/count`
    pub fn keys_count(&mut self, auth: &Auth) -> Value {
        let key = (auth.user.clone(), auth.device.clone());
        let unused: Vec<&str> = match self.fallback.get(&key) {
            Some((_, _, false)) => vec!["signed_curve25519"],
            _ => vec![],
        };
        let resp = json!({
            "one_time_key_counts": self.otk_counts(&key),
            "device_unused_fallback_key_types": unused,
        });
        self.rec("GET", "/e2ee/keys/count".into(), None, &resp);
        resp
    }

    /// `POST /e2ee/keys/query`
    pub fn keys_query(&mut self, auth: &Auth, body: &Value) -> Result<Value, ApiError> {
        let visible = self.contacts(&auth.user);
        let mut device_keys = Map::new();
        let mut failures = Map::new();
        for (muser, wanted) in body["device_keys"].as_object().ok_or_else(|| err(400, "InvalidBody"))? {
            let Some(ulid) = Self::ulid_of(muser) else {
                failures.insert(muser.clone(), json!({ "errcode": "M_INVALID_PARAM" }));
                continue;
            };
            if !visible.contains(&ulid) {
                // no shared DM/group/friendship → empty, like an unknown user
                device_keys.insert(muser.clone(), json!({}));
                continue;
            }
            let wanted: Vec<&str> = wanted
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let mut devs = Map::new();
            for (d, k) in self.devices.get(&ulid).into_iter().flatten() {
                if wanted.is_empty() || wanted.contains(&d.as_str()) {
                    devs.insert(d.clone(), k.clone());
                }
            }
            device_keys.insert(muser.clone(), Value::Object(devs));
        }
        let resp = json!({
            "device_keys": device_keys,
            "failures": failures,
            "master_keys": {},
            "self_signing_keys": {},
            "user_signing_keys": {},
        });
        self.rec("POST", "/e2ee/keys/query".into(), Some(body), &resp);
        Ok(resp)
    }

    /// `POST /e2ee/keys/claim` — atomic pop of one OTK, else the fallback key.
    pub fn keys_claim(&mut self, _auth: &Auth, body: &Value) -> Result<Value, ApiError> {
        let mut out = Map::new();
        for (muser, devs) in body["one_time_keys"]
            .as_object()
            .ok_or_else(|| err(400, "InvalidBody"))?
        {
            let Some(ulid) = Self::ulid_of(muser) else { continue };
            let mut udevs = Map::new();
            for (dev, alg) in devs.as_object().into_iter().flatten() {
                if alg != "signed_curve25519" {
                    continue;
                }
                let key = (ulid.clone(), dev.clone());
                let exhausted = self.faults.exhaust_otk.contains(dev);
                let otk = if exhausted {
                    None
                } else {
                    self.otks.get_mut(&key).and_then(|m| m.pop_first())
                };
                let picked = match otk {
                    Some((id, k)) => Some((id, k)),
                    None => self.fallback.get_mut(&key).map(|(id, k, used)| {
                        *used = true;
                        (id.clone(), k.clone())
                    }),
                };
                if let Some((id, k)) = picked {
                    let mut one = Map::new();
                    one.insert(id, k);
                    udevs.insert(dev.clone(), Value::Object(one));
                }
            }
            if !udevs.is_empty() {
                out.insert(muser.clone(), Value::Object(udevs));
            }
        }
        let resp = json!({ "one_time_keys": out, "failures": {} });
        self.rec("POST", "/e2ee/keys/claim".into(), Some(body), &resp);
        Ok(resp)
    }

    // ----------------------------------------------------------- to-device

    /// `PUT /e2ee/to_device/<txn_id>`
    pub fn to_device_put(&mut self, auth: &Auth, txn_id: &str, body: &Value) -> Result<Value, ApiError> {
        let event_type = body["type"].as_str().ok_or_else(|| err(400, "InvalidBody"))?.to_owned();
        let mut targets = Vec::new();
        for (muser, devs) in body["messages"].as_object().ok_or_else(|| err(400, "InvalidBody"))? {
            let Some(ulid) = Self::ulid_of(muser) else { continue };
            for (dev, content) in devs.as_object().into_iter().flatten() {
                if dev == "*" {
                    let all: Vec<String> = self
                        .devices
                        .get(&ulid)
                        .map(|d| d.keys().cloned().collect())
                        .unwrap_or_default();
                    for d in all {
                        if !(ulid == auth.user && d == auth.device) {
                            targets.push((ulid.clone(), d, content.clone()));
                        }
                    }
                } else {
                    targets.push((ulid.clone(), dev.clone(), content.clone()));
                }
            }
        }
        for (ru, rd, content) in targets {
            if !self.txns.insert((auth.device.clone(), txn_id.to_owned(), rd.clone())) {
                continue; // retried PUT: unique index swallows the duplicate
            }
            if !self.devices.get(&ru).is_some_and(|d| d.contains_key(&rd)) {
                continue; // unknown/deleted device
            }
            let msg = ToDeviceMsg {
                id: self.next_ulid(),
                sender_user: auth.user.clone(),
                sender_device: auth.device.clone(),
                recipient_user: ru.clone(),
                recipient_device: rd.clone(),
                event_type: event_type.clone(),
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
            let ev = json!({
                "type": "E2eeToDevice",
                "id": msg.id,
                "recipient_device": rd,
                "sender": auth.user,
                "sender_device": auth.device,
                "event_type": event_type,
            });
            self.ws_log.push(ev.clone());
            self.ws.entry((ru.clone(), rd.clone())).or_default().push(ev);
            let inbox = self.inbox.entry((ru, rd)).or_default();
            if dup {
                inbox.push(msg.clone());
            }
            inbox.push(msg);
        }
        let resp = json!({});
        self.rec("PUT", format!("/e2ee/to_device/{txn_id}"), Some(body), &resp);
        Ok(resp)
    }

    /// `GET /e2ee/to_device?limit=N` — oldest N
    pub fn to_device_get(&mut self, auth: &Auth, limit: usize) -> Value {
        let key = (auth.user.clone(), auth.device.clone());
        let mut head: Vec<ToDeviceMsg> = self
            .inbox
            .get(&key)
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
                    "sender": Self::matrix_user(&m.sender_user),
                    "sender_device": m.sender_device,
                    "type": m.event_type,
                    "content": m.content,
                })
            })
            .collect();
        let resp = json!({ "messages": messages });
        self.rec("GET", format!("/e2ee/to_device?limit={limit}"), None, &resp);
        resp
    }

    /// `POST /e2ee/to_device/ack {ids}` → 204
    pub fn to_device_ack(&mut self, auth: &Auth, body: &Value) {
        let ids: HashSet<&str> = body["ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if let Some(v) = self.inbox.get_mut(&(auth.user.clone(), auth.device.clone())) {
            v.retain(|m| !ids.contains(m.id.as_str()));
        }
        self.rec("POST", "/e2ee/to_device/ack".into(), Some(body), &Value::Null);
    }

    pub fn inbox_len(&self, user: &str, device: &str) -> usize {
        self.inbox
            .get(&(user.to_owned(), device.to_owned()))
            .map_or(0, Vec::len)
    }

    /// WebSocket events for this socket (bonfire filters `E2eeToDevice` by session).
    pub fn ws_take(&mut self, auth: &Auth) -> Vec<Value> {
        self.ws
            .remove(&(auth.user.clone(), auth.device.clone()))
            .unwrap_or_default()
    }

    // ------------------------------------------------------------ devices

    /// Logout / session revoke: device, its OTKs, fallback and inbox are gone (R3).
    pub fn device_delete(&mut self, user: &str, device: &str) {
        if let Some(d) = self.devices.get_mut(user) {
            d.remove(device);
        }
        let key = (user.to_owned(), device.to_owned());
        self.otks.remove(&key);
        self.fallback.remove(&key);
        self.inbox.remove(&key);
        self.ws.remove(&key);
        self.device_list_update(user);
    }

    /// Really exhaust a device's one-time keys (claim then falls back).
    pub fn drain_otks(&mut self, user: &str, device: &str) {
        self.otks.remove(&(user.to_owned(), device.to_owned()));
    }

    pub fn otk_count(&self, user: &str, device: &str) -> usize {
        self.otks
            .get(&(user.to_owned(), device.to_owned()))
            .map_or(0, |m| m.len())
    }

    pub fn fallback_used(&self, user: &str, device: &str) -> Option<bool> {
        self.fallback.get(&(user.to_owned(), device.to_owned())).map(|f| f.2)
    }

    // ----------------------------------------------------------- channels

    pub fn channel_set_members(&mut self, channel: &str, members: &[&str]) {
        let new: BTreeSet<String> = members.iter().map(|s| s.to_string()).collect();
        let old = self
            .channels
            .insert(channel.to_owned(), new.clone())
            .unwrap_or_default();
        // joiners see the others' devices change (tracked set changes) — emulate the
        // ChannelGroupJoin/Leave fan-out by a device-list poke for everyone involved
        for u in old.symmetric_difference(&new).cloned().collect::<Vec<_>>() {
            for m in new.union(&old).cloned().collect::<Vec<_>>() {
                self.push_ws_user(&m, json!({ "type": "E2eeDeviceListUpdate", "user": u }));
            }
        }
    }

    pub fn channel_members(&self, channel: &str) -> Vec<String> {
        self.channels
            .get(channel)
            .map(|m| m.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// `POST /channels/<id>/messages` with `encrypted` (BE-13 checks, simplified).
    pub fn message_send(
        &mut self,
        auth: &Auth,
        channel: &str,
        encrypted: Value,
        replies: Vec<String>,
    ) -> Result<String, ApiError> {
        if !self.channels.get(channel).is_some_and(|m| m.contains(&auth.user)) {
            return Err(err(403, "NotInChannel"));
        }
        validate_envelope_v1(&encrypted).map_err(|_| err(400, "InvalidEnvelope"))?;
        // Q5: cheap check, not a guarantee
        if encrypted["device_id"] != json!(auth.device) {
            return Err(err(400, "InvalidEnvelope"));
        }
        let id = self.next_ulid();
        self.messages.push(StoredMessage {
            id: id.clone(),
            channel: channel.to_owned(),
            author: auth.user.clone(),
            encrypted,
            replies,
            ts: 1_760_700_000_000 + self.counter,
        });
        Ok(id)
    }

    pub fn channel_messages(&self, channel: &str) -> Vec<StoredMessage> {
        self.messages.iter().filter(|m| m.channel == channel).cloned().collect()
    }

    // -------------------------------------------------------------- backup

    /// `POST /e2ee/backup/version`
    pub fn backup_version_create(&mut self, auth: &Auth, body: &Value) -> Result<Value, ApiError> {
        let alg = body["algorithm"].as_str().unwrap_or_default().to_owned();
        if !matches!(
            alg.as_str(),
            "m.megolm_backup.v1.curve25519-aes-sha2" | "stoat.backup.v1.aead"
        ) {
            return Err(err(400, "UnsupportedBackupAlgorithm"));
        }
        let version = self.next_ulid();
        let b = self.backups.entry(auth.user.clone()).or_default();
        for v in b.versions.values_mut() {
            v.2 = true;
        }
        b.versions
            .insert(version.clone(), (alg, body["auth_data"].clone(), false));
        let resp = json!({ "version": version });
        self.rec("POST", "/e2ee/backup/version".into(), Some(body), &resp);
        Ok(resp)
    }

    /// `GET /e2ee/backup/version`
    pub fn backup_version_get(&mut self, auth: &Auth) -> Result<Value, ApiError> {
        let b = self.backups.get(&auth.user).ok_or_else(|| err(404, "NotFound"))?;
        let (v, (alg, auth_data, _)) = b
            .versions
            .iter()
            .rev()
            .find(|(_, x)| !x.2)
            .ok_or_else(|| err(404, "NotFound"))?;
        let count = b.keys.keys().filter(|k| &k.0 == v).count();
        let resp = json!({
            "algorithm": alg,
            "auth_data": auth_data,
            "version": v,
            "etag": b.etag.to_string(),
            "count": count,
        });
        self.rec("GET", "/e2ee/backup/version".into(), None, &resp);
        Ok(resp)
    }

    /// `PUT /e2ee/backup/keys?version=`
    pub fn backup_keys_put(&mut self, auth: &Auth, version: &str, body: &Value) -> Result<Value, ApiError> {
        let b = self.backups.entry(auth.user.clone()).or_default();
        match b.versions.get(version) {
            Some((_, _, false)) => {}
            _ => return Err(err(409, "WrongBackupVersion")),
        }
        for (room, r) in body["rooms"].as_object().into_iter().flatten() {
            for (session, data) in r["sessions"].as_object().into_iter().flatten() {
                b.keys
                    .insert((version.to_owned(), room.clone(), session.clone()), data.clone());
            }
        }
        b.etag += 1;
        let count = b.keys.keys().filter(|k| k.0 == version).count();
        let resp = json!({ "etag": b.etag.to_string(), "count": count });
        self.rec("PUT", format!("/e2ee/backup/keys?version={version}"), Some(body), &resp);
        Ok(resp)
    }

    /// `GET /e2ee/backup/keys?version=`
    pub fn backup_keys_get(&mut self, auth: &Auth, version: &str) -> Value {
        let mut rooms: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
        if let Some(b) = self.backups.get(&auth.user) {
            for ((v, room, session), data) in &b.keys {
                if v == version {
                    rooms
                        .entry(room.clone())
                        .or_default()
                        .insert(session.clone(), data.clone());
                }
            }
        }
        let rooms: Map<String, Value> = rooms.into_iter().map(|(r, s)| (r, json!({ "sessions": s }))).collect();
        let resp = json!({ "rooms": rooms });
        self.rec("GET", format!("/e2ee/backup/keys?version={version}"), None, &resp);
        resp
    }
}

/// Envelope v1 (00-architecture §R5). Strict: unknown fields rejected (CR-03).
pub fn validate_envelope_v1(v: &Value) -> Result<(), &'static str> {
    let o = v.as_object().ok_or("not an object")?;
    const FIELDS: [&str; 5] = ["v", "algorithm", "session_id", "device_id", "ciphertext"];
    if o.keys().any(|k| !FIELDS.contains(&k.as_str())) {
        return Err("unknown field");
    }
    if o.get("v") != Some(&json!(1)) {
        return Err("unsupported version");
    }
    for f in &FIELDS[1..] {
        if !o.get(*f).is_some_and(Value::is_string) {
            return Err("missing field");
        }
    }
    if o["algorithm"] != "m.megolm.v1.aes-sha2" {
        return Err("unknown algorithm");
    }
    if o["ciphertext"].as_str().unwrap().len() > 16 * 1024 * 4 / 3 {
        return Err("too large");
    }
    Ok(())
}
