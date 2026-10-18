//! Mini own layer on vodozemac — only what S1 (DM roundtrip) and S4 (rotation
//! on member/device removal) need. Built to compare code volume honestly
//! against the matrix-sdk-crypto adapter (CR-01, "2 days" budget).
//!
//! Deliberately missing (all present in matrix-sdk-crypto): persistence, OTK
//! replenishment, fallback keys, device-list tracking/dirty flags, Olm session
//! unwedging, replay detection for Olm, key requests/forwarding, SAS, backup,
//! withheld codes, rotation by time/count, concurrency.

use std::collections::{BTreeSet, HashMap};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde_json::{Map, Value, json};
use spike_msc::fakeserver::{Auth, Server, StoredMessage};
use spike_msc::ids;
use vodozemac::megolm::{self, GroupSession, InboundGroupSession, MegolmMessage, SessionKey};
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature, base64_decode, base64_encode};

const OLM: &str = "m.olm.v1.curve25519-aes-sha2";
const MEGOLM: &str = "m.megolm.v1.aes-sha2";

#[derive(Clone)]
struct DeviceKeys {
    curve: Curve25519PublicKey,
    ed: Ed25519PublicKey,
}

struct Outbound {
    session: GroupSession,
    /// (user, device, curve25519)
    shared_with: BTreeSet<(String, String, String)>,
}

struct Inbound {
    session: InboundGroupSession,
    sender_user: String,
}

pub struct OwnMachine {
    pub auth: Auth,
    account: Account,
    olm: HashMap<String, Vec<Session>>,
    outbound: HashMap<String, Outbound>,
    inbound: HashMap<(String, String), Inbound>,
    devices: HashMap<(String, String), DeviceKeys>,
    server: Server,
}

/// Matrix canonical JSON (sufficient for ASCII content): drop `signatures` and
/// `unsigned`, sorted keys (serde_json's default BTreeMap), no whitespace.
fn canonical(v: &Value) -> String {
    let mut v = v.clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("signatures");
        o.remove("unsigned");
    }
    serde_json::to_string(&v).expect("json")
}

fn olm_to_json(m: &OlmMessage) -> Value {
    let (t, body) = m.to_parts();
    json!({ "type": t, "body": base64_encode(body) })
}

impl OwnMachine {
    pub fn new(server: &Server, user: &str, device: &str) -> Self {
        Self {
            auth: Auth {
                user: user.into(),
                device: device.into(),
            },
            account: Account::new(),
            olm: HashMap::new(),
            outbound: HashMap::new(),
            inbound: HashMap::new(),
            devices: HashMap::new(),
            server: server.clone(),
        }
    }

    fn uid(&self) -> String {
        ids::user_id(&self.auth.user).to_string()
    }

    fn sign(&self, v: &mut Value) {
        let sig = self.account.sign(canonical(v)).to_base64();
        let key = format!("ed25519:{}", self.auth.device);
        v["signatures"] = json!({ self.uid(): { key: sig } });
    }

    fn verify(&self, v: &Value, user: &str, device: &str, ed: &Ed25519PublicKey) -> Result<()> {
        let sig = v["signatures"][user][format!("ed25519:{device}")]
            .as_str()
            .context("no signature")?;
        let sig = Ed25519Signature::from_base64(sig)?;
        ed.verify(canonical(v).as_bytes(), &sig)
            .map_err(|e| anyhow!("bad signature: {e}"))
    }

    /// Device keys + 50 OTKs → `POST /e2ee/keys/upload`.
    pub fn upload_keys(&mut self) -> Result<()> {
        let keys = self.account.identity_keys();
        let d = &self.auth.device;
        let mut dk = json!({
            "user_id": self.uid(),
            "device_id": d,
            "algorithms": [OLM, MEGOLM],
            "keys": {
                format!("curve25519:{d}"): keys.curve25519.to_base64(),
                format!("ed25519:{d}"): keys.ed25519.to_base64(),
            },
        });
        self.sign(&mut dk);
        self.account.generate_one_time_keys(50);
        let mut otks = Map::new();
        for (id, k) in self.account.one_time_keys() {
            let mut o = json!({ "key": k.to_base64() });
            self.sign(&mut o);
            otks.insert(format!("signed_curve25519:{}", id.to_base64()), o);
        }
        let body = json!({ "device_keys": dk, "one_time_keys": otks });
        self.server
            .lock()
            .unwrap()
            .keys_upload(&self.auth, &body)
            .map_err(|e| anyhow!("{e:?}"))?;
        self.account.mark_keys_as_published();
        Ok(())
    }

    /// `keys/query` for users; verify self-signatures, TOFU on (user, device).
    fn query(&mut self, users: &[String]) -> Result<Vec<(String, String)>> {
        let req: Map<String, Value> = users.iter().map(|u| (ids::user_id(u).to_string(), json!([]))).collect();
        let resp = self
            .server
            .lock()
            .unwrap()
            .keys_query(&self.auth, &json!({ "device_keys": req }))
            .map_err(|e| anyhow!("{e:?}"))?;
        let mut out = Vec::new();
        for u in users {
            let mu = ids::user_id(u).to_string();
            for (d, k) in resp["device_keys"][&mu].as_object().into_iter().flatten() {
                ensure!(k["user_id"] == json!(mu) && k["device_id"] == json!(d), "id mismatch");
                let curve =
                    Curve25519PublicKey::from_base64(k["keys"][format!("curve25519:{d}")].as_str().context("curve")?)?;
                let ed = Ed25519PublicKey::from_base64(k["keys"][format!("ed25519:{d}")].as_str().context("ed")?)?;
                self.verify(k, &mu, d, &ed)?;
                let key = (u.clone(), d.clone());
                if let Some(old) = self.devices.get(&key) {
                    ensure!(
                        old.curve == curve && old.ed == ed,
                        "device keys changed for same device_id"
                    );
                }
                self.devices.insert(key, DeviceKeys { curve, ed });
                out.push((u.clone(), d.clone()));
            }
        }
        Ok(out)
    }

    /// Claim OTKs for devices without an Olm session.
    fn ensure_olm(&mut self, targets: &[(String, String)]) -> Result<()> {
        let mut req: Map<String, Value> = Map::new();
        for (u, d) in targets {
            let dk = &self.devices[&(u.clone(), d.clone())];
            if !self.olm.contains_key(&dk.curve.to_base64()) {
                req.entry(ids::user_id(u).to_string()).or_insert_with(|| json!({}))[d] = json!("signed_curve25519");
            }
        }
        if req.is_empty() {
            return Ok(());
        }
        let resp = self
            .server
            .lock()
            .unwrap()
            .keys_claim(&self.auth, &json!({ "one_time_keys": req }))
            .map_err(|e| anyhow!("{e:?}"))?;
        for (mu, devs) in resp["one_time_keys"].as_object().into_iter().flatten() {
            let u = ids::user_ulid(&ruma::UserId::parse(mu.as_str())?).context("user")?;
            for (d, keys) in devs.as_object().into_iter().flatten() {
                let (_, otk) = keys.as_object().and_then(|m| m.iter().next()).context("otk")?;
                let dk = self.devices[&(u.clone(), d.clone())].clone();
                self.verify(otk, mu, d, &dk.ed)?;
                let otk = Curve25519PublicKey::from_base64(otk["key"].as_str().context("key")?)?;
                let s = self
                    .account
                    .create_outbound_session(SessionConfig::version_1(), dk.curve, otk)?;
                self.olm.insert(dk.curve.to_base64(), vec![s]);
            }
        }
        Ok(())
    }

    fn olm_encrypt(&mut self, user: &str, device: &str, ev_type: &str, content: Value) -> Result<Value> {
        let dk = self.devices[&(user.to_owned(), device.to_owned())].clone();
        let plaintext = json!({
            "type": ev_type,
            "content": content,
            "sender": self.uid(),
            "recipient": ids::user_id(user).to_string(),
            "recipient_keys": { "ed25519": dk.ed.to_base64() },
            "keys": { "ed25519": self.account.ed25519_key().to_base64() },
        });
        let s = self
            .olm
            .get_mut(&dk.curve.to_base64())
            .and_then(|v| v.first_mut())
            .context("no olm session")?;
        let msg = s.encrypt(plaintext.to_string())?;
        Ok(json!({
            "algorithm": OLM,
            "sender_key": self.account.curve25519_key().to_base64(),
            "ciphertext": { dk.curve.to_base64(): olm_to_json(&msg) },
        }))
    }

    /// §3 п.2: query, rotate if a recipient disappeared, share the room key.
    pub fn prepare_send(&mut self, channel: &str) -> Result<()> {
        let members = self.server.lock().unwrap().channel_members(channel);
        let devices: Vec<(String, String)> = self
            .query(&members)?
            .into_iter()
            .filter(|(u, d)| !(u == &self.auth.user && d == &self.auth.device))
            .collect();
        let current: BTreeSet<(String, String, String)> = devices
            .iter()
            .map(|(u, d)| {
                (
                    u.clone(),
                    d.clone(),
                    self.devices[&(u.clone(), d.clone())].curve.to_base64(),
                )
            })
            .collect();
        if let Some(o) = self.outbound.get(channel)
            && !o.shared_with.is_subset(&current)
        {
            self.outbound.remove(channel); // member or device gone → rotate
        }
        if !self.outbound.contains_key(channel) {
            let session = GroupSession::new(megolm::SessionConfig::version_1());
            let inbound = InboundGroupSession::new(&session.session_key(), megolm::SessionConfig::version_1());
            self.inbound.insert(
                (channel.to_owned(), session.session_id()),
                Inbound {
                    session: inbound,
                    sender_user: self.auth.user.clone(),
                },
            );
            self.outbound.insert(
                channel.to_owned(),
                Outbound {
                    session,
                    shared_with: BTreeSet::new(),
                },
            );
        }
        let missing: Vec<(String, String, String)> = current
            .difference(&self.outbound[channel].shared_with)
            .cloned()
            .collect();
        let pairs: Vec<(String, String)> = missing.iter().map(|(u, d, _)| (u.clone(), d.clone())).collect();
        self.ensure_olm(&pairs)?;
        let (sid, skey) = {
            let o = &self.outbound[channel].session;
            (o.session_id(), o.session_key().to_base64())
        };
        let room_key = json!({
            "algorithm": MEGOLM,
            "room_id": ids::room_id(channel).to_string(),
            "session_id": sid,
            "session_key": skey,
        });
        let mut messages: Map<String, Value> = Map::new();
        for (u, d, _) in &missing {
            let c = self.olm_encrypt(u, d, "m.room_key", room_key.clone())?;
            messages.entry(ids::user_id(u).to_string()).or_insert_with(|| json!({}))[d] = c;
        }
        if !messages.is_empty() {
            let txn = self.server.lock().unwrap().next_ulid();
            let body = json!({ "type": "m.room.encrypted", "messages": messages });
            self.server
                .lock()
                .unwrap()
                .to_device_put(&self.auth, &txn, &body)
                .map_err(|e| anyhow!("{e:?}"))?;
        }
        self.outbound.get_mut(channel).unwrap().shared_with.extend(missing);
        Ok(())
    }

    pub fn send(&mut self, channel: &str, text: &str) -> Result<String> {
        self.prepare_send(channel)?;
        let o = self.outbound.get_mut(channel).unwrap();
        let plaintext = json!({
            "type": "stoat.message",
            "room_id": ids::room_id(channel).to_string(),
            "content": { "v": 1, "content": text },
        });
        let msg = o.session.encrypt(plaintext.to_string());
        let env = json!({
            "v": 1,
            "algorithm": MEGOLM,
            "session_id": o.session.session_id(),
            "device_id": self.auth.device,
            "ciphertext": msg.to_base64(),
        });
        self.server
            .lock()
            .unwrap()
            .message_send(&self.auth, channel, env, vec![])
            .map_err(|e| anyhow!("{e:?}"))
    }

    /// Inbox → Olm decrypt → `m.room_key` → inbound sessions → ack.
    pub fn receive(&mut self) -> Result<usize> {
        let inbox = self.server.lock().unwrap().to_device_get(&self.auth, 100);
        let mut ids_ = Vec::new();
        let mut keys = 0;
        for m in inbox["messages"].as_array().into_iter().flatten() {
            ids_.push(m["id"].clone());
            if m["type"] != "m.room.encrypted" || m["content"]["algorithm"] != OLM {
                continue;
            }
            let sender =
                ids::user_ulid(&ruma::UserId::parse(m["sender"].as_str().context("sender")?)?).context("user")?;
            let sender_dev = m["sender_device"].as_str().context("dev")?.to_owned();
            let my_curve = self.account.curve25519_key().to_base64();
            let c = &m["content"]["ciphertext"][&my_curve];
            let msg = OlmMessage::from_parts(
                c["type"].as_u64().context("type")? as usize,
                &base64_decode(c["body"].as_str().context("body")?)?,
            )?;
            let sender_key = Curve25519PublicKey::from_base64(m["content"]["sender_key"].as_str().context("sk")?)?;
            let plain = self.olm_decrypt(sender_key, &msg)?;
            let p: Value = serde_json::from_slice(&plain)?;
            // binding checks as in Matrix (against redirection to another device)
            if !self.devices.contains_key(&(sender.clone(), sender_dev.clone())) {
                self.query(std::slice::from_ref(&sender))?;
            }
            let dk = self
                .devices
                .get(&(sender.clone(), sender_dev.clone()))
                .context("unknown sender device")?;
            ensure!(dk.curve == sender_key, "sender_key is not the sender device's key");
            ensure!(
                p["sender"] == m["sender"] && p["recipient"] == json!(self.uid()),
                "olm binding"
            );
            ensure!(
                p["recipient_keys"]["ed25519"] == json!(self.account.ed25519_key().to_base64()),
                "recipient key"
            );
            ensure!(p["keys"]["ed25519"] == json!(dk.ed.to_base64()), "sender ed25519");
            if p["type"] == "m.room_key" {
                let rk = &p["content"];
                let channel = ids::channel_ulid(&ruma::RoomId::parse(rk["room_id"].as_str().context("room")?)?)
                    .context("room")?;
                let key = SessionKey::from_base64(rk["session_key"].as_str().context("sk")?)?;
                let s = InboundGroupSession::new(&key, megolm::SessionConfig::version_1());
                ensure!(
                    s.session_id() == rk["session_id"].as_str().unwrap_or_default(),
                    "session id"
                );
                self.inbound.insert(
                    (channel, s.session_id()),
                    Inbound {
                        session: s,
                        sender_user: sender.clone(),
                    },
                );
                keys += 1;
            }
        }
        if !ids_.is_empty() {
            self.server
                .lock()
                .unwrap()
                .to_device_ack(&self.auth, &json!({ "ids": ids_ }));
        }
        Ok(keys)
    }

    fn olm_decrypt(&mut self, sender_key: Curve25519PublicKey, msg: &OlmMessage) -> Result<Vec<u8>> {
        let sessions = self.olm.entry(sender_key.to_base64()).or_default();
        for s in sessions.iter_mut() {
            if let Ok(p) = s.decrypt(msg) {
                return Ok(p);
            }
        }
        match msg {
            OlmMessage::PreKey(pre) => {
                let r = self
                    .account
                    .create_inbound_session(SessionConfig::version_1(), sender_key, pre)?;
                self.olm.entry(sender_key.to_base64()).or_default().insert(0, r.session);
                Ok(r.plaintext)
            }
            OlmMessage::Normal(_) => bail!("no olm session can decrypt"),
        }
    }

    /// Envelope v1 → text, with channel and author binding.
    pub fn decrypt(&mut self, m: &StoredMessage) -> Result<String> {
        ensure!(
            m.encrypted["v"] == 1 && m.encrypted["algorithm"] == MEGOLM,
            "unsupported"
        );
        let sid = m.encrypted["session_id"].as_str().context("sid")?.to_owned();
        let inbound = self
            .inbound
            .get_mut(&(m.channel.clone(), sid))
            .context("MissingRoomKey")?;
        let msg = MegolmMessage::from_base64(m.encrypted["ciphertext"].as_str().context("ct")?)?;
        let d = inbound.session.decrypt(&msg)?;
        let p: Value = serde_json::from_slice(&d.plaintext)?;
        ensure!(
            p["room_id"] == json!(ids::room_id(&m.channel).to_string()),
            "ChannelMismatch"
        );
        ensure!(inbound.sender_user == m.author, "SenderMismatch");
        Ok(p["content"]["content"].as_str().unwrap_or_default().to_owned())
    }
}
