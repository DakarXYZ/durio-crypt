//! Spike adapter between Stoat (`/e2ee/*` JSON, ULIDs, envelope v1) and
//! `OlmMachine` (ruma types, Matrix IDs). Prototype of CR-20 + CR-19.
//!
//! The adapter never hands ruma types to the server: every request is turned
//! into plain JSON (what the backend sees), every response is plain JSON that is
//! parsed back with `IncomingResponse::try_from_http_response`, exactly like
//! `matrix-sdk-crypto-ffi` does.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use matrix_sdk_common::deserialized_responses::{ProcessedToDeviceEvent, VerificationLevel, VerificationState};
use matrix_sdk_crypto::{
    DecryptionSettings, EncryptionSettings, EventError, MegolmError, OlmMachine, OlmMachineBuilder, TrustRequirement,
    store::types::RoomKeyInfo,
    types::requests::{AnyOutgoingRequest, OutgoingVerificationRequest, ToDeviceRequest},
    vodozemac::megolm::{DecryptionError, MegolmMessage},
};
use matrix_sdk_sqlite::SqliteCryptoStore;
use ruma::{
    OneTimeKeyAlgorithm, OwnedUserId, TransactionId, UInt,
    api::{
        IncomingResponse, IncomingResponseExt,
        client::{
            backup::add_backup_keys::v3::Response as KeysBackupResponse,
            keys::{
                claim_keys::v3::Response as KeysClaimResponse, get_keys::v3::Response as KeysQueryResponse,
                upload_keys::v3::Response as KeysUploadResponse,
            },
            sync::sync_events::DeviceLists,
            to_device::send_event_to_device::v3::Response as ToDeviceResponse,
        },
    },
    events::{AnyMessageLikeEventContent, AnyToDeviceEvent},
    serde::Raw,
};
use serde_json::{Value, json};

use crate::fakeserver::{Auth, Server, StoredMessage};
use crate::ids;
use crate::payload::{EVENT_TYPE, EnvelopeV1, PayloadV1};

/// Trust shown by the UI (`shield()` input). Computed by the adapter: without
/// cross-signing matrix-sdk-crypto reports every device as `UnsignedDevice`,
/// so device-level SAS trust has to be looked up separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    Verified,
    Unverified,
    UnknownDevice,
    /// key from backup / forwarded without a verified chain
    Unauthenticated,
    /// author or device hint does not match the session owner
    Mismatch,
}

#[derive(Clone, Debug)]
pub struct Decrypted {
    pub payload: PayloadV1,
    pub sender_user: String,
    pub sender_device: Option<String>,
    pub verification: Verification,
    pub session_id: String,
    pub message_index: u32,
    pub is_replay: bool,
    /// edit with `edit_seq` not above the already shown one (T17)
    pub stale_edit: bool,
    /// `in_reply_to` ≠ open `replies` (CR-19)
    pub reply_mismatch: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecryptError {
    MissingRoomKey,
    UnknownAlgorithm,
    UnsupportedVersion,
    ChannelMismatch,
    SenderMismatch,
    Corrupted(String),
}

#[derive(Default, Debug)]
pub struct SyncReport {
    pub room_keys: Vec<RoomKeyInfo>,
    pub to_device_processed: usize,
    pub to_device_skipped_dupes: usize,
    pub olm_failures: Vec<String>,
}

pub struct Client {
    pub auth: Auth,
    pub machine: OlmMachine,
    server: Server,
    /// to-device ids processed (committed) but not yet acked (C2). Persisted
    /// atomically with the crypto changes through `next_batch_token`.
    processed: BTreeSet<String>,
    pub inbox_limit: usize,
    /// simulate a crash after processing but before `ack` (S12/T19)
    pub crash_before_ack: bool,
    /// set to false to turn the C2 duplicate filter off (S12 negative control)
    pub dedupe: bool,
    /// CR-19 replay table `(session_id, index) → message_id`
    replay: HashMap<(String, u32), String>,
    /// last shown `edit_seq` per original message
    edits: HashMap<String, u64>,
    pub settings: EncryptionSettings,
    /// every outgoing JSON request (method, path, body) — for fixtures
    pub sent: Vec<(String, String, Value)>,
}

fn decryption_settings() -> DecryptionSettings {
    // No cross-signing in v1 → device trust is ours, not the library's.
    DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    }
}

fn parse<R: IncomingResponse>(v: &Value) -> Result<R> {
    let bytes = serde_json::to_vec(v)?;
    let resp = http::Response::builder().status(200).body(bytes.as_slice())?;
    R::try_from_http_response(resp).map_err(|e| anyhow!("response parse: {e}"))
}

impl Client {
    pub async fn open_memory(server: &Server, user: &str, device: &str) -> Result<Self> {
        let machine = OlmMachine::new(&ids::user_id(user), &ids::device_id(device)).await;
        Self::from_machine(server, user, device, machine).await
    }

    /// SQLite store, values encrypted by `StoreCipher` with a raw 32-byte key
    /// (CR-09: no PBKDF2 on open).
    pub async fn open_sqlite(server: &Server, user: &str, device: &str, dir: &Path, key: &[u8; 32]) -> Result<Self> {
        let store = SqliteCryptoStore::open_with_key(dir, Some(key)).await?;
        let machine = OlmMachineBuilder::new(&ids::user_id(user), &ids::device_id(device))
            .with_crypto_store(store)
            .build()
            .await?;
        Self::from_machine(server, user, device, machine).await
    }

    async fn from_machine(server: &Server, user: &str, device: &str, machine: OlmMachine) -> Result<Self> {
        // restore the processed-but-unacked set committed with the last batch
        let processed = match machine.store().next_batch_token().await? {
            Some(t) => serde_json::from_str(&t).unwrap_or_default(),
            None => BTreeSet::new(),
        };
        Ok(Self {
            auth: Auth {
                user: user.to_owned(),
                device: device.to_owned(),
            },
            machine,
            server: server.clone(),
            processed,
            inbox_limit: 100,
            crash_before_ack: false,
            dedupe: true,
            replay: HashMap::new(),
            edits: HashMap::new(),
            settings: EncryptionSettings::default(),
            sent: Vec::new(),
        })
    }

    pub fn user_id(&self) -> OwnedUserId {
        ids::user_id(&self.auth.user)
    }

    // ------------------------------------------------------------ requests

    fn to_device_body(r: &ToDeviceRequest) -> Value {
        json!({ "type": r.event_type.to_string(), "messages": r.messages })
    }

    async fn send_to_device(&mut self, r: &ToDeviceRequest) -> Result<()> {
        let body = Self::to_device_body(r);
        self.sent
            .push(("PUT".into(), format!("/e2ee/to_device/{}", r.txn_id), body.clone()));
        let resp = self
            .server
            .lock()
            .unwrap()
            .to_device_put(&self.auth, r.txn_id.as_str(), &body)
            .map_err(|e| anyhow!("{e:?}"))?;
        let parsed: ToDeviceResponse = parse(&resp)?;
        self.machine.mark_request_as_sent(&r.txn_id, &parsed).await?;
        Ok(())
    }

    /// Execute one outgoing request against the fake server.
    async fn execute(&mut self, id: &TransactionId, req: &AnyOutgoingRequest) -> Result<()> {
        match req {
            AnyOutgoingRequest::KeysUpload(r) => {
                let mut body = serde_json::Map::new();
                if let Some(dk) = &r.device_keys {
                    body.insert("device_keys".into(), serde_json::to_value(dk)?);
                }
                if !r.one_time_keys.is_empty() {
                    body.insert("one_time_keys".into(), serde_json::to_value(&r.one_time_keys)?);
                }
                if !r.fallback_keys.is_empty() {
                    body.insert("fallback_keys".into(), serde_json::to_value(&r.fallback_keys)?);
                }
                let body = Value::Object(body);
                self.sent
                    .push(("POST".into(), "/e2ee/keys/upload".into(), body.clone()));
                let resp = self
                    .server
                    .lock()
                    .unwrap()
                    .keys_upload(&self.auth, &body)
                    .map_err(|e| anyhow!("{e:?}"))?;
                let parsed: KeysUploadResponse = parse(&resp)?;
                self.machine.mark_request_as_sent(id, &parsed).await?;
            }
            AnyOutgoingRequest::KeysQuery(r) => {
                let body = json!({ "device_keys": r.device_keys });
                self.sent.push(("POST".into(), "/e2ee/keys/query".into(), body.clone()));
                let resp = self
                    .server
                    .lock()
                    .unwrap()
                    .keys_query(&self.auth, &body)
                    .map_err(|e| anyhow!("{e:?}"))?;
                let parsed: KeysQueryResponse = parse(&resp)?;
                self.machine.mark_request_as_sent(id, &parsed).await?;
            }
            AnyOutgoingRequest::KeysClaim(r) => {
                let body = json!({ "one_time_keys": r.one_time_keys });
                self.sent.push(("POST".into(), "/e2ee/keys/claim".into(), body.clone()));
                let resp = self
                    .server
                    .lock()
                    .unwrap()
                    .keys_claim(&self.auth, &body)
                    .map_err(|e| anyhow!("{e:?}"))?;
                let parsed: KeysClaimResponse = parse(&resp)?;
                self.machine.mark_request_as_sent(id, &parsed).await?;
            }
            AnyOutgoingRequest::ToDeviceRequest(r) => {
                let r = r.clone();
                self.send_to_device(&r).await?;
            }
            AnyOutgoingRequest::SignatureUpload(_) => {
                bail!("unexpected signature upload (cross-signing is out of v1)")
            }
            AnyOutgoingRequest::RoomMessage(_) => bail!("unexpected in-room verification"),
            #[allow(unreachable_patterns)]
            _ => bail!("unexpected request kind"),
        }
        Ok(())
    }

    /// Flush `outgoing_requests()` (+ pending backup upload). Returns true if
    /// anything was sent.
    pub async fn flush_outgoing(&mut self) -> Result<bool> {
        let mut any = false;
        let reqs = self.machine.outgoing_requests().await?;
        for r in reqs {
            any = true;
            self.execute(r.request_id(), r.request()).await?;
        }
        // users whose Olm session must be (re)created outside of a room send:
        // pending key-forward answers and unwedging (matrix-sdk does the same
        // `get_missing_sessions(empty)` after each sync)
        if let Some((id, claim)) = self.machine.get_missing_sessions(std::iter::empty()).await? {
            any = true;
            self.execute(&id, &AnyOutgoingRequest::KeysClaim(claim)).await?;
        }
        if let Some((id, req)) = self.machine.backup_machine().backup().await? {
            any = true;
            let body = json!({ "rooms": req.rooms });
            self.sent.push((
                "PUT".into(),
                format!("/e2ee/backup/keys?version={}", req.version),
                body.clone(),
            ));
            let resp = self
                .server
                .lock()
                .unwrap()
                .backup_keys_put(&self.auth, &req.version, &body)
                .map_err(|e| anyhow!("{e:?}"))?;
            // our response is `{etag, count}` — the Matrix shape
            let parsed: KeysBackupResponse = parse(&resp)?;
            self.machine.mark_request_as_sent(&id, &parsed).await?;
        }
        Ok(any)
    }

    /// One pass over the inbox + WS events + OTK counts.
    pub async fn receive(&mut self, report: &mut SyncReport) -> Result<bool> {
        let (ws, inbox, counts) = {
            let mut s = self.server.lock().unwrap();
            let ws = s.ws_take(&self.auth);
            let inbox = s.to_device_get(&self.auth, self.inbox_limit);
            let counts = s.keys_count(&self.auth);
            (ws, inbox, counts)
        };

        let mut changed: Vec<OwnedUserId> = ws
            .iter()
            .filter(|e| e["type"] == "E2eeDeviceListUpdate")
            .filter_map(|e| e["user"].as_str())
            .map(ids::user_id)
            .collect();
        changed.sort();
        changed.dedup();

        let mut batch_ids = Vec::new();
        let mut events: Vec<(String, Raw<AnyToDeviceEvent>)> = Vec::new();
        let mut seen_in_batch = BTreeSet::new();
        for m in inbox["messages"].as_array().into_iter().flatten() {
            let id = m["id"].as_str().context("id")?.to_owned();
            batch_ids.push(id.clone());
            if self.dedupe && (self.processed.contains(&id) || !seen_in_batch.insert(id.clone())) {
                report.to_device_skipped_dupes += 1;
                continue;
            }
            // our inbox item → Matrix to-device event (`sender`, `type`, `content`)
            let ev = json!({ "sender": m["sender"], "type": m["type"], "content": m["content"] });
            events.push((id, Raw::from_json(serde_json::value::to_raw_value(&ev)?)));
        }

        let otk_counts: BTreeMap<OneTimeKeyAlgorithm, UInt> =
            serde_json::from_value(counts["one_time_key_counts"].clone())?;
        let fallback: Vec<OneTimeKeyAlgorithm> =
            serde_json::from_value(counts["device_unused_fallback_key_types"].clone())?;
        let mut device_lists = DeviceLists::new();
        device_lists.changed = changed.clone();

        // One event per `receive_sync_changes` call, in server order (CR-05):
        // a room key and a key request for it arriving in the same batch are
        // otherwise handled before the key is stored ("unknown session"), and
        // the C2 processed-set (`next_batch_token`) is committed per event.
        let mut processed = self.processed.clone();
        // ids we skip as duplicates are still "processed"
        processed.extend(
            batch_ids
                .iter()
                .filter(|i| !events.iter().any(|(e, _)| e == *i))
                .cloned(),
        );
        let n_events = events.len();
        let mut first = true;
        let mut queue: Vec<Option<(String, Raw<AnyToDeviceEvent>)>> = events.into_iter().map(Some).collect();
        if queue.is_empty() {
            queue.push(None); // still feed OTK counts / device lists
        }
        let empty_lists = DeviceLists::new();
        for item in queue {
            let (ev, id) = match item {
                Some((id, ev)) => (vec![ev], Some(id)),
                None => (vec![], None),
            };
            if let Some(id) = &id {
                processed.insert(id.clone());
            }
            let token = serde_json::to_string(&processed)?;
            let (evs, keys) = self
                .machine
                .receive_sync_changes(
                    matrix_sdk_crypto::EncryptionSyncChanges {
                        to_device_events: ev,
                        changed_devices: if first { &device_lists } else { &empty_lists },
                        one_time_keys_counts: &otk_counts,
                        unused_fallback_keys: Some(&fallback),
                        next_batch_token: Some(token),
                    },
                    &decryption_settings(),
                )
                .await?;
            first = false;
            report.room_keys.extend(keys);
            for e in &evs {
                if let ProcessedToDeviceEvent::UnableToDecrypt { utd_info, .. } = e {
                    report.olm_failures.push(format!("{:?}", utd_info.reason));
                }
            }
        }
        self.processed = processed;
        report.to_device_processed += n_events;

        if !batch_ids.is_empty() && !self.crash_before_ack {
            let body = json!({ "ids": batch_ids });
            self.sent
                .push(("POST".into(), "/e2ee/to_device/ack".into(), body.clone()));
            self.server.lock().unwrap().to_device_ack(&self.auth, &body);
            for id in &batch_ids {
                self.processed.remove(id);
            }
        }
        Ok(!batch_ids.is_empty() || !changed.is_empty())
    }

    /// Drive requests + inbox until quiescent.
    pub async fn sync(&mut self) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        for _ in 0..32 {
            let a = self.flush_outgoing().await?;
            let b = self.receive(&mut report).await?;
            if !a && !b {
                return Ok(report);
            }
            if self.crash_before_ack && b {
                // a crashed client would stop here
                return Ok(report);
            }
        }
        Ok(report)
    }

    // -------------------------------------------------------------- send

    /// §3 п.2: track members, query keys, claim OTKs, share the room key.
    pub async fn prepare_send(&mut self, channel: &str) -> Result<()> {
        let members: Vec<OwnedUserId> = self
            .server
            .lock()
            .unwrap()
            .channel_members(channel)
            .iter()
            .map(|u| ids::user_id(u))
            .collect();
        self.machine
            .update_tracked_users(members.iter().map(|u| u.as_ref()))
            .await?;
        self.sync().await?;
        if let Some((id, claim)) = self
            .machine
            .get_missing_sessions(members.iter().map(|u| u.as_ref()))
            .await?
        {
            self.execute(&id, &AnyOutgoingRequest::KeysClaim(claim)).await?;
        }
        let reqs = self
            .machine
            .share_room_key(
                &ids::room_id(channel),
                members.iter().map(|u| u.as_ref()),
                self.settings.clone(),
            )
            .await?;
        for r in reqs {
            self.send_to_device(&r).await?;
        }
        Ok(())
    }

    /// Encrypt into envelope v1.
    pub async fn encrypt(&mut self, channel: &str, payload: &PayloadV1) -> Result<EnvelopeV1> {
        let content = payload.to_padded_json();
        let raw: Raw<AnyMessageLikeEventContent> = Raw::from_json(serde_json::value::to_raw_value(&content)?);
        let res = self
            .machine
            .encrypt_room_event_raw(&ids::room_id(channel), EVENT_TYPE, &raw)
            .await?;
        let c: Value = serde_json::from_str(res.content.json().get())?;
        Ok(EnvelopeV1 {
            v: 1,
            algorithm: c["algorithm"].as_str().context("algorithm")?.to_owned(),
            session_id: c["session_id"].as_str().context("session_id")?.to_owned(),
            device_id: self.auth.device.clone(),
            ciphertext: c["ciphertext"].as_str().context("ciphertext")?.to_owned(),
        })
    }

    pub async fn send(&mut self, channel: &str, payload: &PayloadV1) -> Result<String> {
        self.prepare_send(channel).await?;
        let env = self.encrypt(channel, payload).await?;
        let replies = payload.in_reply_to.clone();
        let id = self
            .server
            .lock()
            .unwrap()
            .message_send(&self.auth, channel, serde_json::to_value(&env)?, replies)
            .map_err(|e| anyhow!("{e:?}"))?;
        Ok(id)
    }

    // ----------------------------------------------------------- decrypt

    /// Stoat message → `Raw<EncryptedEvent>` → `decrypt_room_event`, then the
    /// CR-19 checks (replay, edit rollback, reply binding) and the shield.
    pub async fn decrypt(&mut self, m: &StoredMessage) -> Result<Decrypted, DecryptError> {
        if m.encrypted.get("v") != Some(&json!(1)) {
            return Err(DecryptError::UnsupportedVersion);
        }
        let env: EnvelopeV1 =
            serde_json::from_value(m.encrypted.clone()).map_err(|e| DecryptError::Corrupted(e.to_string()))?;
        if env.algorithm != "m.megolm.v1.aes-sha2" {
            return Err(DecryptError::UnknownAlgorithm);
        }
        let room = ids::room_id(&m.channel);
        let event = json!({
            "type": "m.room.encrypted",
            "sender": ids::user_id(&m.author),
            "event_id": format!("${}", m.id),
            "origin_server_ts": m.ts,
            "room_id": room,
            "content": {
                "algorithm": env.algorithm,
                "ciphertext": env.ciphertext,
                "session_id": env.session_id,
                "device_id": env.device_id,
            },
        });
        let raw = Raw::from_json(serde_json::value::to_raw_value(&event).unwrap());
        // make sure the author's devices are known (tracked users → keys/query),
        // otherwise the sender device cannot be linked to the session
        let author = ids::user_id(&m.author);
        if !self
            .machine
            .tracked_users()
            .await
            .map(|t| t.contains(&author))
            .unwrap_or(true)
        {
            let _ = self.machine.update_tracked_users([author.as_ref()]).await;
            let _ = self.flush_outgoing().await;
        }
        let res = self
            .machine
            .decrypt_room_event(&raw, &room, &decryption_settings())
            .await
            .map_err(|e| match e {
                MegolmError::MissingRoomKey(_) => DecryptError::MissingRoomKey,
                MegolmError::Decryption(DecryptionError::UnknownMessageIndex(..)) => DecryptError::MissingRoomKey,
                MegolmError::EventError(EventError::MismatchedRoom(..)) => DecryptError::ChannelMismatch,
                MegolmError::EventError(EventError::UnsupportedAlgorithm) => DecryptError::UnknownAlgorithm,
                MegolmError::MismatchedIdentityKeys(_) => DecryptError::SenderMismatch,
                MegolmError::EventError(EventError::MismatchedSender(..)) => DecryptError::SenderMismatch,
                other => DecryptError::Corrupted(other.to_string()),
            })?;

        let ev: Value =
            serde_json::from_str(res.event.json().get()).map_err(|e| DecryptError::Corrupted(e.to_string()))?;
        if ev["type"] != EVENT_TYPE {
            return Err(DecryptError::Corrupted("unexpected plaintext type".into()));
        }
        let payload: PayloadV1 =
            serde_json::from_value(ev["content"].clone()).map_err(|e| DecryptError::Corrupted(e.to_string()))?;
        if payload.v != 1 {
            return Err(DecryptError::UnsupportedVersion);
        }

        let info = &res.encryption_info;
        let session_id = info.session_id().unwrap_or_default().to_owned();
        let index = MegolmMessage::from_base64(&env.ciphertext)
            .map_err(|e| DecryptError::Corrupted(e.to_string()))?
            .message_index();

        // CR-19 replay: same (session, index) with another message id
        let is_replay = match self.replay.get(&(session_id.clone(), index)) {
            Some(prev) => prev != &m.id,
            None => {
                self.replay.insert((session_id.clone(), index), m.id.clone());
                false
            }
        };

        // edits: monotonic edit_seq per original (T17)
        let stale_edit = match &payload.edit_of {
            Some(orig) => {
                let shown = self.edits.get(orig).copied();
                if shown.is_some_and(|s| payload.edit_seq <= s) {
                    true
                } else {
                    self.edits.insert(orig.clone(), payload.edit_seq);
                    false
                }
            }
            None => false,
        };
        let reply_mismatch = payload.in_reply_to != m.replies;

        let sender_device = info.sender_device.as_ref().map(|d| d.to_string());
        // key source: backup import / forwarding → never better than Unauthenticated
        let indirect = match self.machine.store().get_inbound_group_session(&room, &session_id).await {
            Ok(Some(s)) => s.has_been_imported() || s.forwarder_data.is_some(),
            _ => false,
        };
        let verification = match &info.verification_state {
            VerificationState::Unverified(VerificationLevel::MismatchedSender) => Verification::Mismatch,
            VerificationState::Unverified(VerificationLevel::None(
                matrix_sdk_common::deserialized_responses::DeviceLinkProblem::InsecureSource,
            )) => Verification::Unauthenticated,
            _ if indirect => Verification::Unauthenticated,
            _ => match &sender_device {
                None => Verification::UnknownDevice,
                Some(d) if d != &env.device_id => Verification::Mismatch,
                Some(d) => match self.machine.get_device(&info.sender, d.as_str().into(), None).await {
                    Ok(Some(dev)) if dev.is_verified() => Verification::Verified,
                    Ok(Some(_)) => Verification::Unverified,
                    _ => Verification::UnknownDevice,
                },
            },
        };

        Ok(Decrypted {
            payload,
            sender_user: ids::user_ulid(&info.sender).unwrap_or_default(),
            sender_device,
            verification,
            session_id,
            message_index: index,
            is_replay,
            stale_edit,
            reply_mismatch,
        })
    }

    // ------------------------------------------------------------- backup

    /// Upload a backup version (`m.megolm_backup.v1.curve25519-aes-sha2`) and
    /// enable it. Returns the base58 recovery key.
    pub async fn enable_backup(&mut self) -> Result<String> {
        let key = matrix_sdk_crypto::store::types::BackupDecryptionKey::new();
        let info = key.to_backup_info();
        let body = serde_json::to_value(&info)?;
        self.sent
            .push(("POST".into(), "/e2ee/backup/version".into(), body.clone()));
        let resp = self
            .server
            .lock()
            .unwrap()
            .backup_version_create(&self.auth, &body)
            .map_err(|e| anyhow!("{e:?}"))?;
        let version = resp["version"].as_str().context("version")?.to_owned();
        let pk = key.megolm_v1_public_key();
        pk.set_version(version.clone());
        self.machine.backup_machine().enable_backup_v1(pk).await?;
        self.machine
            .backup_machine()
            .save_decryption_key(Some(key.clone()), Some(version))
            .await?;
        Ok(key.to_base58())
    }

    /// Restore from server backup with the recovery key (T3).
    pub async fn restore_backup(&mut self, recovery_key: &str) -> Result<usize> {
        use matrix_sdk_crypto::store::types::BackupDecryptionKey;
        use ruma::api::client::backup::KeyBackupData;
        let key = BackupDecryptionKey::from_base58(recovery_key)?;
        let (version, auth_info) = {
            let mut s = self.server.lock().unwrap();
            let v = s.backup_version_get(&self.auth).map_err(|e| anyhow!("{e:?}"))?;
            (v["version"].as_str().context("version")?.to_owned(), v)
        };
        let info: matrix_sdk_crypto::types::RoomKeyBackupInfo =
            serde_json::from_value(json!({"algorithm": auth_info["algorithm"], "auth_data": auth_info["auth_data"]}))?;
        if !key.backup_key_matches(&info) {
            bail!("recovery key does not match backup");
        }
        let all = self.server.lock().unwrap().backup_keys_get(&self.auth, &version);
        let mut exported = Vec::new();
        for (room, r) in all["rooms"].as_object().into_iter().flatten() {
            let room_id = ruma::RoomId::parse(room)?;
            for (session_id, data) in r["sessions"].as_object().into_iter().flatten() {
                let data: KeyBackupData = serde_json::from_value(data.clone())?;
                let backed_up = key.decrypt_session_data(data.session_data)?;
                exported.push(matrix_sdk_crypto::olm::ExportedRoomKey::from_backed_up_room_key(
                    room_id.clone(),
                    session_id.clone(),
                    backed_up,
                ));
            }
        }
        let res = self
            .machine
            .store()
            .import_room_keys(exported, Some(&version), |_, _| {})
            .await?;
        Ok(res.imported_count)
    }

    // ------------------------------------------------------------ helpers

    pub async fn verification_outgoing(&mut self, r: OutgoingVerificationRequest) -> Result<()> {
        match r {
            OutgoingVerificationRequest::ToDevice(t) => self.send_to_device(&t).await,
            OutgoingVerificationRequest::InRoom(_) => bail!("in-room verification not used"),
        }
    }
}
