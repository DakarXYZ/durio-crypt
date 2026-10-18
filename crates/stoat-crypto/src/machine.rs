//! `CryptoMachine`: the core's façade over `OlmMachine` (API sketch of
//! 20-crypto-core). The client does all HTTP; the machine produces requests
//! and consumes responses, to-device batches, WS events and messages.
//!
//! Adapter rules (ADR 0001):
//! 1. to-device events go to the library one by one, in server order;
//! 2. `get_missing_sessions(∅)` after each pass — part of `outgoing_requests`;
//! 3. self and every member of an encrypted channel are tracked;
//! 4. the library's `sender_key` is never forwarded, `device_id` is a hint;
//! 5. one writer per account: file lock on open (CR-17) and serialized
//!    mailbox processing / per-channel sending inside the machine.
//!
//! Requests are cached, cut to the server limits and retried by the outbox;
//! missing room keys are asked for by `gossip` (CR-08); replay and edit
//! tables are `binding` (CR-19).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::Duration;

use async_lock::Mutex;
use futures_util::FutureExt;
use matrix_sdk_common::deserialized_responses::{
    DeviceLinkProblem, ProcessedToDeviceEvent, VerificationLevel, VerificationState, WithheldCode,
};
use matrix_sdk_crypto::vodozemac::megolm::{DecryptionError, MegolmMessage};
use matrix_sdk_crypto::{
    CollectStrategy, DecryptionSettings, EncryptionSettings, EncryptionSyncChanges, EventError, LocalTrust,
    MegolmError, OlmMachine, TrustRequirement,
};
use ruma::api::client::sync::sync_events::DeviceLists;
use ruma::events::{AnyMessageLikeEventContent, AnyToDeviceEvent};
use ruma::serde::Raw;
use ruma::{OneTimeKeyAlgorithm, OwnedRoomId, OwnedUserId, UInt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use stoat_crypto_proto::api::{KeysCountResponse, ToDeviceMessage};
use stoat_crypto_proto::envelope::{EncryptedEnvelope, MAX_CIPHERTEXT_LEN};
use stoat_crypto_proto::payload::{EVENT_TYPE, MegolmPlaintext, MessagePayload, PayloadError};

use crate::backup::PendingRecovery;
use crate::batch::ServerLimits;
use crate::binding::{self, Seen};
use crate::error::{CryptoError, DecryptError, Result, WithheldReason};
use crate::gossip::{self, KeyRequests};
use crate::ids;
use crate::outbox::{self, KV_RETRIES, Outbox, PartMark, Timing, UndeliveredDevice};
use crate::requests::{self, OutgoingRequest, RequestKind, Response};
use crate::store::{self, Opened, StoreConfig};
use crate::types::*;
use crate::verification::{self, Flows};

/// Prefix of our values in the library's custom-value table
const KV_CHANNEL: &str = "stoat.channel.";
/// Every channel ever set up (moved-message detection)
const KV_CHANNELS: &str = "stoat.channels.v1";
/// Channels scanned at most for a session of a missing key
const MAX_CHANNEL_SCAN: usize = 512;

/// Persisted members and settings of an encrypted channel
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChannelState {
    /// Member user ids (ULIDs), self included
    members: BTreeSet<String>,
    settings: ChannelEncryptionSettings,
}

fn decryption_settings() -> DecryptionSettings {
    // no cross-signing in v1: device trust is computed by the core
    DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    }
}

fn store_err<E>(op: &'static str) -> impl FnOnce(E) -> CryptoError {
    move |_| CryptoError::Store(op)
}

/// Core crypto state of one account on one server
#[derive(Clone, Debug)]
pub struct CryptoMachine {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    machine: OlmMachine,
    user_ulid: String,
    device_ulid: String,
    user_id: OwnedUserId,
    /// C2: mailbox ids processed (committed) but not acknowledged yet; the lock
    /// also serializes everything that goes through `receive_sync_changes`
    sync: Mutex<BTreeSet<String>>,
    channels: Mutex<HashMap<String, ChannelState>>,
    /// `KV_CHANNELS`, loaded on first use
    known_channels: Mutex<Option<BTreeSet<String>>>,
    /// per-channel send lock: `prepare_send` + `encrypt` never interleave
    send_locks: SyncMutex<HashMap<String, Arc<Mutex<()>>>>,
    /// cached library requests, the claim in flight, parts, retries
    outbox: Mutex<Outbox>,
    /// something changed since the library requests were cached
    dirty: AtomicBool,
    timing: SyncMutex<Timing>,
    /// CR-08: missing room keys waiting to be asked for
    key_requests: SyncMutex<KeyRequests>,
    /// CR-19 tables
    binding: binding::Tables,
    /// CR-11: verification flows and their last state
    flows: SyncMutex<Flows>,
    /// CR-12: a backup being set up, until the server created the version
    recovery: Mutex<Option<PendingRecovery>>,
    /// dropped last: the store must close before the lock is released
    _opened_lock: StoreLockHolder,
}

#[derive(Debug)]
struct StoreLockHolder {
    #[cfg(not(target_arch = "wasm32"))]
    _lock: Option<crate::lock::StoreLock>,
}

impl CryptoMachine {
    // ------------------------------------------------------------ lifecycle

    /// Open (or create) the crypto state of `user` (ULID) on this device
    /// (session ULID). Fails with `StoreLocked` if another instance has the
    /// store open, `StoreMismatch` if it belongs to another account.
    // wasm is single-threaded: the library types are not `Send` there
    #[cfg_attr(target_arch = "wasm32", allow(clippy::arc_with_non_send_sync))]
    pub async fn open(user: &str, device: &str, store: StoreConfig) -> Result<Self> {
        let user_id = ids::user_id(user)?;
        let device_id = ids::device_id(device)?;
        let Opened {
            machine,
            #[cfg(not(target_arch = "wasm32"))]
            lock,
        } = store::open(&user_id, &device_id, &store).await?;

        // C2: the processed-but-unacked set committed with the last batch
        let processed = match machine
            .store()
            .next_batch_token()
            .await
            .map_err(store_err("read token"))?
        {
            Some(t) => serde_json::from_str(&t).unwrap_or_default(),
            None => BTreeSet::new(),
        };
        // rule 3: always track ourselves (own devices for SAS and key forwarding)
        machine
            .update_tracked_users([user_id.as_ref()])
            .await
            .map_err(store_err("track self"))?;
        // CR-08: key requests are debounced and filtered by the core
        machine.set_room_key_requests_enabled(false);
        let outbox = Outbox::with_retries(
            machine
                .store()
                .get_value(KV_RETRIES)
                .await
                .map_err(store_err("read retries"))?
                .unwrap_or_default(),
        );

        let this = Self {
            inner: Arc::new(Inner {
                machine,
                user_ulid: user.to_ascii_uppercase(),
                device_ulid: device.to_owned(),
                user_id,
                sync: Mutex::new(processed),
                channels: Mutex::new(HashMap::new()),
                known_channels: Mutex::new(None),
                send_locks: SyncMutex::new(HashMap::new()),
                outbox: Mutex::new(outbox),
                dirty: AtomicBool::new(true),
                timing: SyncMutex::new(Timing::default()),
                key_requests: SyncMutex::new(KeyRequests::default()),
                binding: binding::Tables::default(),
                flows: SyncMutex::new(Flows::default()),
                recovery: Mutex::new(None),
                _opened_lock: StoreLockHolder {
                    #[cfg(not(target_arch = "wasm32"))]
                    _lock: lock,
                },
            }),
        };
        // CR-12: keep backing up; secrets not confirmed by the server go again
        this.resume_backup().await?;
        for p in this.pending_secrets().await? {
            this.add_own_request(p.request()).await;
        }
        Ok(this)
    }

    /// Delete the store of a signed-out account (files, not rows). The
    /// machine must be closed (dropped) first, else `StoreLocked`.
    pub fn destroy(store: &StoreConfig) -> Result<()> {
        store::destroy(store)
    }

    pub fn user_id(&self) -> &str {
        &self.inner.user_ulid
    }

    pub fn device_id(&self) -> &str {
        &self.inner.device_ulid
    }

    pub fn identity_keys(&self) -> IdentityKeys {
        let k = self.inner.machine.identity_keys();
        IdentityKeys {
            curve25519: k.curve25519.to_base64(),
            ed25519: k.ed25519.to_base64(),
        }
    }

    pub(crate) fn olm(&self) -> &OlmMachine {
        &self.inner.machine
    }

    pub(crate) fn key_requests(&self) -> &SyncMutex<KeyRequests> {
        &self.inner.key_requests
    }

    pub(crate) fn flows(&self) -> std::sync::MutexGuard<'_, Flows> {
        self.inner.flows.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A to-device request of the core itself (verification, cancellations)
    pub(crate) async fn add_own_request(&self, r: OutgoingRequest) {
        self.inner.outbox.lock().await.add_own(r);
        self.touch();
    }

    // ------------------------------------------------------------- requests

    /// Server limits from `GET /` → `features.e2ee` (`max_to_device_batch`,
    /// `max_request_bytes`). Until called, the backend defaults apply.
    pub async fn set_server_limits(&self, limits: ServerLimits) {
        self.inner.outbox.lock().await.limits = limits;
    }

    /// Delays of the core's own policies (key request debounce, retries of
    /// full mailboxes)
    pub async fn set_timing(&self, timing: Timing) {
        *self.inner.timing.lock().unwrap_or_else(|e| e.into_inner()) = timing;
        self.inner.outbox.lock().await.timing = timing;
    }

    fn timing(&self) -> Timing {
        *self.inner.timing.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) async fn recovery_pending(&self) -> async_lock::MutexGuard<'_, Option<PendingRecovery>> {
        self.inner.recovery.lock().await
    }

    /// Something the library requests depend on changed
    pub(crate) fn touch(&self) {
        self.inner.dirty.store(true, Ordering::SeqCst);
    }

    /// Refresh the cached library requests if something changed. A key query
    /// in flight holds the refresh back (the library would forget it), unless
    /// `force`: a send needs the member keys now.
    async fn refresh(&self, ob: &mut Outbox, force: bool) -> Result<()> {
        if !self.inner.dirty.load(Ordering::SeqCst) || (ob.query_in_flight() && !force) {
            return Ok(());
        }
        self.inner.dirty.store(false, Ordering::SeqCst);
        let mut fresh = Vec::new();
        for r in self
            .olm()
            .outgoing_requests()
            .await
            .map_err(store_err("outgoing requests"))?
        {
            if let Some(r) = requests::from_library(r.request_id(), r.request())? {
                fresh.push(r);
            }
        }
        ob.refreshed(fresh);
        Ok(())
    }

    /// Requests to perform now: key upload, key queries, to-device (key
    /// requests and forwards, verification, retries) and the Olm sessions the
    /// library needs outside of a send (rule 2).
    ///
    /// A request keeps its id until it is marked: calling again before that
    /// returns it again (the host runs each id once, see the crate docs).
    pub async fn outgoing_requests(&self) -> Result<Vec<OutgoingRequest>> {
        let olm = self.olm();
        // CR-11: the library cancels timed-out verifications when it
        // garbage-collects, which happens in `receive_sync_changes`
        if self.flows().any_active() {
            self.refresh_flows();
            let processed = self.inner.sync.lock().await;
            self.sync_changes(&processed, vec![], &DeviceLists::new(), None).await?;
            drop(processed);
            self.refresh_flows();
            self.touch();
        }
        let asked = gossip::request_due(&self.inner.key_requests, olm).await?;
        if !asked.is_empty() {
            self.touch();
        }
        let mut ob = self.inner.outbox.lock().await;
        self.refresh(&mut ob, false).await?;
        let mut library = ob.cached.clone();
        library.extend(asked);
        if ob.claim.is_none()
            && let Some((id, req)) = olm
                .get_missing_sessions(std::iter::empty())
                .await
                .map_err(store_err("missing sessions"))?
        {
            ob.claim = Some(requests::keys_claim(&id, &req)?);
        }
        library.extend(ob.claim.clone());

        let mut out: Vec<OutgoingRequest> = Vec::new();
        for r in library {
            for r in ob.expand(r) {
                if !out.iter().any(|o| o.id == r.id) {
                    out.push(r);
                }
            }
        }
        out.extend(ob.own_and_due());
        drop(ob);
        // CR-12: the next batch of room keys for the backup (one in flight;
        // the library hands out the same request until it is marked)
        out.extend(self.backup_request().await?);
        Ok(out)
    }

    /// Report a successful response (`body` = response JSON; may be empty
    /// for 204)
    pub async fn mark_request_sent(&self, id: &str, kind: RequestKind, body: &str) -> Result<()> {
        // CR-12: our own requests, not the library's
        match kind {
            RequestKind::BackupVersionCreate => return self.backup_version_created(id, body).await,
            RequestKind::BackupKeys => return self.backup_keys_sent(id, body).await,
            RequestKind::SecretPut => {
                self.inner.outbox.lock().await.own_done(id);
                return self.secret_stored(id).await;
            }
            _ => {}
        }
        let response = Response::parse(kind, body)?;
        self.touch();
        let mut ob = self.inner.outbox.lock().await;
        if kind == RequestKind::ToDevice {
            // full mailboxes (`failed`) are retried with the same content
            let retry = ob.is_retry(id);
            if ob.delivered(id, body) {
                self.save_retries(&ob).await?;
            }
            if retry {
                return Ok(());
            }
            if ob.is_own(id) {
                ob.own_done(id);
                return Ok(());
            }
        }
        match ob.part_sent(id, body) {
            PartMark::NotAPart => response.mark_sent(self.olm(), id).await?,
            PartMark::Pending => return Ok(()),
            PartMark::Finished { parent, body } => {
                Response::parse(kind, &body)?.mark_sent(self.olm(), &parent).await?;
                ob.forget(&parent);
            }
        }
        ob.forget(id);
        Ok(())
    }

    /// Report an HTTP failure. The request (or the part of it) comes back
    /// from `outgoing_requests` / `prepare_send`; a 409 on our own key upload
    /// means the server has other keys for this device.
    pub async fn mark_request_failed(&self, id: &str, kind: RequestKind, status: u16) -> Result<()> {
        self.touch();
        match (kind, status) {
            // run the same request again with `x-mfa-ticket`
            (RequestKind::BackupVersionCreate, 401 | 403) => return Err(CryptoError::MfaRequired),
            (RequestKind::BackupVersionCreate, _) => return Ok(()),
            (RequestKind::BackupKeys, 404 | 409) => return self.backup_replaced().await,
            // the library keeps the batch and hands it out again
            (RequestKind::BackupKeys, _) => return Ok(()),
            _ => {}
        }
        let mut ob = self.inner.outbox.lock().await;
        if ob.is_retry(id) {
            ob.retry_failed(id);
            return Ok(());
        }
        if ob.is_own(id) || ob.is_part(id) {
            return Ok(());
        }
        ob.forget(id);
        if kind == RequestKind::KeysUpload && status == 409 {
            return Err(CryptoError::DeviceKeysConflict);
        }
        Ok(())
    }

    async fn save_retries(&self, ob: &Outbox) -> Result<()> {
        self.olm()
            .store()
            .set_value(KV_RETRIES, &ob.retries)
            .await
            .map_err(store_err("save retries"))
    }

    /// Milliseconds until the core has something to send without any other
    /// event (a debounced key request, a retry): call `outgoing_requests`
    /// then. `None`: nothing scheduled.
    pub async fn wakeup_in_ms(&self) -> Option<u64> {
        let keys = self
            .inner
            .key_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .next_due_ms();
        let retries = self.inner.outbox.lock().await.next_retry_ms();
        let verification = self
            .flows()
            .any_active()
            .then(|| outbox::now_ms().saturating_add(verification::POLL_MS));
        let next = keys.into_iter().chain(retries).chain(verification).min()?;
        Some(next.saturating_sub(outbox::now_ms()))
    }

    /// Devices that did not get a to-device message because their mailbox
    /// was full: being retried, or given up on (UI: "device X does not
    /// receive keys")
    pub async fn undelivered_devices(&self) -> Vec<UndeliveredDevice> {
        self.inner
            .outbox
            .lock()
            .await
            .undelivered()
            .into_iter()
            .filter_map(|(user, device, attempts, gave_up)| {
                Some(UndeliveredDevice {
                    user_id: stoat_crypto_proto::ids::user_ulid(&user)?,
                    device_id: device,
                    attempts,
                    gave_up,
                })
            })
            .collect()
    }

    // ---------------------------------------------------------------- inbox

    /// One `receive_sync_changes` call with the current processed-set token
    async fn sync_changes(
        &self,
        processed: &BTreeSet<String>,
        events: Vec<Raw<AnyToDeviceEvent>>,
        changed: &DeviceLists,
        counts: Option<(&BTreeMap<OneTimeKeyAlgorithm, UInt>, &[OneTimeKeyAlgorithm])>,
    ) -> Result<(
        Vec<ProcessedToDeviceEvent>,
        Vec<matrix_sdk_crypto::store::types::RoomKeyInfo>,
    )> {
        let empty = BTreeMap::new();
        let token = serde_json::to_string(processed).map_err(|_| CryptoError::Internal("token"))?;
        let changes = EncryptionSyncChanges {
            to_device_events: events,
            changed_devices: changed,
            one_time_keys_counts: counts.map_or(&empty, |c| c.0),
            unused_fallback_keys: counts.map(|c| c.1),
            next_batch_token: Some(token),
        };
        // the MSC4186 variant treats missing counts as unknown, not as zero:
        // a call without counts must not trigger an OTK upload
        self.olm()
            .receive_sync_changes_msc4186(changes, &decryption_settings())
            .await
            .map_err(store_err("receive sync changes"))
    }

    /// Process a mailbox batch (`GET /e2ee/to_device`), in server order, one
    /// event per library call (rule 1). Each event's id is committed together
    /// with its crypto changes; ids already committed are dropped before the
    /// library (C2, S12). Send `ack_ids` in `ack`, then call `mark_ack_sent`.
    pub async fn receive_to_device(&self, messages: Vec<ToDeviceMessage>) -> Result<ToDeviceResult> {
        let mut processed = self.inner.sync.lock().await;
        let mut result = ToDeviceResult::default();
        let mut in_batch = HashSet::new();
        let mut arrived = Vec::new();
        let mut all_events = Vec::new();
        let no_lists = DeviceLists::new();
        for m in messages {
            if !in_batch.insert(m.id.clone()) {
                result.skipped_duplicates += 1;
                continue;
            }
            result.ack_ids.push(m.id.clone());
            if processed.contains(&m.id) {
                result.skipped_duplicates += 1;
                continue;
            }
            // our mailbox item → Matrix to-device event
            let event = json!({ "sender": m.sender, "type": m.event_type, "content": m.content });
            let raw = Raw::from_json(
                serde_json::value::to_raw_value(&event).map_err(|_| CryptoError::Internal("to-device"))?,
            );
            let mut next = processed.clone();
            next.insert(m.id.clone());
            let (events, keys) = self.sync_changes(&next, vec![raw], &no_lists, None).await?;
            *processed = next;
            result.processed += 1;
            result.undecryptable += events
                .iter()
                .filter(|e| matches!(e, ProcessedToDeviceEvent::UnableToDecrypt { .. }))
                .count();
            arrived.extend(keys.iter().map(|k| (k.room_id.clone(), k.session_id.clone())));
            all_events.extend(events);
            result.room_keys.extend(keys.into_iter().filter_map(|k| {
                Some(RoomKeyInfo {
                    channel_id: ids::channel_ulid(&k.room_id)?,
                    session_id: k.session_id,
                })
            }));
        }
        drop(processed);
        self.touch();
        // CR-11: flows touched, SAS starts of accepted requests accepted
        result.verifications = self.verification_events(&all_events).await?;
        // CR-08: keys that arrived need no request; cancel the ones sent
        let cancels = gossip::keys_arrived(&self.inner.key_requests, self.olm(), &arrived).await?;
        if !cancels.is_empty() {
            let mut ob = self.inner.outbox.lock().await;
            for c in cancels {
                ob.add_own(c);
            }
        }
        Ok(result)
    }

    /// The server confirmed `POST /e2ee/to_device/ack {ids}`: forget the ids
    pub async fn mark_ack_sent(&self, ack_ids: &[String]) -> Result<()> {
        let mut processed = self.inner.sync.lock().await;
        let before = processed.len();
        for id in ack_ids {
            processed.remove(id);
        }
        if processed.len() != before {
            self.sync_changes(&processed, vec![], &DeviceLists::new(), None).await?;
        }
        Ok(())
    }

    /// `E2eeDeviceListUpdate {user}` from the socket (user ULIDs)
    pub async fn receive_device_list_update(&self, users: &[String]) -> Result<()> {
        let mut lists = DeviceLists::new();
        lists.changed = users.iter().map(|u| ids::user_id(u)).collect::<Result<_>>()?;
        let processed = self.inner.sync.lock().await;
        self.sync_changes(&processed, vec![], &lists, None).await?;
        self.touch();
        Ok(())
    }

    /// Socket reconnected: device lists may have changed unseen — every
    /// tracked user is queried again in one batch (Q10). Key queries handed
    /// out before are not waited for any more.
    pub async fn receive_reconnect(&self) -> Result<()> {
        self.olm()
            .mark_all_tracked_users_as_dirty()
            .await
            .map_err(store_err("mark tracked users dirty"))?;
        self.inner.outbox.lock().await.refreshed_ms = 0;
        self.touch();
        Ok(())
    }

    /// `GET /e2ee/keys/count` (or `E2eeKeysLow`): replenish OTKs, create a
    /// fallback key when none is unused
    pub async fn receive_otk_counts(&self, counts: &KeysCountResponse) -> Result<()> {
        let otk: BTreeMap<OneTimeKeyAlgorithm, UInt> = counts
            .one_time_key_counts
            .iter()
            .map(|(k, v)| (OneTimeKeyAlgorithm::from(k.as_str()), UInt::new_saturating(*v)))
            .collect();
        let fallback: Vec<OneTimeKeyAlgorithm> = counts
            .device_unused_fallback_key_types
            .iter()
            .map(|k| OneTimeKeyAlgorithm::from(k.as_str()))
            .collect();
        let processed = self.inner.sync.lock().await;
        self.sync_changes(&processed, vec![], &DeviceLists::new(), Some((&otk, &fallback)))
            .await?;
        self.touch();
        Ok(())
    }

    // ------------------------------------------------------------- channels

    fn send_lock(&self, channel: &str) -> Arc<Mutex<()>> {
        let mut locks = self.inner.send_locks.lock().unwrap_or_else(|e| e.into_inner());
        locks.entry(channel.to_owned()).or_default().clone()
    }

    /// Full member list of an encrypted channel (ULIDs) and its settings.
    /// Call it whenever the client learns the members (channel load, Ready,
    /// `ChannelGroupJoin/Leave`). Members are tracked (rule 3). The core
    /// diffs with the stored list:
    ///
    /// * any change → every member's devices are queried again before the
    ///   next send (the backend publishes no device-list update on join or
    ///   leave);
    /// * a member left → the outbound session is dropped: the next send
    ///   rotates (S4); a member joined → no rotation, the newcomer gets the
    ///   key from the current index (S5);
    /// * new rotation settings → a new session.
    pub async fn set_channel_members(
        &self,
        channel: &str,
        members: &[String],
        settings: ChannelEncryptionSettings,
    ) -> Result<()> {
        let room = ids::room_id(channel)?;
        let mut set = BTreeSet::new();
        let mut users = vec![self.inner.user_id.clone()];
        for m in members {
            users.push(ids::user_id(m)?);
            set.insert(m.to_ascii_uppercase());
        }
        set.insert(self.inner.user_ulid.clone());
        users.sort();
        users.dedup();
        self.olm()
            .update_tracked_users(users.iter().map(OwnedUserId::as_ref))
            .await
            .map_err(store_err("track members"))?;
        let key = channel.to_ascii_uppercase();
        let lock = self.send_lock(channel);
        let _guard = lock.lock().await;
        let previous = self.load_channel(&key).await?;
        let changed = previous.as_ref().is_none_or(|p| p.members != set);
        let left = previous
            .as_ref()
            .is_some_and(|p| p.members.iter().any(|m| !set.contains(m)));
        let resettled = previous.as_ref().is_some_and(|p| p.settings != settings);
        let state = ChannelState { members: set, settings };
        self.olm()
            .store()
            .set_value(&format!("{KV_CHANNEL}{key}"), &state)
            .await
            .map_err(store_err("save channel"))?;
        if changed {
            let mut lists = DeviceLists::new();
            lists.changed = users;
            let processed = self.inner.sync.lock().await;
            self.sync_changes(&processed, vec![], &lists, None).await?;
        }
        // the library keeps the settings of a running session: new rotation
        // limits take effect with a new session
        if left || resettled {
            self.olm()
                .discard_room_key(&room)
                .await
                .map_err(store_err("discard room key"))?;
        }
        self.inner.channels.lock().await.insert(key.clone(), state);
        self.remember_channel(key).await?;
        self.touch();
        Ok(())
    }

    async fn remember_channel(&self, key: String) -> Result<()> {
        let mut known = self.inner.known_channels.lock().await;
        let known = self.load_known_channels(&mut known).await?;
        if known.insert(key) {
            self.olm()
                .store()
                .set_value(KV_CHANNELS, &*known)
                .await
                .map_err(store_err("save channels"))?;
        }
        Ok(())
    }

    async fn load_known_channels<'a>(
        &self,
        known: &'a mut Option<BTreeSet<String>>,
    ) -> Result<&'a mut BTreeSet<String>> {
        if known.is_none() {
            *known = Some(
                self.olm()
                    .store()
                    .get_value(KV_CHANNELS)
                    .await
                    .map_err(store_err("load channels"))?
                    .unwrap_or_default(),
            );
        }
        Ok(known.get_or_insert_with(BTreeSet::new))
    }

    /// Channel state from the cache, else from the store
    async fn load_channel(&self, key: &str) -> Result<Option<ChannelState>> {
        let mut channels = self.inner.channels.lock().await;
        if let Some(s) = channels.get(key) {
            return Ok(Some(s.clone()));
        }
        let stored: Option<ChannelState> = self
            .olm()
            .store()
            .get_value(&format!("{KV_CHANNEL}{key}"))
            .await
            .map_err(store_err("load channel"))?;
        if let Some(s) = &stored {
            channels.insert(key.to_owned(), s.clone());
        }
        Ok(stored)
    }

    async fn channel(&self, channel: &str) -> Result<(OwnedRoomId, Vec<OwnedUserId>, EncryptionSettings)> {
        let room = ids::room_id(channel)?;
        let state = self
            .load_channel(&channel.to_ascii_uppercase())
            .await?
            .ok_or(CryptoError::UnknownChannel)?;
        let users = state
            .members
            .iter()
            .map(|m| ids::user_id(m))
            .collect::<Result<Vec<_>>>()?;
        let defaults = EncryptionSettings::default();
        let settings = EncryptionSettings {
            rotation_period: state
                .settings
                .rotation_period_ms
                .map_or(defaults.rotation_period, Duration::from_millis),
            rotation_period_msgs: state
                .settings
                .rotation_period_msgs
                .unwrap_or(defaults.rotation_period_msgs),
            // v1 trust model: every device of every member, no cross-signing (ADR 0001)
            sharing_strategy: CollectStrategy::AllDevices,
            ..defaults
        };
        Ok((room, users, settings))
    }

    /// Key queries due or in flight for any of `users`, refreshed first: a
    /// send must not go to a stale device list
    async fn member_queries(&self, ob: &mut Outbox, users: &[OwnedUserId]) -> Result<Vec<OutgoingRequest>> {
        self.refresh(ob, true).await?;
        let wanted: Vec<&str> = users.iter().map(|u| u.as_str()).collect();
        Ok(ob
            .cached
            .iter()
            .filter(|r| r.kind == RequestKind::KeysQuery)
            .filter(|r| {
                serde_json::from_str::<Value>(&r.body).is_ok_and(|b| {
                    b["device_keys"]
                        .as_object()
                        .is_some_and(|m| m.keys().any(|u| wanted.contains(&u.as_str())))
                })
            })
            .cloned()
            .collect())
    }

    /// Steps before sending to `channel`. Returns the next requests to run:
    /// key queries of members, then one claim of missing Olm sessions, then the
    /// room key to-device messages. Run them, mark them, call again — an empty
    /// list means `encrypt` can go.
    pub async fn prepare_send(&self, channel: &str) -> Result<Vec<OutgoingRequest>> {
        let lock = self.send_lock(channel);
        let _guard = lock.lock().await;
        let (room, users, settings) = self.channel(channel).await?;
        let olm = self.olm();
        let mut ob = self.inner.outbox.lock().await;

        // 1. members whose devices are not known yet (blocking query, CR-07)
        let queries = self.member_queries(&mut ob, &users).await?;
        if !queries.is_empty() {
            return Ok(queries.into_iter().flat_map(|q| ob.expand(q)).collect());
        }

        // 2. Olm sessions to every member device (one claim in flight)
        if ob.claim.is_none()
            && let Some((id, req)) = olm
                .get_missing_sessions(users.iter().map(OwnedUserId::as_ref))
                .await
                .map_err(store_err("missing sessions"))?
        {
            ob.claim = Some(requests::keys_claim(&id, &req)?);
        }
        if let Some(claim) = ob.claim.clone() {
            return Ok(ob.expand(claim));
        }

        // 3. room key to every device that does not have it (rotation if needed)
        let shares = olm
            .share_room_key(&room, users.iter().map(OwnedUserId::as_ref), settings)
            .await
            .map_err(store_err("share room key"))?;
        let mut out = Vec::new();
        for r in shares {
            out.extend(ob.expand(requests::to_device(&r)?));
        }
        Ok(out)
    }

    /// Encrypt a payload v1 for `channel` into envelope v1. The room key must
    /// be shared (`prepare_send` returned nothing), else `RoomKeyNotShared`.
    /// The advanced ratchet is stored before the envelope is returned.
    pub async fn encrypt(&self, channel: &str, payload: &MessagePayload) -> Result<EncryptedEnvelope> {
        let padded = payload.to_padded_value().map_err(payload_error)?;
        self.encrypt_value(channel, padded).await
    }

    /// Compatibility tests only (CR-23): encrypt a payload JSON object as
    /// given — padded, nothing checked or dropped — to play a newer client
    /// whose payload carries fields (or a version) this one does not know.
    /// Clients send with [`encrypt`](Self::encrypt).
    #[doc(hidden)]
    pub async fn encrypt_payload_json(&self, channel: &str, payload_json: &str) -> Result<EncryptedEnvelope> {
        let value: Value = serde_json::from_str(payload_json).map_err(|_| CryptoError::InvalidPayload)?;
        let padded = stoat_crypto_proto::payload::pad_value(value).map_err(payload_error)?;
        self.encrypt_value(channel, padded).await
    }

    async fn encrypt_value(&self, channel: &str, padded: Value) -> Result<EncryptedEnvelope> {
        let raw: Raw<AnyMessageLikeEventContent> =
            Raw::from_json(serde_json::value::to_raw_value(&padded).map_err(|_| CryptoError::InvalidPayload)?);

        let lock = self.send_lock(channel);
        let _guard = lock.lock().await;
        let (room, users, settings) = self.channel(channel).await?;
        let olm = self.olm();
        // member devices unknown: sharing now would silently skip them
        let queries = {
            let mut ob = self.inner.outbox.lock().await;
            self.member_queries(&mut ob, &users).await?
        };
        if !queries.is_empty() {
            return Err(CryptoError::RoomKeyNotShared);
        }
        // nothing pending means: session exists, is shared and not expired —
        // `encrypt_room_event_raw` panics otherwise
        let pending = olm
            .share_room_key(&room, users.iter().map(OwnedUserId::as_ref), settings)
            .await
            .map_err(store_err("share room key"))?;
        if !pending.is_empty() {
            return Err(CryptoError::RoomKeyNotShared);
        }
        let encrypted = AssertUnwindSafe(olm.encrypt_room_event_raw(&room, EVENT_TYPE, &raw))
            .catch_unwind()
            .await
            .map_err(|_| CryptoError::Internal("encrypt panicked"))?
            .map_err(store_err("encrypt"))?;
        let content: Value =
            serde_json::from_str(encrypted.content.json().get()).map_err(|_| CryptoError::Internal("encrypt"))?;
        let field = |name: &str| {
            content
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(CryptoError::Internal("encrypt"))
        };
        // rule 4: the library's `sender_key` stays out of the envelope (Q5)
        let envelope = EncryptedEnvelope::megolm(
            field("session_id")?,
            self.inner.device_ulid.clone(),
            field("ciphertext")?,
        );
        if envelope.ciphertext.len() > MAX_CIPHERTEXT_LEN {
            return Err(CryptoError::PayloadTooLarge);
        }
        Ok(envelope)
    }

    /// Drop the outbound session of `channel`: the next send creates and
    /// shares a new one
    pub async fn invalidate_outbound_session(&self, channel: &str) -> Result<()> {
        let room = ids::room_id(channel)?;
        let lock = self.send_lock(channel);
        let _guard = lock.lock().await;
        self.olm()
            .discard_room_key(&room)
            .await
            .map_err(store_err("discard room key"))?;
        Ok(())
    }

    // -------------------------------------------------------------- decrypt

    /// Decrypt one message and evaluate everything the UI needs: shield,
    /// replay, edit and reply binding (CR-19).
    pub async fn decrypt(&self, message: &IncomingEncryptedMessage) -> Result<DecryptedMessage, DecryptError> {
        let env = &message.envelope;
        env.validate()?;
        let room = ids::room_id(&message.channel_id).map_err(|_| DecryptError::Corrupted)?;
        let author = ids::user_id(&message.author).map_err(|_| DecryptError::Corrupted)?;
        let index = MegolmMessage::from_base64(&env.ciphertext)
            .map_err(|_| DecryptError::Corrupted)?
            .message_index();

        // the author's devices must be known to link the session to a device
        let olm = self.olm();
        if !olm
            .tracked_users()
            .await
            .map_err(|_| DecryptError::Internal)?
            .contains(&author)
        {
            olm.update_tracked_users([author.as_ref()])
                .await
                .map_err(|_| DecryptError::Internal)?;
        }

        // Stoat message → Matrix `m.room.encrypted` (CR-20), without `sender_key`
        let event = json!({
            "type": "m.room.encrypted",
            "sender": author,
            "event_id": format!("${}", message.message_id),
            "origin_server_ts": message.timestamp,
            "room_id": room,
            "content": {
                "algorithm": env.algorithm,
                "ciphertext": env.ciphertext,
                "session_id": env.session_id,
                "device_id": env.device_id,
            },
        });
        let raw = Raw::from_json(serde_json::value::to_raw_value(&event).map_err(|_| DecryptError::Corrupted)?);
        let decrypted = match olm.decrypt_room_event(&raw, &room, &decryption_settings()).await {
            Ok(d) => d,
            Err(e) => {
                return Err(self
                    .decrypt_failed(map_megolm_error(e), message, room, index, &event)
                    .await);
            }
        };

        let plaintext: Value =
            serde_json::from_str(decrypted.event.json().get()).map_err(|_| DecryptError::Corrupted)?;
        let plaintext = MegolmPlaintext::from_value(&plaintext).map_err(|e| match e {
            PayloadError::UnsupportedVersion => DecryptError::UnsupportedVersion,
            _ => DecryptError::Corrupted,
        })?;
        let payload = plaintext.content;
        let info = &decrypted.encryption_info;
        let session_id = info.session_id().unwrap_or(&env.session_id).to_owned();
        let sender_device = info.sender_device.as_ref().map(|d| d.to_string());

        let channel = message.channel_id.to_ascii_uppercase();
        let binding = self
            .inner
            .binding
            .check(
                olm.store(),
                Seen {
                    channel: &channel,
                    message_id: &message.message_id,
                    session_id: &session_id,
                    index,
                    edit_seq: payload.edit_seq,
                },
            )
            .await
            .map_err(|_| DecryptError::Internal)?;
        let edit_mismatch = binding::edit_mismatch(&message.message_id, payload.edit_of.as_deref(), payload.edit_seq);
        let reply_mismatch = payload.in_reply_to != message.replies;

        // shield (ADR 0001): backup / forwarded keys are never better than
        // Unauthenticated; the device hint must match the session owner
        let indirect = match olm.store().get_inbound_group_session(&room, &session_id).await {
            Ok(Some(s)) => s.has_been_imported() || s.forwarder_data.is_some(),
            _ => false,
        };
        let verification = match &info.verification_state {
            VerificationState::Unverified(VerificationLevel::MismatchedSender) => Verification::Mismatch,
            VerificationState::Unverified(VerificationLevel::None(DeviceLinkProblem::InsecureSource)) => {
                Verification::Unauthenticated
            }
            _ if indirect => Verification::Unauthenticated,
            _ => match &sender_device {
                None => Verification::UnknownDevice,
                Some(d) if d != &env.device_id => Verification::Mismatch,
                Some(d) => match olm.get_device(&info.sender, d.as_str().into(), None).await {
                    Ok(Some(dev)) if dev.is_verified() => Verification::Verified,
                    Ok(Some(_)) => Verification::Unverified,
                    _ => Verification::UnknownDevice,
                },
            },
        };

        Ok(DecryptedMessage {
            payload,
            sender_user: ids::user_ulid(&info.sender).ok_or(DecryptError::SenderMismatch)?,
            sender_device,
            verification,
            session_id,
            message_index: index,
            is_replay: binding.is_replay,
            stale_edit: binding.stale_edit,
            edit_mismatch,
            reply_mismatch,
        })
    }

    /// History page: one call for many messages (results in input order)
    pub async fn decrypt_batch(
        &self,
        messages: &[IncomingEncryptedMessage],
    ) -> Vec<Result<DecryptedMessage, DecryptError>> {
        let mut out = Vec::with_capacity(messages.len());
        for m in messages {
            out.push(self.decrypt(m).await);
        }
        out
    }

    /// A missing key: a session of another channel means the server moved
    /// the message (spike §5.6) — suspicious, nothing to ask for; otherwise
    /// own devices are asked after the debounce (CR-08)
    async fn decrypt_failed(
        &self,
        error: DecryptError,
        message: &IncomingEncryptedMessage,
        room: OwnedRoomId,
        index: u32,
        event: &Value,
    ) -> DecryptError {
        if error != DecryptError::MissingRoomKey {
            return error;
        }
        let session = &message.envelope.session_id;
        let pending = self
            .inner
            .key_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_pending(&room, session);
        if !pending {
            match self.session_elsewhere(&message.channel_id, session).await {
                Ok(true) => return DecryptError::ChannelMismatch,
                Ok(false) => {}
                Err(_) => return DecryptError::Internal,
            }
        }
        let delay = self.timing().key_request_delay_ms;
        self.inner
            .key_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .missing(room, session.clone(), index, event.to_string(), delay);
        DecryptError::MissingRoomKey
    }

    /// Is `session` known in a channel other than `channel`?
    async fn session_elsewhere(&self, channel: &str, session: &str) -> Result<bool> {
        let channel = channel.to_ascii_uppercase();
        let store = self.olm().store();
        if let Some(seen_in) = self
            .inner
            .binding
            .channel_of(store, session)
            .await
            .map_err(store_err("seen sessions"))?
        {
            return Ok(seen_in != channel);
        }
        let others: Vec<String> = {
            let mut known = self.inner.known_channels.lock().await;
            self.load_known_channels(&mut known)
                .await?
                .iter()
                .filter(|c| **c != channel)
                .take(MAX_CHANNEL_SCAN)
                .cloned()
                .collect()
        };
        for other in others {
            let room = ids::room_id(&other)?;
            if store
                .get_inbound_group_session(&room, session)
                .await
                .map_err(store_err("inbound session"))?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ----------------------------------------------------------- devices

    /// Devices of a user (ULID) as known locally
    pub async fn devices(&self, user: &str) -> Result<Vec<DeviceInfo>> {
        let user_id = ids::user_id(user)?;
        let devices = self
            .olm()
            .get_user_devices(&user_id, None)
            .await
            .map_err(store_err("devices"))?;
        Ok(devices
            .devices()
            .map(|d| DeviceInfo {
                user_id: user.to_ascii_uppercase(),
                device_id: d.device_id().to_string(),
                curve25519: d.curve25519_key().map(|k| k.to_base64()),
                ed25519: d.ed25519_key().map(|k| k.to_base64()),
                trust: match d.local_trust_state() {
                    LocalTrust::Verified => Trust::Verified,
                    LocalTrust::BlackListed => Trust::Blocked,
                    _ => Trust::Unverified,
                },
                deleted: d.is_deleted(),
            })
            .collect())
    }

    /// Set the local trust of a device (after SAS, or to block it)
    pub async fn set_device_trust(&self, user: &str, device: &str, trust: Trust) -> Result<()> {
        let user_id = ids::user_id(user)?;
        let device_id = ids::device_id(device)?;
        let d = self
            .olm()
            .get_device(&user_id, &device_id, None)
            .await
            .map_err(store_err("device"))?
            .ok_or(CryptoError::InvalidId)?;
        d.set_local_trust(match trust {
            Trust::Verified => LocalTrust::Verified,
            Trust::Unverified => LocalTrust::Unset,
            Trust::Blocked => LocalTrust::BlackListed,
        })
        .await
        .map_err(store_err("set trust"))
    }
}

fn payload_error(e: PayloadError) -> CryptoError {
    match e {
        PayloadError::TooLarge => CryptoError::PayloadTooLarge,
        _ => CryptoError::InvalidPayload,
    }
}

/// CR-20: library decryption errors → `DecryptError`
pub(crate) fn map_megolm_error(e: MegolmError) -> DecryptError {
    match e {
        MegolmError::MissingRoomKey(Some(code)) => DecryptError::Withheld(withheld_reason(&code)),
        MegolmError::MissingRoomKey(None) => DecryptError::MissingRoomKey,
        // we hold the session, but only from a later index
        MegolmError::Decryption(DecryptionError::UnknownMessageIndex(..)) => DecryptError::MissingRoomKey,
        MegolmError::EventError(EventError::MismatchedRoom(..)) => DecryptError::ChannelMismatch,
        MegolmError::EventError(EventError::UnsupportedAlgorithm) => DecryptError::UnknownAlgorithm,
        MegolmError::EventError(EventError::MismatchedSender(..) | EventError::MismatchedKeys(..))
        | MegolmError::MismatchedIdentityKeys(_) => DecryptError::SenderMismatch,
        MegolmError::Store(_) => DecryptError::Internal,
        _ => DecryptError::Corrupted,
    }
}

fn withheld_reason(code: &WithheldCode) -> WithheldReason {
    match code {
        WithheldCode::Blacklisted => WithheldReason::Blocked,
        WithheldCode::Unverified => WithheldReason::Unverified,
        WithheldCode::Unauthorised => WithheldReason::Unauthorised,
        WithheldCode::Unavailable => WithheldReason::Unavailable,
        WithheldCode::NoOlm => WithheldReason::NoOlmSession,
        _ => WithheldReason::Other,
    }
}

#[cfg(test)]
mod tests {
    use matrix_sdk_crypto::store::CryptoStoreError;
    use ruma::{room_id, user_id};

    use super::*;

    /// CR-20: the error table
    #[test]
    fn megolm_error_table() {
        let table = [
            (MegolmError::MissingRoomKey(None), DecryptError::MissingRoomKey),
            (
                MegolmError::MissingRoomKey(Some(WithheldCode::Blacklisted)),
                DecryptError::Withheld(WithheldReason::Blocked),
            ),
            (
                MegolmError::MissingRoomKey(Some(WithheldCode::NoOlm)),
                DecryptError::Withheld(WithheldReason::NoOlmSession),
            ),
            (
                MegolmError::MissingRoomKey(Some(WithheldCode::HistoryNotShared)),
                DecryptError::Withheld(WithheldReason::Other),
            ),
            (
                MegolmError::Decryption(DecryptionError::UnknownMessageIndex(3, 1)),
                DecryptError::MissingRoomKey,
            ),
            (
                MegolmError::EventError(EventError::MismatchedRoom(
                    room_id!("!a:stoat.invalid").to_owned(),
                    Some(room_id!("!b:stoat.invalid").to_owned()),
                )),
                DecryptError::ChannelMismatch,
            ),
            (
                MegolmError::EventError(EventError::UnsupportedAlgorithm),
                DecryptError::UnknownAlgorithm,
            ),
            (
                MegolmError::EventError(EventError::MismatchedSender(
                    user_id!("@a:stoat.invalid").to_owned(),
                    user_id!("@b:stoat.invalid").to_owned(),
                )),
                DecryptError::SenderMismatch,
            ),
            (
                MegolmError::EventError(EventError::MissingCiphertext),
                DecryptError::Corrupted,
            ),
            (
                MegolmError::Store(CryptoStoreError::UnpicklingError),
                DecryptError::Internal,
            ),
        ];
        for (e, expected) in table {
            let shown = format!("{e:?}");
            assert_eq!(map_megolm_error(e), expected, "{shown}");
        }
    }
}
