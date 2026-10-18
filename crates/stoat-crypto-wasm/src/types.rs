//! Records of the bindings: plain JS objects in camelCase, the shapes of the
//! Android FFI records (`stoat-crypto-ffi/src/types.rs`). Enums the UI
//! branches on are strings (`"KeysUpload"`, `"Verified"`); sum types are
//! tagged with `type` (`{type: "Failed", kind, ...}`).
//!
//! Numbers: counters are `u32`, times and byte counts `f64` (exact up to
//! 2^53) — `serde-wasm-bindgen` would turn a `u64` into a `BigInt` or fail.
//! Heavy or open-ended structures stay JSON strings as on Android: request
//! and response bodies, payload, envelope, `EncryptedFile`.

use std::fmt;

use js_sys::{Reflect, Uint8Array};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_wasm_bindgen::Serializer;
use stoat_crypto as sc;
use stoat_crypto::proto::{EncryptedEnvelope, MessagePayload};
use wasm_bindgen::{JsCast, JsValue};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;

// ------------------------------------------------------------ conversion

/// Rust → JS: maps as objects, `None` as `null`
pub(crate) fn to_js<T: Serialize + ?Sized>(value: &T) -> Result<JsValue, Error> {
    let serializer = Serializer::new()
        .serialize_maps_as_objects(true)
        .serialize_missing_as_null(true);
    value.serialize(&serializer).map_err(|_| Error::internal("serialize"))
}

/// JS → Rust; the library's message (it may quote the input) is dropped
pub(crate) fn from_js<T: DeserializeOwned>(value: JsValue, what: &str) -> Result<T, Error> {
    serde_wasm_bindgen::from_value(value).map_err(|_| Error::input(what))
}

/// Milliseconds (or another non-negative integer) from a JS number
pub(crate) fn millis(v: f64) -> Result<u64, Error> {
    if v.is_finite() && v >= 0.0 && v.fract() == 0.0 && v <= 9_007_199_254_740_991.0 {
        Ok(v as u64)
    } else {
        Err(Error::input("not a non-negative integer"))
    }
}

/// `u64` → JS number (exact below 2^53; counters never get there)
fn num(v: u64) -> f64 {
    v as f64
}

pub(crate) fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Bytes from JS (`Uint8Array`) → string; the bytes are wiped
pub(crate) fn secret_string(mut bytes: Vec<u8>) -> Result<Zeroizing<String>, Error> {
    let s = std::str::from_utf8(&bytes).map(|s| Zeroizing::new(s.to_owned()));
    bytes.zeroize();
    s.map_err(|_| Error::input("not UTF-8"))
}

// ----------------------------------------------------------------- store

/// `{kind: "memory"}` or `{kind: "indexedDb", name, key: Uint8Array(32)}`.
/// The key is copied, the copy is wiped; the caller zeroes its array.
pub(crate) fn store_config(value: &JsValue) -> Result<sc::StoreConfig, Error> {
    let get = |field: &str| Reflect::get(value, &field.into()).map_err(|_| Error::input("store config"));
    match get("kind")?.as_string().as_deref() {
        Some("memory") => Ok(sc::StoreConfig::Memory),
        Some("indexedDb") => {
            let name = get("name")?
                .as_string()
                .filter(|n| !n.is_empty())
                .ok_or_else(|| Error::input("store name"))?;
            let key = get("key")?
                .dyn_into::<Uint8Array>()
                .map_err(|_| Error::input("store key must be a Uint8Array"))?;
            let bytes = Zeroizing::new(key.to_vec());
            let key = sc::StoreKey::from_slice(&bytes).map_err(|_| Error::input("store key must be 32 bytes"))?;
            Ok(sc::StoreConfig::IndexedDb { name, key })
        }
        _ => Err(Error::input("store kind")),
    }
}

// --------------------------------------------------------------- machine

#[derive(Serialize)]
pub(crate) struct IdentityKeys {
    pub curve25519: String,
    pub ed25519: String,
}

/// `GET /` → `features.e2ee` limits
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerLimits {
    pub max_to_device_batch: u32,
    pub max_request_bytes: u32,
}

impl From<ServerLimits> for sc::ServerLimits {
    fn from(l: ServerLimits) -> Self {
        Self {
            max_to_device_batch: l.max_to_device_batch as usize,
            max_request_bytes: l.max_request_bytes as usize,
        }
    }
}

/// Delays of the core's policies (tests shorten them); `ownRetryMs`
/// defaults to 1 s as in Kotlin
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Timing {
    pub key_request_delay_ms: f64,
    pub to_device_retry_ms: f64,
    pub to_device_retry_attempts: u32,
    #[serde(default = "default_own_retry_ms")]
    pub own_retry_ms: f64,
}

fn default_own_retry_ms() -> f64 {
    1000.0
}

impl Timing {
    pub(crate) fn into_core(self) -> Result<sc::Timing, Error> {
        Ok(sc::Timing {
            key_request_delay_ms: millis(self.key_request_delay_ms)?,
            to_device_retry_ms: millis(self.to_device_retry_ms)?,
            to_device_retry_attempts: self.to_device_retry_attempts,
            own_retry_ms: millis(self.own_retry_ms)?,
        })
    }
}

pub(crate) fn request_kind(k: sc::RequestKind) -> &'static str {
    match k {
        sc::RequestKind::KeysUpload => "KeysUpload",
        sc::RequestKind::KeysQuery => "KeysQuery",
        sc::RequestKind::KeysClaim => "KeysClaim",
        sc::RequestKind::ToDevice => "ToDevice",
        sc::RequestKind::BackupVersionCreate => "BackupVersionCreate",
        sc::RequestKind::BackupKeys => "BackupKeys",
        sc::RequestKind::SecretPut => "SecretPut",
    }
}

pub(crate) fn parse_request_kind(k: &str) -> Result<sc::RequestKind, Error> {
    Ok(match k {
        "KeysUpload" => sc::RequestKind::KeysUpload,
        "KeysQuery" => sc::RequestKind::KeysQuery,
        "KeysClaim" => sc::RequestKind::KeysClaim,
        "ToDevice" => sc::RequestKind::ToDevice,
        "BackupVersionCreate" => sc::RequestKind::BackupVersionCreate,
        "BackupKeys" => sc::RequestKind::BackupKeys,
        "SecretPut" => sc::RequestKind::SecretPut,
        _ => return Err(Error::input("request kind")),
    })
}

/// HTTP request to perform: `method` `path` (relative to the API root) with
/// the JSON `body`; then exactly one `markRequestSent` or
/// `markRequestFailed` with the same `id` and `kind`
#[derive(Serialize)]
pub(crate) struct OutgoingRequest {
    pub id: String,
    pub kind: &'static str,
    pub method: String,
    pub path: String,
    pub body: String,
}

impl fmt::Debug for OutgoingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingRequest")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("path", &self.path)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl From<sc::OutgoingRequest> for OutgoingRequest {
    fn from(r: sc::OutgoingRequest) -> Self {
        Self {
            id: r.id,
            kind: request_kind(r.kind),
            method: r.method.to_owned(),
            path: r.path,
            body: r.body,
        }
    }
}

pub(crate) fn requests(v: Vec<sc::OutgoingRequest>) -> Vec<OutgoingRequest> {
    v.into_iter().map(Into::into).collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UndeliveredDevice {
    pub user_id: String,
    pub device_id: String,
    pub attempts: u32,
    pub gave_up: bool,
}

impl From<sc::UndeliveredDevice> for UndeliveredDevice {
    fn from(d: sc::UndeliveredDevice) -> Self {
        Self {
            user_id: d.user_id,
            device_id: d.device_id,
            attempts: d.attempts,
            gave_up: d.gave_up,
        }
    }
}

// --------------------------------------------------------------- mailbox

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RoomKeyInfo {
    pub channel_id: String,
    pub session_id: String,
}

fn room_keys(keys: Vec<sc::RoomKeyInfo>) -> Vec<RoomKeyInfo> {
    keys.into_iter()
        .map(|k| RoomKeyInfo {
            channel_id: k.channel_id,
            session_id: k.session_id,
        })
        .collect()
}

/// Outcome of `receiveToDevice`
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToDeviceResult {
    /// Messages in the page handed in: fetch again while it equals the limit
    pub fetched: u32,
    pub ack_ids: Vec<String>,
    pub room_keys: Vec<RoomKeyInfo>,
    pub processed: u32,
    pub skipped_duplicates: u32,
    pub undecryptable: u32,
    pub verifications: Vec<String>,
}

impl ToDeviceResult {
    pub(crate) fn new(fetched: usize, r: sc::ToDeviceResult) -> Self {
        Self {
            fetched: count(fetched),
            ack_ids: r.ack_ids,
            room_keys: room_keys(r.room_keys),
            processed: count(r.processed),
            skipped_duplicates: count(r.skipped_duplicates),
            undecryptable: count(r.undecryptable),
            verifications: r.verifications,
        }
    }
}

// -------------------------------------------------------------- channels

/// From `Channel.encryption`; absent / `null` = library defaults
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct ChannelEncryptionSettings {
    pub rotation_period_ms: Option<f64>,
    pub rotation_period_msgs: Option<f64>,
}

impl ChannelEncryptionSettings {
    pub(crate) fn into_core(self) -> Result<sc::ChannelEncryptionSettings, Error> {
        Ok(sc::ChannelEncryptionSettings {
            rotation_period_ms: self.rotation_period_ms.map(millis).transpose()?,
            rotation_period_msgs: self.rotation_period_msgs.map(millis).transpose()?,
        })
    }
}

/// Payload v1 JSON → payload (version first, attachments validated)
pub(crate) fn payload_from_json(json: &str) -> Result<MessagePayload, Error> {
    let value: Value = serde_json::from_str(json).map_err(|_| sc::CryptoError::InvalidPayload)?;
    Ok(MessagePayload::from_value(&value).map_err(|_| sc::CryptoError::InvalidPayload)?)
}

/// Payload → JSON without the padding
pub(crate) fn payload_to_json(mut p: MessagePayload) -> String {
    p.pad.clear();
    serde_json::to_string(&p).unwrap_or_default()
}

/// An encrypted channel message as the client got it from the server
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IncomingEncryptedMessage {
    pub message_id: String,
    pub channel_id: String,
    /// Author ULID as the server claims it
    pub author: String,
    /// The message's `encrypted` object, as JSON
    pub envelope_json: String,
    /// The message's open `replies`
    #[serde(default)]
    pub replies: Vec<String>,
    /// Server timestamp, milliseconds
    pub timestamp: f64,
}

impl IncomingEncryptedMessage {
    /// Envelope errors are decryption failures ("update the app"), not
    /// exceptions; a bad timestamp is the host's bug
    pub(crate) fn into_core(self) -> Result<Result<sc::IncomingEncryptedMessage, DecryptResult>, Error> {
        let timestamp = millis(self.timestamp)?;
        let envelope = match EncryptedEnvelope::from_json(&self.envelope_json) {
            Ok(e) => e,
            Err(e) => return Ok(Err(DecryptResult::from(sc::DecryptError::from(e)))),
        };
        Ok(Ok(sc::IncomingEncryptedMessage {
            message_id: self.message_id,
            channel_id: self.channel_id,
            author: self.author,
            envelope,
            replies: self.replies,
            timestamp,
        }))
    }
}

fn verification(v: sc::Verification) -> &'static str {
    match v {
        sc::Verification::Verified => "Verified",
        sc::Verification::Unverified => "Unverified",
        sc::Verification::UnknownDevice => "UnknownDevice",
        sc::Verification::Unauthenticated => "Unauthenticated",
        sc::Verification::Mismatch => "Mismatch",
    }
}

/// A decrypted message. `payloadJson` is plaintext: never log it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DecryptedMessage {
    pub payload_json: String,
    pub sender_user: String,
    pub sender_device: Option<String>,
    pub verification: &'static str,
    pub session_id: String,
    pub message_index: u32,
    pub is_replay: bool,
    pub stale_edit: bool,
    pub edit_mismatch: bool,
    pub reply_mismatch: bool,
    /// Nothing suspicious: show as a normal message (the shield still applies)
    pub is_clean: bool,
}

impl fmt::Debug for DecryptedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedMessage")
            .field("payload_len", &self.payload_json.len())
            .field("verification", &self.verification)
            .field("is_clean", &self.is_clean)
            .finish_non_exhaustive()
    }
}

impl From<sc::DecryptedMessage> for DecryptedMessage {
    fn from(m: sc::DecryptedMessage) -> Self {
        let is_clean = m.is_clean();
        Self {
            payload_json: payload_to_json(m.payload),
            sender_user: m.sender_user,
            sender_device: m.sender_device,
            verification: verification(m.verification),
            session_id: m.session_id,
            message_index: m.message_index,
            is_replay: m.is_replay,
            stale_edit: m.stale_edit,
            edit_mismatch: m.edit_mismatch,
            reply_mismatch: m.reply_mismatch,
            is_clean,
        }
    }
}

fn withheld(r: sc::WithheldReason) -> &'static str {
    match r {
        sc::WithheldReason::Blocked => "Blocked",
        sc::WithheldReason::Unverified => "Unverified",
        sc::WithheldReason::Unauthorised => "Unauthorised",
        sc::WithheldReason::Unavailable => "Unavailable",
        sc::WithheldReason::NoOlmSession => "NoOlmSession",
        sc::WithheldReason::Other => "Other",
    }
}

/// Decryption outcome: a failure is a normal value. `error` = the exact
/// cause (`MissingRoomKey`, `Withheld`, …), `kind` = what the UI shows
/// (`WaitingForKey`, `Withheld`, `UpdateApp`, `Suspicious`, `Broken`,
/// `RetryLater`), `withheldReason` for both `Withheld`, `code` = stable
/// diagnostics code
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all_fields = "camelCase")]
pub(crate) enum DecryptResult {
    Decrypted {
        message: DecryptedMessage,
    },
    Failed {
        error: &'static str,
        kind: &'static str,
        withheld_reason: Option<&'static str>,
        code: String,
    },
}

impl From<sc::DecryptError> for DecryptResult {
    fn from(e: sc::DecryptError) -> Self {
        let mut reason = None;
        let error = match e {
            sc::DecryptError::MissingRoomKey => "MissingRoomKey",
            sc::DecryptError::Withheld(r) => {
                reason = Some(withheld(r));
                "Withheld"
            }
            sc::DecryptError::UnknownAlgorithm => "UnknownAlgorithm",
            sc::DecryptError::UnsupportedVersion => "UnsupportedVersion",
            sc::DecryptError::ChannelMismatch => "ChannelMismatch",
            sc::DecryptError::SenderMismatch => "SenderMismatch",
            sc::DecryptError::Corrupted => "Corrupted",
            sc::DecryptError::Internal => "Internal",
        };
        let kind = match e.kind() {
            sc::DecryptFailureKind::WaitingForKey => "WaitingForKey",
            sc::DecryptFailureKind::Withheld(r) => {
                reason = Some(withheld(r));
                "Withheld"
            }
            sc::DecryptFailureKind::UpdateApp => "UpdateApp",
            sc::DecryptFailureKind::Suspicious => "Suspicious",
            sc::DecryptFailureKind::Broken => "Broken",
            sc::DecryptFailureKind::RetryLater => "RetryLater",
        };
        Self::Failed {
            error,
            kind,
            withheld_reason: reason,
            code: e.code().to_owned(),
        }
    }
}

impl From<Result<sc::DecryptedMessage, sc::DecryptError>> for DecryptResult {
    fn from(r: Result<sc::DecryptedMessage, sc::DecryptError>) -> Self {
        match r {
            Ok(m) => Self::Decrypted { message: m.into() },
            Err(e) => e.into(),
        }
    }
}

// --------------------------------------------------------------- devices

pub(crate) fn trust(t: sc::Trust) -> &'static str {
    match t {
        sc::Trust::Verified => "Verified",
        sc::Trust::Unverified => "Unverified",
        sc::Trust::Blocked => "Blocked",
    }
}

/// `Unverified` (reset) or `Blocked`; `Verified` comes from SAS only (O-3)
pub(crate) fn parse_settable_trust(t: &str) -> Result<sc::Trust, Error> {
    match t {
        "Unverified" => Ok(sc::Trust::Unverified),
        "Blocked" => Ok(sc::Trust::Blocked),
        "Verified" => Err(Error::input("Verified comes from SAS only")),
        _ => Err(Error::input("trust")),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeviceInfo {
    pub user_id: String,
    pub device_id: String,
    pub curve25519: Option<String>,
    pub ed25519: Option<String>,
    pub trust: &'static str,
    pub deleted: bool,
}

impl From<sc::DeviceInfo> for DeviceInfo {
    fn from(d: sc::DeviceInfo) -> Self {
        Self {
            user_id: d.user_id,
            device_id: d.device_id,
            curve25519: d.curve25519,
            ed25519: d.ed25519,
            trust: trust(d.trust),
            deleted: d.deleted,
        }
    }
}

// ---------------------------------------------------------------- backup

/// `createRecovery` / `rotateBackup`: show `recoveryKey` once (`null` on a
/// rotation), then run `request`
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoverySetup {
    pub recovery_key: Option<String>,
    pub request: OutgoingRequest,
}

impl fmt::Debug for RecoverySetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoverySetup")
            .field("recovery_key", &self.recovery_key.as_ref().map(|_| "<redacted>"))
            .field("request", &self.request)
            .finish()
    }
}

impl From<sc::RecoverySetup> for RecoverySetup {
    fn from(s: sc::RecoverySetup) -> Self {
        Self {
            recovery_key: s.recovery_key().map(str::to_owned),
            request: s.request.into(),
        }
    }
}

/// Bodies of the four restore `GET`s, as the server returned them
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoverySecrets {
    pub default_key: String,
    pub key_description: String,
    pub backup_secret: String,
    pub backup_version: String,
}

impl From<RecoverySecrets> for sc::RecoverySecrets {
    fn from(s: RecoverySecrets) -> Self {
        Self {
            default_key: s.default_key,
            key_description: s.key_description,
            backup_secret: s.backup_secret,
            backup_version: s.backup_version,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BackupStatus {
    pub version: Option<String>,
    pub enabled: bool,
    pub recovery_set_up: bool,
    pub outdated: bool,
    pub keys_total: f64,
    pub keys_backed_up: f64,
}

impl From<sc::BackupStatus> for BackupStatus {
    fn from(s: sc::BackupStatus) -> Self {
        Self {
            version: s.version,
            enabled: s.enabled,
            recovery_set_up: s.recovery_set_up,
            outdated: s.outdated,
            keys_total: num(s.keys_total),
            keys_backed_up: num(s.keys_backed_up),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct RestoreProgress {
    pub done: u32,
    pub total: u32,
    pub imported: u32,
    pub failed: u32,
    pub finished: bool,
}

impl From<sc::RestoreProgress> for RestoreProgress {
    fn from(p: sc::RestoreProgress) -> Self {
        Self {
            done: count(p.done),
            total: count(p.total),
            imported: count(p.imported),
            failed: count(p.failed),
            finished: p.is_finished(),
        }
    }
}

// ------------------------------------------------------------ key export

/// A key export file (CR-21): save `data` as text. Ciphertext, but not for
/// logs either.
#[derive(Serialize)]
pub(crate) struct KeyExport {
    pub data: String,
    pub sessions: u32,
}

impl From<sc::KeyExport> for KeyExport {
    fn from(e: sc::KeyExport) -> Self {
        Self {
            sessions: count(e.sessions),
            data: e.data,
        }
    }
}

/// Outcome of `importRoomKeys`: re-decrypt messages waiting for `roomKeys`
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyImportResult {
    pub total: u32,
    pub imported: u32,
    pub skipped: u32,
    pub room_keys: Vec<RoomKeyInfo>,
}

impl From<sc::KeyImportResult> for KeyImportResult {
    fn from(r: sc::KeyImportResult) -> Self {
        Self {
            total: count(r.total),
            imported: count(r.imported),
            skipped: count(r.skipped),
            room_keys: room_keys(r.room_keys),
        }
    }
}

// ------------------------------------------------------------------- SAS

#[derive(Serialize)]
pub(crate) struct SasEmoji {
    pub index: u8,
    pub symbol: String,
    pub description: String,
}

fn cancel_reason(r: sc::CancelReason) -> &'static str {
    match r {
        sc::CancelReason::User => "User",
        sc::CancelReason::Timeout => "Timeout",
        sc::CancelReason::Mismatch => "Mismatch",
        sc::CancelReason::AcceptedElsewhere => "AcceptedElsewhere",
        sc::CancelReason::Other => "Other",
    }
}

/// What the verification screen shows (`type` = the state)
#[derive(Serialize)]
#[serde(tag = "type", rename_all_fields = "camelCase")]
pub(crate) enum SasState {
    Requested,
    Incoming,
    Ready,
    Started,
    ShowCodes {
        emoji: Vec<SasEmoji>,
        decimals: Vec<u16>,
    },
    Confirmed,
    Done,
    Cancelled {
        reason: &'static str,
        code: String,
        by_us: bool,
    },
}

impl From<sc::SasState> for SasState {
    fn from(s: sc::SasState) -> Self {
        match s {
            sc::SasState::Requested => Self::Requested,
            sc::SasState::Incoming => Self::Incoming,
            sc::SasState::Ready => Self::Ready,
            sc::SasState::Started => Self::Started,
            sc::SasState::ShowCodes { emoji, decimals } => Self::ShowCodes {
                emoji: emoji
                    .into_iter()
                    .map(|e| SasEmoji {
                        index: e.index,
                        symbol: e.symbol,
                        description: e.description,
                    })
                    .collect(),
                decimals: decimals.to_vec(),
            },
            sc::SasState::Confirmed => Self::Confirmed,
            sc::SasState::Done => Self::Done,
            sc::SasState::Cancelled { reason, code, by_us } => Self::Cancelled {
                reason: cancel_reason(reason),
                code,
                by_us,
            },
        }
    }
}
