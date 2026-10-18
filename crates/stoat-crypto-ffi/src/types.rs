//! Records and enums of the bindings: plain data, Kotlin data classes.
//!
//! Heavy or open-ended structures cross as JSON strings (20-crypto-core,
//! "requests — JSON strings at the boundary"): request and response bodies,
//! the message payload, the envelope, `EncryptedFile`. Everything the UI
//! branches on is typed.
//!
//! Kotlin's generated `toString()` prints every field: never log
//! `DecryptedMessage` (plaintext), `StoreConfig` (store key) or
//! `RecoverySetup` (recovery key).

use std::fmt;
use std::path::PathBuf;

use serde_json::Value;
use stoat_crypto as sc;
use stoat_crypto::proto::{EncryptedEnvelope, MessagePayload};
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

// ---------------------------------------------------------------- store

/// Where the account's crypto state lives (one store per account and server)
#[derive(uniffi::Enum)]
pub enum StoreConfig {
    /// Nothing persists (tests)
    Memory,
    /// SQLite in the directory `path`; `key` = 32 bytes from the Android
    /// Keystore-wrapped master key. The core wipes its copy; the caller
    /// fills its `ByteArray` with zeros after the call.
    Sqlite { path: String, key: Vec<u8> },
}

impl fmt::Debug for StoreConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory => f.write_str("Memory"),
            Self::Sqlite { path, .. } => f
                .debug_struct("Sqlite")
                .field("path", path)
                .field("key", &"<redacted>")
                .finish(),
        }
    }
}

impl StoreConfig {
    pub(crate) fn into_core(self) -> Result<sc::StoreConfig, CryptoError> {
        match self {
            Self::Memory => Ok(sc::StoreConfig::Memory),
            Self::Sqlite { path, mut key } => {
                let k = sc::StoreKey::from_slice(&key);
                key.zeroize();
                Ok(sc::StoreConfig::Sqlite {
                    path: PathBuf::from(path),
                    key: k.map_err(|_| CryptoError::input("store key must be 32 bytes"))?,
                })
            }
        }
    }
}

// ------------------------------------------------------------- machine

#[derive(Clone, Debug, uniffi::Record)]
pub struct IdentityKeys {
    pub curve25519: String,
    pub ed25519: String,
}

impl From<sc::IdentityKeys> for IdentityKeys {
    fn from(k: sc::IdentityKeys) -> Self {
        Self {
            curve25519: k.curve25519,
            ed25519: k.ed25519,
        }
    }
}

/// `GET /` → `features.e2ee` limits
#[derive(Clone, Copy, Debug, uniffi::Record)]
pub struct ServerLimits {
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

/// Delays of the core's policies (tests shorten them)
#[derive(Clone, Copy, Debug, uniffi::Record)]
pub struct Timing {
    pub key_request_delay_ms: u64,
    pub to_device_retry_ms: u64,
    pub to_device_retry_attempts: u32,
}

impl From<Timing> for sc::Timing {
    fn from(t: Timing) -> Self {
        Self {
            key_request_delay_ms: t.key_request_delay_ms,
            to_device_retry_ms: t.to_device_retry_ms,
            to_device_retry_attempts: t.to_device_retry_attempts,
        }
    }
}

impl From<sc::Timing> for Timing {
    fn from(t: sc::Timing) -> Self {
        Self {
            key_request_delay_ms: t.key_request_delay_ms,
            to_device_retry_ms: t.to_device_retry_ms,
            to_device_retry_attempts: t.to_device_retry_attempts,
        }
    }
}

/// What a request is; passed back with its response
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RequestKind {
    KeysUpload,
    KeysQuery,
    KeysClaim,
    ToDevice,
    BackupVersionCreate,
    BackupKeys,
    SecretPut,
}

impl From<sc::RequestKind> for RequestKind {
    fn from(k: sc::RequestKind) -> Self {
        match k {
            sc::RequestKind::KeysUpload => Self::KeysUpload,
            sc::RequestKind::KeysQuery => Self::KeysQuery,
            sc::RequestKind::KeysClaim => Self::KeysClaim,
            sc::RequestKind::ToDevice => Self::ToDevice,
            sc::RequestKind::BackupVersionCreate => Self::BackupVersionCreate,
            sc::RequestKind::BackupKeys => Self::BackupKeys,
            sc::RequestKind::SecretPut => Self::SecretPut,
        }
    }
}

impl From<RequestKind> for sc::RequestKind {
    fn from(k: RequestKind) -> Self {
        match k {
            RequestKind::KeysUpload => Self::KeysUpload,
            RequestKind::KeysQuery => Self::KeysQuery,
            RequestKind::KeysClaim => Self::KeysClaim,
            RequestKind::ToDevice => Self::ToDevice,
            RequestKind::BackupVersionCreate => Self::BackupVersionCreate,
            RequestKind::BackupKeys => Self::BackupKeys,
            RequestKind::SecretPut => Self::SecretPut,
        }
    }
}

/// HTTP request to perform: `method` (`POST`/`PUT`) `path` (relative to the
/// API root) with the JSON `body`; then exactly one `mark_request_sent` or
/// `mark_request_failed` with the same `id` and `kind`
#[derive(Clone, uniffi::Record)]
pub struct OutgoingRequest {
    pub id: String,
    pub kind: RequestKind,
    pub method: String,
    pub path: String,
    pub body: String,
}

impl fmt::Debug for OutgoingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingRequest")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl From<sc::OutgoingRequest> for OutgoingRequest {
    fn from(r: sc::OutgoingRequest) -> Self {
        Self {
            id: r.id,
            kind: r.kind.into(),
            method: r.method.to_owned(),
            path: r.path,
            body: r.body,
        }
    }
}

pub(crate) fn requests(v: Vec<sc::OutgoingRequest>) -> Vec<OutgoingRequest> {
    v.into_iter().map(Into::into).collect()
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct UndeliveredDevice {
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

// ------------------------------------------------------------- mailbox

/// A Megolm session arrived: re-decrypt messages of `channel_id` waiting for it
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RoomKeyInfo {
    pub channel_id: String,
    pub session_id: String,
}

/// Outcome of `receive_to_device`
#[derive(Clone, Debug, uniffi::Record)]
pub struct ToDeviceResult {
    /// Messages in the page handed in: fetch again while it equals the
    /// `limit` of the request
    pub fetched: u32,
    /// Send in `POST /e2ee/to_device/ack` (≤ 100 per call), then `mark_ack_sent`
    pub ack_ids: Vec<String>,
    pub room_keys: Vec<RoomKeyInfo>,
    pub processed: u32,
    pub skipped_duplicates: u32,
    pub undecryptable: u32,
    /// Verification flows that changed: re-read their state
    pub verifications: Vec<String>,
}

impl ToDeviceResult {
    pub(crate) fn new(fetched: usize, r: sc::ToDeviceResult) -> Self {
        Self {
            fetched: count(fetched),
            ack_ids: r.ack_ids,
            room_keys: r
                .room_keys
                .into_iter()
                .map(|k| RoomKeyInfo {
                    channel_id: k.channel_id,
                    session_id: k.session_id,
                })
                .collect(),
            processed: count(r.processed),
            skipped_duplicates: count(r.skipped_duplicates),
            undecryptable: count(r.undecryptable),
            verifications: r.verifications,
        }
    }
}

pub(crate) fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

// ------------------------------------------------------------- channels

/// From `Channel.encryption`; `None` = library defaults (1 week / 100 messages)
#[derive(Clone, Copy, Debug, Default, uniffi::Record)]
pub struct ChannelEncryptionSettings {
    pub rotation_period_ms: Option<u64>,
    pub rotation_period_msgs: Option<u64>,
}

impl From<ChannelEncryptionSettings> for sc::ChannelEncryptionSettings {
    fn from(s: ChannelEncryptionSettings) -> Self {
        Self {
            rotation_period_ms: s.rotation_period_ms,
            rotation_period_msgs: s.rotation_period_msgs,
        }
    }
}

/// Payload v1 JSON → payload (version first, attachments validated)
pub(crate) fn payload_from_json(json: &str) -> Result<MessagePayload, CryptoError> {
    let value: Value = serde_json::from_str(json).map_err(|_| sc::CryptoError::InvalidPayload)?;
    Ok(MessagePayload::from_value(&value).map_err(|_| sc::CryptoError::InvalidPayload)?)
}

/// Payload → JSON without the padding
pub(crate) fn payload_to_json(mut p: MessagePayload) -> String {
    p.pad.clear();
    serde_json::to_string(&p).unwrap_or_default()
}

/// An encrypted channel message as the client got it from the server
#[derive(Clone, Debug, uniffi::Record)]
pub struct IncomingEncryptedMessage {
    pub message_id: String,
    pub channel_id: String,
    /// Author ULID as the server claims it
    pub author: String,
    /// The message's `encrypted` object, as JSON
    pub envelope_json: String,
    /// The message's open `replies`
    pub replies: Vec<String>,
    /// Server timestamp, milliseconds
    pub timestamp: u64,
}

impl IncomingEncryptedMessage {
    /// Envelope errors are decryption failures ("update the app"), not exceptions
    pub(crate) fn into_core(self) -> Result<sc::IncomingEncryptedMessage, DecryptResult> {
        let envelope = EncryptedEnvelope::from_json(&self.envelope_json)
            .map_err(|e| DecryptResult::from(sc::DecryptError::from(e)))?;
        Ok(sc::IncomingEncryptedMessage {
            message_id: self.message_id,
            channel_id: self.channel_id,
            author: self.author,
            envelope,
            replies: self.replies,
            timestamp: self.timestamp,
        })
    }
}

/// UI shield
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Verification {
    Verified,
    Unverified,
    UnknownDevice,
    /// Key from backup or forwarding: the author is not proven
    Unauthenticated,
    /// Suspicious
    Mismatch,
}

impl From<sc::Verification> for Verification {
    fn from(v: sc::Verification) -> Self {
        match v {
            sc::Verification::Verified => Self::Verified,
            sc::Verification::Unverified => Self::Unverified,
            sc::Verification::UnknownDevice => Self::UnknownDevice,
            sc::Verification::Unauthenticated => Self::Unauthenticated,
            sc::Verification::Mismatch => Self::Mismatch,
        }
    }
}

/// A decrypted message. `payload_json` is plaintext: never log it.
#[derive(Clone, uniffi::Record)]
pub struct DecryptedMessage {
    /// Payload v1 JSON (without padding)
    pub payload_json: String,
    pub sender_user: String,
    pub sender_device: Option<String>,
    pub verification: Verification,
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
            .field("sender_user", &self.sender_user)
            .field("sender_device", &self.sender_device)
            .field("verification", &self.verification)
            .field("session_id", &self.session_id)
            .field("message_index", &self.message_index)
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
            verification: m.verification.into(),
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

/// `m.room_key.withheld` codes
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum WithheldReason {
    Blocked,
    Unverified,
    Unauthorised,
    Unavailable,
    NoOlmSession,
    Other,
}

impl From<sc::WithheldReason> for WithheldReason {
    fn from(r: sc::WithheldReason) -> Self {
        match r {
            sc::WithheldReason::Blocked => Self::Blocked,
            sc::WithheldReason::Unverified => Self::Unverified,
            sc::WithheldReason::Unauthorised => Self::Unauthorised,
            sc::WithheldReason::Unavailable => Self::Unavailable,
            sc::WithheldReason::NoOlmSession => Self::NoOlmSession,
            sc::WithheldReason::Other => Self::Other,
        }
    }
}

/// Why a message could not be decrypted (the exact cause)
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DecryptError {
    MissingRoomKey,
    Withheld { reason: WithheldReason },
    UnknownAlgorithm,
    UnsupportedVersion,
    ChannelMismatch,
    SenderMismatch,
    Corrupted,
    Internal,
}

/// What the UI shows for a message that could not be decrypted
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DecryptFailureKind {
    /// "Waiting for the key…": decrypt again on `ToDeviceResult.room_keys`
    WaitingForKey,
    Withheld {
        reason: WithheldReason,
    },
    /// "Update the app"
    UpdateApp,
    /// Tampered with by the server: never show as text
    Suspicious,
    Broken,
    /// Store failure: try again later
    RetryLater,
}

/// Decryption outcome: a failure is a normal value, not an exception
#[derive(Clone, Debug, uniffi::Enum)]
pub enum DecryptResult {
    Decrypted {
        message: DecryptedMessage,
    },
    Failed {
        error: DecryptError,
        kind: DecryptFailureKind,
        /// Stable code (diagnostics)
        code: String,
    },
}

impl From<sc::DecryptError> for DecryptResult {
    fn from(e: sc::DecryptError) -> Self {
        let error = match e {
            sc::DecryptError::MissingRoomKey => DecryptError::MissingRoomKey,
            sc::DecryptError::Withheld(r) => DecryptError::Withheld { reason: r.into() },
            sc::DecryptError::UnknownAlgorithm => DecryptError::UnknownAlgorithm,
            sc::DecryptError::UnsupportedVersion => DecryptError::UnsupportedVersion,
            sc::DecryptError::ChannelMismatch => DecryptError::ChannelMismatch,
            sc::DecryptError::SenderMismatch => DecryptError::SenderMismatch,
            sc::DecryptError::Corrupted => DecryptError::Corrupted,
            sc::DecryptError::Internal => DecryptError::Internal,
        };
        let kind = match e.kind() {
            sc::DecryptFailureKind::WaitingForKey => DecryptFailureKind::WaitingForKey,
            sc::DecryptFailureKind::Withheld(r) => DecryptFailureKind::Withheld { reason: r.into() },
            sc::DecryptFailureKind::UpdateApp => DecryptFailureKind::UpdateApp,
            sc::DecryptFailureKind::Suspicious => DecryptFailureKind::Suspicious,
            sc::DecryptFailureKind::Broken => DecryptFailureKind::Broken,
            sc::DecryptFailureKind::RetryLater => DecryptFailureKind::RetryLater,
        };
        Self::Failed {
            error,
            kind,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Trust {
    Verified,
    Unverified,
    Blocked,
}

impl From<sc::Trust> for Trust {
    fn from(t: sc::Trust) -> Self {
        match t {
            sc::Trust::Verified => Self::Verified,
            sc::Trust::Unverified => Self::Unverified,
            sc::Trust::Blocked => Self::Blocked,
        }
    }
}

impl From<Trust> for sc::Trust {
    fn from(t: Trust) -> Self {
        match t {
            Trust::Verified => Self::Verified,
            Trust::Unverified => Self::Unverified,
            Trust::Blocked => Self::Blocked,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct DeviceInfo {
    pub user_id: String,
    pub device_id: String,
    pub curve25519: Option<String>,
    pub ed25519: Option<String>,
    pub trust: Trust,
    pub deleted: bool,
}

impl From<sc::DeviceInfo> for DeviceInfo {
    fn from(d: sc::DeviceInfo) -> Self {
        Self {
            user_id: d.user_id,
            device_id: d.device_id,
            curve25519: d.curve25519,
            ed25519: d.ed25519,
            trust: d.trust.into(),
            deleted: d.deleted,
        }
    }
}

// --------------------------------------------------------------- backup

/// `create_recovery` / `rotate_backup`: show `recovery_key` once (`None` on
/// a rotation), then run `request`
#[derive(Clone, uniffi::Record)]
pub struct RecoverySetup {
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
#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct RecoverySecrets {
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

#[derive(Clone, Debug, uniffi::Record)]
pub struct BackupStatus {
    pub version: Option<String>,
    pub enabled: bool,
    pub recovery_set_up: bool,
    pub outdated: bool,
    pub keys_total: u64,
    pub keys_backed_up: u64,
}

impl From<sc::BackupStatus> for BackupStatus {
    fn from(s: sc::BackupStatus) -> Self {
        Self {
            version: s.version,
            enabled: s.enabled,
            recovery_set_up: s.recovery_set_up,
            outdated: s.outdated,
            keys_total: s.keys_total,
            keys_backed_up: s.keys_backed_up,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Record)]
pub struct RestoreProgress {
    pub done: u64,
    pub total: u64,
    pub imported: u64,
    pub failed: u64,
    pub finished: bool,
}

impl From<sc::RestoreProgress> for RestoreProgress {
    fn from(p: sc::RestoreProgress) -> Self {
        Self {
            done: p.done as u64,
            total: p.total as u64,
            imported: p.imported as u64,
            failed: p.failed as u64,
            finished: p.is_finished(),
        }
    }
}

// ----------------------------------------------------------- key export

/// A key export file (CR-21): save `data` as text (`.txt`). Ciphertext, but
/// not for logs either.
#[derive(Clone, uniffi::Record)]
pub struct KeyExport {
    pub data: String,
    /// Sessions in the file
    pub sessions: u32,
}

impl fmt::Debug for KeyExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyExport")
            .field("data_len", &self.data.len())
            .field("sessions", &self.sessions)
            .finish()
    }
}

impl From<sc::KeyExport> for KeyExport {
    fn from(e: sc::KeyExport) -> Self {
        Self {
            sessions: count(e.sessions),
            data: e.data,
        }
    }
}

/// Outcome of `import_room_keys`: re-decrypt messages waiting for
/// `room_keys`; imported keys show as `Unauthenticated`
#[derive(Clone, Debug, uniffi::Record)]
pub struct KeyImportResult {
    /// Sessions in the file
    pub total: u32,
    /// New or better keys stored
    pub imported: u32,
    /// Sessions of non-Stoat rooms (another Matrix client's export), left out
    pub skipped: u32,
    pub room_keys: Vec<RoomKeyInfo>,
}

impl From<sc::KeyImportResult> for KeyImportResult {
    fn from(r: sc::KeyImportResult) -> Self {
        Self {
            total: count(r.total),
            imported: count(r.imported),
            skipped: count(r.skipped),
            room_keys: r
                .room_keys
                .into_iter()
                .map(|k| RoomKeyInfo {
                    channel_id: k.channel_id,
                    session_id: k.session_id,
                })
                .collect(),
        }
    }
}

/// Input of a recovery field, checked as the user types
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RecoveryKeyCheck {
    /// A well-formed recovery key
    Valid,
    /// Shaped like a recovery key, with a typo
    Typo,
    /// Not a recovery key (a passphrase)
    NotAKey,
}

/// Bytes from Kotlin (`ByteArray`) → string; the bytes are wiped
pub(crate) fn secret_string(mut bytes: Vec<u8>) -> Result<Zeroizing<String>, CryptoError> {
    let s = std::str::from_utf8(&bytes).map(|s| Zeroizing::new(s.to_owned()));
    bytes.zeroize();
    s.map_err(|_| CryptoError::input("not UTF-8"))
}
