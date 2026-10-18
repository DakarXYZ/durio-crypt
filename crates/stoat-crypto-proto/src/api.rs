//! Bodies of `/e2ee/*` (contract v1). The shape is Matrix CS API v1.x one to
//! one (C1), the paths are ours. Mirrors `revolt_models::v0::e2ee` on the
//! backend (branch `durio/stage-2`), including its deviations:
//!
//! * `keys/count` **always** carries `device_unused_fallback_key_types`; the
//!   `keys/upload` response carries it too (not part of Matrix, ignored by it);
//! * `PUT /to_device/<txn>` may answer `{"failed": {user: [device]}}` for full
//!   mailboxes (Q11);
//! * the mailbox is `GET /to_device?limit=1..=100` → `{messages:[…]}` plus
//!   `POST /to_device/ack {ids}` (1..=100 ids) → 204 (C2);
//! * the backup version is a query parameter, `etag` is a string.
//!
//! Signed key objects stay [`serde_json::Value`]: signatures are checked over
//! the canonical JSON as received, never over a re-serialization.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::redact::Redacted;

/// Paths of the `/e2ee/*` routes
pub mod paths {
    pub const KEYS_UPLOAD: &str = "/e2ee/keys/upload";
    pub const KEYS_QUERY: &str = "/e2ee/keys/query";
    pub const KEYS_CLAIM: &str = "/e2ee/keys/claim";
    pub const KEYS_COUNT: &str = "/e2ee/keys/count";
    pub const TO_DEVICE: &str = "/e2ee/to_device";
    pub const TO_DEVICE_ACK: &str = "/e2ee/to_device/ack";
    pub const BACKUP_VERSION: &str = "/e2ee/backup/version";
    pub const BACKUP_KEYS: &str = "/e2ee/backup/keys";
    pub const SECRETS: &str = "/e2ee/secrets";

    /// `PUT /e2ee/to_device/<txn_id>`
    pub fn to_device_send(txn_id: &str) -> String {
        format!("{TO_DEVICE}/{}", super::encode_component(txn_id))
    }

    /// `GET /e2ee/to_device?limit=N`
    pub fn to_device_fetch(limit: usize) -> String {
        format!("{TO_DEVICE}?limit={limit}")
    }

    /// `GET|PUT|DELETE /e2ee/backup/version/<v>`
    pub fn backup_version(version: &str) -> String {
        format!("{BACKUP_VERSION}/{}", super::encode_component(version))
    }

    /// `GET|PUT /e2ee/secrets/<type>`
    pub fn secret(secret_type: &str) -> String {
        format!("{SECRETS}/{}", super::encode_component(secret_type))
    }

    /// `PUT|GET /e2ee/backup/keys?version=V`
    pub fn backup_keys(version: &str) -> String {
        format!("{BACKUP_KEYS}?version={}", super::encode_component(version))
    }
}

/// Limits of the mailbox routes (backend validation)
pub const MAX_TO_DEVICE_FETCH: usize = 100;
pub const MAX_TO_DEVICE_ACK: usize = 100;
/// Maximum users or devices in one `keys/query` / `keys/claim`
pub const MAX_DEVICES_PER_REQUEST: usize = 256;
/// Maximum one-time keys stored per device on the server (C26)
pub const MAX_OTK_PER_DEVICE: usize = 100;
/// Maximum sessions in one `PUT /e2ee/backup/keys` (BE-08)
pub const MAX_BACKUP_KEYS_PER_REQUEST: usize = 1_000;
/// Maximum secrets stored per user (BE-08)
pub const MAX_SECRETS: usize = 32;

/// Secret storage entries (`/e2ee/secrets/<type>`, Matrix names)
pub mod secrets {
    /// `{"key": <key id>}`: the key the other secrets are encrypted with
    pub const DEFAULT_KEY: &str = "m.secret_storage.default_key";
    /// Prefix of a key description, followed by the key id
    pub const KEY_PREFIX: &str = "m.secret_storage.key.";
    /// The backup decryption key, encrypted with the secret storage key
    pub const MEGOLM_BACKUP_V1: &str = "m.megolm_backup.v1";

    /// `m.secret_storage.key.<id>`
    pub fn key(id: &str) -> String {
        format!("{KEY_PREFIX}{id}")
    }
}

/// Percent-encode everything outside RFC 3986 "unreserved"
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Error body of the backend: `{"type": "<ErrorType>", …}`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApiError {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten)]
    pub details: BTreeMap<String, Value>,
}

// ------------------------------------------------------------------ keys

/// `POST /e2ee/keys/upload`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KeysUploadRequest {
    /// Signed device keys, only once per device
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_keys: Option<Value>,
    /// `signed_curve25519:<key id>` → signed key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_time_keys: Option<BTreeMap<String, Value>>,
    /// `signed_curve25519:<key id>` → signed key with `"fallback": true`, at most one
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_keys: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KeysUploadResponse {
    pub one_time_key_counts: BTreeMap<String, u64>,
    /// Backend extension, absent in the CR-01 fixtures
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_unused_fallback_key_types: Option<Vec<String>>,
}

/// `POST /e2ee/keys/query`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KeysQueryRequest {
    /// User id → device ids (empty: all devices)
    pub device_keys: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KeysQueryResponse {
    /// User id → device id → signed device keys. Every requested user is
    /// answered; unknown and invisible ones with `{}`.
    pub device_keys: BTreeMap<String, BTreeMap<String, Value>>,
    #[serde(default)]
    pub failures: BTreeMap<String, Value>,
    /// Cross-signing: empty until v1.1
    #[serde(default)]
    pub master_keys: BTreeMap<String, Value>,
    #[serde(default)]
    pub self_signing_keys: BTreeMap<String, Value>,
    #[serde(default)]
    pub user_signing_keys: BTreeMap<String, Value>,
}

/// `POST /e2ee/keys/claim`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KeysClaimRequest {
    /// User id → device id → key algorithm
    pub one_time_keys: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KeysClaimResponse {
    #[serde(default)]
    pub failures: BTreeMap<String, Value>,
    /// User id → device id → `<algorithm>:<key id>` → signed key
    pub one_time_keys: BTreeMap<String, BTreeMap<String, BTreeMap<String, Value>>>,
}

/// `GET /e2ee/keys/count`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KeysCountResponse {
    pub one_time_key_counts: BTreeMap<String, u64>,
    /// Always present: without it the library never creates a fallback key
    pub device_unused_fallback_key_types: Vec<String>,
}

// ------------------------------------------------------------- to-device

/// `PUT /e2ee/to_device/<txn_id>`
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ToDeviceSendRequest {
    #[serde(rename = "type")]
    pub event_type: String,
    /// User id → device id (or `*`) → content
    pub messages: BTreeMap<String, BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ToDeviceSendResponse {
    /// User id → devices whose mailbox is full; nothing was stored for them
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failed: BTreeMap<String, Vec<String>>,
}

/// `GET /e2ee/to_device?limit=N`, oldest first
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ToDeviceFetchResponse {
    pub messages: Vec<ToDeviceMessage>,
}

/// One mailbox message
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ToDeviceMessage {
    /// Mailbox id (ULID), acknowledged with `ack`
    pub id: String,
    /// Matrix-shaped id of the sending user
    pub sender: String,
    /// Sending device (session ULID)
    pub sender_device: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub content: Value,
}

/// `POST /e2ee/to_device/ack` → 204
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ToDeviceAckRequest {
    pub ids: Vec<String>,
}

// ---------------------------------------------------------------- backup

/// `POST /e2ee/backup/version`, `PUT /e2ee/backup/version/<v>`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackupVersionRequest {
    pub algorithm: String,
    /// `{"public_key": …, "signatures": {}}`
    pub auth_data: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackupVersionCreateResponse {
    pub version: String,
}

/// `GET /e2ee/backup/version[/<v>]`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackupVersion {
    pub algorithm: String,
    pub auth_data: Value,
    pub count: u64,
    pub etag: String,
    pub version: String,
}

/// `PUT|GET /e2ee/backup/keys?version=`
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KeysBackup {
    /// Room id → sessions
    pub rooms: BTreeMap<String, RoomKeyBackup>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RoomKeyBackup {
    /// Session id → backed up session
    pub sessions: BTreeMap<String, KeyBackupData>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyBackupData {
    pub first_message_index: u64,
    pub forwarded_count: u64,
    pub is_verified: bool,
    /// `{ciphertext, ephemeral, mac}`
    pub session_data: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeysBackupUpdateResponse {
    pub count: u64,
    pub etag: String,
}

impl KeyBackupData {
    /// Whether this key should replace `existing` — the backend keeps the
    /// better one (lower first index, then verified, then fewer forwards).
    pub fn is_better_than(&self, existing: &KeyBackupData) -> bool {
        if self.first_message_index != existing.first_message_index {
            return self.first_message_index < existing.first_message_index;
        }
        if self.is_verified != existing.is_verified {
            return self.is_verified;
        }
        self.forwarded_count < existing.forwarded_count
    }
}

impl fmt::Debug for ToDeviceSendRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToDeviceSendRequest")
            .field("event_type", &self.event_type)
            .field("messages", &Redacted)
            .finish()
    }
}

impl fmt::Debug for ToDeviceMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToDeviceMessage")
            .field("id", &self.id)
            .field("sender", &self.sender)
            .field("sender_device", &self.sender_device)
            .field("event_type", &self.event_type)
            .field("content", &Redacted)
            .finish()
    }
}

impl fmt::Debug for KeyBackupData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBackupData")
            .field("first_message_index", &self.first_message_index)
            .field("forwarded_count", &self.forwarded_count)
            .field("is_verified", &self.is_verified)
            .field("session_data", &Redacted)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_encoding() {
        assert_eq!(paths::to_device_send("abc-1_2.3"), "/e2ee/to_device/abc-1_2.3");
        assert_eq!(paths::to_device_send("a/b c"), "/e2ee/to_device/a%2Fb%20c");
        assert_eq!(
            paths::backup_keys("01KZ0000000000000000000001"),
            "/e2ee/backup/keys?version=01KZ0000000000000000000001"
        );
    }

    #[test]
    fn better_backup_key() {
        let key = |first_message_index, is_verified, forwarded_count| KeyBackupData {
            first_message_index,
            forwarded_count,
            is_verified,
            session_data: Value::Null,
        };
        assert!(key(0, false, 5).is_better_than(&key(1, true, 0)));
        assert!(key(1, true, 5).is_better_than(&key(1, false, 0)));
        assert!(key(1, true, 0).is_better_than(&key(1, true, 1)));
        assert!(!key(1, true, 1).is_better_than(&key(1, true, 1)));
        assert!(!key(2, true, 0).is_better_than(&key(1, false, 9)));
    }
}
