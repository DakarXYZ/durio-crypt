//! To-device event types of contract v1.
//!
//! The library (matrix-sdk-crypto) builds and parses these contents itself; the
//! core only needs the type names (mailbox routing, the C2 filter, fixtures).
//! Typed here are the events that travel **in plaintext** and are therefore
//! visible to the server: `m.room_key_request` and the SAS flow
//! (`m.key.verification.*`). Everything else is inside `m.room.encrypted`.

use serde::{Deserialize, Serialize};

/// Olm-encrypted container of all secret to-device events
pub const ROOM_ENCRYPTED: &str = "m.room.encrypted";
/// Inside Olm: Megolm session key for a channel
pub const ROOM_KEY: &str = "m.room_key";
/// Inside Olm: answer to a key request
pub const FORWARDED_ROOM_KEY: &str = "m.forwarded_room_key";
/// Inside Olm or plain: the sender will not share a key
pub const ROOM_KEY_WITHHELD: &str = "m.room_key.withheld";
/// Plaintext, sent to `"*"` of the own devices
pub const ROOM_KEY_REQUEST: &str = "m.room_key_request";
/// Inside Olm: Olm session unwedging
pub const DUMMY: &str = "m.dummy";
/// Inside Olm: secret sharing (backup key) between own devices
pub const SECRET_REQUEST: &str = "m.secret.request";
pub const SECRET_SEND: &str = "m.secret.send";
/// Prefix of the plaintext SAS flow
pub const KEY_VERIFICATION_PREFIX: &str = "m.key.verification.";

/// Event types that legitimately travel without Olm encryption; the server
/// must not require `m.room.encrypted` (CR-01 §5.4).
pub fn is_plaintext_allowed(event_type: &str) -> bool {
    event_type == ROOM_KEY_REQUEST || event_type == ROOM_KEY_WITHHELD || event_type.starts_with(KEY_VERIFICATION_PREFIX)
}

/// `m.room_key_request` content (plaintext)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomKeyRequestContent {
    /// `request` or `request_cancellation`
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<RequestedKeyInfo>,
    pub request_id: String,
    pub requesting_device_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestedKeyInfo {
    pub algorithm: String,
    pub room_id: String,
    pub session_id: String,
    /// Deprecated in Matrix, the library omits it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_key: Option<String>,
}

/// `m.key.verification.request` / `.ready` content (plaintext)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRequestContent {
    pub from_device: String,
    pub methods: Vec<String>,
    pub transaction_id: String,
    /// Only in `request`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
}
