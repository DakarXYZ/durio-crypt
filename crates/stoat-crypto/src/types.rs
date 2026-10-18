//! Public value types of the core API. Plain data, no library (ruma) types —
//! so that a library upgrade never reaches the FFI (CR-20).

use std::fmt;

use serde::{Deserialize, Serialize};
use stoat_crypto_proto::{EncryptedEnvelope, MessagePayload};

/// Public identity keys of this device (base64)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityKeys {
    pub curve25519: String,
    pub ed25519: String,
}

/// Rotation settings of a channel's outbound session; `None` = library
/// defaults (one week / 100 messages). From `Channel.encryption` on the server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelEncryptionSettings {
    pub rotation_period_ms: Option<u64>,
    pub rotation_period_msgs: Option<u64>,
}

/// A Megolm session arrived: messages of `channel_id` waiting for
/// `session_id` can be decrypted again
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomKeyInfo {
    pub channel_id: String,
    pub session_id: String,
}

/// Outcome of [`receive_to_device`](crate::CryptoMachine::receive_to_device)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ToDeviceResult {
    /// Mailbox ids whose processing is committed (duplicates included): send
    /// them in `POST /e2ee/to_device/ack`, then call `mark_ack_sent` (C2)
    pub ack_ids: Vec<String>,
    /// New room keys (CR-08: re-decrypt messages waiting for them)
    pub room_keys: Vec<RoomKeyInfo>,
    /// Messages handed to the library
    pub processed: usize,
    /// Messages dropped before the library as already processed (C2, S12)
    pub skipped_duplicates: usize,
    /// Olm messages that could not be decrypted
    pub undecryptable: usize,
    /// Verification flows that changed (CR-11): re-read their state; a new
    /// id is an incoming request (`CryptoMachine::verification`)
    pub verifications: Vec<String>,
}

/// An encrypted channel message as the client got it from the server
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingEncryptedMessage {
    pub message_id: String,
    pub channel_id: String,
    /// Author user id (ULID) as claimed by the server
    pub author: String,
    pub envelope: EncryptedEnvelope,
    /// Open `replies` of the message, compared with `in_reply_to` (CR-19)
    pub replies: Vec<String>,
    /// Server timestamp, milliseconds
    pub timestamp: u64,
}

/// Trust shown by the UI ("shield"). Computed by the core: without
/// cross-signing the library reports every sender as an unsigned device, so
/// SAS trust is looked up per device (ADR 0001).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    /// Sender device verified by SAS
    Verified,
    /// Known device, not verified
    Unverified,
    /// The session's device is unknown (keys not queried yet, or removed)
    UnknownDevice,
    /// Key came from backup or forwarding: the author is not proven
    Unauthenticated,
    /// Author or device hint does not match the session owner (suspicious)
    Mismatch,
}

/// A decrypted message plus everything the UI needs to decide how to show it
#[derive(Clone, PartialEq)]
pub struct DecryptedMessage {
    pub payload: MessagePayload,
    /// Sender user id (ULID) the session belongs to
    pub sender_user: String,
    pub sender_device: Option<String>,
    pub verification: Verification,
    pub session_id: String,
    pub message_index: u32,
    /// Same (session, index) seen under another message id (CR-19)
    pub is_replay: bool,
    /// An older version of this message replaced a newer one (CR-19)
    pub stale_edit: bool,
    /// `edit_of` names another message than the one carrying it (CR-19)
    pub edit_mismatch: bool,
    /// `in_reply_to` differs from the open `replies` (CR-19)
    pub reply_mismatch: bool,
}

impl DecryptedMessage {
    /// Nothing suspicious: show as a normal message (the shield still applies)
    pub fn is_clean(&self) -> bool {
        !(self.is_replay || self.stale_edit || self.edit_mismatch || self.reply_mismatch)
            && self.verification != Verification::Mismatch
    }
}

impl fmt::Debug for DecryptedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedMessage")
            .field("payload", &self.payload)
            .field("sender_user", &self.sender_user)
            .field("sender_device", &self.sender_device)
            .field("verification", &self.verification)
            .field("session_id", &self.session_id)
            .field("message_index", &self.message_index)
            .field("is_replay", &self.is_replay)
            .field("stale_edit", &self.stale_edit)
            .field("edit_mismatch", &self.edit_mismatch)
            .field("reply_mismatch", &self.reply_mismatch)
            .finish()
    }
}

/// Local trust of a device
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// Verified by SAS
    Verified,
    /// Not verified
    Unverified,
    /// Never share keys with it
    Blocked,
}

/// A device of a user as known locally
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub user_id: String,
    pub device_id: String,
    pub curve25519: Option<String>,
    pub ed25519: Option<String>,
    pub trust: Trust,
    /// Removed on the server; kept for old messages
    pub deleted: bool,
}
