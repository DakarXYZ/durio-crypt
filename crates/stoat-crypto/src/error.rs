//! Errors of the core. Flat enums with a stable code and a fixed message:
//! no keys, plaintext or library-provided text ever reach `Display` (the FFI
//! and the clients' logs see these).

use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// Another `CryptoMachine` holds the store (CR-17)
    #[error("the crypto store is open in another instance")]
    StoreLocked,
    /// The store belongs to another account or device
    #[error("the crypto store belongs to another account or device")]
    StoreMismatch,
    /// Opening, reading or writing the store failed
    #[error("crypto store error during {0}")]
    Store(&'static str),
    /// A Stoat id is not a ULID or a Matrix id is not ours
    #[error("invalid identifier")]
    InvalidId,
    /// A server response did not parse for its request kind
    #[error("invalid server response for {0}")]
    InvalidResponse(&'static str),
    /// The server rejected our device keys as different from the stored ones (409)
    #[error("the server has different keys for this device")]
    DeviceKeysConflict,
    /// `set_channel_members` was never called for the channel
    #[error("unknown channel, set its members first")]
    UnknownChannel,
    /// The channel key is not shared yet: run `prepare_send` to completion
    #[error("room key not shared yet")]
    RoomKeyNotShared,
    /// The payload does not fit the envelope limit
    #[error("message too large to encrypt")]
    PayloadTooLarge,
    /// The payload is not a valid payload v1
    #[error("invalid message payload")]
    InvalidPayload,
    /// An `EncryptedFile` is not a valid v2 object
    #[error("invalid encrypted file description")]
    InvalidAttachment,
    /// The downloaded blob is not the one the sender encrypted (CR-10): show
    /// nothing of it
    #[error("attachment hash mismatch")]
    AttachmentHashMismatch,
    /// Unexpected library failure in an operation
    #[error("internal crypto error during {0}")]
    Internal(&'static str),
}

impl CryptoError {
    /// Stable code for FFI / diagnostics (CR-13, CR-22)
    pub fn code(&self) -> &'static str {
        match self {
            Self::StoreLocked => "store_locked",
            Self::StoreMismatch => "store_mismatch",
            Self::Store(_) => "store",
            Self::InvalidId => "invalid_id",
            Self::InvalidResponse(_) => "invalid_response",
            Self::DeviceKeysConflict => "device_keys_conflict",
            Self::UnknownChannel => "unknown_channel",
            Self::RoomKeyNotShared => "room_key_not_shared",
            Self::PayloadTooLarge => "payload_too_large",
            Self::InvalidPayload => "invalid_payload",
            Self::InvalidAttachment => "invalid_attachment",
            Self::AttachmentHashMismatch => "attachment_hash_mismatch",
            Self::Internal(_) => "internal",
        }
    }
}

/// Why a message could not be shown. The UI maps these (20-crypto-core):
/// waiting for the key, "update the app", suspicious, broken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum DecryptError {
    /// No (or not early enough) Megolm session: wait for the key (the core
    /// asks own verified devices for it, CR-08)
    #[error("room key missing")]
    MissingRoomKey,
    /// The sender's device declined to give this device the key
    #[error("room key withheld")]
    Withheld(WithheldReason),
    /// Envelope algorithm unknown — update the app
    #[error("unknown algorithm")]
    UnknownAlgorithm,
    /// Envelope or payload version unknown — update the app
    #[error("unsupported version")]
    UnsupportedVersion,
    /// Plaintext or session is bound to another channel: the server moved
    /// the message (suspicious)
    #[error("channel mismatch")]
    ChannelMismatch,
    /// Plaintext or session does not belong to the claimed sender (suspicious)
    #[error("sender mismatch")]
    SenderMismatch,
    /// Ciphertext or plaintext is broken
    #[error("corrupted message")]
    Corrupted,
    /// Store failure while decrypting; retry later
    #[error("internal error")]
    Internal,
}

impl DecryptError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingRoomKey => "missing_room_key",
            Self::Withheld(_) => "withheld",
            Self::UnknownAlgorithm => "unknown_algorithm",
            Self::UnsupportedVersion => "unsupported_version",
            Self::ChannelMismatch => "channel_mismatch",
            Self::SenderMismatch => "sender_mismatch",
            Self::Corrupted => "corrupted",
            Self::Internal => "internal",
        }
    }

    /// What the UI shows for the message
    pub fn kind(&self) -> DecryptFailureKind {
        match self {
            Self::MissingRoomKey => DecryptFailureKind::WaitingForKey,
            Self::Withheld(r) => DecryptFailureKind::Withheld(*r),
            Self::UnknownAlgorithm | Self::UnsupportedVersion => DecryptFailureKind::UpdateApp,
            Self::ChannelMismatch | Self::SenderMismatch => DecryptFailureKind::Suspicious,
            Self::Corrupted => DecryptFailureKind::Broken,
            Self::Internal => DecryptFailureKind::RetryLater,
        }
    }
}

/// Why the sender withheld a room key (`m.room_key.withheld` codes)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithheldReason {
    /// `m.blacklisted`: the sender blocked this device
    Blocked,
    /// `m.unverified`: the sender shares only with verified devices
    Unverified,
    /// `m.unauthorised`: not allowed to read (e.g. not a member then)
    Unauthorised,
    /// `m.unavailable`: asked for a key the other side does not have
    Unavailable,
    /// `m.no_olm`: no secure channel to this device (no one-time key)
    NoOlmSession,
    /// Any other code
    Other,
}

impl WithheldReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Unverified => "unverified",
            Self::Unauthorised => "unauthorised",
            Self::Unavailable => "unavailable",
            Self::NoOlmSession => "no_olm",
            Self::Other => "other",
        }
    }
}

/// UI-facing state of a message that could not be decrypted
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecryptFailureKind {
    /// "Waiting for the key…": decrypt again on `ToDeviceResult::room_keys`
    WaitingForKey,
    /// The sender will not send the key to this device
    Withheld(WithheldReason),
    /// Newer format: "update the app"
    UpdateApp,
    /// The server tampered with it: show as suspicious, not as text
    Suspicious,
    /// Broken ciphertext or payload
    Broken,
    /// Local store failure: try again later
    RetryLater,
}

pub type Result<T, E = CryptoError> = std::result::Result<T, E>;

impl From<stoat_crypto_proto::EnvelopeError> for DecryptError {
    /// An envelope the client could not even parse
    fn from(e: stoat_crypto_proto::EnvelopeError) -> Self {
        match e {
            stoat_crypto_proto::EnvelopeError::UnsupportedVersion => Self::UnsupportedVersion,
            stoat_crypto_proto::EnvelopeError::UnknownAlgorithm => Self::UnknownAlgorithm,
            _ => Self::Corrupted,
        }
    }
}
