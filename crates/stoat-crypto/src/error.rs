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
            Self::Internal(_) => "internal",
        }
    }
}

/// Why a message could not be shown. The UI maps these (20-crypto-core):
/// waiting for the key, "update the app", suspicious, broken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum DecryptError {
    /// No (or not early enough) Megolm session: wait for the key / request it
    #[error("room key missing")]
    MissingRoomKey,
    /// Envelope algorithm unknown — update the app
    #[error("unknown algorithm")]
    UnknownAlgorithm,
    /// Envelope or payload version unknown — update the app
    #[error("unsupported version")]
    UnsupportedVersion,
    /// Plaintext is bound to another channel (suspicious)
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
            Self::UnknownAlgorithm => "unknown_algorithm",
            Self::UnsupportedVersion => "unsupported_version",
            Self::ChannelMismatch => "channel_mismatch",
            Self::SenderMismatch => "sender_mismatch",
            Self::Corrupted => "corrupted",
            Self::Internal => "internal",
        }
    }
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
