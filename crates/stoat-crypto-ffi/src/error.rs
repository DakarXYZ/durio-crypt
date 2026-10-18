//! `CryptoException` in Kotlin: one subclass per core error code, the
//! message is the core's fixed text (no keys, plaintext or input, CR-16).
//! Decryption failures are not exceptions but values (`DecryptResult`).

use stoat_crypto::CryptoError as Core;

/// Errors of the bindings. Kotlin: `CryptoException.<Variant>(message)`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CryptoError {
    /// Another machine holds the store (one per account and process, CR-17)
    #[error("{0}")]
    StoreLocked(String),
    /// The store belongs to another account or device
    #[error("{0}")]
    StoreMismatch(String),
    /// Opening, reading or writing the store failed
    #[error("{0}")]
    Store(String),
    /// A Stoat id is not a ULID
    #[error("{0}")]
    InvalidId(String),
    /// A server response (or body handed in by the host) did not parse
    #[error("{0}")]
    InvalidResponse(String),
    /// The server has other keys for this device (409 on the key upload)
    #[error("{0}")]
    DeviceKeysConflict(String),
    /// `set_channel_members` was never called for the channel
    #[error("{0}")]
    UnknownChannel(String),
    /// Run `prepare_send` to completion first
    #[error("{0}")]
    RoomKeyNotShared(String),
    #[error("{0}")]
    PayloadTooLarge(String),
    /// Not a valid payload v1
    #[error("{0}")]
    InvalidPayload(String),
    #[error("{0}")]
    UnknownDevice(String),
    #[error("{0}")]
    VerificationNotActive(String),
    /// Run the same request again with `x-mfa-ticket`
    #[error("{0}")]
    MfaRequired(String),
    /// The backup was replaced elsewhere: unlock with the recovery key again
    #[error("{0}")]
    BackupVersionChanged(String),
    #[error("{0}")]
    NoBackup(String),
    #[error("{0}")]
    NoRecovery(String),
    /// Shaped like a recovery key, with a typo
    #[error("{0}")]
    RecoveryKeyTypo(String),
    #[error("{0}")]
    WrongRecoveryKey(String),
    #[error("{0}")]
    BackupKeyMismatch(String),
    #[error("{0}")]
    InvalidRecoveryData(String),
    /// The `EncryptedFile` JSON is not a valid v2 object
    #[error("{0}")]
    InvalidAttachment(String),
    /// The blob is not the one the sender encrypted: show nothing of it
    #[error("{0}")]
    AttachmentHashMismatch(String),
    /// `export_room_keys` with an empty passphrase
    #[error("{0}")]
    PassphraseRequired(String),
    /// Not a key export file (or a cut-off one)
    #[error("{0}")]
    InvalidKeyFile(String),
    /// The key file does not open with this passphrase (or was modified)
    #[error("{0}")]
    WrongPassphrase(String),
    /// A request of the core was refused for good and dropped (review O-2)
    #[error("{0}")]
    RequestRejected(String),
    #[error("{0}")]
    Internal(String),
    /// Input from the host is malformed (not UTF-8, wrong length)
    #[error("{0}")]
    InvalidInput(String),
    /// A one-shot object (`finish()`) was used after it finished
    #[error("{0}")]
    AlreadyFinished(String),
    /// The core panicked; the operation did not complete (report, retry later)
    #[error("{0}")]
    Panic(String),
}

impl CryptoError {
    pub(crate) fn panic() -> Self {
        Self::Panic("internal crypto error (panic)".into())
    }

    pub(crate) fn input(what: &str) -> Self {
        Self::InvalidInput(format!("invalid input: {what}"))
    }

    pub(crate) fn finished() -> Self {
        Self::AlreadyFinished("the object is already finished".into())
    }
}

impl From<Core> for CryptoError {
    fn from(e: Core) -> Self {
        let m = e.to_string();
        match e {
            Core::StoreLocked => Self::StoreLocked(m),
            Core::StoreMismatch => Self::StoreMismatch(m),
            Core::Store(_) => Self::Store(m),
            Core::InvalidId => Self::InvalidId(m),
            Core::InvalidResponse(_) => Self::InvalidResponse(m),
            Core::DeviceKeysConflict => Self::DeviceKeysConflict(m),
            Core::UnknownChannel => Self::UnknownChannel(m),
            Core::RoomKeyNotShared => Self::RoomKeyNotShared(m),
            Core::PayloadTooLarge => Self::PayloadTooLarge(m),
            Core::InvalidPayload => Self::InvalidPayload(m),
            Core::UnknownDevice => Self::UnknownDevice(m),
            Core::VerificationNotActive => Self::VerificationNotActive(m),
            Core::MfaRequired => Self::MfaRequired(m),
            Core::BackupVersionChanged => Self::BackupVersionChanged(m),
            Core::NoBackup => Self::NoBackup(m),
            Core::NoRecovery => Self::NoRecovery(m),
            Core::RecoveryKeyTypo => Self::RecoveryKeyTypo(m),
            Core::WrongRecoveryKey => Self::WrongRecoveryKey(m),
            Core::BackupKeyMismatch => Self::BackupKeyMismatch(m),
            Core::InvalidRecoveryData => Self::InvalidRecoveryData(m),
            Core::InvalidAttachment => Self::InvalidAttachment(m),
            Core::AttachmentHashMismatch => Self::AttachmentHashMismatch(m),
            Core::PassphraseRequired => Self::PassphraseRequired(m),
            Core::InvalidKeyFile => Self::InvalidKeyFile(m),
            Core::WrongPassphrase => Self::WrongPassphrase(m),
            Core::RequestRejected => Self::RequestRejected(m),
            Core::Internal(_) => Self::Internal(m),
        }
    }
}
