//! Errors at the JS boundary: an `Error` with `name = "StoatCryptoError"`,
//! `code` = the variant name of the Android FFI's `CryptoError` (one code
//! per core error, plus `InvalidInput` and `AlreadyFinished`) and the core's
//! fixed message — no keys, plaintext or input (CR-16). The TS package turns
//! it into `class StoatCryptoError extends Error {code}` on the page side.
//! Decryption failures are values (`DecryptResult`), not errors.

use std::fmt;

use stoat_crypto::CryptoError as Core;
use wasm_bindgen::JsValue;

/// Error of the bindings; becomes a JS `Error` (`name`, `code`, `message`)
#[derive(Clone, PartialEq, Eq)]
pub struct Error {
    code: &'static str,
    message: String,
}

impl Error {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Input from the host is malformed (not UTF-8, wrong length, not the
    /// expected shape)
    pub(crate) fn input(what: &str) -> Self {
        Self::new("InvalidInput", format!("invalid input: {what}"))
    }

    /// A one-shot object (`finish()`) was used after it finished
    pub(crate) fn finished() -> Self {
        Self::new("AlreadyFinished", "the object is already finished")
    }

    pub(crate) fn internal(what: &'static str) -> Self {
        Core::Internal(what).into()
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// FFI variant name of a core error (Kotlin `CryptoException.<Code>`)
fn code(e: &Core) -> &'static str {
    match e {
        Core::StoreLocked => "StoreLocked",
        Core::StoreMismatch => "StoreMismatch",
        Core::Store(_) => "Store",
        Core::InvalidId => "InvalidId",
        Core::InvalidResponse(_) => "InvalidResponse",
        Core::DeviceKeysConflict => "DeviceKeysConflict",
        Core::UnknownChannel => "UnknownChannel",
        Core::RoomKeyNotShared => "RoomKeyNotShared",
        Core::PayloadTooLarge => "PayloadTooLarge",
        Core::InvalidPayload => "InvalidPayload",
        Core::UnknownDevice => "UnknownDevice",
        Core::VerificationNotActive => "VerificationNotActive",
        Core::MfaRequired => "MfaRequired",
        Core::BackupVersionChanged => "BackupVersionChanged",
        Core::NoBackup => "NoBackup",
        Core::NoRecovery => "NoRecovery",
        Core::RecoveryKeyTypo => "RecoveryKeyTypo",
        Core::WrongRecoveryKey => "WrongRecoveryKey",
        Core::BackupKeyMismatch => "BackupKeyMismatch",
        Core::InvalidRecoveryData => "InvalidRecoveryData",
        Core::InvalidAttachment => "InvalidAttachment",
        Core::AttachmentHashMismatch => "AttachmentHashMismatch",
        Core::PassphraseRequired => "PassphraseRequired",
        Core::InvalidKeyFile => "InvalidKeyFile",
        Core::WrongPassphrase => "WrongPassphrase",
        Core::RequestRejected => "RequestRejected",
        Core::Internal(_) => "Internal",
    }
}

impl From<Core> for Error {
    fn from(e: Core) -> Self {
        Self::new(code(&e), e.to_string())
    }
}

impl From<Error> for JsValue {
    fn from(e: Error) -> Self {
        let error = js_sys::Error::new(&e.message);
        error.set_name("StoatCryptoError");
        // `Reflect::set` on a fresh `Error` cannot fail; if it did, the
        // error would still be thrown, only without `code`
        let _ = js_sys::Reflect::set(&error, &"code".into(), &e.code.into());
        error.into()
    }
}
