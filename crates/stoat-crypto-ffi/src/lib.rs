//! dur.io crypto core for Android (CR-13): UniFFI bindings over
//! [`stoat_crypto`], packaged as an AAR by `bindings/android/`.
//!
//! Kotlin package `uniffi.stoat_crypto` (`uniffi.toml`). The host contract —
//! which call when, request passes, ids in flight, mailbox and ack — is the
//! core's (`stoat_crypto` crate docs); this crate only changes the shapes:
//!
//! * async methods → Kotlin `suspend`; every one runs on the single tokio
//!   runtime of the process ([`runtime`]); a panic becomes
//!   `CryptoException.Panic`, never a crash; a cancelled coroutine leaves the
//!   operation to finish;
//! * errors → `CryptoException.<Code>` with a fixed message; a failed
//!   decryption is a value (`DecryptResult.Failed`), not an exception;
//! * request and response bodies, payload, envelope and `EncryptedFile` are
//!   JSON strings; everything the UI branches on is typed;
//! * objects (`CryptoMachine`, `SasHandle`, `BackupRestore`, attachment
//!   streams) are `AutoCloseable`: close them explicitly (no cleaner on
//!   minSdk 26). The store stays locked while any object of a machine is open;
//! * secrets from Kotlin (store key, recovery key, passphrase) are
//!   `ByteArray`s; the core wipes its copies, the caller fills its array
//!   with zeros (best effort: the JVM may have copied it). The recovery key
//!   crosses to Kotlin once, as `RecoverySetup.recovery_key`.
//!
//! Kotlin's generated `toString()` prints every field: never log
//! `DecryptedMessage`, `StoreConfig` or `RecoverySetup`.

// CR-16: no panics on paths the host calls (the runtime fence catches the
// library's, these lints keep ours out)
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )
)]

uniffi::setup_scaffolding!("stoat_crypto");

mod attachments;
mod backup;
mod error;
mod machine;
mod runtime;
mod sas;
mod types;

pub use attachments::{
    AttachmentDecryptor, AttachmentEncryptor, AttachmentVerifier, EncryptedAttachment, attachment_chunk_size,
    decrypt_attachment, encrypt_attachment,
};
pub use backup::BackupRestore;
pub use error::CryptoError;
pub use machine::{CryptoMachine, destroy_store};
pub use sas::{CancelReason, SasEmoji, SasHandle, SasState, sas_emoji_table};
pub use types::*;

use stoat_crypto::proto::MessagePayload;
use stoat_crypto::proto::payload::PAYLOAD_VERSION;
use stoat_crypto::proto::recovery_key::{self, RecoveryKeyError};
use types::{payload_from_json, payload_to_json, secret_string};

/// Version of the core (= the AAR version)
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Classify the recovery field input as the user types (UTF-8 bytes; the
/// caller zeroes its array)
#[uniffi::export]
pub fn recovery_key_check(input: Vec<u8>) -> Result<RecoveryKeyCheck, CryptoError> {
    let input = secret_string(input)?;
    Ok(match recovery_key::decode(&input) {
        Ok(_) => RecoveryKeyCheck::Valid,
        Err(RecoveryKeyError::Typo) => RecoveryKeyCheck::Typo,
        Err(RecoveryKeyError::NotAKey) => RecoveryKeyCheck::NotAKey,
    })
}

/// Payload v1 JSON of a text message (`client_nonce` = base64 of 16 random
/// bytes, equal to the `nonce` of the send request)
#[uniffi::export]
pub fn text_payload(content: String, client_nonce: String, ts: u64) -> String {
    payload_to_json(MessagePayload::text(content, client_nonce, ts))
}

/// autumn ids to list in the open `attachments` of the send request: every
/// file **and** thumbnail of the payload
#[uniffi::export]
pub fn payload_file_ids(payload_json: String) -> Result<Vec<String>, CryptoError> {
    Ok(payload_from_json(&payload_json)?.file_ids())
}

/// Current payload version (a payload with a higher `v` cannot be read)
#[uniffi::export]
pub fn payload_version() -> u32 {
    PAYLOAD_VERSION
}
