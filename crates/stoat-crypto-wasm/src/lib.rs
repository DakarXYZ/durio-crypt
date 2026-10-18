//! dur.io crypto core for for-web inside the Windows client (CR-14):
//! wasm-bindgen bindings over [`stoat_crypto`], packaged as the npm package
//! `@durio/stoat-crypto` by `bindings/web/` (`scripts/build-wasm.sh`).
//!
//! The surface is the one of the Android FFI (`stoat-crypto-ffi`), so both
//! clients behave the same; the host contract — which call when, request
//! passes, ids in flight, mailbox and ack — is the core's (`stoat_crypto`
//! crate docs). This crate only changes the shapes:
//!
//! * async methods → `Promise`s; the machine lives in a dedicated Web Worker
//!   (`bindings/web/src/worker.ts`), the page talks to it over a small RPC;
//! * errors → a thrown `Error` with `name = "StoatCryptoError"` and `code` =
//!   the FFI variant name (`StoreLocked`, `WrongPassphrase`, …) and the
//!   core's fixed message (no keys, plaintext or input, CR-16); a failed
//!   decryption is a value (`{type: "Failed"}`), not an exception;
//! * records are plain objects (`serde-wasm-bindgen`, maps as objects, `None`
//!   as `null`, camelCase fields); numbers are `u32`/`f64`, never `BigInt`;
//!   request and response bodies, payload, envelope and `EncryptedFile` are
//!   JSON strings as on Android;
//! * secrets from JS (store key, recovery key, passphrase) are
//!   `Uint8Array`s: the core wipes its copy, the caller fills its array with
//!   zeros (the worker does);
//! * objects (`CryptoMachine`, `SasHandle`, `BackupRestore`, attachment
//!   streams) are freed with `free()` (the worker does it on `close`);
//! * `panic = "abort"`: a panic traps (`WebAssembly.RuntimeError`) and the
//!   instance is unusable — the worker answers `Panic` from then on and the
//!   host starts a new worker (the store is consistent: every core operation
//!   is a store transaction);
//! * `set_device_trust(.., Verified)` is refused (`InvalidInput`): trust
//!   comes from SAS only (review O-3), enforced here rather than in the host.
//!
//! Store: IndexedDB (`matrix-sdk-indexeddb`, values encrypted with the raw
//! 32-byte key from Electron `safeStorage`, no PBKDF2) named by the host per
//! account (`durio-e2ee-<accountKey>`). The library does not stop a second
//! machine on the same databases (CR-17): the worker holds the Web Lock
//! `durio-e2ee:<accountKey>` while the machine is open (`bindings/web`).
//!
//! Never log `DecryptResult` / `DecryptedMessage` (plaintext and attachment
//! keys), `RecoverySetup` (recovery key), `encryptAttachment` results or
//! `KeyExport`.

#![cfg(target_arch = "wasm32")]
// CR-16: no panics on paths the host calls (a panic aborts the instance)
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

mod attachments;
mod error;
mod machine;
mod sas;
mod types;

pub use attachments::{AttachmentDecryptor, AttachmentEncryptor, AttachmentVerifier};
pub use error::Error;
pub use machine::{BackupRestore, CryptoMachine};
pub use sas::SasHandle;

use js_sys::Uint8Array;
use stoat_crypto::proto::MessagePayload;
use stoat_crypto::proto::payload::PAYLOAD_VERSION;
use stoat_crypto::proto::recovery_key::{self, RecoveryKeyError};
use wasm_bindgen::prelude::*;

use crate::types::{payload_from_json, payload_to_json, secret_string, to_js};

/// Version of the core (= the npm package and AAR version)
#[wasm_bindgen(js_name = coreVersion)]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Classify the recovery field input as the user types (UTF-8 bytes; the
/// caller zeroes its array): `"Valid"`, `"Typo"` or `"NotAKey"`
#[wasm_bindgen(js_name = recoveryKeyCheck)]
pub fn recovery_key_check(input: Vec<u8>) -> Result<String, JsValue> {
    let input = secret_string(input)?;
    Ok(match recovery_key::decode(&input) {
        Ok(_) => "Valid",
        Err(RecoveryKeyError::Typo) => "Typo",
        Err(RecoveryKeyError::NotAKey) => "NotAKey",
    }
    .to_owned())
}

/// Payload v1 JSON of a text message (`clientNonce` = base64 of 16 random
/// bytes, equal to the `nonce` of the send request; `ts` in milliseconds)
#[wasm_bindgen(js_name = textPayload)]
pub fn text_payload(content: String, client_nonce: String, ts: f64) -> Result<String, JsValue> {
    let ts = types::millis(ts)?;
    Ok(payload_to_json(MessagePayload::text(content, client_nonce, ts)))
}

/// autumn ids to list in the open `attachments` of the send request: every
/// file **and** thumbnail of the payload
#[wasm_bindgen(js_name = payloadFileIds)]
pub fn payload_file_ids(payload_json: String) -> Result<Vec<String>, JsValue> {
    Ok(payload_from_json(&payload_json)?.file_ids())
}

/// Current payload version (a payload with a higher `v` cannot be read)
#[wasm_bindgen(js_name = payloadVersion)]
pub fn payload_version() -> u32 {
    PAYLOAD_VERSION
}

/// The 64 SAS emoji: `[{index, symbol, description}]` (description =
/// translation key)
#[wasm_bindgen(js_name = sasEmojiTable)]
pub fn sas_emoji_table() -> Result<JsValue, JsValue> {
    let table: Vec<types::SasEmoji> = stoat_crypto::SAS_EMOJI
        .iter()
        .zip(0u8..)
        .map(|((symbol, description), index)| types::SasEmoji {
            index,
            symbol: (*symbol).to_owned(),
            description: (*description).to_owned(),
        })
        .collect();
    Ok(to_js(&table)?)
}

/// IndexedDB databases the store `name` consists of: delete them (after the
/// machine is closed) to destroy the account's store on sign-out
#[wasm_bindgen(js_name = indexeddbNames)]
pub fn indexeddb_names(name: String) -> Vec<String> {
    stoat_crypto::indexeddb_names(&name).into()
}

/// Recommended attachment chunk size in bytes
#[wasm_bindgen(js_name = attachmentChunkSize)]
pub fn attachment_chunk_size() -> u32 {
    u32::try_from(stoat_crypto::ATTACHMENT_CHUNK).unwrap_or(u32::MAX)
}

/// A small blob (thumbnail) in one call: `{ciphertext: Uint8Array, fileJson}`
/// (`fileJson` holds the key: never log it)
#[wasm_bindgen(js_name = encryptAttachment)]
pub fn encrypt_attachment(data: &[u8]) -> Result<JsValue, JsValue> {
    let (ciphertext, file) = stoat_crypto::encrypt_attachment(data);
    let out = js_sys::Object::new();
    let ciphertext = Uint8Array::from(ciphertext.as_slice());
    js_sys::Reflect::set(&out, &"ciphertext".into(), &ciphertext)?;
    js_sys::Reflect::set(&out, &"fileJson".into(), &attachments::file_to_json(&file)?.into())?;
    Ok(out.into())
}

/// Verify the hash, then decrypt (small blobs)
#[wasm_bindgen(js_name = decryptAttachment)]
pub fn decrypt_attachment(ciphertext: &[u8], file_json: String) -> Result<Vec<u8>, JsValue> {
    let file = attachments::file_from_json(&file_json)?;
    Ok(stoat_crypto::decrypt_attachment(ciphertext, &file).map_err(Error::from)?)
}
