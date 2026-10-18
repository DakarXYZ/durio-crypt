//! Wire types of the dur.io end-to-end encryption contract v1 (CR-03).
//!
//! Everything a client or the server exchanges about E2EE, without any
//! cryptography: the message envelope, the encrypted payload, the bodies of
//! `/e2ee/*` (Matrix CS API shape, decision C1), WebSocket events and the
//! identifier mapping (C15).
//!
//! Source of truth for the formats are the JSON vectors in `fixtures/` at the
//! repository root; the backend keeps a byte-identical copy of `fixtures/api`
//! and `fixtures/envelope`.
//!
//! Rules (20-crypto-core, CR-03):
//!
//! * the envelope is strict (`deny_unknown_fields`), the payload is not — newer
//!   clients may add fields;
//! * versioned structures are read version-first: an unknown `v` is
//!   [`UnsupportedVersion`](envelope::EnvelopeError::UnsupportedVersion), not a
//!   parse error;
//! * sizes are checked on the encoded string before decoding;
//! * `Debug` never prints ciphertext, plaintext or key material.

pub mod api;
pub mod b64;
pub mod envelope;
pub mod events;
pub mod ids;
pub mod payload;
pub mod recovery_key;
pub mod to_device;

mod redact;

pub use envelope::{EncryptedEnvelope, EnvelopeError};
pub use payload::{Attachment, EncryptedFile, MegolmPlaintext, MessagePayload, PayloadError, Thumbnail};

/// Megolm, message content in encrypted channels
pub const ALGORITHM_MEGOLM: &str = "m.megolm.v1.aes-sha2";

/// Olm, to-device messages
pub const ALGORITHM_OLM: &str = "m.olm.v1.curve25519-aes-sha2";

/// One-time and fallback key algorithm
pub const KEY_ALGORITHM_SIGNED_CURVE25519: &str = "signed_curve25519";

/// Key backup algorithm (Q22, ADR 0001)
pub const BACKUP_ALGORITHM_MEGOLM_V1: &str = "m.megolm_backup.v1.curve25519-aes-sha2";
