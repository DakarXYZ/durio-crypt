//! dur.io crypto core: E2EE for direct messages and groups.
//!
//! `matrix-sdk-crypto` 0.19.1 (`OlmMachine`) behind a thin adapter (ADR 0001):
//! Stoat ULIDs and `/e2ee/*` JSON on the outside, ruma types only inside.

mod error;
#[allow(dead_code)] // used by the machine façade
mod ids;
#[allow(dead_code)] // used by the machine façade
mod requests;

pub use error::{CryptoError, DecryptError, Result};
pub use requests::{OutgoingRequest, RequestKind};
pub use stoat_crypto_proto as proto;
