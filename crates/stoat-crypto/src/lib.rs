//! dur.io crypto core: E2EE for direct messages and groups.
//!
//! `matrix-sdk-crypto` 0.19.1 (`OlmMachine`) behind a thin adapter (ADR 0001):
//! Stoat ULIDs and `/e2ee/*` JSON on the outside, ruma types only inside.

mod error;
#[allow(dead_code)] // used by the machine façade
mod ids;
#[cfg(not(target_arch = "wasm32"))]
mod lock;
#[allow(dead_code)] // used by the machine façade
mod requests;
#[allow(dead_code)] // used by the machine façade
mod store;

pub use error::{CryptoError, DecryptError, Result};
pub use requests::{OutgoingRequest, RequestKind};
pub use store::{StoreConfig, StoreKey, indexeddb_names};
pub use stoat_crypto_proto as proto;

#[cfg(not(target_arch = "wasm32"))]
pub use lock::LOCK_FILE;
