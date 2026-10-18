//! dur.io crypto core: E2EE for direct messages and groups.
//!
//! `matrix-sdk-crypto` 0.19.1 (`OlmMachine`) behind a thin adapter (ADR 0001):
//! Stoat ULIDs and `/e2ee/*` JSON on the outside, ruma types only inside.
//! The core never does HTTP: [`CryptoMachine`] hands out [`OutgoingRequest`]s,
//! the client performs them and reports the responses.
//!
//! * [`CryptoMachine`] — the façade (API sketch of 20-crypto-core);
//! * [`StoreConfig`] — SQLite / IndexedDB / memory store, key from the host (CR-09);
//! * one writer per account: a file lock next to the store (CR-17);
//! * wire types are re-exported from [`proto`] (`stoat-crypto-proto`, CR-03).
//!
//! Never logs; errors carry codes, not content.

mod error;
mod ids;
#[cfg(not(target_arch = "wasm32"))]
mod lock;
mod machine;
mod requests;
mod store;
mod types;

pub use error::{CryptoError, DecryptError, Result};
pub use machine::CryptoMachine;
pub use requests::{OutgoingRequest, RequestKind};
pub use stoat_crypto_proto as proto;
pub use store::{StoreConfig, StoreKey, indexeddb_names};
pub use types::*;

#[cfg(not(target_arch = "wasm32"))]
pub use lock::LOCK_FILE;
