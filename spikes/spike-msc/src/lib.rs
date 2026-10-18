//! Spike CR-01: `matrix-sdk-crypto` (OlmMachine) behind a thin Stoat adapter.
//!
//! * [`ids`] — C15 identifier mapping
//! * [`fakeserver`] — in-memory `/e2ee/*` (JSON in Matrix shape, C1/C2)
//! * [`payload`] — envelope v1 / payload v1 (R5, C7, C8, CR-19)
//! * [`client`] — adapter (prototype of CR-20) + replay layer (CR-19)

pub mod client;
pub mod fakeserver;
pub mod ids;
pub mod payload;
