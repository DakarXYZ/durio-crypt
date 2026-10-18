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
//!
//! # Host contract (Android, for-web)
//!
//! One machine per account and server, opened once per process; every call
//! may run concurrently, the machine serializes what must be serialized.
//!
//! 1. **Open**: [`CryptoMachine::open`], then [`set_server_limits`] from
//!    `GET /` → `features.e2ee`, then a request pass (6).
//! 2. **Socket Ready / reconnect**: [`receive_reconnect`] (every tracked user
//!    is queried again, Q10); then *always* fetch the mailbox — a doorbell lost
//!    while offline is never repeated (BE-09) — and `GET /e2ee/keys/count` →
//!    [`receive_otk_counts`]; then a request pass.
//! 3. **Mailbox**: on `E2eeToDevice` (and after Ready) `GET
//!    /e2ee/to_device?limit=100` → [`receive_to_device`] → `POST
//!    /e2ee/to_device/ack {ack_ids}` (≤ 100 per call) → [`mark_ack_sent`];
//!    repeat while the page was full. Re-decrypt the messages waiting for the
//!    `room_keys` it returns. On `E2eeKeysLow`: `keys/count` as in 2.
//! 4. **Device lists**: `E2eeDeviceListUpdate {user}` →
//!    [`receive_device_list_update`].
//! 5. **Members**: whenever the client learns the full member list of an
//!    encrypted DM/group (channel load, Ready, `ChannelGroupJoin/Leave`,
//!    encryption enabled) → [`set_channel_members`]. The backend sends no
//!    device-list update on join/leave; the core re-queries and rotates.
//! 6. **Request pass**: [`outgoing_requests`] → run each request → exactly
//!    one [`mark_request_sent`] (body of the 2xx, may be empty) or
//!    [`mark_request_failed`] (status) per run. Repeat until a pass returns
//!    nothing. While a request is in flight a later pass (or `prepare_send`)
//!    returns **the same id** again — the claim, the key upload, key queries,
//!    to-device messages: keep a set of ids in flight and do not start one
//!    twice. Run a pass after every call above, and when [`wakeup_in_ms`]
//!    says (debounced key requests, retries of full mailboxes).
//! 7. **Send** (per channel, one at a time): loop [`prepare_send`] → run →
//!    mark until it returns nothing, then [`encrypt`] (`RoomKeyNotShared` →
//!    back to `prepare_send`), then `POST /channels/{id}/messages`. Edits:
//!    the same with `edit_of` = the message id and `edit_seq` + 1, then
//!    `PATCH`.
//! 8. **Read**: [`decrypt`] / [`decrypt_batch`]; show by
//!    [`DecryptedMessage::is_clean`] and the shield; on error by
//!    [`DecryptError::kind`]. `WaitingForKey` messages are decrypted again
//!    on `room_keys` (3); the core asks own verified devices for the key
//!    by itself.
//! 9. **Logout**: drop the machine, then [`CryptoMachine::destroy`].
//!
//! Report [`undelivered_devices`] in the UI (a device whose mailbox stays
//! full misses keys).
//!
//! [`set_server_limits`]: CryptoMachine::set_server_limits
//! [`receive_reconnect`]: CryptoMachine::receive_reconnect
//! [`receive_otk_counts`]: CryptoMachine::receive_otk_counts
//! [`receive_to_device`]: CryptoMachine::receive_to_device
//! [`mark_ack_sent`]: CryptoMachine::mark_ack_sent
//! [`receive_device_list_update`]: CryptoMachine::receive_device_list_update
//! [`set_channel_members`]: CryptoMachine::set_channel_members
//! [`outgoing_requests`]: CryptoMachine::outgoing_requests
//! [`mark_request_sent`]: CryptoMachine::mark_request_sent
//! [`mark_request_failed`]: CryptoMachine::mark_request_failed
//! [`wakeup_in_ms`]: CryptoMachine::wakeup_in_ms
//! [`prepare_send`]: CryptoMachine::prepare_send
//! [`encrypt`]: CryptoMachine::encrypt
//! [`decrypt`]: CryptoMachine::decrypt
//! [`decrypt_batch`]: CryptoMachine::decrypt_batch
//! [`undelivered_devices`]: CryptoMachine::undelivered_devices

mod batch;
mod binding;
mod error;
mod gossip;
mod ids;
#[cfg(not(target_arch = "wasm32"))]
mod lock;
mod machine;
mod outbox;
mod requests;
mod store;
mod types;

pub use batch::ServerLimits;
pub use error::{CryptoError, DecryptError, DecryptFailureKind, Result, WithheldReason};
pub use machine::CryptoMachine;
pub use outbox::{Timing, UndeliveredDevice};
pub use requests::{OutgoingRequest, RequestKind};
pub use stoat_crypto_proto as proto;
pub use store::{StoreConfig, StoreKey, indexeddb_names};
pub use types::*;

#[cfg(not(target_arch = "wasm32"))]
pub use lock::LOCK_FILE;
