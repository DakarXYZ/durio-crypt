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
//! ## Verification (CR-11)
//!
//! * **Start**: device list → "Verify" → [`request_verification`] →
//!   [`SasHandle`]; the request leaves with the next request pass.
//! * **Incoming**: a mailbox pass returns `ToDeviceResult::verifications`
//!   (flow ids); [`verification`] gives the handle; state `Incoming` → show
//!   the prompt → `accept()` or `cancel()`.
//! * **Flow**: after every mailbox pass and every action re-read
//!   [`SasHandle::state`] and run a request pass: `Ready` → `start()` (either
//!   side; the other side accepts automatically) → `ShowCodes { emoji,
//!   decimals }` → the user compares → `confirm()` or `mismatch()` →
//!   `Confirmed` → `Done` (the device is now `Trust::Verified`). `Cancelled
//!   { reason }` ends the flow (`Mismatch`: warn, possible attack).
//! * **Timeouts**: while a flow is open [`wakeup_in_ms`] is at most 10 s;
//!   the pass it triggers cancels expired flows (`Timeout`). Emoji: index
//!   into [`SAS_EMOJI`], description = translation key.
//!
//! ## Key backup and recovery (CR-12)
//!
//! * **Set up** (settings → "Recovery"): [`create_recovery`] (optional
//!   passphrase) → show `recovery_key()` once, have it written down → run
//!   `request` (`POST /e2ee/backup/version`) and mark it. A 401 →
//!   `MfaRequired` (a backup exists): get an MFA ticket, run **the same
//!   request** again with `x-mfa-ticket`. Once marked sent the backup is on;
//!   the secret uploads (`RequestKind::SecretPut`, survive restarts) and the
//!   key uploads (`RequestKind::BackupKeys`, batches of 100) come from the
//!   normal request passes. [`rotate_backup`]: the same with a new backup key
//!   under the same recovery key (always needs MFA).
//! * **Restore** (new device): `GET /e2ee/secrets/m.secret_storage.default_key`
//!   → `{key: id}` → `GET …/m.secret_storage.key.<id>`, `GET
//!   …/m.megolm_backup.v1`, `GET /e2ee/backup/version` → [`unlock_backup`]
//!   (input = recovery key or passphrase; `RecoveryKeyTypo` vs
//!   `WrongRecoveryKey`) → `GET /e2ee/backup/keys?version=<v>` →
//!   [`restore_backup`] → `next()` until finished (progress bar) → re-decrypt
//!   messages waiting for keys. Restored keys show `Unauthenticated`.
//! * **Replaced elsewhere**: `mark_request_failed` on `BackupKeys` returns
//!   `BackupVersionChanged`; [`backup_status`] says `outdated` → ask for the
//!   recovery key and unlock again. Never upload to a version this device
//!   did not unlock.
//!
//! After a failed request, back off before the next pass: a request the
//! core keeps (secrets, backup batch, own to-device) comes back every pass.
//!
//! ## Attachments (CR-10)
//!
//! * **Upload**: per file [`AttachmentEncryptor::new`] → `update` per chunk
//!   ([`ATTACHMENT_CHUNK`]) → upload the output to `POST
//!   {autumn}/attachments?encrypted=true` → `{id}`; `finish()` → the
//!   `EncryptedFile` for `Attachment::file`. A thumbnail is a separate blob
//!   with its own encryptor ([`encrypt_attachment`] for small ones) and id
//!   (`Attachment::thumbnail`). The send request lists
//!   `payload.file_ids()` (files **and** thumbnails) in its open
//!   `attachments`, else the server deletes the thumbnails after an hour.
//! * **Download**: fetch the blob into a temporary file, hash it with
//!   [`AttachmentVerifier`] (`new(&file)` → `update` per chunk → `finish()`);
//!   only its `Ok` gives the [`AttachmentDecryptor`] for the second pass.
//!   `AttachmentHashMismatch` → show nothing (the server swapped the blob).
//!   Never stream plaintext to a decoder before `finish()` succeeded.
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
//! [`request_verification`]: CryptoMachine::request_verification
//! [`verification`]: CryptoMachine::verification
//! [`create_recovery`]: CryptoMachine::create_recovery
//! [`rotate_backup`]: CryptoMachine::rotate_backup
//! [`unlock_backup`]: CryptoMachine::unlock_backup
//! [`restore_backup`]: CryptoMachine::restore_backup
//! [`backup_status`]: CryptoMachine::backup_status

mod attachments;
mod backup;
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
mod verification;

pub use attachments::{
    ATTACHMENT_CHUNK, AttachmentDecryptor, AttachmentEncryptor, AttachmentVerifier, decrypt_attachment,
    encrypt_attachment,
};
pub use backup::{BackupRestore, BackupStatus, RESTORE_BATCH, RecoverySecrets, RecoverySetup, RestoreProgress};
pub use batch::ServerLimits;
pub use error::{CryptoError, DecryptError, DecryptFailureKind, Result, WithheldReason};
pub use machine::CryptoMachine;
pub use outbox::{Timing, UndeliveredDevice};
pub use requests::{OutgoingRequest, RequestKind};
pub use stoat_crypto_proto as proto;
pub use store::{StoreConfig, StoreKey, indexeddb_names};
pub use types::*;
pub use verification::{CancelReason, SAS_EMOJI, SasEmoji, SasHandle, SasState};

#[cfg(not(target_arch = "wasm32"))]
pub use lock::LOCK_FILE;
