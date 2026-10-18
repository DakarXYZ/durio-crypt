//! CR-08: asking our own devices for a missing room key.
//!
//! The library would send `m.room_key_request` at the first failed decrypt;
//! we switch that off and do it ourselves:
//!
//! * **debounce** — a key often arrives right after its message: a missing
//!   key waits [`Timing::key_request_delay_ms`](crate::Timing) and is asked
//!   for only if it is still missing then;
//! * **no pointless requests** — not for withheld keys, not when no other
//!   own device is verified (only verified devices answer, ADR 0001), not
//!   for a session that belongs to another channel (a message moved by the
//!   server, spike §5.6: reported as `ChannelMismatch` instead);
//! * **cancellation** — a key that arrives directly after the request went
//!   out cancels it; a forwarded key is cancelled by the library itself.
//!
//! The request itself is the library's (`request_room_key`): it records the
//! request, so the forwarded answer is accepted. State is in memory: after a
//! restart the client decrypts the waiting messages again and they queue anew.

use std::collections::HashMap;

use matrix_sdk_crypto::OlmMachine;
use matrix_sdk_crypto::types::events::room::encrypted::EncryptedEvent;
use ruma::serde::Raw;
use ruma::{OwnedRoomId, TransactionId};
use serde_json::json;

use crate::error::{CryptoError, Result};
use crate::outbox::now_ms;
use crate::requests::{self, OutgoingRequest};

/// Bound on keys waiting at once (a long history page of a lost session)
const MAX_WAITING: usize = 1_024;

type Key = (OwnedRoomId, String);

#[derive(Debug)]
struct Waiting {
    due_ms: u64,
    /// Index the message needs: a key known from a later index is still missing
    index: u32,
    /// The encrypted event, kept for `request_room_key` (ciphertext only)
    event: String,
}

#[derive(Debug)]
struct Sent {
    request_id: String,
    index: u32,
}

#[derive(Debug, Default)]
pub(crate) struct KeyRequests {
    waiting: HashMap<Key, Waiting>,
    sent: HashMap<Key, Sent>,
}

impl KeyRequests {
    /// A decrypt failed for a missing key: ask later unless already asked
    pub(crate) fn missing(&mut self, room: OwnedRoomId, session: String, index: u32, event: String, delay_ms: u64) {
        let key = (room, session);
        if self.sent.contains_key(&key) || self.waiting.len() >= MAX_WAITING {
            return;
        }
        self.waiting
            .entry(key)
            .and_modify(|w| w.index = w.index.min(index))
            .or_insert_with(|| Waiting {
                due_ms: now_ms().saturating_add(delay_ms),
                index,
                event,
            });
    }

    /// Already waiting or asked for
    pub(crate) fn is_pending(&self, room: &OwnedRoomId, session: &str) -> bool {
        let key = (room.clone(), session.to_owned());
        self.waiting.contains_key(&key) || self.sent.contains_key(&key)
    }

    /// CR-22: (waiting for the debounce, asked and unanswered)
    pub(crate) fn counts(&self) -> (usize, usize) {
        (self.waiting.len(), self.sent.len())
    }

    /// Milliseconds until the next waiting key is due
    pub(crate) fn next_due_ms(&self) -> Option<u64> {
        self.waiting.values().map(|w| w.due_ms).min()
    }

    fn take_due(&mut self) -> Vec<(Key, Waiting)> {
        let now = now_ms();
        let due: Vec<Key> = self
            .waiting
            .iter()
            .filter(|(_, w)| w.due_ms <= now)
            .map(|(k, _)| k.clone())
            .collect();
        due.into_iter().filter_map(|k| self.waiting.remove_entry(&k)).collect()
    }

    /// A room key arrived: no request for it any more. Returns the request
    /// id to cancel if one went out.
    fn arrived(&mut self, room: &OwnedRoomId, session: &str, first_index: u32) -> Option<String> {
        let key = (room.clone(), session.to_owned());
        if self.waiting.get(&key).is_some_and(|w| first_index <= w.index) {
            self.waiting.remove(&key);
        }
        match self.sent.get(&key) {
            Some(s) if first_index <= s.index => self.sent.remove(&key).map(|s| s.request_id),
            _ => None,
        }
    }
}

/// Does any other own device answer key requests (verified by us)?
async fn any_own_device_verified(olm: &OlmMachine) -> Result<bool> {
    let devices = olm
        .get_user_devices(olm.user_id(), None)
        .await
        .map_err(|_| CryptoError::Store("own devices"))?;
    Ok(devices
        .devices()
        .any(|d| d.device_id() != olm.device_id() && d.is_verified() && !d.is_deleted()))
}

/// Has the session become known (from the needed index) meanwhile?
async fn have_key(olm: &OlmMachine, room: &OwnedRoomId, session: &str, index: u32) -> Result<bool> {
    Ok(olm
        .store()
        .get_inbound_group_session(room, session)
        .await
        .map_err(|_| CryptoError::Store("inbound session"))?
        .is_some_and(|s| s.first_known_index() <= index))
}

/// Send the requests that are due. Returns the to-device requests the library
/// queued (they also come from its `outgoing_requests`, with the same id).
pub(crate) async fn request_due(
    state: &std::sync::Mutex<KeyRequests>,
    olm: &OlmMachine,
) -> Result<Vec<OutgoingRequest>> {
    let due = state.lock().unwrap_or_else(|e| e.into_inner()).take_due();
    if due.is_empty() || !any_own_device_verified(olm).await? {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for ((room, session), w) in due {
        if have_key(olm, &room, &session, w.index).await? {
            continue;
        }
        let raw: Raw<EncryptedEvent> = Raw::from_json(
            serde_json::value::RawValue::from_string(w.event).map_err(|_| CryptoError::Internal("key request"))?,
        );
        let Ok((cancel, request)) = olm.request_room_key(&raw, &room).await else {
            continue;
        };
        // a request from an earlier run is out there already: leave it
        if cancel.is_some() {
            continue;
        }
        if let Some(r) = requests::from_library(request.request_id(), request.request())? {
            out.push(r);
        }
        state.lock().unwrap_or_else(|e| e.into_inner()).sent.insert(
            (room, session),
            Sent {
                request_id: request.request_id().to_string(),
                index: w.index,
            },
        );
    }
    Ok(out)
}

/// Room keys arrived: drop waiting requests; cancel ours that went out and
/// were not answered by a forward (the library deletes and cancels those).
pub(crate) async fn keys_arrived(
    state: &std::sync::Mutex<KeyRequests>,
    olm: &OlmMachine,
    keys: &[(OwnedRoomId, String)],
) -> Result<Vec<OutgoingRequest>> {
    let mut out = Vec::new();
    for (room, session) in keys {
        if !state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_pending(room, session)
        {
            continue;
        }
        let first = match olm.store().get_inbound_group_session(room, session).await {
            Ok(Some(s)) => s.first_known_index(),
            _ => continue,
        };
        let Some(request_id) = state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .arrived(room, session, first)
        else {
            continue;
        };
        let id: &TransactionId = request_id.as_str().into();
        let still_open = olm
            .store()
            .get_outgoing_secret_requests(id)
            .await
            .map_err(|_| CryptoError::Store("key request"))?
            .is_some();
        if !still_open {
            continue;
        }
        olm.store()
            .delete_outgoing_secret_requests(id)
            .await
            .map_err(|_| CryptoError::Store("key request"))?;
        out.push(cancellation(olm, &request_id)?);
    }
    Ok(out)
}

/// `m.room_key_request` with `request_cancellation` to all own devices
fn cancellation(olm: &OlmMachine, request_id: &str) -> Result<OutgoingRequest> {
    let txn = TransactionId::new();
    let body = json!({
        "type": "m.room_key_request",
        "messages": {
            olm.user_id().as_str(): {
                "*": {
                    "action": "request_cancellation",
                    "requesting_device_id": olm.device_id().as_str(),
                    "request_id": request_id,
                }
            }
        }
    });
    Ok(requests::to_device_raw(txn.as_str(), body.to_string()))
}
