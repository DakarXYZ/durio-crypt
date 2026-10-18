//! CR-19: binding of a decrypted payload to its message — replay and edit
//! rollback tables (ADR 0001, addendum A1).
//!
//! Stored in the library's custom-value table (encrypted like everything in
//! the store, committed with SQLite, survives restarts), bounded:
//!
//! * `stoat.seen.v1.<session>` — per Megolm session: its channel and
//!   `message index → message id`, at most [`MAX_INDICES_PER_SESSION`]
//!   (lowest indices go first); `stoat.seen.v1` lists the sessions in the
//!   order they were first seen, at most [`MAX_SESSIONS`] (oldest go first).
//!   Sessions rotate after 100 messages / a week, so a bucket stays small and
//!   a decrypt costs one read, plus one write the first time an index is seen;
//! * `stoat.edits.v1.<channel>` — per channel, only messages that were edited
//!   (`edit_seq ≥ 1`): the highest version shown, at most
//!   [`MAX_EDITS_PER_CHANNEL`] (oldest message ids — ULIDs — go first).
//!
//! What falls out of a table is no longer checked: a replay of an evicted
//! (session, index) or a rollback of an evicted edit is shown as normal.
//! The first id a device sees for a (session, index) wins: if the server
//! serves the copy first, the original is the one flagged.

use std::collections::{BTreeMap, VecDeque};

use async_lock::Mutex;
use matrix_sdk_crypto::store::{CryptoStoreError, Store};
use serde::{Deserialize, Serialize};

const SEEN: &str = "stoat.seen.v1";
const EDITS: &str = "stoat.edits.v1";

pub(crate) const MAX_SESSIONS: usize = 2_048;
pub(crate) const MAX_INDICES_PER_SESSION: usize = 1_024;
pub(crate) const MAX_EDITS_PER_CHANNEL: usize = 512;

type StoreResult<T> = std::result::Result<T, CryptoStoreError>;

#[derive(Debug, Default, Serialize, Deserialize)]
struct SeenBucket {
    /// Channel (ULID) the session was first seen in
    channel: String,
    /// Message index → message id
    indices: BTreeMap<u32, String>,
}

/// Last shown version of an edited message
#[derive(Debug, Serialize, Deserialize)]
struct EditRecord {
    edit_seq: u64,
    session_id: String,
    message_index: u32,
}

/// What the tables say about one decrypted message
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Binding {
    /// Same (session, index) seen under another message id
    pub(crate) is_replay: bool,
    /// An older version than the one already shown
    pub(crate) stale_edit: bool,
}

/// One message to check
pub(crate) struct Seen<'a> {
    pub(crate) channel: &'a str,
    pub(crate) message_id: &'a str,
    pub(crate) session_id: &'a str,
    pub(crate) index: u32,
    pub(crate) edit_seq: u64,
}

/// Read-modify-write of the tables, serialized
#[derive(Debug, Default)]
pub(crate) struct Tables {
    /// Session order of `stoat.seen.v1`, loaded on first use
    order: Mutex<Option<VecDeque<String>>>,
}

fn seen_key(session: &str) -> String {
    format!("{SEEN}.{session}")
}

fn edits_key(channel: &str) -> String {
    format!("{EDITS}.{channel}")
}

impl Tables {
    pub(crate) async fn check(&self, store: &Store, m: Seen<'_>) -> StoreResult<Binding> {
        let mut order = self.order.lock().await;
        if order.is_none() {
            *order = Some(store.get_value(SEEN).await?.unwrap_or_default());
        }
        let order = order.get_or_insert_with(Default::default);

        // replay: (session, index) → first message id
        let key = seen_key(m.session_id);
        let mut bucket: SeenBucket = match store.get_value(&key).await? {
            Some(b) => b,
            None => {
                order.push_back(m.session_id.to_owned());
                while order.len() > MAX_SESSIONS {
                    if let Some(old) = order.pop_front() {
                        store.remove_custom_value(&seen_key(&old)).await?;
                    }
                }
                store.set_value(SEEN, &*order).await?;
                SeenBucket {
                    channel: m.channel.to_owned(),
                    indices: BTreeMap::new(),
                }
            }
        };
        match bucket.indices.get(&m.index) {
            Some(first) if first != m.message_id => {
                return Ok(Binding {
                    is_replay: true,
                    stale_edit: false,
                });
            }
            Some(_) => {}
            None => {
                bucket.indices.insert(m.index, m.message_id.to_owned());
                while bucket.indices.len() > MAX_INDICES_PER_SESSION {
                    bucket.indices.pop_first();
                }
                store.set_value(&key, &bucket).await?;
            }
        }

        // edits: the highest version shown per edited message
        let key = edits_key(m.channel);
        let mut edits: BTreeMap<String, EditRecord> = store.get_value(&key).await?.unwrap_or_default();
        let stale = match edits.get(m.message_id) {
            // the version already shown (history reload)
            Some(r) if r.session_id == m.session_id && r.message_index == m.index => false,
            Some(r) if m.edit_seq <= r.edit_seq => true,
            None if m.edit_seq == 0 => false,
            _ => {
                edits.insert(
                    m.message_id.to_owned(),
                    EditRecord {
                        edit_seq: m.edit_seq,
                        session_id: m.session_id.to_owned(),
                        message_index: m.index,
                    },
                );
                while edits.len() > MAX_EDITS_PER_CHANNEL {
                    edits.pop_first();
                }
                store.set_value(&key, &edits).await?;
                false
            }
        };
        Ok(Binding {
            is_replay: false,
            stale_edit: stale,
        })
    }

    /// Channel a session was first seen in, if any message of it was decrypted
    pub(crate) async fn channel_of(&self, store: &Store, session: &str) -> StoreResult<Option<String>> {
        Ok(store
            .get_value::<SeenBucket>(&seen_key(session))
            .await?
            .map(|b| b.channel))
    }
}

/// `edit_of`/`edit_seq` consistency. Stoat edits are an in-place `PATCH`: the
/// message keeps its id, so an edit names the message that carries it. An
/// original has neither field; an edit has both.
pub(crate) fn edit_mismatch(message_id: &str, edit_of: Option<&str>, edit_seq: u64) -> bool {
    match (edit_of, edit_seq) {
        (None, 0) => false,
        (Some(of), seq) if seq >= 1 => of != message_id,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use matrix_sdk_crypto::OlmMachine;
    use ruma::{device_id, user_id};

    use super::*;

    fn seen<'a>(message_id: &'a str, session_id: &'a str, index: u32, edit_seq: u64) -> Seen<'a> {
        Seen {
            channel: "C",
            message_id,
            session_id,
            index,
            edit_seq,
        }
    }

    async fn machine() -> OlmMachine {
        OlmMachine::new(user_id!("@01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid"), device_id!("D")).await
    }

    #[tokio::test]
    async fn replay_and_rollback() {
        let olm = machine().await;
        let t = Tables::default();
        let s = olm.store();
        assert_eq!(t.check(s, seen("M1", "S", 0, 0)).await.unwrap(), Binding::default());
        // history reload
        assert_eq!(t.check(s, seen("M1", "S", 0, 0)).await.unwrap(), Binding::default());
        // the same ciphertext under another id
        assert!(t.check(s, seen("M2", "S", 0, 0)).await.unwrap().is_replay);
        // an edit of M1, then the original served again
        assert_eq!(t.check(s, seen("M1", "S", 1, 1)).await.unwrap(), Binding::default());
        assert_eq!(t.check(s, seen("M1", "S", 1, 1)).await.unwrap(), Binding::default());
        assert!(t.check(s, seen("M1", "S", 0, 0)).await.unwrap().stale_edit);
        assert!(
            t.check(s, seen("M1", "T", 0, 1)).await.unwrap().stale_edit,
            "same seq, other ciphertext"
        );
        assert_eq!(t.check(s, seen("M1", "T", 1, 2)).await.unwrap(), Binding::default());
        assert_eq!(t.channel_of(s, "S").await.unwrap().as_deref(), Some("C"));
        assert_eq!(t.channel_of(s, "X").await.unwrap(), None);
    }

    #[tokio::test]
    async fn tables_are_bounded() {
        let olm = machine().await;
        let t = Tables::default();
        let s = olm.store();
        for i in 0..(MAX_INDICES_PER_SESSION as u32 + 10) {
            t.check(s, seen(&format!("M{i:05}"), "S", i, 0)).await.unwrap();
        }
        let b: SeenBucket = s.get_value(&seen_key("S")).await.unwrap().unwrap();
        assert_eq!(b.indices.len(), MAX_INDICES_PER_SESSION);
        assert_eq!(b.indices.keys().next(), Some(&10));

        for i in 0..(MAX_SESSIONS + 3) {
            t.check(s, seen("M", &format!("S{i}"), 0, 0)).await.unwrap();
        }
        let order: VecDeque<String> = s.get_value(SEEN).await.unwrap().unwrap();
        assert_eq!(order.len(), MAX_SESSIONS);
        assert!(
            s.get_value::<SeenBucket>(&seen_key("S")).await.unwrap().is_none(),
            "oldest evicted"
        );
        assert!(s.get_value::<SeenBucket>(&seen_key("S0")).await.unwrap().is_none());
        assert!(s.get_value::<SeenBucket>(&seen_key("S3")).await.unwrap().is_some());

        for i in 0..(MAX_EDITS_PER_CHANNEL + 5) {
            t.check(s, seen(&format!("E{i:05}"), "SE", i as u32, 1)).await.unwrap();
        }
        let edits: BTreeMap<String, EditRecord> = s.get_value(&edits_key("C")).await.unwrap().unwrap();
        assert_eq!(edits.len(), MAX_EDITS_PER_CHANNEL);
        assert!(!edits.contains_key("E00000"));
    }

    #[test]
    fn edit_fields_must_agree() {
        assert!(!edit_mismatch("M", None, 0));
        assert!(!edit_mismatch("M", Some("M"), 1));
        assert!(!edit_mismatch("M", Some("M"), 7));
        assert!(edit_mismatch("M", Some("N"), 1), "edit carried by another message");
        assert!(edit_mismatch("M", Some("M"), 0), "edit without a sequence");
        assert!(edit_mismatch("M", None, 2), "sequence without an edit");
    }
}
