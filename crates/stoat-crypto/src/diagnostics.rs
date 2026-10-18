//! CR-22: a diagnostic report the user can send instead of Sentry.
//!
//! [`CryptoMachine::debug_report`] is JSON with **counts, states and error
//! codes only**: no key (public or private), no session id, no ciphertext,
//! no plaintext, no request or response body, no member ids. The only ids
//! are the account's own user and device ULIDs (to find the server logs)
//! and the channel ULIDs the counts are per (metadata the server has).
//! `tests/diagnostics.rs` checks the report against every secret a test
//! account has.
//!
//! The machine records a few things for it in memory (lost on restart):
//! the last decryption failures and request failures (code, kind, status,
//! time), totals of the mailbox, and the last one-time key counts.

use std::collections::{BTreeMap, VecDeque};

use serde_json::{Value, json};

use crate::error::{DecryptError, Result};
use crate::ids;
use crate::machine::CryptoMachine;
use crate::outbox::now_ms;
use crate::requests::RequestKind;

/// Format of the report (bump when a field changes meaning)
pub const DEBUG_REPORT_FORMAT: u32 = 1;
/// Recent failures kept
const RECENT: usize = 32;
/// Channels listed at most (the busiest first)
const MAX_CHANNELS: usize = 256;

/// What the machine records for the report
#[derive(Debug, Default)]
pub(crate) struct Recorder {
    opened_ms: u64,
    decrypted: u64,
    decrypt_errors: BTreeMap<&'static str, u64>,
    recent_decrypt_errors: VecDeque<(u64, &'static str)>,
    recent_request_failures: VecDeque<(u64, &'static str, u16)>,
    mailbox_processed: u64,
    mailbox_duplicates: u64,
    mailbox_undecryptable: u64,
    /// (when, counts per algorithm, unused fallback key types)
    otk_counts: Option<(u64, BTreeMap<String, u64>, Vec<String>)>,
}

fn push<T>(q: &mut VecDeque<T>, item: T) {
    if q.len() >= RECENT {
        q.pop_front();
    }
    q.push_back(item);
}

impl Recorder {
    pub(crate) fn new() -> Self {
        Self {
            opened_ms: now_ms(),
            ..Self::default()
        }
    }

    pub(crate) fn decrypt(&mut self, result: std::result::Result<(), DecryptError>) {
        match result {
            Ok(()) => self.decrypted += 1,
            Err(e) => {
                *self.decrypt_errors.entry(e.code()).or_default() += 1;
                push(&mut self.recent_decrypt_errors, (now_ms(), e.code()));
            }
        }
    }

    pub(crate) fn request_failed(&mut self, kind: RequestKind, status: u16) {
        push(&mut self.recent_request_failures, (now_ms(), kind.as_str(), status));
    }

    pub(crate) fn mailbox(&mut self, processed: usize, duplicates: usize, undecryptable: usize) {
        self.mailbox_processed += processed as u64;
        self.mailbox_duplicates += duplicates as u64;
        self.mailbox_undecryptable += undecryptable as u64;
    }

    pub(crate) fn otk_counts(&mut self, counts: BTreeMap<String, u64>, fallback: Vec<String>) {
        self.otk_counts = Some((now_ms(), counts, fallback));
    }
}

#[derive(Default)]
struct ChannelCounts {
    sessions: u64,
    imported: u64,
    forwarded: u64,
    backed_up: u64,
}

impl CryptoMachine {
    /// A JSON report of the crypto state without secrets (CR-22): sessions
    /// per channel, one-time keys, tracked and dirty users, request queues,
    /// key requests, verification flows, backup, recent decryption and
    /// request failures (codes). For "Send diagnostic report".
    pub async fn debug_report(&self) -> Result<String> {
        let now = now_ms();
        let olm = self.olm();
        let store_err = |_| crate::error::CryptoError::Store("debug report");

        // Megolm sessions per channel (the inbound copies include our own)
        let mut channels: BTreeMap<String, ChannelCounts> = BTreeMap::new();
        let mut other_rooms = 0u64;
        for s in olm.store().get_inbound_group_sessions().await.map_err(store_err)? {
            let Some(channel) = ids::channel_ulid(s.room_id()) else {
                other_rooms += 1;
                continue;
            };
            let c = channels.entry(channel).or_default();
            c.sessions += 1;
            c.imported += u64::from(s.has_been_imported());
            c.forwarded += u64::from(s.forwarder_data.is_some());
            c.backed_up += u64::from(s.backed_up());
        }
        let known = self.known_channel_list().await?;
        for k in &known {
            channels.entry(k.clone()).or_default();
        }
        let total_channels = channels.len();
        let mut listed: Vec<(String, ChannelCounts)> = channels.into_iter().collect();
        listed.sort_by(|a, b| b.1.sessions.cmp(&a.1.sessions).then_with(|| a.0.cmp(&b.0)));
        listed.truncate(MAX_CHANNELS);
        let mut channel_rows = Vec::with_capacity(listed.len());
        for (channel, c) in listed {
            let members = self.channel_member_count(&channel).await?;
            channel_rows.push(json!({
                "channel_id": channel,
                "members": members,
                "inbound_sessions": c.sessions,
                "imported": c.imported,
                "forwarded": c.forwarded,
                "backed_up": c.backed_up,
            }));
        }

        let tracked = olm.store().load_tracked_users().await.map_err(store_err)?;
        let dirty = tracked.iter().filter(|u| u.dirty).count();
        let backup = self.backup_status().await?;
        let (flows, flows_open) = self.flows().counts();
        let (keys_waiting, keys_asked) = self.key_requests().lock().unwrap_or_else(|e| e.into_inner()).counts();
        let unacked = self.processed_unacked().await;
        let outbox = self.outbox_stats().await;
        let undelivered = self.undelivered_devices().await;

        let r = self.recorder();
        let report = json!({
            "format": DEBUG_REPORT_FORMAT,
            "core_version": env!("CARGO_PKG_VERSION"),
            "library": "matrix-sdk-crypto 0.19.1",
            "generated_ms": now,
            "uptime_ms": now.saturating_sub(r.opened_ms),
            "account": { "user_id": self.user_id(), "device_id": self.device_id() },
            "one_time_keys": {
                "server_counts": r.otk_counts.as_ref().map(|(_, c, _)| c),
                "unused_fallback_key_types": r.otk_counts.as_ref().map(|(_, _, f)| f),
                "counts_age_ms": r.otk_counts.as_ref().map(|(at, _, _)| now.saturating_sub(*at)),
            },
            "users": { "tracked": tracked.len(), "dirty": dirty },
            "channels": {
                "total": total_channels,
                "listed": channel_rows,
                "sessions_of_other_rooms": other_rooms,
            },
            "mailbox": {
                "processed_unacked": unacked,
                "processed": r.mailbox_processed,
                "duplicates": r.mailbox_duplicates,
                "undecryptable": r.mailbox_undecryptable,
            },
            "requests": outbox,
            "undelivered_devices": {
                "retrying": undelivered.iter().filter(|d| !d.gave_up).count(),
                "gave_up": undelivered.iter().filter(|d| d.gave_up).count(),
            },
            "key_requests": { "waiting": keys_waiting, "asked": keys_asked },
            "verification": { "flows": flows, "open": flows_open },
            "backup": {
                "enabled": backup.enabled,
                "version": backup.version,
                "outdated": backup.outdated,
                "recovery_set_up": backup.recovery_set_up,
                "keys_total": backup.keys_total,
                "keys_backed_up": backup.keys_backed_up,
            },
            "decryption": {
                "ok": r.decrypted,
                "errors": r.decrypt_errors,
                "recent_errors": r.recent_decrypt_errors.iter()
                    .map(|(at, code)| json!({ "ago_ms": now.saturating_sub(*at), "code": code }))
                    .collect::<Vec<Value>>(),
            },
            "recent_request_failures": r.recent_request_failures.iter()
                .map(|(at, kind, status)| json!({ "ago_ms": now.saturating_sub(*at), "kind": kind, "status": status }))
                .collect::<Vec<Value>>(),
        });
        drop(r);
        Ok(report.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_lists_are_bounded() {
        let mut r = Recorder::new();
        for _ in 0..100 {
            r.decrypt(Err(DecryptError::MissingRoomKey));
            r.request_failed(RequestKind::ToDevice, 500);
        }
        r.decrypt(Ok(()));
        assert_eq!(r.recent_decrypt_errors.len(), RECENT);
        assert_eq!(r.recent_request_failures.len(), RECENT);
        assert_eq!(r.decrypt_errors["missing_room_key"], 100);
        assert_eq!(r.decrypted, 1);
    }
}
