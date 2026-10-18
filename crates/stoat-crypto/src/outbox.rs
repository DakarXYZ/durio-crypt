//! What the machine hands out and how it is marked back (host contract in
//! the crate docs):
//!
//! * **stable ids** — the library's `outgoing_requests` forgets the key
//!   queries in flight on every call (their answers then do not clear the
//!   dirty flags) and gives the key upload a new id each time. Its requests
//!   are therefore cached: refreshed only after something changed, never
//!   while a key query is in flight (unless `prepare_send` needs fresh
//!   member keys or the query is older than [`QUERY_STALE_MS`]); an upload
//!   with the same body keeps its id;
//! * **one claim** in flight at a time (each claim burns one-time keys);
//! * **parts** — bodies over the server limits are cut ([`batch`]); the
//!   library request is marked once every part is;
//! * **retries** — devices refused for a full mailbox (`failed`) get the same
//!   content again with a new transaction id, with exponential backoff, at
//!   most [`Timing::to_device_retry_attempts`] times; then they are reported
//!   by `undelivered_devices`. Pending retries survive restarts (store);
//! * **own requests** (verification messages, key request cancellations,
//!   secret uploads) that fail come back after an exponential delay
//!   ([`Timing::own_retry_ms`], doubled per failure, at most
//!   [`OWN_BACKOFF_CAP_MS`]) instead of on every pass; after
//!   [`OWN_MAX_REJECTIONS`] permanent refusals (4xx other than 401, 408,
//!   429) the request is dropped and reported (review O-2). A retry of a
//!   full mailbox refused that way gives its devices up the same way.

use std::collections::{HashMap, VecDeque};

use crate::batch::{self, ServerLimits};
use crate::requests::{self, OutgoingRequest, RequestKind};
use serde::{Deserialize, Serialize};

/// Wall clock, milliseconds (works in wasm too)
pub(crate) fn now_ms() -> u64 {
    ruma::MilliSecondsSinceUnixEpoch::now().get().into()
}

/// A key query older than this no longer holds back a refresh
pub(crate) const QUERY_STALE_MS: u64 = 60_000;
/// Bound on to-device bodies remembered for `failed` retries
const MAX_HANDED: usize = 4_096;
/// Bound on retries and on devices given up on
const MAX_RETRIES: usize = 256;
const MAX_GAVE_UP: usize = 64;
/// Permanent refusals of an own request before it is dropped (review O-2)
pub const OWN_MAX_REJECTIONS: u32 = 3;
/// Longest delay between two attempts of an own request
pub const OWN_BACKOFF_CAP_MS: u64 = 15 * 60_000;
/// Dropped requests remembered for `debug_report`
const MAX_REJECTED: usize = 32;

/// A refusal the server will repeat: client errors except authentication
/// (the host renews it), timeouts and rate limits. 0 = no response.
pub(crate) fn is_permanent(status: u16) -> bool {
    (400..500).contains(&status) && !matches!(status, 401 | 408 | 429)
}

/// Delay before attempt `failures + 1`
fn own_backoff(base_ms: u64, failures: u32) -> u64 {
    base_ms
        .saturating_mul(1u64 << failures.saturating_sub(1).min(20))
        .min(OWN_BACKOFF_CAP_MS)
}

/// Key of the persisted retries
pub(crate) const KV_RETRIES: &str = "stoat.outbox.retries.v1";

/// Delays of the core's own policies. The defaults are for production;
/// tests shorten them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// Wait before asking own devices for a missing room key (CR-08: 2–5 s)
    pub key_request_delay_ms: u64,
    /// First retry of a to-device message refused for a full mailbox,
    /// doubled after each attempt
    pub to_device_retry_ms: u64,
    /// Attempts before the device is reported as undelivered
    pub to_device_retry_attempts: u32,
    /// First delay after a failed own request (verification, cancellation,
    /// secret upload), doubled after each failure (review O-2)
    pub own_retry_ms: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            key_request_delay_ms: 3_000,
            to_device_retry_ms: 60_000,
            // 1 + 2 + … + 128 min ≈ 4 h
            to_device_retry_attempts: 8,
            own_retry_ms: 1_000,
        }
    }
}

/// A device that did not get a to-device message because its mailbox was
/// full (backend `failed`, Q11)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndeliveredDevice {
    /// User id (ULID)
    pub user_id: String,
    pub device_id: String,
    /// Attempts so far
    pub attempts: u32,
    /// No more retries: the device misses this message (room keys of it are
    /// lost until the next rotation or a key request of its own)
    pub gave_up: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Retry {
    id: String,
    /// `{type, messages}` addressed to the refused devices only
    body: String,
    attempts: u32,
    due_ms: u64,
    /// Permanent HTTP refusals of this retry (review O-2)
    #[serde(default)]
    rejections: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Retries {
    pending: Vec<Retry>,
    /// (Matrix user id, device id, attempts)
    gave_up: Vec<(String, String, u32)>,
}

#[derive(Debug)]
struct Split {
    kind: RequestKind,
    parts: Vec<OutgoingRequest>,
    /// Response body per part once marked sent
    responses: Vec<Option<String>>,
}

/// Outcome of marking a part
pub(crate) enum PartMark {
    /// Not a part of a split request
    NotAPart,
    /// Other parts are still in flight
    Pending,
    /// Every part is done: mark the library request with this body
    Finished { parent: String, body: String },
}

#[derive(Debug, Default)]
pub(crate) struct Outbox {
    pub(crate) limits: ServerLimits,
    pub(crate) timing: Timing,
    /// Library requests of the last refresh, minus the ones marked
    pub(crate) cached: Vec<OutgoingRequest>,
    pub(crate) refreshed_ms: u64,
    /// Key upload in flight: a new one with the same body keeps its id
    upload: Option<OutgoingRequest>,
    /// The claim in flight (library request, not its parts)
    pub(crate) claim: Option<OutgoingRequest>,
    splits: HashMap<String, Split>,
    part_of: HashMap<String, String>,
    /// To-device bodies handed out, for re-sending to `failed` devices
    handed: HashMap<String, String>,
    /// Our own requests (verification, key request cancellations, secret
    /// uploads) and their failures
    own: HashMap<String, Own>,
    /// Own requests and retries dropped after permanent refusals
    rejected: VecDeque<Rejected>,
    pub(crate) retries: Retries,
}

#[derive(Debug)]
struct Own {
    request: OutgoingRequest,
    failures: u32,
    rejections: u32,
    due_ms: u64,
}

/// A request of the core the server kept refusing (review O-2)
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rejected {
    pub(crate) kind: RequestKind,
    pub(crate) status: u16,
    pub(crate) attempts: u32,
}

/// What a failure of an own request leads to
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OwnFailure {
    /// Comes back after the backoff
    Later,
    /// Dropped: the server refused it [`OWN_MAX_REJECTIONS`] times
    Dropped(RequestKind),
}

fn to_device(id: String, body: String) -> OutgoingRequest {
    requests::to_device_raw(&id, body)
}

fn fresh_id() -> String {
    ruma::TransactionId::new().to_string()
}

impl Outbox {
    /// Retries persisted by an earlier run
    pub(crate) fn with_retries(retries: Retries) -> Self {
        Self {
            retries,
            ..Self::default()
        }
    }

    /// Does a key query in flight hold back a refresh?
    pub(crate) fn query_in_flight(&self) -> bool {
        self.cached.iter().any(|r| r.kind == RequestKind::KeysQuery)
            && now_ms().saturating_sub(self.refreshed_ms) < QUERY_STALE_MS
    }

    /// New library requests replace the cache; the upload keeps its id
    pub(crate) fn refreshed(&mut self, mut fresh: Vec<OutgoingRequest>) {
        for r in fresh.iter_mut().filter(|r| r.kind == RequestKind::KeysUpload) {
            match &self.upload {
                Some(u) if u.body == r.body => r.id = u.id.clone(),
                _ => self.upload = Some(r.clone()),
            }
        }
        self.cached = fresh;
        self.refreshed_ms = now_ms();
    }

    /// The library request `id` is done (sent or failed)
    pub(crate) fn forget(&mut self, id: &str) {
        self.cached.retain(|r| r.id != id);
        if self.upload.as_ref().is_some_and(|u| u.id == id) {
            self.upload = None;
        }
        if self.claim.as_ref().is_some_and(|c| c.id == id) {
            self.claim = None;
        }
        if let Some(split) = self.splits.remove(id) {
            for p in split.parts {
                self.part_of.remove(&p.id);
                self.handed.remove(&p.id);
            }
        }
        self.handed.remove(id);
    }

    pub(crate) fn add_own(&mut self, r: OutgoingRequest) {
        self.own.insert(
            r.id.clone(),
            Own {
                request: r,
                failures: 0,
                rejections: 0,
                due_ms: 0,
            },
        );
    }

    /// Requests as the client must send them: parts instead of oversized
    /// bodies (only the parts not marked yet)
    pub(crate) fn expand(&mut self, r: OutgoingRequest) -> Vec<OutgoingRequest> {
        if let Some(split) = self.splits.get(&r.id) {
            return split
                .parts
                .iter()
                .zip(&split.responses)
                .filter(|(_, done)| done.is_none())
                .map(|(p, _)| p.clone())
                .collect();
        }
        let bodies = match r.kind {
            RequestKind::ToDevice => batch::split_to_device(&r.body, &self.limits),
            RequestKind::KeysClaim => batch::split_claim(&r.body),
            _ => None,
        };
        let Some(bodies) = bodies else {
            if r.kind == RequestKind::ToDevice {
                self.remember(&r);
            }
            return vec![r];
        };
        let parts: Vec<OutgoingRequest> = bodies
            .into_iter()
            .map(|body| {
                let id = fresh_id();
                match r.kind {
                    RequestKind::ToDevice => to_device(id, body),
                    _ => OutgoingRequest { id, body, ..r.clone() },
                }
            })
            .collect();
        for p in &parts {
            self.part_of.insert(p.id.clone(), r.id.clone());
            if p.kind == RequestKind::ToDevice {
                self.remember(p);
            }
        }
        self.splits.insert(
            r.id.clone(),
            Split {
                kind: r.kind,
                responses: vec![None; parts.len()],
                parts: parts.clone(),
            },
        );
        parts
    }

    fn remember(&mut self, r: &OutgoingRequest) {
        if self.handed.len() >= MAX_HANDED {
            self.handed.clear();
        }
        self.handed.insert(r.id.clone(), r.body.clone());
    }

    /// Our own requests and the retries that are due
    pub(crate) fn own_and_due(&mut self) -> Vec<OutgoingRequest> {
        let now = now_ms();
        let mut out: Vec<OutgoingRequest> = self
            .own
            .values()
            .filter(|o| o.due_ms <= now)
            .map(|o| o.request.clone())
            .collect();
        out.extend(
            self.retries
                .pending
                .iter()
                .filter(|r| r.due_ms <= now)
                .map(|r| to_device(r.id.clone(), r.body.clone())),
        );
        for r in &out {
            self.handed.insert(r.id.clone(), r.body.clone());
        }
        out
    }

    pub(crate) fn next_retry_ms(&self) -> Option<u64> {
        let own = self.own.values().filter(|o| o.failures > 0).map(|o| o.due_ms);
        self.retries.pending.iter().map(|r| r.due_ms).chain(own).min()
    }

    /// An own request failed with `status`: back off, or drop it after
    /// [`OWN_MAX_REJECTIONS`] permanent refusals
    pub(crate) fn own_failed(&mut self, id: &str, status: u16) -> OwnFailure {
        let base = self.timing.own_retry_ms;
        let Some(o) = self.own.get_mut(id) else {
            return OwnFailure::Later;
        };
        o.failures += 1;
        if is_permanent(status) {
            o.rejections += 1;
        }
        if o.rejections >= OWN_MAX_REJECTIONS {
            let kind = o.request.kind;
            let attempts = o.failures;
            self.own.remove(id);
            self.handed.remove(id);
            self.reject(kind, status, attempts);
            return OwnFailure::Dropped(kind);
        }
        o.due_ms = now_ms().saturating_add(own_backoff(base, o.failures));
        OwnFailure::Later
    }

    fn reject(&mut self, kind: RequestKind, status: u16, attempts: u32) {
        if self.rejected.len() >= MAX_REJECTED {
            self.rejected.pop_front();
        }
        self.rejected.push_back(Rejected { kind, status, attempts });
    }

    pub(crate) fn is_own(&self, id: &str) -> bool {
        self.own.contains_key(id)
    }

    pub(crate) fn is_retry(&self, id: &str) -> bool {
        self.retries.pending.iter().any(|r| r.id == id)
    }

    /// A to-device request (any kind) was answered: queue the `failed`
    /// devices. Returns true if the retries changed (persist them).
    pub(crate) fn delivered(&mut self, id: &str, response: &str) -> bool {
        let failed = batch::failed_recipients(response);
        let mut changed = false;
        let attempts = match self.retries.pending.iter().position(|r| r.id == id) {
            Some(i) => {
                changed = true;
                self.retries.pending.remove(i).attempts
            }
            None => 0,
        };
        let body = self.handed.remove(id);
        // devices given up on that got something again are fine now
        if !self.retries.gave_up.is_empty()
            && let Some(b) = &body
        {
            let got: Vec<(String, String)> = batch::recipients(b)
                .into_iter()
                .filter(|d| !failed.contains(d))
                .collect();
            let before = self.retries.gave_up.len();
            self.retries
                .gave_up
                .retain(|(u, d, _)| !got.iter().any(|(gu, gd)| gu == u && (gd == d || gd == "*")));
            changed |= before != self.retries.gave_up.len();
        }
        if failed.is_empty() {
            return changed;
        }
        let Some(body) = body.and_then(|b| batch::restrict_to_device(&b, &failed)) else {
            return changed;
        };
        let attempts = attempts + 1;
        if attempts > self.timing.to_device_retry_attempts {
            for (u, d) in failed {
                self.retries.gave_up.retain(|(gu, gd, _)| !(gu == &u && gd == &d));
                self.retries.gave_up.push((u, d, attempts - 1));
            }
            let excess = self.retries.gave_up.len().saturating_sub(MAX_GAVE_UP);
            self.retries.gave_up.drain(..excess);
            return true;
        }
        let backoff = self
            .timing
            .to_device_retry_ms
            .saturating_mul(1u64 << (attempts - 1).min(20));
        self.retries.pending.push(Retry {
            id: fresh_id(),
            body,
            attempts,
            due_ms: now_ms().saturating_add(backoff),
            rejections: 0,
        });
        let excess = self.retries.pending.len().saturating_sub(MAX_RETRIES);
        self.retries.pending.drain(..excess);
        true
    }

    /// A retry failed at the HTTP level: try again after the base delay;
    /// refused permanently [`OWN_MAX_REJECTIONS`] times, its devices are
    /// given up. Returns true if the retries changed (persist them).
    pub(crate) fn retry_failed(&mut self, id: &str, status: u16) -> bool {
        let delay = self.timing.to_device_retry_ms;
        self.handed.remove(id);
        let Some(i) = self.retries.pending.iter().position(|r| r.id == id) else {
            return false;
        };
        let r = &mut self.retries.pending[i];
        r.due_ms = now_ms().saturating_add(delay);
        if is_permanent(status) {
            r.rejections += 1;
        }
        if r.rejections < OWN_MAX_REJECTIONS {
            return r.rejections > 0;
        }
        let r = self.retries.pending.remove(i);
        for (u, d) in batch::recipients(&r.body) {
            self.retries.gave_up.retain(|(gu, gd, _)| !(gu == &u && gd == &d));
            self.retries.gave_up.push((u, d, r.attempts));
        }
        let excess = self.retries.gave_up.len().saturating_sub(MAX_GAVE_UP);
        self.retries.gave_up.drain(..excess);
        self.reject(RequestKind::ToDevice, status, r.attempts);
        true
    }

    pub(crate) fn own_done(&mut self, id: &str) {
        self.own.remove(id);
        self.handed.remove(id);
    }

    /// Mark a part sent. Claim parts keep their response for the merge.
    pub(crate) fn part_sent(&mut self, id: &str, body: &str) -> PartMark {
        let Some(parent) = self.part_of.get(id).cloned() else {
            return PartMark::NotAPart;
        };
        let Some(split) = self.splits.get_mut(&parent) else {
            return PartMark::NotAPart;
        };
        if let Some(i) = split.parts.iter().position(|p| p.id == id) {
            split.responses[i] = Some(body.to_owned());
        }
        if split.responses.iter().any(Option::is_none) {
            return PartMark::Pending;
        }
        let body = match split.kind {
            RequestKind::KeysClaim => {
                batch::merge_claim_responses(split.responses.iter().flatten().map(String::as_str))
            }
            // to-device: `failed` was handled per part
            _ => "{}".to_owned(),
        };
        PartMark::Finished { parent, body }
    }

    pub(crate) fn is_part(&self, id: &str) -> bool {
        self.part_of.contains_key(id)
    }

    /// CR-22: counts only — no bodies, no ids
    pub(crate) fn stats(&self) -> serde_json::Value {
        let mut cached = std::collections::BTreeMap::<&str, usize>::new();
        for r in &self.cached {
            *cached.entry(r.kind.as_str()).or_default() += 1;
        }
        serde_json::json!({
            "cached": cached,
            "upload_in_flight": self.upload.is_some(),
            "claim_in_flight": self.claim.is_some(),
            "split_requests": self.splits.len(),
            "own": self.own.len(),
            "own_backing_off": self.own.values().filter(|o| o.failures > 0).count(),
            "rejected": self.rejected.iter()
                .map(|r| serde_json::json!({ "kind": r.kind.as_str(), "status": r.status, "attempts": r.attempts }))
                .collect::<Vec<_>>(),
            "retries_pending": self.retries.pending.len(),
            "retry_attempts_max": self.retries.pending.iter().map(|r| r.attempts).max().unwrap_or(0),
            "devices_given_up": self.retries.gave_up.len(),
            "limits": {
                "max_to_device_batch": self.limits.max_to_device_batch,
                "max_request_bytes": self.limits.max_request_bytes,
            },
        })
    }

    pub(crate) fn undelivered(&self) -> Vec<(String, String, u32, bool)> {
        let mut out: Vec<(String, String, u32, bool)> = self
            .retries
            .pending
            .iter()
            .flat_map(|r| {
                batch::recipients(&r.body)
                    .into_iter()
                    .map(move |(u, d)| (u, d, r.attempts, false))
            })
            .collect();
        out.extend(
            self.retries
                .gave_up
                .iter()
                .map(|(u, d, a)| (u.clone(), d.clone(), *a, true)),
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use stoat_crypto_proto::api::paths;

    use super::*;

    fn td(id: &str, devices: &[&str]) -> OutgoingRequest {
        let msgs: serde_json::Map<String, serde_json::Value> =
            devices.iter().map(|d| (d.to_string(), json!({ "c": d }))).collect();
        to_device(
            id.into(),
            json!({ "type": "m.room.encrypted", "messages": { "@u:stoat.invalid": msgs } }).to_string(),
        )
    }

    #[test]
    fn upload_keeps_its_id_while_the_body_is_the_same() {
        let mut ob = Outbox::default();
        let up = |id: &str, body: &str| OutgoingRequest {
            id: id.into(),
            kind: RequestKind::KeysUpload,
            method: "POST",
            path: paths::KEYS_UPLOAD.into(),
            body: body.into(),
        };
        ob.refreshed(vec![up("1", "a")]);
        ob.refreshed(vec![up("2", "a")]);
        assert_eq!(ob.cached[0].id, "1");
        ob.refreshed(vec![up("3", "b")]);
        assert_eq!(ob.cached[0].id, "3");
        ob.forget("3");
        ob.refreshed(vec![up("4", "b")]);
        assert_eq!(ob.cached[0].id, "4");
    }

    #[test]
    fn parts_finish_the_parent_once() {
        let mut ob = Outbox {
            limits: ServerLimits {
                max_to_device_batch: 2,
                ..ServerLimits::default()
            },
            ..Outbox::default()
        };
        let parent = td("P", &["D1", "D2", "D3"]);
        let parts = ob.expand(parent.clone());
        assert_eq!(parts.len(), 2);
        assert!(ob.is_part(&parts[0].id));
        // handed again: same part ids
        assert_eq!(ob.expand(parent.clone()), parts);
        assert!(matches!(ob.part_sent(&parts[1].id, "{}"), PartMark::Pending));
        assert_eq!(ob.expand(parent.clone()), vec![parts[0].clone()]);
        match ob.part_sent(&parts[0].id, "") {
            PartMark::Finished { parent, body } => assert_eq!((parent.as_str(), body.as_str()), ("P", "{}")),
            _ => panic!("not finished"),
        }
        ob.forget("P");
        assert!(!ob.is_part(&parts[0].id));
    }

    #[test]
    fn full_mailboxes_are_retried_then_given_up() {
        let mut ob = Outbox {
            timing: Timing {
                to_device_retry_ms: 0,
                to_device_retry_attempts: 2,
                ..Timing::default()
            },
            ..Outbox::default()
        };
        let r = td("T", &["D1", "D2"]);
        ob.expand(r);
        let failed = r#"{"failed":{"@u:stoat.invalid":["D2"]}}"#;
        assert!(ob.delivered("T", failed));
        let due = ob.own_and_due();
        assert_eq!(due.len(), 1);
        assert_eq!(
            batch::recipients(&due[0].body),
            [("@u:stoat.invalid".to_string(), "D2".to_string())]
        );
        assert_eq!(ob.undelivered(), [("@u:stoat.invalid".into(), "D2".into(), 1, false)]);
        // still full twice more → given up
        assert!(ob.delivered(&due[0].id, failed));
        let due = ob.own_and_due();
        assert!(ob.delivered(&due[0].id, failed));
        assert!(ob.own_and_due().is_empty());
        assert_eq!(ob.undelivered(), [("@u:stoat.invalid".into(), "D2".into(), 2, true)]);
        // the device gets something again: no longer reported
        ob.expand(td("U", &["D2"]));
        assert!(ob.delivered("U", "{}"));
        assert!(ob.undelivered().is_empty());
    }

    /// O-2: own requests back off on any failure; only permanent refusals
    /// count towards dropping them
    #[test]
    fn own_requests_back_off_then_are_dropped() {
        let mut ob = Outbox::default();
        ob.add_own(td("V", &["D1"]));
        assert_eq!(ob.own_and_due().len(), 1);
        // a server error: later, not on the next pass
        assert_eq!(ob.own_failed("V", 503), OwnFailure::Later);
        assert!(ob.own_and_due().is_empty());
        let wait = ob.next_retry_ms().unwrap().saturating_sub(now_ms());
        assert!((1..=1_000).contains(&wait), "{wait}");
        // rate limits, timeouts, auth and no response never drop it
        for status in [401, 408, 429, 0, 500] {
            assert_eq!(ob.own_failed("V", status), OwnFailure::Later);
        }
        assert!(ob.is_own("V"));
        // the delay doubles up to the cap
        assert_eq!(own_backoff(1_000, 1), 1_000);
        assert_eq!(own_backoff(1_000, 4), 8_000);
        assert_eq!(own_backoff(1_000, 60), OWN_BACKOFF_CAP_MS);
        assert_eq!(own_backoff(0, 9), 0);

        // permanent refusals: dropped on the third, reported
        assert_eq!(ob.own_failed("V", 400), OwnFailure::Later);
        assert_eq!(ob.own_failed("V", 404), OwnFailure::Later);
        assert_eq!(ob.own_failed("V", 400), OwnFailure::Dropped(RequestKind::ToDevice));
        assert!(!ob.is_own("V") && ob.own_and_due().is_empty());
        assert_eq!(
            ob.rejected.iter().collect::<Vec<_>>(),
            [&Rejected {
                kind: RequestKind::ToDevice,
                status: 400,
                attempts: 9
            }]
        );
        assert_eq!(ob.stats()["rejected"][0]["kind"], "to_device");
        assert!(!(500..600).any(is_permanent) && is_permanent(403) && !is_permanent(429));
    }

    /// O-2: a full-mailbox retry refused for good gives its devices up
    #[test]
    fn retries_refused_for_good_give_up_their_devices() {
        let mut ob = Outbox {
            timing: Timing {
                to_device_retry_ms: 0,
                ..Timing::default()
            },
            ..Outbox::default()
        };
        ob.expand(td("T", &["D1", "D2"]));
        assert!(ob.delivered("T", r#"{"failed":{"@u:stoat.invalid":["D2"]}}"#));
        let id = ob.own_and_due()[0].id.clone();
        assert!(!ob.retry_failed(&id, 502), "a server error changes nothing persisted");
        assert!(ob.retry_failed(&id, 400));
        assert!(ob.retry_failed(&id, 400));
        assert!(ob.retry_failed(&id, 400));
        assert!(!ob.is_retry(&id));
        assert_eq!(ob.undelivered(), [("@u:stoat.invalid".into(), "D2".into(), 1, true)]);
        assert_eq!(ob.rejected.len(), 1);
    }
}
