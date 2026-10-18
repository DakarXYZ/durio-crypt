//! CR-11: SAS verification of a device — our own other device or another
//! user's — over to-device messages (`m.key.verification.request / ready /
//! start / accept / key / mac / done / cancel`).
//!
//! The protocol is the library's (`VerificationRequest` + `Sas`):
//! `curve25519-hkdf-sha256`, `hkdf-hmac-sha256.v2`, the commitment in
//! `accept`, the tie-break of two simultaneous starts and the MAC of the
//! device keys. This module is the state the UI reads and the actions it
//! takes, as plain types ([`SasHandle`], [`SasState`]).
//!
//! * **No callbacks**: every mailbox pass reports the flows it touched
//!   (`ToDeviceResult::verifications`); the client re-reads
//!   [`SasHandle::state`]. Messages the user's actions produce are queued in
//!   the outbox and leave with the next request pass.
//! * **Timeouts without timers**: the library cancels a request after
//!   10 min and a SAS after 5 min or 1 min without the other side's next
//!   step, when it garbage-collects. While a flow is active,
//!   `wakeup_in_ms` asks for a pass at least every [`POLL_MS`]; that pass
//!   runs the collection and sends the `m.timeout` cancel.
//! * **One acceptance**: a SAS started by the other side of a request we
//!   accepted is accepted automatically (the user already said yes).
//! * Done → the device is verified locally (`Trust::Verified`), which drives
//!   the shield and key forwarding between own devices (CR-08). Without
//!   cross-signing nothing is uploaded (v1.1).

use std::collections::VecDeque;
use std::fmt;

use matrix_sdk_common::deserialized_responses::ProcessedToDeviceEvent;
use matrix_sdk_crypto::types::requests::OutgoingVerificationRequest;
use matrix_sdk_crypto::{CancelInfo, Sas, SasState as LibSasState, VerificationRequest, VerificationRequestState};
use ruma::OwnedUserId;
use ruma::events::key::verification::VerificationMethod;
use ruma::events::key::verification::cancel::CancelCode;
use serde_json::Value;

use crate::error::{CryptoError, Result};
use crate::ids;
use crate::machine::CryptoMachine;
use crate::requests;

/// While a verification is active the host passes at least this often
pub const POLL_MS: u64 = 10_000;
/// Flows remembered for their last state (terminal ones are evicted first)
const MAX_FLOWS: usize = 64;

/// The 64 SAS emoji of the Matrix spec (`sas-emoji.json`): symbol and the
/// English description, which is the translation key of the clients' own
/// strings. Index = position.
pub const SAS_EMOJI: [(&str, &str); 64] = [
    ("🐶", "Dog"),
    ("🐱", "Cat"),
    ("🦁", "Lion"),
    ("🐎", "Horse"),
    ("🦄", "Unicorn"),
    ("🐷", "Pig"),
    ("🐘", "Elephant"),
    ("🐰", "Rabbit"),
    ("🐼", "Panda"),
    ("🐓", "Rooster"),
    ("🐧", "Penguin"),
    ("🐢", "Turtle"),
    ("🐟", "Fish"),
    ("🐙", "Octopus"),
    ("🦋", "Butterfly"),
    ("🌷", "Flower"),
    ("🌳", "Tree"),
    ("🌵", "Cactus"),
    ("🍄", "Mushroom"),
    ("🌏", "Globe"),
    ("🌙", "Moon"),
    ("☁️", "Cloud"),
    ("🔥", "Fire"),
    ("🍌", "Banana"),
    ("🍎", "Apple"),
    ("🍓", "Strawberry"),
    ("🌽", "Corn"),
    ("🍕", "Pizza"),
    ("🎂", "Cake"),
    ("❤️", "Heart"),
    ("😀", "Smiley"),
    ("🤖", "Robot"),
    ("🎩", "Hat"),
    ("👓", "Glasses"),
    ("🔧", "Spanner"),
    ("🎅", "Santa"),
    ("👍", "Thumbs Up"),
    ("☂️", "Umbrella"),
    ("⌛", "Hourglass"),
    ("⏰", "Clock"),
    ("🎁", "Gift"),
    ("💡", "Light Bulb"),
    ("📕", "Book"),
    ("✏️", "Pencil"),
    ("📎", "Paperclip"),
    ("✂️", "Scissors"),
    ("🔒", "Lock"),
    ("🔑", "Key"),
    ("🔨", "Hammer"),
    ("☎️", "Telephone"),
    ("🏁", "Flag"),
    ("🚂", "Train"),
    ("🚲", "Bicycle"),
    ("✈️", "Aeroplane"),
    ("🚀", "Rocket"),
    ("🏆", "Trophy"),
    ("⚽", "Ball"),
    ("🎸", "Guitar"),
    ("🎺", "Trumpet"),
    ("🔔", "Bell"),
    ("⚓", "Anchor"),
    ("🎧", "Headphones"),
    ("📁", "Folder"),
    ("📌", "Pin"),
];

/// One of the seven emoji to compare
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SasEmoji {
    /// 0..64, index into [`SAS_EMOJI`] (and the clients' translations)
    pub index: u8,
    pub symbol: String,
    /// English description = translation key
    pub description: String,
}

/// Why a verification was cancelled
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelReason {
    /// A user pressed cancel (either side)
    User,
    /// A step did not come in time (`m.timeout`)
    Timeout,
    /// The codes or the keys did not match: possible attack, do not trust
    Mismatch,
    /// Another of the user's devices took the request (`m.accepted`)
    AcceptedElsewhere,
    /// Protocol error, unknown method, unexpected message
    Other,
}

/// What the verification UI shows
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SasState {
    /// We asked; waiting for the other device to accept
    Requested,
    /// The other device asks: [`SasHandle::accept`] or [`SasHandle::cancel`]
    Incoming,
    /// Both accepted: either side may [`SasHandle::start`]
    Ready,
    /// Keys are being exchanged
    Started,
    /// Compare with the other screen, then [`SasHandle::confirm`] or
    /// [`SasHandle::mismatch`]
    ShowCodes { emoji: Vec<SasEmoji>, decimals: [u16; 3] },
    /// We confirmed; waiting for the other side
    Confirmed,
    /// Both confirmed: the device is verified
    Done,
    Cancelled {
        reason: CancelReason,
        /// Matrix cancel code, e.g. `m.user`
        code: String,
        by_us: bool,
    },
}

impl SasState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done | Self::Cancelled { .. })
    }
}

#[derive(Debug)]
struct Flow {
    id: String,
    user: OwnedUserId,
    last: SasState,
}

/// Flows seen by this machine and their last state (the library forgets a
/// flow once it is done or cancelled)
#[derive(Debug, Default)]
pub(crate) struct Flows(VecDeque<Flow>);

impl Flows {
    fn get(&self, flow: &str) -> Option<&Flow> {
        self.0.iter().find(|f| f.id == flow)
    }

    fn insert(&mut self, id: String, user: OwnedUserId, state: SasState) {
        if let Some(f) = self.0.iter_mut().find(|f| f.id == id) {
            f.last = state;
            return;
        }
        if self.0.len() >= MAX_FLOWS {
            let i = self.0.iter().position(|f| f.last.is_terminal()).unwrap_or(0);
            self.0.remove(i);
        }
        self.0.push_back(Flow { id, user, last: state });
    }

    pub(crate) fn any_active(&self) -> bool {
        self.0.iter().any(|f| !f.last.is_terminal())
    }

    /// CR-22: (known, open)
    pub(crate) fn counts(&self) -> (usize, usize) {
        (self.0.len(), self.0.iter().filter(|f| !f.last.is_terminal()).count())
    }
}

fn cancelled(info: &CancelInfo) -> SasState {
    let code = info.cancel_code();
    let reason = match code {
        CancelCode::User => CancelReason::User,
        CancelCode::Timeout => CancelReason::Timeout,
        CancelCode::MismatchedSas | CancelCode::KeyMismatch | CancelCode::MismatchedCommitment => {
            CancelReason::Mismatch
        }
        CancelCode::Accepted => CancelReason::AcceptedElsewhere,
        _ => CancelReason::Other,
    };
    SasState::Cancelled {
        reason,
        code: code.as_str().to_owned(),
        by_us: info.cancelled_by_us(),
    }
}

fn from_request(r: &VerificationRequest) -> SasState {
    match r.state() {
        VerificationRequestState::Created { .. } => SasState::Requested,
        VerificationRequestState::Requested { .. } => SasState::Incoming,
        VerificationRequestState::Ready { .. } => SasState::Ready,
        VerificationRequestState::Transitioned { .. } => SasState::Started,
        VerificationRequestState::Done => SasState::Done,
        VerificationRequestState::Cancelled(info) => cancelled(&info),
    }
}

fn from_sas(s: &Sas) -> SasState {
    match s.state() {
        // started by the other side without a request we accepted
        LibSasState::Started { .. } if !s.we_started() && !s.started_from_request() => SasState::Incoming,
        LibSasState::Created { .. } | LibSasState::Started { .. } | LibSasState::Accepted { .. } => SasState::Started,
        LibSasState::KeysExchanged { emojis, decimals } => SasState::ShowCodes {
            emoji: emojis
                .map(|e| {
                    e.indices
                        .iter()
                        .zip(e.emojis.iter())
                        .map(|(i, e)| SasEmoji {
                            index: *i,
                            symbol: e.symbol.to_owned(),
                            description: e.description.to_owned(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            decimals: [decimals.0, decimals.1, decimals.2],
        },
        LibSasState::Confirmed => SasState::Confirmed,
        LibSasState::Done { .. } => SasState::Done,
        LibSasState::Cancelled(info) => cancelled(&info),
    }
}

/// One verification flow, as the UI drives it. Cheap to clone; state lives
/// in the machine.
#[derive(Clone)]
pub struct SasHandle {
    machine: CryptoMachine,
    user: OwnedUserId,
    flow_id: String,
}

impl fmt::Debug for SasHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SasHandle")
            .field("user", &self.user)
            .field("flow_id", &self.flow_id)
            .finish()
    }
}

impl SasHandle {
    /// The transaction id of the flow (also in `ToDeviceResult::verifications`)
    pub fn flow_id(&self) -> &str {
        &self.flow_id
    }

    /// The other user (ULID); our own for a self-verification
    pub fn other_user_id(&self) -> String {
        ids::user_ulid(&self.user).unwrap_or_default()
    }

    /// The other device, once known (an incoming request names it, an
    /// outgoing one learns it from `ready`)
    pub fn other_device_id(&self) -> Option<String> {
        let olm = self.machine.olm();
        if let Some(s) = olm.get_verification(&self.user, &self.flow_id).and_then(|v| v.sas_v1()) {
            return Some(s.other_device_id().to_string());
        }
        olm.get_verification_request(&self.user, &self.flow_id)?
            .other_device_id()
            .map(|d| d.to_string())
    }

    /// Verifying one of our own devices
    pub fn is_self_verification(&self) -> bool {
        self.user == self.machine.olm().user_id()
    }

    /// Current state; a flow the library forgot keeps its last state (a
    /// non-final one becomes a timeout)
    pub fn state(&self) -> SasState {
        let olm = self.machine.olm();
        let current = match olm.get_verification(&self.user, &self.flow_id).and_then(|v| v.sas_v1()) {
            Some(s) => Some(from_sas(&s)),
            None => olm
                .get_verification_request(&self.user, &self.flow_id)
                .map(|r| from_request(&r)),
        };
        let mut flows = self.machine.flows();
        let state = match current {
            Some(s) => s,
            None => match flows.get(&self.flow_id) {
                Some(f) if f.last.is_terminal() => f.last.clone(),
                _ => SasState::Cancelled {
                    reason: CancelReason::Timeout,
                    code: CancelCode::Timeout.as_str().to_owned(),
                    by_us: true,
                },
            },
        };
        flows.insert(self.flow_id.clone(), self.user.clone(), state.clone());
        state
    }

    fn request(&self) -> Option<VerificationRequest> {
        self.machine.olm().get_verification_request(&self.user, &self.flow_id)
    }

    fn sas(&self) -> Option<Box<Sas>> {
        self.machine
            .olm()
            .get_verification(&self.user, &self.flow_id)
            .and_then(|v| v.sas_v1())
    }

    /// Accept an incoming request (SAS only) or an incoming SAS start
    pub async fn accept(&self) -> Result<()> {
        let out = match self.request() {
            Some(r) if matches!(r.state(), VerificationRequestState::Requested { .. }) => {
                r.accept_with_methods(vec![VerificationMethod::SasV1])
            }
            _ => self.sas().and_then(|s| s.accept()),
        };
        self.after(self.machine.queue_verification(out).await)
    }

    /// Record the state an action left: the library forgets finished flows
    /// at its next garbage collection
    fn after(&self, r: Result<()>) -> Result<()> {
        self.state();
        r
    }

    /// Start SAS on a ready request (either side may)
    pub async fn start(&self) -> Result<()> {
        let r = self.request().ok_or(CryptoError::VerificationNotActive)?;
        let started = r.start_sas().await.map_err(|_| CryptoError::Store("start sas"))?;
        self.after(self.machine.queue_verification(started.map(|(_, out)| out)).await)
    }

    /// The codes match: send our MAC. Done once the other side confirms too.
    pub async fn confirm(&self) -> Result<()> {
        let sas = self.sas().ok_or(CryptoError::VerificationNotActive)?;
        // no cross-signing in v1: there is never a signature upload
        let (outs, _signatures) = sas.confirm().await.map_err(|_| CryptoError::Store("confirm sas"))?;
        if outs.is_empty() {
            return Err(CryptoError::VerificationNotActive);
        }
        for out in outs {
            self.machine.queue_verification(Some(out)).await?;
        }
        self.after(Ok(()))
    }

    /// The codes differ: cancel with `m.mismatched_sas`
    pub async fn mismatch(&self) -> Result<()> {
        let sas = self.sas().ok_or(CryptoError::VerificationNotActive)?;
        self.after(
            self.machine
                .queue_verification(sas.cancel_with_code(CancelCode::MismatchedSas))
                .await,
        )
    }

    /// Cancel with `m.user` (any time before Done)
    pub async fn cancel(&self) -> Result<()> {
        let out = match self.sas() {
            Some(s) if !s.is_cancelled() && !s.is_done() => s.cancel(),
            _ => self.request().and_then(|r| r.cancel()),
        };
        self.after(self.machine.queue_verification(out).await)
    }
}

impl CryptoMachine {
    /// Ask a device to verify: one of our own other devices, or a device of
    /// another user (a member of a shared encrypted channel, so its keys are
    /// known). The request leaves with the next request pass.
    pub async fn request_verification(&self, user: &str, device: &str) -> Result<SasHandle> {
        let user_id = ids::user_id(user)?;
        let device_id = ids::device_id(device)?;
        let device = self
            .olm()
            .get_device(&user_id, &device_id, None)
            .await
            .map_err(|_| CryptoError::Store("device"))?
            .ok_or(CryptoError::UnknownDevice)?;
        if device.is_deleted() || device_id == self.olm().device_id() && user_id == self.olm().user_id() {
            return Err(CryptoError::UnknownDevice);
        }
        let (request, out) = device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
        let flow_id = request.flow_id().as_str().to_owned();
        self.flows()
            .insert(flow_id.clone(), user_id.clone(), SasState::Requested);
        self.queue_verification(Some(out)).await?;
        Ok(SasHandle {
            machine: self.clone(),
            user: user_id,
            flow_id,
        })
    }

    /// A flow by id (from `ToDeviceResult::verifications` or an earlier
    /// handle); `None` if this machine never saw it
    pub fn verification(&self, flow_id: &str) -> Option<SasHandle> {
        let user = self.flows().get(flow_id)?.user.clone();
        Some(SasHandle {
            machine: self.clone(),
            user,
            flow_id: flow_id.to_owned(),
        })
    }

    /// Flows that are not finished (incoming requests included)
    pub fn verifications(&self) -> Vec<SasHandle> {
        let flows: Vec<(String, OwnedUserId)> = self
            .flows()
            .0
            .iter()
            .filter(|f| !f.last.is_terminal())
            .map(|f| (f.id.clone(), f.user.clone()))
            .collect();
        flows
            .into_iter()
            .map(|(flow_id, user)| SasHandle {
                machine: self.clone(),
                user,
                flow_id,
            })
            .filter(|h| !h.state().is_terminal())
            .collect()
    }

    /// Queue a verification message the user's action produced. `None`:
    /// the action does not apply in the current state.
    pub(crate) async fn queue_verification(&self, out: Option<OutgoingVerificationRequest>) -> Result<()> {
        match out.ok_or(CryptoError::VerificationNotActive)? {
            OutgoingVerificationRequest::ToDevice(r) => {
                let r = requests::to_device(&r)?;
                self.add_own_request(r).await;
                Ok(())
            }
            // to-device verification only (v1)
            OutgoingVerificationRequest::InRoom(_) => Err(CryptoError::Internal("in-room verification")),
        }
    }

    /// Mailbox pass: register the flows the events belong to, accept SAS
    /// starts of requests we accepted. Returns the flow ids touched.
    pub(crate) async fn verification_events(&self, events: &[ProcessedToDeviceEvent]) -> Result<Vec<String>> {
        let mut touched: Vec<String> = Vec::new();
        for e in events {
            let raw = match e {
                ProcessedToDeviceEvent::PlainText(raw) | ProcessedToDeviceEvent::Decrypted { raw, .. } => raw,
                _ => continue,
            };
            let Ok(event) = serde_json::from_str::<Value>(raw.json().get()) else {
                continue;
            };
            if !event["type"]
                .as_str()
                .is_some_and(|t| t.starts_with("m.key.verification."))
            {
                continue;
            }
            let (Some(flow), Some(sender)) = (event["content"]["transaction_id"].as_str(), event["sender"].as_str())
            else {
                continue;
            };
            let Ok(user) = ruma::UserId::parse(sender) else {
                continue;
            };
            let known = self.olm().get_verification_request(&user, flow).is_some()
                || self.olm().get_verification(&user, flow).is_some();
            if !known {
                continue;
            }
            if !touched.iter().any(|t| t == flow) {
                touched.push(flow.to_owned());
            }
            if self.flows().get(flow).is_none() {
                self.flows()
                    .insert(flow.to_owned(), user.to_owned(), SasState::Incoming);
            }
        }
        for flow in &touched {
            let Some(h) = self.verification(flow) else { continue };
            if let Some(s) = h.sas()
                && !s.we_started()
                && s.started_from_request()
                && !s.has_been_accepted()
                && !s.is_cancelled()
            {
                self.queue_verification(s.accept()).await?;
            }
            h.state();
        }
        Ok(touched)
    }

    /// After the library garbage-collected: record the cancels it made
    pub(crate) fn refresh_flows(&self) {
        let active: Vec<String> = self
            .flows()
            .0
            .iter()
            .filter(|f| !f.last.is_terminal())
            .map(|f| f.id.clone())
            .collect();
        for flow in active {
            if let Some(h) = self.verification(&flow) {
                h.state();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emoji_table_is_the_spec_table() {
        assert_eq!(SAS_EMOJI.len(), 64);
        assert_eq!(SAS_EMOJI[0], ("🐶", "Dog"));
        assert_eq!(SAS_EMOJI[63], ("📌", "Pin"));
        let mut names: Vec<&str> = SAS_EMOJI.iter().map(|e| e.1).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 64);
    }

    #[test]
    fn flows_are_bounded_terminal_first() {
        let user = OwnedUserId::try_from("@01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid").unwrap();
        let mut flows = Flows::default();
        flows.insert("active".into(), user.clone(), SasState::Ready);
        for i in 0..MAX_FLOWS {
            flows.insert(format!("{i}"), user.clone(), SasState::Done);
        }
        assert_eq!(flows.0.len(), MAX_FLOWS);
        assert!(flows.get("active").is_some());
        assert!(flows.any_active());
    }
}
