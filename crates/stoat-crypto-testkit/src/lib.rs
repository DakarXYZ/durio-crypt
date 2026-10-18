//! dur.io E2EE testkit (CR-15): several virtual devices, each a real
//! [`stoat_crypto::CryptoMachine`], against a **live** backend over HTTP and
//! the bonfire WebSocket — what the fake server (CR-18) cannot prove.
//!
//! The scenarios are `#[ignore]`d tests in `tests/live.rs`; they run against
//! the URLs in `STOAT_API`, `STOAT_WS` and `STOAT_AUTUMN`:
//!
//! ```text
//! scripts/testkit-backend.sh up     # delta + bonfire + autumn + infra in Docker
//! scripts/testkit-backend.sh test   # cargo nextest … --run-ignored only (JUnit XML)
//! scripts/testkit-backend.sh check  # Mongo / MinIO hold ciphertext only
//! ```
//!
//! Every scenario uses fresh users (no database cleanup). The backend keeps
//! its rate limits: the client waits out a 429 (`retry_after`) and spreads
//! unauthenticated calls over `X-Forwarded-For` addresses (the per-IP bucket of
//! `/auth/*` is keyed by that header on the test stack).
//!
//! The rules the driver follows are the host contract of `stoat_crypto`
//! (request passes, mailbox + ack, send loop) — the same a client implements.

mod account;
mod device;
mod evidence;
mod http;
mod ws;

pub use account::{Account, Stack};
pub use device::{Device, payload_text, settle, timing};
pub use evidence::Evidence;
pub use http::{Http, HttpError, Reply};

/// URLs of the backend under test, from the environment
#[derive(Clone, Debug)]
pub struct Config {
    /// delta (`STOAT_API`), e.g. `http://durio-test-delta:14702`
    pub api: String,
    /// bonfire (`STOAT_WS`), e.g. `ws://durio-test-bonfire:14703`
    pub ws: String,
    /// autumn (`STOAT_AUTUMN`), e.g. `http://durio-test-autumn:14704`
    pub autumn: String,
    /// Where the evidence for `testkit-backend.sh check` goes (`STOAT_TESTKIT_OUT`)
    pub out: Option<std::path::PathBuf>,
}

impl Config {
    /// `None` without `STOAT_API` (no live backend configured)
    pub fn from_env() -> Option<Self> {
        let api = std::env::var("STOAT_API").ok()?;
        let base = api.trim_end_matches('/').to_owned();
        let host = base.split("://").nth(1).unwrap_or(&base).to_owned();
        Some(Self {
            ws: std::env::var("STOAT_WS").unwrap_or_else(|_| format!("ws://{host}/events")),
            autumn: std::env::var("STOAT_AUTUMN").unwrap_or_else(|_| format!("{base}/autumn")),
            out: std::env::var("STOAT_TESTKIT_OUT").ok().map(Into::into),
            api: base,
        })
    }
}
