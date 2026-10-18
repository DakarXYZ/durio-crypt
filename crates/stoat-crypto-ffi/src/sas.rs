//! SAS verification flow for the UI (CR-11): re-read `state()` after every
//! mailbox pass and every action, then run a request pass.

use stoat_crypto as sc;

use crate::error::CryptoError;
use crate::runtime::{InRuntime, guard, run};

/// One of the seven emoji to compare
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SasEmoji {
    /// 0..64, index into the emoji table (and the translations)
    pub index: u8,
    pub symbol: String,
    /// English description = translation key
    pub description: String,
}

impl From<sc::SasEmoji> for SasEmoji {
    fn from(e: sc::SasEmoji) -> Self {
        Self {
            index: e.index,
            symbol: e.symbol,
            description: e.description,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CancelReason {
    User,
    Timeout,
    /// Codes or keys did not match: possible attack, do not trust
    Mismatch,
    AcceptedElsewhere,
    Other,
}

impl From<sc::CancelReason> for CancelReason {
    fn from(r: sc::CancelReason) -> Self {
        match r {
            sc::CancelReason::User => Self::User,
            sc::CancelReason::Timeout => Self::Timeout,
            sc::CancelReason::Mismatch => Self::Mismatch,
            sc::CancelReason::AcceptedElsewhere => Self::AcceptedElsewhere,
            sc::CancelReason::Other => Self::Other,
        }
    }
}

/// What the verification screen shows
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SasState {
    Requested,
    /// Incoming: `accept()` or `cancel()`
    Incoming,
    /// Either side may `start()`
    Ready,
    Started,
    /// Compare, then `confirm()` or `mismatch()`
    ShowCodes {
        emoji: Vec<SasEmoji>,
        decimals: Vec<u16>,
    },
    Confirmed,
    /// The device is verified
    Done,
    Cancelled {
        reason: CancelReason,
        /// Matrix cancel code, e.g. `m.user`
        code: String,
        by_us: bool,
    },
}

impl From<sc::SasState> for SasState {
    fn from(s: sc::SasState) -> Self {
        match s {
            sc::SasState::Requested => Self::Requested,
            sc::SasState::Incoming => Self::Incoming,
            sc::SasState::Ready => Self::Ready,
            sc::SasState::Started => Self::Started,
            sc::SasState::ShowCodes { emoji, decimals } => Self::ShowCodes {
                emoji: emoji.into_iter().map(Into::into).collect(),
                decimals: decimals.to_vec(),
            },
            sc::SasState::Confirmed => Self::Confirmed,
            sc::SasState::Done => Self::Done,
            sc::SasState::Cancelled { reason, code, by_us } => Self::Cancelled {
                reason: reason.into(),
                code,
                by_us,
            },
        }
    }
}

/// One verification flow. Holds the machine: `close()` it when the screen
/// is gone.
#[derive(Debug, uniffi::Object)]
pub struct SasHandle {
    inner: InRuntime<sc::SasHandle>,
}

impl SasHandle {
    pub(crate) fn new(inner: sc::SasHandle) -> Self {
        Self {
            inner: InRuntime::new(inner),
        }
    }
}

#[uniffi::export]
impl SasHandle {
    pub fn flow_id(&self) -> String {
        self.inner.flow_id().to_owned()
    }

    /// The other user (ULID); our own for a self-verification
    pub fn other_user_id(&self) -> Result<String, CryptoError> {
        guard(|| Ok(self.inner.other_user_id()))
    }

    pub fn other_device_id(&self) -> Result<Option<String>, CryptoError> {
        guard(|| Ok(self.inner.other_device_id()))
    }

    pub fn is_self_verification(&self) -> Result<bool, CryptoError> {
        guard(|| Ok(self.inner.is_self_verification()))
    }

    pub fn state(&self) -> Result<SasState, CryptoError> {
        guard(|| Ok(self.inner.state().into()))
    }

    pub async fn accept(&self) -> Result<(), CryptoError> {
        let h = (*self.inner).clone();
        run(async move { Ok(h.accept().await?) }).await
    }

    pub async fn start(&self) -> Result<(), CryptoError> {
        let h = (*self.inner).clone();
        run(async move { Ok(h.start().await?) }).await
    }

    pub async fn confirm(&self) -> Result<(), CryptoError> {
        let h = (*self.inner).clone();
        run(async move { Ok(h.confirm().await?) }).await
    }

    pub async fn mismatch(&self) -> Result<(), CryptoError> {
        let h = (*self.inner).clone();
        run(async move { Ok(h.mismatch().await?) }).await
    }

    pub async fn cancel(&self) -> Result<(), CryptoError> {
        let h = (*self.inner).clone();
        run(async move { Ok(h.cancel().await?) }).await
    }
}

/// The 64 SAS emoji (index → symbol, description = translation key)
#[uniffi::export]
pub fn sas_emoji_table() -> Vec<SasEmoji> {
    sc::SAS_EMOJI
        .iter()
        .zip(0u8..)
        .map(|((symbol, description), index)| SasEmoji {
            index,
            symbol: (*symbol).to_owned(),
            description: (*description).to_owned(),
        })
        .collect()
}
