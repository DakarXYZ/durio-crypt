//! SAS verification flow for the UI (CR-11): re-read `state()` after every
//! mailbox pass and every action, then run a request pass.

use js_sys::Promise;
use stoat_crypto as sc;
use wasm_bindgen::prelude::*;

use crate::error::Error;
use crate::machine::spawn;
use crate::types::{SasState, to_js};

/// One verification flow; `free()` it when the screen is gone
#[derive(Debug)]
#[wasm_bindgen]
pub struct SasHandle {
    inner: sc::SasHandle,
}

impl SasHandle {
    pub(crate) fn new(inner: sc::SasHandle) -> Self {
        Self { inner }
    }

    fn act<F, Fut>(&self, f: F) -> Promise
    where
        F: FnOnce(sc::SasHandle) -> Fut,
        Fut: Future<Output = sc::Result<()>> + 'static,
    {
        let fut = f(self.inner.clone());
        spawn(async move {
            fut.await.map_err(Error::from)?;
            Ok(JsValue::UNDEFINED)
        })
    }
}

#[wasm_bindgen]
impl SasHandle {
    #[wasm_bindgen(js_name = flowId)]
    pub fn flow_id(&self) -> String {
        self.inner.flow_id().to_owned()
    }

    /// The other user (ULID); our own for a self-verification
    #[wasm_bindgen(js_name = otherUserId)]
    pub fn other_user_id(&self) -> String {
        self.inner.other_user_id()
    }

    #[wasm_bindgen(js_name = otherDeviceId)]
    pub fn other_device_id(&self) -> Option<String> {
        self.inner.other_device_id()
    }

    #[wasm_bindgen(js_name = isSelfVerification)]
    pub fn is_self_verification(&self) -> bool {
        self.inner.is_self_verification()
    }

    /// `{type: "Requested" | "Incoming" | "Ready" | "Started" | "ShowCodes"
    /// | "Confirmed" | "Done" | "Cancelled", ...}`
    pub fn state(&self) -> Result<JsValue, JsValue> {
        Ok(to_js(&SasState::from(self.inner.state()))?)
    }

    pub fn accept(&self) -> Promise {
        self.act(|h| async move { h.accept().await })
    }

    pub fn start(&self) -> Promise {
        self.act(|h| async move { h.start().await })
    }

    pub fn confirm(&self) -> Promise {
        self.act(|h| async move { h.confirm().await })
    }

    pub fn mismatch(&self) -> Promise {
        self.act(|h| async move { h.mismatch().await })
    }

    pub fn cancel(&self) -> Promise {
        self.act(|h| async move { h.cancel().await })
    }
}
