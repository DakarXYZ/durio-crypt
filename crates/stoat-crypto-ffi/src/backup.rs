//! Restore of the key backup in batches (CR-12): `next()` until finished,
//! one store transaction per batch; interrupted → start again.

use std::sync::Arc;

use stoat_crypto as sc;
use tokio::sync::Mutex;

use crate::error::CryptoError;
use crate::runtime::{InRuntime, run};
use crate::types::RestoreProgress;

/// Holds the machine: `close()` it when the restore is done
#[derive(Debug, uniffi::Object)]
pub struct BackupRestore {
    inner: InRuntime<Arc<Mutex<sc::BackupRestore>>>,
}

impl BackupRestore {
    pub(crate) fn new(inner: sc::BackupRestore) -> Self {
        Self {
            inner: InRuntime::new(Arc::new(Mutex::new(inner))),
        }
    }
}

#[uniffi::export]
impl BackupRestore {
    pub async fn progress(&self) -> Result<RestoreProgress, CryptoError> {
        let r = (*self.inner).clone();
        run(async move { Ok(r.lock().await.progress().into()) }).await
    }

    /// Import up to `max` sessions (0 = the default batch)
    pub async fn next(&self, max: u32) -> Result<RestoreProgress, CryptoError> {
        let r = (*self.inner).clone();
        run(async move { Ok(r.lock().await.next(max as usize).await?.into()) }).await
    }
}
