//! The one tokio runtime of the process (C24, ADR 0001) and the panic fence
//! of every export (CR-13, security review "FFI and panics").
//!
//! UniFFI does not run futures itself: Kotlin polls them. `matrix-sdk-sqlite`
//! needs tokio (deadpool), so every async export spawns its work onto this
//! runtime and Kotlin awaits the `JoinHandle`. That gives three properties:
//!
//! * one runtime per process, owned here (the app creates none, AN-20);
//! * a panic inside the core or the library ends the task, not the app: the
//!   join error becomes [`CryptoError::Panic`] (`panic = "unwind"` in release);
//! * a cancelled Kotlin coroutine drops only the handle — the task runs to
//!   the end and writes its result ("finish and store, nobody reads it"),
//!   which every core operation is built for (20-crypto-core, CR-13).

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

use crate::error::CryptoError;

/// Worker threads: the work is short store transactions and crypto; SQLite
/// itself runs on the blocking pool
const WORKERS: usize = 2;

static RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();

fn runtime() -> Result<&'static Runtime, CryptoError> {
    RUNTIME
        .get_or_init(|| {
            Builder::new_multi_thread()
                .worker_threads(WORKERS)
                .thread_name("stoat-crypto")
                .enable_all()
                .build()
                .ok()
        })
        .as_ref()
        .ok_or_else(|| CryptoError::Internal("internal crypto error during runtime start".into()))
}

/// Run `fut` on the core runtime; a panic in it is an error, not a crash
pub(crate) async fn run<T, F>(fut: F) -> Result<T, CryptoError>
where
    F: Future<Output = Result<T, CryptoError>> + Send + 'static,
    T: Send + 'static,
{
    match runtime()?.spawn(fut).await {
        Ok(result) => result,
        Err(_) => Err(CryptoError::panic()),
    }
}

/// [`run`] for operations whose failures are values (decryption)
pub(crate) async fn run_value<T, F>(fut: F) -> Result<T, CryptoError>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    run(async move { Ok(fut.await) }).await
}

/// Synchronous exports: inside the runtime context (the library may expect
/// one), panics caught
pub(crate) fn guard<T>(f: impl FnOnce() -> Result<T, CryptoError>) -> Result<T, CryptoError> {
    let _context = runtime()?.enter();
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err(CryptoError::panic()))
}

/// Holds a value whose drop needs the runtime: the SQLite pool of the store
/// hands its connections to `spawn_blocking` when dropped, and Kotlin's
/// `close()` (or the cleaner) runs on a JVM thread outside any runtime —
/// without this the process aborts on `close()`.
pub(crate) struct InRuntime<T>(Option<T>);

impl<T> InRuntime<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(Some(value))
    }
}

impl<T> std::ops::Deref for InRuntime<T> {
    type Target = T;

    #[allow(clippy::expect_used)]
    fn deref(&self) -> &T {
        // `None` only inside `drop`
        self.0.as_ref().expect("value present until drop")
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for InRuntime<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> Drop for InRuntime<T> {
    fn drop(&mut self) {
        if let Some(value) = self.0.take() {
            let _context = runtime().ok().map(Runtime::enter);
            let _ = catch_unwind(AssertUnwindSafe(move || drop(value)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::panic)]
    fn boom() -> Result<u8, CryptoError> {
        panic!("boom")
    }

    #[test]
    fn panics_become_typed_errors() {
        assert!(matches!(guard(boom), Err(CryptoError::Panic(_))));
        assert_eq!(guard(|| Ok(1)).unwrap(), 1);
    }

    #[tokio::test]
    async fn async_panics_become_typed_errors() {
        assert!(matches!(run(async { boom() }).await, Err(CryptoError::Panic(_))));
        // the runtime survives the panic
        assert_eq!(run(async { Ok(2) }).await.unwrap(), 2);
    }
}
