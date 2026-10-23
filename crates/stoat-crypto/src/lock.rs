//! CR-17: one writer per account. The library does not stop a second
//! `OlmMachine` from opening the same store (spike S11: `CrossProcessLock` is
//! opt-in), and two writers would corrupt the Olm/Megolm ratchets. An exclusive
//! advisory lock on `crypto.lock` next to the database is taken on `open` and
//! held while the machine lives; a second `open` gets `StoreLocked`.
//!
//! `flock` semantics (per open file description), so a second open is refused
//! within the same process as well as from another one.

use std::fs::{File, OpenOptions};
use std::path::Path;

use crate::error::{CryptoError, Result};

/// Name of the lock file inside the store directory
pub const LOCK_FILE: &str = "crypto.lock";

#[derive(Debug)]
pub(crate) struct StoreLock {
    _file: File,
}

impl StoreLock {
    /// Take the lock without waiting
    pub(crate) fn acquire(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|_| CryptoError::Store("create store directory"))?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(dir.join(LOCK_FILE))
            .map_err(|_| CryptoError::Store("open lock file"))?;
        try_lock(&file)?;
        Ok(Self { _file: file })
    }
}

/// `flock` itself: std's `File::try_lock` is not implemented for Android (Rust
/// 1.96 answers "unsupported" there), which left every store unopenable. The
/// same call on every unix, so the tests on Linux run what Android runs.
#[cfg(unix)]
fn try_lock(file: &File) -> Result<()> {
    use rustix::fs::{FlockOperation, flock};
    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(CryptoError::StoreLocked),
        Err(_) => Err(CryptoError::Store("lock")),
    }
}

#[cfg(not(unix))]
fn try_lock(file: &File) -> Result<()> {
    use std::fs::TryLockError;
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(CryptoError::StoreLocked),
        Err(TryLockError::Error(_)) => Err(CryptoError::Store("lock")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let first = StoreLock::acquire(dir.path()).unwrap();
        assert_eq!(StoreLock::acquire(dir.path()).unwrap_err(), CryptoError::StoreLocked);
        drop(first);
        let _again = StoreLock::acquire(dir.path()).unwrap();
    }
}
