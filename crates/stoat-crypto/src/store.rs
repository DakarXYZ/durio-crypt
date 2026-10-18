//! CR-09: crypto store. Ready-made stores of the library behind one config:
//!
//! * SQLite (`matrix-sdk-sqlite`, Android and tests): values encrypted by
//!   `StoreCipher` (ChaCha20-Poly1305) with the raw 32-byte key from the host,
//!   `open_with_key` — no PBKDF2 on open, so a cold FCM start stays fast (CR-17);
//! * IndexedDB (`matrix-sdk-indexeddb`, for-web inside the Windows client,
//!   stage 5): same key, only built for `wasm32`;
//! * memory: tests and ephemeral sessions.
//!
//! The host owns the key (Android Keystore-wrapped bytes, Electron
//! `safeStorage`); the core never stores it and wipes its copy on drop.
//! Schema migrations are the library's (`store_016_migrates_to_019` checks a
//! 0.16 snapshot opens with 0.19.1).

use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;

use matrix_sdk_crypto::{OlmMachine, OlmMachineBuilder, store::CryptoStoreError};
use ruma::{DeviceId, UserId};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
#[cfg(not(target_arch = "wasm32"))]
use crate::lock::{LOCK_FILE, StoreLock};

/// SQLite file names of `matrix-sdk-sqlite` (database + WAL)
#[cfg(not(target_arch = "wasm32"))]
const SQLITE_FILES: [&str; 3] = [
    "matrix-sdk-crypto.sqlite3",
    "matrix-sdk-crypto.sqlite3-wal",
    "matrix-sdk-crypto.sqlite3-shm",
];

/// 32-byte store key from the platform, wiped on drop
#[derive(Clone)]
pub struct StoreKey(Zeroizing<[u8; 32]>);

impl StoreKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// From a slice of exactly 32 bytes
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::Store("store key length"))?;
        Ok(Self::new(bytes))
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoreKey(<redacted>)")
    }
}

/// Where the account's crypto state lives. One store per account and server
/// (multi-account: one machine, file and lock each).
#[derive(Clone, Debug)]
pub enum StoreConfig {
    /// Nothing persists; for tests
    Memory,
    /// SQLite database in `path` (a directory), values encrypted with `key`
    #[cfg(not(target_arch = "wasm32"))]
    Sqlite { path: PathBuf, key: StoreKey },
    /// IndexedDB databases prefixed with `name`, values encrypted with `key`
    #[cfg(target_arch = "wasm32")]
    IndexedDb { name: String, key: StoreKey },
}

/// Lock held for the lifetime of an opened store (CR-17)
#[derive(Debug)]
pub(crate) struct Opened {
    pub(crate) machine: OlmMachine,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) lock: Option<StoreLock>,
}

fn build_error(e: CryptoStoreError) -> CryptoError {
    match e {
        CryptoStoreError::MismatchedAccount { .. } => CryptoError::StoreMismatch,
        _ => CryptoError::Store("open"),
    }
}

pub(crate) async fn open(user_id: &UserId, device_id: &DeviceId, config: &StoreConfig) -> Result<Opened> {
    match config {
        StoreConfig::Memory => Ok(Opened {
            machine: OlmMachine::new(user_id, device_id).await,
            #[cfg(not(target_arch = "wasm32"))]
            lock: None,
        }),
        #[cfg(not(target_arch = "wasm32"))]
        StoreConfig::Sqlite { path, key } => {
            // the lock first: never let a second instance touch the database
            let lock = StoreLock::acquire(path)?;
            let store = matrix_sdk_sqlite::SqliteCryptoStore::open_with_key(path, Some(key.bytes()))
                .await
                .map_err(|_| CryptoError::Store("open sqlite"))?;
            let machine = OlmMachineBuilder::new(user_id, device_id)
                .with_crypto_store(store)
                .build()
                .await
                .map_err(build_error)?;
            Ok(Opened {
                machine,
                lock: Some(lock),
            })
        }
        #[cfg(target_arch = "wasm32")]
        StoreConfig::IndexedDb { name, key } => {
            // single writer in the browser: Web Locks around the machine (CR-14)
            let store = matrix_sdk_indexeddb::IndexeddbCryptoStore::open_with_key(name, key.bytes())
                .await
                .map_err(|_| CryptoError::Store("open indexeddb"))?;
            let machine = OlmMachineBuilder::new(user_id, device_id)
                .with_crypto_store(store)
                .build()
                .await
                .map_err(build_error)?;
            Ok(Opened { machine })
        }
    }
}

/// Delete the store of a signed-out account: files, not rows (CR-09).
/// Fails with `StoreLocked` while a machine has it open.
pub(crate) fn destroy(config: &StoreConfig) -> Result<()> {
    match config {
        StoreConfig::Memory => Ok(()),
        #[cfg(not(target_arch = "wasm32"))]
        StoreConfig::Sqlite { path, .. } => {
            if !path.exists() {
                return Ok(());
            }
            let lock = StoreLock::acquire(path)?;
            for name in SQLITE_FILES {
                match std::fs::remove_file(path.join(name)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(CryptoError::Store("delete store")),
                }
            }
            drop(lock);
            let _ = std::fs::remove_file(path.join(LOCK_FILE));
            // only if nothing of the host's is left in it
            let _ = std::fs::remove_dir(path);
            Ok(())
        }
        #[cfg(target_arch = "wasm32")]
        // the library deletes its databases only in its own tests; until the
        // wasm bindings (CR-14) the host deletes `indexeddb_names(name)` itself
        StoreConfig::IndexedDb { .. } => Err(CryptoError::Store("delete indexeddb store")),
    }
}

/// IndexedDB databases `matrix-sdk-indexeddb` creates for a store `name`
/// (to be deleted by the host on sign-out until CR-14 does it here)
pub fn indexeddb_names(name: &str) -> [String; 2] {
    [
        format!("{name}::matrix-sdk-crypto"),
        format!("{name}::matrix-sdk-crypto-meta"),
    ]
}
