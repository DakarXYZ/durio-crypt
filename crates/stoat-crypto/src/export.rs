//! CR-21: room keys to a password-protected file and back — for a reinstall
//! without the server backup and for debugging (T2/T3).
//!
//! Format: Matrix "Megolm session export" (`-----BEGIN MEGOLM SESSION
//! DATA-----`, AES-256-CTR + HMAC-SHA-256, key from PBKDF2-SHA-512), the
//! library's `encrypt_room_key_export` / `decrypt_room_key_export` — no own
//! crypto. Before the library sees a file the core checks its header: the
//! PBKDF2 round count comes from the file, so a crafted file could make the
//! device hash for hours (same limit as the backup passphrase), and a file
//! too short for the format must not reach the library's slicing.
//!
//! Imported keys are `Verification::Unauthenticated`, like keys from the
//! backup: anybody can write a file with a session of their own. An import
//! never makes a key worse (lower first index wins, the library's merge).

use std::fmt;

use matrix_sdk_crypto::olm::ExportedRoomKey;
use matrix_sdk_crypto::{KeyExportError, decrypt_room_key_export, encrypt_room_key_export};

use stoat_crypto_proto::key_export;

use crate::error::{CryptoError, Result};
use crate::gossip;
use crate::ids;
use crate::machine::CryptoMachine;
use crate::types::RoomKeyInfo;

/// PBKDF2 rounds of an export (what Matrix clients use)
pub const EXPORT_ROUNDS: u32 = 500_000;

/// A key export to save as a file (`.txt`, ASCII). Ciphertext only — still
/// no reason to log it.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyExport {
    /// The armored file content
    pub data: String,
    /// Sessions in the file
    pub sessions: usize,
}

impl fmt::Debug for KeyExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyExport")
            .field("data_len", &self.data.len())
            .field("sessions", &self.sessions)
            .finish()
    }
}

/// Outcome of an import
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyImportResult {
    /// Sessions in the file
    pub total: usize,
    /// New or better keys stored
    pub imported: usize,
    /// Sessions of rooms that are not Stoat channels (another Matrix
    /// client's export), left out
    pub skipped: usize,
    /// Keys stored: re-decrypt messages waiting for them
    pub room_keys: Vec<RoomKeyInfo>,
}

impl CryptoMachine {
    /// Export the room keys of `channels` (all channels if empty) into a
    /// file encrypted with `passphrase` (not empty). PBKDF2 makes this take
    /// about a second: run it off the UI thread.
    pub async fn export_room_keys(&self, passphrase: &str, channels: &[String]) -> Result<KeyExport> {
        if passphrase.is_empty() {
            return Err(CryptoError::PassphraseRequired);
        }
        let rooms = channels.iter().map(|c| ids::room_id(c)).collect::<Result<Vec<_>>>()?;
        let keys = self
            .olm()
            .store()
            .export_room_keys(|s| rooms.is_empty() || rooms.iter().any(|r| r == s.room_id()))
            .await
            .map_err(|_| CryptoError::Store("export room keys"))?;
        let sessions = keys.len();
        let data = encrypt_room_key_export(&keys, passphrase, EXPORT_ROUNDS)
            .map_err(|_| CryptoError::Internal("export room keys"))?;
        Ok(KeyExport { data, sessions })
    }

    /// Import a key file (ours, or another Matrix client's: only sessions of
    /// Stoat channels are kept). `WrongPassphrase` if the MAC does not
    /// match, `InvalidKeyFile` if it is not such a file. Imported keys show
    /// as `Unauthenticated`.
    pub async fn import_room_keys(&self, file: &str, passphrase: &str) -> Result<KeyImportResult> {
        // the armor first, never the library on a crafted file (proto, fuzzed)
        let file = key_export::parse(file).map_err(|_| CryptoError::InvalidKeyFile)?;
        let keys = decrypt_room_key_export(file.armored.as_bytes(), passphrase).map_err(|e| match e {
            KeyExportError::InvalidMac => CryptoError::WrongPassphrase,
            _ => CryptoError::InvalidKeyFile,
        })?;
        let total = keys.len();
        let (ours, foreign): (Vec<ExportedRoomKey>, Vec<ExportedRoomKey>) =
            keys.into_iter().partition(|k| ids::channel_ulid(&k.room_id).is_some());
        let skipped = foreign.len();
        drop(foreign);

        // `None`: not from a backup — the keys go up to ours if it is on
        let r = self
            .olm()
            .store()
            .import_room_keys(ours, None, |_, _| {})
            .await
            .map_err(|_| CryptoError::Store("import room keys"))?;
        self.touch();

        let arrived: Vec<_> = r
            .keys
            .iter()
            .flat_map(|(room, by_sender)| {
                by_sender
                    .values()
                    .flatten()
                    .map(move |session| (room.clone(), session.clone()))
            })
            .collect();
        // CR-08: no key requests for these any more
        let cancels = gossip::keys_arrived(self.key_requests(), self.olm(), &arrived).await?;
        for c in cancels {
            self.add_own_request(c).await;
        }
        Ok(KeyImportResult {
            total,
            imported: r.imported_count,
            skipped,
            room_keys: arrived
                .into_iter()
                .filter_map(|(room, session_id)| {
                    Some(RoomKeyInfo {
                        channel_id: ids::channel_ulid(&room)?,
                        session_id,
                    })
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_debug_has_no_data() {
        let e = KeyExport {
            data: format!(
                "{}
QUJD
{}",
                key_export::HEADER,
                key_export::FOOTER
            ),
            sessions: 1,
        };
        let shown = format!("{e:?}");
        assert!(!shown.contains("QUJD") && !shown.contains("BEGIN"), "{shown}");
    }
}
