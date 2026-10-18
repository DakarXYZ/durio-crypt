//! Armor of a key export file (CR-21): the Matrix "Megolm session export",
//!
//! ```text
//! -----BEGIN MEGOLM SESSION DATA-----
//! base64( version 1 | salt 16 | IV 16 | PBKDF2 rounds u32 BE | ciphertext | HMAC-SHA-256 32 )
//! -----END MEGOLM SESSION DATA-----
//! ```
//!
//! Only the structure is checked here, no cryptography: the core runs this
//! before `matrix-sdk-crypto` decrypts the file, so that a crafted file can
//! not make the device hash for hours (the round count comes from the file)
//! nor reach the library's slicing too short. Fuzzed (`fuzz/key_export`).

use thiserror::Error;

use crate::b64;

pub const HEADER: &str = "-----BEGIN MEGOLM SESSION DATA-----";
pub const FOOTER: &str = "-----END MEGOLM SESSION DATA-----";
/// The only format version
pub const FORMAT_VERSION: u8 = 1;
/// Most PBKDF2 rounds accepted from a file (as for the backup passphrase)
pub const MAX_ROUNDS: u32 = 1_000_000;
/// Largest file read (review O-8): 64 MiB ≈ 90 000 sessions; a bigger
/// account exports per channel
pub const MAX_FILE_LEN: usize = 64 * 1024 * 1024;
/// version + salt + IV + rounds … MAC
pub const MIN_PAYLOAD: usize = 1 + 16 + 16 + 4 + 32;

/// Why a file is not a key export we read. Never carries file content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum KeyExportError {
    /// No armor, not base64 or too short for the format
    #[error("not a key export file")]
    NotAKeyFile,
    /// Over [`MAX_FILE_LEN`]: refused before anything is copied or decoded
    #[error("key export file too large")]
    TooLarge,
    /// A format version other than 1
    #[error("unsupported key export version")]
    UnsupportedVersion,
    /// PBKDF2 rounds of 0 or over [`MAX_ROUNDS`]
    #[error("key export with an unacceptable key derivation cost")]
    BadRounds,
}

/// A structurally valid export
#[derive(Clone, PartialEq, Eq)]
pub struct KeyExportFile {
    /// Normalized armored text (blank lines, indentation, CRLF and base64
    /// padding removed) as the library reads it
    pub armored: String,
    /// PBKDF2 rounds the passphrase is stretched with
    pub rounds: u32,
}

impl std::fmt::Debug for KeyExportFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyExportFile")
            .field("armored_len", &self.armored.len())
            .field("rounds", &self.rounds)
            .finish()
    }
}

/// Check the armor and the header fields of a key export file
pub fn parse(file: &str) -> Result<KeyExportFile, KeyExportError> {
    if file.len() > MAX_FILE_LEN {
        return Err(KeyExportError::TooLarge);
    }
    let text = file.trim();
    if !(text.starts_with(HEADER) && text.ends_with(FOOTER)) || text.len() < HEADER.len() + FOOTER.len() {
        return Err(KeyExportError::NotAKeyFile);
    }
    let body: String = text[HEADER.len()..text.len() - FOOTER.len()]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let payload = b64::decode(&body).map_err(|_| KeyExportError::NotAKeyFile)?;
    if payload.len() < MIN_PAYLOAD {
        return Err(KeyExportError::NotAKeyFile);
    }
    if payload[0] != FORMAT_VERSION {
        return Err(KeyExportError::UnsupportedVersion);
    }
    let rounds = u32::from_be_bytes([payload[33], payload[34], payload[35], payload[36]]);
    if !(1..=MAX_ROUNDS).contains(&rounds) {
        return Err(KeyExportError::BadRounds);
    }
    Ok(KeyExportFile {
        armored: format!("{HEADER}\n{}\n{FOOTER}", b64::encode(&payload)),
        rounds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn armor(payload: &[u8]) -> String {
        format!("{HEADER}\n{}\n{FOOTER}", b64::encode(payload))
    }

    fn payload(version: u8, rounds: u32, len: usize) -> Vec<u8> {
        let mut p = vec![version];
        p.extend([7u8; 32]);
        p.extend(rounds.to_be_bytes());
        p.resize(len, 9);
        p
    }

    #[test]
    fn header_fields_are_checked() {
        let good = armor(&payload(1, 500_000, 120));
        let parsed = parse(&good).unwrap();
        assert_eq!((parsed.armored.as_str(), parsed.rounds), (good.as_str(), 500_000));
        assert!(!format!("{parsed:?}").contains(&good[40..60]));

        // blanks, indentation, CRLF, wrapped lines and padding from a text editor
        let p = payload(1, 10, 121);
        let b = b64::encode(&p);
        let messy = format!("\n  {HEADER}\r\n  {}\r\n{}==\r\n{FOOTER}\r\n", &b[..40], &b[40..]);
        assert_eq!(parse(&messy).unwrap().armored, armor(&p));

        for (bad, e) in [
            (String::new(), KeyExportError::NotAKeyFile),
            ("hello".into(), KeyExportError::NotAKeyFile),
            (format!("{HEADER}{FOOTER}"), KeyExportError::NotAKeyFile),
            (format!("{HEADER}\n!!!\n{FOOTER}"), KeyExportError::NotAKeyFile),
            (
                format!("{HEADER}\n{}", b64::encode(payload(1, 10, 120))),
                KeyExportError::NotAKeyFile,
            ),
            (armor(&payload(1, 10, MIN_PAYLOAD - 1)), KeyExportError::NotAKeyFile),
            (armor(&payload(2, 10, 120)), KeyExportError::UnsupportedVersion),
            (armor(&payload(1, 0, 120)), KeyExportError::BadRounds),
            (armor(&payload(1, MAX_ROUNDS + 1, 120)), KeyExportError::BadRounds),
            (armor(&payload(1, u32::MAX, 120)), KeyExportError::BadRounds),
        ] {
            assert_eq!(parse(&bad).err(), Some(e), "{bad:?}");
        }
    }

    #[test]
    fn oversized_files_are_refused_first() {
        // valid armor around a body that alone is over the limit
        let big = format!(
            "{HEADER}
{}
{FOOTER}",
            "A".repeat(MAX_FILE_LEN)
        );
        assert_eq!(parse(&big).err(), Some(KeyExportError::TooLarge));
        let at_limit = format!(
            "{HEADER}
{}",
            " ".repeat(MAX_FILE_LEN - HEADER.len() - 1)
        );
        assert_eq!(parse(&at_limit).err(), Some(KeyExportError::NotAKeyFile));
    }

    /// The header and footer may overlap in a short input: no slicing panic
    #[test]
    fn overlapping_armor_is_refused() {
        let overlap = "-----BEGIN MEGOLM SESSION DATA-----END MEGOLM SESSION DATA-----";
        assert_eq!(parse(overlap).err(), Some(KeyExportError::NotAKeyFile));
    }
}
