//! Recovery key text format (Matrix "key representation", CR-12): base58
//! (Bitcoin alphabet) of `0x8B 0x01 || 32-byte key || parity`, the parity
//! byte being the XOR of all bytes before it — 48 characters, shown in
//! groups of 4 separated by spaces. Whitespace is insignificant on input.
//!
//! Input that has the shape of a key (48 characters after whitespace is
//! removed) but does not decode is a **typo** — the UI says so instead of
//! "wrong key". Anything else is not a recovery key (maybe a passphrase).

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const PREFIX: [u8; 2] = [0x8b, 0x01];
const KEY_LEN: usize = 32;
const DECODED_LEN: usize = PREFIX.len() + KEY_LEN + 1;
/// Characters of an encoded key without spaces
pub const ENCODED_LEN: usize = 48;
const GROUP: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RecoveryKeyError {
    /// Shaped like a recovery key but it does not check out (a mistyped or
    /// missing character)
    #[error("recovery key has a typo")]
    Typo,
    /// Not shaped like a recovery key at all
    #[error("not a recovery key")]
    NotAKey,
}

fn parity(key: &[u8]) -> u8 {
    key.iter().fold(PREFIX[0] ^ PREFIX[1], |acc, b| acc ^ b)
}

fn compact(input: &str) -> Zeroizing<String> {
    Zeroizing::new(input.chars().filter(|c| !c.is_whitespace()).collect())
}

/// Shaped like a recovery key (decides between "recovery key" and
/// "passphrase" for one input field)
pub fn looks_like_recovery_key(input: &str) -> bool {
    let c = compact(input);
    c.chars().count() == ENCODED_LEN && c.chars().all(|ch| ch.is_ascii_alphanumeric())
}

/// The display form: 48 characters in groups of 4
pub fn encode(key: &[u8; KEY_LEN]) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; DECODED_LEN]);
    bytes[..2].copy_from_slice(&PREFIX);
    bytes[2..2 + KEY_LEN].copy_from_slice(key);
    bytes[DECODED_LEN - 1] = parity(key);
    let plain = Zeroizing::new(bs58::encode(bytes.as_slice()).into_string());
    let mut out = Zeroizing::new(String::with_capacity(plain.len() + plain.len() / GROUP));
    for (i, ch) in plain.chars().enumerate() {
        if i > 0 && i % GROUP == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

/// The 32 key bytes of a recovery key
pub fn decode(input: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, RecoveryKeyError> {
    if !looks_like_recovery_key(input) {
        return Err(RecoveryKeyError::NotAKey);
    }
    let c = compact(input);
    let mut decoded = bs58::decode(c.as_str())
        .into_vec()
        .map_err(|_| RecoveryKeyError::Typo)?;
    let result = (|| {
        if decoded.len() != DECODED_LEN || decoded[..2] != PREFIX {
            return Err(RecoveryKeyError::Typo);
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&decoded[2..2 + KEY_LEN]);
        // the parity is a checksum of public structure, not a secret comparison
        if parity(key.as_slice()) != decoded[DECODED_LEN - 1] {
            return Err(RecoveryKeyError::Typo);
        }
        Ok(key)
    })();
    decoded.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_groups() {
        for seed in [0u8, 1, 0x42, 0xff] {
            let key = [seed; 32];
            let text = encode(&key);
            assert_eq!(text.replace(' ', "").len(), ENCODED_LEN);
            assert!(text.split(' ').all(|g| g.len() == 4), "{}", text.as_str());
            assert_eq!(*decode(&text).unwrap(), key);
            assert_eq!(*decode(&text.replace(' ', "\n")).unwrap(), key);
        }
    }

    #[test]
    fn typo_or_not_a_key() {
        let text = encode(&[7; 32]).replace(' ', "");
        let mut chars: Vec<char> = text.chars().collect();
        chars[20] = if chars[20] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.iter().collect();
        assert_eq!(decode(&typo).unwrap_err(), RecoveryKeyError::Typo);
        // `0`, `O`, `I`, `l` are not base58: still a typo, not a passphrase
        let mut chars: Vec<char> = text.chars().collect();
        chars[5] = '0';
        assert_eq!(
            decode(&chars.iter().collect::<String>()).unwrap_err(),
            RecoveryKeyError::Typo
        );
        assert_eq!(decode(&text[..47]).unwrap_err(), RecoveryKeyError::NotAKey);
        assert_eq!(
            decode("correct horse battery staple").unwrap_err(),
            RecoveryKeyError::NotAKey
        );
    }
}
