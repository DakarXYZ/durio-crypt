//! Base64 as used by the contract: the standard alphabet **without** padding
//! (like Matrix and vodozemac). Readers accept both padded and unpadded input.
//!
//! The only exception is the JWK `k` of an `EncryptedFile`, which is base64url
//! by the format; see [`decode_url`].

use base64::Engine;
use base64::alphabet::{STANDARD, URL_SAFE};
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

const WRITE: GeneralPurpose = GeneralPurpose::new(&STANDARD, GeneralPurposeConfig::new().with_encode_padding(false));

const READ: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

const READ_URL: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

pub use base64::DecodeError;

/// Encode with the standard alphabet, no padding
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    WRITE.encode(bytes)
}

/// Decode standard base64, padded or not
pub fn decode(s: &str) -> Result<Vec<u8>, DecodeError> {
    READ.decode(s)
}

/// Decode base64url, padded or not (JWK `k`)
pub fn decode_url(s: &str) -> Result<Vec<u8>, DecodeError> {
    READ_URL.decode(s)
}

/// Upper bound of the decoded length of a base64 string of `encoded_len`
/// characters — to reject oversized fields before allocating (CR-03).
pub const fn decoded_len_upper(encoded_len: usize) -> usize {
    encoded_len / 4 * 3 + 3
}

/// Length of the unpadded base64 encoding of `len` bytes
pub const fn encoded_len(len: usize) -> usize {
    (len * 4).div_ceil(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_unpadded_reads_both() {
        assert_eq!(encode(b"ab"), "YWI");
        assert_eq!(decode("YWI").unwrap(), b"ab");
        assert_eq!(decode("YWI=").unwrap(), b"ab");
        assert!(decode("YW!").is_err());
        assert_eq!(decode_url("-_8").unwrap(), [0xfb, 0xff]);
        assert!(decode("-_8").is_err());
    }

    #[test]
    fn lengths() {
        for n in 0..100 {
            let s = encode(vec![0u8; n]);
            assert_eq!(s.len(), encoded_len(n));
            assert!(decoded_len_upper(s.len()) >= n);
        }
    }
}
