//! CR-10: encrypted attachments, Matrix `EncryptedFile` v2 (C8).
//!
//! AES-256-CTR over the file, SHA-256 over the ciphertext; key, IV and hash
//! travel inside the Megolm payload (`Attachment::file`,
//! `Thumbnail::file`). The IV has random high 64 bits and a **zero counter
//! half**, so implementations with a 64-bit counter agree on large files.
//!
//! CTR is not authenticated: the only integrity is the hash inside the
//! authenticated payload. Decryption is therefore two passes and the types
//! enforce the order — [`AttachmentVerifier`] hashes the downloaded
//! ciphertext and compares in constant time; only a successful
//! [`AttachmentVerifier::finish`] yields the [`AttachmentDecryptor`]. No
//! plaintext byte exists before the hash matched (a swapped blob never
//! reaches an image or video decoder).
//!
//! Chunked on purpose (FFI): the host loops over 64–256 KiB chunks itself,
//! one call per chunk, no reader callbacks across the boundary. Every file
//! and every thumbnail gets its own random key and IV: never reuse a pair.

use std::fmt;

use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use rand_10::{Rng, rng};
use sha2::{Digest, Sha256};
use stoat_crypto_proto::b64;
use stoat_crypto_proto::payload::{EncryptedFile, JsonWebKey};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const HASH_LEN: usize = 32;

/// Suggested chunk size for the host loop
pub const ATTACHMENT_CHUNK: usize = 256 * 1024;

/// Key, IV and ciphertext hash of an `EncryptedFile`
type Parts = (Zeroizing<[u8; KEY_LEN]>, [u8; IV_LEN], [u8; HASH_LEN]);

/// Key, IV and hash of an `EncryptedFile` after its structural checks
fn parts(file: &EncryptedFile) -> Result<Parts> {
    file.validate().map_err(|_| CryptoError::InvalidAttachment)?;
    let bad = |_| CryptoError::InvalidAttachment;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    let decoded = Zeroizing::new(b64::decode_url(&file.key.k).map_err(bad)?);
    key.copy_from_slice(decoded.get(..KEY_LEN).ok_or(CryptoError::InvalidAttachment)?);
    let iv: [u8; IV_LEN] = b64::decode(&file.iv)
        .map_err(bad)?
        .try_into()
        .map_err(|_| CryptoError::InvalidAttachment)?;
    let hash = file.hashes.get("sha256").ok_or(CryptoError::InvalidAttachment)?;
    let hash: [u8; HASH_LEN] = b64::decode(hash)
        .map_err(bad)?
        .try_into()
        .map_err(|_| CryptoError::InvalidAttachment)?;
    Ok((key, iv, hash))
}

fn cipher(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Aes256Ctr {
    Aes256Ctr::new(key.into(), iv.into())
}

/// Encrypts one file (or one thumbnail) chunk by chunk:
/// `new()` → `update` per chunk (upload the output in order) → `finish()`
/// gives the `EncryptedFile` for the payload.
pub struct AttachmentEncryptor {
    cipher: Aes256Ctr,
    sha: Sha256,
    key: Zeroizing<[u8; KEY_LEN]>,
    iv: [u8; IV_LEN],
    size: u64,
}

impl Default for AttachmentEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

impl AttachmentEncryptor {
    /// Fresh random key and IV (low 64 bits zero)
    pub fn new() -> Self {
        let mut rng = rng();
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        rng.fill_bytes(key.as_mut_slice());
        let mut iv = [0u8; IV_LEN];
        rng.fill_bytes(&mut iv[..8]);
        Self {
            cipher: cipher(&key, &iv),
            sha: Sha256::new(),
            key,
            iv,
            size: 0,
        }
    }

    /// Encrypt the next chunk of the plaintext
    pub fn update(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut out = chunk.to_vec();
        self.update_in_place(&mut out);
        out
    }

    /// Encrypt the next chunk in place (no copy)
    pub fn update_in_place(&mut self, chunk: &mut [u8]) {
        self.cipher.apply_keystream(chunk);
        self.sha.update(&*chunk);
        self.size += chunk.len() as u64;
    }

    /// Bytes encrypted so far (= plaintext and ciphertext size)
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Key, IV and ciphertext hash for `Attachment::file` / `Thumbnail::file`
    pub fn finish(self) -> EncryptedFile {
        let hash = self.sha.finalize();
        EncryptedFile {
            v: "v2".into(),
            key: JsonWebKey {
                kty: "oct".into(),
                key_ops: vec!["encrypt".into(), "decrypt".into()],
                alg: "A256CTR".into(),
                k: b64::encode_url(self.key.as_slice()),
                ext: true,
            },
            iv: b64::encode(self.iv),
            hashes: [("sha256".to_owned(), b64::encode(hash))].into(),
        }
    }
}

/// First pass over a downloaded blob: hash the ciphertext, compare with the
/// payload in constant time. Only then a decryptor exists.
pub struct AttachmentVerifier {
    sha: Sha256,
    expected: [u8; HASH_LEN],
    key: Zeroizing<[u8; KEY_LEN]>,
    iv: [u8; IV_LEN],
}

impl AttachmentVerifier {
    /// `InvalidAttachment` if the `EncryptedFile` is not a valid v2 object
    pub fn new(file: &EncryptedFile) -> Result<Self> {
        let (key, iv, expected) = parts(file)?;
        Ok(Self {
            sha: Sha256::new(),
            expected,
            key,
            iv,
        })
    }

    /// Hash the next chunk of the ciphertext
    pub fn update(&mut self, chunk: &[u8]) {
        self.sha.update(chunk);
    }

    /// `AttachmentHashMismatch` if the blob is not the one the sender
    /// encrypted (swapped or truncated by the server): show nothing
    pub fn finish(self) -> Result<AttachmentDecryptor> {
        let hash = self.sha.finalize();
        if !bool::from(hash.as_slice().ct_eq(&self.expected)) {
            return Err(CryptoError::AttachmentHashMismatch);
        }
        Ok(AttachmentDecryptor {
            cipher: cipher(&self.key, &self.iv),
        })
    }
}

/// Second pass: decrypt the verified blob from its start, chunk by chunk
pub struct AttachmentDecryptor {
    cipher: Aes256Ctr,
}

impl AttachmentDecryptor {
    /// Decrypt the next chunk
    pub fn update(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut out = chunk.to_vec();
        self.update_in_place(&mut out);
        out
    }

    /// Decrypt the next chunk in place
    pub fn update_in_place(&mut self, chunk: &mut [u8]) {
        self.cipher.apply_keystream(chunk);
    }
}

/// One-shot encryption for small blobs (thumbnails)
pub fn encrypt_attachment(data: &[u8]) -> (Vec<u8>, EncryptedFile) {
    let mut enc = AttachmentEncryptor::new();
    let out = enc.update(data);
    (out, enc.finish())
}

/// One-shot decryption for small blobs: verifies the hash first
pub fn decrypt_attachment(ciphertext: &[u8], file: &EncryptedFile) -> Result<Vec<u8>> {
    let mut v = AttachmentVerifier::new(file)?;
    v.update(ciphertext);
    Ok(v.finish()?.update(ciphertext))
}

impl fmt::Debug for AttachmentEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentEncryptor")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AttachmentVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentVerifier").finish_non_exhaustive()
    }
}

impl fmt::Debug for AttachmentDecryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentDecryptor").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use matrix_sdk_crypto::{AttachmentDecryptor as LibDecryptor, AttachmentEncryptor as LibEncryptor};

    use super::*;

    fn blob(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn chunked_roundtrip_any_split() {
        let data = blob(70_000);
        for chunk in [1, 15, 16, 17, 4096, 70_000] {
            let mut enc = AttachmentEncryptor::new();
            let ct: Vec<u8> = data.chunks(chunk).flat_map(|c| enc.update(c)).collect();
            assert_eq!(enc.size(), data.len() as u64);
            let file = enc.finish();
            assert_ne!(ct, data);
            let mut v = AttachmentVerifier::new(&file).unwrap();
            for c in ct.chunks(chunk + 3) {
                v.update(c);
            }
            let mut dec = v.finish().unwrap();
            let pt: Vec<u8> = ct.chunks(chunk + 5).flat_map(|c| dec.update(c)).collect();
            assert_eq!(pt, data, "{chunk}");
        }
    }

    #[test]
    fn iv_counter_half_is_zero_and_keys_differ() {
        let a = encrypt_attachment(b"x").1;
        let b = encrypt_attachment(b"x").1;
        let iv = b64::decode(&a.iv).unwrap();
        assert_eq!(&iv[8..], &[0u8; 8]);
        assert_ne!(a.key.k, b.key.k);
        assert_ne!(a.iv, b.iv);
        a.validate().unwrap();
    }

    #[test]
    fn swapped_or_truncated_blob_yields_no_plaintext() {
        let (mut ct, file) = encrypt_attachment(&blob(1000));
        assert_eq!(
            decrypt_attachment(&ct[..999], &file).unwrap_err(),
            CryptoError::AttachmentHashMismatch
        );
        ct[500] ^= 1;
        assert_eq!(
            decrypt_attachment(&ct, &file).unwrap_err(),
            CryptoError::AttachmentHashMismatch
        );
        let (other, _) = encrypt_attachment(&blob(1000));
        assert!(decrypt_attachment(&other, &file).is_err());
    }

    #[test]
    fn invalid_encrypted_file() {
        let (ct, mut file) = encrypt_attachment(b"abc");
        file.key.alg = "A128CTR".into();
        assert_eq!(
            decrypt_attachment(&ct, &file).unwrap_err(),
            CryptoError::InvalidAttachment
        );
    }

    /// Interop: the library's (Matrix) implementation reads ours and the
    /// other way round — same format, same counter
    #[test]
    fn matrix_sdk_crypto_interop() {
        let data = blob(100_000);
        let (ct, file) = encrypt_attachment(&data);
        let info: matrix_sdk_crypto::MediaEncryptionInfo =
            serde_json::from_value(serde_json::to_value(&file).unwrap()).unwrap();
        let mut reader = &ct[..];
        let mut out = Vec::new();
        LibDecryptor::new(&mut reader, info)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, data);

        let mut reader = &data[..];
        let mut lib = LibEncryptor::new(&mut reader);
        let mut ct = Vec::new();
        lib.read_to_end(&mut ct).unwrap();
        let file: EncryptedFile = serde_json::from_value(serde_json::to_value(lib.finish()).unwrap()).unwrap();
        assert_eq!(decrypt_attachment(&ct, &file).unwrap(), data);
    }

    #[test]
    fn debug_has_no_key() {
        let enc = AttachmentEncryptor::new();
        let key = b64::encode_url(enc.key.as_slice());
        let shown = format!("{enc:?}");
        assert!(!shown.contains(&key), "{shown}");
        let file = enc.finish();
        assert!(!format!("{file:?}").contains(&file.key.k));
    }
}
