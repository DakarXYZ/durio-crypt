//! Attachments chunk by chunk (CR-10). Upload: `AttachmentEncryptor` →
//! `update` per chunk → `finish()` = `EncryptedFile` JSON for the payload.
//! Download: hash the whole blob with `AttachmentVerifier` first; only its
//! `finish()` gives the `AttachmentDecryptor` for the second pass.

use std::fmt;
use std::sync::{Arc, Mutex};

use stoat_crypto as sc;
use stoat_crypto::proto::EncryptedFile;

use crate::error::CryptoError;
use crate::runtime::guard;

fn file_from_json(json: &str) -> Result<EncryptedFile, CryptoError> {
    let file: EncryptedFile = serde_json::from_str(json).map_err(|_| sc::CryptoError::InvalidAttachment)?;
    file.validate().map_err(|_| sc::CryptoError::InvalidAttachment)?;
    Ok(file)
}

fn file_to_json(file: &EncryptedFile) -> Result<String, CryptoError> {
    serde_json::to_string(file).map_err(|_| sc::CryptoError::Internal("encrypted file").into())
}

/// `None` = finished; a poisoned lock (panic midway) is unusable
fn with<T, R>(m: &Mutex<Option<T>>, f: impl FnOnce(&mut T) -> R) -> Result<R, CryptoError> {
    let mut guard = m.lock().map_err(|_| CryptoError::panic())?;
    let inner = guard.as_mut().ok_or_else(CryptoError::finished)?;
    Ok(f(inner))
}

fn take<T>(m: &Mutex<Option<T>>) -> Result<T, CryptoError> {
    m.lock()
        .map_err(|_| CryptoError::panic())?
        .take()
        .ok_or_else(CryptoError::finished)
}

/// Recommended chunk size in bytes
#[uniffi::export]
pub fn attachment_chunk_size() -> u32 {
    u32::try_from(sc::ATTACHMENT_CHUNK).unwrap_or(u32::MAX)
}

#[derive(Debug, uniffi::Object)]
pub struct AttachmentEncryptor {
    inner: Mutex<Option<sc::AttachmentEncryptor>>,
}

#[uniffi::export]
impl AttachmentEncryptor {
    /// Fresh key and IV for one file or thumbnail
    #[uniffi::constructor]
    pub fn new() -> Result<Arc<Self>, CryptoError> {
        guard(|| {
            Ok(Arc::new(Self {
                inner: Mutex::new(Some(sc::AttachmentEncryptor::new())),
            }))
        })
    }

    /// Encrypt the next chunk; upload the output in order
    pub fn update(&self, chunk: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        guard(|| {
            let mut chunk = chunk;
            with(&self.inner, |e| e.update_in_place(&mut chunk))?;
            Ok(chunk)
        })
    }

    /// Bytes encrypted so far
    pub fn size(&self) -> Result<u64, CryptoError> {
        guard(|| with(&self.inner, |e| e.size()))
    }

    /// `EncryptedFile` JSON for `Attachment.file` / `Thumbnail.file`
    pub fn finish(&self) -> Result<String, CryptoError> {
        guard(|| file_to_json(&take(&self.inner)?.finish()))
    }
}

#[derive(Debug, uniffi::Object)]
pub struct AttachmentVerifier {
    inner: Mutex<Option<sc::AttachmentVerifier>>,
}

#[uniffi::export]
impl AttachmentVerifier {
    /// `file_json` = the `EncryptedFile` from the decrypted payload
    #[uniffi::constructor]
    pub fn new(file_json: String) -> Result<Arc<Self>, CryptoError> {
        guard(|| {
            let file = file_from_json(&file_json)?;
            Ok(Arc::new(Self {
                inner: Mutex::new(Some(sc::AttachmentVerifier::new(&file)?)),
            }))
        })
    }

    /// Hash the next chunk of the downloaded ciphertext
    pub fn update(&self, chunk: Vec<u8>) -> Result<(), CryptoError> {
        guard(|| with(&self.inner, |v| v.update(&chunk)))
    }

    /// `AttachmentHashMismatch`: the server swapped the blob, show nothing
    pub fn finish(&self) -> Result<Arc<AttachmentDecryptor>, CryptoError> {
        guard(|| {
            let decryptor = take(&self.inner)?.finish()?;
            Ok(Arc::new(AttachmentDecryptor {
                inner: Mutex::new(Some(decryptor)),
            }))
        })
    }
}

/// Second pass over the verified blob, from its start
#[derive(Debug, uniffi::Object)]
pub struct AttachmentDecryptor {
    inner: Mutex<Option<sc::AttachmentDecryptor>>,
}

#[uniffi::export]
impl AttachmentDecryptor {
    pub fn update(&self, chunk: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        guard(|| {
            let mut chunk = chunk;
            with(&self.inner, |d| d.update_in_place(&mut chunk))?;
            Ok(chunk)
        })
    }
}

/// A small blob (thumbnail) in one call
#[derive(Clone, uniffi::Record)]
pub struct EncryptedAttachment {
    pub ciphertext: Vec<u8>,
    /// `EncryptedFile` JSON
    pub file_json: String,
}

impl fmt::Debug for EncryptedAttachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedAttachment")
            .field("len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

#[uniffi::export]
pub fn encrypt_attachment(data: Vec<u8>) -> Result<EncryptedAttachment, CryptoError> {
    guard(|| {
        let (ciphertext, file) = sc::encrypt_attachment(&data);
        Ok(EncryptedAttachment {
            ciphertext,
            file_json: file_to_json(&file)?,
        })
    })
}

/// Verify the hash, then decrypt (small blobs)
#[uniffi::export]
pub fn decrypt_attachment(ciphertext: Vec<u8>, file_json: String) -> Result<Vec<u8>, CryptoError> {
    guard(|| Ok(sc::decrypt_attachment(&ciphertext, &file_from_json(&file_json)?)?))
}
