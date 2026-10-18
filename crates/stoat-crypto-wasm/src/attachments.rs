//! Attachments chunk by chunk (CR-10). Upload: `AttachmentEncryptor` →
//! `update` per chunk → `finish()` = `EncryptedFile` JSON for the payload.
//! Download: hash the whole blob with `AttachmentVerifier` first; only its
//! `finish()` gives the `AttachmentDecryptor` for the second pass.

use stoat_crypto as sc;
use stoat_crypto::proto::EncryptedFile;
use wasm_bindgen::prelude::*;

use crate::error::Error;

pub(crate) fn file_from_json(json: &str) -> Result<EncryptedFile, Error> {
    let file: EncryptedFile = serde_json::from_str(json).map_err(|_| sc::CryptoError::InvalidAttachment)?;
    file.validate().map_err(|_| sc::CryptoError::InvalidAttachment)?;
    Ok(file)
}

pub(crate) fn file_to_json(file: &EncryptedFile) -> Result<String, Error> {
    serde_json::to_string(file).map_err(|_| Error::internal("encrypted file"))
}

fn live<T>(inner: &mut Option<T>) -> Result<&mut T, Error> {
    inner.as_mut().ok_or_else(Error::finished)
}

#[derive(Debug)]
#[wasm_bindgen]
pub struct AttachmentEncryptor {
    inner: Option<sc::AttachmentEncryptor>,
}

#[wasm_bindgen]
impl AttachmentEncryptor {
    /// Fresh key and IV for one file or thumbnail
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: Some(sc::AttachmentEncryptor::new()),
        }
    }

    /// Encrypt the next chunk; upload the output in order
    pub fn update(&mut self, mut chunk: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        live(&mut self.inner)?.update_in_place(&mut chunk);
        Ok(chunk)
    }

    /// Bytes encrypted so far
    pub fn size(&mut self) -> Result<f64, JsValue> {
        Ok(live(&mut self.inner)?.size() as f64)
    }

    /// `EncryptedFile` JSON for `Attachment.file` / `Thumbnail.file` (holds
    /// the key: never log it)
    pub fn finish(&mut self) -> Result<String, JsValue> {
        let encryptor = self.inner.take().ok_or_else(Error::finished)?;
        Ok(file_to_json(&encryptor.finish())?)
    }
}

#[derive(Debug)]
#[wasm_bindgen]
pub struct AttachmentVerifier {
    inner: Option<sc::AttachmentVerifier>,
}

#[wasm_bindgen]
impl AttachmentVerifier {
    /// `fileJson` = the `EncryptedFile` from the decrypted payload
    #[wasm_bindgen(constructor)]
    pub fn new(file_json: String) -> Result<AttachmentVerifier, JsValue> {
        let file = file_from_json(&file_json)?;
        Ok(Self {
            inner: Some(sc::AttachmentVerifier::new(&file).map_err(Error::from)?),
        })
    }

    /// Hash the next chunk of the downloaded ciphertext
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), JsValue> {
        live(&mut self.inner)?.update(chunk);
        Ok(())
    }

    /// `AttachmentHashMismatch`: the server swapped the blob, show nothing
    pub fn finish(&mut self) -> Result<AttachmentDecryptor, JsValue> {
        let verifier = self.inner.take().ok_or_else(Error::finished)?;
        Ok(AttachmentDecryptor {
            inner: verifier.finish().map_err(Error::from)?,
        })
    }
}

/// Second pass over the verified blob, from its start
#[derive(Debug)]
#[wasm_bindgen]
pub struct AttachmentDecryptor {
    inner: sc::AttachmentDecryptor,
}

#[wasm_bindgen]
impl AttachmentDecryptor {
    pub fn update(&mut self, mut chunk: Vec<u8>) -> Vec<u8> {
        self.inner.update_in_place(&mut chunk);
        chunk
    }
}
