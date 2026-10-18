//! Payload v1 — what is inside the Megolm ciphertext (00-architecture §R5, C7,
//! C8, CR-19, Q9).
//!
//! The Megolm plaintext is Matrix-shaped (C7):
//! `{"type":"stoat.message","room_id":"!…:stoat.invalid","content":MessagePayload}`.
//! `type` and `room_id` are added by the library when encrypting; the library
//! checks `room_id` against the session on decryption.
//!
//! No `deny_unknown_fields` here: fields added by newer clients must not break
//! older ones (CR-03, CR-23).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::b64;
use crate::redact::Redacted;

/// Current payload version
pub const PAYLOAD_VERSION: u32 = 1;

/// Event type of the Megolm plaintext
pub const EVENT_TYPE: &str = "stoat.message";

/// The serialized payload is padded to a multiple of this (Q9)
pub const PAD_BLOCK: usize = 256;

/// Largest padded payload whose envelope still fits [`MAX_CIPHERTEXT_LEN`]
/// (checked by `max_payload_fits_envelope`).
///
/// [`MAX_CIPHERTEXT_LEN`]: crate::envelope::MAX_CIPHERTEXT_LEN
pub const MAX_PAYLOAD_LEN: usize = 12_032;

/// Length of the plaintext wrapper `{"type":"stoat.message","room_id":"!<26>:stoat.invalid","content":}`
pub const PLAINTEXT_OVERHEAD: usize = 89;

/// Upper bound of the base64 ciphertext length of a Megolm message carrying
/// `plaintext_len` bytes: version, index and length varints, AES-256-CBC with
/// PKCS#7 padding, 8-byte MAC and 64-byte Ed25519 signature.
pub const fn megolm_ciphertext_len_upper(plaintext_len: usize) -> usize {
    let aes = (plaintext_len / 16 + 1) * 16;
    let raw = 1 + (1 + 5) + (1 + 3) + aes + 8 + 64;
    b64::encoded_len(raw)
}

/// Payload v1
#[derive(Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct MessagePayload {
    /// Payload version, [`PAYLOAD_VERSION`]
    pub v: u32,
    /// Message text (markdown), absent for attachment-only messages
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Encrypted attachments (C8)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    /// base64 of 16 random bytes, equal to the `nonce` of the send request (CR-19)
    pub client_nonce: String,
    /// Id of the edited message, only in edits (CR-19)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edit_of: Option<String>,
    /// Monotonic edit counter, 0 for the original (CR-19)
    #[serde(default)]
    pub edit_seq: u64,
    /// Replied message ids, compared with the open `replies` (CR-19)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub in_reply_to: Vec<String>,
    /// Sender clock, milliseconds since the epoch (display only)
    pub ts: u64,
    /// Padding to a multiple of [`PAD_BLOCK`] bytes (Q9)
    #[serde(default)]
    pub pad: String,
}

/// Attachment of an encrypted message (C8)
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    /// autumn file id of the encrypted blob
    pub id: String,
    pub name: String,
    pub content_type: String,
    /// Size of the plaintext file in bytes
    pub size: u64,
    /// Stoat file metadata (`{"type":"Image","width":…}`), as is
    pub metadata: Value,
    #[serde(default)]
    pub spoiler: bool,
    /// Key, IV and hash of the blob
    pub file: EncryptedFile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<Thumbnail>,
}

/// Encrypted thumbnail of an image or video attachment (C8)
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Thumbnail {
    pub id: String,
    pub width: u32,
    pub height: u32,
    pub file: EncryptedFile,
}

/// Matrix `EncryptedFile` v2 without `url` (C8): AES-256-CTR, the low 64 bits
/// of the IV are zero, SHA-256 of the ciphertext.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedFile {
    /// `"v2"`
    pub v: String,
    pub key: JsonWebKey,
    /// base64, 16 bytes
    pub iv: String,
    /// `sha256` → base64 hash of the ciphertext
    pub hashes: BTreeMap<String, String>,
}

/// JWK of an attachment key (`kty: "oct"`, `alg: "A256CTR"`, `k` base64url)
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonWebKey {
    pub kty: String,
    pub key_ops: Vec<String>,
    pub alg: String,
    pub k: String,
    pub ext: bool,
}

/// Megolm plaintext (C7)
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct MegolmPlaintext {
    #[serde(rename = "type")]
    pub event_type: String,
    pub room_id: String,
    pub content: MessagePayload,
}

/// Why a payload was rejected. Never carries payload content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PayloadError {
    /// `v` other than 1 — "update the app"
    #[error("unsupported payload version")]
    UnsupportedVersion,
    /// Plaintext `type` other than [`EVENT_TYPE`]
    #[error("unexpected plaintext type")]
    UnexpectedType,
    /// Serialized payload over [`MAX_PAYLOAD_LEN`]
    #[error("payload too large")]
    TooLarge,
    #[error("malformed payload: {0}")]
    Malformed(&'static str),
}

impl MessagePayload {
    /// Text message v1
    pub fn text(content: impl Into<String>, client_nonce: impl Into<String>, ts: u64) -> Self {
        Self {
            v: PAYLOAD_VERSION,
            content: Some(content.into()),
            client_nonce: client_nonce.into(),
            ts,
            ..Default::default()
        }
    }

    /// autumn ids for the open `attachments` of the send request: every file
    /// **and every thumbnail** (C9) — a file not listed there is never marked
    /// used and the server deletes it after an hour
    pub fn file_ids(&self) -> Vec<String> {
        self.attachments
            .iter()
            .flat_map(|a| std::iter::once(a.id.clone()).chain(a.thumbnail.as_ref().map(|t| t.id.clone())))
            .collect()
    }

    /// Serialize with `pad` so that the JSON length is a multiple of
    /// [`PAD_BLOCK`] bytes (Q9). Fails over [`MAX_PAYLOAD_LEN`].
    pub fn to_padded_value(&self) -> Result<Value, PayloadError> {
        pad_value(serde_json::to_value(self).map_err(|_| PayloadError::Malformed("serialize"))?)
    }

    /// Parse version first: a payload from a newer client is
    /// [`PayloadError::UnsupportedVersion`], not a parse error.
    pub fn from_value(value: &Value) -> Result<Self, PayloadError> {
        let object = value.as_object().ok_or(PayloadError::Malformed("not an object"))?;
        match object.get("v").and_then(Value::as_u64) {
            Some(v) if v == u64::from(PAYLOAD_VERSION) => {}
            Some(_) => return Err(PayloadError::UnsupportedVersion),
            None => return Err(PayloadError::Malformed("missing version")),
        }
        let payload = Self::deserialize(value).map_err(|_| PayloadError::Malformed("not a payload v1"))?;
        for a in &payload.attachments {
            a.file.validate()?;
            if let Some(t) = &a.thumbnail {
                t.file.validate()?;
            }
        }
        Ok(payload)
    }
}

impl MegolmPlaintext {
    /// Parse a decrypted Megolm plaintext, version first
    pub fn from_value(value: &Value) -> Result<Self, PayloadError> {
        if value.get("type").and_then(Value::as_str) != Some(EVENT_TYPE) {
            return Err(PayloadError::UnexpectedType);
        }
        let room_id = value
            .get("room_id")
            .and_then(Value::as_str)
            .ok_or(PayloadError::Malformed("room_id"))?
            .to_owned();
        let content = MessagePayload::from_value(value.get("content").ok_or(PayloadError::Malformed("content"))?)?;
        Ok(Self {
            event_type: EVENT_TYPE.to_owned(),
            room_id,
            content,
        })
    }
}

/// Lengths of the decoded `EncryptedFile` fields
const FILE_KEY_LEN: usize = 32;
const FILE_IV_LEN: usize = 16;
const FILE_HASH_LEN: usize = 32;

fn check_b64(s: &str, len: usize, url: bool) -> Result<(), PayloadError> {
    // length first: no allocation for a hostile 16 MB field
    if s.len() > b64::encoded_len(len) + 2 {
        return Err(PayloadError::Malformed("encrypted file field too long"));
    }
    let bytes = if url { b64::decode_url(s) } else { b64::decode(s) };
    match bytes {
        Ok(b) if b.len() == len => Ok(()),
        _ => Err(PayloadError::Malformed("encrypted file field")),
    }
}

impl EncryptedFile {
    /// Structural checks of `EncryptedFile` v2 (does not touch the blob)
    pub fn validate(&self) -> Result<(), PayloadError> {
        if self.v != "v2" || self.key.kty != "oct" || self.key.alg != "A256CTR" {
            return Err(PayloadError::Malformed("encrypted file version or key type"));
        }
        check_b64(&self.key.k, FILE_KEY_LEN, true)?;
        check_b64(&self.iv, FILE_IV_LEN, false)?;
        check_b64(
            self.hashes
                .get("sha256")
                .ok_or(PayloadError::Malformed("encrypted file hash"))?,
            FILE_HASH_LEN,
            false,
        )
    }
}

/// Set `pad` of a payload JSON object so that its serialized length is a
/// multiple of [`PAD_BLOCK`] bytes (Q9); every other field is kept as is.
/// Fails over [`MAX_PAYLOAD_LEN`] or for a non-object.
pub fn pad_value(mut value: Value) -> Result<Value, PayloadError> {
    let object = value.as_object_mut().ok_or(PayloadError::Malformed("not an object"))?;
    object.insert("pad".into(), Value::String(String::new()));
    let base = serde_json::to_vec(&value)
        .map_err(|_| PayloadError::Malformed("serialize"))?
        .len();
    let need = (PAD_BLOCK - base % PAD_BLOCK) % PAD_BLOCK;
    if base + need > MAX_PAYLOAD_LEN {
        return Err(PayloadError::TooLarge);
    }
    value["pad"] = Value::String("0".repeat(need));
    Ok(value)
}

impl fmt::Debug for MessagePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessagePayload")
            .field("v", &self.v)
            .field("content", &self.content.as_ref().map(|_| Redacted))
            .field("attachments", &self.attachments.len())
            .field("edit_of", &self.edit_of)
            .field("edit_seq", &self.edit_seq)
            .field("in_reply_to", &self.in_reply_to)
            .field("ts", &self.ts)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Attachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attachment")
            .field("id", &self.id)
            .field("name", &Redacted)
            .field("size", &self.size)
            .field("file", &self.file)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Thumbnail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Thumbnail")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for EncryptedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedFile")
            .field("v", &self.v)
            .field("key", &Redacted)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for JsonWebKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonWebKey")
            .field("k", &Redacted)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for MegolmPlaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MegolmPlaintext")
            .field("type", &self.event_type)
            .field("room_id", &self.room_id)
            .field("content", &self.content)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::envelope::MAX_CIPHERTEXT_LEN;

    #[test]
    fn padding_is_block_multiple() {
        for n in [0, 1, 100, 255, 256, 1000, 5000] {
            let p = MessagePayload::text("я".repeat(n), "AAAAAAAAAAAAAAAAAAAAAA", 1);
            let v = p.to_padded_value().unwrap();
            assert_eq!(serde_json::to_vec(&v).unwrap().len() % PAD_BLOCK, 0, "{n}");
            assert_eq!(MessagePayload::from_value(&v).unwrap().content, p.content);
        }
    }

    #[test]
    fn too_large() {
        let p = MessagePayload::text("x".repeat(MAX_PAYLOAD_LEN), "", 1);
        assert_eq!(p.to_padded_value(), Err(PayloadError::TooLarge));
    }

    #[test]
    fn max_payload_fits_envelope() {
        assert!(megolm_ciphertext_len_upper(MAX_PAYLOAD_LEN + PLAINTEXT_OVERHEAD) <= MAX_CIPHERTEXT_LEN);
        assert!(megolm_ciphertext_len_upper(MAX_PAYLOAD_LEN + PAD_BLOCK + PLAINTEXT_OVERHEAD) > MAX_CIPHERTEXT_LEN);
        let wrapper = json!({
            "type": EVENT_TYPE,
            "room_id": crate::ids::room_id("01KCCCCCCCCCCCCCCCCCCCCCCC").unwrap(),
            "content": {},
        });
        assert_eq!(serde_json::to_vec(&wrapper).unwrap().len() - 2, PLAINTEXT_OVERHEAD);
    }

    #[test]
    fn version_first_and_unknown_fields() {
        let mut v = json!({ "v": 1, "client_nonce": "n", "ts": 1, "from_the_future": [1, 2] });
        assert!(MessagePayload::from_value(&v).is_ok());
        v["v"] = json!(2);
        v["ts"] = json!("not a number");
        assert_eq!(MessagePayload::from_value(&v), Err(PayloadError::UnsupportedVersion));
    }

    #[test]
    fn plaintext_type_checked() {
        let v = json!({ "type": "m.room.message", "room_id": "!x:stoat.invalid", "content": { "v": 1, "client_nonce": "n", "ts": 1 } });
        assert_eq!(MegolmPlaintext::from_value(&v), Err(PayloadError::UnexpectedType));
    }

    #[test]
    fn debug_redacted() {
        let p = MessagePayload::text("SECRET TEXT", "n", 1);
        let s = format!("{p:?}");
        assert!(!s.contains("SECRET") && s.contains("<redacted>"), "{s}");
    }
}
