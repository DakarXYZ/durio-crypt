//! Encrypted message envelope v1 (00-architecture §R5, Q5).
//!
//! `{"v":1,"algorithm":"m.megolm.v1.aes-sha2","session_id":…,"device_id":…,"ciphertext":…}`
//!
//! Strict: unknown fields are rejected — the backend validates the envelope the
//! same way and the format only changes with a new `v`. The library's
//! `sender_key` is never forwarded (Q5); `device_id` is an unauthenticated hint
//! that the core compares with the session owner.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::redact::Redacted;
use crate::{ALGORITHM_MEGOLM, ids};

/// Current envelope version
pub const ENVELOPE_VERSION: u32 = 1;

/// Maximum length of `ciphertext` (base64 characters), backend `max_envelope_bytes`
pub const MAX_CIPHERTEXT_LEN: usize = 16_384;

/// Maximum length of `session_id`, as on the backend
pub const MAX_SESSION_ID_LEN: usize = 128;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    /// Envelope version, always [`ENVELOPE_VERSION`]
    pub v: u32,
    /// Encryption algorithm, [`ALGORITHM_MEGOLM`]
    pub algorithm: String,
    /// Megolm session id
    pub session_id: String,
    /// Sending device (session ULID), only a hint
    pub device_id: String,
    /// Megolm message, base64
    pub ciphertext: String,
}

/// Why an envelope was rejected. Never carries envelope content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum EnvelopeError {
    /// `v` other than 1 — "update the app"
    #[error("unsupported envelope version")]
    UnsupportedVersion,
    /// Algorithm other than Megolm v1 — "update the app"
    #[error("unknown encryption algorithm")]
    UnknownAlgorithm,
    /// Ciphertext or session id over the limit
    #[error("envelope too large")]
    TooLarge,
    /// Structure does not match envelope v1
    #[error("malformed envelope: {0}")]
    Malformed(&'static str),
}

impl EncryptedEnvelope {
    /// Megolm envelope v1
    pub fn megolm(session_id: impl Into<String>, device_id: impl Into<String>, ciphertext: impl Into<String>) -> Self {
        Self {
            v: ENVELOPE_VERSION,
            algorithm: ALGORITHM_MEGOLM.to_owned(),
            session_id: session_id.into(),
            device_id: device_id.into(),
            ciphertext: ciphertext.into(),
        }
    }

    /// Parse and validate, version first: an envelope from a newer client is
    /// [`EnvelopeError::UnsupportedVersion`], not a parse error.
    pub fn from_value(value: &Value) -> Result<Self, EnvelopeError> {
        let object = value.as_object().ok_or(EnvelopeError::Malformed("not an object"))?;
        match object.get("v").and_then(Value::as_u64) {
            Some(v) if v == u64::from(ENVELOPE_VERSION) => {}
            Some(_) => return Err(EnvelopeError::UnsupportedVersion),
            None => return Err(EnvelopeError::Malformed("missing version")),
        }
        // size limits before anything is decoded or copied
        if object
            .get("ciphertext")
            .and_then(Value::as_str)
            .is_some_and(|c| c.len() > MAX_CIPHERTEXT_LEN)
        {
            return Err(EnvelopeError::TooLarge);
        }
        // serde's own message may quote field values, so it is dropped
        let envelope = Self::deserialize(value).map_err(|_| EnvelopeError::Malformed("not an envelope v1"))?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// [`from_value`](Self::from_value) for a JSON string
    pub fn from_json(json: &str) -> Result<Self, EnvelopeError> {
        let value: Value = serde_json::from_str(json).map_err(|_| EnvelopeError::Malformed("not JSON"))?;
        Self::from_value(&value)
    }

    /// Checks of envelope v1 (the backend applies the same ones)
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.v != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion);
        }
        if self.algorithm != ALGORITHM_MEGOLM {
            return Err(EnvelopeError::UnknownAlgorithm);
        }
        if self.ciphertext.len() > MAX_CIPHERTEXT_LEN || self.session_id.len() > MAX_SESSION_ID_LEN {
            return Err(EnvelopeError::TooLarge);
        }
        if self.ciphertext.is_empty() || self.session_id.is_empty() {
            return Err(EnvelopeError::Malformed("empty field"));
        }
        if !ids::is_ulid(&self.device_id) {
            return Err(EnvelopeError::Malformed("device_id"));
        }
        Ok(())
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("envelope serializes")
    }
}

impl fmt::Debug for EncryptedEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedEnvelope")
            .field("v", &self.v)
            .field("algorithm", &self.algorithm)
            .field("session_id", &self.session_id)
            .field("device_id", &self.device_id)
            .field("ciphertext", &Redacted)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn valid() -> Value {
        json!({
            "v": 1,
            "algorithm": ALGORITHM_MEGOLM,
            "session_id": "sid",
            "device_id": "01KDA1A1A1A1A1A1A1A1A1A1A1",
            "ciphertext": "SECRET",
        })
    }

    #[test]
    fn version_first() {
        let mut v = valid();
        v["v"] = json!(2);
        v["new_field"] = json!(true);
        assert_eq!(
            EncryptedEnvelope::from_value(&v),
            Err(EnvelopeError::UnsupportedVersion)
        );
        v["v"] = json!("1");
        assert!(matches!(
            EncryptedEnvelope::from_value(&v),
            Err(EnvelopeError::Malformed(_))
        ));
    }

    #[test]
    fn size_checked_before_parse() {
        let mut v = valid();
        v["ciphertext"] = json!("A".repeat(MAX_CIPHERTEXT_LEN + 1));
        v["junk"] = json!(1);
        assert_eq!(EncryptedEnvelope::from_value(&v), Err(EnvelopeError::TooLarge));
    }

    #[test]
    fn device_id_must_be_ulid() {
        let mut v = valid();
        v["device_id"] = json!("not-a-device");
        assert!(matches!(
            EncryptedEnvelope::from_value(&v),
            Err(EnvelopeError::Malformed(_))
        ));
    }

    #[test]
    fn debug_redacted() {
        let e = EncryptedEnvelope::from_value(&valid()).unwrap();
        let s = format!("{e:?}");
        assert!(
            !s.contains("SECRET") && s.contains("<redacted>") && s.contains("sid"),
            "{s}"
        );
    }
}
