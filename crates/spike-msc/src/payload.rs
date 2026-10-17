//! Envelope v1 and payload v1 (00-architecture §R5, C7, C8, CR-19).
//!
//! Megolm plaintext is Matrix-shaped:
//! `{"type":"stoat.message","room_id":"!…:stoat.invalid","content":PayloadV1}`.
//! `type` and `room_id` are added by `OlmMachine::encrypt_room_event_raw`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const EVENT_TYPE: &str = "stoat.message";
pub const PAD_BLOCK: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeV1 {
    pub v: u32,
    pub algorithm: String,
    pub session_id: String,
    /// Unauthenticated hint (Q5).
    pub device_id: String,
    pub ciphertext: String,
}

/// No `deny_unknown_fields`: newer clients may add fields (CR-03).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct PayloadV1 {
    pub v: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    /// base64(16 random bytes) = `nonce` of the send request
    pub client_nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edit_of: Option<String>,
    #[serde(default)]
    pub edit_seq: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub in_reply_to: Vec<String>,
    pub ts: u64,
    #[serde(default)]
    pub pad: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Attachment {
    pub id: String,
    pub name: String,
    pub content_type: String,
    pub size: u64,
    pub metadata: Value,
    #[serde(default)]
    pub spoiler: bool,
    /// Matrix `EncryptedFile` v2 without `url` (C8)
    pub file: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<Thumbnail>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Thumbnail {
    pub id: String,
    pub width: u32,
    pub height: u32,
    pub file: Value,
}

impl PayloadV1 {
    /// Serialize with `pad` so that the serialized payload length is a multiple
    /// of 256 bytes (Q9).
    pub fn to_padded_json(&self) -> Value {
        let mut p = self.clone();
        p.pad.clear();
        let base = serde_json::to_string(&p).expect("serializable").len();
        let need = (PAD_BLOCK - base % PAD_BLOCK) % PAD_BLOCK;
        p.pad = "0".repeat(need);
        let v = serde_json::to_value(&p).expect("serializable");
        debug_assert_eq!(serde_json::to_string(&v).unwrap().len() % PAD_BLOCK, 0);
        v
    }
}
