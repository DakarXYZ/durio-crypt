//! CR-20, requests and responses: library requests → `/e2ee/*` JSON (paths,
//! methods, bodies of contract v1), server JSON → library responses.
//!
//! The client executes the HTTP call and hands the body back; it never needs to
//! know request types (as in `matrix-sdk-crypto-ffi`). Response parsing goes
//! through `IncomingResponse::try_from_http_response`, so the server's extra
//! fields (`device_unused_fallback_key_types`, `failed`) are ignored the same
//! way the library ignores unknown Matrix fields.

use std::fmt;

use matrix_sdk_crypto::types::requests::{AnyOutgoingRequest, ToDeviceRequest};
use ruma::TransactionId;
use ruma::api::client::keys::claim_keys::v3::Request as KeysClaimRequest;
use ruma::api::client::keys::{
    claim_keys::v3::Response as KeysClaimResponse, get_keys::v3::Response as KeysQueryResponse,
    upload_keys::v3::Response as KeysUploadResponse,
};
use ruma::api::client::to_device::send_event_to_device::v3::Response as ToDeviceResponse;
use ruma::api::{IncomingResponse, IncomingResponseExt};
use serde_json::{Map, Value, json};
use stoat_crypto_proto::api::paths;

use crate::error::{CryptoError, Result};

/// What an [`OutgoingRequest`] is; passed back with the response
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RequestKind {
    /// `POST /e2ee/keys/upload`
    KeysUpload,
    /// `POST /e2ee/keys/query`
    KeysQuery,
    /// `POST /e2ee/keys/claim`
    KeysClaim,
    /// `PUT /e2ee/to_device/<txn_id>`
    ToDevice,
}

impl RequestKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KeysUpload => "keys_upload",
            Self::KeysQuery => "keys_query",
            Self::KeysClaim => "keys_claim",
            Self::ToDevice => "to_device",
        }
    }
}

/// HTTP request the client must perform, then report with
/// `mark_request_sent(id, kind, response)` or `mark_request_failed`.
#[derive(Clone, PartialEq, Eq)]
pub struct OutgoingRequest {
    /// Request id (for to-device: the transaction id in the path)
    pub id: String,
    pub kind: RequestKind,
    /// `POST` or `PUT`
    pub method: &'static str,
    /// Path relative to the API root, e.g. `/e2ee/keys/upload`
    pub path: String,
    /// JSON body
    pub body: String,
}

impl fmt::Debug for OutgoingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // bodies carry Olm ciphertext and signed keys: size only
        f.debug_struct("OutgoingRequest")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body_len", &self.body.len())
            .finish()
    }
}

fn request(id: &TransactionId, kind: RequestKind, method: &'static str, path: String, body: Value) -> OutgoingRequest {
    OutgoingRequest {
        id: id.to_string(),
        kind,
        method,
        path,
        body: body.to_string(),
    }
}

fn to_value(v: &impl serde::Serialize, what: &'static str) -> Result<Value> {
    serde_json::to_value(v).map_err(|_| CryptoError::Internal(what))
}

/// A library request in contract v1 form. `None` for kinds v1 never produces
/// (signature upload, in-room verification): without cross-signing and with
/// to-device verification only they do not occur.
pub(crate) fn from_library(id: &TransactionId, req: &AnyOutgoingRequest) -> Result<Option<OutgoingRequest>> {
    Ok(Some(match req {
        AnyOutgoingRequest::KeysUpload(r) => {
            // empty maps are left out: the backend treats a present `device_keys` as an upload of them
            let mut body = Map::new();
            if let Some(dk) = &r.device_keys {
                body.insert("device_keys".into(), to_value(dk, "keys upload")?);
            }
            if !r.one_time_keys.is_empty() {
                body.insert("one_time_keys".into(), to_value(&r.one_time_keys, "keys upload")?);
            }
            if !r.fallback_keys.is_empty() {
                body.insert("fallback_keys".into(), to_value(&r.fallback_keys, "keys upload")?);
            }
            request(
                id,
                RequestKind::KeysUpload,
                "POST",
                paths::KEYS_UPLOAD.into(),
                Value::Object(body),
            )
        }
        AnyOutgoingRequest::KeysQuery(r) => request(
            id,
            RequestKind::KeysQuery,
            "POST",
            paths::KEYS_QUERY.into(),
            json!({ "device_keys": to_value(&r.device_keys, "keys query")? }),
        ),
        AnyOutgoingRequest::KeysClaim(r) => keys_claim(id, r)?,
        AnyOutgoingRequest::ToDeviceRequest(r) => to_device(r)?,
        _ => return Ok(None),
    }))
}

pub(crate) fn keys_claim(id: &TransactionId, r: &KeysClaimRequest) -> Result<OutgoingRequest> {
    Ok(request(
        id,
        RequestKind::KeysClaim,
        "POST",
        paths::KEYS_CLAIM.into(),
        json!({ "one_time_keys": to_value(&r.one_time_keys, "keys claim")? }),
    ))
}

pub(crate) fn to_device(r: &ToDeviceRequest) -> Result<OutgoingRequest> {
    Ok(request(
        &r.txn_id,
        RequestKind::ToDevice,
        "PUT",
        paths::to_device_send(r.txn_id.as_str()),
        json!({ "type": r.event_type.to_string(), "messages": to_value(&r.messages, "to-device")? }),
    ))
}

fn parse<R: IncomingResponse>(body: &str, what: &'static str) -> Result<R> {
    // an empty 200/204 body is an empty object for the response types we use
    let body = if body.trim().is_empty() { "{}" } else { body };
    let response = http::Response::builder()
        .status(200)
        .body(body.as_bytes())
        .map_err(|_| CryptoError::InvalidResponse(what))?;
    R::try_from_http_response(response).map_err(|_| CryptoError::InvalidResponse(what))
}

/// Server response of a request, parsed for its kind
pub(crate) enum Response {
    KeysUpload(KeysUploadResponse),
    KeysQuery(KeysQueryResponse),
    KeysClaim(KeysClaimResponse),
    ToDevice(ToDeviceResponse),
}

impl Response {
    pub(crate) fn parse(kind: RequestKind, body: &str) -> Result<Self> {
        Ok(match kind {
            RequestKind::KeysUpload => Self::KeysUpload(parse(body, "keys upload")?),
            RequestKind::KeysQuery => Self::KeysQuery(parse(body, "keys query")?),
            RequestKind::KeysClaim => Self::KeysClaim(parse(body, "keys claim")?),
            RequestKind::ToDevice => Self::ToDevice(parse(body, "to-device")?),
        })
    }

    pub(crate) async fn mark_sent(&self, machine: &matrix_sdk_crypto::OlmMachine, id: &str) -> Result<()> {
        let id: &TransactionId = id.into();
        let r = match self {
            Self::KeysUpload(r) => machine.mark_request_as_sent(id, r).await,
            Self::KeysQuery(r) => machine.mark_request_as_sent(id, r).await,
            Self::KeysClaim(r) => machine.mark_request_as_sent(id, r).await,
            Self::ToDevice(r) => machine.mark_request_as_sent(id, r).await,
        };
        r.map_err(|_| CryptoError::Store("mark request sent"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn fixture(rel: &str) -> Value {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(rel);
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    /// Every fixture response parses for its kind (the table of CR-20)
    #[test]
    fn fixture_responses_parse() {
        let table = [
            (RequestKind::KeysUpload, "api/keys/upload.initial.json"),
            (RequestKind::KeysUpload, "api/keys/upload.otk_only.json"),
            (RequestKind::KeysQuery, "api/keys/query.json"),
            (RequestKind::KeysClaim, "api/keys/claim.json"),
            (RequestKind::ToDevice, "api/to_device/put.m.room.encrypted.json"),
        ];
        for (kind, rel) in table {
            let body = fixture(rel)["response"].to_string();
            assert!(Response::parse(kind, &body).is_ok(), "{rel}");
        }
    }

    /// Backend deviations from the CR-01 fixtures still parse
    #[test]
    fn backend_extensions_parse() {
        let table = [
            (
                RequestKind::KeysUpload,
                r#"{"one_time_key_counts":{"signed_curve25519":3},"device_unused_fallback_key_types":[]}"#,
            ),
            (
                RequestKind::ToDevice,
                r#"{"failed":{"@01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid":["X"]}}"#,
            ),
            (RequestKind::ToDevice, ""),
            (
                RequestKind::KeysQuery,
                r#"{"device_keys":{"@01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid":{}},"failures":{}}"#,
            ),
        ];
        for (kind, body) in table {
            assert!(Response::parse(kind, body).is_ok(), "{kind:?} {body}");
        }
    }

    #[test]
    fn garbage_is_invalid_response() {
        for kind in [RequestKind::KeysUpload, RequestKind::KeysQuery, RequestKind::KeysClaim] {
            assert!(matches!(
                Response::parse(kind, "[1,2]"),
                Err(CryptoError::InvalidResponse(_))
            ));
        }
    }
}
