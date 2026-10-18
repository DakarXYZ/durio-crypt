//! Request bodies cut to the server limits and the mailbox `failed` field.
//!
//! * to-device: at most `max_to_device_batch` messages (a `*` entry counts as
//!   one) and `max_request_bytes` of JSON per `PUT` (BE-07, BE-29, BE-21) —
//!   the library cuts room key shares at 250 messages, but not by size, and
//!   other to-device requests not at all;
//! * keys/claim: at most [`MAX_DEVICES_PER_REQUEST`] devices per request; the
//!   library sends every missing session in one claim;
//! * `PUT /to_device` may answer `{"failed": {user: [device]}}` for devices
//!   whose mailbox is full (Q11): nothing was stored for them.
//!
//! Pure functions over JSON strings; the machine keeps the state.

use serde_json::{Map, Value, json};
use stoat_crypto_proto::api::{MAX_DEVICES_PER_REQUEST, ToDeviceSendResponse};

/// Room left in a body for the parts outside `messages`
const BODY_MARGIN: usize = 1024;

/// Limits of the server, `GET /` → `features.e2ee` (BE-21). The defaults are
/// the backend defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerLimits {
    /// `max_to_device_batch`: messages per `PUT /e2ee/to_device`
    pub max_to_device_batch: usize,
    /// `max_request_bytes`: JSON body size of any request
    pub max_request_bytes: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_to_device_batch: 1_000,
            max_request_bytes: 4_194_304,
        }
    }
}

/// `(user, device, content)` of a to-device body, in body order
type Entry = (String, String, Value);

fn to_device_entries(body: &Value) -> Option<(Value, Vec<Entry>)> {
    let event_type = body.get("type")?.clone();
    let mut entries = Vec::new();
    for (user, devices) in body.get("messages")?.as_object()? {
        for (device, content) in devices.as_object()? {
            entries.push((user.clone(), device.clone(), content.clone()));
        }
    }
    Some((event_type, entries))
}

fn to_device_body(event_type: &Value, entries: &[Entry]) -> String {
    let mut messages: Map<String, Value> = Map::new();
    for (user, device, content) in entries {
        let devices = messages.entry(user.clone()).or_insert_with(|| json!({}));
        if let Some(d) = devices.as_object_mut() {
            d.insert(device.clone(), content.clone());
        }
    }
    json!({ "type": event_type, "messages": messages }).to_string()
}

/// Approximate JSON size of one entry inside `messages`
fn entry_len((user, device, content): &Entry) -> usize {
    user.len() + device.len() + content.to_string().len() + 12
}

/// Bodies of a to-device request cut to the limits, or `None` if it fits.
/// One message larger than the byte limit still goes alone (the server will
/// refuse it; nothing better can be done).
pub(crate) fn split_to_device(body: &str, limits: &ServerLimits) -> Option<Vec<String>> {
    let value: Value = serde_json::from_str(body).ok()?;
    let (event_type, entries) = to_device_entries(&value)?;
    let batch = limits.max_to_device_batch.max(1);
    if entries.len() <= batch && body.len() <= limits.max_request_bytes {
        return None;
    }
    let room = limits.max_request_bytes.saturating_sub(BODY_MARGIN).max(1);
    let mut parts = Vec::new();
    let mut current: Vec<Entry> = Vec::new();
    let mut size = 0;
    for e in entries {
        let len = entry_len(&e);
        if !current.is_empty() && (current.len() >= batch || size + len > room) {
            parts.push(to_device_body(&event_type, &current));
            current.clear();
            size = 0;
        }
        size += len;
        current.push(e);
    }
    if !current.is_empty() {
        parts.push(to_device_body(&event_type, &current));
    }
    Some(parts)
}

/// Bodies of a `keys/claim` cut to [`MAX_DEVICES_PER_REQUEST`] devices, or
/// `None` if it fits
pub(crate) fn split_claim(body: &str) -> Option<Vec<String>> {
    let value: Value = serde_json::from_str(body).ok()?;
    let mut devices = Vec::new();
    for (user, map) in value.get("one_time_keys")?.as_object()? {
        for (device, algorithm) in map.as_object()? {
            devices.push((user.clone(), device.clone(), algorithm.clone()));
        }
    }
    if devices.len() <= MAX_DEVICES_PER_REQUEST {
        return None;
    }
    Some(
        devices
            .chunks(MAX_DEVICES_PER_REQUEST)
            .map(|chunk| to_device_body(&Value::Null, chunk))
            .map(|b| {
                // same nesting as to-device, under `one_time_keys`
                let v: Value = serde_json::from_str(&b).unwrap_or_default();
                json!({ "one_time_keys": v["messages"] }).to_string()
            })
            .collect(),
    )
}

/// One `keys/claim` response from the responses of its parts
pub(crate) fn merge_claim_responses<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut keys: Map<String, Value> = Map::new();
    let mut failures: Map<String, Value> = Map::new();
    for body in parts {
        let Ok(v) = serde_json::from_str::<Value>(body) else {
            continue;
        };
        if let Some(f) = v.get("failures").and_then(Value::as_object) {
            failures.extend(f.clone());
        }
        for (user, devices) in v.get("one_time_keys").and_then(Value::as_object).into_iter().flatten() {
            let merged = keys.entry(user.clone()).or_insert_with(|| json!({}));
            if let (Some(m), Some(d)) = (merged.as_object_mut(), devices.as_object()) {
                m.extend(d.clone());
            }
        }
    }
    json!({ "one_time_keys": keys, "failures": failures }).to_string()
}

/// `(user, device)` pairs the server refused for a full mailbox
pub(crate) fn failed_recipients(response: &str) -> Vec<(String, String)> {
    if response.trim().is_empty() {
        return Vec::new();
    }
    serde_json::from_str::<ToDeviceSendResponse>(response)
        .map(|r| {
            r.failed
                .into_iter()
                .flat_map(|(u, ds)| ds.into_iter().map(move |d| (u.clone(), d)))
                .collect()
        })
        .unwrap_or_default()
}

/// Every `(user, device)` addressed by a to-device body (`*` as is)
pub(crate) fn recipients(body: &str) -> Vec<(String, String)> {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| to_device_entries(&v))
        .map(|(_, e)| e.into_iter().map(|(u, d, _)| (u, d)).collect())
        .unwrap_or_default()
}

/// The body re-addressed to `devices` only: each gets the content addressed
/// to it, else the user's `*` content. `None` if nothing is left.
pub(crate) fn restrict_to_device(body: &str, devices: &[(String, String)]) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    let (event_type, entries) = to_device_entries(&value)?;
    let mut kept = Vec::new();
    for (user, device) in devices {
        let content = entries
            .iter()
            .find(|(u, d, _)| u == user && d == device)
            .or_else(|| entries.iter().find(|(u, d, _)| u == user && d == "*"));
        if let Some((_, _, content)) = content {
            kept.push((user.clone(), device.clone(), content.clone()));
        }
    }
    (!kept.is_empty()).then(|| to_device_body(&event_type, &kept))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(users: usize, devices: usize, content_len: usize) -> String {
        let mut messages = Map::new();
        for u in 0..users {
            let mut d = Map::new();
            for i in 0..devices {
                d.insert(format!("D{i}"), json!({ "ciphertext": "x".repeat(content_len) }));
            }
            messages.insert(format!("@u{u}:stoat.invalid"), Value::Object(d));
        }
        json!({ "type": "m.room.encrypted", "messages": messages }).to_string()
    }

    fn count(body: &str) -> usize {
        recipients(body).len()
    }

    #[test]
    fn small_bodies_are_not_split() {
        let b = body(3, 2, 10);
        assert_eq!(split_to_device(&b, &ServerLimits::default()), None);
    }

    #[test]
    fn split_by_count_keeps_every_message_once() {
        let b = body(5, 3, 10);
        let limits = ServerLimits {
            max_to_device_batch: 4,
            ..ServerLimits::default()
        };
        let parts = split_to_device(&b, &limits).unwrap();
        assert_eq!(parts.len(), 4);
        assert!(parts.iter().all(|p| count(p) <= 4));
        let mut all: Vec<_> = parts.iter().flat_map(|p| recipients(p)).collect();
        all.sort();
        let mut expected = recipients(&b);
        expected.sort();
        assert_eq!(all, expected);
        for p in &parts {
            assert!(p.contains("\"type\":\"m.room.encrypted\""));
        }
    }

    #[test]
    fn split_by_size_stays_under_the_limit() {
        let b = body(10, 10, 2_000);
        let limits = ServerLimits {
            max_to_device_batch: 1_000,
            max_request_bytes: 20_000,
        };
        let parts = split_to_device(&b, &limits).unwrap();
        assert!(parts.len() > 1);
        assert!(
            parts.iter().all(|p| p.len() <= 20_000),
            "{:?}",
            parts.iter().map(String::len).collect::<Vec<_>>()
        );
        assert_eq!(parts.iter().map(|p| count(p)).sum::<usize>(), 100);
    }

    #[test]
    fn one_oversized_message_goes_alone() {
        let b = body(1, 2, 50_000);
        let limits = ServerLimits {
            max_to_device_batch: 1_000,
            max_request_bytes: 10_000,
        };
        let parts = split_to_device(&b, &limits).unwrap();
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn claims_split_at_the_device_limit_and_merge_back() {
        let mut keys = Map::new();
        for u in 0..3 {
            let mut d = Map::new();
            for i in 0..100 {
                d.insert(format!("D{i}"), json!("signed_curve25519"));
            }
            keys.insert(format!("@u{u}:stoat.invalid"), Value::Object(d));
        }
        let b = json!({ "one_time_keys": keys }).to_string();
        let parts = split_claim(&b).unwrap();
        assert_eq!(parts.len(), 2);
        let sizes: Vec<usize> = parts
            .iter()
            .map(|p| {
                let v: Value = serde_json::from_str(p).unwrap();
                v["one_time_keys"]
                    .as_object()
                    .unwrap()
                    .values()
                    .map(|d| d.as_object().unwrap().len())
                    .sum()
            })
            .collect();
        assert_eq!(sizes, [256, 44]);

        let r1 = json!({ "one_time_keys": { "@u0:stoat.invalid": { "D1": { "k": 1 } } }, "failures": {} });
        let r2 = json!({ "one_time_keys": { "@u0:stoat.invalid": { "D2": { "k": 2 } }, "@u1:stoat.invalid": { "D1": { "k": 3 } } } });
        let merged: Value =
            serde_json::from_str(&merge_claim_responses([r1.to_string().as_str(), &r2.to_string()])).unwrap();
        assert_eq!(
            merged["one_time_keys"]["@u0:stoat.invalid"].as_object().unwrap().len(),
            2
        );
        assert_eq!(merged["one_time_keys"]["@u1:stoat.invalid"]["D1"]["k"], 3);
        assert!(
            split_claim(&json!({ "one_time_keys": { "@u:stoat.invalid": { "D": "signed_curve25519" } } }).to_string())
                .is_none()
        );
    }

    #[test]
    fn failed_devices_are_re_addressed() {
        let b = json!({
            "type": "m.room_key_request",
            "messages": {
                "@a:stoat.invalid": { "*": { "x": 1 } },
                "@b:stoat.invalid": { "B1": { "x": 2 }, "B2": { "x": 3 } },
            }
        })
        .to_string();
        let failed = failed_recipients(r#"{"failed":{"@a:stoat.invalid":["A2"],"@b:stoat.invalid":["B2"]}}"#);
        assert_eq!(failed.len(), 2);
        let retry: Value = serde_json::from_str(&restrict_to_device(&b, &failed).unwrap()).unwrap();
        assert_eq!(retry["type"], "m.room_key_request");
        assert_eq!(retry["messages"]["@a:stoat.invalid"]["A2"]["x"], 1);
        assert_eq!(retry["messages"]["@b:stoat.invalid"]["B2"]["x"], 3);
        assert!(retry["messages"]["@b:stoat.invalid"].get("B1").is_none());
        assert!(failed_recipients("").is_empty());
        assert!(failed_recipients("{}").is_empty());
        assert!(restrict_to_device(&b, &[("@c:stoat.invalid".into(), "C1".into())]).is_none());
    }
}
