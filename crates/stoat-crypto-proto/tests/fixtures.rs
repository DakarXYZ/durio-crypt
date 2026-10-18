//! Contract v1 vectors from `fixtures/` round-trip through the typed bodies
//! unchanged (CR-03). The same files are copied to the backend
//! (`stoatchat/crates/core/models/tests/fixtures/e2ee/`), so a type that drops
//! or renames a field fails here first.

use std::path::PathBuf;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use stoat_crypto_proto::api::*;
use stoat_crypto_proto::envelope::{EncryptedEnvelope, EnvelopeError};
use stoat_crypto_proto::events::E2eeEvent;
use stoat_crypto_proto::payload::{MegolmPlaintext, PAD_BLOCK, PayloadError};
use stoat_crypto_proto::to_device::{RoomKeyRequestContent, VerificationRequestContent};
use stoat_crypto_proto::{ids, to_device};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn read(rel: &str) -> Value {
    let text = std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// `value` → `T` → JSON is the same value (key order aside)
fn roundtrip<T: DeserializeOwned + Serialize>(value: &Value, what: &str) -> T {
    let typed: T = serde_json::from_value(value.clone()).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert_eq!(
        &serde_json::to_value(&typed).unwrap(),
        value,
        "{what} changed in a round trip"
    );
    typed
}

/// Request and response of an exchange fixture
fn exchange<Req, Resp>(rel: &str) -> (Req, Resp)
where
    Req: DeserializeOwned + Serialize,
    Resp: DeserializeOwned + Serialize,
{
    let f = read(rel);
    (roundtrip(&f["request"], rel), roundtrip(&f["response"], rel))
}

fn response<Resp: DeserializeOwned + Serialize>(rel: &str) -> (String, Resp) {
    let f = read(rel);
    assert!(f["request"].is_null(), "{rel}");
    (f["path"].as_str().unwrap().to_owned(), roundtrip(&f["response"], rel))
}

#[test]
fn keys() {
    let (req, resp): (KeysUploadRequest, KeysUploadResponse) = exchange("api/keys/upload.initial.json");
    let dk = req.device_keys.expect("device keys");
    assert!(ids::user_ulid(dk["user_id"].as_str().unwrap()).is_some());
    assert_eq!(req.one_time_keys.unwrap().len(), 50);
    assert!(req.fallback_keys.is_none(), "fallback comes in a separate upload");
    assert_eq!(resp.one_time_key_counts["signed_curve25519"], 50);

    let (req, _): (KeysUploadRequest, KeysUploadResponse) = exchange("api/keys/upload.otk_only.json");
    assert!(req.device_keys.is_none() && req.one_time_keys.is_none());
    let fallback = req.fallback_keys.unwrap();
    assert_eq!(fallback.len(), 1);
    assert_eq!(fallback.values().next().unwrap()["fallback"], true);

    let (req, resp): (KeysQueryRequest, KeysQueryResponse) = exchange("api/keys/query.json");
    assert_eq!(req.device_keys.len(), 1);
    assert!(resp.master_keys.is_empty() && resp.self_signing_keys.is_empty() && resp.user_signing_keys.is_empty());

    let (req, resp): (KeysClaimRequest, KeysClaimResponse) = exchange("api/keys/claim.json");
    let (user, devices) = req.one_time_keys.iter().next().unwrap();
    assert!(
        devices
            .values()
            .all(|a| a == stoat_crypto_proto::KEY_ALGORITHM_SIGNED_CURVE25519)
    );
    assert_eq!(resp.one_time_keys[user].len(), devices.len());

    let (path, count): (_, KeysCountResponse) = response("api/keys/count.json");
    assert_eq!(path, paths::KEYS_COUNT);
    assert_eq!(count.device_unused_fallback_key_types, Vec::<String>::new());
}

/// The backend answers `keys/upload` with the fallback list as well
#[test]
fn upload_response_with_fallback_types() {
    let v = serde_json::json!({
        "one_time_key_counts": { "signed_curve25519": 50 },
        "device_unused_fallback_key_types": ["signed_curve25519"],
    });
    let r: KeysUploadResponse = roundtrip(&v, "upload response");
    assert_eq!(r.device_unused_fallback_key_types.unwrap(), ["signed_curve25519"]);
}

#[test]
fn to_device() {
    for t in [
        "m.room.encrypted",
        "m.room_key_request",
        "m.key.verification.request",
        "m.key.verification.ready",
    ] {
        let rel = format!("api/to_device/put.{t}.json");
        let f = read(&rel);
        let (req, _): (ToDeviceSendRequest, ToDeviceSendResponse) = exchange(&rel);
        assert_eq!(req.event_type, t);
        let txn = f["path"].as_str().unwrap().strip_prefix("/e2ee/to_device/").unwrap();
        assert_eq!(paths::to_device_send(txn), f["path"].as_str().unwrap());
        assert_eq!(
            to_device::is_plaintext_allowed(t),
            t != to_device::ROOM_ENCRYPTED,
            "{t}"
        );
        for devices in req.messages.values() {
            for content in devices.values() {
                match t {
                    "m.room_key_request" => {
                        let c: RoomKeyRequestContent = roundtrip(content, &rel);
                        assert_eq!(c.action, "request");
                        assert!(devices.contains_key("*"), "key requests go to all own devices");
                    }
                    "m.key.verification.request" | "m.key.verification.ready" => {
                        let _: VerificationRequestContent = roundtrip(content, &rel);
                    }
                    _ => assert_eq!(content["algorithm"], stoat_crypto_proto::ALGORITHM_OLM),
                }
            }
        }
    }

    let (path, fetched): (_, ToDeviceFetchResponse) = response("api/to_device/get.json");
    assert_eq!(path, paths::to_device_fetch(100));
    for m in &fetched.messages {
        assert!(ids::user_ulid(&m.sender).is_some(), "sender is Matrix-shaped");
        assert!(ids::is_ulid(&m.sender_device) && ids::is_ulid(&m.id));
    }

    let (ack, _): (ToDeviceAckRequest, Value) = exchange("api/to_device/ack.json");
    assert!(!ack.ids.is_empty() && ack.ids.len() <= MAX_TO_DEVICE_ACK);
}

#[test]
fn backup() {
    let (req, created): (BackupVersionRequest, BackupVersionCreateResponse) =
        exchange("api/backup/version.create.json");
    assert_eq!(req.algorithm, stoat_crypto_proto::BACKUP_ALGORITHM_MEGOLM_V1);
    assert_eq!(req.auth_data["signatures"], serde_json::json!({}));

    let (_, version): (_, BackupVersion) = response("api/backup/version.get.json");
    assert_eq!(version.version, created.version);

    let f = read("api/backup/keys.put.json");
    assert_eq!(f["path"], paths::backup_keys(&created.version));
    let (put, updated): (KeysBackup, KeysBackupUpdateResponse) = exchange("api/backup/keys.put.json");
    assert_eq!(
        updated.count as usize,
        put.rooms.values().map(|r| r.sessions.len()).sum::<usize>()
    );
    for room in put.rooms.keys() {
        assert!(ids::channel_ulid(room).is_some());
    }

    let (_, all): (_, KeysBackup) = response("api/backup/keys.get.json");
    assert!(!all.rooms.is_empty());
}

#[test]
fn envelope() {
    let valid = read("envelope/valid.json");
    let e = EncryptedEnvelope::from_value(&valid).unwrap();
    assert_eq!(e.to_value(), valid);

    for (name, expected) in [
        ("unknown_field", EnvelopeError::Malformed("not an envelope v1")),
        ("version", EnvelopeError::UnsupportedVersion),
        ("missing_ciphertext", EnvelopeError::Malformed("not an envelope v1")),
        ("algorithm", EnvelopeError::UnknownAlgorithm),
    ] {
        let bad = read(&format!("envelope/invalid.{name}.json"));
        assert_eq!(EncryptedEnvelope::from_value(&bad), Err(expected), "{name}");
    }
}

#[test]
fn payload() {
    for name in ["full", "edit"] {
        let rel = format!("payload/megolm_plaintext.{name}.json");
        let v = read(&rel);
        let p = MegolmPlaintext::from_value(&v).unwrap();
        assert_eq!(serde_json::to_value(&p).unwrap(), v, "{rel}");
        assert!(ids::channel_ulid(&p.room_id).is_some());
        assert_eq!(serde_json::to_vec(&v["content"]).unwrap().len() % PAD_BLOCK, 0, "{rel}");
        // re-padding a received payload gives the same length
        assert_eq!(
            serde_json::to_vec(&p.content.to_padded_value().unwrap()).unwrap().len(),
            serde_json::to_vec(&v["content"]).unwrap().len()
        );
    }

    let full = MegolmPlaintext::from_value(&read("payload/megolm_plaintext.full.json")).unwrap();
    let a = &full.content.attachments[0];
    assert!(a.spoiler);
    assert_eq!(a.file.v, "v2");
    // C8: low 64 bits of the IV are zero
    let iv = stoat_crypto_proto::b64::decode(&a.file.iv).unwrap();
    assert_eq!(&iv[8..], &[0u8; 8]);
    assert!(a.thumbnail.is_some());
    assert_eq!(full.content.in_reply_to.len(), 1);

    let edit = MegolmPlaintext::from_value(&read("payload/megolm_plaintext.edit.json")).unwrap();
    assert!(edit.content.edit_of.is_some() && edit.content.edit_seq == 1);

    // a payload from a newer client
    let mut future = read("payload/megolm_plaintext.edit.json");
    future["content"]["v"] = serde_json::json!(2);
    assert_eq!(
        MegolmPlaintext::from_value(&future),
        Err(PayloadError::UnsupportedVersion)
    );
}

#[test]
fn ws_events() {
    for name in ["E2eeToDevice", "E2eeDeviceListUpdate"] {
        let v = read(&format!("ws/{name}.json"));
        let e: E2eeEvent = roundtrip(&v, name);
        match e {
            E2eeEvent::E2eeToDevice {
                sender,
                recipient_device,
                ..
            } => {
                // the backend sends the Matrix-shaped sender
                assert!(ids::user_ulid(&sender).is_some(), "{sender}");
                assert!(ids::is_ulid(&recipient_device));
            }
            E2eeEvent::E2eeDeviceListUpdate { user } => assert!(ids::is_ulid(&user)),
        }
    }
}

#[test]
fn recovery_key_format() {
    let k = read("backup/recovery_key.json");
    let key = k["recovery_key"].as_str().unwrap();
    assert_eq!(key.len(), 48);
}

/// Recovery key vectors (CR-12): key bytes → display form, and inputs the
/// UI must classify as a typo or as "not a key" (`DUMP_FIXTURES=1` rewrites)
#[test]
fn recovery_key_vectors() {
    use stoat_crypto_proto::recovery_key::{self, RecoveryKeyError};

    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let keys: [[u8; 32]; 3] = [[0; 32], std::array::from_fn(|i| i as u8), [0xff; 32]];
    let valid: Vec<Value> = keys
        .iter()
        .map(|k| json!({ "key_hex": hex(k), "recovery_key": recovery_key::encode(k).as_str() }))
        .collect();
    let good = recovery_key::encode(&keys[1]).replace(' ', "");
    let swap = |i: usize, c: char| -> String {
        let mut v: Vec<char> = good.chars().collect();
        v[i] = if v[i] == c { 'z' } else { c };
        v.into_iter().collect()
    };
    let invalid = [
        (swap(30, 'A'), "typo"),
        (swap(7, '0'), "typo"),
        (good[..44].to_owned(), "not_a_key"),
        ("correct horse battery staple".to_owned(), "not_a_key"),
    ];
    for (input, kind) in &invalid {
        let e = recovery_key::decode(input).unwrap_err();
        let expected = if *kind == "typo" {
            RecoveryKeyError::Typo
        } else {
            RecoveryKeyError::NotAKey
        };
        assert_eq!(e, expected, "{input}");
    }
    let value = json!({
        "note": "base58(0x8B 0x01 || key || parity), 48 chars in groups of 4; whitespace ignored on input",
        "valid": valid,
        "invalid": invalid.iter().map(|(i, k)| json!({ "input": i, "error": k })).collect::<Vec<_>>(),
    });
    let rel = "backup/recovery_key.vectors.json";
    let text = serde_json::to_string_pretty(&value).unwrap() + "\n";
    if std::env::var_os("DUMP_FIXTURES").is_some() {
        std::fs::write(root().join(rel), &text).unwrap();
    }
    let committed = std::fs::read_to_string(root().join(rel)).unwrap().replace("\r\n", "\n");
    assert_eq!(committed, text, "{rel} is stale: DUMP_FIXTURES=1");
    for v in value["valid"].as_array().unwrap() {
        let decoded = recovery_key::decode(v["recovery_key"].as_str().unwrap()).unwrap();
        assert_eq!(hex(decoded.as_slice()), v["key_hex"]);
    }
}
