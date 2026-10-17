//! Build a 0.16 SQLite crypto store for device A holding one inbound Megolm
//! session from B, plus an encrypted event that only that session decrypts.
//! Output: <out>/store/ (sqlite) and <out>/case.json.

use std::collections::BTreeMap;

use matrix_sdk_crypto::{
    types::requests::AnyOutgoingRequest, DecryptionSettings, EncryptionSettings, EncryptionSyncChanges, OlmMachine,
    TrustRequirement,
};
use matrix_sdk_sqlite::SqliteCryptoStore;
use ruma::{
    api::{client::sync::sync_events::DeviceLists, IncomingResponse},
    events::AnyMessageLikeEventContent,
    serde::Raw,
    DeviceId, OneTimeKeyAlgorithm, RoomId, UInt, UserId,
};
use serde_json::{json, Value};

fn parse<R: IncomingResponse>(v: &Value) -> R {
    let bytes = serde_json::to_vec(v).unwrap();
    R::try_from_http_response(http::Response::builder().status(200).body(bytes).unwrap()).unwrap()
}

async fn upload(m: &OlmMachine) -> (Value, Value) {
    for r in m.outgoing_requests().await.unwrap() {
        if let AnyOutgoingRequest::KeysUpload(u) = r.request() {
            let dk = serde_json::to_value(u.device_keys.as_ref().unwrap()).unwrap();
            let otks = serde_json::to_value(&u.one_time_keys).unwrap();
            let n = u.one_time_keys.len();
            let resp: ruma::api::client::keys::upload_keys::v3::Response =
                parse(&json!({"one_time_key_counts": {"signed_curve25519": n}}));
            m.mark_request_as_sent(r.request_id(), &resp).await.unwrap();
            return (dk, otks);
        }
    }
    panic!("no upload")
}

#[tokio::main]
async fn main() {
    let out = std::path::PathBuf::from(std::env::args().nth(1).expect("out dir"));
    let key = [0x42u8; 32];
    let a_id = UserId::parse("@01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid").unwrap();
    let b_id = UserId::parse("@01kbbbbbbbbbbbbbbbbbbbbbbb:stoat.invalid").unwrap();
    let a_dev: &DeviceId = "01KDA1A1A1A1A1A1A1A1A1A1A1".into();
    let b_dev: &DeviceId = "01KDB1B1B1B1B1B1B1B1B1B1B1".into();
    let room = RoomId::parse("!01kccccccccccccccccccccccc:stoat.invalid").unwrap();

    let store = SqliteCryptoStore::open_with_key(out.join("store"), Some(&key))
        .await
        .unwrap();
    let a = OlmMachine::with_store(&a_id, a_dev, store, None).await.unwrap();
    let b = OlmMachine::new(&b_id, b_dev).await;
    let (a_dk, a_otks) = upload(&a).await;
    upload(&b).await;

    b.update_tracked_users([a_id.as_ref()]).await.unwrap();
    for r in b.outgoing_requests().await.unwrap() {
        if let AnyOutgoingRequest::KeysQuery(_) = r.request() {
            let resp: ruma::api::client::keys::get_keys::v3::Response = parse(&json!({
                "device_keys": { a_id.as_str(): { a_dev.as_str(): a_dk } },
                "failures": {}, "master_keys": {}, "self_signing_keys": {}, "user_signing_keys": {}
            }));
            b.mark_request_as_sent(r.request_id(), &resp).await.unwrap();
        }
    }
    let (cid, _claim) = b
        .get_missing_sessions([a_id.as_ref()].into_iter())
        .await
        .unwrap()
        .unwrap();
    let (otk_id, otk) = a_otks.as_object().unwrap().iter().next().unwrap();
    let resp: ruma::api::client::keys::claim_keys::v3::Response = parse(&json!({
        "one_time_keys": { a_id.as_str(): { a_dev.as_str(): { otk_id: otk } } }, "failures": {}
    }));
    b.mark_request_as_sent(&cid, &resp).await.unwrap();
    let reqs = b
        .share_room_key(&room, [a_id.as_ref()].into_iter(), EncryptionSettings::default())
        .await
        .unwrap();
    let content = serde_json::to_value(&reqs[0].messages[&a_id]).unwrap()[a_dev.as_str()].clone();
    let ev = json!({ "sender": b_id, "type": "m.room.encrypted", "content": content });
    let counts: BTreeMap<OneTimeKeyAlgorithm, UInt> = BTreeMap::new();
    let lists = DeviceLists::new();
    let settings = DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    };
    a.receive_sync_changes(
        EncryptionSyncChanges {
            to_device_events: vec![Raw::from_json(serde_json::value::to_raw_value(&ev).unwrap())],
            changed_devices: &lists,
            one_time_keys_counts: &counts,
            unused_fallback_keys: None,
            next_batch_token: Some("[\"01KZ0000000000000000000016\"]".into()),
        },
        &settings,
    )
    .await
    .unwrap();

    let payload =
        json!({"v": 1, "content": "сообщение из 0.16", "client_nonce": "AAAAAAAAAAAAAAAAAAAAAA", "ts": 1, "pad": ""});
    let raw: Raw<AnyMessageLikeEventContent> = Raw::from_json(serde_json::value::to_raw_value(&payload).unwrap());
    let enc = b.encrypt_room_event_raw(&room, "stoat.message", &raw).await.unwrap();
    let event = json!({
        "type": "m.room.encrypted", "sender": b_id, "event_id": "$01KZ0000000000000000000099",
        "origin_server_ts": 1_760_700_000_000u64, "room_id": room, "content": enc.json(),
    });
    let r = a
        .decrypt_room_event(
            &Raw::from_json(serde_json::value::to_raw_value(&event).unwrap()),
            &room,
            &settings,
        )
        .await
        .expect("0.16 decrypts its own case");
    let _ = r;
    let ik = a.identity_keys();
    std::fs::write(
        out.join("case.json"),
        serde_json::to_string_pretty(&json!({
            "created_with": "matrix-sdk-crypto 0.16.0 / matrix-sdk-sqlite 0.16.0 (schema v13)",
            "store_key_hex": "42 x 32",
            "user_id": a_id, "device_id": a_dev, "room_id": room,
            "curve25519": ik.curve25519.to_base64(), "ed25519": ik.ed25519.to_base64(),
            "event": event, "plaintext": "сообщение из 0.16",
        }))
        .unwrap(),
    )
    .unwrap();
    println!("ok");
}
