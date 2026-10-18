//! Criterion 4: a matrix-sdk-sqlite 0.16 store (schema v13, created by
//! `tools/store-016`) opens with 0.19.1 (schema v19), migrates itself and keeps
//! the account and the inbound Megolm session.

use matrix_sdk_crypto::{DecryptionSettings, OlmMachineBuilder, TrustRequirement};
use matrix_sdk_sqlite::SqliteCryptoStore;
use ruma::{DeviceId, RoomId, UserId, serde::Raw};
use serde_json::Value;

#[tokio::test]
async fn store_016_migrates_to_019() {
    let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/stores/v016");
    let case: Value = serde_json::from_str(&std::fs::read_to_string(src.join("case.json")).unwrap()).unwrap();
    // work on a copy: migration rewrites the file
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(
        src.join("store/matrix-sdk-crypto.sqlite3"),
        dir.path().join("matrix-sdk-crypto.sqlite3"),
    )
    .unwrap();

    let store = SqliteCryptoStore::open_with_key(dir.path(), Some(&[0x42u8; 32]))
        .await
        .expect("open + migrate");
    let user = UserId::parse(case["user_id"].as_str().unwrap()).unwrap();
    let device: &DeviceId = case["device_id"].as_str().unwrap().into();
    let m = OlmMachineBuilder::new(&user, device)
        .with_crypto_store(store)
        .build()
        .await
        .unwrap();
    assert_eq!(
        m.identity_keys().curve25519.to_base64(),
        case["curve25519"].as_str().unwrap()
    );
    assert_eq!(m.identity_keys().ed25519.to_base64(), case["ed25519"].as_str().unwrap());

    let room = RoomId::parse(case["room_id"].as_str().unwrap()).unwrap();
    let ev = Raw::from_json(serde_json::value::to_raw_value(&case["event"]).unwrap());
    let settings = DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    };
    let d = m
        .decrypt_room_event(&ev, &room, &settings)
        .await
        .expect("session survived migration");
    let v: Value = serde_json::from_str(d.event.json().get()).unwrap();
    assert_eq!(v["content"]["content"], case["plaintext"]);
    // the processed-ids token (C2) survives as well
    assert_eq!(
        m.store().next_batch_token().await.unwrap().as_deref(),
        Some("[\"01KZ0000000000000000000016\"]")
    );
}
