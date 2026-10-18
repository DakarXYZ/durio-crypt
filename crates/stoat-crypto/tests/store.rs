//! CR-09 store and CR-17 single writer, through the public API.

mod common;

use std::path::PathBuf;

use common::*;
use serde_json::{Value, json};
use stoat_crypto::proto::api::ToDeviceMessage;
use stoat_crypto::proto::{EncryptedEnvelope, ids};
use stoat_crypto::{
    ChannelEncryptionSettings, CryptoError, CryptoMachine, IncomingEncryptedMessage, LOCK_FILE, StoreConfig, StoreKey,
    Verification,
};

fn config(path: PathBuf, key: [u8; 32]) -> StoreConfig {
    StoreConfig::Sqlite {
        path,
        key: StoreKey::new(key),
    }
}

/// Criterion 4 of CR-01 through the façade: a matrix-sdk-sqlite 0.16 store
/// (schema v13, `tools/store-016`) opens with 0.19.1, keeps the account, the
/// inbound Megolm session and the C2 processed set.
#[tokio::test]
async fn store_016_migrates_to_019() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/stores/v016");
    let case: Value = serde_json::from_str(&std::fs::read_to_string(src.join("case.json")).unwrap()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(
        src.join("store/matrix-sdk-crypto.sqlite3"),
        dir.path().join("matrix-sdk-crypto.sqlite3"),
    )
    .unwrap();

    let user = ids::user_ulid(case["user_id"].as_str().unwrap()).unwrap();
    let device = case["device_id"].as_str().unwrap();
    let m = CryptoMachine::open(&user, device, config(dir.path().into(), [0x42; 32]))
        .await
        .expect("open + migrate");
    let keys = m.identity_keys();
    assert_eq!(keys.curve25519, case["curve25519"].as_str().unwrap());
    assert_eq!(keys.ed25519, case["ed25519"].as_str().unwrap());

    let ev = &case["event"];
    let content = &ev["content"];
    let msg = IncomingEncryptedMessage {
        message_id: ev["event_id"].as_str().unwrap().trim_start_matches('$').into(),
        channel_id: ids::channel_ulid(ev["room_id"].as_str().unwrap()).unwrap(),
        author: ids::user_ulid(ev["sender"].as_str().unwrap()).unwrap(),
        // envelope v1: the library's `sender_key` is not part of it
        envelope: EncryptedEnvelope::megolm(
            content["session_id"].as_str().unwrap(),
            content["device_id"].as_str().unwrap(),
            content["ciphertext"].as_str().unwrap(),
        ),
        replies: vec![],
        timestamp: ev["origin_server_ts"].as_u64().unwrap(),
    };
    let d = m.decrypt(&msg).await.expect("session survived migration");
    assert_eq!(d.payload.content.as_deref(), case["plaintext"].as_str());
    assert_eq!(d.verification, Verification::UnknownDevice);

    // the processed-but-unacked id committed by 0.16 is still filtered
    let dup = ToDeviceMessage {
        id: "01KZ0000000000000000000016".into(),
        sender: ids::user_id(&user).unwrap(),
        sender_device: device.into(),
        event_type: "m.room.encrypted".into(),
        content: json!({}),
    };
    let r = m.receive_to_device(vec![dup]).await.unwrap();
    assert_eq!((r.processed, r.skipped_duplicates), (0, 1));
    assert_eq!(r.ack_ids, ["01KZ0000000000000000000016"]);
}

/// CR-17: the second instance on one store gets `StoreLocked`, not a
/// corrupted database; `destroy` waits for the machine to close.
#[tokio::test]
async fn one_writer_per_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("acc");
    let (user, device) = (ulid("A"), dev("A1"));
    let first = CryptoMachine::open(&user, &device, config(path.clone(), [1; 32]))
        .await
        .unwrap();
    assert!(path.join(LOCK_FILE).exists());

    let second = CryptoMachine::open(&user, &device, config(path.clone(), [1; 32])).await;
    assert_eq!(second.unwrap_err(), CryptoError::StoreLocked);
    assert_eq!(
        CryptoMachine::destroy(&config(path.clone(), [1; 32])).unwrap_err(),
        CryptoError::StoreLocked
    );

    // a clone is the same instance, the lock goes with the last one
    let clone = first.clone();
    drop(first);
    assert_eq!(
        CryptoMachine::open(&user, &device, config(path.clone(), [1; 32]))
            .await
            .unwrap_err(),
        CryptoError::StoreLocked
    );
    let keys = clone.identity_keys();
    drop(clone);

    let again = CryptoMachine::open(&user, &device, config(path.clone(), [1; 32]))
        .await
        .unwrap();
    assert_eq!(again.identity_keys(), keys, "same account after reopening");
    drop(again);

    CryptoMachine::destroy(&config(path.clone(), [1; 32])).unwrap();
    assert!(!path.exists(), "store files removed");
    let fresh = CryptoMachine::open(&user, &device, config(path, [1; 32]))
        .await
        .unwrap();
    assert_ne!(fresh.identity_keys(), keys, "a destroyed store starts a new account");
}

#[tokio::test]
async fn wrong_key_or_account_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let m = CryptoMachine::open(&ulid("A"), &dev("A1"), config(path.clone(), [1; 32]))
        .await
        .unwrap();
    drop(m);
    assert!(matches!(
        CryptoMachine::open(&ulid("A"), &dev("A1"), config(path.clone(), [2; 32])).await,
        Err(CryptoError::Store(_))
    ));
    assert_eq!(
        CryptoMachine::open(&ulid("B"), &dev("B1"), config(path.clone(), [1; 32]))
            .await
            .unwrap_err(),
        CryptoError::StoreMismatch
    );
    assert_eq!(
        CryptoMachine::open("not-a-ulid", &dev("A1"), StoreConfig::Memory)
            .await
            .unwrap_err(),
        CryptoError::InvalidId
    );
    assert!(StoreKey::from_slice(&[0; 31]).is_err());
    assert_eq!(format!("{:?}", StoreKey::new([9; 32])), "StoreKey(<redacted>)");
}

/// Channel members and the replay table survive a restart
#[tokio::test]
async fn channel_state_and_replay_table_persist() {
    let srv = server();
    let dir = tempfile::tempdir().unwrap();
    let mut a = Device::login_sqlite(&srv, "A", "A1", dir.path()).await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    b.send(&dm, &text("x")).await;
    a.sync().await;
    let m = last(&srv, &dm);
    assert!(a.decrypt(&m).await.unwrap().is_clean());

    a.restart().await;
    // no set_channel_members after the restart: loaded from the store
    a.send(&dm, &text("after restart")).await;
    b.sync().await;
    assert_eq!(b.read(&last(&srv, &dm)).await, "after restart");
    let mut replayed = m.clone();
    replayed.id = "01KZREPLAY0000000000000001".into();
    assert!(a.decrypt(&replayed).await.unwrap().is_replay, "replay table persisted");

    // settings round-trip too
    a.m()
        .set_channel_members(
            &dm,
            &[a.auth.user.clone(), b.auth.user.clone()],
            ChannelEncryptionSettings {
                rotation_period_ms: Some(3_600_000),
                rotation_period_msgs: Some(2),
            },
        )
        .await
        .unwrap();
    a.restart().await;
    let s1 = a.encrypt(&dm, &text("1")).await.session_id;
    let s2 = a.encrypt(&dm, &text("2")).await.session_id;
    let s3 = a.encrypt(&dm, &text("3")).await.session_id;
    assert_eq!(s1, s2);
    assert_ne!(s2, s3, "rotation after 2 messages");
}
