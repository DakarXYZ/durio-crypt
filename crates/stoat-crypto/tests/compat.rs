//! CR-23: version compatibility (`docs/versioning.md`).
//!
//! * **Store N−1 → N.** `fixtures/stores/v010/` is a SQLite store written by
//!   stoat-crypto 0.1.0 (the first release); every later version must open
//!   it and keep the account, the Megolm sessions, the CR-19 tables, the
//!   channel state, the C2 processed set and the backup state. The snapshot
//!   is frozen: `DUMP_STORE_V010=1` rewrites it and is only for the version
//!   that made it. A new release adds its own snapshot next to it.
//! * **Payload N → N−1.** A payload with fields this version does not know
//!   decrypts and shows; unknown fields are dropped, never an error.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use stoat_crypto::proto::api::ToDeviceMessage;
use stoat_crypto::proto::{EncryptedEnvelope, ids};
use stoat_crypto::{CryptoMachine, IncomingEncryptedMessage, StoreConfig, StoreKey};
use stoat_crypto_fakeserver::StoredMessage;

/// Test store key of the snapshot (no real data is ever in a fixture)
const STORE_KEY: [u8; 32] = [0x42; 32];
const SQLITE: [&str; 3] = [
    "matrix-sdk-crypto.sqlite3",
    "matrix-sdk-crypto.sqlite3-wal",
    "matrix-sdk-crypto.sqlite3-shm",
];

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/stores/v010")
}

fn config(path: &Path) -> StoreConfig {
    StoreConfig::Sqlite {
        path: path.to_path_buf(),
        key: StoreKey::new(STORE_KEY),
    }
}

fn message_json(m: &StoredMessage, plaintext: &str) -> Value {
    json!({
        "id": m.id, "channel": m.channel, "author": m.author, "encrypted": m.encrypted,
        "replies": m.replies, "ts": m.ts, "plaintext": plaintext,
    })
}

fn incoming(m: &Value) -> IncomingEncryptedMessage {
    IncomingEncryptedMessage {
        message_id: m["id"].as_str().unwrap().into(),
        channel_id: m["channel"].as_str().unwrap().into(),
        author: m["author"].as_str().unwrap().into(),
        envelope: EncryptedEnvelope::from_value(&m["encrypted"]).unwrap(),
        replies: serde_json::from_value(m["replies"].clone()).unwrap(),
        timestamp: m["ts"].as_u64().unwrap(),
    }
}

/// Wait until the closed store is checkpointed (the pool closes its
/// connections on the blocking pool after the machine is dropped)
async fn settled(dir: &Path) {
    for _ in 0..50 {
        if !dir.join(SQLITE[1]).exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Write the 0.1.0 snapshot: A (SQLite) in a DM with B — received, sent and
/// edited messages, recovery and backup, one mailbox batch processed but not
/// acknowledged.
async fn write_snapshot() {
    let srv = server();
    let tmp = tempfile::tempdir().unwrap();
    let mut a = Device::open(&srv, "A", "A1", config(tmp.path())).await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    let recovery_version = {
        a.setup_recovery(None).await;
        a.m().backup_status().await.unwrap().version.unwrap()
    };

    b.send(&dm, &text("from B, written by 0.1.0")).await;
    a.sync().await;
    let received = last(&srv, &dm);
    assert!(a.decrypt(&received).await.unwrap().is_clean());

    a.send(&dm, &text("from A, written by 0.1.0")).await;
    b.sync().await;
    let sent = last(&srv, &dm);
    assert!(a.decrypt(&sent).await.unwrap().is_clean());

    let original_id = b.send(&dm, &text("before the edit")).await;
    a.sync().await;
    let original = last(&srv, &dm);
    assert!(a.decrypt(&original).await.unwrap().is_clean());
    let mut edit = text("after the edit");
    edit.edit_of = Some(original_id.clone());
    edit.edit_seq = 1;
    let envelope = b.encrypt(&dm, &edit).await;
    srv.lock()
        .unwrap()
        .message_edit(&b.auth, &dm, &original_id, envelope.to_value())
        .unwrap();
    let edited = last(&srv, &dm);
    assert!(a.decrypt(&edited).await.unwrap().is_clean());

    // a mailbox batch committed but never acknowledged (crash before ack)
    b.m().invalidate_outbound_session(&dm).await.unwrap();
    b.send(&dm, &text("new session, key not acked")).await;
    a.crash_before_ack = true;
    let before = a.received.ack_ids.len();
    a.receive().await;
    let unacked: Vec<String> = a.received.ack_ids[before..].to_vec();
    assert!(!unacked.is_empty());
    let pending = last(&srv, &dm);

    let identity = a.m().identity_keys();
    drop(a);
    settled(tmp.path()).await;

    let out = fixture_dir();
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(out.join("store")).unwrap();
    for name in SQLITE {
        let from = tmp.path().join(name);
        if from.exists() {
            std::fs::copy(&from, out.join("store").join(name)).unwrap();
        }
    }
    // one small file: WAL folded in, free pages dropped (the library turns
    // WAL on again when it opens the store)
    let db = rusqlite::Connection::open(out.join("store").join(SQLITE[0])).unwrap();
    db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE; VACUUM;")
        .unwrap();
    drop(db);
    for name in &SQLITE[1..] {
        let _ = std::fs::remove_file(out.join("store").join(name));
    }
    let case = json!({
        "created_with": format!("stoat-crypto {} (matrix-sdk-crypto 0.19.1, matrix-sdk-sqlite 0.19.1)", env!("CARGO_PKG_VERSION")),
        "note": "Test account on the fake server; store key = 32 bytes 0x42. Only test keys, no real data.",
        "user": ulid("A"),
        "device": dev("A1"),
        "curve25519": identity.curve25519,
        "ed25519": identity.ed25519,
        "channel": dm,
        "members": [ulid("A"), ulid("B")],
        "backup_version": recovery_version,
        "messages": [
            message_json(&received, "from B, written by 0.1.0"),
            message_json(&sent, "from A, written by 0.1.0"),
            message_json(&edited, "after the edit"),
            message_json(&pending, "new session, key not acked"),
        ],
        "original_before_edit": message_json(&original, "before the edit"),
        "unacked_ids": unacked,
    });
    std::fs::write(
        out.join("case.json"),
        serde_json::to_string_pretty(&case).unwrap() + "\n",
    )
    .unwrap();
}

/// Store N−1 (0.1.0) opens in N with everything the core keeps
#[tokio::test]
async fn store_v010_opens_in_current_version() {
    if std::env::var_os("DUMP_STORE_V010").is_some() {
        write_snapshot().await;
    }
    let src = fixture_dir();
    let case: Value = serde_json::from_str(&std::fs::read_to_string(src.join("case.json")).unwrap()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    for name in SQLITE {
        let from = src.join("store").join(name);
        if from.exists() {
            std::fs::copy(&from, tmp.path().join(name)).unwrap();
        }
    }
    let user = case["user"].as_str().unwrap();
    let device = case["device"].as_str().unwrap();
    let m = CryptoMachine::open(user, device, config(tmp.path()))
        .await
        .expect("open the 0.1.0 store");

    // the account
    let keys = m.identity_keys();
    assert_eq!(keys.curve25519, case["curve25519"].as_str().unwrap());
    assert_eq!(keys.ed25519, case["ed25519"].as_str().unwrap());

    // Megolm sessions (received, own, edited), payloads of 0.1.0
    let messages = case["messages"].as_array().unwrap();
    for msg in messages {
        let d = m.decrypt(&incoming(msg)).await.expect("0.1.0 message decrypts");
        assert_eq!(d.payload.content.as_deref(), msg["plaintext"].as_str());
        assert!(d.is_clean(), "{}: {d:?}", msg["plaintext"]);
    }

    // CR-19 tables: the replay table and the edit table survived
    let mut replayed = incoming(&messages[0]);
    replayed.message_id = "01KZREPLAY0000000000000001".into();
    assert!(m.decrypt(&replayed).await.unwrap().is_replay, "replay table");
    let rollback = m.decrypt(&incoming(&case["original_before_edit"])).await.unwrap();
    assert!(rollback.stale_edit, "edit table");

    // C2: the processed-but-unacked ids are still filtered
    let unacked: Vec<String> = serde_json::from_value(case["unacked_ids"].clone()).unwrap();
    let dups = unacked
        .iter()
        .map(|id| ToDeviceMessage {
            id: id.clone(),
            sender: ids::user_id(user).unwrap(),
            sender_device: device.into(),
            event_type: "m.room.encrypted".into(),
            content: json!({}),
        })
        .collect();
    let r = m.receive_to_device(dups).await.unwrap();
    assert_eq!((r.processed, r.skipped_duplicates), (0, unacked.len()));
    assert_eq!(r.ack_ids, unacked);

    // backup and recovery state
    let status = m.backup_status().await.unwrap();
    assert!(
        status.enabled && status.recovery_set_up && !status.outdated,
        "{status:?}"
    );
    assert_eq!(status.version.as_deref(), case["backup_version"].as_str());

    // channel state: no `set_channel_members` needed after the upgrade
    let channel = case["channel"].as_str().unwrap();
    m.prepare_send(channel).await.expect("channel members persisted");
}

/// Payload N → N−1: a newer client adds fields (top level, inside an
/// attachment, nested objects); this version decrypts the message, shows
/// what it knows and drops the rest. A higher `v` is "update the app".
#[tokio::test]
async fn payload_with_unknown_fields_decrypts() {
    let srv = server();
    let a = Device::login(&srv, "A", "A1").await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "C", &[&a, &b]).await;

    let mut future = serde_json::to_value(text("from a newer client")).unwrap();
    future["stoat_future_field"] = json!({ "nested": [1, 2, 3], "flag": true });
    future["reactions_v2"] = json!(["x"]);
    let (_, file) = stoat_crypto::encrypt_attachment(b"pixels");
    let mut attachment = json!({
        "id": "01KFILE0000000000000000001", "name": "a.png", "content_type": "image/png",
        "size": 6, "metadata": { "type": "Image", "width": 1, "height": 1 },
        "file": serde_json::to_value(&file).unwrap(),
        "blurhash": "LEHV6nWB2yk8pyo0adR*.7kCMdnj",
    });
    attachment["file"]["future"] = json!(1);
    future["attachments"] = json!([attachment]);

    a.prepare(&dm).await;
    let envelope = a.m().encrypt_payload_json(&dm, &future.to_string()).await.unwrap();
    let id = srv
        .lock()
        .unwrap()
        .message_send(&a.auth, &dm, envelope.to_value(), vec![])
        .unwrap();
    b.sync().await;
    let m = last(&srv, &dm);
    assert_eq!(m.id, id);
    let d = b.decrypt(&m).await.expect("unknown fields are tolerated");
    assert!(d.is_clean());
    assert_eq!(d.payload.content.as_deref(), Some("from a newer client"));
    assert_eq!(d.payload.attachments.len(), 1);
    assert_eq!(d.payload.attachments[0].file.key.k, file.key.k);

    // a payload version this client does not know: "update the app"
    let mut v2 = serde_json::to_value(text("v2")).unwrap();
    v2["v"] = json!(2);
    let envelope = a.m().encrypt_payload_json(&dm, &v2.to_string()).await.unwrap();
    srv.lock()
        .unwrap()
        .message_send(&a.auth, &dm, envelope.to_value(), vec![])
        .unwrap();
    let e = b.decrypt(&last(&srv, &dm)).await.unwrap_err();
    assert_eq!(e, stoat_crypto::DecryptError::UnsupportedVersion);
    assert_eq!(e.kind(), stoat_crypto::DecryptFailureKind::UpdateApp);
}
