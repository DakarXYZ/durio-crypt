//! CR-22: the diagnostic report carries counts and codes, never a secret:
//! checked against every secret and every piece of content a test account
//! has (store key, recovery key, room keys, identity keys, session ids,
//! ciphertext, plaintext, member ids).

mod common;

use common::*;
use matrix_sdk_crypto::decrypt_room_key_export;
use serde_json::Value;
use stoat_crypto::{RequestKind, StoreConfig, StoreKey};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::test]
async fn debug_report_has_no_secrets() {
    let srv = server();
    let dir = tempfile::tempdir().unwrap();
    let store_key = [0x5a; 32];
    let store = StoreConfig::Sqlite {
        path: dir.path().to_path_buf(),
        key: StoreKey::new(store_key),
    };
    let mut a = Device::open(&srv, "A", "A1", store).await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "C", &[&a, &b]).await;
    let recovery_key = a.setup_recovery(None).await;

    let plaintexts = ["the eagle lands at noon", "bring the documents"];
    b.send(&dm, &text(plaintexts[0])).await;
    a.sync().await;
    a.send(&dm, &text(plaintexts[1])).await;
    a.sync().await;
    b.sync().await;
    for m in messages(&srv, &dm) {
        a.decrypt(&m).await.unwrap();
    }
    // failures to show up in the report
    let stranger = Device::login(&srv, "D", "D1").await;
    let mut foreign = last(&srv, &dm);
    foreign.channel = ulid("F");
    assert!(a.decrypt(&foreign).await.is_err());
    a.m()
        .mark_request_failed("01KZFAKE", RequestKind::KeysQuery, 502)
        .await
        .unwrap();

    let report = a.m().debug_report().await.unwrap();
    let json: Value = serde_json::from_str(&report).expect("valid JSON");

    // what it is for
    assert_eq!(json["format"], 1);
    assert_eq!(json["account"]["device_id"], a.auth.device.as_str());
    let rows = json["channels"]["listed"].as_array().unwrap();
    let row = rows
        .iter()
        .find(|r| r["channel_id"] == dm.as_str())
        .expect("the DM is listed");
    assert_eq!(row["members"], 2);
    assert_eq!(row["inbound_sessions"], 2, "B's session and the own copy");
    assert!(json["users"]["tracked"].as_u64().unwrap() >= 2);
    assert!(json["decryption"]["ok"].as_u64().unwrap() >= 2);
    assert_eq!(json["decryption"]["errors"]["channel_mismatch"], 1, "{report}");
    assert_eq!(json["decryption"]["recent_errors"][0]["code"], "channel_mismatch");
    assert_eq!(json["recent_request_failures"][0]["kind"], "keys_query");
    assert_eq!(json["recent_request_failures"][0]["status"], 502);
    assert_eq!(json["backup"]["enabled"], true);
    assert!(
        json["one_time_keys"]["server_counts"]["signed_curve25519"]
            .as_u64()
            .is_some()
    );
    assert!(json["mailbox"]["processed"].as_u64().unwrap() >= 1);

    // what it must never contain
    let mut secrets: Vec<String> = vec![
        hex(&store_key),
        "WlpaWlpaWlpa".into(),
        recovery_key.clone(),
        recovery_key.replace(' ', ""),
        recovery_key[..14].into(),
        b.auth.user.clone(),
        b.auth.device.clone(),
        stranger.auth.user.clone(),
    ];
    for d in [&a, &b] {
        let k = d.m().identity_keys();
        secrets.push(k.curve25519);
        secrets.push(k.ed25519);
    }
    for m in messages(&srv, &dm) {
        let e = &m.encrypted;
        secrets.push(e["session_id"].as_str().unwrap().into());
        secrets.push(e["ciphertext"].as_str().unwrap()[..32].into());
        secrets.push(m.id.clone());
    }
    for p in plaintexts {
        secrets.push(p.into());
        secrets.push(p.split(' ').next_back().unwrap().into());
    }
    // the room keys themselves
    let export = a.m().export_room_keys("x", &[]).await.unwrap();
    for k in decrypt_room_key_export(export.data.as_bytes(), "x").unwrap() {
        secrets.push(k.session_key.to_base64()[..32].into());
        secrets.push(k.session_id.clone());
        secrets.push(k.sender_key.to_base64());
    }
    for s in &secrets {
        assert!(s.len() >= 4, "weak probe {s:?}");
        assert!(!report.contains(s.as_str()), "report leaks {s:?}:\n{report}");
    }
}
