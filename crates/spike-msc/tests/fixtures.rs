//! Contract v1 fixtures, generated from what matrix-sdk-crypto 0.19.1 actually
//! sends/accepts through the adapter.
//!
//! `DUMP_FIXTURES=1 cargo test -p spike-msc --test fixtures` rewrites
//! `fixtures/`; without the variable the test only checks that the committed
//! fixtures still parse and validate.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use common::*;
use matrix_sdk_crypto::LocalTrust;
use serde_json::{Value, json};
use spike_msc::fakeserver::validate_envelope_v1;
use spike_msc::ids;
use spike_msc::payload::{Attachment, EnvelopeV1, PayloadV1, Thumbnail};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn write(rel: &str, v: &Value) {
    let p = root().join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let mut s = serde_json::to_string_pretty(v).unwrap();
    s.push('\n');
    std::fs::write(p, s).unwrap();
}

fn file_v2(bytes: &[u8]) -> Value {
    use std::io::Read;
    let mut src = bytes;
    let mut enc = matrix_sdk_crypto::AttachmentEncryptor::new(&mut src);
    let mut out = Vec::new();
    enc.read_to_end(&mut out).unwrap();
    serde_json::to_value(enc.finish()).unwrap()
}

fn full_payload(reply_to: &str) -> PayloadV1 {
    PayloadV1 {
        v: 1,
        content: Some("Смотри фото из отпуска **жирным**".into()),
        attachments: vec![Attachment {
            id: "01KFILE0000000000000000001".into(),
            name: "отпуск.jpg".into(),
            content_type: "image/jpeg".into(),
            size: 123456,
            metadata: json!({ "type": "Image", "width": 1920, "height": 1080 }),
            spoiler: true,
            file: file_v2(b"original image bytes"),
            thumbnail: Some(Thumbnail {
                id: "01KFILE0000000000000000002".into(),
                width: 320,
                height: 180,
                file: file_v2(b"thumbnail bytes"),
            }),
        }],
        client_nonce: "q83vEjRWeJCrze8SNFZ4kA".into(),
        edit_of: None,
        edit_seq: 0,
        in_reply_to: vec![reply_to.to_owned()],
        ts: 1_760_700_000_000,
        pad: String::new(),
    }
}

#[tokio::test]
async fn contract_v1_fixtures() {
    if std::env::var("DUMP_FIXTURES").is_err() {
        check_committed();
        return;
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_default())
        .with_test_writer()
        .try_init();
    let srv = server();
    let mut a = login(&srv, "A", "1").await;
    let mut b1 = login(&srv, "B", "1").await;
    let mut b2 = login(&srv, "B", "2").await;
    let dm = channel(&srv, "C", &["A", "B"]);
    let recovery_key = a.enable_backup().await.unwrap();

    a.send(&dm, &text("первое")).await.unwrap();
    let first = last(&srv, &dm);
    sync_all(&mut [&mut b1, &mut b2, &mut a]).await;

    // full payload v1 (attachments, thumbnail, reply), then an edit of it
    let p = full_payload(&first.id);
    a.send(&dm, &p).await.unwrap();
    let full = last(&srv, &dm);
    let mut edit = text("исправленный текст");
    edit.edit_of = Some(full.id.clone());
    edit.edit_seq = 1;
    a.send(&dm, &edit).await.unwrap();
    let edit_msg = last(&srv, &dm);
    sync_all(&mut [&mut b1, &mut b2, &mut a]).await;

    // exact Megolm plaintext produced by the library: decrypt with vodozemac
    // directly using the exported inbound session
    let room = ids::room_id(&dm);
    let sid = full.encrypted["session_id"].as_str().unwrap();
    let igs = a
        .machine
        .store()
        .get_inbound_group_session(&room, sid)
        .await
        .unwrap()
        .unwrap();
    let exported = igs.export().await;
    let mut vs = matrix_sdk_crypto::vodozemac::megolm::InboundGroupSession::import(
        &exported.session_key,
        matrix_sdk_crypto::vodozemac::megolm::SessionConfig::version_1(),
    );
    let mm = matrix_sdk_crypto::vodozemac::megolm::MegolmMessage::from_base64(
        full.encrypted["ciphertext"].as_str().unwrap(),
    )
    .unwrap();
    let plain = vs.decrypt(&mm).unwrap().plaintext;
    let plaintext: Value = serde_json::from_slice(&plain).unwrap();
    let mm = matrix_sdk_crypto::vodozemac::megolm::MegolmMessage::from_base64(
        edit_msg.encrypted["ciphertext"].as_str().unwrap(),
    )
    .unwrap();
    let edit_plain: Value = serde_json::from_slice(&vs.decrypt(&mm).unwrap().plaintext).unwrap();

    // key request / forward: drop the next room key to B2, B1↔B2 trusted
    b1.machine.update_tracked_users([b1.user_id().as_ref()]).await.unwrap();
    b2.machine.update_tracked_users([b2.user_id().as_ref()]).await.unwrap();
    sync_all(&mut [&mut b1, &mut b2]).await;
    for (x, y) in [(&b1, &b2), (&b2, &b1)] {
        x.machine
            .get_device(&y.user_id(), y.auth.device.as_str().into(), None)
            .await
            .unwrap()
            .unwrap()
            .set_local_trust(LocalTrust::Verified)
            .await
            .unwrap();
    }
    srv.lock().unwrap().channel_set_members(&dm, &[&ulid("A"), &ulid("B")]);
    a.machine.discard_room_key(&room).await.unwrap();
    let b2d = b2.auth.device.clone();
    let mut once = false;
    srv.lock().unwrap().faults.drop_filter = Some(Box::new(move |m| {
        let hit = !once && m.recipient_device == b2d && m.event_type == "m.room.encrypted";
        once |= hit;
        hit
    }));
    a.send(&dm, &text("lost")).await.unwrap();
    srv.lock().unwrap().faults.drop_filter = None;
    let lost = last(&srv, &dm);
    b2.sync().await.unwrap();
    let _ = b2.decrypt(&lost).await;
    sync_all(&mut [&mut b2, &mut b1]).await;
    let r = b2.decrypt(&lost).await;
    let types: Vec<String> = srv
        .lock()
        .unwrap()
        .log
        .iter()
        .filter(|e| e.path.starts_with("/e2ee/to_device/"))
        .map(|e| {
            let r = e.request.clone().unwrap_or_default();
            format!(
                "{} {} -> {}",
                e.path,
                r["type"],
                r["messages"]
                    .as_object()
                    .map(|m| m
                        .iter()
                        .map(|(u, d)| format!("{u}:{:?}", d.as_object().map(|x| x.keys().cloned().collect::<Vec<_>>())))
                        .collect::<Vec<_>>()
                        .join(","))
                    .unwrap_or_default()
            )
        })
        .collect();
    assert!(r.is_ok(), "{r:?} {types:#?}");

    // SAS request + ready (plaintext to-device). B1 must track A first —
    // OlmMachine ignores verification requests from unknown devices.
    b1.machine.update_tracked_users([a.user_id().as_ref()]).await.unwrap();
    b1.sync().await.unwrap();
    let b_on_a = a
        .machine
        .get_device(&b1.user_id(), b1.auth.device.as_str().into(), None)
        .await
        .unwrap()
        .unwrap();
    let (_req, out) = b_on_a.request_verification();
    a.verification_outgoing(out).await.unwrap();
    b1.sync().await.unwrap();
    let rb = b1.machine.get_verification_requests(&a.user_id()).pop().unwrap();
    b1.verification_outgoing(rb.accept().unwrap()).await.unwrap();
    a.sync().await.unwrap();

    // restore on a fresh device (backup version GET + keys GET)
    let mut a2 = login(&srv, "A", "2").await;
    assert!(a2.restore_backup(&recovery_key).await.unwrap() >= 1);

    // ---- dump ----
    let s = srv.lock().unwrap();
    let mut done: BTreeMap<String, ()> = BTreeMap::new();
    for ex in &s.log {
        let base = ex.path.split('?').next().unwrap().to_owned();
        let name = match (ex.method, base.as_str()) {
            ("POST", "/e2ee/keys/upload") => {
                if ex.request.as_ref().unwrap().get("device_keys").is_some() {
                    "keys/upload.initial".to_owned()
                } else {
                    "keys/upload.otk_only".to_owned()
                }
            }
            ("POST", "/e2ee/keys/query") => "keys/query".into(),
            ("POST", "/e2ee/keys/claim") => "keys/claim".into(),
            ("GET", "/e2ee/keys/count") => "keys/count".into(),
            ("PUT", p) if p.starts_with("/e2ee/to_device/") => {
                let t = ex.request.as_ref().unwrap()["type"].as_str().unwrap().to_owned();
                format!("to_device/put.{t}")
            }
            ("GET", "/e2ee/to_device") => {
                if ex.response["messages"].as_array().is_none_or(|a| a.is_empty()) {
                    continue;
                }
                "to_device/get".into()
            }
            ("POST", "/e2ee/to_device/ack") => "to_device/ack".into(),
            ("POST", "/e2ee/backup/version") => "backup/version.create".into(),
            ("GET", "/e2ee/backup/version") => "backup/version.get".into(),
            ("PUT", "/e2ee/backup/keys") => "backup/keys.put".into(),
            ("GET", "/e2ee/backup/keys") => "backup/keys.get".into(),
            _ => continue,
        };
        if done.insert(name.clone(), ()).is_some() {
            continue;
        }
        write(
            &format!("api/{name}.json"),
            &json!({
                "method": ex.method,
                "path": ex.path,
                "request": ex.request,
                "response": ex.response,
            }),
        );
    }
    let mut ws_done = BTreeMap::new();
    for ev in &s.ws_log {
        let t = ev["type"].as_str().unwrap().to_owned();
        if ws_done.insert(t.clone(), ()).is_none() {
            write(&format!("ws/{t}.json"), ev);
        }
    }
    drop(s);
    let env: EnvelopeV1 = serde_json::from_value(full.encrypted.clone()).unwrap();
    write("envelope/valid.json", &full.encrypted);
    let mut bad = full.encrypted.clone();
    bad["sender_key"] = json!("x");
    write("envelope/invalid.unknown_field.json", &bad);
    let mut bad = full.encrypted.clone();
    bad["v"] = json!(2);
    write("envelope/invalid.version.json", &bad);
    let mut bad = full.encrypted.clone();
    bad.as_object_mut().unwrap().remove("ciphertext");
    write("envelope/invalid.missing_ciphertext.json", &bad);
    let mut bad = full.encrypted.clone();
    bad["algorithm"] = json!("m.megolm.v2.aes-sha2");
    write("envelope/invalid.algorithm.json", &bad);
    write("payload/megolm_plaintext.full.json", &plaintext);
    write("payload/megolm_plaintext.edit.json", &edit_plain);
    write(
        "backup/recovery_key.json",
        &json!({ "note": "throwaway key from the spike run; format: base58, 48 chars, groups of 4", "recovery_key": recovery_key }),
    );
    let _ = env;
    check_committed();
}

fn check_committed() {
    let rd =
        |rel: &str| -> Value { serde_json::from_str(&std::fs::read_to_string(root().join(rel)).unwrap()).unwrap() };
    assert!(validate_envelope_v1(&rd("envelope/valid.json")).is_ok());
    for bad in ["unknown_field", "version", "missing_ciphertext", "algorithm"] {
        assert!(
            validate_envelope_v1(&rd(&format!("envelope/invalid.{bad}.json"))).is_err(),
            "{bad}"
        );
    }
    let p = rd("payload/megolm_plaintext.full.json");
    assert_eq!(p["type"], "stoat.message");
    assert!(p["room_id"].as_str().unwrap().ends_with(":stoat.invalid"));
    let payload: PayloadV1 = serde_json::from_value(p["content"].clone()).unwrap();
    assert_eq!(serde_json::to_string(&payload).unwrap().len() % 256, 0);
    assert_eq!(payload.attachments[0].file["v"], "v2");
    let q = rd("api/keys/query.json");
    for k in [
        "device_keys",
        "failures",
        "master_keys",
        "self_signing_keys",
        "user_signing_keys",
    ] {
        assert!(q["response"].get(k).is_some(), "{k}");
    }
    let c = rd("api/keys/count.json");
    assert!(c["response"]["one_time_key_counts"]["signed_curve25519"].is_u64());
    assert!(c["response"]["device_unused_fallback_key_types"].is_array());
}
