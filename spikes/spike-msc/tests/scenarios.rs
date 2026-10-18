//! CR-01 scenario matrix S1–S12 against `matrix-sdk-crypto` 0.19.1 + fakeserver.

mod common;

use common::*;
use matrix_sdk_crypto::LocalTrust;
use spike_msc::client::{Client, DecryptError, Verification};
use spike_msc::ids;
use spike_msc::payload::PayloadV1;

async fn trust(a: &Client, b: &Client) {
    // mark b's device as locally verified on a (out-of-band, S8 does real SAS)
    let d = a
        .machine
        .get_device(&b.user_id(), b.auth.device.as_str().into(), None)
        .await
        .unwrap()
        .expect("device known");
    d.set_local_trust(LocalTrust::Verified).await.unwrap();
}

// S1 = T1 ------------------------------------------------------------------
#[tokio::test]
async fn s01_dm_roundtrip_only_ciphertext_on_server() {
    let srv = server();
    let mut a = login(&srv, "A", "1").await;
    let mut b = login(&srv, "B", "1").await;
    let dm = channel(&srv, "C", &["A", "B"]);

    a.send(&dm, &text("привет, это секрет")).await.unwrap();
    b.sync().await.unwrap();

    let m = last(&srv, &dm);
    let stored = serde_json::to_string(&m.encrypted).unwrap();
    assert!(!stored.contains("секрет") && !stored.contains("привет"));
    // envelope v1: exactly these fields
    let keys: Vec<_> = m.encrypted.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["algorithm", "ciphertext", "device_id", "session_id", "v"]);

    let d = b.decrypt(&m).await.unwrap();
    assert_eq!(d.payload.content.as_deref(), Some("привет, это секрет"));
    assert_eq!(d.sender_user, ulid("A"));
    assert_eq!(d.sender_device.as_deref(), Some(dev("A1").as_str()));
    assert_eq!(d.verification, Verification::Unverified); // TOFU, not SAS-verified
    assert_eq!(d.message_index, 0);
    assert!(!d.is_replay && !d.stale_edit && !d.reply_mismatch);
    // padding (Q9)
    assert_eq!(serde_json::to_string(&d.payload).unwrap().len() % 256, 0);

    // CR-24: the sender reads its own echo, not flagged as replay
    let echo = a.decrypt(&m).await.unwrap();
    assert_eq!(echo.payload.content.as_deref(), Some("привет, это секрет"));
    assert!(!echo.is_replay);
}

// S2 = T2 ------------------------------------------------------------------
#[tokio::test]
async fn s02_new_device_sees_only_new_messages() {
    let srv = server();
    let mut a1 = login(&srv, "A", "1").await;
    let mut b = login(&srv, "B", "1").await;
    let dm = channel(&srv, "C", &["A", "B"]);
    a1.send(&dm, &text("old")).await.unwrap();
    b.sync().await.unwrap();
    let old = last(&srv, &dm);

    let mut a2 = login(&srv, "A", "2").await;
    a2.sync().await.unwrap();
    assert_eq!(a2.decrypt(&old).await.unwrap_err(), DecryptError::MissingRoomKey);
    // a2 is not verified by a1 → its key request is NOT answered
    sync_all(&mut [&mut a2, &mut a1]).await;
    assert_eq!(a2.decrypt(&old).await.unwrap_err(), DecryptError::MissingRoomKey);

    // B learns about A2 via E2eeDeviceListUpdate → keys/query → shares (no rotation needed)
    b.send(&dm, &text("new from B")).await.unwrap();
    a2.sync().await.unwrap();
    let m = last(&srv, &dm);
    assert_eq!(
        a2.decrypt(&m).await.unwrap().payload.content.as_deref(),
        Some("new from B")
    );

    // A1's own outbound session also reaches A2
    a1.send(&dm, &text("new from A1")).await.unwrap();
    a2.sync().await.unwrap();
    let m = last(&srv, &dm);
    assert_eq!(
        a2.decrypt(&m).await.unwrap().payload.content.as_deref(),
        Some("new from A1")
    );
}

// S3 = T3 ------------------------------------------------------------------
#[tokio::test]
async fn s03_backup_restore_with_recovery_key() {
    let srv = server();
    let mut a1 = login(&srv, "A", "1").await;
    let mut b = login(&srv, "B", "1").await;
    let dm = channel(&srv, "C", &["A", "B"]);
    let recovery_key = a1.enable_backup().await.unwrap();
    // Matrix recovery key: base58, 48 chars in groups of 4 → 59 with spaces
    assert_eq!(recovery_key.replace(' ', "").len(), 48);

    b.send(&dm, &text("from B before A2")).await.unwrap();
    a1.sync().await.unwrap(); // receives room key → backup upload in the same loop
    a1.send(&dm, &text("from A1 before A2")).await.unwrap();
    a1.sync().await.unwrap();
    let msgs = messages(&srv, &dm);

    let mut a2 = login(&srv, "A", "2").await;
    for m in &msgs {
        assert_eq!(a2.decrypt(m).await.unwrap_err(), DecryptError::MissingRoomKey);
    }
    let imported = a2.restore_backup(&recovery_key).await.unwrap();
    assert_eq!(imported, 2);
    for (m, t) in msgs.iter().zip(["from B before A2", "from A1 before A2"]) {
        let d = a2.decrypt(m).await.unwrap();
        assert_eq!(d.payload.content.as_deref(), Some(t));
        // m.megolm_backup.v1: anybody with the public key can inject → never "verified"
        assert_eq!(d.verification, Verification::Unauthenticated, "{t}");
    }
    // wrong key is rejected before touching the store
    let wrong = matrix_sdk_crypto::store::types::BackupDecryptionKey::new().to_base58();
    assert!(a2.restore_backup(&wrong).await.is_err());
}

// S4 = T4/T5 ---------------------------------------------------------------
#[tokio::test]
async fn s04_removed_member_and_removed_device_rotate() {
    let srv = server();
    let mut a = login(&srv, "A", "1").await;
    let mut b1 = login(&srv, "B", "1").await;
    let mut b2 = login(&srv, "B", "2").await;
    let mut c = login(&srv, "C", "1").await;
    let mut d = login(&srv, "D", "1").await;
    let g = channel(&srv, "G", &["A", "B", "C", "D"]);

    a.send(&g, &text("m1 to all")).await.unwrap();
    sync_all(&mut [&mut b1, &mut b2, &mut c, &mut d]).await;
    let m1 = last(&srv, &g);
    for x in [&mut b1, &mut b2, &mut c, &mut d] {
        let r = x.decrypt(&m1).await;
        assert!(r.is_ok(), "{} {:?}", x.auth.device, r.err());
    }

    // T5: C removed from the group
    channel(&srv, "G", &["A", "B", "D"]);
    a.send(&g, &text("m2 without C")).await.unwrap();
    sync_all(&mut [&mut b1, &mut b2, &mut c, &mut d]).await;
    let m2 = last(&srv, &g);
    assert_ne!(
        m1.encrypted["session_id"], m2.encrypted["session_id"],
        "rotation on leave"
    );
    assert_eq!(c.decrypt(&m2).await.unwrap_err(), DecryptError::MissingRoomKey);
    assert!(b2.decrypt(&m2).await.is_ok());

    // T4: B2 logs out (device deleted on the server)
    let b2_dev = b2.auth.device.clone();
    srv.lock().unwrap().device_delete(&ulid("B"), &b2_dev);
    a.send(&g, &text("m3 without B2")).await.unwrap();
    sync_all(&mut [&mut b1, &mut d]).await;
    let m3 = last(&srv, &g);
    assert_ne!(
        m2.encrypted["session_id"], m3.encrypted["session_id"],
        "rotation on device removal"
    );
    assert_eq!(b2.decrypt(&m3).await.unwrap_err(), DecryptError::MissingRoomKey);
    assert_eq!(
        b1.decrypt(&m3).await.unwrap().payload.content.as_deref(),
        Some("m3 without B2")
    );
    assert!(d.decrypt(&m3).await.is_ok());
}

// S5 = T6 ------------------------------------------------------------------
#[tokio::test]
async fn s05_new_member_reads_only_new() {
    let srv = server();
    let mut a = login(&srv, "A", "1").await;
    let mut b = login(&srv, "B", "1").await;
    let mut d = login(&srv, "D", "1").await;
    let g = channel(&srv, "G", &["A", "B"]);
    a.send(&g, &text("before D")).await.unwrap();
    let m1 = last(&srv, &g);

    channel(&srv, "G", &["A", "B", "D"]);
    a.send(&g, &text("after D")).await.unwrap();
    sync_all(&mut [&mut b, &mut d]).await;
    let m2 = last(&srv, &g);
    // adding a member does not rotate: D gets the session from the current index
    assert_eq!(m1.encrypted["session_id"], m2.encrypted["session_id"]);
    assert_eq!(
        d.decrypt(&m2).await.unwrap().payload.content.as_deref(),
        Some("after D")
    );
    assert_eq!(d.decrypt(&m1).await.unwrap_err(), DecryptError::MissingRoomKey);
    assert!(b.decrypt(&m1).await.is_ok());
}

// S6 = T7 ------------------------------------------------------------------
#[tokio::test]
async fn s06_lost_room_key_recovered_from_own_verified_device() {
    let srv = server();
    let mut a = login(&srv, "A", "1").await;
    let mut b1 = login(&srv, "B", "1").await;
    let mut b2 = login(&srv, "B", "2").await;
    let dm = channel(&srv, "C", &["A", "B"]);
    // B's two devices verified each other (S8 shows the real SAS flow)
    sync_all(&mut [&mut b1, &mut b2]).await;
    b1.machine.update_tracked_users([b1.user_id().as_ref()]).await.unwrap();
    b2.machine.update_tracked_users([b2.user_id().as_ref()]).await.unwrap();
    sync_all(&mut [&mut b1, &mut b2]).await;
    trust(&b1, &b2).await;
    trust(&b2, &b1).await;

    // the server loses the m.room_key for B2 (first encrypted to-device to B2)
    let b2_dev = b2.auth.device.clone();
    let mut dropped = false;
    srv.lock().unwrap().faults.drop_filter = Some(Box::new(move |m| {
        if !dropped && m.recipient_device == b2_dev && m.event_type == "m.room.encrypted" {
            dropped = true;
            return true;
        }
        false
    }));
    a.send(&dm, &text("lost key")).await.unwrap();
    srv.lock().unwrap().faults.drop_filter = None;
    b1.sync().await.unwrap();
    b2.sync().await.unwrap();
    let m = last(&srv, &dm);
    assert!(b1.decrypt(&m).await.is_ok());
    // «Ожидание ключа…» → automatic m.room_key_request to own devices
    assert_eq!(b2.decrypt(&m).await.unwrap_err(), DecryptError::MissingRoomKey);
    sync_all(&mut [&mut b2, &mut b1]).await;
    let d = b2.decrypt(&m).await.expect("forwarded key from verified own device");
    assert_eq!(d.payload.content.as_deref(), Some("lost key"));
    assert_eq!(d.verification, Verification::Unauthenticated); // forwarded

    // control: an UNverified own device gets nothing
    let mut b3 = login(&srv, "B", "3").await;
    let b3_dev = b3.auth.device.clone();
    let mut dropped = false;
    srv.lock().unwrap().faults.drop_filter = Some(Box::new(move |m| {
        if !dropped && m.recipient_device == b3_dev && m.event_type == "m.room.encrypted" {
            dropped = true;
            return true;
        }
        false
    }));
    a.send(&dm, &text("lost again")).await.unwrap();
    srv.lock().unwrap().faults.drop_filter = None;
    let m = last(&srv, &dm);
    b3.sync().await.unwrap();
    assert_eq!(b3.decrypt(&m).await.unwrap_err(), DecryptError::MissingRoomKey);
    sync_all(&mut [&mut b3, &mut b1, &mut b2]).await;
    assert_eq!(b3.decrypt(&m).await.unwrap_err(), DecryptError::MissingRoomKey);
}

// S7 = T8/T16/T17 ----------------------------------------------------------
#[tokio::test]
async fn s07_tamper_room_author_replay_edit_reply() {
    let srv = server();
    let mut a = login(&srv, "A", "1").await;
    let mut b = login(&srv, "B", "1").await;
    let _c = login(&srv, "C", "1").await;
    let dm = channel(&srv, "C", &["A", "B"]);
    let other = channel(&srv, "X", &["A", "B", "C"]);
    a.send(&other, &text("prime X")).await.unwrap();
    a.send(&dm, &text("original")).await.unwrap();
    b.sync().await.unwrap();
    let m = last(&srv, &dm);
    assert!(b.decrypt(&m).await.is_ok());

    // (1) server moves the ciphertext into another channel
    let mut moved = m.clone();
    moved.channel = other.clone();
    moved.id = "01KZMOVED0000000000000000A".into();
    let e = b.decrypt(&moved).await.unwrap_err();
    // session lookup is keyed by (room_id, session_id) → the key is simply not found;
    // MismatchedRoom is only reachable if the plaintext room_id differs
    assert_eq!(e, DecryptError::MissingRoomKey);

    // (2) server rewrites the author
    let mut forged = m.clone();
    forged.author = ulid("C");
    let d = b.decrypt(&forged).await.unwrap();
    assert_eq!(d.verification, Verification::Mismatch);

    // (3) device_id hint changed
    let mut hint = m.clone();
    hint.encrypted["device_id"] = serde_json::json!(dev("9"));
    assert_eq!(b.decrypt(&hint).await.unwrap().verification, Verification::Mismatch);

    // (4) T16: same ciphertext re-served under a new message id
    let mut replay = m.clone();
    replay.id = "01KZREPLAY000000000000000A".into();
    assert!(b.decrypt(&replay).await.unwrap().is_replay);
    // reloading history (same id) is fine
    assert!(!b.decrypt(&m).await.unwrap().is_replay);

    // (5) T17: edit rollback
    let mut e2 = text("edit 2");
    e2.edit_of = Some(m.id.clone());
    e2.edit_seq = 2;
    let mut e1 = text("edit 1");
    e1.edit_of = Some(m.id.clone());
    e1.edit_seq = 1;
    a.send(&dm, &e1).await.unwrap();
    let edit1 = last(&srv, &dm);
    a.send(&dm, &e2).await.unwrap();
    let edit2 = last(&srv, &dm);
    b.sync().await.unwrap();
    assert!(!b.decrypt(&edit2).await.unwrap().stale_edit);
    assert!(
        b.decrypt(&edit1).await.unwrap().stale_edit,
        "older edit served after newer"
    );

    // (6) open `replies` do not match the encrypted in_reply_to
    let mut r = text("reply");
    r.in_reply_to = vec![m.id.clone()];
    a.send(&dm, &r).await.unwrap();
    b.sync().await.unwrap();
    let mut reply = last(&srv, &dm);
    assert!(!b.decrypt(&reply).await.unwrap().reply_mismatch);
    reply.replies = vec![edit1.id.clone()];
    assert!(b.decrypt(&reply).await.unwrap().reply_mismatch);

    // (7) ciphertext bit-flip → signature check fails
    let mut flip = m.clone();
    let ct = flip.encrypted["ciphertext"].as_str().unwrap().to_owned();
    let mut bytes: Vec<char> = ct.chars().collect();
    bytes[20] = if bytes[20] == 'A' { 'B' } else { 'A' };
    flip.encrypted["ciphertext"] = serde_json::json!(bytes.into_iter().collect::<String>());
    flip.id = "01KZFLIP00000000000000000A".into();
    assert!(matches!(
        b.decrypt(&flip).await.unwrap_err(),
        DecryptError::Corrupted(_)
    ));

    // (8) unknown envelope version / algorithm → "update the app", no panic
    let mut v2 = m.clone();
    v2.encrypted["v"] = serde_json::json!(2);
    assert_eq!(b.decrypt(&v2).await.unwrap_err(), DecryptError::UnsupportedVersion);
    let mut alg = m.clone();
    alg.encrypted["algorithm"] = serde_json::json!("m.megolm.v2.aes-sha2");
    assert_eq!(b.decrypt(&alg).await.unwrap_err(), DecryptError::UnknownAlgorithm);
}

// S8 = T12 -----------------------------------------------------------------
#[tokio::test]
async fn s08_sas_emoji_both_sides_verified() {
    let srv = server();
    let mut a = login(&srv, "A", "1").await;
    let mut b = login(&srv, "B", "1").await;
    let _dm = channel(&srv, "C", &["A", "B"]);
    a.machine.update_tracked_users([b.user_id().as_ref()]).await.unwrap();
    b.machine.update_tracked_users([a.user_id().as_ref()]).await.unwrap();
    sync_all(&mut [&mut a, &mut b]).await;

    let b_on_a = a
        .machine
        .get_device(&b.user_id(), b.auth.device.as_str().into(), None)
        .await
        .unwrap()
        .unwrap();
    assert!(!b_on_a.is_verified());
    let (req_a, out) = b_on_a.request_verification();
    a.verification_outgoing(out).await.unwrap();
    b.sync().await.unwrap();

    let req_b = b
        .machine
        .get_verification_requests(&a.user_id())
        .pop()
        .expect("request arrived");
    let out = req_b.accept().expect("ready");
    b.verification_outgoing(out).await.unwrap();
    a.sync().await.unwrap();
    assert!(req_a.is_ready());

    let (sas_a, out) = req_a.start_sas().await.unwrap().expect("sas start");
    a.verification_outgoing(out).await.unwrap();
    b.sync().await.unwrap();
    let sas_b = b
        .machine
        .get_verification(&a.user_id(), req_b.flow_id().as_str())
        .and_then(|v| v.sas_v1())
        .expect("sas on b");
    let out = sas_b.accept().expect("accept");
    b.verification_outgoing(out).await.unwrap();
    sync_all(&mut [&mut a, &mut b]).await;

    let ea = sas_a.emoji().expect("emoji a");
    let eb = sas_b.emoji().expect("emoji b");
    let sa: Vec<_> = ea.iter().map(|e| e.symbol).collect();
    let sb: Vec<_> = eb.iter().map(|e| e.symbol).collect();
    assert_eq!(sa, sb, "7 emoji match");
    assert_eq!(sas_a.decimals(), sas_b.decimals());

    let (outs, sig) = sas_a.confirm().await.unwrap();
    assert!(sig.is_none(), "no cross-signing → no signature upload");
    for o in outs {
        a.verification_outgoing(o).await.unwrap();
    }
    b.sync().await.unwrap();
    let (outs, sig) = sas_b.confirm().await.unwrap();
    assert!(sig.is_none());
    for o in outs {
        b.verification_outgoing(o).await.unwrap();
    }
    sync_all(&mut [&mut a, &mut b]).await;
    assert!(sas_a.is_done() && sas_b.is_done());

    let b_on_a = a
        .machine
        .get_device(&b.user_id(), b.auth.device.as_str().into(), None)
        .await
        .unwrap()
        .unwrap();
    let a_on_b = b
        .machine
        .get_device(&a.user_id(), a.auth.device.as_str().into(), None)
        .await
        .unwrap()
        .unwrap();
    assert!(b_on_a.is_verified() && a_on_b.is_verified());
    assert!(b_on_a.is_locally_trusted() && a_on_b.is_locally_trusted());

    // the adapter's shield now reports Verified
    let dm = ulid("C");
    a.send(&dm, &text("after sas")).await.unwrap();
    b.sync().await.unwrap();
    assert_eq!(
        b.decrypt(&last(&srv, &dm)).await.unwrap().verification,
        Verification::Verified
    );
}

// S9 = T13 -----------------------------------------------------------------
#[tokio::test]
async fn s09_otk_exhausted_fallback_then_replenish() {
    let srv = server();
    let mut a = login(&srv, "A", "1").await;
    let mut b = login(&srv, "B", "1").await;
    let dm = channel(&srv, "C", &["A", "B"]);
    let (bu, bd) = (b.auth.user.clone(), b.auth.device.clone());
    assert_eq!(
        srv.lock().unwrap().otk_count(&bu, &bd),
        50,
        "client keeps 50 on the server (C26)"
    );
    srv.lock().unwrap().drain_otks(&bu, &bd);

    a.send(&dm, &text("via fallback")).await.unwrap();
    assert_eq!(srv.lock().unwrap().fallback_used(&bu, &bd), Some(true));
    let r = b.sync().await.unwrap();
    assert!(r.olm_failures.is_empty(), "{:?}", r.olm_failures);
    assert_eq!(
        b.decrypt(&last(&srv, &dm)).await.unwrap().payload.content.as_deref(),
        Some("via fallback")
    );
    // B noticed 0 OTKs → replenished to 50
    b.sync().await.unwrap();
    assert_eq!(srv.lock().unwrap().otk_count(&bu, &bd), 50);
    // matrix-sdk-crypto 0.19 rotates the fallback key by AGE (1 week), not when
    // the server reports it used: the used fallback stays and MUST keep being
    // served by keys/claim until replaced (contract note for BE-04)
    assert_eq!(srv.lock().unwrap().fallback_used(&bu, &bd), Some(true));
}

// S10 ----------------------------------------------------------------------
#[tokio::test]
async fn s10_restart_mid_send_no_index_reuse() {
    let srv = server();
    let dir = tempfile::tempdir().unwrap();
    let key = [7u8; 32];
    let mut a = Client::open_sqlite(&srv, &ulid("A"), &dev("A1"), dir.path(), &key)
        .await
        .unwrap();
    a.sync().await.unwrap();
    let ident = a.machine.identity_keys();
    let mut b = login(&srv, "B", "1").await;
    let dm = channel(&srv, "C", &["A", "B"]);

    a.send(&dm, &text("m0")).await.unwrap(); // index 0
    a.prepare_send(&dm).await.unwrap();
    let lost = a.encrypt(&dm, &text("m1 never sent")).await.unwrap(); // index 1, then crash
    drop(a);

    let mut a = Client::open_sqlite(&srv, &ulid("A"), &dev("A1"), dir.path(), &key)
        .await
        .unwrap();
    assert_eq!(a.machine.identity_keys().curve25519, ident.curve25519);
    a.sync().await.unwrap();
    a.send(&dm, &text("m2 after restart")).await.unwrap();
    b.sync().await.unwrap();
    let msgs = messages(&srv, &dm);
    let d0 = b.decrypt(&msgs[0]).await.unwrap();
    let d2 = b.decrypt(&msgs[1]).await.unwrap();
    assert_eq!(d0.message_index, 0);
    assert_eq!(msgs[1].encrypted["session_id"].as_str().unwrap(), lost.session_id);
    assert_eq!(
        d2.message_index, 2,
        "index 1 was consumed before the crash, never reused"
    );
    assert!(!d2.is_replay);
}

// S11 ----------------------------------------------------------------------
#[tokio::test]
async fn s11_two_processes_same_store_cross_process_lock() {
    use matrix_sdk_common::cross_process_lock::{CrossProcessLockConfig, CrossProcessLockUnobtained};
    use matrix_sdk_sqlite::SqliteCryptoStore;
    let dir = tempfile::tempdir().unwrap();
    let key = [9u8; 32];
    // two independent "processes": two stores (own connection pools) on one file
    let s1 = SqliteCryptoStore::open_with_key(dir.path(), Some(&key)).await.unwrap();
    let s2 = SqliteCryptoStore::open_with_key(dir.path(), Some(&key)).await.unwrap();
    let uid = ids::user_id(&ulid("A"));
    let did = ids::device_id(&dev("A1"));
    let m1 = matrix_sdk_crypto::OlmMachineBuilder::new(&uid, &did)
        .with_crypto_store(s1)
        .build()
        .await
        .unwrap();
    // opening a second machine is NOT prevented by the library
    let m2 = matrix_sdk_crypto::OlmMachineBuilder::new(&uid, &did)
        .with_crypto_store(s2)
        .build()
        .await
        .unwrap();
    assert_eq!(m1.identity_keys().curve25519, m2.identity_keys().curve25519);

    let l1 = m1
        .store()
        .create_store_lock("crypto".into(), CrossProcessLockConfig::multi_process("main"));
    let l2 = m2
        .store()
        .create_store_lock("crypto".into(), CrossProcessLockConfig::multi_process("fcm"));
    let g1 = l1.try_lock_once().await.unwrap().expect("first holder gets it");
    match l2.try_lock_once().await.unwrap() {
        Err(CrossProcessLockUnobtained::Busy) => {}
        other => panic!("second holder must be refused, got {other:?}"),
    }
    drop(g1);
    let g2 = l2
        .spin_lock(Some(2_000))
        .await
        .unwrap()
        .expect("after release second gets it");
    drop(g2);
    // first holder re-acquires: lock reports dirty → caller must reload caches
    let g1 = l1.spin_lock(Some(2_000)).await.unwrap().expect("re-acquired");
    assert!(
        matches!(
            g1,
            matrix_sdk_common::cross_process_lock::CrossProcessLockState::Dirty(_)
        ),
        "dirty after another holder had it"
    );
}

// S12 = T19 ----------------------------------------------------------------
async fn s12_run(dedupe: bool) -> (usize, Vec<String>, usize, bool) {
    let srv = server();
    let dir = tempfile::tempdir().unwrap();
    let key = [3u8; 32];
    let mut a = login(&srv, "A", "1").await;
    let mut b = Client::open_sqlite(&srv, &ulid("B"), &dev("B1"), dir.path(), &key)
        .await
        .unwrap();
    b.sync().await.unwrap();
    let dm = channel(&srv, "C", &["A", "B"]);
    a.send(&dm, &text("before crash")).await.unwrap();
    let m = last(&srv, &dm);

    b.crash_before_ack = true;
    b.sync().await.unwrap();
    let (bu, bd) = (b.auth.user.clone(), b.auth.device.clone());
    assert!(srv.lock().unwrap().inbox_len(&bu, &bd) > 0, "not acked");
    drop(b);

    let mut b = Client::open_sqlite(&srv, &ulid("B"), &dev("B1"), dir.path(), &key)
        .await
        .unwrap();
    b.dedupe = dedupe;
    let r = b.sync().await.unwrap();
    assert_eq!(srv.lock().unwrap().inbox_len(&bu, &bd), 0, "acked after restart");
    let ok = b.decrypt(&m).await.is_ok();
    // did B start a new Olm session towards A ("unwedging" → m.dummy)?
    let a_inbox = srv.lock().unwrap().inbox_len(&a.auth.user, &a.auth.device);
    (r.to_device_skipped_dupes, r.olm_failures, a_inbox, ok)
}

#[tokio::test]
async fn s12_crash_between_processing_and_ack() {
    let (skipped, failures, a_inbox, ok) = s12_run(true).await;
    assert!(
        skipped >= 1,
        "replayed ids dropped by the C2 filter before receive_sync_changes"
    );
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(a_inbox, 0, "no false unwedging (no m.dummy to A)");
    assert!(ok);
}

#[tokio::test]
async fn s12b_control_without_filter_library_detects_replay() {
    // negative control: what OlmMachine does on its own when the same Olm
    // message is fed twice
    let (skipped, failures, a_inbox, ok) = s12_run(false).await;
    assert_eq!(skipped, 0);
    println!("S12b: olm failures without filter = {failures:?}, m.dummy to A = {a_inbox}");
    assert!(ok);
    assert_eq!(
        a_inbox, 0,
        "matrix-sdk-crypto recognises the replayed hash → no unwedging"
    );
}

// payload v1 with attachments (C8) -------------------------------------------
#[tokio::test]
async fn payload_v1_attachment_encrypted_file_v2() {
    use std::io::Read;
    let srv = server();
    let mut a = login(&srv, "A", "1").await;
    let mut b = login(&srv, "B", "1").await;
    let dm = channel(&srv, "C", &["A", "B"]);

    let plain = b"\x89PNG fake image bytes".repeat(100);
    let mut src: &[u8] = &plain[..];
    let mut enc = matrix_sdk_crypto::AttachmentEncryptor::new(&mut src);
    let mut cipher = Vec::new();
    enc.read_to_end(&mut cipher).unwrap();
    let info = enc.finish();
    let file = serde_json::to_value(&info).unwrap();
    // IV: low 64 bits (counter) are zero (C8)
    let iv = file["iv"].as_str().unwrap();
    let iv = matrix_sdk_crypto::vodozemac::base64_decode(iv).unwrap();
    assert_eq!(&iv[8..], &[0u8; 8]);
    assert_eq!(file["v"], "v2");

    let mut p = text("see attached");
    p.attachments = vec![spike_msc::payload::Attachment {
        id: "01KFILE0000000000000000000".into(),
        name: "отпуск.jpg".into(),
        content_type: "image/jpeg".into(),
        size: plain.len() as u64,
        metadata: serde_json::json!({"type": "Image", "width": 1920, "height": 1080}),
        spoiler: true,
        file: file.clone(),
        thumbnail: None,
    }];
    a.send(&dm, &p).await.unwrap();
    b.sync().await.unwrap();
    let d = b.decrypt(&last(&srv, &dm)).await.unwrap();
    let att = &d.payload.attachments[0];
    assert!(att.spoiler);
    let info: matrix_sdk_crypto::MediaEncryptionInfo = serde_json::from_value(att.file.clone()).unwrap();
    let mut csrc: &[u8] = &cipher[..];
    let mut dec = matrix_sdk_crypto::AttachmentDecryptor::new(&mut csrc, info).unwrap();
    let mut out = Vec::new();
    dec.read_to_end(&mut out).unwrap();
    assert_eq!(out, plain);
    let _: PayloadV1 = d.payload.clone();
}
