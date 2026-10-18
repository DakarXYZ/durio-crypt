//! Scenarios of the CR-01 spike, re-run through the `CryptoMachine` façade and
//! the backend-faithful fake server (CR-18 scaffolding). SAS, backup and key
//! forwarding scenarios (S3, S6, S8) move here with blocks 3B/3C; until then
//! they live in `spikes/spike-msc/tests/scenarios.rs`.

mod common;

use common::*;
use serde_json::json;
use stoat_crypto::proto::EncryptedEnvelope;
use stoat_crypto::{CryptoError, DecryptError, Trust, Verification};

/// S1/T1 + CR-24: only ciphertext reaches the server; every device of the
/// peer reads; the sender reads its own echo without a replay mark.
#[tokio::test]
async fn s01_dm_roundtrip_and_echo() {
    let srv = server();
    let mut a = Device::login(&srv, "A", "A1").await;
    let mut b1 = Device::login(&srv, "B", "B1").await;
    let mut b2 = Device::login(&srv, "B", "B2").await;
    let dm = channel(&srv, "C", &[&a, &b1, &b2]).await;

    let id = a.send(&dm, &text("привет")).await;
    let stored = last(&srv, &dm);
    assert_eq!(stored.id, id);
    let fields: Vec<&String> = stored.encrypted.as_object().unwrap().keys().collect();
    assert_eq!(fields, ["algorithm", "ciphertext", "device_id", "session_id", "v"]);
    assert!(!stored.encrypted.to_string().contains("привет"));

    sync_all(&mut [&mut b1, &mut b2, &mut a]).await;
    for d in [&b1, &b2] {
        let m = d.decrypt(&stored).await.unwrap();
        assert_eq!(m.payload.content.as_deref(), Some("привет"));
        assert_eq!(m.sender_user, a.auth.user);
        assert_eq!(m.sender_device.as_deref(), Some(a.auth.device.as_str()));
        assert_eq!(m.verification, Verification::Unverified);
        assert!(m.is_clean());
    }
    assert!(b1.received.room_keys.iter().any(|k| k.channel_id == dm));

    let echo = a.decrypt(&stored).await.unwrap();
    assert_eq!(echo.payload.content.as_deref(), Some("привет"));
    assert!(echo.is_clean(), "{echo:?}");
    // history reload: same message again is still clean
    assert!(b1.decrypt(&stored).await.unwrap().is_clean());

    // B answers, A reads
    b2.send(&dm, &text("ответ")).await;
    sync_all(&mut [&mut a, &mut b1]).await;
    assert_eq!(a.read(&last(&srv, &dm)).await, "ответ");
    assert_eq!(b1.read(&last(&srv, &dm)).await, "ответ");
}

/// S4/T4-T5: a member leaving or a device being removed rotates the session;
/// the removed side cannot read what follows. S5/T6: a new member reads only
/// what is sent after joining.
#[tokio::test]
async fn s04_s05_membership_changes() {
    let srv = server();
    let mut a = Device::login(&srv, "A", "A1").await;
    let mut b1 = Device::login(&srv, "B", "B1").await;
    let mut b2 = Device::login(&srv, "B", "B2").await;
    let mut c = Device::login(&srv, "C", "C1").await;
    let group = channel(&srv, "G", &[&a, &b1, &b2, &c]).await;

    a.send(&group, &text("all")).await;
    let first = last(&srv, &group);
    sync_all(&mut [&mut b1, &mut b2, &mut c]).await;
    assert_eq!(c.read(&first).await, "all");

    // C leaves: the server changes membership, A learns the new member list
    let members = [a.auth.user.as_str(), b1.auth.user.as_str()];
    srv.lock().unwrap().channel_set_members(&group, &members);
    a.join(&group, &["A", "B"]).await;
    a.send(&group, &text("without C")).await;
    let second = last(&srv, &group);
    assert_ne!(second.encrypted["session_id"], first.encrypted["session_id"], "rotated");
    sync_all(&mut [&mut b1, &mut b2, &mut c]).await;
    assert_eq!(b2.read(&second).await, "without C");
    assert_eq!(c.decrypt(&second).await.unwrap_err(), DecryptError::MissingRoomKey);

    // B2 is logged out: device list update, rotation, B2 gets nothing new
    srv.lock().unwrap().device_delete(&b2.auth.user, &b2.auth.device);
    a.sync().await;
    a.send(&group, &text("without B2")).await;
    let third = last(&srv, &group);
    assert_ne!(third.encrypted["session_id"], second.encrypted["session_id"]);
    b1.sync().await;
    assert_eq!(b1.read(&third).await, "without B2");
    assert!(
        !a.m()
            .devices(&b1.auth.user)
            .await
            .unwrap()
            .iter()
            .any(|d| d.device_id == b2.auth.device && !d.deleted),
        "removed device is gone or marked deleted"
    );

    // D joins (no device-list event from the backend on join): reads only new
    let mut d = Device::login(&srv, "D", "D1").await;
    let members = [a.auth.user.as_str(), b1.auth.user.as_str(), d.auth.user.as_str()];
    srv.lock().unwrap().channel_set_members(&group, &members);
    a.join(&group, &["A", "B", "D"]).await;
    d.join(&group, &["A", "B", "D"]).await;
    a.send(&group, &text("hello D")).await;
    let fourth = last(&srv, &group);
    assert_eq!(
        fourth.encrypted["session_id"], third.encrypted["session_id"],
        "adding does not rotate"
    );
    sync_all(&mut [&mut d, &mut b1]).await;
    assert_eq!(d.read(&fourth).await, "hello D");
    assert_eq!(d.decrypt(&third).await.unwrap_err(), DecryptError::MissingRoomKey);
}

/// T8/T16/T17 + CR-19: what a malicious server can do is flagged or refused
#[tokio::test]
async fn s07_server_tampering() {
    let srv = server();
    let a = Device::login(&srv, "A", "A1").await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let c = Device::login(&srv, "C", "C1").await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    let other = channel(&srv, "E", &[&a, &b, &c]).await;

    let first_id = a.send(&dm, &text("first")).await;
    let mut reply = text("reply");
    reply.in_reply_to = vec![first_id.clone()];
    a.send(&dm, &reply).await;
    let reply = last(&srv, &dm);
    b.sync().await;
    assert!(b.decrypt(&reply).await.unwrap().is_clean());

    // moved to another channel: the session is looked up per channel
    let mut moved = reply.clone();
    moved.channel = other.clone();
    assert_eq!(b.decrypt(&moved).await.unwrap_err(), DecryptError::MissingRoomKey);

    // author swapped by the server
    let mut forged = reply.clone();
    forged.author = c.auth.user.clone();
    forged.id = "01KZFORGED0000000000000001".into();
    let r = b.decrypt(&forged).await;
    assert!(
        matches!(r, Err(DecryptError::SenderMismatch))
            || r.as_ref().is_ok_and(|m| m.verification == Verification::Mismatch),
        "{r:?}"
    );

    // device hint swapped
    let mut hint = reply.clone();
    hint.encrypted["device_id"] = json!(c.auth.device);
    assert_eq!(b.decrypt(&hint).await.unwrap().verification, Verification::Mismatch);

    // the same ciphertext replayed under another message id
    let mut replayed = reply.clone();
    replayed.id = "01KZREPLAY0000000000000001".into();
    assert!(b.decrypt(&replayed).await.unwrap().is_replay);

    // open `replies` rewritten
    let mut rewired = reply.clone();
    rewired.replies = vec![];
    assert!(b.decrypt(&rewired).await.unwrap().reply_mismatch);

    // an edit, then the server serves the old version again
    let mut edit = text("edited");
    edit.edit_of = Some(first_id.clone());
    edit.edit_seq = 1;
    let new_env = a.encrypt(&dm, &edit).await;
    let original = srv.lock().unwrap().messages(&dm)[0].clone();
    srv.lock()
        .unwrap()
        .message_edit(&a.auth, &dm, &first_id, new_env.to_value())
        .unwrap();
    let edited = srv.lock().unwrap().messages(&dm)[0].clone();
    let shown = b.decrypt(&edited).await.unwrap();
    assert_eq!(shown.payload.content.as_deref(), Some("edited"));
    assert!(shown.is_clean(), "{shown:?}");
    assert!(b.decrypt(&original).await.unwrap().stale_edit, "rollback flagged");
    // an edit carried by another message
    let mut carried = edited.clone();
    carried.id = reply.id.clone();
    let carried = b.decrypt(&carried).await.unwrap();
    assert!(carried.edit_mismatch || carried.is_replay);

    // broken ciphertext, newer envelope versions
    let mut broken = reply.clone();
    let ct = broken.encrypted["ciphertext"].as_str().unwrap().to_owned();
    broken.encrypted["ciphertext"] = json!(format!("{}AAAA", &ct[..ct.len() - 4]));
    assert!(matches!(
        b.decrypt(&broken).await.unwrap_err(),
        DecryptError::Corrupted | DecryptError::MissingRoomKey
    ));
    let mut v2 = reply.clone();
    v2.encrypted["v"] = json!(2);
    assert_eq!(b.decrypt(&v2).await.unwrap_err(), DecryptError::UnsupportedVersion);
    let mut alg = reply.clone();
    alg.encrypted["algorithm"] = json!("m.megolm.v2.aes-sha2");
    assert_eq!(b.decrypt(&alg).await.unwrap_err(), DecryptError::UnknownAlgorithm);
}

/// T12 outcome without the SAS flow (3C): local trust drives the shield
#[tokio::test]
async fn shield_follows_device_trust() {
    let srv = server();
    let mut a = Device::login(&srv, "A", "A1").await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    a.send(&dm, &text("x")).await;
    b.sync().await;
    let m = last(&srv, &dm);
    assert_eq!(b.decrypt(&m).await.unwrap().verification, Verification::Unverified);
    b.m()
        .set_device_trust(&a.auth.user, &a.auth.device, Trust::Verified)
        .await
        .unwrap();
    assert_eq!(b.decrypt(&m).await.unwrap().verification, Verification::Verified);
    let devices = b.m().devices(&a.auth.user).await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].trust, Trust::Verified);
    assert_eq!(
        devices[0].ed25519.as_deref(),
        Some(a.m().identity_keys().ed25519.as_str())
    );

    // blocked devices do not get new room keys
    a.m()
        .set_device_trust(&b.auth.user, &b.auth.device, Trust::Blocked)
        .await
        .unwrap();
    a.m().invalidate_outbound_session(&dm).await.unwrap();
    a.send(&dm, &text("not for you")).await;
    b.sync().await;
    assert_eq!(
        b.decrypt(&last(&srv, &dm)).await.unwrap_err(),
        DecryptError::MissingRoomKey
    );
    a.sync().await;
}

/// S9/T13: one-time keys exhausted → the fallback key; the device tops up
/// to 50 OTKs and replaces a used fallback
#[tokio::test]
async fn s09_otk_exhausted_fallback_then_replenish() {
    let srv = server();
    let a = Device::login(&srv, "A", "A1").await;
    let mut b = Device::login(&srv, "B", "B1").await;
    assert_eq!(srv.lock().unwrap().otk_count(&b.auth.device), 50);
    assert_eq!(srv.lock().unwrap().fallback_used(&b.auth.device), Some(false));
    srv.lock().unwrap().drain_otks(&b.auth.device);

    let dm = channel(&srv, "D", &[&a, &b]).await;
    a.send(&dm, &text("via fallback")).await;
    assert_eq!(srv.lock().unwrap().fallback_used(&b.auth.device), Some(true));
    b.sync().await;
    assert_eq!(b.read(&last(&srv, &dm)).await, "via fallback");
    assert_eq!(srv.lock().unwrap().otk_count(&b.auth.device), 50, "replenished");
}

/// S10: a restart between encrypting and sending never reuses a Megolm index
#[tokio::test]
async fn s10_restart_mid_send_no_index_reuse() {
    let srv = server();
    let dir = tempfile::tempdir().unwrap();
    let mut a = Device::login_sqlite(&srv, "A", "A1", dir.path()).await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    a.send(&dm, &text("one")).await;
    let lost = a.encrypt(&dm, &text("never sent")).await;
    let keys = a.m().identity_keys();

    a.restart().await;
    assert_eq!(a.m().identity_keys(), keys);
    a.send(&dm, &text("two")).await;
    let two = last(&srv, &dm);
    let index = |e: &EncryptedEnvelope| stoat_crypto_index(&e.ciphertext);
    let sent = EncryptedEnvelope::from_value(&two.encrypted).unwrap();
    assert_eq!(sent.session_id, lost.session_id);
    assert!(index(&sent) > index(&lost));
    b.sync().await;
    assert_eq!(b.read(&two).await, "two");
}

/// Megolm message index straight from the ciphertext (version byte, then a
/// protobuf varint field 0x08)
fn stoat_crypto_index(ciphertext: &str) -> u32 {
    let bytes = stoat_crypto::proto::b64::decode(ciphertext).unwrap();
    assert_eq!((bytes[0], bytes[1]), (3, 0x08));
    let (mut value, mut shift) = (0u32, 0);
    for b in &bytes[2..] {
        value |= u32::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    value
}

/// S12/T19: crash after processing the mailbox but before `ack`. After the
/// restart the server delivers the same ids; they are dropped before the
/// library — no Olm errors, no unwedging.
#[tokio::test]
async fn s12_crash_between_processing_and_ack() {
    let srv = server();
    let dir = tempfile::tempdir().unwrap();
    let mut a = Device::login(&srv, "A", "A1").await;
    let mut b = Device::login_sqlite(&srv, "B", "B1", dir.path()).await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    a.send(&dm, &text("before crash")).await;
    let m = last(&srv, &dm);

    b.crash_before_ack = true;
    b.sync().await;
    let pending = srv.lock().unwrap().inbox_len(&b.auth.device);
    assert!(pending > 0, "nothing acknowledged");
    assert_eq!(b.received.undecryptable, 0);

    b.restart().await;
    b.crash_before_ack = false;
    b.received = Default::default();
    b.sync().await;
    assert_eq!(b.received.skipped_duplicates, pending, "redelivered ids dropped");
    assert_eq!(b.received.processed, 0);
    assert_eq!(b.received.undecryptable, 0);
    assert_eq!(srv.lock().unwrap().inbox_len(&b.auth.device), 0);
    assert_eq!(b.read(&m).await, "before crash");
    // no m.dummy / new Olm session towards A
    a.received = Default::default();
    a.sync().await;
    assert_eq!(a.received.processed, 0);
}

/// Duplicates and reordering in one batch (C2 filter inside a batch)
#[tokio::test]
async fn duplicated_and_reordered_mailbox() {
    let srv = server();
    srv.lock().unwrap().faults.duplicate = 1.0;
    srv.lock().unwrap().faults.reorder_window = 4;
    let a = Device::login(&srv, "A", "A1").await;
    let mut b1 = Device::login(&srv, "B", "B1").await;
    let mut b2 = Device::login(&srv, "B", "B2").await;
    let dm = channel(&srv, "D", &[&a, &b1, &b2]).await;
    for i in 0..3 {
        a.send(&dm, &text(&format!("m{i}"))).await;
        a.m().invalidate_outbound_session(&dm).await.unwrap();
    }
    sync_all(&mut [&mut b1, &mut b2]).await;
    for d in [&b1, &b2] {
        assert!(d.received.skipped_duplicates > 0);
        assert_eq!(d.received.undecryptable, 0);
        for m in messages(&srv, &dm) {
            assert!(d.read(&m).await.starts_with('m'));
        }
    }
}

/// `encrypt` before the room key is shared is refused, not a panic
#[tokio::test]
async fn encrypt_requires_prepare_send() {
    let srv = server();
    let a = Device::login(&srv, "A", "A1").await;
    let b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    assert_eq!(
        a.m().encrypt(&dm, &text("x")).await.unwrap_err(),
        CryptoError::RoomKeyNotShared
    );
    assert_eq!(
        a.m().encrypt(&ulid("Z"), &text("x")).await.unwrap_err(),
        CryptoError::UnknownChannel
    );
    let huge = text(&"x".repeat(13_000));
    assert_eq!(
        a.m().encrypt(&dm, &huge).await.unwrap_err(),
        CryptoError::PayloadTooLarge
    );
    a.prepare(&dm).await;
    a.m().encrypt(&dm, &text("x")).await.unwrap();
}

/// Requests a client cannot complete do not wedge the machine
#[tokio::test]
async fn failed_requests_are_retried() {
    let srv = server();
    let a = Device::login(&srv, "A", "A1").await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    srv.lock()
        .unwrap()
        .faults
        .fail_next
        .push(("/e2ee/keys/claim".into(), 502));
    srv.lock()
        .unwrap()
        .faults
        .fail_next
        .push(("/e2ee/to_device/".into(), 502));
    a.send(&dm, &text("eventually")).await;
    b.sync().await;
    assert_eq!(b.read(&last(&srv, &dm)).await, "eventually");
}
