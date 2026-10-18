//! Scenarios of the CR-01 spike, re-run through the `CryptoMachine` façade and
//! the backend-faithful fake server (CR-18 scaffolding), plus the checks of
//! CR-04…CR-07, CR-10, CR-19 and CR-24. Key forwarding (S6) is in
//! `delivery.rs`; SAS and backup (S3, S8) move here with block 3C — until
//! then they live in `spikes/spike-msc/tests/scenarios.rs`.

mod common;

use common::*;
use serde_json::json;
use stoat_crypto::proto::api::ToDeviceMessage;
use stoat_crypto::proto::{Attachment, EncryptedEnvelope, Thumbnail};
use stoat_crypto::{
    ATTACHMENT_CHUNK, AttachmentEncryptor, AttachmentVerifier, CryptoError, DecryptError, DecryptFailureKind,
    RequestKind, Trust, Verification, WithheldReason, decrypt_attachment, encrypt_attachment,
};

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

    // moved to another channel: the session belongs to `dm` (spike §5.6)
    let mut moved = reply.clone();
    moved.channel = other.clone();
    assert_eq!(b.decrypt(&moved).await.unwrap_err(), DecryptError::ChannelMismatch);

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

    // blocked devices do not get new room keys, and are told so
    a.m()
        .set_device_trust(&b.auth.user, &b.auth.device, Trust::Blocked)
        .await
        .unwrap();
    a.m().invalidate_outbound_session(&dm).await.unwrap();
    a.send(&dm, &text("not for you")).await;
    b.sync().await;
    let e = b.decrypt(&last(&srv, &dm)).await.unwrap_err();
    assert_eq!(e, DecryptError::Withheld(WithheldReason::Blocked));
    assert_eq!(e.kind(), DecryptFailureKind::Withheld(WithheldReason::Blocked));
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

/// CR-24: own other devices get the room keys; the sender reads its own
/// message from the server after a restart (the outbound session is also an
/// inbound one in the store), and neither copy is a replay
#[tokio::test]
async fn cr24_own_devices_and_echo_after_restart() {
    let srv = server();
    let dir = tempfile::tempdir().unwrap();
    let mut a1 = Device::login_sqlite(&srv, "A", "A1", dir.path()).await;
    let mut a2 = Device::login(&srv, "A", "A2").await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "D", &[&a1, &a2, &b]).await;
    sync_all(&mut [&mut a1, &mut a2]).await;

    a1.send(&dm, &text("mine")).await;
    let m = last(&srv, &dm);
    sync_all(&mut [&mut a2, &mut b]).await;
    let other = a2.decrypt(&m).await.unwrap();
    assert_eq!(other.payload.content.as_deref(), Some("mine"));
    assert_eq!(other.sender_device.as_deref(), Some(a1.auth.device.as_str()));
    assert!(other.is_clean(), "{other:?}");
    assert!(a2.received.room_keys.iter().any(|k| k.channel_id == dm));

    a1.restart().await;
    let echo = a1.decrypt(&m).await.unwrap();
    assert_eq!(echo.payload.content.as_deref(), Some("mine"));
    assert!(echo.is_clean(), "{echo:?}");
    assert!(a1.decrypt(&m).await.unwrap().is_clean(), "history reload");
    // A2 answers, A1 reads it
    a2.send(&dm, &text("from A2")).await;
    a1.sync().await;
    assert_eq!(a1.read(&last(&srv, &dm)).await, "from A2");
}

/// CR-04: a crash after the keys were generated but before the upload went
/// out loses nothing — the same keys are uploaded after the restart; the
/// upload keeps its id while it is in flight
#[tokio::test]
async fn crash_before_key_upload_keeps_keys() {
    let srv = server();
    let dir = tempfile::tempdir().unwrap();
    let mut b = Device::open_quiet(&srv, "B", "B1", sqlite(dir.path())).await;
    let first = b.m().outgoing_requests().await.unwrap();
    let upload = first
        .iter()
        .find(|r| r.kind == RequestKind::KeysUpload)
        .unwrap()
        .clone();
    let again = b.m().outgoing_requests().await.unwrap();
    assert!(
        again.iter().any(|r| r.id == upload.id && r.body == upload.body),
        "same id while in flight"
    );
    // the server answers 502: the next upload is new but carries the same keys
    b.m().mark_request_failed(&upload.id, upload.kind, 502).await.unwrap();
    let keys = b.m().identity_keys();

    b.restart().await;
    assert_eq!(b.m().identity_keys(), keys);
    b.sync().await;
    assert_eq!(srv.lock().unwrap().otk_count(&b.auth.device), 50);
    let a = Device::login(&srv, "A", "A1").await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    a.send(&dm, &text("after crash")).await;
    b.sync().await;
    assert_eq!(b.read(&last(&srv, &dm)).await, "after crash");
}

/// CR-05: an Olm message addressed to another device does not decrypt (the
/// recipient keys inside the plaintext bind it), and gives no room key
#[tokio::test]
async fn redirected_olm_message_is_rejected() {
    let srv = server();
    let a = Device::login(&srv, "A", "A1").await;
    let mut b1 = Device::login(&srv, "B", "B1").await;
    let mut b2 = Device::login(&srv, "B", "B2").await;
    let dm = channel(&srv, "D", &[&a, &b1, &b2]).await;
    let b2_dev = b2.auth.device.clone();
    srv.lock().unwrap().faults.drop_filter = Some(Box::new(move |m| m.recipient_device == b2_dev));
    a.send(&dm, &text("for B1 only")).await;
    srv.lock().unwrap().faults.drop_filter = None;

    let stolen: Vec<ToDeviceMessage> = srv
        .lock()
        .unwrap()
        .inbox(&b1.auth.device)
        .into_iter()
        .filter(|m| m.event_type == "m.room.encrypted")
        .map(|m| ToDeviceMessage {
            id: format!("01KZREDIRECT{}", &m.id[12..]),
            sender: stoat_crypto::proto::ids::user_id(&m.sender_user).unwrap(),
            sender_device: m.sender_device,
            event_type: m.event_type,
            content: m.content,
        })
        .collect();
    assert!(!stolen.is_empty());
    let r = b2.m().receive_to_device(stolen).await.unwrap();
    assert_eq!(r.undecryptable, r.processed);
    assert!(r.room_keys.is_empty());
    b1.sync().await;
    b2.sync().await;
    let m = last(&srv, &dm);
    assert_eq!(b1.read(&m).await, "for B1 only");
    assert_eq!(b2.decrypt(&m).await.unwrap_err(), DecryptError::MissingRoomKey);
}

/// CR-07: device keys the server swapped under a known device id are
/// ignored; the old keys stay in use
#[tokio::test]
async fn swapped_device_keys_are_ignored() {
    let srv = server();
    let mut a = Device::login(&srv, "A", "A1").await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let mangler = Device::login(&srv, "M", "M1").await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    a.send(&dm, &text("before")).await;
    let known = a.m().devices(&b.auth.user).await.unwrap();

    // another device's curve key under B1's id (signature no longer matches)
    let foreign = srv
        .lock()
        .unwrap()
        .device_keys(&mangler.auth.user, &mangler.auth.device)
        .unwrap()
        .clone();
    {
        let mut s = srv.lock().unwrap();
        let keys = s.device_keys_mut(&b.auth.user, &b.auth.device).unwrap();
        let key_id = format!("curve25519:{}", b.auth.device);
        let foreign_key = foreign["keys"][format!("curve25519:{}", mangler.auth.device)].clone();
        keys["keys"][key_id] = foreign_key;
        s.device_list_update(&b.auth.user);
    }
    a.sync().await;
    assert_eq!(a.m().devices(&b.auth.user).await.unwrap(), known);
    a.m().invalidate_outbound_session(&dm).await.unwrap();
    a.send(&dm, &text("after")).await;
    b.sync().await;
    assert_eq!(b.read(&last(&srv, &dm)).await, "after");
}

/// CR-07: joining publishes no device-list update. A member who left, added
/// a device while out of contact and came back gets the key on the new
/// device too — the core re-queries members on any membership change.
#[tokio::test]
async fn rejoin_with_a_new_device_is_seen() {
    let srv = server();
    let mut a = Device::login(&srv, "A", "A1").await;
    let b = Device::login(&srv, "B", "B1").await;
    let mut c1 = Device::login(&srv, "C", "C1").await;
    let group = channel(&srv, "G", &[&a, &b, &c1]).await;
    a.send(&group, &text("all")).await;

    // C leaves; while A and C share no channel, C adds a device
    srv.lock()
        .unwrap()
        .channel_set_members(&group, &[&a.auth.user, &b.auth.user]);
    a.join(&group, &["A", "B"]).await;
    let mut c2 = Device::login(&srv, "C", "C2").await;
    a.sync().await;
    assert!(
        !a.m()
            .devices(&c1.auth.user)
            .await
            .unwrap()
            .iter()
            .any(|d| d.device_id == c2.auth.device),
        "A was not told"
    );

    // C comes back
    srv.lock()
        .unwrap()
        .channel_set_members(&group, &[&a.auth.user, &b.auth.user, &c1.auth.user]);
    a.join(&group, &["A", "B", "C"]).await;
    c2.join(&group, &["A", "B", "C"]).await;
    a.send(&group, &text("welcome back")).await;
    sync_all(&mut [&mut c1, &mut c2]).await;
    let m = last(&srv, &group);
    assert_eq!(c1.read(&m).await, "welcome back");
    assert_eq!(c2.read(&m).await, "welcome back");
}

/// CR-19: an edit is an in-place PATCH — it names its own message and has
/// a sequence; anything else is flagged. Rollbacks stay flagged after a
/// restart (the tables are in the store).
#[tokio::test]
async fn cr19_edit_binding() {
    let srv = server();
    let dir = tempfile::tempdir().unwrap();
    let a = Device::login(&srv, "A", "A1").await;
    let mut b = Device::login_sqlite(&srv, "B", "B1", dir.path()).await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    let id = a.send(&dm, &text("v0")).await;
    b.sync().await;
    let v0 = last(&srv, &dm);
    assert!(b.decrypt(&v0).await.unwrap().is_clean());

    let mut edits = Vec::new();
    for seq in 1..=2 {
        let mut e = text(&format!("v{seq}"));
        e.edit_of = Some(id.clone());
        e.edit_seq = seq;
        let env = a.encrypt(&dm, &e).await;
        srv.lock()
            .unwrap()
            .message_edit(&a.auth, &dm, &id, env.to_value())
            .unwrap();
        let shown = b.decrypt(&last(&srv, &dm)).await.unwrap();
        assert!(shown.is_clean(), "{shown:?}");
        edits.push(last(&srv, &dm));
    }
    b.restart().await;
    assert!(b.decrypt(&edits[1]).await.unwrap().is_clean(), "latest, reloaded");
    assert!(b.decrypt(&edits[0]).await.unwrap().stale_edit, "older edit");
    assert!(b.decrypt(&v0).await.unwrap().stale_edit, "original");

    // malformed edits
    for (edit_of, seq) in [
        (Some("01KZOTHER00000000000000000"), 3),
        (Some(id.as_str()), 0),
        (None, 4),
    ] {
        let mut e = text("odd");
        e.edit_of = edit_of.map(str::to_owned);
        e.edit_seq = seq;
        let env = a.encrypt(&dm, &e).await;
        srv.lock()
            .unwrap()
            .message_edit(&a.auth, &dm, &id, env.to_value())
            .unwrap();
        let shown = b.decrypt(&last(&srv, &dm)).await.unwrap();
        assert!(shown.edit_mismatch, "{edit_of:?} {seq}");
        assert!(!shown.is_clean());
    }
}

/// CR-10/T10: a file and its thumbnail travel as separate encrypted blobs;
/// keys and hashes ride in the payload; the reader verifies each blob before
/// a single byte is decrypted, and a swapped blob is refused.
#[tokio::test]
async fn cr10_attachment_with_thumbnail() {
    let srv = server();
    let a = Device::login(&srv, "A", "A1").await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "F", &[&a, &b]).await;
    let photo: Vec<u8> = (0..600_000u32).map(|i| (i % 253) as u8).collect();
    let thumb = b"tiny jpeg".to_vec();

    // sender: encrypt chunk by chunk, upload with `?encrypted=true`, get ids
    let mut enc = AttachmentEncryptor::new();
    let blob: Vec<u8> = photo.chunks(ATTACHMENT_CHUNK).flat_map(|c| enc.update(c)).collect();
    let file = enc.finish();
    let (thumb_blob, thumb_file) = encrypt_attachment(&thumb);
    let mut payload = text("photo");
    payload.attachments.push(Attachment {
        id: "FILE1".into(),
        name: "cat.jpg".into(),
        content_type: "image/jpeg".into(),
        size: photo.len() as u64,
        metadata: json!({ "type": "Image", "width": 800, "height": 600 }),
        spoiler: false,
        file,
        thumbnail: Some(Thumbnail {
            id: "THUMB1".into(),
            width: 80,
            height: 60,
            file: thumb_file,
        }),
    });
    // the open `attachments` of the send request list the thumbnail too (C9)
    assert_eq!(payload.file_ids(), ["FILE1", "THUMB1"]);
    a.send(&dm, &payload).await;
    assert!(!last(&srv, &dm).encrypted.to_string().contains("cat.jpg"));

    // reader: hash pass, then decrypt pass
    b.sync().await;
    let got = b.decrypt(&last(&srv, &dm)).await.unwrap().payload;
    let att = &got.attachments[0];
    assert_eq!(att.name, "cat.jpg");
    let mut v = AttachmentVerifier::new(&att.file).unwrap();
    for c in blob.chunks(ATTACHMENT_CHUNK) {
        v.update(c);
    }
    let mut dec = v.finish().unwrap();
    let out: Vec<u8> = blob.chunks(ATTACHMENT_CHUNK).flat_map(|c| dec.update(c)).collect();
    assert_eq!(out, photo);
    let thumb_file = &att.thumbnail.as_ref().unwrap().file;
    assert_eq!(decrypt_attachment(&thumb_blob, thumb_file).unwrap(), thumb);

    // the server serves another blob under the thumbnail id
    assert_eq!(
        decrypt_attachment(&blob, thumb_file).unwrap_err(),
        CryptoError::AttachmentHashMismatch
    );
}
