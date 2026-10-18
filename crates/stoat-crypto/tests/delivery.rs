//! Getting keys to devices when the happy path fails: key requests to own
//! verified devices (S6, CR-08), full mailboxes (`failed`, Q11) and bodies
//! cut to the server limits (BE-21, BE-29).

mod common;

use common::*;
use serde_json::Value;
use stoat_crypto::{
    DecryptError, DecryptFailureKind, RequestKind, ServerLimits, Timing, UndeliveredDevice, Verification,
};

/// Contents of the `m.room_key_request` messages a device sent
fn key_requests(d: &Device) -> Vec<Value> {
    d.sent("/e2ee/to_device/")
        .into_iter()
        .filter(|b| b["type"] == "m.room_key_request")
        .flat_map(|b| {
            b["messages"]
                .as_object()
                .into_iter()
                .flat_map(|m| m.values())
                .flat_map(|d| d.as_object().into_iter().flat_map(|d| d.values().cloned()))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Drop the next room key (Olm to-device) addressed to `device`
fn lose_next_room_key(d: &Device, device: &str) {
    let device = device.to_owned();
    let mut dropped = false;
    d.server.lock().unwrap().faults.drop_filter = Some(Box::new(move |m| {
        if !dropped && m.recipient_device == device && m.event_type == "m.room.encrypted" {
            dropped = true;
            return true;
        }
        false
    }));
}

async fn verified_pair(b1: &mut Device, b2: &mut Device) {
    sync_all(&mut [b1, b2]).await;
    b1.trust(b2).await;
    b2.trust(b1).await;
}

/// S6/T7: the server lost the room key for B2 → after the debounce B2 asks
/// its own devices; verified B1 forwards; the key is "unauthenticated"; the
/// request is cancelled once answered. An unverified own device (B3) asks
/// nobody and gets nothing.
#[tokio::test]
async fn s06_lost_room_key_recovered_from_own_verified_device() {
    let srv = server();
    let mut a = Device::login(&srv, "A", "A1").await;
    let mut b1 = Device::login(&srv, "B", "B1").await;
    let mut b2 = Device::login(&srv, "B", "B2").await;
    let dm = channel(&srv, "D", &[&a, &b1, &b2]).await;
    verified_pair(&mut b1, &mut b2).await;

    lose_next_room_key(&a, &b2.auth.device);
    a.send(&dm, &text("lost key")).await;
    srv.lock().unwrap().faults.drop_filter = None;
    b1.sync().await;
    b2.sync().await;
    let m = last(&srv, &dm);
    assert_eq!(b1.read(&m).await, "lost key");
    let e = b2.decrypt(&m).await.unwrap_err();
    assert_eq!(e, DecryptError::MissingRoomKey);
    assert_eq!(e.kind(), DecryptFailureKind::WaitingForKey);

    sync_all(&mut [&mut b2, &mut b1]).await;
    let d = b2.decrypt(&m).await.expect("forwarded by B1");
    assert_eq!(d.payload.content.as_deref(), Some("lost key"));
    assert_eq!(d.verification, Verification::Unauthenticated, "forwarded key");
    let reqs = key_requests(&b2);
    assert_eq!(reqs.iter().filter(|r| r["action"] == "request").count(), 1, "{reqs:?}");
    assert_eq!(reqs.iter().filter(|r| r["action"] == "request_cancellation").count(), 1);
    // decrypting again asks nobody again
    b2.decrypt(&m).await.unwrap();
    b2.sync().await;
    assert_eq!(key_requests(&b2).len(), 2);

    // control: B3 verified nobody
    let mut b3 = Device::login(&srv, "B", "B3").await;
    b3.m()
        .set_channel_members(&dm, &[a.auth.user.clone()], Default::default())
        .await
        .unwrap();
    lose_next_room_key(&a, &b3.auth.device);
    a.sync().await;
    a.send(&dm, &text("lost again")).await;
    srv.lock().unwrap().faults.drop_filter = None;
    let m = last(&srv, &dm);
    b3.sync().await;
    assert_eq!(b3.decrypt(&m).await.unwrap_err(), DecryptError::MissingRoomKey);
    sync_all(&mut [&mut b3, &mut b1, &mut b2]).await;
    assert_eq!(b3.decrypt(&m).await.unwrap_err(), DecryptError::MissingRoomKey);
    assert!(key_requests(&b3).is_empty(), "nobody would answer");
}

/// CR-08: a key that arrives within the debounce is never asked for; one
/// that arrives directly after the request went out cancels it
#[tokio::test]
async fn key_requests_are_debounced_and_cancelled() {
    let srv = server();
    let a = Device::login(&srv, "A", "A1").await;
    let mut b1 = Device::login(&srv, "B", "B1").await;
    let mut b2 = Device::login(&srv, "B", "B2").await;
    let dm = channel(&srv, "D", &[&a, &b1, &b2]).await;
    verified_pair(&mut b1, &mut b2).await;
    b2.m().set_timing(Timing::default()).await;

    // the message is seen before the mailbox is read: wait, then the key comes
    a.send(&dm, &text("one")).await;
    let m = last(&srv, &dm);
    assert_eq!(b2.decrypt(&m).await.unwrap_err(), DecryptError::MissingRoomKey);
    let wait = b2.m().wakeup_in_ms().await.expect("a key request is scheduled");
    assert!((1_000..=3_000).contains(&wait), "{wait}");
    let held = b2.m().outgoing_requests().await.unwrap();
    assert!(!held.iter().any(|r| r.body.contains("m.room_key_request")), "held back");
    b2.sync().await;
    assert_eq!(b2.read(&m).await, "one");
    assert_eq!(b2.m().wakeup_in_ms().await, None);
    assert!(key_requests(&b2).is_empty());

    // no debounce: the request goes out, then the key arrives directly
    b2.m().set_timing(fast()).await;
    a.m().invalidate_outbound_session(&dm).await.unwrap();
    a.send(&dm, &text("two")).await;
    let m = last(&srv, &dm);
    assert_eq!(b2.decrypt(&m).await.unwrap_err(), DecryptError::MissingRoomKey);
    assert!(b2.flush().await);
    let reqs = key_requests(&b2);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0]["action"], "request");
    assert_eq!(reqs[0]["body"]["session_id"], m.encrypted["session_id"]);
    b2.receive().await;
    b2.flush().await;
    let reqs = key_requests(&b2);
    assert_eq!(reqs.len(), 2, "{reqs:?}");
    assert_eq!(reqs[1]["action"], "request_cancellation");
    assert_eq!(reqs[1]["request_id"], reqs[0]["request_id"]);
    assert_eq!(b2.read(&m).await, "two");
    sync_all(&mut [&mut b1, &mut b2]).await;
    assert_eq!(key_requests(&b2).len(), 2, "nothing asked again");
}

/// Spike §5.6: a message moved by the server into another channel is
/// reported as a channel mismatch, and no key is requested for it — also
/// when the session was never used for a decrypt here (only its key known)
#[tokio::test]
async fn moved_message_requests_no_key() {
    let srv = server();
    let a = Device::login(&srv, "A", "A1").await;
    let mut b1 = Device::login(&srv, "B", "B1").await;
    let mut b2 = Device::login(&srv, "B", "B2").await;
    let dm = channel(&srv, "D", &[&a, &b1, &b2]).await;
    let other = channel(&srv, "E", &[&a, &b1, &b2]).await;
    verified_pair(&mut b1, &mut b2).await;
    a.send(&dm, &text("here")).await;
    b2.sync().await;

    let mut moved = last(&srv, &dm);
    moved.channel = other.clone();
    let e = b2.decrypt(&moved).await.unwrap_err();
    assert_eq!(e, DecryptError::ChannelMismatch);
    assert_eq!(e.kind(), DecryptFailureKind::Suspicious);
    b2.sync().await;
    assert!(key_requests(&b2).is_empty());
    assert_eq!(b2.m().wakeup_in_ms().await, None);
    // the original still reads, and is then known as a session of `dm`
    assert_eq!(b2.read(&last(&srv, &dm)).await, "here");
    assert_eq!(b2.decrypt(&moved).await.unwrap_err(), DecryptError::ChannelMismatch);
}

/// Q11: a full mailbox (`failed`) gets the same content again with backoff,
/// across a restart; after the last attempt the device is reported
#[tokio::test]
async fn full_mailbox_is_retried_then_reported() {
    let srv = server();
    let dir = tempfile::tempdir().unwrap();
    let mut a = Device::login_sqlite(&srv, "A", "A1", dir.path()).await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    a.sync().await;
    let retry_now = Timing {
        to_device_retry_ms: 0,
        to_device_retry_attempts: 2,
        ..fast()
    };
    a.m().set_timing(retry_now).await;

    srv.lock().unwrap().max_pending_to_device = 0;
    let id = a.send(&dm, &text("late")).await;
    let pending = a.m().undelivered_devices().await;
    assert_eq!(
        pending,
        [UndeliveredDevice {
            user_id: b.auth.user.clone(),
            device_id: b.auth.device.clone(),
            attempts: 1,
            gave_up: false,
        }]
    );
    // the retry survives a restart
    a.restart().await;
    a.m().set_timing(retry_now).await;
    assert_eq!(a.m().undelivered_devices().await, pending);
    srv.lock().unwrap().max_pending_to_device = 10_000;
    assert!(a.flush().await);
    assert!(a.m().undelivered_devices().await.is_empty());
    b.sync().await;
    let m = last(&srv, &dm);
    assert_eq!(m.id, id);
    assert_eq!(b.read(&m).await, "late");

    // still full after every attempt: given up and reported
    srv.lock().unwrap().max_pending_to_device = 0;
    a.m().invalidate_outbound_session(&dm).await.unwrap();
    a.send(&dm, &text("lost")).await;
    for _ in 0..3 {
        a.flush().await;
    }
    let report = a.m().undelivered_devices().await;
    assert_eq!(report.len(), 1);
    assert!(report[0].gave_up, "{report:?}");
    assert_eq!(a.m().wakeup_in_ms().await, None);
    srv.lock().unwrap().max_pending_to_device = 10_000;
    b.sync().await;
    assert_eq!(
        b.decrypt(&last(&srv, &dm)).await.unwrap_err(),
        DecryptError::MissingRoomKey
    );
    // the device gets keys again: no longer reported
    a.m().invalidate_outbound_session(&dm).await.unwrap();
    a.send(&dm, &text("back")).await;
    assert!(a.m().undelivered_devices().await.is_empty());
    b.sync().await;
    assert_eq!(b.read(&last(&srv, &dm)).await, "back");
}

/// BE-21/BE-29: to-device bodies are cut to `max_to_device_batch` messages
/// and `max_request_bytes`; the server refuses nothing
#[tokio::test]
async fn to_device_follows_server_limits() {
    let srv = server();
    let mut a = Device::login(&srv, "A", "A1").await;
    let mut readers = Vec::new();
    for (u, d) in [("B", "B1"), ("B", "B2"), ("C", "C1"), ("C", "C2"), ("E", "E1")] {
        readers.push(Device::login(&srv, u, d).await);
    }
    let group = {
        let mut all: Vec<&Device> = readers.iter().collect();
        all.push(&a);
        channel(&srv, "G", &all).await
    };
    a.sync().await;

    // by count
    srv.lock().unwrap().max_to_device_batch = 2;
    a.m()
        .set_server_limits(ServerLimits {
            max_to_device_batch: 2,
            ..ServerLimits::default()
        })
        .await;
    a.send(&group, &text("by count")).await;
    let by_count = last(&srv, &group);

    // by size: an Olm room key message is about 1 KiB
    srv.lock().unwrap().max_to_device_batch = 1_000;
    srv.lock().unwrap().max_request_bytes = 3_000;
    a.m()
        .set_server_limits(ServerLimits {
            max_to_device_batch: 1_000,
            max_request_bytes: 3_000,
        })
        .await;
    a.m().invalidate_outbound_session(&group).await.unwrap();
    a.send(&group, &text("by size")).await;
    let by_size = last(&srv, &group);
    srv.lock().unwrap().max_request_bytes = stoat_crypto_fakeserver::MAX_REQUEST_BYTES;

    let srv_log = srv.lock().unwrap().log.clone();
    let puts: Vec<_> = srv_log
        .iter()
        .filter(|e| e.device == a.auth.device && e.path.starts_with("/e2ee/to_device/"))
        .collect();
    assert!(puts.iter().all(|e| e.status == 200), "nothing refused");
    let room_key_puts = puts
        .iter()
        .filter(|e| e.request.as_ref().is_some_and(|b| b["type"] == "m.room.encrypted"))
        .count();
    // unsplit it would be one PUT per send
    assert!(room_key_puts >= 5, "split: {room_key_puts}");
    for r in readers.iter_mut() {
        r.sync().await;
        assert_eq!(r.read(&by_count).await, "by count");
        assert_eq!(r.read(&by_size).await, "by size");
    }
}

/// A part that fails is sent again alone; the parts already sent are not
#[tokio::test]
async fn failed_part_is_retried_alone() {
    let srv = server();
    let a = Device::login(&srv, "A", "A1").await;
    let mut readers = Vec::new();
    for (u, d) in [("B", "B1"), ("B", "B2"), ("C", "C1")] {
        readers.push(Device::login(&srv, u, d).await);
    }
    let group = {
        let mut all: Vec<&Device> = readers.iter().collect();
        all.push(&a);
        channel(&srv, "G", &all).await
    };
    a.m()
        .set_server_limits(ServerLimits {
            max_to_device_batch: 2,
            ..ServerLimits::default()
        })
        .await;
    // claim, then the room key in two parts: the first part fails once
    let mut parts = Vec::new();
    for _ in 0..16 {
        let reqs = a.m().prepare_send(&group).await.unwrap();
        if reqs.is_empty() {
            break;
        }
        for r in &reqs {
            if r.kind == RequestKind::ToDevice && parts.is_empty() {
                parts = reqs.iter().map(|r| r.id.clone()).collect();
                a.m().mark_request_failed(&r.id, r.kind, 502).await.unwrap();
                continue;
            }
            a.execute(r).await;
        }
    }
    assert_eq!(parts.len(), 2);
    let sent: Vec<String> = srv
        .lock()
        .unwrap()
        .log
        .iter()
        .filter(|e| e.path.starts_with("/e2ee/to_device/"))
        .map(|e| e.path.rsplit('/').next().unwrap().to_owned())
        .collect();
    assert_eq!(
        sent.iter().filter(|p| **p == parts[0]).count(),
        1,
        "failed part sent once"
    );
    assert_eq!(
        sent.iter().filter(|p| **p == parts[1]).count(),
        1,
        "sent part not repeated"
    );
    let id = a.send(&group, &text("parts")).await;
    for r in readers.iter_mut() {
        r.sync().await;
        let m = last(&srv, &group);
        assert_eq!(m.id, id);
        assert_eq!(r.read(&m).await, "parts");
    }
}
