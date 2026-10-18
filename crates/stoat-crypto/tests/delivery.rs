//! Getting keys to devices when the happy path fails: full mailboxes
//! (`failed`, Q11) and bodies cut to the server limits (BE-21, BE-29).

mod common;

use common::*;
use stoat_crypto::{DecryptError, RequestKind, ServerLimits, Timing, UndeliveredDevice};

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
