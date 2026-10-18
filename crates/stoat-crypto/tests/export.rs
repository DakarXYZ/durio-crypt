//! CR-21: room keys to a password-protected file (Matrix "Megolm session
//! export") and back, through the façade.

mod common;

use common::*;
use stoat_crypto::{CryptoError, DecryptError, Verification};

/// A1 reads a DM, exports its keys; a new device A2 (fresh SQLite store, no
/// backup) imports the file and reads the history — as `Unauthenticated`
#[tokio::test]
async fn export_import_into_fresh_store() {
    let srv = server();
    let mut a1 = Device::login(&srv, "A", "A1").await;
    let b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "C", &[&a1, &b]).await;
    let other = channel(&srv, "E", &[&a1, &b]).await;
    b.send(&dm, &text("one")).await;
    a1.sync().await;
    a1.send(&dm, &text("two")).await;
    b.send(&other, &text("elsewhere")).await;
    a1.sync().await;

    let all = a1.m().export_room_keys("correct horse", &[]).await.unwrap();
    assert_eq!(all.sessions, 3, "B's two sessions and A1's own");
    assert!(all.data.starts_with("-----BEGIN MEGOLM SESSION DATA-----"));
    for secret in ["one", "two", "elsewhere"] {
        assert!(!all.data.contains(secret));
    }
    let only_dm = a1
        .m()
        .export_room_keys("correct horse", std::slice::from_ref(&dm))
        .await
        .unwrap();
    assert_eq!(only_dm.sessions, 2);
    assert_eq!(
        a1.m().export_room_keys("", &[]).await.unwrap_err(),
        CryptoError::PassphraseRequired
    );

    let dir = tempfile::tempdir().unwrap();
    let mut a2 = Device::login_sqlite(&srv, "A", "A2", dir.path()).await;
    let msgs = messages(&srv, &dm);
    for m in &msgs {
        assert_eq!(a2.decrypt(m).await.unwrap_err(), DecryptError::MissingRoomKey);
    }
    let r = a2.m().import_room_keys(&only_dm.data, "correct horse").await.unwrap();
    assert_eq!((r.total, r.imported, r.skipped), (2, 2, 0));
    assert_eq!(r.room_keys.len(), 2);
    assert!(r.room_keys.iter().all(|k| k.channel_id == dm));

    // survives a restart: the keys are in the store
    a2.restart().await;
    for (m, t) in msgs.iter().zip(["one", "two"]) {
        let d = a2.decrypt(m).await.unwrap();
        assert_eq!(d.payload.content.as_deref(), Some(t));
        // anybody can write a key file: never better than Unauthenticated
        assert_eq!(d.verification, Verification::Unauthenticated, "{t}");
    }
    // the other channel was not in the file
    let elsewhere = last(&srv, &other);
    assert_eq!(a2.decrypt(&elsewhere).await.unwrap_err(), DecryptError::MissingRoomKey);

    // importing again changes nothing
    let again = a2.m().import_room_keys(&only_dm.data, "correct horse").await.unwrap();
    assert_eq!((again.total, again.imported), (2, 0));
    a2.sync().await;
}

/// An import never makes a key worse: A1 importing its own export keeps the
/// directly received (authenticated) sessions
#[tokio::test]
async fn import_does_not_downgrade_known_sessions() {
    let srv = server();
    let mut a = Device::login(&srv, "A", "A1").await;
    let b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "C", &[&a, &b]).await;
    b.send(&dm, &text("direct")).await;
    a.sync().await;
    let m = last(&srv, &dm);
    assert_eq!(a.decrypt(&m).await.unwrap().verification, Verification::Unverified);

    let file = a.m().export_room_keys("pw", &[]).await.unwrap();
    let r = a.m().import_room_keys(&file.data, "pw").await.unwrap();
    assert_eq!(r.imported, 0);
    assert_eq!(a.decrypt(&m).await.unwrap().verification, Verification::Unverified);
}

#[tokio::test]
async fn wrong_passphrase_or_broken_file() {
    let srv = server();
    let mut a = Device::login(&srv, "A", "A1").await;
    let b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "C", &[&a, &b]).await;
    b.send(&dm, &text("x")).await;
    a.sync().await;
    let file = a.m().export_room_keys("right", &[]).await.unwrap().data;
    let fresh = Device::login(&srv, "A", "A2").await;
    let m = fresh.m();

    assert_eq!(
        m.import_room_keys(&file, "wrong").await.unwrap_err(),
        CryptoError::WrongPassphrase
    );
    assert_eq!(
        m.import_room_keys(&file, "").await.unwrap_err(),
        CryptoError::WrongPassphrase
    );

    // a flipped character in the body: the MAC does not match
    let lines: Vec<&str> = file.lines().collect();
    let body = lines[1];
    let i = body.len() / 2;
    let flipped = if &body[i..=i] == "A" { "B" } else { "A" };
    let tampered = format!(
        "{}\n{}{}{}\n{}",
        lines[0],
        &body[..i],
        flipped,
        &body[i + 1..],
        lines[2]
    );
    assert_eq!(
        m.import_room_keys(&tampered, "right").await.unwrap_err(),
        CryptoError::WrongPassphrase
    );

    // not a key file at all, cut off, or cut short
    let cut_footer = file.rsplit_once('\n').unwrap().0.to_owned();
    let cut_short = format!("{}\n{}\n{}", lines[0], &body[..40], lines[2]);
    for broken in ["", "hello", &cut_footer, &cut_short, &file.replace("MEGOLM", "OLM")] {
        assert_eq!(
            m.import_room_keys(broken, "right").await.unwrap_err(),
            CryptoError::InvalidKeyFile,
            "{broken:.60}"
        );
    }

    // over the 64 MiB cap: refused before anything is decoded (review O-8)
    let huge = format!(
        "{}
{}{}",
        lines[0],
        "A".repeat(stoat_crypto::proto::key_export::MAX_FILE_LEN),
        &file[lines[0].len()..]
    );
    assert_eq!(
        m.import_room_keys(&huge, "right").await.unwrap_err(),
        CryptoError::InvalidKeyFile
    );

    // nothing was imported by any of these
    assert_eq!(
        fresh.decrypt(&last(&srv, &dm)).await.unwrap_err(),
        DecryptError::MissingRoomKey
    );
    let ok = m.import_room_keys(&file, "right").await.unwrap();
    assert_eq!(ok.imported, 1);
    assert_eq!(fresh.read(&last(&srv, &dm)).await, "x");
}
