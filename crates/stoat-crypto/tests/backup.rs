//! CR-12: key backup, recovery key and secret storage against the fake
//! server (S3/T3 of the spike, through the façade), plus rotation, a backup
//! replaced elsewhere, restarts and a tampering server.

mod common;

use common::*;
use serde_json::json;
use stoat_crypto::proto::api::{paths, secrets};
use stoat_crypto::{CryptoError, DecryptError, RequestKind, Verification};

/// S3/T3: A1 sets up recovery; its keys (own and received) go up in the
/// background. A new device A2 cannot read the history until it unlocks the
/// backup with the recovery key; then it reads everything, marked
/// `Unauthenticated` (anybody with the public key can add to a v1 backup).
#[tokio::test]
async fn s03_backup_restore_with_recovery_key() {
    let srv = server();
    let mut a1 = Device::login(&srv, "A", "A1").await;
    let b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "C", &[&a1, &b]).await;
    let recovery_key = a1.setup_recovery(None).await;
    assert_eq!(recovery_key.len(), 59, "48 characters in groups of 4");

    b.send(&dm, &text("from B before A2")).await;
    a1.sync().await;
    a1.send(&dm, &text("from A1 before A2")).await;
    a1.sync().await;
    let status = a1.m().backup_status().await.unwrap();
    assert!(status.enabled && status.recovery_set_up && !status.outdated);
    assert_eq!((status.keys_total, status.keys_backed_up), (2, 2));
    // the backup holds ciphertext only
    let uploads = a1.sent("/e2ee/backup/keys");
    assert!(!uploads.is_empty());
    assert!(!uploads.iter().any(|u| u.to_string().contains("from B")));
    let secret = a1.sent(&paths::secret(secrets::MEGOLM_BACKUP_V1));
    assert_eq!(secret.len(), 1);
    assert!(secret[0]["encrypted"].as_object().unwrap().len() == 1);

    let msgs = messages(&srv, &dm);
    let mut a2 = Device::login(&srv, "A", "A2").await;
    for m in &msgs {
        assert_eq!(a2.decrypt(m).await.unwrap_err(), DecryptError::MissingRoomKey);
    }
    // a restore before unlocking has no key
    assert_eq!(
        a2.m().restore_backup("{\"rooms\":{}}").await.unwrap_err(),
        CryptoError::NoBackup
    );
    // whitespace is insignificant
    let typed = format!(" {}\n", recovery_key.replace(' ', "  "));
    let p = a2.restore(&typed).await.unwrap();
    assert_eq!((p.total, p.imported, p.failed), (2, 2, 0));
    for (m, t) in msgs.iter().zip(["from B before A2", "from A1 before A2"]) {
        let d = a2.decrypt(m).await.unwrap();
        assert_eq!(d.payload.content.as_deref(), Some(t));
        assert_eq!(d.verification, Verification::Unauthenticated, "{t}");
    }
    // restored keys are not uploaded again; A2's new keys are
    let before = a2.sent("/e2ee/backup/keys").len();
    a2.sync().await;
    assert_eq!(a2.sent("/e2ee/backup/keys").len(), before);
    a2.join(&dm, &["A", "B"]).await;
    a2.send(&dm, &text("from A2")).await;
    a2.sync().await;
    assert_eq!(a2.sent("/e2ee/backup/keys").len(), before + 1);
    let s2 = a2.m().backup_status().await.unwrap();
    assert_eq!(s2.version, status.version);
    assert_eq!(s2.keys_total, s2.keys_backed_up);
}

/// The input field takes the recovery key or the passphrase; a typo is told
/// apart from a wrong key
#[tokio::test]
async fn passphrase_recovery_key_typo_and_wrong_key() {
    let srv = server();
    let mut a1 = Device::login(&srv, "A", "A1").await;
    let b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "C", &[&a1, &b]).await;
    let recovery_key = a1.setup_recovery(Some("correct horse battery staple")).await;
    a1.send(&dm, &text("secret history")).await;
    a1.sync().await;

    let a2 = Device::login(&srv, "A", "A2").await;
    let mut typo: Vec<char> = recovery_key.chars().collect();
    typo[10] = if typo[10] == 'x' { 'y' } else { 'x' };
    let typo: String = typo.into_iter().collect();
    assert_eq!(a2.restore(&typo).await.unwrap_err(), CryptoError::RecoveryKeyTypo);
    assert_eq!(
        a2.restore("wrong horse battery staple").await.unwrap_err(),
        CryptoError::WrongRecoveryKey
    );
    let other = stoat_crypto::proto::recovery_key::encode(&[9; 32]);
    assert_eq!(a2.restore(&other).await.unwrap_err(), CryptoError::WrongRecoveryKey);
    assert_eq!(a2.restore("correct horse battery staple").await.unwrap().imported, 1);
    assert_eq!(a2.read(&last(&srv, &dm)).await, "secret history");
    // the recovery key of a passphrase setup works as well
    let a3 = Device::login(&srv, "A", "A3").await;
    assert_eq!(a3.restore(&recovery_key).await.unwrap().imported, 1);
}

/// Rotation keeps the recovery key and needs MFA; the other device's next
/// upload meets the new version (409), stops uploading and says so; it
/// unlocks the new version with the same recovery key.
#[tokio::test]
async fn rotation_and_backup_replaced_elsewhere() {
    let srv = server();
    let mut a1 = Device::login(&srv, "A", "A1").await;
    let b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "C", &[&a1, &b]).await;
    let recovery_key = a1.setup_recovery(None).await;
    let mut a2 = Device::login(&srv, "A", "A2").await;
    a2.restore(&recovery_key).await.unwrap();
    let v1 = a1.m().backup_status().await.unwrap().version.unwrap();

    let setup = a1.m().rotate_backup().await.unwrap();
    assert!(setup.recovery_key().is_none());
    assert_eq!(a1.run_setup(&setup, false).await.unwrap_err(), CryptoError::MfaRequired);
    a1.run_setup(&setup, true).await.unwrap();
    a1.sync().await;
    let v2 = a1.m().backup_status().await.unwrap().version.unwrap();
    assert_ne!(v1, v2);
    // only the backup secret changes, the key description stays
    assert_eq!(a1.sent(&paths::secret(secrets::DEFAULT_KEY)).len(), 1);
    assert_eq!(a1.sent(&paths::secret(secrets::MEGOLM_BACKUP_V1)).len(), 2);

    b.send(&dm, &text("after rotation")).await;
    sync_all(&mut [&mut a1, &mut a2]).await;
    assert!(a2.take_errors().contains(&CryptoError::BackupVersionChanged));
    let s = a2.m().backup_status().await.unwrap();
    assert!(s.outdated && !s.enabled);
    // nothing more goes to the old version
    let before = a2.sent("/e2ee/backup/keys").len();
    a2.sync().await;
    assert_eq!(a2.sent("/e2ee/backup/keys").len(), before);

    let a3 = Device::login(&srv, "A", "A3").await;
    assert_eq!(a3.restore(&recovery_key).await.unwrap().imported, 1);
    assert_eq!(a3.read(&last(&srv, &dm)).await, "after rotation");
    a2.restore(&recovery_key).await.unwrap();
    let s = a2.m().backup_status().await.unwrap();
    assert_eq!(
        (s.version.as_deref(), s.outdated, s.enabled),
        (Some(v2.as_str()), false, true)
    );
}

/// A new recovery over an existing backup needs MFA; without it nothing on
/// the server changes and the old recovery key keeps working
#[tokio::test]
async fn reset_recovery_needs_mfa() {
    let srv = server();
    let mut a1 = Device::login(&srv, "A", "A1").await;
    let b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "C", &[&a1, &b]).await;
    let old_key = a1.setup_recovery(None).await;
    a1.send(&dm, &text("x")).await;
    a1.sync().await;

    let setup = a1.m().create_recovery(None).await.unwrap();
    assert_eq!(a1.run_setup(&setup, false).await.unwrap_err(), CryptoError::MfaRequired);
    a1.sync().await;
    let a2 = Device::login(&srv, "A", "A2").await;
    assert_eq!(a2.restore(&old_key).await.unwrap().imported, 1);

    a1.run_setup(&setup, true).await.unwrap();
    a1.sync().await;
    let new_key = setup.recovery_key().unwrap();
    assert_ne!(new_key, old_key);
    let a3 = Device::login(&srv, "A", "A3").await;
    assert_eq!(a3.restore(&old_key).await.unwrap_err(), CryptoError::WrongRecoveryKey);
    // the new backup got every key again
    assert_eq!(a3.restore(new_key).await.unwrap().imported, 1);
}

/// Restarts: the backup stays on; secrets the server did not confirm before
/// a crash go up after the restart
#[tokio::test]
async fn backup_and_pending_secrets_survive_restart() {
    let srv = server();
    let dir = tempfile::tempdir().unwrap();
    let mut a1 = Device::login_sqlite(&srv, "A", "A1", dir.path()).await;
    let b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "C", &[&a1, &b]).await;

    let setup = a1.m().create_recovery(None).await.unwrap();
    // the secret PUTs fail: the app is killed before they succeed
    srv.lock()
        .unwrap()
        .faults
        .fail_next
        .extend((0..3).map(|_| ("/e2ee/secrets/".to_owned(), 503)));
    a1.run_setup(&setup, false).await.unwrap();
    a1.flush().await;
    assert!(a1.sent("/e2ee/secrets/").is_empty());
    a1.restart().await;
    a1.sync().await;
    assert_eq!(a1.sent("/e2ee/secrets/").len(), 3);
    let pending: Vec<_> = a1
        .m()
        .outgoing_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.kind == RequestKind::SecretPut)
        .collect();
    assert!(pending.is_empty());

    a1.send(&dm, &text("after restart")).await;
    a1.sync().await;
    let s = a1.m().backup_status().await.unwrap();
    assert!(s.enabled);
    assert_eq!(s.keys_total, s.keys_backed_up);
    let a2 = Device::login(&srv, "A", "A2").await;
    assert_eq!(a2.restore(setup.recovery_key().unwrap()).await.unwrap().imported, 1);
}

/// The server swaps the backup for one of its own or corrupts a secret:
/// the device refuses, nothing is enabled
#[tokio::test]
async fn tampered_backup_or_secrets_are_refused() {
    let srv = server();
    let mut a1 = Device::login(&srv, "A", "A1").await;
    let recovery_key = a1.setup_recovery(None).await;
    let a2 = Device::login(&srv, "A", "A2").await;

    let original = srv.lock().unwrap().backup_auth_data_mut(&a1.auth.user).unwrap().clone();
    srv.lock().unwrap().backup_auth_data_mut(&a1.auth.user).unwrap()["public_key"] =
        json!("hrj6/DOX12YMdiapgpo0+ow8OXZDKV11dnYUwuQ+DnE");
    assert_eq!(
        a2.restore(&recovery_key).await.unwrap_err(),
        CryptoError::BackupKeyMismatch
    );
    assert!(!a2.m().backup_status().await.unwrap().enabled);
    *srv.lock().unwrap().backup_auth_data_mut(&a1.auth.user).unwrap() = original;

    {
        let mut s = srv.lock().unwrap();
        let secret = s.secret_mut(&a1.auth.user, secrets::MEGOLM_BACKUP_V1).unwrap();
        let data = secret["encrypted"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        data["ciphertext"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }
    assert_eq!(
        a2.restore(&recovery_key).await.unwrap_err(),
        CryptoError::InvalidRecoveryData
    );
    assert!(!a2.m().backup_status().await.unwrap().enabled);
}
