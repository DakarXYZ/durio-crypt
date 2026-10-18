//! CR-16: secrets and plaintext never show in `Debug`, `Display` or error
//! codes of what the host can print or log.

mod common;

use common::*;
use stoat_crypto::{CryptoError, RequestKind, StoreKey, encrypt_attachment};

#[test]
fn store_key_and_attachment_keys_are_redacted() {
    let key = StoreKey::new([0x5a; 32]);
    let shown = format!("{key:?}");
    assert!(
        !shown.contains("90") && !shown.contains("5a") && !shown.contains("Wlpa"),
        "{shown}"
    );

    let (_, file) = encrypt_attachment(b"pixels");
    let shown = format!("{file:?}");
    assert!(!shown.contains(&file.key.k) && !shown.contains(&file.iv), "{shown}");
}

#[tokio::test]
async fn recovery_key_never_in_debug_or_errors() {
    let srv = server();
    let a1 = Device::login(&srv, "A", "A1").await;
    let setup = a1.m().create_recovery(None).await.unwrap();
    let key = setup.recovery_key().unwrap().to_owned();
    let compact = key.replace(' ', "");
    let shown = format!("{setup:?}");
    assert!(!shown.contains(&compact) && !shown.contains(&key[..9]), "{shown}");
    // the version request carries the public key only
    assert!(!setup.request.body.contains(&compact));
    a1.run_setup(&setup, false).await.unwrap();
    // queued secret uploads print without their (encrypted) bodies
    let reqs = a1.m().outgoing_requests().await.unwrap();
    let secrets: Vec<_> = reqs.iter().filter(|r| r.kind == RequestKind::SecretPut).collect();
    assert_eq!(secrets.len(), 3);
    for r in secrets {
        let shown = format!("{r:?}");
        assert!(!shown.contains("ciphertext") && shown.contains("body_len"), "{shown}");
    }

    a1.flush().await;

    // a wrong key: the error says what, never echoes the input
    let a2 = Device::login(&srv, "A", "A2").await;
    let wrong = stoat_crypto::proto::recovery_key::encode(&[3; 32]);
    let e = a2.restore(&wrong).await.unwrap_err();
    assert_eq!(e, CryptoError::WrongRecoveryKey);
    for text in [format!("{e}"), format!("{e:?}"), e.code().to_owned()] {
        assert!(
            !text.contains(&wrong.replace(' ', "")) && !text.contains(&wrong[..9]),
            "{text}"
        );
    }
}

#[tokio::test]
async fn decrypted_message_debug_has_no_text() {
    let srv = server();
    let a = Device::login(&srv, "A", "A1").await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "C", &[&a, &b]).await;
    a.send(&dm, &text("very private words")).await;
    b.sync().await;
    let m = b.decrypt(&last(&srv, &dm)).await.unwrap();
    let shown = format!("{m:?}");
    assert!(!shown.contains("private"), "{shown}");
}
