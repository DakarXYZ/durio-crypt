//! CR-15 scenarios against a live backend (`scripts/testkit-backend.sh`).
//! Ignored by default; `--run-ignored only` with `STOAT_API` / `STOAT_WS` /
//! `STOAT_AUTUMN` set runs them. Fresh users per scenario.
#![allow(clippy::print_stderr)]

use std::time::Duration;

use rand::RngCore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use stoat_crypto::proto::api::{self, paths, secrets};
use stoat_crypto::proto::{Attachment, MessagePayload, Thumbnail};
use stoat_crypto::{
    AttachmentEncryptor, AttachmentVerifier, CryptoError, DecryptError, RecoverySecrets, SasState, Trust, Verification,
    encrypt_attachment,
};
use stoat_crypto_testkit::{Device, Evidence, Stack, payload_text, settle};

macro_rules! stack {
    () => {
        match Stack::connect().await {
            Some(s) => s,
            None => {
                eprintln!("STOAT_API not set: skipped");
                return;
            }
        }
    };
}

fn marker() -> String {
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    format!("tk{}", hex(&b))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn last(messages: &[Value]) -> &Value {
    messages.last().expect("a message")
}

/// The whole scenario has a deadline: a hang is a failure, not a stuck CI job
async fn deadline<F: std::future::Future<Output = ()>>(f: F) {
    tokio::time::timeout(Duration::from_secs(300), f)
        .await
        .expect("scenario timed out");
}

/// T1: A and B, one device each, DM: both read, the server stores ciphertext
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t01_dm_send_receive() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        a.befriend(&b).await.unwrap();
        let ch = a.encrypted_dm(&b).await.unwrap();
        let (mut da, mut db) = (Device::open(&a).await, Device::open(&b).await);
        da.refresh_members(&ch).await;
        db.refresh_members(&ch).await;

        let m = marker();
        da.send_text(&ch, &format!("{m} hello bob")).await;
        settle(&mut [&mut da, &mut db]).await;
        let msgs = db.messages(&ch).await;
        let msg = last(&msgs);
        assert_eq!(db.read(msg).await, format!("{m} hello bob"));
        // what the server keeps and serves: envelope + placeholder, never the text
        assert!(!msg.to_string().contains(&m), "plaintext on the wire: {msg}");
        assert_eq!(msg["encrypted"]["device_id"], da.device());
        let d = db.decrypt(msg).await.unwrap();
        assert_eq!(
            (d.sender_user.as_str(), d.verification),
            (a.user_id.as_str(), Verification::Unverified)
        );
        assert!(d.is_clean());

        db.send_text(&ch, &format!("{m} hi alice")).await;
        settle(&mut [&mut da, &mut db]).await;
        assert_eq!(
            da.read_all(&ch).await,
            [format!("{m} hello bob"), format!("{m} hi alice")]
        );
        let mut ev = Evidence::default();
        ev.message(&ch, &m);
        ev.save(&s.config, "t01_dm_send_receive");
    })
    .await;
}

/// T2/T7: a new own device cannot read old history; after the two own devices
/// trust each other the key is requested and forwarded; new messages of the
/// other user reach the new device directly
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t02_new_device_and_key_forwarding() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        a.befriend(&b).await.unwrap();
        let ch = a.encrypted_dm(&b).await.unwrap();
        let (mut a1, mut b1) = (Device::open(&a).await, Device::open(&b).await);
        a1.refresh_members(&ch).await;
        b1.refresh_members(&ch).await;
        let m = marker();
        a1.send_text(&ch, &format!("{m} before")).await;
        settle(&mut [&mut a1, &mut b1]).await;

        let mut a2 = Device::open(&a.new_device().await.unwrap()).await;
        a2.refresh_members(&ch).await;
        settle(&mut [&mut a1, &mut b1, &mut a2]).await;
        let old = last(&a2.messages(&ch).await).clone();
        assert_eq!(a2.decrypt(&old).await.unwrap_err(), DecryptError::MissingRoomKey);

        // both own devices verified (SAS is t05): A2 asks A1, A1 forwards
        a1.machine
            .set_device_trust(a2.user(), a2.device(), Trust::Verified)
            .await
            .unwrap();
        a2.machine
            .set_device_trust(a1.user(), a1.device(), Trust::Verified)
            .await
            .unwrap();
        assert_eq!(a2.decrypt(&old).await.unwrap_err(), DecryptError::MissingRoomKey);
        settle(&mut [&mut a2, &mut a1]).await;
        a2.sync().await;
        assert!(!a2.received.room_keys.is_empty(), "no forwarded key arrived");
        let d = a2.decrypt(&old).await.unwrap();
        assert_eq!(d.payload.content.as_deref(), Some(format!("{m} before").as_str()));
        assert_eq!(d.verification, Verification::Unauthenticated);

        // B learned A2 from E2eeDeviceListUpdate: its next message is readable on A2
        b1.send_text(&ch, &format!("{m} after")).await;
        settle(&mut [&mut b1, &mut a1, &mut a2]).await;
        assert_eq!(a2.read(last(&a2.messages(&ch).await)).await, format!("{m} after"));
        let mut ev = Evidence::default();
        ev.message(&ch, &m);
        ev.save(&s.config, "t02_new_device_and_key_forwarding");
    })
    .await;
}

/// T5: group of three, C removed: the key rotates, C cannot read new messages
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t05_group_member_leave_rotates() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        let c = s.register("carol").await.unwrap();
        a.befriend(&b).await.unwrap();
        a.befriend(&c).await.unwrap();
        let g = a.encrypted_group("testkit", &[&b, &c]).await.unwrap();
        let (mut da, mut db, mut dc) = (Device::open(&a).await, Device::open(&b).await, Device::open(&c).await);
        for d in [&mut da, &mut db, &mut dc] {
            d.refresh_members(&g).await;
        }
        let m = marker();
        da.send_text(&g, &format!("{m} one")).await;
        settle(&mut [&mut da, &mut db, &mut dc]).await;
        let first = last(&dc.messages(&g).await).clone();
        assert_eq!(dc.read(&first).await, format!("{m} one"));
        assert_eq!(db.read(&first).await, format!("{m} one"));

        a.remove_member(&g, &c).await.unwrap();
        da.refresh_members(&g).await;
        db.refresh_members(&g).await;
        da.send_text(&g, &format!("{m} two")).await;
        settle(&mut [&mut da, &mut db, &mut dc]).await;
        let second = last(&db.messages(&g).await).clone();
        assert_eq!(db.read(&second).await, format!("{m} two"));
        assert_ne!(
            second["encrypted"]["session_id"], first["encrypted"]["session_id"],
            "no rotation after a member left"
        );
        // C may not even fetch the channel; with the envelope it still has no key
        assert!(c.http().get(&format!("/channels/{g}/messages")).await.is_err());
        assert_eq!(dc.decrypt(&second).await.unwrap_err(), DecryptError::MissingRoomKey);
        let mut ev = Evidence::default();
        ev.message(&g, &m);
        ev.save(&s.config, "t05_group_member_leave_rotates");
    })
    .await;
}

async fn recovery_secrets(d: &Device) -> RecoverySecrets {
    let get = |p: String| {
        let http = d.http.clone();
        async move { http.call("GET", &p, None).await.unwrap().body }
    };
    let default_key = get(paths::secret(secrets::DEFAULT_KEY)).await;
    let id = serde_json::from_str::<Value>(&default_key).unwrap()["key"]
        .as_str()
        .unwrap()
        .to_owned();
    RecoverySecrets {
        key_description: get(paths::secret(&secrets::key(&id))).await,
        backup_secret: get(paths::secret(secrets::MEGOLM_BACKUP_V1)).await,
        backup_version: get(paths::BACKUP_VERSION.to_owned()).await,
        default_key,
    }
}

/// T3: backup set up on A1, history restored on a new device with the
/// recovery key; a second backup version needs an MFA ticket; the restored
/// device notices the replaced version
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t03_backup_restore_and_mfa() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        a.befriend(&b).await.unwrap();
        let ch = a.encrypted_dm(&b).await.unwrap();
        let (mut a1, mut b1) = (Device::open(&a).await, Device::open(&b).await);
        a1.refresh_members(&ch).await;
        b1.refresh_members(&ch).await;

        let setup = a1.machine.create_recovery(None).await.unwrap();
        let key = setup.recovery_key().unwrap().to_owned();
        a1.execute(&setup.request).await.unwrap();
        assert!(a1.errors.is_empty(), "first version needs no MFA: {:?}", a1.errors);
        let m = marker();
        a1.send_text(&ch, &format!("{m} one")).await;
        b1.sync().await;
        b1.send_text(&ch, &format!("{m} two")).await;
        settle(&mut [&mut b1, &mut a1]).await;
        let status = a1.machine.backup_status().await.unwrap();
        assert!(status.enabled && status.keys_backed_up >= 2, "{status:?}");

        // restore on a new device
        let mut a2 = Device::open(&a.new_device().await.unwrap()).await;
        a2.refresh_members(&ch).await;
        assert_eq!(
            a2.machine
                .unlock_backup("not the key", &recovery_secrets(&a2).await)
                .await,
            Err(CryptoError::WrongRecoveryKey)
        );
        let version = a2
            .machine
            .unlock_backup(&key, &recovery_secrets(&a2).await)
            .await
            .unwrap();
        let body = a2
            .http
            .call("GET", &paths::backup_keys(&version), None)
            .await
            .unwrap()
            .body;
        let mut restore = a2.machine.restore_backup(&body).await.unwrap();
        let progress = loop {
            let p = restore.next(1).await.unwrap();
            if p.is_finished() {
                break p;
            }
        };
        assert!(progress.imported >= 2, "{progress:?}");
        drop(restore);
        let texts = a2.read_all(&ch).await;
        assert_eq!(texts, [format!("{m} one"), format!("{m} two")]);
        let d = a2.decrypt(last(&a2.messages(&ch).await)).await.unwrap();
        assert_eq!(d.verification, Verification::Unauthenticated);

        // a new version over the existing one: 401 → MFA ticket → same request
        let rotate = a1.machine.rotate_backup().await.unwrap();
        a1.execute(&rotate.request).await.unwrap();
        assert_eq!(a1.errors.drain(..).collect::<Vec<_>>(), [CryptoError::MfaRequired]);
        let ticket = a.mfa_ticket().await.unwrap();
        a1.execute_with(&rotate.request, Some(&ticket)).await.unwrap();
        assert!(a1.errors.is_empty(), "{:?}", a1.errors);
        a1.sync().await;
        let rotated = a1.machine.backup_status().await.unwrap();
        assert_ne!(rotated.version, status.version);

        // A2 still uploads to the old version: a new key → replaced elsewhere
        a2.send_text(&ch, &format!("{m} three")).await;
        a2.sync().await;
        assert!(
            a2.errors.contains(&CryptoError::BackupVersionChanged),
            "{:?}",
            a2.errors
        );
        assert!(a2.machine.backup_status().await.unwrap().outdated);
        let mut ev = Evidence::default();
        ev.message(&ch, &m);
        ev.save(&s.config, "t03_backup_restore_and_mfa");
    })
    .await;
}

/// T12: SAS between two users over the real mailbox: both devices verified
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t12_sas_between_users() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        a.befriend(&b).await.unwrap();
        let ch = a.encrypted_dm(&b).await.unwrap();
        let (mut da, mut db) = (Device::open(&a).await, Device::open(&b).await);
        da.refresh_members(&ch).await;
        db.refresh_members(&ch).await;
        settle(&mut [&mut da, &mut db]).await;

        let ha = da.machine.request_verification(db.user(), db.device()).await.unwrap();
        assert_eq!(ha.state(), SasState::Requested);
        settle(&mut [&mut da, &mut db]).await;
        let hb = db.machine.verification(ha.flow_id()).expect("the request reached B");
        assert_eq!(hb.state(), SasState::Incoming);
        hb.accept().await.unwrap();
        settle(&mut [&mut db, &mut da]).await;
        assert_eq!(ha.state(), SasState::Ready);
        ha.start().await.unwrap();
        settle(&mut [&mut da, &mut db]).await;
        let (
            SasState::ShowCodes {
                emoji: ea,
                decimals: xa,
            },
            SasState::ShowCodes {
                emoji: eb,
                decimals: xb,
            },
        ) = (ha.state(), hb.state())
        else {
            panic!("codes not shown: {:?} / {:?}", ha.state(), hb.state());
        };
        assert_eq!((ea.len(), &ea, xa), (7, &eb, xb));
        ha.confirm().await.unwrap();
        hb.confirm().await.unwrap();
        settle(&mut [&mut da, &mut db]).await;
        assert_eq!((ha.state(), hb.state()), (SasState::Done, SasState::Done));
        let trust = |list: Vec<stoat_crypto::DeviceInfo>, id: &str| {
            list.into_iter().find(|d| d.device_id == id).map(|d| d.trust)
        };
        assert_eq!(
            trust(da.machine.devices(db.user()).await.unwrap(), db.device()),
            Some(Trust::Verified)
        );
        assert_eq!(
            trust(db.machine.devices(da.user()).await.unwrap(), da.device()),
            Some(Trust::Verified)
        );

        // the shield follows: B's next message is Verified on A
        let m = marker();
        db.send_text(&ch, &format!("{m} verified")).await;
        settle(&mut [&mut db, &mut da]).await;
        let d = da.decrypt(last(&da.messages(&ch).await)).await.unwrap();
        assert_eq!(d.verification, Verification::Verified);
        let mut ev = Evidence::default();
        ev.message(&ch, &m);
        ev.save(&s.config, "t12_sas_between_users");
    })
    .await;
}

/// T10: attachment with a thumbnail through autumn `?encrypted=true`:
/// autumn stores and serves exactly our ciphertext, the hash is checked
/// before decryption
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t10_attachment_with_thumbnail() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        a.befriend(&b).await.unwrap();
        let ch = a.encrypted_dm(&b).await.unwrap();
        let (mut da, mut db) = (Device::open(&a).await, Device::open(&b).await);
        da.refresh_members(&ch).await;
        db.refresh_members(&ch).await;
        let m = marker();

        // a "picture" with the marker inside, encrypted in chunks
        let mut picture = format!("{m} PNG-ish ").into_bytes();
        picture.extend((0..300_000u32).map(|i| (i % 253) as u8));
        let mut enc = AttachmentEncryptor::new();
        let mut blob = Vec::new();
        for chunk in picture.chunks(stoat_crypto::ATTACHMENT_CHUNK) {
            blob.extend(enc.update(chunk));
        }
        let file = enc.finish();
        let thumb_plain = format!("{m} thumbnail").into_bytes();
        let (thumb_blob, thumb_file) = encrypt_attachment(&thumb_plain);

        let autumn = da.http.clone_for(&s.config.autumn);
        let file_id = autumn
            .upload("/attachments?encrypted=true", blob.clone())
            .await
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let thumb_id = autumn
            .upload("/attachments?encrypted=true", thumb_blob.clone())
            .await
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let payload = MessagePayload {
            content: Some(format!("{m} look")),
            attachments: vec![Attachment {
                id: file_id.clone(),
                name: format!("{m}.png"),
                content_type: "image/png".into(),
                size: picture.len() as u64,
                metadata: json!({ "type": "Image", "width": 640, "height": 480 }),
                spoiler: true,
                file,
                thumbnail: Some(Thumbnail {
                    id: thumb_id.clone(),
                    width: 64,
                    height: 48,
                    file: thumb_file,
                }),
            }],
            ..payload_text("")
        };
        da.send(&ch, &payload).await;
        settle(&mut [&mut da, &mut db]).await;

        let msgs = db.messages(&ch).await;
        let msg = last(&msgs);
        assert!(!msg.to_string().contains(&m), "name or text leaked: {msg}");
        let got = db.decrypt(msg).await.unwrap().payload;
        let att = &got.attachments[0];
        assert!(att.spoiler);
        let autumn_b = db.http.clone_for(&s.config.autumn);
        for (id, expect_blob, f, plain) in [
            (&att.id, &blob, &att.file, &picture),
            (
                &att.thumbnail.as_ref().unwrap().id,
                &thumb_blob,
                &att.thumbnail.as_ref().unwrap().file,
                &thumb_plain,
            ),
        ] {
            let downloaded = autumn_b.download(&format!("/attachments/{id}/file.bin")).await.unwrap();
            assert_eq!(&downloaded, expect_blob, "autumn changed the blob");
            let mut v = AttachmentVerifier::new(f).unwrap();
            for chunk in downloaded.chunks(10_000) {
                v.update(chunk);
            }
            let mut dec = v.finish().unwrap();
            assert_eq!(&dec.update(&downloaded), plain);
        }
        let mut ev = Evidence::default();
        ev.message(&ch, &m);
        ev.file(&file_id, &hex(&Sha256::digest(&picture)));
        ev.file(&thumb_id, &hex(&Sha256::digest(&thumb_plain)));
        ev.save(&s.config, "t10_attachment_with_thumbnail");
    })
    .await;
}

/// Q11: B's mailbox is full: A's room key is refused for B (`failed`), the
/// core retries with backoff and reports the device until it gets through
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn q11_full_mailbox_retry() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        a.befriend(&b).await.unwrap();
        let ch = a.encrypted_dm(&b).await.unwrap();
        let (mut da, mut db) = (Device::open(&a).await, Device::open(&b).await);
        da.refresh_members(&ch).await;
        db.refresh_members(&ch).await;
        settle(&mut [&mut da, &mut db]).await;

        // B goes offline; fill its mailbox with plaintext key-request cancels
        db.offline = true;
        let to = stoat_crypto::proto::ids::user_id(db.user()).unwrap();
        let mut filled = false;
        for i in 0..1_000 {
            let body = json!({
                "type": "m.room_key_request",
                "messages": { &to: { db.device(): {
                    "action": "request_cancellation",
                    "request_id": format!("tk{i}"),
                    "requesting_device_id": da.device(),
                } } }
            });
            let r = da
                .http
                .put(&paths::to_device_send(&format!("tkfill{i}")), Some(&body))
                .await
                .unwrap();
            if r.get("failed")
                .is_some_and(|f| f.as_object().is_some_and(|o| !o.is_empty()))
            {
                filled = true;
                break;
            }
        }
        assert!(filled, "mailbox never reported full: lower max_pending_to_device");

        let m = marker();
        da.send_text(&ch, &format!("{m} queued")).await;
        da.sync().await;
        let undelivered = da.machine.undelivered_devices().await;
        assert!(
            undelivered.iter().any(|u| u.device_id == db.device() && !u.gave_up),
            "{undelivered:?}"
        );

        // B back online drains the mailbox; A's retry gets through
        db.offline = false;
        let mut read = false;
        for _ in 0..40 {
            db.sync().await;
            if let Some(wait) = da.machine.wakeup_in_ms().await {
                tokio::time::sleep(Duration::from_millis(wait.min(2_000))).await;
            }
            da.sync().await;
            db.sync().await;
            if db.decrypt(last(&db.messages(&ch).await)).await.is_ok() {
                read = true;
                break;
            }
        }
        assert!(read, "the retried key never arrived");
        assert!(da.machine.undelivered_devices().await.is_empty());
        let mut ev = Evidence::default();
        ev.message(&ch, &m);
        ev.save(&s.config, "q11_full_mailbox_retry");
    })
    .await;
}

/// T4/T15: B logs out one of two devices: the backend deletes it and rings
/// `E2eeDeviceListUpdate`; A stops encrypting to it, B's other device still reads
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t04_logout_cascade() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        a.befriend(&b).await.unwrap();
        let ch = a.encrypted_dm(&b).await.unwrap();
        let mut da = Device::open(&a).await;
        let mut b1 = Device::open(&b).await;
        let b2_account = b.new_device().await.unwrap();
        let mut b2 = Device::open(&b2_account).await;
        for d in [&mut da, &mut b1, &mut b2] {
            d.refresh_members(&ch).await;
        }
        let m = marker();
        da.send_text(&ch, &format!("{m} to both")).await;
        settle(&mut [&mut da, &mut b1, &mut b2]).await;
        let first = last(&b2.messages(&ch).await).clone();
        assert_eq!(b2.read(&first).await, format!("{m} to both"));
        let b2_id = b2.device().to_owned();
        let known =
            |list: Vec<stoat_crypto::DeviceInfo>| list.into_iter().find(|d| d.device_id == b2_id).map(|d| d.deleted);
        assert_eq!(
            known(da.machine.devices(b.user_id.as_str()).await.unwrap()),
            Some(false)
        );

        b2_account.logout().await.unwrap();
        b2.disconnect();
        assert_eq!(
            b2.http
                .raw("GET", api::paths::KEYS_COUNT, None, None)
                .await
                .unwrap()
                .status,
            401
        );
        settle(&mut [&mut da, &mut b1]).await;
        assert_ne!(
            known(da.machine.devices(b.user_id.as_str()).await.unwrap()),
            Some(false),
            "A still lists the logged-out device as active"
        );
        // the next message: B1 reads it, no key went to the deleted device
        da.send_text(&ch, &format!("{m} after logout")).await;
        settle(&mut [&mut da, &mut b1]).await;
        let second = last(&b1.messages(&ch).await).clone();
        assert_eq!(b1.read(&second).await, format!("{m} after logout"));
        assert_eq!(b2.decrypt(&second).await.unwrap_err(), DecryptError::MissingRoomKey);
        let mut ev = Evidence::default();
        ev.message(&ch, &m);
        ev.save(&s.config, "t04_logout_cascade");
    })
    .await;
}
