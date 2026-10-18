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
use stoat_crypto_testkit::rabbit::PushQueue;
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

/// T6: D joins a group of three: D reads what is sent after it joined, not
/// what came before; the session does not rotate on a join (the newcomer
/// gets the key from the current index)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t06_member_added_reads_only_new() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        let c = s.register("carol").await.unwrap();
        let d = s.register("dave").await.unwrap();
        for other in [&b, &c, &d] {
            a.befriend(other).await.unwrap();
        }
        let g = a.encrypted_group("testkit", &[&b, &c]).await.unwrap();
        let (mut da, mut db, mut dc) = (Device::open(&a).await, Device::open(&b).await, Device::open(&c).await);
        for x in [&mut da, &mut db, &mut dc] {
            x.refresh_members(&g).await;
        }
        let m = marker();
        da.send_text(&g, &format!("{m} before")).await;
        settle(&mut [&mut da, &mut db, &mut dc]).await;

        a.add_member(&g, &d).await.unwrap();
        let mut dd = Device::open(&d).await;
        for x in [&mut da, &mut db, &mut dc, &mut dd] {
            x.refresh_members(&g).await;
        }
        da.send_text(&g, &format!("{m} after")).await;
        db.send_text(&g, &format!("{m} from bob")).await;
        settle(&mut [&mut da, &mut db, &mut dc, &mut dd]).await;

        let msgs = dd.messages(&g).await;
        assert_eq!(msgs.len(), 3, "the newcomer sees the history (encrypted)");
        assert_eq!(dd.decrypt(&msgs[0]).await.unwrap_err(), DecryptError::MissingRoomKey);
        assert_eq!(dd.read(&msgs[1]).await, format!("{m} after"));
        assert_eq!(dd.read(&msgs[2]).await, format!("{m} from bob"));
        assert_eq!(
            msgs[0]["encrypted"]["session_id"], msgs[1]["encrypted"]["session_id"],
            "a join must not rotate"
        );
        // the old members still read everything
        assert_eq!(dc.read_all(&g).await.len(), 3);
        // nobody forwards old keys to another user (requests go to own verified devices only)
        dd.sync().await;
        assert_eq!(dd.decrypt(&msgs[0]).await.unwrap_err(), DecryptError::MissingRoomKey);
        let mut ev = Evidence::default();
        ev.message(&g, &m);
        ev.save(&s.config, "t06_member_added_reads_only_new");
    })
    .await;
}

fn repost(env: &Value) -> Value {
    json!({ "nonce": marker(), "encrypted": env })
}

/// T8/T16/T17 through the real API: what a malicious server (or a member)
/// does with real envelopes is flagged — a replay under a new id, a move to
/// another channel, a forged author, a rolled-back edit
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t08_t16_t17_server_tampering() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        let c = s.register("carol").await.unwrap();
        a.befriend(&b).await.unwrap();
        a.befriend(&c).await.unwrap();
        let dm = a.encrypted_dm(&b).await.unwrap();
        let g = a.encrypted_group("testkit", &[&b, &c]).await.unwrap();
        let (mut da, mut db, mut dc) = (Device::open(&a).await, Device::open(&b).await, Device::open(&c).await);
        da.refresh_members(&dm).await;
        db.refresh_members(&dm).await;
        for x in [&mut da, &mut db, &mut dc] {
            x.refresh_members(&g).await;
        }
        let m = marker();
        let id = da.send_text(&dm, &format!("{m} original")).await;
        settle(&mut [&mut da, &mut db]).await;
        let original = last(&db.messages(&dm).await).clone();
        assert!(db.decrypt(&original).await.unwrap().is_clean());

        // T16: the same ciphertext again under a new message id
        da.http
            .post(&format!("/channels/{dm}/messages"), &repost(&original["encrypted"]))
            .await
            .unwrap();
        let replayed = last(&db.messages(&dm).await).clone();
        assert_ne!(replayed["_id"], original["_id"]);
        assert!(db.decrypt(&replayed).await.unwrap().is_replay, "replay not flagged");
        assert!(
            !db.decrypt(&original).await.unwrap().is_replay,
            "re-reading is no replay"
        );

        // T8: moved into another channel (the group): the session is bound to the DM
        da.http
            .post(&format!("/channels/{g}/messages"), &repost(&original["encrypted"]))
            .await
            .unwrap();
        let moved = last(&db.messages(&g).await).clone();
        assert_eq!(db.decrypt(&moved).await.unwrap_err(), DecryptError::ChannelMismatch);
        assert!(dc.decrypt(&moved).await.is_err(), "C has no key and must not show it");

        // T8: author forged: B reposts A's group envelope; the server checks
        // the device hint, so B must claim its own device
        da.send_text(&g, &format!("{m} group")).await;
        settle(&mut [&mut da, &mut db, &mut dc]).await;
        let genuine = last(&dc.messages(&g).await).clone();
        let refused = db
            .http
            .raw(
                "POST",
                &format!("/channels/{g}/messages"),
                Some(&repost(&genuine["encrypted"]).to_string()),
                None,
            )
            .await
            .unwrap();
        assert_eq!(refused.status, 400, "device hint of another session: {}", refused.body);
        let mut forged_env = genuine["encrypted"].clone();
        forged_env["device_id"] = json!(db.device());
        db.http
            .post(&format!("/channels/{g}/messages"), &repost(&forged_env))
            .await
            .unwrap();
        let forged = last(&dc.messages(&g).await).clone();
        assert_eq!(forged["author"], b.user_id.as_str());
        let r = dc.decrypt(&forged).await;
        assert!(
            matches!(r, Err(DecryptError::SenderMismatch))
                || r.as_ref()
                    .is_ok_and(|d| d.verification == Verification::Mismatch && !d.is_clean()),
            "forged author shown as normal: {r:?}"
        );

        // T17: two edits, then the server serves the first edit (and the original) again
        let mut envelopes = Vec::new();
        for seq in 1..=2u64 {
            let mut e = payload_text(&format!("{m} edit {seq}"));
            e.edit_of = Some(id.clone());
            e.edit_seq = seq;
            let env = da.encrypt(&dm, &e).await;
            da.http
                .call(
                    "PATCH",
                    &format!("/channels/{dm}/messages/{id}"),
                    Some(&json!({ "encrypted": env.to_value() })),
                )
                .await
                .unwrap();
            envelopes.push(env.to_value());
        }
        let path = format!("/channels/{dm}/messages/{id}");
        let latest = db.http.get(&path).await.unwrap();
        let shown = db.decrypt(&latest).await.unwrap();
        assert_eq!(shown.payload.content, Some(format!("{m} edit 2")));
        assert!(shown.is_clean(), "{shown:?}");
        for old in [&envelopes[0], &original["encrypted"]] {
            da.http
                .call("PATCH", &path, Some(&json!({ "encrypted": old })))
                .await
                .unwrap();
            let rolled = db.http.get(&path).await.unwrap();
            assert!(db.decrypt(&rolled).await.unwrap().stale_edit, "rollback not flagged");
        }
        let mut ev = Evidence::default();
        ev.message(&dm, &m);
        ev.message(&g, &m);
        ev.save(&s.config, "t08_t16_t17_server_tampering");
    })
    .await;
}

/// T9: what a client without E2EE gets, over HTTP and the socket, is the
/// placeholder text and an unknown system message, never ciphertext as
/// text; its plaintext send and edit are refused
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t09_old_client_view() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        a.befriend(&b).await.unwrap();
        let dm = a.encrypted_dm(&b).await.unwrap();
        let (mut da, mut db) = (Device::open(&a).await, Device::open(&b).await);
        da.refresh_members(&dm).await;
        db.refresh_members(&dm).await;
        let m = marker();
        let id = da.send_text(&dm, &format!("{m} secret")).await;
        settle(&mut [&mut da, &mut db]).await;

        // HTTP: the history as an old client fetches it
        let all = db.all_messages(&dm).await;
        let system = all
            .iter()
            .find(|x| x["system"]["type"] == "encryption_enabled")
            .unwrap_or_else(|| panic!("no encryption_enabled system message: {all:?}"));
        assert_eq!(system["system"]["by"], a.user_id.as_str());
        let msg = all.iter().find(|x| x["_id"] == id.as_str()).unwrap();
        let placeholder = msg["content"].as_str().expect("old clients get a text");
        assert!(!placeholder.is_empty() && !placeholder.contains(&m));
        assert!(!placeholder.contains(msg["encrypted"]["ciphertext"].as_str().unwrap()));

        // socket: the `Message` event carries the same placeholder
        let event = db
            .message_events
            .iter()
            .find(|e| e["_id"] == id.as_str())
            .unwrap_or_else(|| panic!("no Message event: {:?}", db.message_events));
        assert_eq!(event["content"], placeholder);
        assert!(!event.to_string().contains(&m));

        // an old client writes plaintext: refused, nothing stored in clear
        let plain = b
            .http()
            .raw(
                "POST",
                &format!("/channels/{dm}/messages"),
                Some(&json!({ "content": format!("{m} oops") }).to_string()),
                None,
            )
            .await
            .unwrap();
        assert_eq!(plain.status, 400, "{}", plain.body);
        assert_eq!(plain.json()["type"], "EncryptedChannelViolation");
        let edit = a
            .http()
            .raw(
                "PATCH",
                &format!("/channels/{dm}/messages/{id}"),
                Some(&json!({ "content": format!("{m} oops") }).to_string()),
                None,
            )
            .await
            .unwrap();
        assert_eq!(edit.status, 400, "{}", edit.body);
        let mut ev = Evidence::default();
        ev.message(&dm, &m);
        ev.save(&s.config, "t09_old_client_view");
    })
    .await;
}

/// T11 without FCM: pushd's FCM payload, read by a test consumer of the
/// outbound routing key, carries the envelope and a fixed body, never the
/// text; the recipient's device decrypts the envelope from the push alone
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t11_push_carries_only_the_envelope() {
    let s = stack!();
    let Some(queue) = PushQueue::bind(&format!("testkit-push-{}", marker())).await else {
        eprintln!("STOAT_RABBIT_API not set: skipped");
        return;
    };
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        a.befriend(&b).await.unwrap();
        let dm = a.encrypted_dm(&b).await.unwrap();
        let (mut da, mut db) = (Device::open(&a).await, Device::open(&b).await);
        da.refresh_members(&dm).await;
        db.refresh_members(&dm).await;
        settle(&mut [&mut da, &mut db]).await;
        let token = format!("tk-fcm-{}", marker());
        b.subscribe_fcm(&token).await.unwrap();
        // pushd notifies only users without a socket
        db.disconnect();
        tokio::time::sleep(Duration::from_secs(2)).await;

        let m = marker();
        let id = da.send_text(&dm, &format!("{m} push me")).await;
        // (an earlier system message of the DM may be routed to the new
        // subscription too: pushd resolves subscriptions when it consumes)
        let push = queue
            .wait_for(30, |p| {
                p["token"] == token.as_str() && p["notification"]["data"]["message"]["_id"] == id.as_str()
            })
            .await
            .expect("no FCM payload of the message for B's session");
        assert!(!push.to_string().contains(&m), "plaintext in the push payload: {push}");
        assert_eq!(push["user_id"], b.user_id.as_str());
        assert_eq!(push["session_id"], db.device());
        assert_eq!(push["notification"]["type"], "MessageNotification");
        let n = &push["notification"]["data"];
        assert_eq!(n["message"]["_id"], id.as_str());
        assert_eq!(n["message"]["encrypted"]["device_id"], da.device());
        let body = n["body"].as_str().unwrap_or_default();
        assert!(!body.is_empty() && !body.contains(&m), "{body}");
        eprintln!("push body: {body:?}");

        // the push fast path: one mailbox pass, then the envelope from the push
        db.sync().await;
        assert_eq!(db.read(&n["message"]).await, format!("{m} push me"));
        let mut ev = Evidence::default();
        ev.message(&dm, &m);
        ev.save(&s.config, "t11_push_carries_only_the_envelope");
    })
    .await;
    queue.delete().await;
}

/// T13: B's one-time keys are claimed away: A's session uses the fallback
/// key, B reads, then tops up to 50 OTKs and a fresh fallback key
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t13_otks_exhausted_fallback_then_replenish() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        let x = s.register("mallory").await.unwrap();
        a.befriend(&b).await.unwrap();
        // claims are answered for users one shares a DM, group or friendship with
        x.befriend(&b).await.unwrap();
        let ch = a.encrypted_dm(&b).await.unwrap();
        let mut db = Device::open(&b).await;
        let c0 = db.http.get(paths::KEYS_COUNT).await.unwrap();
        assert_eq!(c0["one_time_key_counts"]["signed_curve25519"], 50, "{c0}");
        assert_eq!(c0["device_unused_fallback_key_types"], json!(["signed_curve25519"]));

        // a third user (a friend of B) drains B's keys
        let target = stoat_crypto::proto::ids::user_id(db.user()).unwrap();
        let claim = json!({ "one_time_keys": { &target: { db.device(): "signed_curve25519" } } });
        let xh = x.http();
        let mut claimed = 0;
        let mut fallback_seen = false;
        for _ in 0..60 {
            let r = xh.post(paths::KEYS_CLAIM, &claim).await.unwrap();
            let keys = &r["one_time_keys"][&target][db.device()];
            if keys
                .as_object()
                .is_some_and(|o| o.values().any(|k| k["fallback"] == true))
            {
                fallback_seen = true;
                break;
            }
            claimed += 1;
        }
        assert!(fallback_seen, "the fallback key was never handed out");
        assert_eq!(claimed, 50, "one OTK per claim");
        let c1 = db.http.get(paths::KEYS_COUNT).await.unwrap();
        assert_eq!(
            c1["one_time_key_counts"]["signed_curve25519"].as_u64().unwrap_or(0),
            0,
            "{c1}"
        );

        // A starts an Olm session on the fallback key; B reads
        let mut da = Device::open(&a).await;
        da.refresh_members(&ch).await;
        db.refresh_members(&ch).await;
        let m = marker();
        da.send_text(&ch, &format!("{m} via fallback")).await;
        settle(&mut [&mut da, &mut db]).await;
        assert_eq!(
            db.read(last(&db.messages(&ch).await)).await,
            format!("{m} via fallback")
        );
        assert_eq!(db.received.undecryptable, 0);

        // B replenished its 50 OTKs. matrix-sdk-crypto 0.19.1 rotates the
        // fallback key by age (a week), not on use: it stays reported as used
        let c2 = db.http.get(paths::KEYS_COUNT).await.unwrap();
        assert_eq!(c2["one_time_key_counts"]["signed_curve25519"], 50, "{c2}");
        assert_eq!(c2["device_unused_fallback_key_types"], json!([]), "{c2}");
        let report = db.report().await;
        assert_eq!(
            report["one_time_keys"]["server_counts"]["signed_curve25519"], 50,
            "{report}"
        );

        // drained again within that week: the used fallback key must still be
        // handed out (Matrix semantics), or new senders cannot reach B
        let mut fallback_again = false;
        for _ in 0..60 {
            let r = xh.post(paths::KEYS_CLAIM, &claim).await.unwrap();
            let keys = &r["one_time_keys"][&target][db.device()];
            if keys
                .as_object()
                .is_some_and(|o| o.values().any(|k| k["fallback"] == true))
            {
                fallback_again = true;
                break;
            }
            if keys.as_object().is_none_or(|o| o.is_empty()) {
                break;
            }
        }
        assert!(fallback_again, "no key at all for B once its OTKs are gone again");
        let mut dx = Device::open(&x).await;
        let dm_x = x.encrypted_dm(&b).await.unwrap();
        dx.refresh_members(&dm_x).await;
        db.refresh_members(&dm_x).await;
        dx.send_text(&dm_x, &format!("{m} fallback reused")).await;
        settle(&mut [&mut dx, &mut db]).await;
        assert_eq!(
            db.read(last(&db.messages(&dm_x).await)).await,
            format!("{m} fallback reused")
        );
        assert_eq!(db.received.undecryptable, 0);
        let mut ev = Evidence::default();
        ev.message(&ch, &m);
        ev.message(&dm_x, &m);
        ev.save(&s.config, "t13_otks_exhausted_fallback_then_replenish");
    })
    .await;
}

/// T14: the same person on two servers (separate backends, databases and
/// brokers): two accounts, two devices, keys and mailboxes never cross
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t14_two_servers_do_not_mix() {
    let s1 = stack!();
    let Some(s2) = Stack::connect_second().await else {
        eprintln!("STOAT_API2 not set: skipped");
        return;
    };
    deadline(async {
        let a1 = s1.register("alice").await.unwrap();
        let b1 = s1.register("bob").await.unwrap();
        let a2 = s2.register_like("alice", &a1).await.unwrap();
        let b2 = s2.register_like("bob", &b1).await.unwrap();
        assert_ne!(a1.user_id, a2.user_id, "two servers, two accounts");
        a1.befriend(&b1).await.unwrap();
        a2.befriend(&b2).await.unwrap();
        let dm1 = a1.encrypted_dm(&b1).await.unwrap();
        let dm2 = a2.encrypted_dm(&b2).await.unwrap();
        let (mut da1, mut db1) = (Device::open(&a1).await, Device::open(&b1).await);
        let (mut da2, mut db2) = (Device::open(&a2).await, Device::open(&b2).await);
        da1.refresh_members(&dm1).await;
        db1.refresh_members(&dm1).await;
        da2.refresh_members(&dm2).await;
        db2.refresh_members(&dm2).await;
        let m = marker();
        da1.send_text(&dm1, &format!("{m} on one")).await;
        da2.send_text(&dm2, &format!("{m} on two")).await;
        settle(&mut [&mut da1, &mut db1, &mut da2, &mut db2]).await;
        assert_eq!(db1.read(last(&db1.messages(&dm1).await)).await, format!("{m} on one"));
        assert_eq!(db2.read(last(&db2.messages(&dm2).await)).await, format!("{m} on two"));

        // the other server's message: no key here, and the channel is unknown there
        let from2 = last(&db2.messages(&dm2).await).clone();
        assert_eq!(db1.decrypt(&from2).await.unwrap_err(), DecryptError::MissingRoomKey);
        assert!(b1.http().get(&format!("/channels/{dm2}")).await.is_err());
        // a server knows no device of the other server's accounts
        for (h, other) in [(a1.http(), &b2), (a2.http(), &b1)] {
            let user = stoat_crypto::proto::ids::user_id(&other.user_id).unwrap();
            let r = h
                .post(paths::KEYS_QUERY, &json!({ "device_keys": { &user: [] } }))
                .await
                .unwrap();
            let devices = r["device_keys"][&user].as_object().map_or(0, |o| o.len());
            assert_eq!(devices, 0, "{r}");
        }
        assert!(da1.machine.devices(&b2.user_id).await.unwrap().is_empty());
        assert!(
            da1.machine
                .devices(&a1.user_id)
                .await
                .unwrap()
                .iter()
                .all(|d| d.device_id != da2.device())
        );
        // the other server does not accept this server's token
        let foreign = s2
            .anon()
            .with_token(&a1.token)
            .raw("GET", paths::KEYS_COUNT, None, None)
            .await
            .unwrap();
        assert_eq!(foreign.status, 401);
        let mut ev = Evidence::default();
        ev.message(&dm1, &m);
        ev.save(&s1.config, "t14_two_servers_do_not_mix");
    })
    .await;
}

/// T18: the server cannot switch encryption off (no route, no other
/// algorithm, plaintext refused); a server that pretends the channel is
/// plain does not change the core: the channel state is local and survives
/// a restart, sending goes on encrypted. (The warning is the host's,
/// AN-39/WEB-05.)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t18_encryption_cannot_be_dropped() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        a.befriend(&b).await.unwrap();
        let dm = a.encrypted_dm(&b).await.unwrap();
        let ah = a.http();
        let delete = ah
            .raw("DELETE", &format!("/channels/{dm}/encryption"), None, None)
            .await
            .unwrap();
        assert_eq!(delete.status, 404, "{}", delete.body);
        let swap = ah
            .raw(
                "PUT",
                &format!("/channels/{dm}/encryption"),
                Some(&json!({ "algorithm": "m.megolm.v2.aes-sha2" }).to_string()),
                None,
            )
            .await
            .unwrap();
        assert!(!swap.ok(), "algorithm swapped: {}", swap.body);
        let channel = ah.get(&format!("/channels/{dm}")).await.unwrap();
        assert_eq!(
            channel["encryption"]["algorithm"],
            stoat_crypto::proto::ALGORITHM_MEGOLM
        );

        let mut da = Device::open_persistent(&a).await;
        let mut db = Device::open(&b).await;
        da.refresh_members(&dm).await;
        db.refresh_members(&dm).await;
        let m = marker();
        da.send_text(&dm, &format!("{m} one")).await;
        settle(&mut [&mut da, &mut db]).await;

        // a lying server: the channel comes without `encryption`; the core
        // does not ask, it kept the channel (members, settings) in its store
        da.restart().await;
        da.reconnect().await.unwrap();
        da.send_text(&dm, &format!("{m} two")).await;
        settle(&mut [&mut da, &mut db]).await;
        assert_eq!(db.read_all(&dm).await, [format!("{m} one"), format!("{m} two")]);
        let report = da.report().await;
        assert!(
            report["channels"]["listed"]
                .as_array()
                .is_some_and(|l| l.iter().any(|c| c["channel_id"] == dm.as_str())),
            "{report}"
        );
        let plain = ah
            .raw(
                "POST",
                &format!("/channels/{dm}/messages"),
                Some(&json!({ "content": format!("{m} plain") }).to_string()),
                None,
            )
            .await
            .unwrap();
        assert_eq!(plain.status, 400);
        let mut ev = Evidence::default();
        ev.message(&dm, &m);
        ev.save(&s.config, "t18_encryption_cannot_be_dropped");
    })
    .await;
}

/// T19: the device processes its mailbox and dies before `ack`; after the
/// restart the server delivers the same ids again: they are dropped before
/// the library (no Olm error, no unwedging m.dummy to the sender)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live backend: scripts/testkit-backend.sh up && test"]
async fn t19_crash_between_processing_and_ack() {
    let s = stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        a.befriend(&b).await.unwrap();
        let dm = a.encrypted_dm(&b).await.unwrap();
        let mut da = Device::open(&a).await;
        let mut db = Device::open_persistent(&b).await;
        da.refresh_members(&dm).await;
        db.refresh_members(&dm).await;
        let m = marker();
        da.send_text(&dm, &format!("{m} before the crash")).await;

        let page = db.fetch_page().await.unwrap();
        let n = page.len();
        assert!(n > 0, "the room key is in the mailbox");
        let r = db.process(page, false).await.unwrap();
        assert_eq!((r.processed, r.undecryptable), (n, 0));
        db.restart().await;

        db.received = Default::default();
        let again = db.fetch_page().await.unwrap();
        assert_eq!(again.len(), n, "nothing was acknowledged");
        let r = db.process(again, true).await.unwrap();
        assert_eq!(
            (r.skipped_duplicates, r.processed, r.undecryptable),
            (n, 0, 0),
            "redelivered ids must be dropped before the library"
        );
        assert!(db.fetch_page().await.unwrap().is_empty(), "acknowledged now");
        db.reconnect().await.unwrap();
        assert_eq!(
            db.read(last(&db.messages(&dm).await)).await,
            format!("{m} before the crash")
        );

        // no new Olm session / m.dummy towards A
        da.received = Default::default();
        tokio::time::sleep(Duration::from_millis(500)).await;
        da.sync().await;
        assert_eq!(da.received.processed, 0, "A got something: an unwedging attempt?");
        let mut ev = Evidence::default();
        ev.message(&dm, &m);
        ev.save(&s.config, "t19_crash_between_processing_and_ack");
    })
    .await;
}
