//! The bindings' surface driven like Kotlin drives it (JSON bodies, owned
//! values, `Arc` objects) against the fake server: what the AAR exposes
//! works end to end before any Kotlin runs (CR-13).

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use stoat_crypto_fakeserver::{Auth, FakeServer, Server};
use stoat_crypto_ffi::{
    AttachmentEncryptor, AttachmentVerifier, ChannelEncryptionSettings, CryptoError, CryptoMachine, DecryptFailureKind,
    DecryptResult, IncomingEncryptedMessage, RecoveryKeyCheck, SasState, StoreConfig, Timing, Verification,
    decrypt_attachment, destroy_store, encrypt_attachment, payload_file_ids, recovery_key_check, sas_emoji_table,
    text_payload,
};

fn ulid(tag: &str) -> String {
    format!("01K{}", tag.repeat(26)).chars().take(26).collect()
}

fn dev(tag: &str) -> String {
    format!("01KD{}", tag.repeat(26)).chars().take(26).collect()
}

struct Client {
    m: Arc<CryptoMachine>,
    auth: Auth,
    server: Server,
}

impl Client {
    async fn open(server: &Server, user: &str, device: &str, store: StoreConfig) -> Self {
        let auth = Auth::new(ulid(user), dev(device));
        let m = CryptoMachine::open(auth.user.clone(), auth.device.clone(), store)
            .await
            .unwrap();
        m.set_timing(Timing {
            key_request_delay_ms: 0,
            to_device_retry_ms: 60_000,
            to_device_retry_attempts: 8,
        })
        .await
        .unwrap();
        let c = Self {
            m,
            auth,
            server: server.clone(),
        };
        c.sync().await;
        c
    }

    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, String) {
        let r = self.server.lock().unwrap().handle(&self.auth, method, path, body);
        (r.status, r.body.to_string())
    }

    async fn run(&self, reqs: Vec<stoat_crypto_ffi::OutgoingRequest>) -> bool {
        for r in &reqs {
            let body: Value = serde_json::from_str(&r.body).unwrap();
            let (status, resp) = self.call(&r.method, &r.path, Some(&body));
            if status < 300 {
                self.m.mark_request_sent(r.id.clone(), r.kind, resp).await.unwrap();
            } else {
                let _ = self.m.mark_request_failed(r.id.clone(), r.kind, status).await;
            }
        }
        !reqs.is_empty()
    }

    /// Request passes and mailbox until nothing moves
    async fn sync(&self) {
        for _ in 0..32 {
            let sent = self.run(self.m.outgoing_requests().await.unwrap()).await;
            let (_, page) = self.call("GET", "/e2ee/to_device?limit=100", None);
            let r = self.m.receive_to_device(page).await.unwrap();
            if !r.ack_ids.is_empty() {
                let body = serde_json::json!({ "ids": r.ack_ids });
                assert_eq!(self.call("POST", "/e2ee/to_device/ack", Some(&body)).0, 204);
                self.m.mark_ack_sent(r.ack_ids.clone()).await.unwrap();
            }
            let (_, counts) = self.call("GET", "/e2ee/keys/count", None);
            self.m.receive_otk_counts(counts).await.unwrap();
            if !sent && r.fetched == 0 {
                return;
            }
        }
        panic!("sync does not converge");
    }

    async fn send(&self, channel: &str, payload_json: String) -> String {
        loop {
            let reqs = self.m.prepare_send(channel.to_owned()).await.unwrap();
            if !self.run(reqs).await {
                break;
            }
        }
        let envelope = self.m.encrypt(channel.to_owned(), payload_json).await.unwrap();
        let envelope: Value = serde_json::from_str(&envelope).unwrap();
        self.server
            .lock()
            .unwrap()
            .message_send(&self.auth, channel, envelope, vec![])
            .unwrap()
    }

    fn incoming(&self, channel: &str) -> Vec<IncomingEncryptedMessage> {
        self.server
            .lock()
            .unwrap()
            .messages(channel)
            .into_iter()
            .map(|m| IncomingEncryptedMessage {
                message_id: m.id,
                channel_id: m.channel,
                author: m.author,
                envelope_json: m.encrypted.to_string(),
                replies: m.replies,
                timestamp: m.ts,
            })
            .collect()
    }
}

async fn dm(a: &Client, b: &Client, name: &str) -> String {
    let id = ulid(name);
    let members = vec![a.auth.user.clone(), b.auth.user.clone()];
    let refs: Vec<&str> = members.iter().map(String::as_str).collect();
    a.server.lock().unwrap().channel_set_members(&id, &refs);
    for c in [a, b] {
        c.m.set_channel_members(id.clone(), members.clone(), ChannelEncryptionSettings::default())
            .await
            .unwrap();
    }
    id
}

fn content(r: &DecryptResult) -> String {
    match r {
        DecryptResult::Decrypted { message } => {
            let p: Value = serde_json::from_str(&message.payload_json).unwrap();
            p["content"].as_str().unwrap().to_owned()
        }
        DecryptResult::Failed { code, .. } => panic!("not decrypted: {code}"),
    }
}

#[tokio::test]
async fn dm_roundtrip_and_batch() {
    let server = FakeServer::new().shared();
    let a = Client::open(&server, "A", "A1", StoreConfig::Memory).await;
    let b = Client::open(&server, "B", "B1", StoreConfig::Memory).await;
    let ch = dm(&a, &b, "C").await;
    a.send(&ch, text_payload("hello".into(), "AAAAAAAAAAAAAAAAAAAAAA".into(), 1))
        .await;
    a.send(&ch, text_payload("again".into(), "AAAAAAAAAAAAAAAAAAAAAA".into(), 2))
        .await;
    b.sync().await;

    let mut messages = b.incoming(&ch);
    // an envelope from a newer client is a value, not an exception
    let mut newer = messages[0].clone();
    newer.envelope_json = newer.envelope_json.replace("\"v\":1", "\"v\":2");
    messages.insert(1, newer);
    let results = b.m.decrypt_batch(messages).await.unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(content(&results[0]), "hello");
    assert!(matches!(
        results[1],
        DecryptResult::Failed {
            kind: DecryptFailureKind::UpdateApp,
            ..
        }
    ));
    assert_eq!(content(&results[2]), "again");
    let DecryptResult::Decrypted { message } = &results[0] else {
        unreachable!()
    };
    assert_eq!(message.sender_user, a.auth.user);
    assert_eq!(message.verification, Verification::Unverified);
    assert!(message.is_clean);
    assert!(!format!("{message:?}").contains("hello"));

    // the sender reads its own echo
    assert_eq!(
        content(&a.m.decrypt(a.incoming(&ch)[0].clone()).await.unwrap()),
        "hello"
    );
}

#[tokio::test]
async fn sas_through_handles() {
    let server = FakeServer::new().shared();
    let a = Client::open(&server, "A", "A1", StoreConfig::Memory).await;
    let b = Client::open(&server, "B", "B1", StoreConfig::Memory).await;
    dm(&a, &b, "C").await;
    a.sync().await;
    b.sync().await;

    let ha =
        a.m.request_verification(b.auth.user.clone(), b.auth.device.clone())
            .await
            .unwrap();
    assert_eq!(ha.state().unwrap(), SasState::Requested);
    a.sync().await;
    b.sync().await;
    let hb = b.m.verification(ha.flow_id()).unwrap().expect("incoming flow");
    assert_eq!(hb.state().unwrap(), SasState::Incoming);
    hb.accept().await.unwrap();
    b.sync().await;
    a.sync().await;
    assert_eq!(ha.state().unwrap(), SasState::Ready);
    ha.start().await.unwrap();
    for _ in 0..3 {
        a.sync().await;
        b.sync().await;
    }
    let (
        SasState::ShowCodes {
            emoji: ea,
            decimals: da,
        },
        SasState::ShowCodes {
            emoji: eb,
            decimals: db,
        },
    ) = (ha.state().unwrap(), hb.state().unwrap())
    else {
        panic!("codes not shown");
    };
    assert_eq!((ea.len(), da.len()), (7, 3));
    assert_eq!((&ea, &da), (&eb, &db));
    let table = sas_emoji_table();
    for e in &ea {
        assert_eq!(table[e.index as usize], *e);
    }
    ha.confirm().await.unwrap();
    hb.confirm().await.unwrap();
    for _ in 0..3 {
        a.sync().await;
        b.sync().await;
    }
    assert_eq!(ha.state().unwrap(), SasState::Done);
    assert_eq!(hb.state().unwrap(), SasState::Done);
    let devices = a.m.devices(b.auth.user.clone()).await.unwrap();
    assert_eq!(devices[0].trust, stoat_crypto_ffi::Trust::Verified);
}

#[tokio::test]
async fn backup_errors_are_typed() {
    let server = FakeServer::new().shared();
    let a = Client::open(&server, "A", "A1", StoreConfig::Memory).await;
    let setup = a.m.create_recovery(Some(b"correct horse".to_vec())).await.unwrap();
    let key = setup.recovery_key.clone().expect("a new key");
    assert_eq!(recovery_key_check(key.into_bytes()).unwrap(), RecoveryKeyCheck::Valid);
    assert!(!format!("{setup:?}").contains(setup.recovery_key.as_deref().unwrap()));
    a.run(vec![setup.request]).await;
    // a second version needs MFA: the error is typed, not a generic exception
    let again = a.m.create_recovery(None).await.unwrap();
    let body: Value = serde_json::from_str(&again.request.body).unwrap();
    let (status, _) = a.call(&again.request.method, &again.request.path, Some(&body));
    let err =
        a.m.mark_request_failed(again.request.id.clone(), again.request.kind, status)
            .await
            .unwrap_err();
    assert!(matches!(err, CryptoError::MfaRequired(_)), "{err:?}");
}

#[tokio::test]
async fn store_key_and_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_string_lossy().into_owned();
    let bad = CryptoMachine::open(
        ulid("A"),
        dev("A1"),
        StoreConfig::Sqlite {
            path: path.clone(),
            key: vec![1; 16],
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(bad, CryptoError::InvalidInput(_)));
    let store = || StoreConfig::Sqlite {
        path: path.clone(),
        key: vec![7; 32],
    };
    let m = CryptoMachine::open(ulid("A"), dev("A1"), store()).await.unwrap();
    let second = CryptoMachine::open(ulid("A"), dev("A1"), store()).await.unwrap_err();
    assert!(matches!(second, CryptoError::StoreLocked(_)));
    assert!(matches!(destroy_store(store()), Err(CryptoError::StoreLocked(_))));
    drop(m);
    destroy_store(store()).unwrap();
    assert!(!PathBuf::from(&path).join("matrix-sdk-crypto.sqlite3").exists());
}

#[test]
fn attachments_stream_and_one_shot() {
    let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let enc = AttachmentEncryptor::new().unwrap();
    let mut blob = Vec::new();
    for chunk in data.chunks(32 * 1024) {
        blob.extend(enc.update(chunk.to_vec()).unwrap());
    }
    assert_eq!(enc.size().unwrap(), data.len() as u64);
    let file = enc.finish().unwrap();
    assert!(matches!(enc.finish(), Err(CryptoError::AlreadyFinished(_))));
    assert_ne!(blob, data);

    let verifier = AttachmentVerifier::new(file.clone()).unwrap();
    for chunk in blob.chunks(10_000) {
        verifier.update(chunk.to_vec()).unwrap();
    }
    let dec = verifier.finish().unwrap();
    let mut plain = Vec::new();
    for chunk in blob.chunks(7_777) {
        plain.extend(dec.update(chunk.to_vec()).unwrap());
    }
    assert_eq!(plain, data);

    // a swapped blob gives no decryptor
    let mut swapped = blob.clone();
    swapped[0] ^= 1;
    let verifier = AttachmentVerifier::new(file.clone()).unwrap();
    verifier.update(swapped.clone()).unwrap();
    assert!(matches!(verifier.finish(), Err(CryptoError::AttachmentHashMismatch(_))));
    assert!(matches!(
        decrypt_attachment(swapped, file),
        Err(CryptoError::AttachmentHashMismatch(_))
    ));
    assert!(matches!(
        AttachmentVerifier::new("{}".into()),
        Err(CryptoError::InvalidAttachment(_))
    ));

    let thumb = encrypt_attachment(b"thumbnail".to_vec()).unwrap();
    assert_eq!(
        decrypt_attachment(thumb.ciphertext, thumb.file_json.clone()).unwrap(),
        b"thumbnail"
    );

    // the payload lists files and thumbnails for the open `attachments`
    let file: Value = serde_json::from_str(&thumb.file_json).unwrap();
    let payload = serde_json::json!({
        "v": 1, "client_nonce": "AAAAAAAAAAAAAAAAAAAAAA", "ts": 1,
        "attachments": [{
            "id": "F1", "name": "a.png", "content_type": "image/png", "size": 9,
            "metadata": {"type": "Image", "width": 1, "height": 1}, "file": file,
            "thumbnail": {"id": "T1", "width": 1, "height": 1, "file": file}
        }]
    });
    assert_eq!(payload_file_ids(payload.to_string()).unwrap(), ["F1", "T1"]);
    assert!(matches!(
        payload_file_ids("{\"v\":1}".into()),
        Err(CryptoError::InvalidPayload(_))
    ));
}

fn fixture(rel: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(rel);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn fixture_vectors_through_the_bindings() {
    let v = fixture("backup/recovery_key.vectors.json");
    for valid in v["valid"].as_array().unwrap() {
        let key = valid["recovery_key"].as_str().unwrap();
        assert_eq!(recovery_key_check(key.into()).unwrap(), RecoveryKeyCheck::Valid);
    }
    for invalid in v["invalid"].as_array().unwrap() {
        let expected = match invalid["error"].as_str().unwrap() {
            "typo" => RecoveryKeyCheck::Typo,
            _ => RecoveryKeyCheck::NotAKey,
        };
        let input = invalid["input"].as_str().unwrap();
        assert_eq!(recovery_key_check(input.into()).unwrap(), expected, "{input}");
    }
    assert!(matches!(
        recovery_key_check(vec![0xff, 0xfe]),
        Err(CryptoError::InvalidInput(_))
    ));

    let table = sas_emoji_table();
    let emoji = fixture("sas/emoji.json");
    let emoji = emoji["emoji"].as_array().unwrap();
    assert_eq!(table.len(), emoji.len());
    for (t, f) in table.iter().zip(emoji) {
        assert_eq!(u64::from(t.index), f["index"].as_u64().unwrap());
        assert_eq!(t.symbol, f["symbol"].as_str().unwrap());
        assert_eq!(t.description, f["description"].as_str().unwrap());
    }
}

/// Kotlin closes objects on its own threads, outside any tokio runtime: the
/// SQLite pool must still drop cleanly (it used to abort the process)
#[test]
fn close_outside_any_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let store = || StoreConfig::Sqlite {
        path: dir.path().to_string_lossy().into_owned(),
        key: vec![7; 32],
    };
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let (m, sas) = rt.block_on(async {
        let server = FakeServer::new().shared();
        let a = Client::open(&server, "A", "A1", store()).await;
        let b = Client::open(&server, "B", "B1", StoreConfig::Memory).await;
        dm(&a, &b, "C").await;
        a.sync().await;
        let sas =
            a.m.request_verification(b.auth.user.clone(), b.auth.device.clone())
                .await
                .unwrap();
        (a.m, sas)
    });
    drop(rt);
    drop(sas);
    drop(m);
    destroy_store(store()).unwrap();
}
