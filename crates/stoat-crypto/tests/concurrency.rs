//! CR-17: parallel encrypt / decrypt / receive_to_device on one machine lose
//! no update — every Megolm index is used once and stays used after reopening
//! the store.

mod common;

use std::collections::BTreeSet;

use common::*;
use stoat_crypto::proto::api::ToDeviceMessage;
use stoat_crypto::proto::{EncryptedEnvelope, ids};
use stoat_crypto::{ChannelEncryptionSettings, CryptoMachine, IncomingEncryptedMessage};

const N: usize = 300;

fn incoming(channel: &str, author: &str, n: usize, envelope: EncryptedEnvelope) -> IncomingEncryptedMessage {
    IncomingEncryptedMessage {
        message_id: format!("01KZ{n:022}"),
        channel_id: channel.into(),
        author: author.into(),
        envelope,
        replies: vec![],
        timestamp: 1,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_operations_lose_nothing() {
    let srv = server();
    let dir = tempfile::tempdir().unwrap();
    let mut a = Device::login_sqlite(&srv, "A", "A1", dir.path()).await;
    let mut b = Device::login(&srv, "B", "B1").await;
    let dm = channel(&srv, "D", &[&a, &b]).await;
    // one session for the whole run: no rotation after 100 messages
    let settings = ChannelEncryptionSettings {
        rotation_period_ms: None,
        rotation_period_msgs: Some(10_000),
    };
    let members = [a.auth.user.clone(), b.auth.user.clone()];
    a.m().set_channel_members(&dm, &members, settings).await.unwrap();
    a.prepare(&dm).await;
    b.sync().await;

    let ma: CryptoMachine = a.m().clone();
    let mb: CryptoMachine = b.m().clone();
    let mut tasks = Vec::new();
    for n in 0..N {
        let (ma, mb, dm) = (ma.clone(), mb.clone(), dm.clone());
        let author = a.auth.user.clone();
        tasks.push(tokio::spawn(async move {
            let env = ma.encrypt(&dm, &text(&format!("p{n}"))).await.unwrap();
            // the receiver decrypts while the sender keeps encrypting
            let d = mb.decrypt(&incoming(&dm, &author, n, env.clone())).await.unwrap();
            assert_eq!(d.payload.content.unwrap(), format!("p{n}"));
            assert!(!d.is_replay);
            // and the sender's mailbox is fed duplicates concurrently
            let dup = ToDeviceMessage {
                id: format!("01KY{:022}", n % 7),
                sender: ids::user_id(&author).unwrap(),
                sender_device: "01KDZZZZZZZZZZZZZZZZZZZZZZ".into(),
                event_type: "m.dummy".into(),
                content: serde_json::json!({}),
            };
            ma.receive_to_device(vec![dup]).await.unwrap();
            d.message_index
        }));
    }
    let mut indices = BTreeSet::new();
    for t in tasks {
        assert!(indices.insert(t.await.unwrap()), "index used twice");
    }
    assert_eq!(indices.len(), N);
    drop((ma, mb));

    // the C2 set saw 7 distinct ids, each processed once
    let r = a
        .m()
        .receive_to_device(
            (0..7)
                .map(|i| ToDeviceMessage {
                    id: format!("01KY{i:022}"),
                    sender: ids::user_id(&a.auth.user).unwrap(),
                    sender_device: "01KDZZZZZZZZZZZZZZZZZZZZZZ".into(),
                    event_type: "m.dummy".into(),
                    content: serde_json::json!({}),
                })
                .collect(),
        )
        .await
        .unwrap();
    assert_eq!((r.processed, r.skipped_duplicates), (0, 7));

    // after reopening, the ratchet continues past every index handed out
    a.restart().await;
    a.prepare(&dm).await;
    let next = a.m().encrypt(&dm, &text("after")).await.unwrap();
    b.sync().await;
    let d = b.m().decrypt(&incoming(&dm, &a.auth.user, N + 1, next)).await.unwrap();
    assert!(d.is_clean());
}
