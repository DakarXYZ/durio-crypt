//! CR-18 scaffolding: random operation sequences against the fake server with
//! mailbox faults, crashes and restarts. Invariants checked after a final
//! fault-free sync:
//!
//! 1. every device that was a member when a message was sent reads it;
//! 4. no panics;
//! 5. no Megolm (session, index) is used twice, restarts included;
//! 6. replays of to-device messages (duplicates, crash before ack) never
//!    reach Olm — no undecryptable to-device messages, no unwedging.
//!
//! Invariants 2 and 3 (removed members, tampering) are covered by the
//! scenarios for now; membership changes and tampering join the operation set
//! with block 3B. Proptest cases are few: each one runs three SQLite machines.

mod common;

use std::collections::HashSet;

use common::*;
use proptest::prelude::*;
use stoat_crypto::proto::EncryptedEnvelope;

#[derive(Clone, Debug)]
enum Op {
    /// device i sends a message
    Send(usize),
    /// device i runs a normal sync
    Sync(usize),
    /// device i processes its mailbox and "crashes" before ack
    CrashBeforeAck(usize),
    /// device i restarts from its store
    Restart(usize),
    /// every to-device message is stored twice from now on (or not)
    Duplicate(bool),
    /// device i drops its outbound session (next send rotates)
    Rotate(usize),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..3usize).prop_map(Op::Send),
        2 => (0..3usize).prop_map(Op::Sync),
        1 => (0..3usize).prop_map(Op::CrashBeforeAck),
        1 => (0..3usize).prop_map(Op::Restart),
        1 => any::<bool>().prop_map(Op::Duplicate),
        1 => (0..3usize).prop_map(Op::Rotate),
    ]
}

async fn run(ops: Vec<Op>) {
    let srv = server();
    let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let mut devices = vec![
        Device::login_sqlite(&srv, "A", "A1", dirs[0].path()).await,
        Device::login_sqlite(&srv, "B", "B1", dirs[1].path()).await,
        Device::login_sqlite(&srv, "B", "B2", dirs[2].path()).await,
    ];
    let dm = {
        let refs: Vec<&Device> = devices.iter().collect();
        channel(&srv, "D", &refs).await
    };
    // everyone has seen everyone's devices before the first send
    for d in devices.iter_mut() {
        d.sync().await;
    }

    let mut sent = Vec::new();
    for (n, op) in ops.into_iter().enumerate() {
        match op {
            Op::Send(i) => {
                let body = format!("m{n}");
                let id = devices[i].send(&dm, &text(&body)).await;
                sent.push((id, body));
            }
            Op::Sync(i) => devices[i].sync().await,
            Op::CrashBeforeAck(i) => {
                devices[i].crash_before_ack = true;
                devices[i].sync().await;
                devices[i].crash_before_ack = false;
            }
            Op::Restart(i) => devices[i].restart().await,
            Op::Duplicate(on) => srv.lock().unwrap().faults.duplicate = if on { 1.0 } else { 0.0 },
            Op::Rotate(i) => devices[i].m().invalidate_outbound_session(&dm).await.unwrap(),
        }
    }

    srv.lock().unwrap().faults.duplicate = 0.0;
    for _ in 0..3 {
        for d in devices.iter_mut() {
            d.sync().await;
        }
    }

    let stored = messages(&srv, &dm);
    assert_eq!(stored.len(), sent.len());
    let mut used = HashSet::new();
    for m in &stored {
        let e = EncryptedEnvelope::from_value(&m.encrypted).unwrap();
        let (_, body) = sent.iter().find(|(id, _)| id == &m.id).unwrap();
        for d in &devices {
            let r = d
                .decrypt(m)
                .await
                .unwrap_or_else(|e| panic!("{} cannot read {body}: {e:?}", d.auth.device));
            assert_eq!(r.payload.content.as_deref(), Some(body.as_str()));
            assert!(r.is_clean(), "{r:?}");
        }
        // (5) one (session, index) per message, restarts included
        let index = devices[0].decrypt(m).await.unwrap().message_index;
        assert!(used.insert((e.session_id, index)), "Megolm index reused");
    }
    for d in &devices {
        assert_eq!(
            d.received.undecryptable, 0,
            "{} had undecryptable to-device",
            d.auth.device
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10,
        max_shrink_iters: 16,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn mailbox_faults_restarts_and_rotation(ops in prop::collection::vec(op(), 1..12)) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(run(ops));
    }
}
