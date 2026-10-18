//! CR-18: random operation sequences against the fake server — sends,
//! edits, a member leaving and coming back, a device removed, mailbox faults,
//! crashes and restarts. Invariants checked after a final fault-free sync:
//!
//! 1. every device that was a member when a message (its latest version)
//!    was sent reads it;
//! 2. a device that was not a member then — the member had left, joined
//!    later, or the device was removed — reads nothing of it;
//! 3. what the server tampers with (replay under another id, swapped author,
//!    moved to another channel, rewired replies, rolled-back edit) is never
//!    shown as a normal message;
//! 4. no panics;
//! 5. no Megolm (session, index) is used twice, restarts included;
//! 6. replays of to-device messages (duplicates, crash before ack) never
//!    reach Olm — no undecryptable to-device messages, no unwedging.
//!
//! Proptest cases are few: each one runs four SQLite machines.

mod common;

use std::collections::{BTreeSet, HashSet};

use common::*;
use proptest::prelude::*;
use stoat_crypto::proto::EncryptedEnvelope;
use stoat_crypto::{DecryptError, Verification};
use stoat_crypto_fakeserver::StoredMessage;

/// Devices: A1, B1, B2, C1
const N: usize = 4;
const B2: usize = 2;
const C1: usize = 3;

#[derive(Clone, Debug)]
enum Op {
    /// device i sends a message
    Send(usize),
    /// device i edits the last message it sent
    Edit(usize),
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
    /// user C leaves the group, or comes back
    ToggleC,
    /// B2 logs out (removed for good)
    RemoveB2,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..N).prop_map(Op::Send),
        1 => (0..N).prop_map(Op::Edit),
        2 => (0..N).prop_map(Op::Sync),
        1 => (0..N).prop_map(Op::CrashBeforeAck),
        1 => (0..N).prop_map(Op::Restart),
        1 => any::<bool>().prop_map(Op::Duplicate),
        1 => (0..N).prop_map(Op::Rotate),
        1 => Just(Op::ToggleC),
        1 => Just(Op::RemoveB2),
    ]
}

/// What a message should look like now
struct Sent {
    id: String,
    author: usize,
    body: String,
    edit_seq: u64,
    /// Devices that were members when the latest version was sent
    readers: BTreeSet<usize>,
    /// Earlier versions as stored (rollback material)
    old: Vec<StoredMessage>,
}

struct World {
    devices: Vec<Device>,
    group: String,
    other: String,
    c_member: bool,
    b2_removed: bool,
}

impl World {
    fn alive(&self, i: usize) -> bool {
        !(i == B2 && self.b2_removed)
    }

    fn member(&self, i: usize) -> bool {
        self.alive(i) && (i != C1 || self.c_member)
    }

    fn members(&self) -> BTreeSet<usize> {
        (0..N).filter(|i| self.member(*i)).collect()
    }

    /// The server changes the group; every device learns the member list
    async fn set_c(&mut self, member: bool) {
        self.c_member = member;
        let users: Vec<String> = ["A", "B", "C"]
            .iter()
            .filter(|u| member || **u != "C")
            .map(|u| ulid(u))
            .collect();
        let refs: Vec<&str> = users.iter().map(String::as_str).collect();
        let srv = self.devices[0].server.clone();
        srv.lock().unwrap().channel_set_members(&self.group, &refs);
        for i in 0..N {
            if self.alive(i) {
                self.devices[i]
                    .m()
                    .set_channel_members(&self.group, &users, Default::default())
                    .await
                    .unwrap();
            }
        }
    }
}

async fn run(ops: Vec<Op>) {
    let srv = server();
    let dirs: Vec<_> = (0..N).map(|_| tempfile::tempdir().unwrap()).collect();
    let devices = vec![
        Device::login_sqlite(&srv, "A", "A1", dirs[0].path()).await,
        Device::login_sqlite(&srv, "B", "B1", dirs[1].path()).await,
        Device::login_sqlite(&srv, "B", "B2", dirs[2].path()).await,
        Device::login_sqlite(&srv, "C", "C1", dirs[3].path()).await,
    ];
    let (group, other) = {
        let refs: Vec<&Device> = devices.iter().collect();
        (channel(&srv, "G", &refs).await, channel(&srv, "E", &refs).await)
    };
    let mut w = World {
        devices,
        group,
        other,
        c_member: true,
        b2_removed: false,
    };
    // everyone has seen everyone's devices before the first send
    for d in w.devices.iter_mut() {
        d.sync().await;
    }

    let mut sent: Vec<Sent> = Vec::new();
    for (n, op) in ops.into_iter().enumerate() {
        match op {
            Op::Send(i) if w.member(i) => {
                let body = format!("m{n}");
                let id = w.devices[i].send(&w.group, &text(&body)).await;
                sent.push(Sent {
                    id,
                    author: i,
                    body,
                    edit_seq: 0,
                    readers: w.members(),
                    old: Vec::new(),
                });
            }
            Op::Edit(i) if w.member(i) => {
                let Some(m) = sent.iter_mut().rev().find(|m| m.author == i) else {
                    continue;
                };
                let stored = srv
                    .lock()
                    .unwrap()
                    .messages(&w.group)
                    .into_iter()
                    .find(|s| s.id == m.id)
                    .unwrap();
                let mut payload = text(&format!("e{n}"));
                payload.edit_of = Some(m.id.clone());
                payload.edit_seq = m.edit_seq + 1;
                let env = w.devices[i].encrypt(&w.group, &payload).await;
                let d = &w.devices[i];
                srv.lock()
                    .unwrap()
                    .message_edit(&d.auth, &w.group, &m.id, env.to_value())
                    .unwrap();
                m.old.push(stored);
                m.body = format!("e{n}");
                m.edit_seq += 1;
                m.readers = (0..N).filter(|j| w.member(*j)).collect();
            }
            Op::Sync(i) if w.alive(i) => w.devices[i].sync().await,
            Op::CrashBeforeAck(i) if w.alive(i) => {
                w.devices[i].crash_before_ack = true;
                w.devices[i].sync().await;
                w.devices[i].crash_before_ack = false;
            }
            Op::Restart(i) if w.alive(i) => w.devices[i].restart().await,
            Op::Duplicate(on) => srv.lock().unwrap().faults.duplicate = if on { 1.0 } else { 0.0 },
            Op::Rotate(i) if w.alive(i) => w.devices[i].m().invalidate_outbound_session(&w.group).await.unwrap(),
            Op::ToggleC => w.set_c(!w.c_member).await,
            Op::RemoveB2 if !w.b2_removed => {
                let (user, device) = (w.devices[B2].auth.user.clone(), w.devices[B2].auth.device.clone());
                srv.lock().unwrap().device_delete(&user, &device);
                w.b2_removed = true;
                // the socket event reaches every client before its next send
                for i in 0..N {
                    if w.alive(i) {
                        w.devices[i].receive_ws().await;
                    }
                }
            }
            _ => {}
        }
    }

    srv.lock().unwrap().faults.duplicate = 0.0;
    for _ in 0..3 {
        for i in 0..N {
            if w.alive(i) {
                w.devices[i].sync().await;
            }
        }
    }

    let stored = messages(&srv, &w.group);
    assert_eq!(stored.len(), sent.len());
    let mut used = HashSet::new();
    let mut indices = Vec::new();
    for s in &sent {
        let m = stored.iter().find(|m| m.id == s.id).unwrap();
        for (i, d) in w.devices.iter().enumerate() {
            let r = d.decrypt(m).await;
            if s.readers.contains(&i) && w.alive(i) {
                // (1)
                let r = r.unwrap_or_else(|e| panic!("{} cannot read {}: {e:?}", d.auth.device, s.body));
                assert_eq!(r.payload.content.as_deref(), Some(s.body.as_str()));
                assert!(r.is_clean(), "{r:?}");
                if i == 0 {
                    indices.push((r.session_id.clone(), r.message_index));
                }
            } else if !s.readers.contains(&i) {
                // (2)
                assert!(r.is_err(), "{} read {} sent while not a member", d.auth.device, s.body);
            }
        }
        // (5) one (session, index) per version, restarts included
        let e = EncryptedEnvelope::from_value(&m.encrypted).unwrap();
        assert!(used.insert(e.ciphertext), "ciphertext reused");
    }
    let unique: HashSet<_> = indices.iter().collect();
    assert_eq!(unique.len(), indices.len(), "Megolm index reused");

    // (3) tampering, judged by every device that reads the original
    for s in &sent {
        let m = stored.iter().find(|m| m.id == s.id).unwrap();
        let mut variants: Vec<(&str, StoredMessage)> = Vec::new();
        let mut replay = m.clone();
        replay.id = format!("01KZREPLAY{}", &m.id[10..]);
        variants.push(("replay", replay));
        let mut author = m.clone();
        author.author = w.devices[(s.author + 1) % N].auth.user.clone();
        if author.author != m.author {
            variants.push(("author", author));
        }
        let mut moved = m.clone();
        moved.channel = w.other.clone();
        variants.push(("moved", moved));
        let mut rewired = m.clone();
        rewired.replies = vec![sent[0].id.clone()];
        variants.push(("replies", rewired));
        for old in &s.old {
            variants.push(("rollback", old.clone()));
        }
        for (i, d) in w.devices.iter().enumerate() {
            if !(s.readers.contains(&i) && w.alive(i)) {
                continue;
            }
            for (what, v) in &variants {
                match d.decrypt(v).await {
                    Ok(r) => assert!(
                        !r.is_clean() || r.verification == Verification::Mismatch,
                        "{what} shown as normal on {}: {r:?}",
                        d.auth.device
                    ),
                    Err(e) => assert!(
                        matches!(
                            e,
                            DecryptError::ChannelMismatch | DecryptError::SenderMismatch | DecryptError::MissingRoomKey
                        ),
                        "{what}: {e:?}"
                    ),
                }
            }
        }
    }

    // (6)
    for (i, d) in w.devices.iter().enumerate() {
        if w.alive(i) {
            assert_eq!(
                d.received.undecryptable, 0,
                "{} had undecryptable to-device",
                d.auth.device
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        // more in a soak run: PROPTEST_CASES=200
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(12),
        max_shrink_iters: 16,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn membership_devices_faults_and_tampering(ops in prop::collection::vec(op(), 1..16)) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(run(ops));
    }
}
