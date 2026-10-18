//! Chaos scenarios against a live backend (`scripts/testkit-backend.sh
//! chaos`): Redis, RabbitMQ, bonfire and delta restarted (or stopped) while
//! devices send and receive, sockets dropped, the mailbox delivered twice and
//! out of order. After the clients recover (reconnect rule + mailbox pass)
//! every message the server accepted must decrypt, nothing twice, nothing
//! undecryptable. Results: `out/testkit/chaos/<scenario>.json`.
//!
//! The scenarios that restart containers skip unless `STOAT_CHAOS_DIR` is
//! set (the script answers the test's requests there); the client-side ones
//! only need the stack.
#![allow(clippy::print_stderr)]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use rand::RngCore;
use serde_json::{Value, json};
use stoat_crypto::proto::MessagePayload;
use stoat_crypto::{DecryptError, SasState, Trust};
use stoat_crypto_testkit::rabbit::PushQueue;
use stoat_crypto_testkit::{Device, Stack, chaos, metrics, payload_text, settle};

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

macro_rules! chaos_stack {
    () => {{
        if chaos::dir().is_none() {
            eprintln!("STOAT_CHAOS_DIR not set (scripts/testkit-backend.sh chaos): skipped");
            return;
        }
        stack!()
    }};
}

fn marker() -> String {
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    format!("tk{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}

fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 10_000.0).round() / 10.0
}

async fn deadline<F: std::future::Future<Output = ()>>(f: F) {
    tokio::time::timeout(Duration::from_secs(600), f)
        .await
        .expect("scenario timed out");
}

fn save(name: &str, s: &Stack, v: &Value) {
    eprintln!("{name}: {}", serde_json::to_string_pretty(v).unwrap_or_default());
    if let Some(out) = &s.config.out {
        let dir = out.join("chaos");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(
            dir.join(format!("{name}.json")),
            serde_json::to_string_pretty(v).unwrap_or_default(),
        );
    }
}

/// Outcome of a send that may have to be retried
#[derive(Debug, PartialEq)]
enum Sent {
    Id(String),
    /// A 5xx, then the nonce is "already used" (400 `InvalidOperation`): the
    /// server stored the message but never said so; a client refetches
    StoredUnconfirmed,
    Failed,
}

/// Send like a client: on failure keep the payload (same nonce), recover,
/// try again
async fn send_retrying(
    d: &mut Device,
    ch: &str,
    payload: &MessagePayload,
    tries: usize,
    errors: &mut Vec<String>,
) -> Sent {
    let mut had_5xx = false;
    for _ in 0..tries {
        match d.try_send(ch, payload).await {
            Ok(id) if !id.is_empty() => return Sent::Id(id),
            Ok(_) => errors.push("empty id".into()),
            Err(e) => {
                let e = e.to_string();
                if had_5xx && e.contains("HTTP 400") && e.contains("InvalidOperation") {
                    errors.push(short(&e));
                    return Sent::StoredUnconfirmed;
                }
                had_5xx |= e.contains("HTTP 5");
                errors.push(short(&e));
            }
        }
        tokio::time::sleep(Duration::from_millis(700)).await;
        if d.socket_lost() {
            let _ = d.reconnect().await;
        }
    }
    Sent::Failed
}

impl Sent {
    fn id(self) -> String {
        match self {
            Sent::Id(id) => id,
            other => panic!("send: {other:?}"),
        }
    }
}

fn short(e: &str) -> String {
    e.chars().take(160).collect()
}

/// Reconnect (socket lost) or resync until it works; time to recover
async fn recover(d: &mut Device) -> f64 {
    let started = Instant::now();
    loop {
        let ok = if d.socket_lost() {
            d.reconnect().await.is_ok()
        } else {
            d.try_sync().await.is_ok()
        };
        if ok {
            return ms(started.elapsed());
        }
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "{} never recovered",
            d.device()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Every accepted message is on the server, and every encrypted message
/// the server stored (also those whose send got an error back) decrypts
/// cleanly on every reader. A message stored twice (a retry after an error
/// response, same nonce) is counted, not a failure.
async fn verify(readers: &[&Device], ch: &str, ids: &[String]) -> Value {
    let mut problems = Vec::new();
    let mut stored = 0;
    let mut stored_twice = 0;
    for r in readers {
        let msgs = r.messages(ch).await;
        stored = msgs.len();
        for id in ids {
            if !msgs.iter().any(|m| m["_id"] == id.as_str()) {
                problems.push(format!("{}: {id} missing", r.device()));
            }
        }
        let mut nonces = BTreeSet::new();
        stored_twice = 0;
        for m in &msgs {
            let id = m["_id"].as_str().unwrap_or_default();
            match r.decrypt(m).await {
                Ok(d) if d.is_clean() => {
                    if !nonces.insert(d.payload.client_nonce.clone()) {
                        stored_twice += 1;
                    }
                }
                Ok(d) => problems.push(format!("{}: {id} unclean (replay {})", r.device(), d.is_replay)),
                Err(e) => problems.push(format!("{}: {id} {}", r.device(), e.code())),
            }
        }
    }
    json!({
        "accepted": ids.len(), "stored": stored, "stored_twice": stored_twice,
        "readers": readers.len(), "problems": problems,
    })
}

struct Group {
    ch: String,
    da: Device,
    db1: Device,
    db2: Device,
    dc: Device,
}

impl Group {
    fn all(&mut self) -> [&mut Device; 4] {
        [&mut self.da, &mut self.db1, &mut self.db2, &mut self.dc]
    }

    fn readers(&self) -> [&Device; 3] {
        [&self.db1, &self.db2, &self.dc]
    }
}

/// A, B (two devices), C in an encrypted group, everyone synced
async fn group(s: &Stack) -> Group {
    let a = s.register("alice").await.unwrap();
    let b = s.register("bob").await.unwrap();
    let c = s.register("carol").await.unwrap();
    a.befriend(&b).await.unwrap();
    a.befriend(&c).await.unwrap();
    let ch = a.encrypted_group("chaos", &[&b, &c]).await.unwrap();
    let mut g = Group {
        da: Device::open(&a).await,
        db1: Device::open(&b).await,
        db2: Device::open(&b.new_device().await.unwrap()).await,
        dc: Device::open(&c).await,
        ch,
    };
    let ch = g.ch.clone();
    for d in g.all() {
        d.refresh_members(&ch).await;
    }
    let [a, b1, b2, c] = g.all();
    settle(&mut [a, b1, b2, c]).await;
    g
}

async fn settle_group(g: &mut Group) {
    let [a, b1, b2, c] = g.all();
    settle(&mut [a, b1, b2, c]).await;
}

/// Device reports (CR-22), the parts that tell convergence
async fn reports(g: &Group) -> Vec<Value> {
    let mut out = Vec::new();
    for d in [&g.da, &g.db1, &g.db2, &g.dc] {
        let r = d.report().await;
        out.push(json!({
            "mailbox": r["mailbox"],
            "own_backing_off": r["requests"]["own_backing_off"],
            "rejected": r["requests"]["rejected"],
            "undelivered": r["undelivered_devices"],
            "key_requests": r["key_requests"],
            "recent_request_failures": r["recent_request_failures"].as_array().map_or(0, Vec::len),
        }));
    }
    out
}

/// `target` goes away while A sends 12 messages (a new room key every 4th)
/// and B2 and C keep syncing: `restart` for redis (in-memory, data lost),
/// `stop`, 5 s, `start` for delta and bonfire. Then everyone recovers
/// (reconnect rule, mailbox pass) and reads everything.
async fn outage_mid_flow(name: &str, target: &str) {
    let s = chaos_stack!();
    deadline(async {
        let mut g = group(&s).await;
        let m = marker();
        let ch = g.ch.clone();
        let mut ids = vec![g.da.send_text(&ch, &format!("{m} before")).await];
        settle_group(&mut g).await;
        metrics::start();

        let started = Instant::now();
        let t = target.to_owned();
        let action = tokio::spawn(async move {
            if t == "redis" {
                chaos::act("restart", &t).await
            } else {
                let stop = chaos::act("stop", &t).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
                stop + chaos::act("start", &t).await + Duration::from_secs(5)
            }
        });
        let mut errors = Vec::new();
        let mut failed_sends = 0;
        let mut unconfirmed = 0;
        for i in 0..12 {
            if i % 4 == 3 {
                g.da.machine.invalidate_outbound_session(&ch).await.unwrap();
            }
            let p = payload_text(&format!("{m} during {i}"));
            match send_retrying(&mut g.da, &ch, &p, 60, &mut errors).await {
                Sent::Id(id) => ids.push(id),
                Sent::StoredUnconfirmed => unconfirmed += 1,
                Sent::Failed => failed_sends += 1,
            }
            // readers keep going as far as they can
            for d in [&mut g.db2, &mut g.dc] {
                if let Err(e) = d.try_sync().await {
                    errors.push(short(&e.to_string()));
                }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let outage_ms = ms(action.await.unwrap());
        let traffic_ms = ms(started.elapsed());

        // sockets after the outage: still delivering doorbells without a reconnect?
        let lost: Vec<bool> = [&g.da, &g.db1, &g.db2, &g.dc].iter().map(|d| d.socket_lost()).collect();
        // probes every 5 s for 30 s: seconds until B1's old socket rings again (null: never)
        let doorbell = if g.db1.socket_lost() {
            Value::Null
        } else {
            g.db1.receive_ws().await;
            let since = Instant::now();
            let mut rang = Value::Null;
            while since.elapsed() < Duration::from_secs(30) {
                g.da.machine.invalidate_outbound_session(&ch).await.unwrap();
                let p = payload_text(&format!("{m} probe"));
                ids.push(send_retrying(&mut g.da, &ch, &p, 20, &mut errors).await.id());
                tokio::time::sleep(Duration::from_secs(5)).await;
                if g.db1.receive_ws().await > 0 {
                    rang = json!((since.elapsed().as_secs_f64() * 10.0).round() / 10.0);
                    break;
                }
            }
            rang
        };
        // a fresh socket of the same session gets them (what a reconnect fixes)
        let fresh = if g.db2.socket_lost() {
            Value::Null
        } else {
            g.db2.reconnect().await.unwrap();
            g.db2.receive_ws().await;
            g.da.machine.invalidate_outbound_session(&ch).await.unwrap();
            let p = payload_text(&format!("{m} fresh probe"));
            ids.push(send_retrying(&mut g.da, &ch, &p, 20, &mut errors).await.id());
            tokio::time::sleep(Duration::from_secs(3)).await;
            json!(g.db2.receive_ws().await > 0)
        };

        let mut recovery = Vec::new();
        for d in g.all() {
            recovery.push(recover(d).await);
        }
        settle_group(&mut g).await;
        ids.push(g.da.send_text(&ch, &format!("{m} after")).await);
        settle_group(&mut g).await;

        let check = verify(&g.readers(), &ch, &ids).await;
        let undecryptable: usize = g.readers().iter().map(|d| d.received.undecryptable).sum();
        let duplicates: usize = g.readers().iter().map(|d| d.received.skipped_duplicates).sum();
        let http = metrics::stop();
        let result = json!({
            "target": target,
            "outage_ms": outage_ms,
            "traffic_ms": traffic_ms,
            "messages_accepted": ids.len(),
            "sends_given_up": failed_sends,
            "sends_stored_but_answered_with_error": unconfirmed,
            "client_errors_seen": errors.len(),
            "client_error_samples": errors.iter().take(6).collect::<Vec<_>>(),
            "sockets_lost": lost,
            "old_socket_rings_again_after_s": doorbell,
            "fresh_socket_rings": fresh,
            "recovery_ms": recovery,
            "verify": check,
            "undecryptable": undecryptable,
            "skipped_duplicates": duplicates,
            "http": { "calls": http.total_calls, "server_errors": http.server_errors,
                      "transport_errors": http.transport_errors, "rate_limited": http.rate_limited },
            "device_reports": reports(&g).await,
        });
        save(name, &s, &result);
        assert_eq!(failed_sends, 0, "a send never went through");
        assert_eq!(result["verify"]["problems"], json!([]), "not converged");
        assert_eq!(undecryptable, 0);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "chaos: scripts/testkit-backend.sh up && chaos"]
async fn chaos_redis_restart() {
    outage_mid_flow("chaos_redis_restart", "redis").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "chaos: scripts/testkit-backend.sh up && chaos"]
async fn chaos_bonfire_down() {
    outage_mid_flow("chaos_bonfire_down", "bonfire").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "chaos: scripts/testkit-backend.sh up && chaos"]
async fn chaos_delta_down() {
    outage_mid_flow("chaos_delta_down", "delta").await;
}

/// Send once without retries; the HTTP status of the message POST (0: no response)
async fn probe_send(d: &mut Device, ch: &str, text: &str) -> u16 {
    let p = payload_text(text);
    let Ok(env) = d.try_encrypt(ch, &p).await else {
        return 0;
    };
    let body = Device::send_body(&p, &env).to_string();
    d.http
        .raw("POST", &format!("/channels/{ch}/messages"), Some(&body), None)
        .await
        .map_or(0, |r| r.status)
}

/// RabbitMQ restarted. The backend services keep their AMQP connection
/// object and never reconnect: delta's event publish fails (a debug build
/// panics in `EventV1::p`, the message is stored but the client gets 500),
/// pushd consumes nothing. The scenario records that, heals the stack by
/// restarting delta, then pushd and bonfire, and checks that E2EE converged.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "chaos: scripts/testkit-backend.sh up && chaos"]
async fn chaos_rabbit_restart() {
    let s = chaos_stack!();
    deadline(async {
        let mut g = group(&s).await;
        let m = marker();
        let ch = g.ch.clone();
        let mut ids = vec![g.da.send_text(&ch, &format!("{m} before")).await];
        settle_group(&mut g).await;
        let token = format!("tk-fcm-{}", marker());
        g.db2.account.subscribe_fcm(&token).await.unwrap();

        let restart_ms = ms(chaos::act("restart", "rabbit").await);
        tokio::time::sleep(Duration::from_secs(2)).await;
        // the queue goes after the restart: the management API is back with the broker
        let queue = PushQueue::bind(&format!("testkit-chaos-{}", marker()))
            .await
            .expect("STOAT_RABBIT_API");
        let mut statuses = Vec::new();
        for i in 0..3 {
            statuses.push(probe_send(&mut g.da, &ch, &format!("{m} after rabbit {i}")).await);
        }

        chaos::act("restart", "delta").await;
        for d in g.all() {
            recover(d).await;
        }
        let after_delta = probe_send(&mut g.da, &ch, &format!("{m} after delta restart")).await;

        // push with pushd untouched since the broker restart
        g.db2.disconnect();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let id = g.da.send_text(&ch, &format!("{m} push 1")).await;
        ids.push(id.clone());
        let push_before = queue
            .wait_for(15, |p| {
                p["token"] == token.as_str() && p["notification"]["data"]["message"]["_id"] == id.as_str()
            })
            .await
            .is_some();

        chaos::act("restart", "pushd").await;
        chaos::act("restart", "bonfire").await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        let id = g.da.send_text(&ch, &format!("{m} push 2")).await;
        ids.push(id.clone());
        let push_after = queue
            .wait_for(20, |p| {
                p["token"] == token.as_str() && p["notification"]["data"]["message"]["_id"] == id.as_str()
            })
            .await
            .is_some();
        queue.delete().await;

        let mut recovery = Vec::new();
        for d in g.all() {
            recovery.push(recover(d).await);
        }
        settle_group(&mut g).await;
        ids.push(g.da.send_text(&ch, &format!("{m} after")).await);
        settle_group(&mut g).await;
        let check = verify(&g.readers(), &ch, &ids).await;
        let undecryptable: usize = g.readers().iter().map(|d| d.received.undecryptable).sum();
        let result = json!({
            "target": "rabbit",
            "restart_ms": restart_ms,
            "message_post_status_after_broker_restart": statuses,
            "message_post_status_after_delta_restart": after_delta,
            "push_delivered_pushd_not_restarted": push_before,
            "push_delivered_after_pushd_restart": push_after,
            "recovery_ms": recovery,
            "verify": check,
            "undecryptable": undecryptable,
            "device_reports": reports(&g).await,
        });
        save("chaos_rabbit_restart", &s, &result);
        assert_eq!(after_delta, 200, "delta does not work after its own restart");
        assert!(push_after, "no push even after pushd restarted");
        assert_eq!(result["verify"]["problems"], json!([]), "not converged");
        assert_eq!(undecryptable, 0);
    })
    .await;
}

/// delta down for a while: requests fail without a response (status 0);
/// an own request of the core (a SAS request) backs off instead of being
/// hammered or dropped (review O-2), and goes through once delta is back;
/// the verification then completes
#[tokio::test(flavor = "multi_thread")]
#[ignore = "chaos: scripts/testkit-backend.sh up && chaos"]
async fn chaos_delta_down_own_request_backoff() {
    let s = chaos_stack!();
    deadline(async {
        let a = s.register("alice").await.unwrap();
        let b = s.register("bob").await.unwrap();
        a.befriend(&b).await.unwrap();
        let ch = a.encrypted_dm(&b).await.unwrap();
        let (mut da, mut db) = (Device::open(&a).await, Device::open(&b).await);
        da.refresh_members(&ch).await;
        db.refresh_members(&ch).await;
        settle(&mut [&mut da, &mut db]).await;

        chaos::act("stop", "delta").await;
        metrics::start();
        let ha = da.machine.request_verification(db.user(), db.device()).await.unwrap();
        let outage = Instant::now();
        let mut passes = 0;
        let mut wakeups = Vec::new();
        while outage.elapsed() < Duration::from_secs(10) {
            let _ = da.try_flush().await;
            passes += 1;
            wakeups.push(da.machine.wakeup_in_ms().await);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let during = metrics::snapshot();
        let attempts = during
            .routes
            .iter()
            .filter(|(r, _)| r.starts_with("PUT /e2ee/to_device"))
            .map(|(_, v)| v.calls)
            .sum::<usize>();
        let report = da.report().await;
        assert!(
            da.errors.is_empty(),
            "status 0 must not drop the request: {:?}",
            da.errors
        );
        chaos::act("start", "delta").await;
        let back = Instant::now();
        let recovery = [recover(&mut da).await, recover(&mut db).await];

        // the request reaches B once delta is back
        let mut hb = None;
        for _ in 0..40 {
            if let Some(w) = da.machine.wakeup_in_ms().await {
                tokio::time::sleep(Duration::from_millis(w.min(1_000))).await;
            }
            da.sync().await;
            db.sync().await;
            hb = db.machine.verification(ha.flow_id());
            if hb.is_some() {
                break;
            }
        }
        let hb = hb.expect("the SAS request never arrived after the outage");
        let delivered_after_ms = ms(back.elapsed());
        hb.accept().await.unwrap();
        settle(&mut [&mut db, &mut da]).await;
        ha.start().await.unwrap();
        settle(&mut [&mut da, &mut db]).await;
        ha.confirm().await.unwrap();
        hb.confirm().await.unwrap();
        settle(&mut [&mut da, &mut db]).await;
        assert_eq!((ha.state(), hb.state()), (SasState::Done, SasState::Done));
        let trust = da
            .machine
            .devices(db.user())
            .await
            .unwrap()
            .into_iter()
            .find(|d| d.device_id == db.device())
            .map(|d| d.trust);
        assert_eq!(trust, Some(Trust::Verified));
        let http = metrics::stop();
        let result = json!({
            "outage_s": 10, "flush_passes": passes,
            "to_device_attempts_during_outage": attempts,
            "wakeups_ms": wakeups.iter().take(12).collect::<Vec<_>>(),
            "report_requests_during_outage": report["requests"],
            "recent_request_failures": report["recent_request_failures"],
            "recovery_ms": recovery,
            "sas_request_delivered_after_ms": delivered_after_ms,
            "http_transport_errors": http.transport_errors,
        });
        save("chaos_delta_down_own_request_backoff", &s, &result);
        // 500 ms ×2 backoff: about 5 tries in 10 s, not one per pass
        assert!(
            attempts <= 6,
            "own request not backing off: {attempts} tries in {passes} passes"
        );
        assert!(attempts >= 2, "own request not retried at all");
        let _ = ch;
    })
    .await;
}

/// Client side: sockets dropped at random while messages flow; the mailbox
/// delivered reversed and twice (as a buggy proxy would), then a crash
/// before ack: every key arrives once, nothing is lost or decrypted twice
#[tokio::test(flavor = "multi_thread")]
#[ignore = "chaos: scripts/testkit-backend.sh up && chaos"]
async fn chaos_client_socket_drops_and_mailbox_faults() {
    let s = stack!();
    deadline(async {
        let mut g = group(&s).await;
        let m = marker();
        let ch = g.ch.clone();
        let mut ids = Vec::new();
        let mut drops = 0;

        // 1. sockets dropped while A rotates and sends
        for i in 0..9 {
            if i % 3 == 0 {
                g.da.machine.invalidate_outbound_session(&ch).await.unwrap();
            }
            ids.push(g.da.send_text(&ch, &format!("{m} drop {i}")).await);
            if i % 2 == 0 {
                g.dc.disconnect();
                drops += 1;
            }
            if g.dc.socket_lost() && i % 4 == 1 {
                g.dc.reconnect().await.unwrap();
            }
            g.db2.sync().await;
        }
        g.dc.reconnect().await.unwrap();

        // 2. B1's mailbox: three room keys from A over one Olm session,
        // handed to the machine reversed, then the same page again
        let mut faults = Vec::new();
        let page = g.db1.fetch_page().await.unwrap();
        let n = page.len();
        let mut reversed = page.clone();
        reversed.reverse();
        let r1 = g.db1.process(reversed, false).await.unwrap();
        let r2 = g.db1.process(page.clone(), true).await.unwrap();
        faults.push(json!({
            "page": n, "reversed_processed": r1.processed, "reversed_undecryptable": r1.undecryptable,
            "again_duplicates": r2.skipped_duplicates, "again_processed": r2.processed,
        }));
        // duplicates inside one batch
        g.da.machine.invalidate_outbound_session(&ch).await.unwrap();
        ids.push(g.da.send_text(&ch, &format!("{m} doubled")).await);
        let page = g.db1.fetch_page().await.unwrap();
        let mut doubled = page.clone();
        doubled.extend(page.iter().cloned());
        let r3 = g.db1.process(doubled, true).await.unwrap();
        faults.push(json!({
            "page": page.len(), "doubled_processed": r3.processed,
            "doubled_duplicates": r3.skipped_duplicates, "undecryptable": r3.undecryptable,
        }));

        settle(&mut [&mut g.da, &mut g.db1, &mut g.db2, &mut g.dc]).await;
        let check = verify(&[&g.db1, &g.db2, &g.dc], &ch, &ids).await;
        let undecryptable: usize = [&g.db1, &g.db2, &g.dc].iter().map(|d| d.received.undecryptable).sum();
        let result = json!({
            "socket_drops": drops, "messages": ids.len(), "mailbox_faults": faults,
            "verify": check, "undecryptable": undecryptable,
            "b1_duplicates_dropped": g.db1.received.skipped_duplicates,
        });
        save("chaos_client_socket_drops_and_mailbox_faults", &s, &result);
        assert_eq!(result["verify"]["problems"], json!([]));
        assert_eq!(undecryptable, 0);
        assert_eq!(r1.undecryptable, 0, "reordered Olm messages of one session");
        assert_eq!((r2.processed, r2.skipped_duplicates), (0, n));
        assert_eq!(r3.processed * 2, r3.processed + r3.skipped_duplicates);
        // nothing waits for a key
        for d in [&g.db1, &g.db2, &g.dc] {
            for msg in d.messages(&ch).await {
                assert_ne!(d.decrypt(&msg).await.err(), Some(DecryptError::MissingRoomKey));
            }
        }
    })
    .await;
}
