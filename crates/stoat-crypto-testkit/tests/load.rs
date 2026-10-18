//! Load scenario against a live backend (`scripts/testkit-backend.sh load`):
//! one group of `STOAT_LOAD_USERS` members (default 50, one device each).
//! Skipped unless `STOAT_LOAD` is set. Numbers go to `out/testkit/load.json`
//! and `docs/load-chaos.md`.
//!
//! Phases: register, open devices (key upload), friends + group, the first
//! send (room key fan-out to every member), everyone receives, a burst
//! (every member sends at once: n fan-outs, n·(n−1) to-device messages, one
//! OTK claimed per pair), steady sends (no fan-out), everyone reads
//! everything, then the one-time keys are topped up again.
#![allow(clippy::print_stderr)]

use std::future::Future;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use stoat_crypto::proto::api::paths;
use stoat_crypto_testkit::{Account, Device, Stack, metrics, payload_text};

/// Run `f` on every device at once; devices come back in order
async fn each<T, F, Fut>(devices: Vec<Device>, f: F) -> (Vec<Device>, Vec<T>)
where
    T: Send + 'static,
    F: Fn(usize, Device) -> Fut,
    Fut: Future<Output = (Device, T)> + Send + 'static,
{
    let handles: Vec<_> = devices
        .into_iter()
        .enumerate()
        .map(|(i, d)| tokio::spawn(f(i, d)))
        .collect();
    let mut out_d = Vec::new();
    let mut out_t = Vec::new();
    for h in handles {
        let (d, t) = h.await.expect("device task");
        out_d.push(d);
        out_t.push(t);
    }
    (out_d, out_t)
}

fn percentiles(mut ms: Vec<f64>) -> Value {
    ms.sort_by(f64::total_cmp);
    let p = |q: f64| {
        if ms.is_empty() {
            0.0
        } else {
            (ms[((ms.len() as f64 - 1.0) * q).round() as usize] * 10.0).round() / 10.0
        }
    };
    json!({ "n": ms.len(), "p50_ms": p(0.5), "p95_ms": p(0.95), "max_ms": p(1.0) })
}

fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 10_000.0).round() / 10.0
}

struct Phases(Vec<(String, f64, usize)>);

impl Phases {
    /// A phase ended; `devices`: to-device messages sent so far (all devices)
    fn done(&mut self, name: &str, started: Instant, devices: &[Device]) {
        let t = ms(started.elapsed());
        let sent: usize = devices.iter().flat_map(|d| d.sent_to_device.values()).sum();
        let before: usize = self.0.iter().map(|p| p.2).sum();
        eprintln!("load: {name}: {t} ms, {} to-device sent", sent - before);
        self.0.push((name.to_owned(), t, sent - before));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "load: scripts/testkit-backend.sh up && load"]
async fn load_group_fanout() {
    if std::env::var("STOAT_LOAD").is_err() {
        eprintln!("STOAT_LOAD not set: skipped");
        return;
    }
    let Some(s) = Stack::connect().await else {
        eprintln!("STOAT_API not set: skipped");
        return;
    };
    let n: usize = std::env::var("STOAT_LOAD_USERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    const STEADY: usize = 5;
    tokio::time::timeout(Duration::from_secs(1_500), run(s, n, STEADY))
        .await
        .expect("load scenario timed out");
}

async fn run(s: Stack, n: usize, steady: usize) {
    metrics::start();
    let mut phases = Phases(Vec::new());
    let total = Instant::now();

    // register
    let t = Instant::now();
    let mut handles = Vec::new();
    for i in 0..n {
        let s = s.clone();
        handles.push(tokio::spawn(
            async move { s.register(&format!("load{i}")).await.unwrap() },
        ));
    }
    let mut accounts: Vec<Account> = Vec::new();
    for h in handles {
        accounts.push(h.await.unwrap());
    }
    phases.done("register", t, &[]);

    // devices: machine, socket, first key upload
    let t = Instant::now();
    let mut handles = Vec::new();
    for a in &accounts {
        let a = a.clone();
        handles.push(tokio::spawn(async move { Device::open(&a).await }));
    }
    let mut devices = Vec::new();
    for h in handles {
        devices.push(h.await.unwrap());
    }
    phases.done("open_devices", t, &devices);

    // friends of the creator, one group of everyone
    let t = Instant::now();
    let creator = accounts[0].clone();
    let mut handles = Vec::new();
    let others: Vec<Account> = accounts[1..].to_vec();
    for other in others {
        let creator = creator.clone();
        handles.push(tokio::spawn(async move { creator.befriend(&other).await.unwrap() }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let members: Vec<&Account> = accounts.iter().skip(1).collect();
    let g = creator.encrypted_group("load", &members).await.unwrap();
    let ids: Vec<String> = accounts.iter().map(|a| a.user_id.clone()).collect();
    for d in &mut devices {
        d.set_members(&g, &ids).await;
    }
    phases.done("friends_and_group", t, &devices);

    // the first send: query n users, claim n−1 OTKs, n−1 room keys
    let t = Instant::now();
    let first = devices[0].send_text(&g, "load first").await;
    phases.done("first_send_fanout", t, &devices);

    // everyone fetches the mailbox and reads it
    let t = Instant::now();
    let first_c = first.clone();
    let g_c = g.clone();
    let (devs, read) = each(devices, move |_, mut d| {
        let (g, first) = (g_c.clone(), first_c.clone());
        async move {
            let started = Instant::now();
            d.sync().await;
            let m = d.http.get(&format!("/channels/{g}/messages/{first}")).await.unwrap();
            let ok = d.decrypt(&m).await.is_ok();
            (d, (ok, ms(started.elapsed())))
        }
    })
    .await;
    devices = devs;
    phases.done("first_receive_all", t, &devices);
    let first_readers = read.iter().filter(|(ok, _)| *ok).count();
    let first_receive = percentiles(read.iter().map(|(_, t)| *t).collect());

    // burst: everyone sends at once (n fan-outs)
    let t = Instant::now();
    let g_c = g.clone();
    let (devs, burst) = each(devices, move |i, mut d| {
        let g = g_c.clone();
        async move {
            let started = Instant::now();
            let r = d.try_send(&g, &payload_text(&format!("load burst {i}"))).await;
            (d, (r.is_ok(), ms(started.elapsed())))
        }
    })
    .await;
    devices = devs;
    phases.done("burst_send", t, &devices);
    let burst_ok = burst.iter().filter(|(ok, _)| *ok).count();
    let burst_send = percentiles(burst.iter().map(|(_, t)| *t).collect());

    // everyone drains n−1 room keys
    let t = Instant::now();
    let (devs, drained) = each(devices, |_, mut d| async move {
        let started = Instant::now();
        let before = d.received.processed;
        d.sync().await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        d.sync().await;
        let got = d.received.processed - before;
        (d, (got, ms(started.elapsed())))
    })
    .await;
    devices = devs;
    let burst_receive_ms = ms(t.elapsed());
    phases.done("burst_receive_all", t, &devices);
    let to_device_received: usize = drained.iter().map(|(n, _)| n).sum();
    let burst_receive = percentiles(drained.iter().map(|(_, t)| *t).collect());

    // steady: Megolm only, no fan-out
    let t = Instant::now();
    let g_c = g.clone();
    let (devs, steady_times) = each(devices, move |i, mut d| {
        let g = g_c.clone();
        async move {
            let mut times = Vec::new();
            for k in 0..steady {
                let started = Instant::now();
                d.send_text(&g, &format!("load steady {i}.{k}")).await;
                times.push(ms(started.elapsed()));
            }
            (d, times)
        }
    })
    .await;
    devices = devs;
    phases.done("steady_send", t, &devices);
    let steady_send = percentiles(steady_times.into_iter().flatten().collect());

    // everyone reads everything
    let t = Instant::now();
    let g_c = g.clone();
    let (devs, reads) = each(devices, move |_, mut d| {
        let g = g_c.clone();
        async move {
            d.sync().await;
            let msgs = d.messages(&g).await;
            let mut ok = 0;
            let mut errors: Vec<String> = Vec::new();
            let started = Instant::now();
            for m in &msgs {
                match d.decrypt(m).await {
                    Ok(x) if x.is_clean() => ok += 1,
                    Ok(x) => errors.push(format!("unclean {:?}", x.verification)),
                    Err(e) => errors.push(e.code().to_owned()),
                }
            }
            let per_msg = ms(started.elapsed()) / msgs.len().max(1) as f64;
            (d, (msgs.len(), ok, errors, per_msg))
        }
    })
    .await;
    devices = devs;
    phases.done("read_all", t, &devices);
    let expected = 1 + n + n * steady;
    let read_ok: usize = reads.iter().map(|r| r.1).sum();
    let read_errors: Vec<String> = reads.iter().flat_map(|r| r.2.clone()).collect();
    let decrypt_per_msg = percentiles(reads.iter().map(|r| r.3).collect());
    // Megolm sessions per sender (a rotation shows as a second one)
    let mut sessions = std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    for m in devices[0].messages(&g).await {
        sessions
            .entry(m["author"].as_str().unwrap_or_default().to_owned())
            .or_default()
            .insert(m["encrypted"]["session_id"].as_str().unwrap_or_default().to_owned());
    }
    let senders_with_two_sessions = sessions.values().filter(|s| s.len() > 1).count();

    // OTKs: n−1 claimed from every device in the burst; the sync above topped up
    let t = Instant::now();
    let (devs, counts) = each(devices, |_, mut d| async move {
        d.sync().await;
        let c = d.http.get(paths::KEYS_COUNT).await.unwrap();
        let count = c["one_time_key_counts"]["signed_curve25519"].as_u64().unwrap_or(0);
        (d, count)
    })
    .await;
    devices = devs;
    phases.done("otk_check", t, &devices);
    let topped_up = counts.iter().filter(|c| **c == 50).count();

    // state per device (CR-22) and HTTP latencies
    let mut agg = json!({
        "mailbox_processed": 0, "mailbox_duplicates": 0, "mailbox_undecryptable": 0,
        "decrypt_ok": 0, "decrypt_errors": {}, "request_failures": 0,
        "undelivered_retrying": 0, "undelivered_gave_up": 0, "dirty_users": 0,
    });
    for d in &devices {
        let r = d.report().await;
        for (k, path) in [
            ("mailbox_processed", "/mailbox/processed"),
            ("mailbox_duplicates", "/mailbox/duplicates"),
            ("mailbox_undecryptable", "/mailbox/undecryptable"),
            ("decrypt_ok", "/decryption/ok"),
            ("undelivered_retrying", "/undelivered_devices/retrying"),
            ("undelivered_gave_up", "/undelivered_devices/gave_up"),
            ("dirty_users", "/users/dirty"),
        ] {
            let v = agg[k].as_u64().unwrap_or(0) + r.pointer(path).and_then(Value::as_u64).unwrap_or(0);
            agg[k] = json!(v);
        }
        if let Some(errs) = r["decryption"]["errors"].as_object() {
            for (code, c) in errs {
                let v = agg["decrypt_errors"][code].as_u64().unwrap_or(0) + c.as_u64().unwrap_or(0);
                agg["decrypt_errors"][code] = json!(v);
            }
        }
        let f = r["recent_request_failures"].as_array().map_or(0, Vec::len) as u64;
        agg["request_failures"] = json!(agg["request_failures"].as_u64().unwrap_or(0) + f);
    }
    let mut sent_types = std::collections::BTreeMap::<String, usize>::new();
    let mut received_types = std::collections::BTreeMap::<String, usize>::new();
    for d in &devices {
        for (k, v) in &d.sent_to_device {
            *sent_types.entry(k.clone()).or_default() += v;
        }
        for (k, v) in &d.received_types {
            *received_types.entry(k.clone()).or_default() += v;
        }
    }
    let http = metrics::stop();
    let report = json!({
        "users": n,
        "devices": devices.len(),
        "group_members": n,
        "steady_messages_per_member": steady,
        "total_ms": ms(total.elapsed()),
        "phases": phases.0.iter().map(|(k, v, td)| json!({ "phase": k, "ms": v, "to_device_sent": td })).collect::<Vec<_>>(),
        "first_send": { "readers": first_readers, "receive_per_device": first_receive },
        "burst": {
            "sent_ok": burst_ok,
            "send_per_device": burst_send,
            "to_device_received": to_device_received,
            // device 0 shared its session in the first send already
            "to_device_expected": (n - 1) * (n - 1),
            "to_device_per_s": (to_device_received as f64 / (burst_receive_ms / 1000.0)).round(),
            "receive_per_device": burst_receive,
        },
        "steady_send": steady_send,
        "senders_with_more_than_one_session": senders_with_two_sessions,
        "read": {
            "expected_per_device": expected,
            "decrypted_clean": read_ok,
            "expected_total": expected * n,
            "errors": read_errors.len(),
            "error_codes": read_errors.iter().take(20).collect::<Vec<_>>(),
            "decrypt_ms_per_message": decrypt_per_msg,
        },
        "otk": { "topped_up_to_50": topped_up, "counts": counts },
        "device_reports": agg,
        "to_device_sent_by_type": sent_types,
        "to_device_received_by_type": received_types,
        "http": http,
    });
    let out = s.config.out.clone().unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&out);
    let _ = std::fs::write(out.join("load.json"), serde_json::to_string_pretty(&report).unwrap());
    eprintln!("{}", serde_json::to_string_pretty(&report).unwrap());

    assert_eq!(first_readers, n, "not everyone read the first message");
    assert_eq!(burst_ok, n, "sends failed in the burst");
    assert_eq!(read_ok, expected * n, "messages not decrypted cleanly: {read_errors:?}");
    assert_eq!(agg["mailbox_undecryptable"], 0);
    assert_eq!(http.server_errors, 0, "5xx under load");
    assert_eq!(topped_up, n, "one-time keys not topped up: {counts:?}");
}
