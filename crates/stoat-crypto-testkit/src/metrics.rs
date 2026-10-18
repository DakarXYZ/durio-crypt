//! Latencies of every HTTP call while recording is on (load and chaos
//! scenarios): per route (ids replaced by `{id}`), status and time.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Serialize;

static ON: AtomicBool = AtomicBool::new(false);
static SAMPLES: Mutex<Vec<Sample>> = Mutex::new(Vec::new());

#[derive(Clone, Debug)]
struct Sample {
    route: String,
    /// 0: no response (transport error)
    status: u16,
    ms: f64,
}

/// Start recording (drops what was recorded before)
pub fn start() {
    SAMPLES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ON.store(true, Ordering::SeqCst);
}

/// Stop recording and summarise per route
pub fn stop() -> Summary {
    ON.store(false, Ordering::SeqCst);
    let samples = std::mem::take(&mut *SAMPLES.lock().unwrap_or_else(|e| e.into_inner()));
    Summary::of(&samples)
}

/// Summary so far, recording goes on
pub fn snapshot() -> Summary {
    Summary::of(&SAMPLES.lock().unwrap_or_else(|e| e.into_inner()))
}

pub(crate) fn record(method: &str, path: &str, status: u16, took: Duration) {
    if !ON.load(Ordering::Relaxed) {
        return;
    }
    let sample = Sample {
        route: format!("{method} {}", route(path)),
        status,
        ms: took.as_secs_f64() * 1000.0,
    };
    SAMPLES.lock().unwrap_or_else(|e| e.into_inner()).push(sample);
}

/// `/channels/01J…/messages?limit=5` → `/channels/{id}/messages`
fn route(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    path.split('/')
        .map(|seg| {
            let id_like = seg.len() >= 16 && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            if id_like { "{id}" } else { seg }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RouteStats {
    pub calls: usize,
    /// 2xx
    pub ok: usize,
    /// 429 (waited out and retried by the client)
    pub rate_limited: usize,
    /// other 4xx
    pub client_errors: usize,
    /// 5xx
    pub server_errors: usize,
    /// no response
    pub transport_errors: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Summary {
    pub routes: BTreeMap<String, RouteStats>,
    pub total_calls: usize,
    pub server_errors: usize,
    pub transport_errors: usize,
    pub rate_limited: usize,
}

impl Summary {
    fn of(samples: &[Sample]) -> Self {
        let mut by: BTreeMap<String, Vec<&Sample>> = BTreeMap::new();
        for s in samples {
            by.entry(s.route.clone()).or_default().push(s);
        }
        let mut out = Summary {
            total_calls: samples.len(),
            ..Default::default()
        };
        for (route, list) in by {
            let mut ms: Vec<f64> = list.iter().filter(|s| s.status != 429).map(|s| s.ms).collect();
            ms.sort_by(f64::total_cmp);
            let pct = |p: f64| {
                if ms.is_empty() {
                    0.0
                } else {
                    let i = ((ms.len() as f64 - 1.0) * p).round() as usize;
                    (ms[i] * 10.0).round() / 10.0
                }
            };
            let count = |f: &dyn Fn(u16) -> bool| list.iter().filter(|s| f(s.status)).count();
            let r = RouteStats {
                calls: list.len(),
                ok: count(&|s| (200..300).contains(&s)),
                rate_limited: count(&|s| s == 429),
                client_errors: count(&|s| (400..500).contains(&s) && s != 429),
                server_errors: count(&|s| s >= 500),
                transport_errors: count(&|s| s == 0),
                p50_ms: pct(0.5),
                p95_ms: pct(0.95),
                max_ms: ms.last().copied().map(|m| (m * 10.0).round() / 10.0).unwrap_or(0.0),
            };
            out.server_errors += r.server_errors;
            out.transport_errors += r.transport_errors;
            out.rate_limited += r.rate_limited;
            out.routes.insert(route, r);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_hide_ids() {
        assert_eq!(
            route("/channels/01JABCDEFGHJKMNPQRSTVWXYZ0/messages?limit=5"),
            "/channels/{id}/messages"
        );
        assert_eq!(route("/e2ee/to_device/tk0123456789abcdef01"), "/e2ee/to_device/{id}");
        assert_eq!(route("/e2ee/keys/count"), "/e2ee/keys/count");
    }
}
