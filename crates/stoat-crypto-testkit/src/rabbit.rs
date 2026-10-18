//! T11 without FCM: a test consumer of pushd's outbound FCM routing key,
//! over the RabbitMQ management HTTP API (`STOAT_RABBIT_API`, e.g.
//! `http://user:pass@durio-test-rabbit:15672`). pushd has no FCM credentials
//! on the stack, so nothing else consumes that key.

use std::time::Duration;

use serde_json::{Value, json};

/// pushd's exchange and the routing key it publishes FCM payloads with
/// (`[pushd] exchange`, `[pushd.fcm] queue`)
pub const PUSH_EXCHANGE: &str = "revolt.notifications";
pub const FCM_ROUTING_KEY: &str = "notifications.outbound.fcm";

#[derive(Debug)]
pub struct PushQueue {
    client: reqwest::Client,
    base: String,
    user: String,
    pass: String,
    queue: String,
}

impl PushQueue {
    /// Declare a fresh queue bound to the FCM routing key (durable: RabbitMQ 4
    /// refuses transient non-exclusive queues; [`PushQueue::delete`] removes it); `None` without
    /// `STOAT_RABBIT_API`
    pub async fn bind(name: &str) -> Option<Self> {
        let url = std::env::var("STOAT_RABBIT_API").ok()?;
        let (scheme, rest) = url.split_once("://")?;
        let (cred, host) = rest.split_once('@')?;
        let (user, pass) = cred.split_once(':')?;
        let q = Self {
            client: reqwest::Client::new(),
            base: format!("{scheme}://{}", host.trim_end_matches('/')),
            user: user.to_owned(),
            pass: pass.to_owned(),
            queue: name.to_owned(),
        };
        // pushd declares the exchange when it starts; wait for it
        for _ in 0..30 {
            let r = q
                .call("GET", &format!("/api/exchanges/%2F/{PUSH_EXCHANGE}"), None)
                .await;
            if r.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        q.call(
            "PUT",
            &format!("/api/queues/%2F/{}", q.queue),
            Some(json!({ "durable": true, "auto_delete": false })),
        )
        .await
        .unwrap_or_else(|e| panic!("declare test queue: {e}"));
        q.call(
            "POST",
            &format!("/api/bindings/%2F/e/{PUSH_EXCHANGE}/q/{}", q.queue),
            Some(json!({ "routing_key": FCM_ROUTING_KEY })),
        )
        .await
        .unwrap_or_else(|e| panic!("bind test queue: {e}"));
        Some(q)
    }

    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut b = self
            .client
            .request(m, format!("{}{path}", self.base))
            .basic_auth(&self.user, Some(&self.pass));
        if let Some(body) = body {
            b = b.json(&body);
        }
        let r = b.send().await.map_err(|e| e.to_string())?;
        let status = r.status();
        let text = r.text().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("{status}: {text}"));
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// Messages waiting in the queue, taken off it (JSON payloads)
    pub async fn take(&self) -> Vec<Value> {
        let got = self
            .call(
                "POST",
                &format!("/api/queues/%2F/{}/get", self.queue),
                Some(json!({ "count": 100, "ackmode": "ack_requeue_false", "encoding": "auto" })),
            )
            .await
            .unwrap_or_else(|e| panic!("read test queue: {e}"));
        got.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|m| m["payload"].as_str())
                    .map(|p| serde_json::from_str(p).unwrap_or(Value::Null))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Wait up to `secs` for a payload matching `f`
    pub async fn wait_for(&self, secs: u64, f: impl Fn(&Value) -> bool) -> Option<Value> {
        let mut seen = Vec::new();
        for _ in 0..secs * 2 {
            for p in self.take().await {
                if f(&p) {
                    return Some(p);
                }
                seen.push(p);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        None
    }

    pub async fn delete(self) {
        let _ = self
            .call("DELETE", &format!("/api/queues/%2F/{}", self.queue), None)
            .await;
    }
}
