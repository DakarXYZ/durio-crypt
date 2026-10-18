//! bonfire socket of one session: collects the E2EE doorbells
//! (`E2eeToDevice`, `E2eeDeviceListUpdate`) for the device driver.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug)]
pub(crate) struct Socket {
    events: Arc<Mutex<Vec<Value>>>,
    task: JoinHandle<()>,
}

impl Socket {
    /// Connect and wait for `Ready`
    pub(crate) async fn connect(ws: &str, token: &str) -> Self {
        let url = format!("{}/?version=1&format=json&token={token}", ws.trim_end_matches('/'));
        let (stream, _) = tokio_tungstenite::connect_async(url.as_str())
            .await
            .unwrap_or_else(|e| panic!("bonfire at {ws}: {e}"));
        let (mut tx, mut rx) = stream.split();
        // until Ready, then everything E2EE goes to `events`
        loop {
            match tokio::time::timeout(Duration::from_secs(30), rx.next()).await {
                Ok(Some(Ok(Message::Text(t)))) => {
                    let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                    match v["type"].as_str() {
                        Some("Ready") => break,
                        Some("Error") => panic!("bonfire error: {v}"),
                        _ => {}
                    }
                }
                Ok(Some(Ok(_))) => {}
                other => panic!("bonfire closed before Ready: {other:?}"),
            }
        }
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let task = tokio::spawn(async move {
            let mut ping = tokio::time::interval(Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = ping.tick() => {
                        let p = json!({ "type": "Ping", "data": 0 }).to_string();
                        if tx.send(Message::Text(p.into())).await.is_err() {
                            return;
                        }
                    }
                    m = rx.next() => match m {
                        Some(Ok(Message::Text(t))) => {
                            let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                            if v["type"].as_str().is_some_and(|t| t.starts_with("E2ee")) {
                                sink.lock().unwrap_or_else(|e| e.into_inner()).push(v);
                            }
                        }
                        Some(Ok(_)) => {}
                        _ => return,
                    }
                }
            }
        });
        Self { events, task }
    }

    /// E2EE events received since the last call
    pub(crate) fn take(&self) -> Vec<Value> {
        std::mem::take(&mut *self.events.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.task.abort();
    }
}
