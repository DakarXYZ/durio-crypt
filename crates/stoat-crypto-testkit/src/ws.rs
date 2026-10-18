//! bonfire socket of one session: collects the events after `Ready` for the
//! device driver (the E2EE doorbells `E2eeToDevice`, `E2eeDeviceListUpdate`,
//! and `Message` as an old client would see it).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug)]
pub(crate) struct Socket {
    events: Arc<Mutex<Vec<Value>>>,
    closed: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl Socket {
    /// Connect and wait for `Ready`
    pub(crate) async fn connect(ws: &str, token: &str) -> Self {
        Self::try_connect(ws, token)
            .await
            .unwrap_or_else(|e| panic!("bonfire at {ws}: {e}"))
    }

    /// Connect and wait for `Ready`; an error if bonfire is not there
    pub(crate) async fn try_connect(ws: &str, token: &str) -> Result<Self, String> {
        let url = format!("{}/?version=1&format=json&token={token}", ws.trim_end_matches('/'));
        let (stream, _) = tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::connect_async(url.as_str()))
            .await
            .map_err(|_| "connect timed out".to_owned())?
            .map_err(|e| e.to_string())?;
        let (mut tx, mut rx) = stream.split();
        // until Ready, then everything else goes to `events`
        loop {
            match tokio::time::timeout(Duration::from_secs(30), rx.next()).await {
                Ok(Some(Ok(Message::Text(t)))) => {
                    let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                    match v["type"].as_str() {
                        Some("Ready") => break,
                        Some("Error") => return Err(format!("bonfire error: {v}")),
                        _ => {}
                    }
                }
                Ok(Some(Ok(_))) => {}
                other => return Err(format!("bonfire closed before Ready: {other:?}")),
            }
        }
        let events = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let (sink, gone) = (events.clone(), closed.clone());
        let task = tokio::spawn(async move {
            let mut ping = tokio::time::interval(Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = ping.tick() => {
                        let p = json!({ "type": "Ping", "data": 0 }).to_string();
                        if tx.send(Message::Text(p.into())).await.is_err() {
                            break;
                        }
                    }
                    m = rx.next() => match m {
                        Some(Ok(Message::Text(t))) => {
                            let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                            let keep = v["type"]
                                .as_str()
                                .is_some_and(|t| t.starts_with("E2ee") || t == "Message");
                            if keep {
                                sink.lock().unwrap_or_else(|e| e.into_inner()).push(v);
                            }
                        }
                        Some(Ok(_)) => {}
                        _ => break,
                    }
                }
            }
            gone.store(true, Ordering::SeqCst);
        });
        Ok(Self { events, closed, task })
    }

    /// Events received since the last call
    pub(crate) fn take(&self) -> Vec<Value> {
        std::mem::take(&mut *self.events.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// The server closed the socket (or it broke)
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.task.abort();
    }
}
