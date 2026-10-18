//! HTTP to the backend: JSON in, status + body out; 429 is waited out.

use std::time::{Duration, Instant};

use rand::Rng;
use reqwest::{Method, RequestBuilder};
use serde_json::Value;

use crate::metrics;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("{method} {path}: HTTP {status}: {body}")]
    Status {
        method: String,
        path: String,
        status: u16,
        body: String,
    },
    #[error("rate limited too long on {0}")]
    RateLimited(String),
}

/// A response: status and raw body
#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub body: String,
}

impl Reply {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

/// Authenticated (or anonymous) client of one base URL
#[derive(Clone, Debug)]
pub struct Http {
    client: reqwest::Client,
    pub base: String,
    pub token: Option<String>,
    /// Stands in for the client address in the per-IP rate limit buckets
    forwarded_for: String,
}

const MAX_RATE_LIMIT_WAITS: usize = 40;

impl Http {
    pub fn new(base: &str, token: Option<String>) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .connect_timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            base: base.trim_end_matches('/').to_owned(),
            token,
            forwarded_for: format!(
                "10.{}.{}.{}",
                rng.gen_range(0..255),
                rng.gen_range(0..255),
                rng.gen_range(1..255)
            ),
        }
    }

    pub fn with_token(&self, token: &str) -> Self {
        Self {
            token: Some(token.to_owned()),
            ..self.clone()
        }
    }

    /// The same session against another service (autumn)
    pub fn clone_for(&self, base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
            ..self.clone()
        }
    }

    fn build(&self, method: &Method, path: &str, mfa: Option<&str>) -> RequestBuilder {
        let mut b = self
            .client
            .request(method.clone(), format!("{}{path}", self.base))
            .header("X-Forwarded-For", &self.forwarded_for);
        if let Some(t) = &self.token {
            b = b.header("x-session-token", t);
        }
        if let Some(t) = mfa {
            b = b.header("x-mfa-ticket", t);
        }
        b
    }

    /// Any status is a `Reply`; only 429 is retried
    pub async fn raw(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        mfa: Option<&str>,
    ) -> Result<Reply, HttpError> {
        let m = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
        for _ in 0..MAX_RATE_LIMIT_WAITS {
            let mut b = self.build(&m, path, mfa);
            if let Some(body) = body {
                b = b.header("content-type", "application/json").body(body.to_owned());
            }
            let started = Instant::now();
            let sent = async {
                let resp = b.send().await?;
                let status = resp.status().as_u16();
                Ok::<_, reqwest::Error>((status, resp.text().await?))
            }
            .await;
            let (status, text) = match sent {
                Ok(r) => r,
                Err(e) => {
                    metrics::record(method, path, 0, started.elapsed());
                    return Err(e.into());
                }
            };
            metrics::record(method, path, status, started.elapsed());
            if status == 429 {
                wait_rate_limit(&text).await;
                continue;
            }
            return Ok(Reply { status, body: text });
        }
        Err(HttpError::RateLimited(path.to_owned()))
    }

    /// 2xx or an error
    pub async fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Reply, HttpError> {
        let body = body.map(Value::to_string);
        let r = self.raw(method, path, body.as_deref(), None).await?;
        if !r.ok() {
            return Err(HttpError::Status {
                method: method.to_owned(),
                path: path.to_owned(),
                status: r.status,
                body: r.body,
            });
        }
        Ok(r)
    }

    pub async fn get(&self, path: &str) -> Result<Value, HttpError> {
        Ok(self.call("GET", path, None).await?.json())
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value, HttpError> {
        Ok(self.call("POST", path, Some(body)).await?.json())
    }

    pub async fn put(&self, path: &str, body: Option<&Value>) -> Result<Value, HttpError> {
        Ok(self.call("PUT", path, body).await?.json())
    }

    /// Multipart upload (`file` field), autumn
    pub async fn upload(&self, path: &str, bytes: Vec<u8>) -> Result<Value, HttpError> {
        for _ in 0..MAX_RATE_LIMIT_WAITS {
            let part = reqwest::multipart::Part::bytes(bytes.clone()).file_name("blob");
            let form = reqwest::multipart::Form::new().part("file", part);
            let started = Instant::now();
            let resp = self.build(&Method::POST, path, None).multipart(form).send().await?;
            let status = resp.status().as_u16();
            let text = resp.text().await?;
            metrics::record("POST", path, status, started.elapsed());
            match status {
                429 => wait_rate_limit(&text).await,
                200..=299 => return Ok(serde_json::from_str(&text).unwrap_or(Value::Null)),
                _ => {
                    return Err(HttpError::Status {
                        method: "POST".into(),
                        path: path.to_owned(),
                        status,
                        body: text,
                    });
                }
            }
        }
        Err(HttpError::RateLimited(path.to_owned()))
    }

    /// Raw bytes of a download
    pub async fn download(&self, path: &str) -> Result<Vec<u8>, HttpError> {
        for _ in 0..MAX_RATE_LIMIT_WAITS {
            let resp = self.build(&Method::GET, path, None).send().await?;
            let status = resp.status().as_u16();
            if status == 429 {
                wait_rate_limit(&resp.text().await?).await;
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(HttpError::Status {
                    method: "GET".into(),
                    path: path.to_owned(),
                    status,
                    body: resp.text().await?,
                });
            }
            return Ok(resp.bytes().await?.to_vec());
        }
        Err(HttpError::RateLimited(path.to_owned()))
    }
}

async fn wait_rate_limit(body: &str) {
    let ms = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["retry_after"].as_u64())
        .unwrap_or(1_000);
    tokio::time::sleep(Duration::from_millis(ms.min(10_000) + 50)).await;
}
