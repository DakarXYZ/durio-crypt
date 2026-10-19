//! A scripted E2EE peer for the clients' end-to-end tests (WEB-08, D7): the
//! testkit devices behind a line protocol on stdin/stdout, so a Playwright
//! test can register users, chat with the app under test, answer its SAS and
//! revoke its session.
//!
//! ```text
//! scripts/testkit-backend.sh peer     # docker run -i … target/debug/examples/peer
//! → {"id":1,"cmd":"register","as":"bob","name":"bob"}
//! ← {"id":1,"ok":true,"result":{"user_id":"…","username":"bob_x#1234",…}}
//! ```
//!
//! Every open device is synced in the background (requests, mailbox, socket
//! events) every 300 ms. Commands run one at a time; a command that panics
//! (a testkit assertion) answers `ok: false` and the peer keeps running.
//! `server: 2` on `register` uses the second backend (`STOAT_API2`).
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::FutureExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use stoat_crypto::proto::{Attachment, MessagePayload, Thumbnail, b64};
use stoat_crypto::{SasHandle, SasState, decrypt_attachment, encrypt_attachment};
use stoat_crypto_testkit::{Account, Device, Stack, payload_text};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

type Shared = Arc<Mutex<Device>>;

#[derive(Default)]
struct Peer {
    stacks: HashMap<u64, Stack>,
    accounts: HashMap<String, Account>,
    devices: Arc<Mutex<HashMap<String, Shared>>>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn arg<'a>(c: &'a Value, name: &str) -> Result<&'a str, String> {
    c[name].as_str().ok_or_else(|| format!("missing \"{name}\""))
}

fn timeout_of(c: &Value) -> Duration {
    Duration::from_millis(c["timeout_ms"].as_u64().unwrap_or(30_000))
}

fn sas_json(state: &SasState) -> Value {
    match state {
        SasState::Requested => json!({ "type": "Requested" }),
        SasState::Incoming => json!({ "type": "Incoming" }),
        SasState::Ready => json!({ "type": "Ready" }),
        SasState::Started => json!({ "type": "Started" }),
        SasState::ShowCodes { emoji, decimals } => json!({
            "type": "ShowCodes",
            "emoji": emoji.iter().map(|e| json!({ "index": e.index, "symbol": e.symbol, "description": e.description })).collect::<Vec<_>>(),
            "decimals": decimals,
        }),
        SasState::Confirmed => json!({ "type": "Confirmed" }),
        SasState::Done => json!({ "type": "Done" }),
        SasState::Cancelled { reason, code, by_us } => json!({
            "type": "Cancelled",
            "reason": format!("{reason:?}"),
            "code": code,
            "by_us": by_us,
        }),
    }
}

impl Peer {
    async fn stack(&mut self, n: u64) -> Result<Stack, String> {
        if let Some(s) = self.stacks.get(&n) {
            return Ok(s.clone());
        }
        let s = if n == 2 {
            Stack::connect_second().await
        } else {
            Stack::connect().await
        };
        let s = s.ok_or_else(|| format!("server {n} not configured (STOAT_API{})", if n == 2 { "2" } else { "" }))?;
        self.stacks.insert(n, s.clone());
        Ok(s)
    }

    fn account(&self, c: &Value, name: &str) -> Result<Account, String> {
        let key = arg(c, name)?;
        self.accounts
            .get(key)
            .cloned()
            .ok_or_else(|| format!("no account \"{key}\""))
    }

    async fn device(&self, c: &Value) -> Result<Shared, String> {
        let key = arg(c, "as")?;
        self.devices
            .lock()
            .await
            .get(key)
            .cloned()
            .ok_or_else(|| format!("no open device \"{key}\""))
    }

    async fn sas(&self, c: &Value) -> Result<SasHandle, String> {
        let flow = arg(c, "flow")?;
        let d = self.device(c).await?;
        let d = d.lock().await;
        d.machine.verification(flow).ok_or_else(|| format!("no flow {flow}"))
    }

    async fn run(&mut self, c: &Value) -> Result<Value, String> {
        let e = |e: stoat_crypto_testkit::HttpError| e.to_string();
        match arg(c, "cmd")? {
            "ping" => Ok(json!("pong")),

            "register" => {
                let stack = self.stack(c["server"].as_u64().unwrap_or(1)).await?;
                let a = stack.register(arg(c, "name")?).await.map_err(e)?;
                let out = json!({
                    "user_id": a.user_id, "username": a.username, "email": a.email,
                    "password": a.password, "session_id": a.session_id, "token": a.token,
                });
                self.accounts.insert(arg(c, "as")?.to_owned(), a);
                Ok(out)
            }

            // a session of an account made elsewhere (in the app under test)
            "adopt" => {
                let stack = self.stack(c["server"].as_u64().unwrap_or(1)).await?;
                let mut a = Account {
                    stack,
                    user_id: String::new(),
                    username: String::new(),
                    email: arg(c, "email")?.to_owned(),
                    password: arg(c, "password")?.to_owned(),
                    token: String::new(),
                    session_id: String::new(),
                };
                a.login().await.map_err(e)?;
                let me = a.http().get("/users/@me").await.map_err(e)?;
                a.username = format!(
                    "{}#{}",
                    me["username"].as_str().unwrap_or_default(),
                    me["discriminator"].as_str().unwrap_or_default()
                );
                let out = json!({ "user_id": a.user_id, "username": a.username, "session_id": a.session_id });
                self.accounts.insert(arg(c, "as")?.to_owned(), a);
                Ok(out)
            }

            // a new session (device) of the account `like`
            "login" => {
                let a = self.account(c, "like")?.new_device().await.map_err(e)?;
                let out = json!({ "user_id": a.user_id, "session_id": a.session_id, "token": a.token });
                self.accounts.insert(arg(c, "as")?.to_owned(), a);
                Ok(out)
            }

            "logout" => {
                let key = arg(c, "as")?;
                self.devices.lock().await.remove(key);
                self.account(c, "as")?.logout().await.map_err(e)?;
                Ok(Value::Null)
            }

            "open" => {
                let a = self.account(c, "as")?;
                let d = Device::open(&a).await;
                let id = d.device().to_owned();
                self.devices
                    .lock()
                    .await
                    .insert(arg(c, "as")?.to_owned(), Arc::new(Mutex::new(d)));
                Ok(json!({ "device_id": id }))
            }

            "close" => {
                self.devices.lock().await.remove(arg(c, "as")?);
                Ok(Value::Null)
            }

            "befriend" => {
                let (from, to) = (self.account(c, "from")?, self.account(c, "to")?);
                from.befriend(&to).await.map_err(e)?;
                Ok(Value::Null)
            }

            // DM of `as` with `with`, encryption switched on by `as` unless `encrypt: false`
            "dm" => {
                let (a, b) = (self.account(c, "as")?, self.account(c, "with")?);
                let dm = a.http().get(&format!("/users/{}/dm", b.user_id)).await.map_err(e)?;
                let id = dm["_id"].as_str().unwrap_or_default().to_owned();
                if c["encrypt"].as_bool() != Some(false) {
                    a.enable_encryption(&id).await.map_err(e)?;
                }
                Ok(json!({ "channel": id }))
            }

            "send" => {
                let (ch, text) = (arg(c, "channel")?, arg(c, "text")?);
                let d = self.device(c).await?;
                let mut d = d.lock().await;
                d.refresh_members(ch).await;
                let id = d.send_text(ch, text).await;
                d.try_sync().await.map_err(e)?;
                Ok(json!({ "message": id }))
            }

            "edit" => {
                let (ch, id, text) = (arg(c, "channel")?, arg(c, "message")?, arg(c, "text")?);
                let d = self.device(c).await?;
                let mut d = d.lock().await;
                d.refresh_members(ch).await;
                let mut p = payload_text(text);
                p.edit_of = Some(id.to_owned());
                p.edit_seq = c["seq"].as_u64().unwrap_or(1);
                let env = d.encrypt(ch, &p).await;
                d.http
                    .call(
                        "PATCH",
                        &format!("/channels/{ch}/messages/{id}"),
                        Some(&json!({ "encrypted": env.to_value() })),
                    )
                    .await
                    .map_err(e)?;
                Ok(Value::Null)
            }

            // an encrypted file (and thumbnail) through autumn `?encrypted=true`
            "send_file" => {
                let ch = arg(c, "channel")?;
                let data = b64::decode(arg(c, "data")?).map_err(|x| x.to_string())?;
                let d = self.device(c).await?;
                let mut d = d.lock().await;
                d.refresh_members(ch).await;
                let autumn = d.http.clone_for(&d.account.stack.config.autumn);
                let (blob, file) = encrypt_attachment(&data);
                let up = autumn.upload("/attachments?encrypted=true", blob).await.map_err(e)?;
                let file_id = up["id"].as_str().unwrap_or_default().to_owned();
                let thumbnail = match c["thumbnail"].as_str() {
                    Some(t) => {
                        let t = b64::decode(t).map_err(|x| x.to_string())?;
                        let (tblob, tfile) = encrypt_attachment(&t);
                        let up = autumn.upload("/attachments?encrypted=true", tblob).await.map_err(e)?;
                        Some(Thumbnail {
                            id: up["id"].as_str().unwrap_or_default().to_owned(),
                            width: c["thumb_width"].as_u64().unwrap_or(64) as u32,
                            height: c["thumb_height"].as_u64().unwrap_or(64) as u32,
                            file: tfile,
                        })
                    }
                    None => None,
                };
                let payload = MessagePayload {
                    content: c["text"].as_str().map(str::to_owned),
                    attachments: vec![Attachment {
                        id: file_id.clone(),
                        name: arg(c, "name")?.to_owned(),
                        content_type: c["content_type"]
                            .as_str()
                            .unwrap_or("application/octet-stream")
                            .to_owned(),
                        size: data.len() as u64,
                        metadata: c.get("metadata").cloned().unwrap_or_else(|| json!({ "type": "File" })),
                        spoiler: false,
                        file,
                        thumbnail,
                    }],
                    ..payload_text("")
                };
                let id = d.send(ch, &payload).await;
                Ok(json!({ "message": id, "file": file_id }))
            }

            "messages" => {
                let d = self.device(c).await?;
                let mut d = d.lock().await;
                let _ = d.try_sync().await;
                Ok(Value::Array(read_messages(&d, arg(c, "channel")?).await))
            }

            // sync until a message of the channel decrypts to `text` (or contains `contains`)
            "wait_text" => {
                let ch = arg(c, "channel")?;
                let deadline = Instant::now() + timeout_of(c);
                let d = self.device(c).await?;
                loop {
                    let found = {
                        let mut d = d.lock().await;
                        let _ = d.try_sync().await;
                        read_messages(&d, ch).await.into_iter().find(|m| {
                            let t = m["text"].as_str().unwrap_or_default();
                            c["text"].as_str().is_some_and(|x| t == x)
                                || c["contains"].as_str().is_some_and(|x| t.contains(x))
                        })
                    };
                    if let Some(m) = found {
                        return Ok(m);
                    }
                    if Instant::now() > deadline {
                        return Err(format!("no message {} in {ch}", c["text"]));
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }

            "verify" => {
                let d = self.device(c).await?;
                let mut d = d.lock().await;
                let _ = d.try_sync().await;
                let h = d
                    .machine
                    .request_verification(arg(c, "user")?, arg(c, "device")?)
                    .await
                    .map_err(|x| x.to_string())?;
                let _ = d.try_sync().await;
                Ok(json!({ "flow": h.flow_id() }))
            }

            // the first flow in state Incoming (a request from the app under test)
            "sas_incoming" => {
                let deadline = Instant::now() + timeout_of(c);
                let d = self.device(c).await?;
                loop {
                    let flow = {
                        let mut d = d.lock().await;
                        let _ = d.try_sync().await;
                        d.machine
                            .verifications()
                            .into_iter()
                            .find(|h| h.state() == SasState::Incoming)
                            .map(|h| h.flow_id().to_owned())
                    };
                    if let Some(flow) = flow {
                        return Ok(json!({ "flow": flow }));
                    }
                    if Instant::now() > deadline {
                        return Err("no incoming verification".into());
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }

            // state of a flow, waiting until its type is one of `until`
            "sas_state" => {
                let until: Vec<String> = c["until"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
                    .unwrap_or_default();
                let deadline = Instant::now() + timeout_of(c);
                let d = self.device(c).await?;
                loop {
                    let h = self.sas(c).await?;
                    {
                        let mut d = d.lock().await;
                        let _ = d.try_sync().await;
                    }
                    let state = sas_json(&h.state());
                    let t = state["type"].as_str().unwrap_or_default().to_owned();
                    if until.is_empty() || until.contains(&t) {
                        return Ok(state);
                    }
                    if Instant::now() > deadline {
                        return Err(format!("flow stayed {state}"));
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }

            // under the device lock: an action must not interleave with the
            // pump's mailbox pass (a MAC arriving during `confirm` was lost)
            "sas" => {
                let h = self.sas(c).await?;
                let d = self.device(c).await?;
                let mut d = d.lock().await;
                match arg(c, "action")? {
                    "accept" => h.accept().await,
                    "start" => h.start().await,
                    "confirm" => h.confirm().await,
                    "mismatch" => h.mismatch().await,
                    "cancel" => h.cancel().await,
                    other => return Err(format!("unknown SAS action {other}")),
                }
                .map_err(|x| x.to_string())?;
                let _ = d.try_sync().await;
                Ok(sas_json(&h.state()))
            }

            "devices" => {
                let d = self.device(c).await?;
                let mut d = d.lock().await;
                let _ = d.try_sync().await;
                let list = d.machine.devices(arg(c, "user")?).await.map_err(|x| x.to_string())?;
                Ok(Value::Array(
                    list.into_iter()
                        .map(|i| json!({ "device_id": i.device_id, "trust": format!("{:?}", i.trust), "deleted": i.deleted }))
                        .collect(),
                ))
            }

            // any API call of an account: {status, body}
            "api" => {
                let a = self.account(c, "as")?;
                let body = c.get("body").map(Value::to_string);
                let r = a
                    .http()
                    .raw(arg(c, "method")?, arg(c, "path")?, body.as_deref(), c["mfa"].as_str())
                    .await
                    .map_err(e)?;
                Ok(json!({ "status": r.status, "body": r.json() }))
            }

            other => Err(format!("unknown command {other}")),
        }
    }
}

/// Encrypted messages of a channel as the device reads them, oldest first
async fn read_messages(d: &Device, channel: &str) -> Vec<Value> {
    let autumn = d.http.clone_for(&d.account.stack.config.autumn);
    let mut out = Vec::new();
    for m in d.messages(channel).await {
        let mut row = json!({ "id": m["_id"], "author": m["author"], "edited": m.get("edited").is_some() });
        match d.decrypt(&m).await {
            Ok(dm) => {
                row["text"] = json!(dm.payload.content.unwrap_or_default());
                row["verification"] = json!(format!("{:?}", dm.verification));
                row["sender_device"] = json!(dm.sender_device);
                let mut files = Vec::new();
                for a in &dm.payload.attachments {
                    let mut f = json!({ "name": a.name, "size": a.size, "content_type": a.content_type });
                    if let Ok(blob) = autumn.download(&format!("/attachments/{}/file.bin", a.id)).await {
                        f["sha256"] = json!(
                            decrypt_attachment(&blob, &a.file)
                                .map(|p| hex(&Sha256::digest(&p)))
                                .ok()
                        );
                    }
                    if let Some(t) = &a.thumbnail
                        && let Ok(blob) = autumn.download(&format!("/attachments/{}/file.bin", t.id)).await
                    {
                        f["thumbnail"] = json!({
                            "width": t.width, "height": t.height,
                            "size": decrypt_attachment(&blob, &t.file).map(|p| p.len()).ok(),
                        });
                    }
                    files.push(f);
                }
                row["attachments"] = Value::Array(files);
            }
            Err(err) => row["error"] = json!(format!("{err:?}")),
        }
        out.push(row);
    }
    out
}

/// Every open device: requests, mailbox and socket events
fn pump(devices: Arc<Mutex<HashMap<String, Shared>>>) {
    tokio::spawn(async move {
        loop {
            let all: Vec<(String, Shared)> = devices
                .lock()
                .await
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for (name, d) in all {
                let mut d = d.lock().await;
                match AssertUnwindSafe(d.try_sync()).catch_unwind().await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => eprintln!("peer: sync of {name}: {err}"),
                    Err(_) => eprintln!("peer: sync of {name} panicked"),
                }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    });
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut peer = Peer::default();
    pump(peer.devices.clone());
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let c: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
        let answer = match AssertUnwindSafe(peer.run(&c)).catch_unwind().await {
            Ok(Ok(result)) => json!({ "id": c["id"], "ok": true, "result": result }),
            Ok(Err(error)) => json!({ "id": c["id"], "ok": false, "error": error }),
            Err(panic) => {
                let msg = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                    .unwrap_or_else(|| "panic".into());
                json!({ "id": c["id"], "ok": false, "error": msg })
            }
        };
        let _ = stdout.write_all(format!("{answer}\n").as_bytes()).await;
        let _ = stdout.flush().await;
    }
}
