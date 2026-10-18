//! The wasm surface driven the way JavaScript drives it — methods looked up
//! by their JS names on the wrapper objects, arguments and results as plain
//! JS values — against the fake server (CR-14). Runs in Node:
//! `scripts/build-wasm.sh test` (wasm-bindgen-test-runner).

#![cfg(target_arch = "wasm32")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use js_sys::{Array, Function, Promise, Reflect, Uint8Array};
use serde::Serialize;
use serde_json::{Value, json};
use stoat_crypto_fakeserver::{Auth, FakeServer, Server};
use stoat_crypto_wasm as w;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::wasm_bindgen_test;

fn ulid(tag: &str) -> String {
    format!("01K{}", tag.repeat(26)).chars().take(26).collect()
}

fn dev(tag: &str) -> String {
    format!("01KD{}", tag.repeat(26)).chars().take(26).collect()
}

fn js<T: Serialize>(v: &T) -> JsValue {
    v.serialize(&serde_wasm_bindgen::Serializer::json_compatible()).unwrap()
}

fn val(v: JsValue) -> Value {
    serde_wasm_bindgen::from_value(v).unwrap()
}

fn s(v: &str) -> JsValue {
    JsValue::from_str(v)
}

fn bytes(v: &[u8]) -> JsValue {
    Uint8Array::from(v).into()
}

/// `obj[method](...args)`, awaited if it returns a promise
async fn invoke(obj: &JsValue, method: &str, args: &[JsValue]) -> Result<JsValue, JsValue> {
    let f: Function = Reflect::get(obj, &s(method))?.dyn_into()?;
    let r = f.apply(obj, &args.iter().collect::<Array>())?;
    match r.dyn_into::<Promise>() {
        Ok(p) => JsFuture::from(p).await,
        Err(r) => Ok(r),
    }
}

async fn ok(obj: &JsValue, method: &str, args: &[JsValue]) -> JsValue {
    match invoke(obj, method, args).await {
        Ok(v) => v,
        Err(e) => panic!("{method}: {}", describe(&e)),
    }
}

/// `(name, code, message)` of a thrown error
fn error_parts(e: &JsValue) -> (String, String, String) {
    let get = |k: &str| {
        Reflect::get(e, &s(k))
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default()
    };
    (get("name"), get("code"), get("message"))
}

fn describe(e: &JsValue) -> String {
    let (name, code, message) = error_parts(e);
    format!("{name}/{code}: {message}")
}

/// The call fails with a `StoatCryptoError` of `code`; returns its message
async fn fails(obj: &JsValue, method: &str, args: &[JsValue], code: &str) -> String {
    let e = invoke(obj, method, args)
        .await
        .err()
        .unwrap_or_else(|| panic!("{method} succeeded"));
    assert!(e.is_instance_of::<js_sys::Error>(), "{method}: not an Error");
    let (name, got, message) = error_parts(&e);
    assert_eq!(
        (name.as_str(), got.as_str()),
        ("StoatCryptoError", code),
        "{method}: {message}"
    );
    message
}

fn store_memory() -> JsValue {
    js(&json!({ "kind": "memory" }))
}

struct Client {
    m: JsValue,
    auth: Auth,
    server: Server,
}

impl Client {
    async fn open(server: &Server, user: &str, device: &str) -> Self {
        let auth = Auth::new(ulid(user), dev(device));
        let m = JsFuture::from(w::CryptoMachine::open(
            auth.user.clone(),
            auth.device.clone(),
            store_memory(),
        ))
        .await
        .map_err(|e| describe(&e))
        .unwrap();
        let timing = json!({
            "keyRequestDelayMs": 0, "toDeviceRetryMs": 60000, "toDeviceRetryAttempts": 8, "ownRetryMs": 0
        });
        ok(&m, "setTiming", &[js(&timing)]).await;
        let c = Self {
            m,
            auth,
            server: server.clone(),
        };
        c.sync().await;
        c
    }

    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, String) {
        let r = self.server.lock().unwrap().handle(&self.auth, method, path, body);
        (r.status, r.body.to_string())
    }

    async fn run(&self, reqs: JsValue) -> bool {
        let reqs = val(reqs);
        let reqs = reqs.as_array().unwrap();
        for r in reqs {
            let body: Value = serde_json::from_str(r["body"].as_str().unwrap()).unwrap();
            let (status, resp) = self.call(r["method"].as_str().unwrap(), r["path"].as_str().unwrap(), Some(&body));
            let (id, kind) = (s(r["id"].as_str().unwrap()), s(r["kind"].as_str().unwrap()));
            if status < 300 {
                ok(&self.m, "markRequestSent", &[id, kind, s(&resp)]).await;
            } else {
                let _ = invoke(&self.m, "markRequestFailed", &[id, kind, JsValue::from(status)]).await;
            }
        }
        !reqs.is_empty()
    }

    /// Request passes and mailbox until nothing moves
    async fn sync(&self) {
        for _ in 0..32 {
            let sent = self.run(ok(&self.m, "outgoingRequests", &[]).await).await;
            let (_, page) = self.call("GET", "/e2ee/to_device?limit=100", None);
            let r = val(ok(&self.m, "receiveToDevice", &[s(&page)]).await);
            let ack = r["ackIds"].as_array().unwrap();
            if !ack.is_empty() {
                let body = json!({ "ids": ack });
                assert_eq!(self.call("POST", "/e2ee/to_device/ack", Some(&body)).0, 204);
                ok(&self.m, "markAckSent", &[js(&r["ackIds"])]).await;
            }
            let (_, counts) = self.call("GET", "/e2ee/keys/count", None);
            ok(&self.m, "receiveOtkCounts", &[s(&counts)]).await;
            if !sent && r["fetched"] == 0 {
                return;
            }
        }
        panic!("sync does not converge");
    }

    async fn send(&self, channel: &str, text: &str, ts: f64) -> String {
        while self.run(ok(&self.m, "prepareSend", &[s(channel)]).await).await {}
        let payload = w::text_payload(text.into(), "AAAAAAAAAAAAAAAAAAAAAA".into(), ts).unwrap();
        let envelope = ok(&self.m, "encrypt", &[s(channel), s(&payload)]).await;
        let envelope: Value = serde_json::from_str(&envelope.as_string().unwrap()).unwrap();
        self.server
            .lock()
            .unwrap()
            .message_send(&self.auth, channel, envelope, vec![])
            .unwrap()
    }

    /// Messages of a channel as the SDK would hand them in
    fn incoming(&self, channel: &str) -> Vec<Value> {
        self.server
            .lock()
            .unwrap()
            .messages(channel)
            .into_iter()
            .map(|m| {
                json!({
                    "messageId": m.id, "channelId": m.channel, "author": m.author,
                    "envelopeJson": m.encrypted.to_string(), "replies": m.replies, "timestamp": m.ts
                })
            })
            .collect()
    }
}

async fn dm(a: &Client, b: &Client, name: &str) -> String {
    let id = ulid(name);
    let members = vec![a.auth.user.clone(), b.auth.user.clone()];
    let refs: Vec<&str> = members.iter().map(String::as_str).collect();
    a.server.lock().unwrap().channel_set_members(&id, &refs);
    for c in [a, b] {
        ok(&c.m, "setChannelMembers", &[s(&id), js(&members), JsValue::UNDEFINED]).await;
    }
    id
}

fn content(r: &Value) -> String {
    assert_eq!(r["type"], "Decrypted", "{r}");
    let p: Value = serde_json::from_str(r["message"]["payloadJson"].as_str().unwrap()).unwrap();
    p["content"].as_str().unwrap().to_owned()
}

#[wasm_bindgen_test]
async fn dm_roundtrip_and_batch() {
    let server = FakeServer::new().shared();
    let a = Client::open(&server, "A", "A1").await;
    let b = Client::open(&server, "B", "B1").await;
    let ch = dm(&a, &b, "C").await;
    a.send(&ch, "hello", 1.0).await;
    a.send(&ch, "again", 2.0).await;
    b.sync().await;

    let mut messages = b.incoming(&ch);
    // an envelope from a newer client is a value, not an exception
    let mut newer = messages[0].clone();
    newer["envelopeJson"] = Value::String(newer["envelopeJson"].as_str().unwrap().replace("\"v\":1", "\"v\":2"));
    messages.insert(1, newer);
    let results = val(ok(&b.m, "decryptBatch", &[js(&messages)]).await);
    let results = results.as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(content(&results[0]), "hello");
    assert_eq!(results[1]["type"], "Failed");
    assert_eq!(results[1]["kind"], "UpdateApp");
    assert_eq!(results[1]["error"], "UnsupportedVersion");
    assert_eq!(results[1]["withheldReason"], Value::Null);
    assert_eq!(content(&results[2]), "again");
    let message = &results[0]["message"];
    assert_eq!(message["senderUser"], a.auth.user.as_str());
    assert_eq!(message["senderDevice"], a.auth.device.as_str());
    assert_eq!(message["verification"], "Unverified");
    assert_eq!(message["isClean"], true);
    // numbers, never BigInt
    assert!(message["messageIndex"].is_u64());

    // the sender reads its own echo; one message at a time
    let own = val(ok(&a.m, "decrypt", &[js(&a.incoming(&ch)[0])]).await);
    assert_eq!(content(&own), "hello");

    // devices and keys as plain objects
    let devices = val(ok(&a.m, "devices", &[s(&b.auth.user)]).await);
    assert_eq!(devices[0]["deviceId"], b.auth.device.as_str());
    assert_eq!(devices[0]["trust"], "Unverified");
    let keys = val(ok(&a.m, "identityKeys", &[]).await);
    assert!(keys["ed25519"].as_str().unwrap().len() > 40);
    assert_eq!(val(ok(&a.m, "userId", &[]).await), a.auth.user.as_str());
    let wake = val(ok(&a.m, "wakeupInMs", &[]).await);
    assert!(wake.is_null() || wake.is_number());
    assert!(
        val(ok(&a.m, "undeliveredDevices", &[]).await)
            .as_array()
            .unwrap()
            .is_empty()
    );
}

/// Every core error reaches JS as a `StoatCryptoError` with the FFI code
#[wasm_bindgen_test]
async fn errors_carry_ffi_codes() {
    let server = FakeServer::new().shared();
    let a = Client::open(&server, "A", "A1").await;

    // open: bad ids, bad store configs
    let open = |user: String, store: JsValue| async move {
        JsFuture::from(w::CryptoMachine::open(user, dev("A9"), store)).await
    };
    let e = open("not-a-ulid".into(), store_memory()).await.unwrap_err();
    assert_eq!(error_parts(&e).1, "InvalidId");
    let short_key = js(&json!({"kind": "indexedDb", "name": "x"}));
    Reflect::set(&short_key, &s("key"), &bytes(&[7; 16])).unwrap();
    let e = open(ulid("A"), short_key).await.unwrap_err();
    assert_eq!(error_parts(&e).1, "InvalidInput");
    let e = open(ulid("A"), js(&json!({"kind": "sqlite"}))).await.unwrap_err();
    assert_eq!(error_parts(&e).1, "InvalidInput");

    fails(
        &a.m,
        "encrypt",
        &[
            s(&ulid("Z")),
            s(&w::text_payload("x".into(), "AAAAAAAAAAAAAAAAAAAAAA".into(), 1.0).unwrap()),
        ],
        "UnknownChannel",
    )
    .await;
    fails(&a.m, "encrypt", &[s(&ulid("Z")), s("{\"v\":1}")], "InvalidPayload").await;
    fails(&a.m, "receiveToDevice", &[s("garbage")], "InvalidResponse").await;
    fails(&a.m, "receiveOtkCounts", &[s("[]")], "InvalidResponse").await;
    fails(
        &a.m,
        "markRequestSent",
        &[s("id"), s("NoSuchKind"), s("{}")],
        "InvalidInput",
    )
    .await;
    fails(
        &a.m,
        "setServerLimits",
        &[js(&json!({"maxToDeviceBatch": "many"}))],
        "InvalidInput",
    )
    .await;
    fails(
        &a.m,
        "setTiming",
        &[js(
            &json!({"keyRequestDelayMs": -1, "toDeviceRetryMs": 0, "toDeviceRetryAttempts": 1}),
        )],
        "InvalidInput",
    )
    .await;
    fails(&a.m, "decrypt", &[js(&json!({"messageId": "x"}))], "InvalidInput").await;
    fails(&a.m, "devices", &[s("nope")], "InvalidId").await;
    fails(
        &a.m,
        "requestVerification",
        &[s(&ulid("Q")), s(&dev("Q1"))],
        "UnknownDevice",
    )
    .await;
    fails(&a.m, "restoreBackup", &[s("{}")], "NoBackup").await;
    fails(&a.m, "rotateBackup", &[], "NoRecovery").await;
    fails(
        &a.m,
        "exportRoomKeys",
        &[bytes(b""), js(&Vec::<String>::new())],
        "PassphraseRequired",
    )
    .await;
    fails(
        &a.m,
        "importRoomKeys",
        &[s("not a key file"), bytes(b"pw")],
        "InvalidKeyFile",
    )
    .await;
    fails(
        &a.m,
        "unlockBackup",
        &[bytes(&[0xff, 0xfe]), js(&json!({}))],
        "InvalidInput",
    )
    .await;
    // O-3: trust comes from SAS only
    fails(
        &a.m,
        "setDeviceTrust",
        &[s(&a.auth.user), s(&dev("B1")), s("Verified")],
        "InvalidInput",
    )
    .await;
    // the core answers an unknown device here with InvalidId (as on Android)
    fails(
        &a.m,
        "setDeviceTrust",
        &[s(&ulid("Q")), s(&dev("Q1")), s("Blocked")],
        "InvalidId",
    )
    .await;

    // MFA: a second backup version is refused with a typed error
    let setup = val(ok(&a.m, "createRecovery", &[JsValue::UNDEFINED]).await);
    assert!(setup["recoveryKey"].is_string());
    assert_eq!(
        w::recovery_key_check(setup["recoveryKey"].as_str().unwrap().as_bytes().to_vec()).unwrap(),
        "Valid"
    );
    a.run(js(&[&setup["request"]])).await;
    let again = val(ok(&a.m, "createRecovery", &[JsValue::UNDEFINED]).await);
    let r = &again["request"];
    let body: Value = serde_json::from_str(r["body"].as_str().unwrap()).unwrap();
    let (status, _) = a.call(r["method"].as_str().unwrap(), r["path"].as_str().unwrap(), Some(&body));
    fails(
        &a.m,
        "markRequestFailed",
        &[
            s(r["id"].as_str().unwrap()),
            s(r["kind"].as_str().unwrap()),
            JsValue::from(status),
        ],
        "MfaRequired",
    )
    .await;
    let status = val(ok(&a.m, "backupStatus", &[]).await);
    assert_eq!(status["enabled"], true);
    assert!(status["keysTotal"].is_number());

    // free functions
    assert_eq!(w::recovery_key_check(b"correct horse".to_vec()).unwrap(), "NotAKey");
    let e = w::recovery_key_check(vec![0xff]).unwrap_err();
    assert_eq!(error_parts(&e).1, "InvalidInput");
    let e = w::payload_file_ids("{\"v\":1}".into()).unwrap_err();
    assert_eq!(error_parts(&e).1, "InvalidPayload");
    let e = w::text_payload("x".into(), "n".into(), -1.0).unwrap_err();
    assert_eq!(error_parts(&e).1, "InvalidInput");
    assert_eq!(w::payload_version(), 1);
    assert_eq!(w::core_version(), env!("CARGO_PKG_VERSION"));
    let names = w::indexeddb_names("durio-e2ee-abc".into());
    assert_eq!(
        names,
        [
            "durio-e2ee-abc::matrix-sdk-crypto",
            "durio-e2ee-abc::matrix-sdk-crypto-meta"
        ]
    );
    let table = val(w::sas_emoji_table().unwrap());
    assert_eq!(table.as_array().unwrap().len(), 64);
    assert_eq!(table[0]["index"], 0);
}

/// Thrown errors never quote keys, passphrases, plaintext or the input
#[wasm_bindgen_test]
async fn no_secrets_in_thrown_errors() {
    let server = FakeServer::new().shared();
    let a = Client::open(&server, "A", "A1").await;
    let b = Client::open(&server, "B", "B1").await;
    let ch = dm(&a, &b, "C").await;
    a.send(&ch, "kept secret text", 1.0).await;
    let export = val(ok(
        &a.m,
        "exportRoomKeys",
        &[bytes(b"right passphrase"), js(&Vec::<String>::new())],
    )
    .await);

    let secret = "hunter2-SECRET-7f3a";
    let mut messages = vec![
        fails(
            &b.m,
            "importRoomKeys",
            &[s(export["data"].as_str().unwrap()), bytes(secret.as_bytes())],
            "WrongPassphrase",
        )
        .await,
        fails(
            &b.m,
            "importRoomKeys",
            &[s(secret), bytes(secret.as_bytes())],
            "InvalidKeyFile",
        )
        .await,
        fails(
            &b.m,
            "receiveToDevice",
            &[s(&format!("{{\"messages\": \"{secret}\"}}"))],
            "InvalidResponse",
        )
        .await,
        fails(
            &b.m,
            "encrypt",
            &[s(&ch), s(&format!("{{\"v\":1,\"content\":\"{secret}\"}}"))],
            "InvalidPayload",
        )
        .await,
        fails(
            &b.m,
            "markRequestSent",
            &[s(secret), s(secret), s(secret)],
            "InvalidInput",
        )
        .await,
        fails(
            &b.m,
            "decrypt",
            &[js(&json!({"messageId": secret, "envelopeJson": secret}))],
            "InvalidInput",
        )
        .await,
        fails(
            &b.m,
            "unlockBackup",
            &[bytes(secret.as_bytes()), js(&json!({"defaultKey": secret}))],
            "InvalidInput",
        )
        .await,
        fails(
            &b.m,
            "setDeviceTrust",
            &[s(secret), s(secret), s(secret)],
            "InvalidInput",
        )
        .await,
    ];
    let e = w::decrypt_attachment(secret.as_bytes(), secret.into()).unwrap_err();
    messages.push(error_parts(&e).2);
    let e = JsFuture::from(w::CryptoMachine::open(secret.into(), secret.into(), store_memory()))
        .await
        .unwrap_err();
    messages.push(error_parts(&e).2);
    let key = val(ok(&a.m, "identityKeys", &[]).await);
    for m in &messages {
        assert!(!m.is_empty());
        for needle in [
            secret,
            "kept secret text",
            "right passphrase",
            key["ed25519"].as_str().unwrap(),
        ] {
            assert!(!m.contains(needle), "{m}");
        }
    }
}

/// CR-22: the report holds counts, states and codes — not text, keys,
/// session ids, the other user's id or ciphertext
#[wasm_bindgen_test]
async fn debug_report_hygiene() {
    let server = FakeServer::new().shared();
    let a = Client::open(&server, "A", "A1").await;
    let b = Client::open(&server, "B", "B1").await;
    let ch = dm(&a, &b, "C").await;
    a.send(&ch, "report must not show this", 1.0).await;
    b.sync().await;
    let got = val(ok(&b.m, "decrypt", &[js(&b.incoming(&ch)[0])]).await);
    let session = got["message"]["sessionId"].as_str().unwrap().to_owned();
    let envelope: Value = serde_json::from_str(b.incoming(&ch)[0]["envelopeJson"].as_str().unwrap()).unwrap();
    let ciphertext = envelope["ciphertext"].as_str().unwrap();

    let report = ok(&b.m, "debugReport", &[]).await.as_string().unwrap();
    let parsed: Value = serde_json::from_str(&report).unwrap();
    assert!(parsed.is_object());
    let keys_a = val(ok(&a.m, "identityKeys", &[]).await);
    let keys_b = val(ok(&b.m, "identityKeys", &[]).await);
    for needle in [
        "report must not show this",
        session.as_str(),
        &ciphertext[..32],
        a.auth.user.as_str(),
        a.auth.device.as_str(),
        keys_a["curve25519"].as_str().unwrap(),
        keys_b["curve25519"].as_str().unwrap(),
        keys_b["ed25519"].as_str().unwrap(),
    ] {
        assert!(!report.contains(needle), "report leaks {needle}");
    }
}

/// CR-21 through the wasm surface; imported keys are `Unauthenticated`
#[wasm_bindgen_test]
async fn key_export_and_import() {
    let server = FakeServer::new().shared();
    let a = Client::open(&server, "A", "A1").await;
    let b = Client::open(&server, "B", "B1").await;
    let ch = dm(&a, &b, "C").await;
    b.send(&ch, "kept", 1.0).await;
    a.sync().await;

    let export = val(ok(
        &a.m,
        "exportRoomKeys",
        &[bytes(b"pass phrase"), js(&Vec::<String>::new())],
    )
    .await);
    assert_eq!(export["sessions"], 1);
    let data = export["data"].as_str().unwrap();

    let a2 = Client::open(&server, "A", "A2").await;
    let before = val(ok(&a2.m, "decrypt", &[js(&a2.incoming(&ch)[0])]).await);
    assert_eq!(before["kind"], "WaitingForKey");
    let r = val(ok(&a2.m, "importRoomKeys", &[s(data), bytes(b"pass phrase")]).await);
    assert_eq!(
        (&r["total"], &r["imported"], &r["skipped"]),
        (&json!(1), &json!(1), &json!(0))
    );
    assert_eq!(r["roomKeys"][0]["channelId"], ch.as_str());
    let got = val(ok(&a2.m, "decrypt", &[js(&a2.incoming(&ch)[0])]).await);
    assert_eq!(content(&got), "kept");
    assert_eq!(got["message"]["verification"], "Unauthenticated");
}

#[wasm_bindgen_test]
async fn sas_through_handles() {
    let server = FakeServer::new().shared();
    let a = Client::open(&server, "A", "A1").await;
    let b = Client::open(&server, "B", "B1").await;
    dm(&a, &b, "C").await;
    a.sync().await;
    b.sync().await;

    let ha = ok(&a.m, "requestVerification", &[s(&b.auth.user), s(&b.auth.device)]).await;
    assert_eq!(val(ok(&ha, "state", &[]).await)["type"], "Requested");
    let all = ok(&a.m, "verifications", &[]).await;
    assert_eq!(Array::from(&all).length(), 1);
    a.sync().await;
    b.sync().await;
    let flow = ok(&ha, "flowId", &[]).await;
    let hb = ok(&b.m, "verification", &[flow]).await;
    assert!(!hb.is_undefined(), "incoming flow");
    assert_eq!(val(ok(&hb, "state", &[]).await)["type"], "Incoming");
    assert_eq!(val(ok(&hb, "otherUserId", &[]).await), a.auth.user.as_str());
    ok(&hb, "accept", &[]).await;
    b.sync().await;
    a.sync().await;
    assert_eq!(val(ok(&ha, "state", &[]).await)["type"], "Ready");
    ok(&ha, "start", &[]).await;
    for _ in 0..3 {
        a.sync().await;
        b.sync().await;
    }
    let (sa, sb) = (val(ok(&ha, "state", &[]).await), val(ok(&hb, "state", &[]).await));
    assert_eq!(sa["type"], "ShowCodes", "{sa}");
    assert_eq!(sa["emoji"].as_array().unwrap().len(), 7);
    assert_eq!(sa["decimals"].as_array().unwrap().len(), 3);
    assert_eq!((&sa["emoji"], &sa["decimals"]), (&sb["emoji"], &sb["decimals"]));
    ok(&ha, "confirm", &[]).await;
    ok(&hb, "confirm", &[]).await;
    for _ in 0..3 {
        a.sync().await;
        b.sync().await;
    }
    assert_eq!(val(ok(&ha, "state", &[]).await)["type"], "Done");
    assert_eq!(val(ok(&hb, "state", &[]).await)["type"], "Done");
    let devices = val(ok(&a.m, "devices", &[s(&b.auth.user)]).await);
    assert_eq!(devices[0]["trust"], "Verified");
    // a cancelled flow is a value with a reason
    let h2 = ok(&b.m, "requestVerification", &[s(&a.auth.user), s(&a.auth.device)]).await;
    ok(&h2, "cancel", &[]).await;
    let st = val(ok(&h2, "state", &[]).await);
    assert_eq!(
        (&st["type"], &st["reason"], &st["byUs"]),
        (&json!("Cancelled"), &json!("User"), &json!(true))
    );
    fails(&h2, "confirm", &[], "VerificationNotActive").await;
}

#[wasm_bindgen_test]
fn attachments_stream_and_one_shot() {
    let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let mut enc = w::AttachmentEncryptor::new();
    let mut blob = Vec::new();
    for chunk in data.chunks(32 * 1024) {
        blob.extend(enc.update(chunk.to_vec()).unwrap());
    }
    assert_eq!(enc.size().unwrap(), data.len() as f64);
    let file = enc.finish().unwrap();
    assert_eq!(error_parts(&enc.finish().unwrap_err()).1, "AlreadyFinished");
    assert_ne!(blob, data);

    let mut verifier = w::AttachmentVerifier::new(file.clone()).unwrap();
    for chunk in blob.chunks(10_000) {
        verifier.update(chunk).unwrap();
    }
    let mut dec = verifier.finish().unwrap();
    let mut plain = Vec::new();
    for chunk in blob.chunks(7_777) {
        plain.extend(dec.update(chunk.to_vec()));
    }
    assert_eq!(plain, data);

    // a swapped blob gives no decryptor
    let mut swapped = blob.clone();
    swapped[0] ^= 1;
    let mut verifier = w::AttachmentVerifier::new(file.clone()).unwrap();
    verifier.update(&swapped).unwrap();
    assert_eq!(error_parts(&verifier.finish().unwrap_err()).1, "AttachmentHashMismatch");
    assert_eq!(
        error_parts(&w::decrypt_attachment(&swapped, file.clone()).unwrap_err()).1,
        "AttachmentHashMismatch"
    );
    assert_eq!(
        error_parts(&w::AttachmentVerifier::new("{}".into()).unwrap_err()).1,
        "InvalidAttachment"
    );

    let thumb = w::encrypt_attachment(b"thumbnail").unwrap();
    let ciphertext: Uint8Array = Reflect::get(&thumb, &s("ciphertext")).unwrap().dyn_into().unwrap();
    let file_json = Reflect::get(&thumb, &s("fileJson")).unwrap().as_string().unwrap();
    assert_eq!(
        w::decrypt_attachment(&ciphertext.to_vec(), file_json.clone()).unwrap(),
        b"thumbnail"
    );

    let file: Value = serde_json::from_str(&file_json).unwrap();
    let payload = json!({
        "v": 1, "client_nonce": "AAAAAAAAAAAAAAAAAAAAAA", "ts": 1,
        "attachments": [{
            "id": "F1", "name": "a.png", "content_type": "image/png", "size": 9,
            "metadata": {"type": "Image", "width": 1, "height": 1}, "file": file,
            "thumbnail": {"id": "T1", "width": 1, "height": 1, "file": file}
        }]
    });
    assert_eq!(w::payload_file_ids(payload.to_string()).unwrap(), ["F1", "T1"]);
    assert!(w::attachment_chunk_size() > 0);
}
