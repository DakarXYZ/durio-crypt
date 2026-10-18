//! The fake follows the backend's behaviour (stoatchat `durio/stage-2`, route
//! tests in `crates/delta/src/routes/e2ee/`), replayed with contract fixtures.

use std::path::PathBuf;

use serde_json::{Value, json};

use super::*;

const A: &str = "01KAAAAAAAAAAAAAAAAAAAAAAA";
const A1: &str = "01KDA1A1A1A1A1A1A1A1A1A1A1";
const B: &str = "01KBBBBBBBBBBBBBBBBBBBBBBB";
const B1: &str = "01KDB1B1B1B1B1B1B1B1B1B1B1";
const B2: &str = "01KDB2B2B2B2B2B2B2B2B2B2B2";
const C: &str = "01KCCCCCCCCCCCCCCCCCCCCCCC";

fn fixture(rel: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(rel);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn device_keys(user: &str, device: &str) -> Value {
    json!({
        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
        "device_id": device,
        "keys": { format!("curve25519:{device}"): "c", format!("ed25519:{device}"): "e" },
        "signatures": {},
        "user_id": ids::user_id(user).unwrap(),
    })
}

fn otks(prefix: &str, n: usize) -> Value {
    let m: Map<String, Value> = (0..n)
        .map(|i| {
            (
                format!("signed_curve25519:{prefix}{i}"),
                json!({ "key": format!("{prefix}{i}") }),
            )
        })
        .collect();
    Value::Object(m)
}

fn post(s: &mut FakeServer, auth: &Auth, path: &str, body: Value) -> Response {
    s.handle(auth, "POST", path, Some(&body))
}

/// A1 and B1/B2 registered, A and B share a DM
fn setup() -> FakeServer {
    let mut s = FakeServer::new();
    for (u, d) in [(A, A1), (B, B1), (B, B2)] {
        let r = post(
            &mut s,
            &Auth::new(u, d),
            api::paths::KEYS_UPLOAD,
            json!({ "device_keys": device_keys(u, d) }),
        );
        assert_eq!(r.status, 200);
    }
    s.channel_set_members(C, &[A, B]);
    s
}

#[test]
fn upload_fixture_and_counts() {
    let mut s = FakeServer::new();
    let a = Auth::new(A, A1);
    let initial = fixture("api/keys/upload.initial.json");
    let r = post(&mut s, &a, api::paths::KEYS_UPLOAD, initial["request"].clone());
    assert_eq!(r.status, 200);
    // the fixture response plus the backend's always-present fallback list
    let mut expected = initial["response"].clone();
    expected["device_unused_fallback_key_types"] = json!([]);
    assert_eq!(r.body, expected);

    let r = post(
        &mut s,
        &a,
        api::paths::KEYS_UPLOAD,
        fixture("api/keys/upload.otk_only.json")["request"].clone(),
    );
    assert_eq!(r.body["device_unused_fallback_key_types"], json!(["signed_curve25519"]));

    let r = s.handle(&a, "GET", api::paths::KEYS_COUNT, None);
    assert_eq!(r.body["one_time_key_counts"]["signed_curve25519"], 50);

    // repeating the same device keys is fine, changing them is not (C22)
    let dk = initial["request"]["device_keys"].clone();
    assert_eq!(
        post(&mut s, &a, api::paths::KEYS_UPLOAD, json!({ "device_keys": dk })).status,
        200
    );
    let mut other = dk.clone();
    other["keys"][format!("curve25519:{A1}")] = json!("changed");
    assert_eq!(
        post(&mut s, &a, api::paths::KEYS_UPLOAD, json!({ "device_keys": other })).status,
        409
    );
}

#[test]
fn upload_limits() {
    let mut s = setup();
    let a = Auth::new(A, A1);
    // keys of a device that never uploaded device keys
    let r = post(
        &mut s,
        &Auth::new(A, B2),
        api::paths::KEYS_UPLOAD,
        json!({ "one_time_keys": otks("x", 1) }),
    );
    assert_eq!(r.status, 404);
    assert_eq!(
        post(
            &mut s,
            &a,
            api::paths::KEYS_UPLOAD,
            json!({ "one_time_keys": otks("a", 60) })
        )
        .status,
        200
    );
    let r = post(
        &mut s,
        &a,
        api::paths::KEYS_UPLOAD,
        json!({ "one_time_keys": otks("b", 41) }),
    );
    assert_eq!((r.status, r.body["type"].as_str()), (422, Some("PayloadTooLarge")));
    let two = json!({ "signed_curve25519:F1": {}, "signed_curve25519:F2": {} });
    assert_eq!(
        post(&mut s, &a, api::paths::KEYS_UPLOAD, json!({ "fallback_keys": two })).status,
        400
    );
    // device keys for another device id
    let r = post(
        &mut s,
        &a,
        api::paths::KEYS_UPLOAD,
        json!({ "device_keys": device_keys(A, B1) }),
    );
    assert_eq!(r.status, 400);
}

#[test]
fn claim_until_fallback_repeats() {
    let mut s = setup();
    let b1 = Auth::new(B, B1);
    post(
        &mut s,
        &b1,
        api::paths::KEYS_UPLOAD,
        json!({ "one_time_keys": otks("o", 1), "fallback_keys": { "signed_curve25519:F": { "fallback": true } } }),
    );
    let a = Auth::new(A, A1);
    let body = json!({ "one_time_keys": { ids::user_id(B).unwrap(): { B1: "signed_curve25519" } } });
    let mut got = Vec::new();
    for _ in 0..3 {
        let r = post(&mut s, &a, api::paths::KEYS_CLAIM, body.clone());
        let keys = r.body["one_time_keys"][ids::user_id(B).unwrap()][B1]
            .as_object()
            .unwrap()
            .clone();
        got.extend(keys.keys().cloned());
    }
    // one OTK, then the same fallback key again and again
    assert_eq!(
        got,
        ["signed_curve25519:o0", "signed_curve25519:F", "signed_curve25519:F"]
    );
    assert_eq!(s.fallback_used(B1), Some(true));
    let counts = s.handle(&b1, "GET", api::paths::KEYS_COUNT, None);
    assert_eq!(counts.body["device_unused_fallback_key_types"], json!([]));

    // a device claimed under the wrong user gives nothing
    let wrong = json!({ "one_time_keys": { ids::user_id(A).unwrap(): { B1: "signed_curve25519" } } });
    assert_eq!(
        post(&mut s, &a, api::paths::KEYS_CLAIM, wrong).body["one_time_keys"],
        json!({})
    );
}

#[test]
fn query_answers_everyone() {
    let mut s = setup();
    let stranger = "01KSSSSSSSSSSSSSSSSSSSSSSS";
    let body = json!({ "device_keys": {
        ids::user_id(B).unwrap(): [],
        ids::user_id(stranger).unwrap(): [],
        "@not-a-user:stoat.invalid": [],
        ids::user_id(A).unwrap(): [B1],
    }});
    let r = post(&mut s, &Auth::new(A, A1), api::paths::KEYS_QUERY, body);
    let dk = &r.body["device_keys"];
    assert_eq!(dk[ids::user_id(B).unwrap()].as_object().unwrap().len(), 2);
    assert_eq!(dk[ids::user_id(stranger).unwrap()], json!({}));
    assert_eq!(dk["@not-a-user:stoat.invalid"], json!({}));
    assert_eq!(dk[ids::user_id(A).unwrap()], json!({}));
    for k in ["failures", "master_keys", "self_signing_keys", "user_signing_keys"] {
        assert_eq!(r.body[k], json!({}), "{k}");
    }
}

#[test]
fn to_device_wildcard_and_mailbox() {
    let mut s = setup();
    let b1 = Auth::new(B, B1);
    let b2 = Auth::new(B, B2);
    let put = |s: &mut FakeServer, auth: &Auth, txn: &str, messages: Value| {
        s.handle(
            auth,
            "PUT",
            &api::paths::to_device_send(txn),
            Some(&json!({ "type": "m.room_key_request", "messages": messages })),
        )
    };
    // `*` reaches every device of the user except the sender itself
    let r = put(
        &mut s,
        &b1,
        "t1",
        json!({ ids::user_id(B).unwrap(): { "*": { "n": 1 } } }),
    );
    assert_eq!(r, Response::ok(json!({})));
    assert_eq!((s.inbox_len(B1), s.inbox_len(B2)), (0, 1));
    // explicit address wins over `*`
    put(
        &mut s,
        &b1,
        "t2",
        json!({ ids::user_id(B).unwrap(): { "*": { "n": 2 }, B2: { "n": 3 } } }),
    );
    // retried PUT is swallowed while the first copy is undelivered
    put(
        &mut s,
        &b1,
        "t2",
        json!({ ids::user_id(B).unwrap(): { B2: { "n": 4 } } }),
    );
    let r = s.handle(&b2, "GET", "/e2ee/to_device?limit=10", None);
    let got: Vec<Value> = r.body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["content"]["n"].clone())
        .collect();
    assert_eq!(got, [json!(1), json!(3)]);
    let m = &r.body["messages"][0];
    assert_eq!(m["sender"], ids::user_id(B).unwrap());
    assert_eq!(m["sender_device"], B1);
    assert_eq!(m["type"], "m.room_key_request");

    // doorbells only to the recipient device, Matrix-shaped sender
    let ws = s.ws_take(&b2);
    assert!(
        ws.iter()
            .any(|e| e["type"] == "E2eeToDevice" && e["sender"] == ids::user_id(B).unwrap())
    );
    assert!(!s.ws_take(&b1).iter().any(|e| e["type"] == "E2eeToDevice"));

    for bad in ["0", "101", "x"] {
        assert_eq!(
            s.handle(&b2, "GET", &format!("/e2ee/to_device?limit={bad}"), None)
                .status,
            400
        );
    }
    let first = m["id"].as_str().unwrap().to_owned();
    assert_eq!(
        post(&mut s, &b2, api::paths::TO_DEVICE_ACK, json!({ "ids": [] })).status,
        400
    );
    assert_eq!(
        post(&mut s, &b2, api::paths::TO_DEVICE_ACK, json!({ "ids": vec!["x"; 101] })).status,
        400
    );
    // another device cannot acknowledge them
    assert_eq!(
        post(&mut s, &b1, api::paths::TO_DEVICE_ACK, json!({ "ids": [first] })).status,
        204
    );
    assert_eq!(s.inbox_len(B2), 2);
    assert_eq!(
        post(
            &mut s,
            &b2,
            api::paths::TO_DEVICE_ACK,
            json!({ "ids": [first, "unknown"] })
        )
        .status,
        204
    );
    assert_eq!(s.inbox_len(B2), 1);

    assert_eq!(put(&mut s, &b1, "bad/txn", json!({})).status, 400);
    assert_eq!(put(&mut s, &b1, "bad txn", json!({})).status, 400);
    assert_eq!(
        put(&mut s, &b1, "t3", json!({ ids::user_id(B).unwrap(): { B2: 5 } })).status,
        400
    );
}

#[test]
fn full_mailbox_is_reported() {
    let mut s = setup();
    s.max_pending_to_device = 1;
    let a = Auth::new(A, A1);
    let body = json!({ "type": "m.room.encrypted", "messages": { ids::user_id(B).unwrap(): { B1: {}, B2: {} } } });
    s.handle(&a, "PUT", "/e2ee/to_device/t1", Some(&body));
    let r = s.handle(&a, "PUT", "/e2ee/to_device/t2", Some(&body));
    let mut failed: Vec<String> = serde_json::from_value(r.body["failed"][ids::user_id(B).unwrap()].clone()).unwrap();
    failed.sort();
    assert_eq!(failed, [B1, B2]);
}

#[test]
fn invisible_users_get_nothing() {
    let mut s = setup();
    s.channel_set_members(C, &[A]);
    let a = Auth::new(A, A1);
    let body = json!({ "type": "m.room.encrypted", "messages": { ids::user_id(B).unwrap(): { "*": {} } } });
    s.handle(&a, "PUT", "/e2ee/to_device/t1", Some(&body));
    assert_eq!(s.inbox_len(B1) + s.inbox_len(B2), 0);
}

#[test]
fn device_list_updates() {
    let mut s = setup();
    let a = Auth::new(A, A1);
    s.ws_take(&a);
    // group changes publish nothing (backend behaviour)
    s.channel_set_members(C, &[A, B, "01KDDDDDDDDDDDDDDDDDDDDDDD"]);
    assert!(s.ws_take(&a).is_empty());
    s.device_delete(B, B2);
    assert_eq!(s.ws_take(&a), [json!({ "type": "E2eeDeviceListUpdate", "user": B })]);
    let q = post(
        &mut s,
        &a,
        api::paths::KEYS_QUERY,
        json!({ "device_keys": { ids::user_id(B).unwrap(): [] } }),
    );
    assert_eq!(
        q.body["device_keys"][ids::user_id(B).unwrap()]
            .as_object()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn backup_versions_and_keys() {
    let mut s = FakeServer::new();
    let a = Auth::new(A, A1);
    let create = fixture("api/backup/version.create.json");
    let r = post(&mut s, &a, api::paths::BACKUP_VERSION, create["request"].clone());
    let v1 = r.body["version"].as_str().unwrap().to_owned();
    // a second version needs an MFA ticket
    assert_eq!(
        post(&mut s, &a, api::paths::BACKUP_VERSION, create["request"].clone()).status,
        401
    );
    s.grant_mfa_ticket(A);
    let v2 = post(&mut s, &a, api::paths::BACKUP_VERSION, create["request"].clone()).body["version"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut bad = create["request"].clone();
    bad["algorithm"] = json!("stoat.backup.v1.aead");
    s.grant_mfa_ticket(A);
    assert_eq!(post(&mut s, &a, api::paths::BACKUP_VERSION, bad).status, 400);

    let put = fixture("api/backup/keys.put.json")["request"].clone();
    let r = s.handle(&a, "PUT", &api::paths::backup_keys(&v1), Some(&put));
    assert_eq!((r.status, r.body["current_version"].as_str()), (409, Some(v2.as_str())));
    let r = s.handle(&a, "PUT", &api::paths::backup_keys(&v2), Some(&put));
    assert_eq!(r.body, json!({ "count": 1, "etag": "1" }));

    // a worse key does not replace the stored one
    let mut worse = put.clone();
    let room = put["rooms"].as_object().unwrap().keys().next().unwrap().clone();
    let session = put["rooms"][&room]["sessions"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    worse["rooms"][&room]["sessions"][&session]["first_message_index"] = json!(5);
    worse["rooms"][&room]["sessions"][&session]["session_data"] = json!({ "worse": true });
    assert_eq!(
        s.handle(&a, "PUT", &api::paths::backup_keys(&v2), Some(&worse)).body["etag"],
        "1"
    );
    let got = s.handle(&a, "GET", &api::paths::backup_keys(&v2), None);
    assert_eq!(got.body, put);

    let version = s.handle(&a, "GET", api::paths::BACKUP_VERSION, None);
    assert_eq!(version.body["version"], v2);
    assert_eq!(version.body["count"], 1);
}

#[test]
fn messages_need_strict_envelope_from_own_device() {
    let mut s = setup();
    let a = Auth::new(A, A1);
    let env = fixture("envelope/valid.json");
    let mut foreign = env.clone();
    foreign["device_id"] = json!(B1);
    assert_eq!(s.message_send(&a, C, foreign, vec![]).unwrap_err().status, 400);
    let mut own = env.clone();
    own["device_id"] = json!(A1);
    let id = s.message_send(&a, C, own.clone(), vec![]).unwrap();
    let mut extra = own.clone();
    extra["sender_key"] = json!("x");
    assert_eq!(s.message_send(&a, C, extra, vec![]).unwrap_err().status, 400);
    assert_eq!(
        s.message_send(&a, "01KXXXXXXXXXXXXXXXXXXXXXXX", own.clone(), vec![])
            .unwrap_err()
            .status,
        404
    );
    assert_eq!(
        s.message_edit(&Auth::new(B, B1), C, &id, own.clone())
            .unwrap_err()
            .status,
        400,
        "device id is not B1"
    );
    s.message_edit(&a, C, &id, own).unwrap();
    assert!(s.messages(C)[0].edited);
}

#[test]
fn injected_failures() {
    let mut s = setup();
    s.faults.fail_next.push(("/e2ee/keys/query".into(), 502));
    let a = Auth::new(A, A1);
    let body = json!({ "device_keys": {} });
    assert_eq!(post(&mut s, &a, api::paths::KEYS_QUERY, body.clone()).status, 502);
    assert_eq!(post(&mut s, &a, api::paths::KEYS_QUERY, body).status, 200);
}

#[test]
fn backup_version_by_id_and_limits() {
    let mut s = setup();
    let a = Auth::new(A, A1);
    let create = fixture("api/backup/version.create.json")["request"].clone();
    let v1 = post(&mut s, &a, api::paths::BACKUP_VERSION, create.clone()).body["version"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = api::paths::backup_version(&v1);
    assert_eq!(s.handle(&a, "GET", &path, None).body["version"], v1);
    // signatures may change, the key and the algorithm may not
    let mut update = create.clone();
    update["auth_data"]["signatures"] = json!({ "x": {} });
    assert_eq!(s.handle(&a, "PUT", &path, Some(&update)).status, 204);
    let mut other_key = create.clone();
    other_key["auth_data"]["public_key"] = json!("AAAA");
    assert_eq!(s.handle(&a, "PUT", &path, Some(&other_key)).status, 400);
    // more than 1000 sessions in one request
    let sessions: Map<String, Value> = (0..1001)
        .map(|i| {
            (
                format!("s{i}"),
                json!({ "first_message_index": 0, "forwarded_count": 0, "is_verified": false, "session_data": {} }),
            )
        })
        .collect();
    let room = ids::room_id(C).unwrap();
    let body = json!({ "rooms": { room: { "sessions": sessions } } });
    assert_eq!(
        s.handle(&a, "PUT", &api::paths::backup_keys(&v1), Some(&body)).status,
        422
    );
    // delete needs a ticket; afterwards the version is gone
    assert_eq!(s.handle(&a, "DELETE", &path, None).status, 401);
    s.grant_mfa_ticket(A);
    assert_eq!(s.handle(&a, "DELETE", &path, None).status, 204);
    assert_eq!(s.handle(&a, "GET", &path, None).status, 404);
    assert_eq!(s.handle(&a, "GET", api::paths::BACKUP_VERSION, None).status, 404);
}

#[test]
fn secrets_like_the_backend() {
    let mut s = setup();
    let a = Auth::new(A, A1);
    let path = api::paths::secret(&api::secrets::key("ABCDEF"));
    assert_eq!(path, "/e2ee/secrets/m.secret_storage.key.ABCDEF");
    assert_eq!(s.handle(&a, "GET", &path, None).status, 404);
    let content = json!({ "algorithm": "m.secret_storage.v1.aes-hmac-sha2", "iv": "x" });
    assert_eq!(s.handle(&a, "PUT", &path, Some(&content)).status, 204);
    assert_eq!(s.handle(&a, "GET", &path, None).body, content);
    assert_eq!(s.handle(&Auth::new(B, B1), "GET", &path, None).status, 404);

    let long = api::paths::secret(&api::secrets::key(&"k".repeat(65)));
    for (p, body, status) in [
        ("/e2ee/secrets/m.anything", json!({}), 400),
        (long.as_str(), json!({}), 400),
        ("/e2ee/secrets/m.megolm_backup.v1", json!("text"), 400),
        (
            "/e2ee/secrets/m.megolm_backup.v1",
            json!({ "data": "x".repeat(16_384) }),
            422,
        ),
        ("/e2ee/secrets/m.cross_signing.master", json!({}), 401),
    ] {
        assert_eq!(s.handle(&a, "PUT", p, Some(&body)).status, status, "{p}");
    }
    s.grant_mfa_ticket(A);
    assert_eq!(
        s.handle(&a, "PUT", "/e2ee/secrets/m.cross_signing.master", Some(&json!({})))
            .status,
        204
    );
    for i in 0..30 {
        let p = api::paths::secret(&api::secrets::key(&format!("K{i}")));
        assert_eq!(s.handle(&a, "PUT", &p, Some(&json!({}))).status, 204, "{i}");
    }
    let p = api::paths::secret(&api::secrets::key("ONE_TOO_MANY"));
    assert_eq!(s.handle(&a, "PUT", &p, Some(&json!({}))).status, 400);
    // replacing an existing one is fine at the limit
    assert_eq!(s.handle(&a, "PUT", &path, Some(&json!({}))).status, 204);
}
