//! Size probe: every OlmMachine entry point the spike adapter uses is reachable
//! through one JSON command dispatcher, so the linker keeps the same code a
//! real wrapper would (minus our own adapter logic, a few % of the binary).

use std::cell::RefCell;
use std::io::Read;

use matrix_sdk_crypto::{
    AttachmentDecryptor, AttachmentEncryptor, DecryptionSettings, EncryptionSettings, EncryptionSyncChanges,
    OlmMachine, OlmMachineBuilder, TrustRequirement, store::types::BackupDecryptionKey,
    types::requests::AnyOutgoingRequest,
};
use ruma::{
    DeviceId, RoomId, UserId,
    api::{IncomingResponseExt, client::sync::sync_events::DeviceLists},
    serde::Raw,
};
use serde_json::{Value, json};

thread_local! {
    static M: RefCell<Option<OlmMachine>> = const { RefCell::new(None) };
}

fn m() -> OlmMachine {
    M.with(|m| m.borrow().clone().expect("open first"))
}

fn parse<R: ruma::api::IncomingResponse>(v: &Value) -> R {
    let b = serde_json::to_vec(v).unwrap();
    R::try_from_http_response(http::Response::builder().status(200).body(b.as_slice()).unwrap()).unwrap()
}

fn settings() -> DecryptionSettings {
    DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    }
}

pub async fn run(cmd: &str, arg: &str) -> String {
    let a: Value = serde_json::from_str(arg).unwrap_or(Value::Null);
    let s = |k: &str| a[k].as_str().unwrap_or_default().to_owned();
    match cmd {
        "open" => {
            let user = UserId::parse(s("user")).unwrap();
            let dev: &DeviceId = a["device"].as_str().unwrap().into();
            #[allow(unused_mut)]
            let mut b = OlmMachineBuilder::new(&user, dev);
            #[cfg(feature = "sqlite")]
            {
                let st = matrix_sdk_sqlite::SqliteCryptoStore::open_with_key(s("path"), Some(&[0u8; 32]))
                    .await
                    .unwrap();
                b = b.with_crypto_store(st);
            }
            #[cfg(feature = "indexeddb")]
            {
                let st = matrix_sdk_indexeddb::IndexeddbCryptoStore::open_with_key(&s("path"), &[0u8; 32])
                    .await
                    .unwrap();
                b = b.with_crypto_store(st);
            }
            let mm = b.build().await.unwrap();
            M.with(|x| *x.borrow_mut() = Some(mm));
            "{}".into()
        }
        "outgoing" => {
            let mut out = vec![];
            for r in m().outgoing_requests().await.unwrap() {
                let body = match r.request() {
                    AnyOutgoingRequest::KeysUpload(u) => json!({
                        "device_keys": u.device_keys,
                        "one_time_keys": u.one_time_keys,
                        "fallback_keys": u.fallback_keys,
                    }),
                    AnyOutgoingRequest::KeysQuery(q) => json!({ "device_keys": q.device_keys }),
                    AnyOutgoingRequest::KeysClaim(c) => json!({ "one_time_keys": c.one_time_keys }),
                    AnyOutgoingRequest::ToDeviceRequest(t) => {
                        json!({ "type": t.event_type.to_string(), "messages": t.messages })
                    }
                    _ => json!({}),
                };
                out.push(json!({ "id": r.request_id().to_string(), "body": body }));
            }
            json!(out).to_string()
        }
        "sent" => {
            let id: ruma::OwnedTransactionId = s("id").into();
            let r = &a["response"];
            let mm = m();
            use ruma::api::client as c;
            let res = match s("kind").as_str() {
                "upload" => {
                    mm.mark_request_as_sent(&id, &parse::<c::keys::upload_keys::v3::Response>(r))
                        .await
                }
                "query" => {
                    mm.mark_request_as_sent(&id, &parse::<c::keys::get_keys::v3::Response>(r))
                        .await
                }
                "claim" => {
                    mm.mark_request_as_sent(&id, &parse::<c::keys::claim_keys::v3::Response>(r))
                        .await
                }
                "backup" => {
                    mm.mark_request_as_sent(&id, &parse::<c::backup::add_backup_keys::v3::Response>(r))
                        .await
                }
                _ => {
                    mm.mark_request_as_sent(&id, &parse::<c::to_device::send_event_to_device::v3::Response>(r))
                        .await
                }
            };
            format!("{:?}", res.is_ok())
        }
        "receive" => {
            let evs: Vec<Raw<_>> = serde_json::from_value(a["events"].clone()).unwrap_or_default();
            let counts = serde_json::from_value(a["counts"].clone()).unwrap_or_default();
            let fb: Vec<_> = serde_json::from_value(a["fallback"].clone()).unwrap_or_default();
            let mut lists = DeviceLists::new();
            lists.changed = serde_json::from_value(a["changed"].clone()).unwrap_or_default();
            let (e, k) = m()
                .receive_sync_changes(
                    EncryptionSyncChanges {
                        to_device_events: evs,
                        changed_devices: &lists,
                        one_time_keys_counts: &counts,
                        unused_fallback_keys: Some(&fb),
                        next_batch_token: Some(s("token")),
                    },
                    &settings(),
                )
                .await
                .unwrap();
            format!("{} {}", e.len(), k.len())
        }
        "track" => {
            let users: Vec<ruma::OwnedUserId> = serde_json::from_value(a["users"].clone()).unwrap();
            m().update_tracked_users(users.iter().map(|u| u.as_ref()))
                .await
                .unwrap();
            let c = m()
                .get_missing_sessions(users.iter().map(|u| u.as_ref()))
                .await
                .unwrap();
            format!("{:?}", c.map(|x| x.0))
        }
        "share" => {
            let users: Vec<ruma::OwnedUserId> = serde_json::from_value(a["users"].clone()).unwrap();
            let room = RoomId::parse(s("room")).unwrap();
            let r = m()
                .share_room_key(&room, users.iter().map(|u| u.as_ref()), EncryptionSettings::default())
                .await
                .unwrap();
            json!(
                r.iter()
                    .map(|t| json!({ "txn": t.txn_id.to_string(), "messages": t.messages }))
                    .collect::<Vec<_>>()
            )
            .to_string()
        }
        "encrypt" => {
            let room = RoomId::parse(s("room")).unwrap();
            let raw = Raw::from_json(serde_json::value::to_raw_value(&a["content"]).unwrap());
            m().encrypt_room_event_raw(&room, "stoat.message", &raw)
                .await
                .unwrap()
                .content
                .json()
                .get()
                .to_owned()
        }
        "decrypt" => {
            let room = RoomId::parse(s("room")).unwrap();
            let ev = Raw::from_json(serde_json::value::to_raw_value(&a["event"]).unwrap());
            match m().decrypt_room_event(&ev, &room, &settings()).await {
                Ok(d) => {
                    let sid = d.encryption_info.session_id().unwrap_or_default().to_owned();
                    let sess = m().store().get_inbound_group_session(&room, &sid).await;
                    let dev = match &d.encryption_info.sender_device {
                        Some(dv) => m()
                            .get_device(&d.encryption_info.sender, dv, None)
                            .await
                            .ok()
                            .flatten()
                            .map(|x| x.is_verified()),
                        None => None,
                    };
                    format!(
                        "{} {:?} {:?} {:?}",
                        d.event.json().get(),
                        d.encryption_info.verification_state,
                        dev,
                        sess.map(|x| x.map(|y| y.has_been_imported()))
                    )
                }
                Err(e) => format!("err {e}"),
            }
        }
        "backup_enable" => {
            let k = BackupDecryptionKey::new();
            let pk = k.megolm_v1_public_key();
            pk.set_version(s("version"));
            m().backup_machine().enable_backup_v1(pk).await.unwrap();
            m().backup_machine()
                .save_decryption_key(Some(k.clone()), Some(s("version")))
                .await
                .unwrap();
            let r = m().backup_machine().backup().await.unwrap();
            format!(
                "{} {} {:?}",
                k.to_base58(),
                serde_json::to_string(&k.to_backup_info()).unwrap(),
                r.map(|x| x.0)
            )
        }
        "backup_restore" => {
            let k = BackupDecryptionKey::from_base58(&s("key")).unwrap();
            let data: ruma::api::client::backup::KeyBackupData = serde_json::from_value(a["data"].clone()).unwrap();
            let room = RoomId::parse(s("room")).unwrap();
            let bk = k.decrypt_session_data(data.session_data).unwrap();
            let ek = matrix_sdk_crypto::olm::ExportedRoomKey::from_backed_up_room_key(room, s("session"), bk);
            let r = m()
                .store()
                .import_room_keys(vec![ek], Some(&s("version")), |_, _| {})
                .await
                .unwrap();
            r.imported_count.to_string()
        }
        "sas" => {
            let user = UserId::parse(s("user")).unwrap();
            let dev: &DeviceId = a["device"].as_str().unwrap().into();
            if let Some(d) = m().get_device(&user, dev, None).await.unwrap() {
                let (req, _out) = d.request_verification();
                if let Some((sas, _)) = req.start_sas().await.unwrap() {
                    let _ = sas.accept();
                    let _ = sas.confirm().await;
                    return format!("{:?} {:?}", sas.emoji().map(|e| e.map(|x| x.symbol)), sas.decimals());
                }
                if let Some(r) = m().get_verification_requests(&user).pop() {
                    let _ = r.accept();
                }
                d.set_local_trust(matrix_sdk_crypto::LocalTrust::Verified)
                    .await
                    .unwrap();
            }
            "{}".into()
        }
        "attach" => {
            let data = a["data"].as_str().unwrap_or_default().as_bytes().to_vec();
            let mut src = data.as_slice();
            let mut enc = AttachmentEncryptor::new(&mut src);
            let mut c = vec![];
            enc.read_to_end(&mut c).unwrap();
            let info = enc.finish();
            let mut cs = c.as_slice();
            let mut dec = AttachmentDecryptor::new(&mut cs, info).unwrap();
            let mut p = vec![];
            dec.read_to_end(&mut p).unwrap();
            p.len().to_string()
        }
        _ => String::new(),
    }
}

#[cfg(feature = "wasm")]
mod wasm {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub async fn run(cmd: String, arg: String) -> String {
        super::run(&cmd, &arg).await
    }
}

#[cfg(feature = "native")]
mod native {
    use std::ffi::{CStr, CString, c_char};

    /// # Safety
    /// `cmd` and `arg` must be valid NUL-terminated strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn probe_run(cmd: *const c_char, arg: *const c_char) -> *mut c_char {
        let cmd = unsafe { CStr::from_ptr(cmd) }.to_string_lossy().into_owned();
        let arg = unsafe { CStr::from_ptr(arg) }.to_string_lossy().into_owned();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let out = rt.block_on(super::run(&cmd, &arg));
        CString::new(out).unwrap().into_raw()
    }
}
