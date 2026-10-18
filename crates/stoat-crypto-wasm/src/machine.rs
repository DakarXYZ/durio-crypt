//! `CryptoMachine` for JS: the core façade with JSON bodies and plain
//! objects at the boundary, every async call a `Promise`. The host contract
//! (order of calls, request passes, ids in flight) is the core's —
//! `stoat_crypto` crate docs.
//!
//! Each method copies its arguments and a handle of the core machine into
//! the future before returning the promise, so nothing borrows the JS object
//! while the call runs; `free()` during a call only drops the JS side.

use std::future::Future;
use std::rc::Rc;

use async_lock::Mutex;
use js_sys::Promise;
use stoat_crypto as sc;
use stoat_crypto::proto::api::{KeysCountResponse, ToDeviceFetchResponse};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::Error;
use crate::sas::SasHandle;
use crate::types::{
    BackupStatus, ChannelEncryptionSettings, DecryptResult, DeviceInfo, IdentityKeys, IncomingEncryptedMessage,
    KeyExport, KeyImportResult, RecoverySecrets, RecoverySetup, RestoreProgress, ServerLimits, Timing, ToDeviceResult,
    UndeliveredDevice, from_js, parse_request_kind, parse_settable_trust, payload_from_json, requests, secret_string,
    store_config, to_js,
};

/// The promise of a future; an `Error` rejects it with a `StoatCryptoError`
pub(crate) fn spawn<F>(fut: F) -> Promise
where
    F: Future<Output = Result<JsValue, Error>> + 'static,
{
    future_to_promise(async move { fut.await.map_err(JsValue::from) })
}

/// [`spawn`] for a serializable result
fn spawn_value<T, F>(fut: F) -> Promise
where
    T: serde::Serialize,
    F: Future<Output = Result<T, Error>> + 'static,
{
    spawn(async move { to_js(&fut.await?) })
}

/// [`spawn`] for calls without a result
fn spawn_unit<F>(fut: F) -> Promise
where
    F: Future<Output = Result<(), Error>> + 'static,
{
    spawn(async move {
        fut.await?;
        Ok(JsValue::UNDEFINED)
    })
}

fn invalid_response(what: &'static str) -> Error {
    sc::CryptoError::InvalidResponse(what).into()
}

/// Crypto state of one account on one server. Open once per account (the
/// worker holds the Web Lock) and `free()` it on logout or account switch.
#[derive(Debug)]
#[wasm_bindgen]
pub struct CryptoMachine {
    inner: sc::CryptoMachine,
}

impl CryptoMachine {
    fn core(&self) -> sc::CryptoMachine {
        self.inner.clone()
    }
}

#[wasm_bindgen]
impl CryptoMachine {
    /// Open (or create) the state of `userId` (ULID) on this device (session
    /// ULID). `store`: `{kind: "memory"}` or `{kind: "indexedDb", name, key}`
    /// (key = 32 bytes; the caller zeroes its array after the call).
    /// Resolves to a `CryptoMachine`.
    pub fn open(user_id: String, device_id: String, store: JsValue) -> Promise {
        let store = store_config(&store);
        spawn(async move {
            let inner = sc::CryptoMachine::open(&user_id, &device_id, store?).await?;
            Ok(CryptoMachine { inner }.into())
        })
    }

    #[wasm_bindgen(js_name = userId)]
    pub fn user_id(&self) -> String {
        self.inner.user_id().to_owned()
    }

    #[wasm_bindgen(js_name = deviceId)]
    pub fn device_id(&self) -> String {
        self.inner.device_id().to_owned()
    }

    /// `{curve25519, ed25519}` (base64)
    #[wasm_bindgen(js_name = identityKeys)]
    pub fn identity_keys(&self) -> Result<JsValue, JsValue> {
        let k = self.inner.identity_keys();
        Ok(to_js(&IdentityKeys {
            curve25519: k.curve25519,
            ed25519: k.ed25519,
        })?)
    }

    // ------------------------------------------------------------ requests

    /// `{maxToDeviceBatch, maxRequestBytes}` from `GET /` → `features.e2ee`
    #[wasm_bindgen(js_name = setServerLimits)]
    pub fn set_server_limits(&self, limits: JsValue) -> Promise {
        let limits = from_js::<ServerLimits>(limits, "server limits");
        let m = self.core();
        spawn_unit(async move {
            m.set_server_limits(limits?.into()).await;
            Ok(())
        })
    }

    /// `{keyRequestDelayMs, toDeviceRetryMs, toDeviceRetryAttempts,
    /// ownRetryMs?}`
    #[wasm_bindgen(js_name = setTiming)]
    pub fn set_timing(&self, timing: JsValue) -> Promise {
        let timing = from_js::<Timing>(timing, "timing").and_then(Timing::into_core);
        let m = self.core();
        spawn_unit(async move {
            m.set_timing(timing?).await;
            Ok(())
        })
    }

    /// The request pass: run each id once (keep a set of ids in flight)
    #[wasm_bindgen(js_name = outgoingRequests)]
    pub fn outgoing_requests(&self) -> Promise {
        let m = self.core();
        spawn_value(async move { Ok(requests(m.outgoing_requests().await?)) })
    }

    /// 2xx: `body` = the response JSON (empty for 204)
    #[wasm_bindgen(js_name = markRequestSent)]
    pub fn mark_request_sent(&self, id: String, kind: String, body: String) -> Promise {
        let kind = parse_request_kind(&kind);
        let m = self.core();
        spawn_unit(async move { Ok(m.mark_request_sent(&id, kind?, &body).await?) })
    }

    /// Non-2xx (`status` 0: no response): `MfaRequired`,
    /// `BackupVersionChanged`, `DeviceKeysConflict` and `RequestRejected`
    /// need the UI; other failures come back later
    #[wasm_bindgen(js_name = markRequestFailed)]
    pub fn mark_request_failed(&self, id: String, kind: String, status: u16) -> Promise {
        let kind = parse_request_kind(&kind);
        let m = self.core();
        spawn_unit(async move { Ok(m.mark_request_failed(&id, kind?, status).await?) })
    }

    /// When to run a request pass without any other event (`null`: nothing
    /// scheduled). The core has no timers: the host schedules it.
    #[wasm_bindgen(js_name = wakeupInMs)]
    pub fn wakeup_in_ms(&self) -> Promise {
        let m = self.core();
        spawn_value(async move { Ok(m.wakeup_in_ms().await.map(|ms| ms as f64)) })
    }

    #[wasm_bindgen(js_name = undeliveredDevices)]
    pub fn undelivered_devices(&self) -> Promise {
        let m = self.core();
        spawn_value(async move {
            Ok(m.undelivered_devices()
                .await
                .into_iter()
                .map(UndeliveredDevice::from)
                .collect::<Vec<_>>())
        })
    }

    // ------------------------------------------------------------- mailbox

    /// `GET /e2ee/to_device?limit=N` response body
    #[wasm_bindgen(js_name = receiveToDevice)]
    pub fn receive_to_device(&self, body: String) -> Promise {
        let page =
            serde_json::from_str::<ToDeviceFetchResponse>(&body).map_err(|_| invalid_response("to-device fetch"));
        drop(body);
        let m = self.core();
        spawn_value(async move {
            let page = page?;
            let fetched = page.messages.len();
            Ok(ToDeviceResult::new(fetched, m.receive_to_device(page.messages).await?))
        })
    }

    /// `POST /e2ee/to_device/ack {ids}` succeeded
    #[wasm_bindgen(js_name = markAckSent)]
    pub fn mark_ack_sent(&self, ack_ids: Vec<String>) -> Promise {
        let m = self.core();
        spawn_unit(async move { Ok(m.mark_ack_sent(&ack_ids).await?) })
    }

    /// `E2eeDeviceListUpdate {user}` (user ULIDs)
    #[wasm_bindgen(js_name = receiveDeviceListUpdate)]
    pub fn receive_device_list_update(&self, users: Vec<String>) -> Promise {
        let m = self.core();
        spawn_unit(async move { Ok(m.receive_device_list_update(&users).await?) })
    }

    /// Socket `Ready` after a reconnect
    #[wasm_bindgen(js_name = receiveReconnect)]
    pub fn receive_reconnect(&self) -> Promise {
        let m = self.core();
        spawn_unit(async move { Ok(m.receive_reconnect().await?) })
    }

    /// `GET /e2ee/keys/count` response body
    #[wasm_bindgen(js_name = receiveOtkCounts)]
    pub fn receive_otk_counts(&self, body: String) -> Promise {
        let counts = serde_json::from_str::<KeysCountResponse>(&body).map_err(|_| invalid_response("keys count"));
        let m = self.core();
        spawn_unit(async move { Ok(m.receive_otk_counts(&counts?).await?) })
    }

    // ------------------------------------------------------------ channels

    /// Full member list (ULIDs) of an encrypted DM/group and its settings
    /// (`{rotationPeriodMs?, rotationPeriodMsgs?}` or `undefined`)
    #[wasm_bindgen(js_name = setChannelMembers)]
    pub fn set_channel_members(&self, channel_id: String, members: Vec<String>, settings: JsValue) -> Promise {
        let settings = if settings.is_undefined() || settings.is_null() {
            Ok(ChannelEncryptionSettings::default())
        } else {
            from_js::<ChannelEncryptionSettings>(settings, "channel settings")
        }
        .and_then(ChannelEncryptionSettings::into_core);
        let m = self.core();
        spawn_unit(async move { Ok(m.set_channel_members(&channel_id, &members, settings?).await?) })
    }

    /// Requests to run before `encrypt` (claim, key share); loop until empty
    #[wasm_bindgen(js_name = prepareSend)]
    pub fn prepare_send(&self, channel_id: String) -> Promise {
        let m = self.core();
        spawn_value(async move { Ok(requests(m.prepare_send(&channel_id).await?)) })
    }

    /// Payload v1 JSON → envelope JSON for `encrypted` of the send request
    pub fn encrypt(&self, channel_id: String, payload_json: String) -> Promise {
        let payload = payload_from_json(&payload_json);
        drop(payload_json);
        let m = self.core();
        spawn(async move {
            let envelope = m.encrypt(&channel_id, &payload?).await?;
            Ok(envelope.to_value().to_string().into())
        })
    }

    #[wasm_bindgen(js_name = invalidateOutboundSession)]
    pub fn invalidate_outbound_session(&self, channel_id: String) -> Promise {
        let m = self.core();
        spawn_unit(async move { Ok(m.invalidate_outbound_session(&channel_id).await?) })
    }

    /// One message `{messageId, channelId, author, envelopeJson, replies,
    /// timestamp}`; a failure is `{type: "Failed"}`, not a rejection
    pub fn decrypt(&self, message: JsValue) -> Promise {
        let message = from_js::<IncomingEncryptedMessage>(message, "message").and_then(|m| m.into_core());
        let m = self.core();
        spawn_value(async move {
            Ok(match message? {
                Ok(message) => DecryptResult::from(m.decrypt(&message).await),
                Err(failed) => failed,
            })
        })
    }

    /// A history page: results in input order
    #[wasm_bindgen(js_name = decryptBatch)]
    pub fn decrypt_batch(&self, messages: JsValue) -> Promise {
        let messages = from_js::<Vec<IncomingEncryptedMessage>>(messages, "messages");
        let m = self.core();
        spawn_value(async move {
            let mut out: Vec<Option<DecryptResult>> = Vec::new();
            let mut valid = Vec::new();
            for message in messages? {
                match message.into_core()? {
                    Ok(m) => {
                        valid.push(m);
                        out.push(None);
                    }
                    Err(failed) => out.push(Some(failed)),
                }
            }
            let mut decrypted = m.decrypt_batch(&valid).await.into_iter();
            Ok(out
                .into_iter()
                .map(|r| match r {
                    Some(failed) => failed,
                    None => decrypted
                        .next()
                        .map(DecryptResult::from)
                        .unwrap_or_else(|| sc::DecryptError::Internal.into()),
                })
                .collect::<Vec<_>>())
        })
    }

    // ------------------------------------------------------------- devices

    pub fn devices(&self, user_id: String) -> Promise {
        let m = self.core();
        spawn_value(async move {
            Ok(m.devices(&user_id)
                .await?
                .into_iter()
                .map(DeviceInfo::from)
                .collect::<Vec<_>>())
        })
    }

    /// `"Unverified"` (reset) or `"Blocked"` only. `"Verified"` is refused
    /// (`InvalidInput`): a SAS flow reaching `Done` sets it (review O-3)
    #[wasm_bindgen(js_name = setDeviceTrust)]
    pub fn set_device_trust(&self, user_id: String, device_id: String, trust: String) -> Promise {
        let trust = parse_settable_trust(&trust);
        let m = self.core();
        spawn_unit(async move { Ok(m.set_device_trust(&user_id, &device_id, trust?).await?) })
    }

    // -------------------------------------------------------- verification

    /// Ask a device to verify (SAS); the request leaves with the next pass.
    /// Resolves to a `SasHandle`.
    #[wasm_bindgen(js_name = requestVerification)]
    pub fn request_verification(&self, user_id: String, device_id: String) -> Promise {
        let m = self.core();
        spawn(async move { Ok(SasHandle::new(m.request_verification(&user_id, &device_id).await?).into()) })
    }

    /// The flow of an id from `ToDeviceResult.verifications`
    pub fn verification(&self, flow_id: String) -> Option<SasHandle> {
        self.inner.verification(&flow_id).map(SasHandle::new)
    }

    /// Every flow the machine knows (open and recently finished)
    pub fn verifications(&self) -> Vec<SasHandle> {
        self.inner.verifications().into_iter().map(SasHandle::new).collect()
    }

    // -------------------------------------------------------------- backup

    /// New recovery key (+ optional passphrase, UTF-8 bytes; the caller
    /// zeroes its array) and the backup version request
    #[wasm_bindgen(js_name = createRecovery)]
    pub fn create_recovery(&self, passphrase: Option<Vec<u8>>) -> Promise {
        let passphrase = passphrase.map(secret_string).transpose();
        let m = self.core();
        spawn_value(async move {
            let passphrase = passphrase?;
            Ok(RecoverySetup::from(
                m.create_recovery(passphrase.as_deref().map(String::as_str)).await?,
            ))
        })
    }

    /// A new backup version under the same recovery key (needs MFA)
    #[wasm_bindgen(js_name = rotateBackup)]
    pub fn rotate_backup(&self) -> Promise {
        let m = self.core();
        spawn_value(async move { Ok(RecoverySetup::from(m.rotate_backup().await?)) })
    }

    /// Recovery key or passphrase (UTF-8 bytes) + the four GET bodies
    /// `{defaultKey, keyDescription, backupSecret, backupVersion}` → the
    /// backup version to fetch keys of
    #[wasm_bindgen(js_name = unlockBackup)]
    pub fn unlock_backup(&self, input: Vec<u8>, secrets: JsValue) -> Promise {
        let input = secret_string(input);
        let secrets = from_js::<RecoverySecrets>(secrets, "recovery secrets");
        let m = self.core();
        spawn(async move {
            let version = m.unlock_backup(&input?, &secrets?.into()).await?;
            Ok(version.into())
        })
    }

    /// `GET /e2ee/backup/keys?version=<v>` body → a `BackupRestore`
    #[wasm_bindgen(js_name = restoreBackup)]
    pub fn restore_backup(&self, keys_body: String) -> Promise {
        let m = self.core();
        spawn(async move {
            let restore = m.restore_backup(&keys_body).await?;
            Ok(BackupRestore {
                inner: Rc::new(Mutex::new(restore)),
            }
            .into())
        })
    }

    #[wasm_bindgen(js_name = backupStatus)]
    pub fn backup_status(&self) -> Promise {
        let m = self.core();
        spawn_value(async move { Ok(BackupStatus::from(m.backup_status().await?)) })
    }

    #[wasm_bindgen(js_name = disableBackup)]
    pub fn disable_backup(&self) -> Promise {
        let m = self.core();
        spawn_unit(async move { Ok(m.disable_backup().await?) })
    }

    // ---------------------------------------------------------- key export

    /// Room keys of `channelIds` (all if empty) → `{data, sessions}`, a file
    /// encrypted with `passphrase` (UTF-8 bytes, not empty). Seconds of
    /// PBKDF2: the worker is busy meanwhile.
    #[wasm_bindgen(js_name = exportRoomKeys)]
    pub fn export_room_keys(&self, passphrase: Vec<u8>, channel_ids: Vec<String>) -> Promise {
        let passphrase = secret_string(passphrase);
        let m = self.core();
        spawn_value(async move { Ok(KeyExport::from(m.export_room_keys(&passphrase?, &channel_ids).await?)) })
    }

    /// Import a key file (`data` of an export, or another Matrix client's);
    /// `WrongPassphrase` / `InvalidKeyFile` on failure, nothing imported then
    #[wasm_bindgen(js_name = importRoomKeys)]
    pub fn import_room_keys(&self, file: String, passphrase: Vec<u8>) -> Promise {
        let passphrase = secret_string(passphrase);
        let m = self.core();
        spawn_value(async move { Ok(KeyImportResult::from(m.import_room_keys(&file, &passphrase?).await?)) })
    }

    /// Diagnostic report (JSON, CR-22): counts, states and error codes, no
    /// keys, ids of others, ciphertext or text — for "Send report"
    #[wasm_bindgen(js_name = debugReport)]
    pub fn debug_report(&self) -> Promise {
        let m = self.core();
        spawn(async move { Ok(m.debug_report().await?.into()) })
    }
}

/// Restore of the key backup in batches (CR-12): `next()` until finished;
/// `free()` it when done
#[derive(Debug)]
#[wasm_bindgen]
pub struct BackupRestore {
    inner: Rc<Mutex<sc::BackupRestore>>,
}

#[wasm_bindgen]
impl BackupRestore {
    /// `{done, total, imported, failed, finished}`
    pub fn progress(&self) -> Promise {
        let r = self.inner.clone();
        spawn_value(async move { Ok(RestoreProgress::from(r.lock().await.progress())) })
    }

    /// Import up to `max` sessions (0 = the default batch)
    pub fn next(&self, max: u32) -> Promise {
        let r = self.inner.clone();
        spawn_value(async move { Ok(RestoreProgress::from(r.lock().await.next(max as usize).await?)) })
    }
}
