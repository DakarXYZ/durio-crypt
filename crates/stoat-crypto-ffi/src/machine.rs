//! `CryptoMachine` for Kotlin: the core façade with JSON bodies and owned
//! values at the boundary. The host contract (order of calls, request
//! passes, ids in flight) is the core's — `stoat_crypto` crate docs.

use std::sync::Arc;

use stoat_crypto as sc;
use stoat_crypto::proto::api::{KeysCountResponse, ToDeviceFetchResponse};

use crate::backup::BackupRestore;
use crate::error::CryptoError;
use crate::runtime::{InRuntime, guard, run, run_value};
use crate::sas::SasHandle;
use crate::types::{
    BackupStatus, ChannelEncryptionSettings, DecryptResult, DeviceInfo, IdentityKeys, IncomingEncryptedMessage,
    KeyExport, KeyImportResult, OutgoingRequest, RecoverySecrets, RecoverySetup, RequestKind, ServerLimits,
    StoreConfig, Timing, ToDeviceResult, Trust, UndeliveredDevice, payload_from_json, requests, secret_string,
};

/// Crypto state of one account on one server. Open once per process
/// (`StoreLocked` otherwise) and `close()` it on logout or account switch:
/// the store stays locked while this object, a `SasHandle` or a
/// `BackupRestore` of it is open.
#[derive(Debug, uniffi::Object)]
pub struct CryptoMachine {
    inner: InRuntime<sc::CryptoMachine>,
}

impl CryptoMachine {
    fn core(&self) -> sc::CryptoMachine {
        (*self.inner).clone()
    }
}

#[uniffi::export]
impl CryptoMachine {
    /// Open (or create) the state of `user_id` (ULID) on this device
    /// (session ULID)
    #[uniffi::constructor]
    pub async fn open(user_id: String, device_id: String, store: StoreConfig) -> Result<Arc<Self>, CryptoError> {
        let store = store.into_core()?;
        run(async move {
            let inner = sc::CryptoMachine::open(&user_id, &device_id, store).await?;
            Ok(Arc::new(Self {
                inner: InRuntime::new(inner),
            }))
        })
        .await
    }

    pub fn user_id(&self) -> String {
        self.inner.user_id().to_owned()
    }

    pub fn device_id(&self) -> String {
        self.inner.device_id().to_owned()
    }

    pub fn identity_keys(&self) -> Result<IdentityKeys, CryptoError> {
        guard(|| Ok(self.inner.identity_keys().into()))
    }

    // ------------------------------------------------------------ requests

    pub async fn set_server_limits(&self, limits: ServerLimits) -> Result<(), CryptoError> {
        let m = self.core();
        run(async move {
            m.set_server_limits(limits.into()).await;
            Ok(())
        })
        .await
    }

    pub async fn set_timing(&self, timing: Timing) -> Result<(), CryptoError> {
        let m = self.core();
        run(async move {
            m.set_timing(timing.into()).await;
            Ok(())
        })
        .await
    }

    /// The request pass: run each id once (keep a set of ids in flight)
    pub async fn outgoing_requests(&self) -> Result<Vec<OutgoingRequest>, CryptoError> {
        let m = self.core();
        run(async move { Ok(requests(m.outgoing_requests().await?)) }).await
    }

    /// 2xx: `body` = the response JSON (empty for 204)
    pub async fn mark_request_sent(&self, id: String, kind: RequestKind, body: String) -> Result<(), CryptoError> {
        let m = self.core();
        run(async move { Ok(m.mark_request_sent(&id, kind.into(), &body).await?) }).await
    }

    /// Non-2xx (or no response): `MfaRequired`, `BackupVersionChanged` and
    /// `DeviceKeysConflict` need the UI; other failures come back later
    pub async fn mark_request_failed(&self, id: String, kind: RequestKind, status: u16) -> Result<(), CryptoError> {
        let m = self.core();
        run(async move { Ok(m.mark_request_failed(&id, kind.into(), status).await?) }).await
    }

    /// When to run a request pass without any other event (`None`: nothing
    /// scheduled). The core has no timers: the host schedules it.
    pub async fn wakeup_in_ms(&self) -> Result<Option<u64>, CryptoError> {
        let m = self.core();
        run_value(async move { m.wakeup_in_ms().await }).await
    }

    pub async fn undelivered_devices(&self) -> Result<Vec<UndeliveredDevice>, CryptoError> {
        let m = self.core();
        run_value(async move { m.undelivered_devices().await.into_iter().map(Into::into).collect() }).await
    }

    // ------------------------------------------------------------- mailbox

    /// `GET /e2ee/to_device?limit=N` response body
    pub async fn receive_to_device(&self, body: String) -> Result<ToDeviceResult, CryptoError> {
        let page: ToDeviceFetchResponse =
            serde_json::from_str(&body).map_err(|_| sc::CryptoError::InvalidResponse("to-device fetch"))?;
        let fetched = page.messages.len();
        let m = self.core();
        run(async move { Ok(ToDeviceResult::new(fetched, m.receive_to_device(page.messages).await?)) }).await
    }

    /// `POST /e2ee/to_device/ack {ids}` succeeded
    pub async fn mark_ack_sent(&self, ack_ids: Vec<String>) -> Result<(), CryptoError> {
        let m = self.core();
        run(async move { Ok(m.mark_ack_sent(&ack_ids).await?) }).await
    }

    /// `E2eeDeviceListUpdate {user}` (user ULIDs)
    pub async fn receive_device_list_update(&self, users: Vec<String>) -> Result<(), CryptoError> {
        let m = self.core();
        run(async move { Ok(m.receive_device_list_update(&users).await?) }).await
    }

    /// Socket `Ready` after a reconnect
    pub async fn receive_reconnect(&self) -> Result<(), CryptoError> {
        let m = self.core();
        run(async move { Ok(m.receive_reconnect().await?) }).await
    }

    /// `GET /e2ee/keys/count` response body
    pub async fn receive_otk_counts(&self, body: String) -> Result<(), CryptoError> {
        let counts: KeysCountResponse =
            serde_json::from_str(&body).map_err(|_| sc::CryptoError::InvalidResponse("keys count"))?;
        let m = self.core();
        run(async move { Ok(m.receive_otk_counts(&counts).await?) }).await
    }

    // ------------------------------------------------------------ channels

    /// Full member list (ULIDs) of an encrypted DM/group and its settings
    pub async fn set_channel_members(
        &self,
        channel_id: String,
        members: Vec<String>,
        settings: ChannelEncryptionSettings,
    ) -> Result<(), CryptoError> {
        let m = self.core();
        run(async move { Ok(m.set_channel_members(&channel_id, &members, settings.into()).await?) }).await
    }

    /// Requests to run before `encrypt` (claim, key share); loop until empty
    pub async fn prepare_send(&self, channel_id: String) -> Result<Vec<OutgoingRequest>, CryptoError> {
        let m = self.core();
        run(async move { Ok(requests(m.prepare_send(&channel_id).await?)) }).await
    }

    /// Payload v1 JSON → envelope JSON for `encrypted` of the send request
    pub async fn encrypt(&self, channel_id: String, payload_json: String) -> Result<String, CryptoError> {
        let payload = payload_from_json(&payload_json)?;
        drop(payload_json);
        let m = self.core();
        run(async move { Ok(m.encrypt(&channel_id, &payload).await?.to_value().to_string()) }).await
    }

    pub async fn invalidate_outbound_session(&self, channel_id: String) -> Result<(), CryptoError> {
        let m = self.core();
        run(async move { Ok(m.invalidate_outbound_session(&channel_id).await?) }).await
    }

    /// One message; a failure is a `DecryptResult.Failed`, not an exception
    pub async fn decrypt(&self, message: IncomingEncryptedMessage) -> Result<DecryptResult, CryptoError> {
        let message = match message.into_core() {
            Ok(m) => m,
            Err(failed) => return Ok(failed),
        };
        let m = self.core();
        run_value(async move { DecryptResult::from(m.decrypt(&message).await) }).await
    }

    /// A history page: results in input order
    pub async fn decrypt_batch(
        &self,
        messages: Vec<IncomingEncryptedMessage>,
    ) -> Result<Vec<DecryptResult>, CryptoError> {
        let mut out: Vec<Option<DecryptResult>> = Vec::with_capacity(messages.len());
        let mut valid = Vec::new();
        for message in messages {
            match message.into_core() {
                Ok(m) => {
                    valid.push(m);
                    out.push(None);
                }
                Err(failed) => out.push(Some(failed)),
            }
        }
        let m = self.core();
        let decrypted = run_value(async move { m.decrypt_batch(&valid).await }).await?;
        let mut decrypted = decrypted.into_iter();
        Ok(out
            .into_iter()
            .map(|r| match r {
                Some(failed) => failed,
                None => decrypted
                    .next()
                    .map(DecryptResult::from)
                    .unwrap_or_else(|| sc::DecryptError::Internal.into()),
            })
            .collect())
    }

    // ------------------------------------------------------------- devices

    pub async fn devices(&self, user_id: String) -> Result<Vec<DeviceInfo>, CryptoError> {
        let m = self.core();
        run(async move { Ok(m.devices(&user_id).await?.into_iter().map(Into::into).collect()) }).await
    }

    pub async fn set_device_trust(&self, user_id: String, device_id: String, trust: Trust) -> Result<(), CryptoError> {
        let m = self.core();
        run(async move { Ok(m.set_device_trust(&user_id, &device_id, trust.into()).await?) }).await
    }

    // -------------------------------------------------------- verification

    /// Ask a device to verify (SAS); the request leaves with the next pass
    pub async fn request_verification(
        &self,
        user_id: String,
        device_id: String,
    ) -> Result<Arc<SasHandle>, CryptoError> {
        let m = self.core();
        run(async move {
            Ok(Arc::new(SasHandle::new(
                m.request_verification(&user_id, &device_id).await?,
            )))
        })
        .await
    }

    /// The flow of an id from `ToDeviceResult.verifications`
    pub fn verification(&self, flow_id: String) -> Result<Option<Arc<SasHandle>>, CryptoError> {
        guard(|| Ok(self.inner.verification(&flow_id).map(|h| Arc::new(SasHandle::new(h)))))
    }

    /// Every flow the machine knows (open and recently finished)
    pub fn verifications(&self) -> Result<Vec<Arc<SasHandle>>, CryptoError> {
        guard(|| {
            Ok(self
                .inner
                .verifications()
                .into_iter()
                .map(|h| Arc::new(SasHandle::new(h)))
                .collect())
        })
    }

    // -------------------------------------------------------------- backup

    /// New recovery key (+ optional passphrase, UTF-8 bytes; the caller
    /// zeroes its array) and the backup version request
    pub async fn create_recovery(&self, passphrase: Option<Vec<u8>>) -> Result<RecoverySetup, CryptoError> {
        let passphrase = passphrase.map(secret_string).transpose()?;
        let m = self.core();
        run(async move {
            Ok(m.create_recovery(passphrase.as_deref().map(String::as_str))
                .await?
                .into())
        })
        .await
    }

    /// A new backup version under the same recovery key (needs MFA)
    pub async fn rotate_backup(&self) -> Result<RecoverySetup, CryptoError> {
        let m = self.core();
        run(async move { Ok(m.rotate_backup().await?.into()) }).await
    }

    /// Recovery key or passphrase (UTF-8 bytes) + the four GET bodies →
    /// the backup version to fetch keys of
    pub async fn unlock_backup(&self, input: Vec<u8>, secrets: RecoverySecrets) -> Result<String, CryptoError> {
        let input = secret_string(input)?;
        let m = self.core();
        run(async move { Ok(m.unlock_backup(&input, &secrets.into()).await?) }).await
    }

    /// `GET /e2ee/backup/keys?version=<v>` body → a restore in batches
    pub async fn restore_backup(&self, keys_body: String) -> Result<Arc<BackupRestore>, CryptoError> {
        let m = self.core();
        run(async move { Ok(Arc::new(BackupRestore::new(m.restore_backup(&keys_body).await?))) }).await
    }

    pub async fn backup_status(&self) -> Result<BackupStatus, CryptoError> {
        let m = self.core();
        run(async move { Ok(m.backup_status().await?.into()) }).await
    }

    pub async fn disable_backup(&self) -> Result<(), CryptoError> {
        let m = self.core();
        run(async move { Ok(m.disable_backup().await?) }).await
    }

    // ---------------------------------------------------------- key export

    /// Room keys of `channel_ids` (all if empty) → a file encrypted with
    /// `passphrase` (UTF-8 bytes, not empty; the caller zeroes its array).
    /// About a second of PBKDF2.
    pub async fn export_room_keys(
        &self,
        passphrase: Vec<u8>,
        channel_ids: Vec<String>,
    ) -> Result<KeyExport, CryptoError> {
        let passphrase = secret_string(passphrase)?;
        let m = self.core();
        run(async move { Ok(m.export_room_keys(&passphrase, &channel_ids).await?.into()) }).await
    }

    /// Diagnostic report (JSON, CR-22): counts, states and error codes, no
    /// keys, ids of others, ciphertext or text — for "Send report"
    pub async fn debug_report(&self) -> Result<String, CryptoError> {
        let m = self.core();
        run(async move { Ok(m.debug_report().await?) }).await
    }

    /// Import a key file (`data` of an export, or another Matrix client's);
    /// `WrongPassphrase` / `InvalidKeyFile` on failure, nothing imported then
    pub async fn import_room_keys(&self, file: String, passphrase: Vec<u8>) -> Result<KeyImportResult, CryptoError> {
        let passphrase = secret_string(passphrase)?;
        let m = self.core();
        run(async move { Ok(m.import_room_keys(&file, &passphrase).await?.into()) }).await
    }
}

/// Delete the store of a signed-out account (after `close()` of its machine)
#[uniffi::export]
pub fn destroy_store(store: StoreConfig) -> Result<(), CryptoError> {
    let store = store.into_core()?;
    guard(|| Ok(sc::CryptoMachine::destroy(&store)?))
}
