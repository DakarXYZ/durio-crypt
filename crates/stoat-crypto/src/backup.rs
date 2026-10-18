//! CR-12: server-side key backup, the recovery key and secret storage.
//!
//! * **Backup** — `m.megolm_backup.v1.curve25519-aes-sha2` (ADR 0001): room
//!   keys are encrypted to the backup's public key and uploaded in the
//!   background (`RequestKind::BackupKeys`, the library's batches of 100).
//!   Anybody who knows the public key — the server included — can add
//!   forged sessions, so keys restored from the backup are always
//!   `Verification::Unauthenticated`.
//! * **Secret storage** — `m.secret_storage.v1.aes-hmac-sha2` under
//!   `/e2ee/secrets/<type>`: the backup decryption key (random, 32 bytes)
//!   is stored as `m.megolm_backup.v1`, encrypted with the secret storage
//!   key. That key, base58-encoded, **is the recovery key** the user writes
//!   down (or it is derived from a passphrase with `m.pbkdf2`; then both the
//!   passphrase and its recovery key work). Rotating the backup keeps the
//!   recovery key.
//! * **Trust in the server** — the server can not read the secrets nor make
//!   a recovery key "work"; what it can do is caught: a backup version whose
//!   public key does not match the key in secret storage is refused
//!   (`BackupKeyMismatch`), uploads only ever go to the public key this
//!   device set up or verified, a new version made elsewhere stops uploads
//!   (`BackupVersionChanged`) until the user unlocks it with the recovery
//!   key, and a key description with an absurd PBKDF2 iteration count is
//!   refused before any work.
//!
//! State: the library stores the decryption key and version; the core
//! stores whether the backup is on (`stoat.backup.v1`), the secret storage
//! key for rotation (`stoat.recovery.v1`, encrypted by the store cipher like
//! the rest) and secret uploads not confirmed yet (`stoat.secrets.pending.v1`).

use std::collections::VecDeque;
use std::fmt;

use matrix_sdk_crypto::olm::ExportedRoomKey;
use matrix_sdk_crypto::secret_storage::{AesHmacSha2EncryptedData, SecretStorageKey};
use matrix_sdk_crypto::store::types::BackupDecryptionKey;
use matrix_sdk_crypto::types::RoomKeyBackupInfo;
use matrix_sdk_crypto::types::requests::KeysBackupRequest;
use ruma::api::IncomingResponseExt;
use ruma::api::client::backup::KeyBackupData;
use ruma::api::client::backup::add_backup_keys::v3::Response as KeysBackupResponse;
use ruma::events::EventContentFromType;
use ruma::events::secret::request::SecretName;
use ruma::events::secret_storage::key::SecretStorageKeyEventContent;
use ruma::{OwnedRoomId, RoomId, TransactionId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use stoat_crypto_proto::api::{self, BackupVersion, paths, secrets};
use stoat_crypto_proto::{BACKUP_ALGORITHM_MEGOLM_V1, b64, recovery_key};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CryptoError, Result};
use crate::machine::CryptoMachine;
use crate::requests::{OutgoingRequest, RequestKind};

/// Backup on/off and version as the core sees it
pub(crate) const KV_BACKUP: &str = "stoat.backup.v1";
/// The secret storage key (for rotation without asking the user again)
const KV_RECOVERY: &str = "stoat.recovery.v1";
/// Secret uploads not confirmed by the server yet
pub(crate) const KV_SECRETS_PENDING: &str = "stoat.secrets.pending.v1";
/// Upper bound of PBKDF2 rounds accepted from a key description (Matrix
/// clients use 500 000): a server must not make the device hash forever
const MAX_PBKDF2_ITERATIONS: u64 = 1_000_000;
/// Sessions decrypted and imported per [`BackupRestore::next`] by default
pub const RESTORE_BATCH: usize = 200;

fn store_err<E>(op: &'static str) -> impl FnOnce(E) -> CryptoError {
    move |_| CryptoError::Store(op)
}

fn invalid<E>(_: E) -> CryptoError {
    CryptoError::InvalidRecoveryData
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct BackupState {
    /// Version this device uploads to
    pub(crate) version: Option<String>,
    /// The server answered 404/409: another device replaced the backup
    pub(crate) outdated: bool,
}

/// The secret storage key, kept to store new secrets without the user
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct RecoveryState {
    key_id: String,
    /// base58, as the user wrote it down
    key: String,
    /// `m.secret_storage.key.<id>` content without the passphrase part
    #[zeroize(skip)]
    description: Value,
}

/// A secret upload not confirmed yet (its body is ciphertext)
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PendingSecret {
    id: String,
    secret_type: String,
    body: String,
}

impl PendingSecret {
    pub(crate) fn request(&self) -> OutgoingRequest {
        OutgoingRequest {
            id: self.id.clone(),
            kind: RequestKind::SecretPut,
            method: "PUT",
            path: paths::secret(&self.secret_type),
            body: self.body.clone(),
        }
    }
}

/// A backup being set up: kept until the server created the version
pub(crate) struct PendingRecovery {
    request_id: String,
    ssss: SecretStorageKey,
    /// new secret storage key (create): its description and default go up too
    new_key: bool,
    backup_key: BackupDecryptionKey,
}

impl fmt::Debug for PendingRecovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingRecovery")
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

/// What `create_recovery` / `rotate_backup` hand to the UI
pub struct RecoverySetup {
    recovery_key: Option<Zeroizing<String>>,
    /// `POST /e2ee/backup/version` (`RequestKind::BackupVersionCreate`); with
    /// `x-mfa-ticket` when a backup exists already
    pub request: OutgoingRequest,
}

impl RecoverySetup {
    /// The recovery key to show once and have written down (48 characters
    /// in groups of 4); `None` for a rotation (the key stays the same)
    pub fn recovery_key(&self) -> Option<&str> {
        self.recovery_key.as_deref().map(String::as_str)
    }
}

impl fmt::Debug for RecoverySetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoverySetup")
            .field("recovery_key", &self.recovery_key.as_ref().map(|_| "<redacted>"))
            .field("request", &self.request)
            .finish()
    }
}

/// Bodies of the four `GET`s a restore needs, as the server returned them
#[derive(Clone, Debug, Default)]
pub struct RecoverySecrets {
    /// `GET /e2ee/secrets/m.secret_storage.default_key`
    pub default_key: String,
    /// `GET /e2ee/secrets/m.secret_storage.key.<id>` (id from `default_key`)
    pub key_description: String,
    /// `GET /e2ee/secrets/m.megolm_backup.v1`
    pub backup_secret: String,
    /// `GET /e2ee/backup/version`
    pub backup_version: String,
}

/// Backup as the settings screen shows it
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupStatus {
    /// Version this device uploads to
    pub version: Option<String>,
    /// Uploading new keys
    pub enabled: bool,
    /// This device holds the secret storage key (can rotate)
    pub recovery_set_up: bool,
    /// The backup was replaced elsewhere: unlock again with the recovery key
    pub outdated: bool,
    /// Room keys on this device / of them in the backup
    pub keys_total: u64,
    pub keys_backed_up: u64,
}

/// Progress of a restore
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RestoreProgress {
    /// Sessions processed / in the backup
    pub done: usize,
    pub total: usize,
    /// New or better keys stored
    pub imported: usize,
    /// Entries that did not decrypt or parse (skipped)
    pub failed: usize,
}

impl RestoreProgress {
    pub fn is_finished(&self) -> bool {
        self.done >= self.total
    }
}

/// A restore in batches: [`next`](Self::next) until finished; each batch is
/// one store transaction. Interrupted → start again: an import never makes a
/// key worse (lower first index wins).
pub struct BackupRestore {
    machine: CryptoMachine,
    key: BackupDecryptionKey,
    version: String,
    queue: VecDeque<(OwnedRoomId, String, Value)>,
    progress: RestoreProgress,
}

impl fmt::Debug for BackupRestore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupRestore")
            .field("version", &self.version)
            .field("progress", &self.progress)
            .finish_non_exhaustive()
    }
}

impl BackupRestore {
    pub fn progress(&self) -> RestoreProgress {
        self.progress
    }

    /// Decrypt and import up to `max` sessions (0 = [`RESTORE_BATCH`])
    pub async fn next(&mut self, max: usize) -> Result<RestoreProgress> {
        let max = if max == 0 { RESTORE_BATCH } else { max };
        let mut keys = Vec::new();
        for _ in 0..max {
            let Some((room, session, data)) = self.queue.pop_front() else {
                break;
            };
            self.progress.done += 1;
            let decrypted = serde_json::from_value::<KeyBackupData>(data)
                .ok()
                .and_then(|d| self.key.decrypt_session_data(d.session_data).ok());
            match decrypted {
                Some(k) => keys.push(ExportedRoomKey::from_backed_up_room_key(room, session, k)),
                None => self.progress.failed += 1,
            }
        }
        if !keys.is_empty() {
            let r = self
                .machine
                .olm()
                .store()
                .import_room_keys(keys, Some(&self.version), |_, _| {})
                .await
                .map_err(store_err("import backup"))?;
            self.progress.imported += r.imported_count;
            self.machine.touch();
        }
        Ok(self.progress)
    }
}

/// `{"encrypted": {<key id>: {iv, ciphertext, mac}}}`
fn encrypted_secret(ssss: &SecretStorageKey, name: &str, plaintext: &[u8]) -> Result<String> {
    let data = ssss.encrypt(plaintext.to_vec(), &SecretName::from(name));
    let data = serde_json::to_value(&data).map_err(|_| CryptoError::Internal("secret"))?;
    Ok(json!({ "encrypted": { ssss.key_id(): data } }).to_string())
}

fn description(key_id: &str, value: &Value) -> Result<SecretStorageKeyEventContent> {
    let raw = serde_json::value::to_raw_value(value).map_err(invalid)?;
    SecretStorageKeyEventContent::from_parts(&secrets::key(key_id), &raw).map_err(invalid)
}

/// The secret storage key from what the user typed: a recovery key (typo
/// detection) or the passphrase
fn unlock_key(input: &str, key_id: &str, description_json: &str) -> Result<SecretStorageKey> {
    let value: Value = serde_json::from_str(description_json).map_err(invalid)?;
    let content = description(key_id, &value)?;
    if recovery_key::looks_like_recovery_key(input) {
        let bytes = recovery_key::decode(input).map_err(|_| CryptoError::RecoveryKeyTypo)?;
        let mut without_passphrase = content;
        without_passphrase.passphrase = None;
        return SecretStorageKey::from_account_data(&recovery_key::encode(&bytes), without_passphrase)
            .map_err(|_| CryptoError::WrongRecoveryKey);
    }
    let Some(p) = &content.passphrase else {
        return Err(CryptoError::WrongRecoveryKey);
    };
    if u64::from(p.iterations) > MAX_PBKDF2_ITERATIONS || p.algorithm.as_str() != "m.pbkdf2" {
        return Err(CryptoError::InvalidRecoveryData);
    }
    SecretStorageKey::from_account_data(input, content).map_err(|_| CryptoError::WrongRecoveryKey)
}

impl CryptoMachine {
    async fn backup_state(&self) -> Result<BackupState> {
        Ok(self
            .olm()
            .store()
            .get_value(KV_BACKUP)
            .await
            .map_err(store_err("read backup state"))?
            .unwrap_or_default())
    }

    async fn set_backup_state(&self, state: &BackupState) -> Result<()> {
        self.olm()
            .store()
            .set_value(KV_BACKUP, state)
            .await
            .map_err(store_err("save backup state"))
    }

    /// On open: keep uploading to the version this device had enabled
    pub(crate) async fn resume_backup(&self) -> Result<()> {
        let state = self.backup_state().await?;
        let Some(version) = state.version.filter(|_| !state.outdated) else {
            return Ok(());
        };
        let bm = self.olm().backup_machine();
        let keys = bm.get_backup_keys().await.map_err(store_err("backup keys"))?;
        if let (Some(key), Some(stored)) = (keys.decryption_key, keys.backup_version)
            && stored == version
        {
            let pk = key.megolm_v1_public_key();
            pk.set_version(version);
            bm.enable_backup_v1(pk).await.map_err(store_err("enable backup"))?;
        }
        Ok(())
    }

    /// Upload new keys to `version` with `key` from now on
    async fn enable_backup(&self, key: BackupDecryptionKey, version: &str) -> Result<()> {
        let bm = self.olm().backup_machine();
        // another version: every key goes up again
        if bm.backup_version().await.as_deref() != Some(version) {
            bm.disable_backup().await.map_err(store_err("reset backup"))?;
        }
        let pk = key.megolm_v1_public_key();
        pk.set_version(version.to_owned());
        bm.save_decryption_key(Some(key), Some(version.to_owned()))
            .await
            .map_err(store_err("save backup key"))?;
        bm.enable_backup_v1(pk).await.map_err(store_err("enable backup"))?;
        self.set_backup_state(&BackupState {
            version: Some(version.to_owned()),
            outdated: false,
        })
        .await?;
        self.touch();
        Ok(())
    }

    async fn recovery_state(&self) -> Result<Option<RecoveryState>> {
        self.olm()
            .store()
            .get_value(KV_RECOVERY)
            .await
            .map_err(store_err("read recovery"))
    }

    async fn save_recovery(&self, ssss: &SecretStorageKey) -> Result<()> {
        let mut description =
            serde_json::to_value(ssss.event_content()).map_err(|_| CryptoError::Internal("recovery"))?;
        if let Some(o) = description.as_object_mut() {
            o.remove("passphrase");
        }
        let state = RecoveryState {
            key_id: ssss.key_id().to_owned(),
            key: ssss.to_base58(),
            description,
        };
        self.olm()
            .store()
            .set_value(KV_RECOVERY, &state)
            .await
            .map_err(store_err("save recovery"))
    }

    fn version_request(&self, backup_key: &BackupDecryptionKey) -> Result<OutgoingRequest> {
        let info =
            serde_json::to_value(backup_key.to_backup_info()).map_err(|_| CryptoError::Internal("backup info"))?;
        Ok(OutgoingRequest {
            id: TransactionId::new().to_string(),
            kind: RequestKind::BackupVersionCreate,
            method: "POST",
            path: paths::BACKUP_VERSION.into(),
            body: info.to_string(),
        })
    }

    async fn begin_setup(&self, ssss: SecretStorageKey, new_key: bool) -> Result<RecoverySetup> {
        let backup_key = BackupDecryptionKey::new();
        let request = self.version_request(&backup_key)?;
        let recovery_key = new_key.then(|| Zeroizing::new(ssss.to_base58()));
        *self.recovery_pending().await = Some(PendingRecovery {
            request_id: request.id.clone(),
            ssss,
            new_key,
            backup_key,
        });
        Ok(RecoverySetup { recovery_key, request })
    }

    /// Set up (or reset) recovery: a new secret storage key — random, or
    /// from `passphrase` — and a new backup. Run the returned request; when
    /// it is marked sent the backup is on and the secrets are queued for
    /// upload. Replacing an existing backup needs an MFA ticket on the
    /// request (`MfaRequired` from `mark_request_failed` on 401).
    pub async fn create_recovery(&self, passphrase: Option<&str>) -> Result<RecoverySetup> {
        let ssss = match passphrase {
            Some(p) if !p.is_empty() => SecretStorageKey::new_from_passphrase(p),
            _ => SecretStorageKey::new(),
        };
        self.begin_setup(ssss, true).await
    }

    /// New backup version and backup key under the same recovery key (after
    /// a suspected leak of the backup key). Needs recovery set up on this
    /// device (`NoRecovery`) and an MFA ticket on the request.
    pub async fn rotate_backup(&self) -> Result<RecoverySetup> {
        let state = self.recovery_state().await?.ok_or(CryptoError::NoRecovery)?;
        let content = description(&state.key_id, &state.description)?;
        let ssss = SecretStorageKey::from_account_data(&state.key, content).map_err(|_| CryptoError::NoRecovery)?;
        self.begin_setup(ssss, false).await
    }

    /// `POST /e2ee/backup/version` answered `{version}`
    pub(crate) async fn backup_version_created(&self, id: &str, body: &str) -> Result<()> {
        let version = serde_json::from_str::<api::BackupVersionCreateResponse>(body)
            .map_err(|_| CryptoError::InvalidResponse("backup version"))?
            .version;
        let pending = {
            let mut p = self.recovery_pending().await;
            match p.as_ref() {
                Some(r) if r.request_id == id => p.take(),
                // an older setup, replaced by a newer one: ignore
                _ => None,
            }
        };
        let Some(PendingRecovery {
            ssss,
            new_key,
            backup_key,
            ..
        }) = pending
        else {
            return Ok(());
        };

        // secrets first into the store, so a crash cannot lose them
        let secret = Zeroizing::new(b64::encode(backup_key.as_bytes()));
        let mut uploads = vec![(
            secrets::MEGOLM_BACKUP_V1.to_owned(),
            encrypted_secret(&ssss, secrets::MEGOLM_BACKUP_V1, secret.as_bytes())?,
        )];
        if new_key {
            let description =
                serde_json::to_value(ssss.event_content()).map_err(|_| CryptoError::Internal("recovery"))?;
            uploads.push((secrets::key(ssss.key_id()), description.to_string()));
            uploads.push((
                secrets::DEFAULT_KEY.to_owned(),
                json!({ "key": ssss.key_id() }).to_string(),
            ));
        }
        let mut pending: Vec<PendingSecret> = self.pending_secrets().await?;
        // a newer value of the same secret replaces the queued one
        pending.retain(|p| !uploads.iter().any(|(t, _)| t == &p.secret_type));
        pending.extend(uploads.into_iter().map(|(secret_type, body)| PendingSecret {
            id: TransactionId::new().to_string(),
            secret_type,
            body,
        }));
        self.olm()
            .store()
            .set_value(KV_SECRETS_PENDING, &pending)
            .await
            .map_err(store_err("save pending secrets"))?;
        self.save_recovery(&ssss).await?;
        self.enable_backup(backup_key, &version).await?;
        for p in &pending {
            self.add_own_request(p.request()).await;
        }
        Ok(())
    }

    pub(crate) async fn pending_secrets(&self) -> Result<Vec<PendingSecret>> {
        Ok(self
            .olm()
            .store()
            .get_value(KV_SECRETS_PENDING)
            .await
            .map_err(store_err("read pending secrets"))?
            .unwrap_or_default())
    }

    /// `PUT /e2ee/secrets/<type>` succeeded
    pub(crate) async fn secret_stored(&self, id: &str) -> Result<()> {
        let mut pending = self.pending_secrets().await?;
        pending.retain(|p| p.id != id);
        self.olm()
            .store()
            .set_value(KV_SECRETS_PENDING, &pending)
            .await
            .map_err(store_err("save pending secrets"))
    }

    /// The next batch of room keys for the backup
    pub(crate) async fn backup_request(&self) -> Result<Option<OutgoingRequest>> {
        let Some((id, KeysBackupRequest { version, rooms })) = self
            .olm()
            .backup_machine()
            .backup()
            .await
            .map_err(store_err("backup"))?
        else {
            return Ok(None);
        };
        Ok(Some(OutgoingRequest {
            id: id.to_string(),
            kind: RequestKind::BackupKeys,
            method: "PUT",
            path: paths::backup_keys(&version),
            body: json!({ "rooms": rooms }).to_string(),
        }))
    }

    /// `PUT /e2ee/backup/keys` answered `{etag, count}`
    pub(crate) async fn backup_keys_sent(&self, id: &str, body: &str) -> Result<()> {
        let response = http::Response::builder()
            .status(200)
            .body(body.as_bytes())
            .map_err(|_| CryptoError::InvalidResponse("backup keys"))?;
        let response = KeysBackupResponse::try_from_http_response(response)
            .map_err(|_| CryptoError::InvalidResponse("backup keys"))?;
        let id: &TransactionId = id.into();
        self.olm()
            .mark_request_as_sent(id, &response)
            .await
            .map_err(store_err("mark backup sent"))
    }

    /// 404/409 on an upload: the backup was deleted or replaced elsewhere.
    /// Uploads stop until the user unlocks the new one (never follow a
    /// version this device did not verify).
    pub(crate) async fn backup_replaced(&self) -> Result<()> {
        self.olm()
            .backup_machine()
            .disable_backup()
            .await
            .map_err(store_err("disable backup"))?;
        let mut state = self.backup_state().await?;
        state.outdated = true;
        self.set_backup_state(&state).await?;
        Err(CryptoError::BackupVersionChanged)
    }

    /// Unlock the backup on this device with the recovery key or passphrase
    /// (`input`) and the four secret-storage bodies. On success this device
    /// uploads its keys too; then [`restore_backup`](Self::restore_backup).
    /// Returns the backup version.
    pub async fn unlock_backup(&self, input: &str, secrets: &RecoverySecrets) -> Result<String> {
        let default: Value = serde_json::from_str(&secrets.default_key).map_err(invalid)?;
        let key_id = default["key"].as_str().ok_or(CryptoError::InvalidRecoveryData)?;
        let ssss = unlock_key(input, key_id, &secrets.key_description)?;

        let secret: Value = serde_json::from_str(&secrets.backup_secret).map_err(invalid)?;
        let data: AesHmacSha2EncryptedData =
            serde_json::from_value(secret["encrypted"][key_id].clone()).map_err(invalid)?;
        let plaintext = Zeroizing::new(
            ssss.decrypt(&data, &SecretName::from(secrets::MEGOLM_BACKUP_V1))
                .map_err(invalid)?,
        );
        let encoded = std::str::from_utf8(&plaintext).map_err(invalid)?;
        let key = BackupDecryptionKey::from_base64(encoded.trim()).map_err(invalid)?;

        let version: BackupVersion = serde_json::from_str(&secrets.backup_version).map_err(invalid)?;
        if version.algorithm != BACKUP_ALGORITHM_MEGOLM_V1 {
            return Err(CryptoError::InvalidRecoveryData);
        }
        let info: RoomKeyBackupInfo =
            serde_json::from_value(json!({ "algorithm": version.algorithm, "auth_data": version.auth_data }))
                .map_err(invalid)?;
        // the server could point us at a backup of its own
        if !key.backup_key_matches(&info) {
            return Err(CryptoError::BackupKeyMismatch);
        }
        self.enable_backup(key, &version.version).await?;
        self.save_recovery(&ssss).await?;
        Ok(version.version)
    }

    /// Prepare the import of `GET /e2ee/backup/keys?version=<v>` (the body)
    /// with the key of the unlocked backup
    pub async fn restore_backup(&self, keys_body: &str) -> Result<BackupRestore> {
        let keys = self
            .olm()
            .backup_machine()
            .get_backup_keys()
            .await
            .map_err(store_err("backup keys"))?;
        let (Some(key), Some(version)) = (keys.decryption_key, keys.backup_version) else {
            return Err(CryptoError::NoBackup);
        };
        let body: api::KeysBackup =
            serde_json::from_str(keys_body).map_err(|_| CryptoError::InvalidResponse("backup keys"))?;
        let mut queue = VecDeque::new();
        for (room, r) in body.rooms {
            let Ok(room) = RoomId::parse(&room) else { continue };
            for (session, data) in r.sessions {
                let data = serde_json::to_value(&data).map_err(|_| CryptoError::Internal("backup keys"))?;
                queue.push_back((room.clone(), session, data));
            }
        }
        Ok(BackupRestore {
            machine: self.clone(),
            key,
            version,
            progress: RestoreProgress {
                total: queue.len(),
                ..RestoreProgress::default()
            },
            queue,
        })
    }

    /// For the settings screen
    pub async fn backup_status(&self) -> Result<BackupStatus> {
        let bm = self.olm().backup_machine();
        let counts = bm.room_key_counts().await.map_err(store_err("key counts"))?;
        let state = self.backup_state().await?;
        Ok(BackupStatus {
            version: state.version,
            enabled: bm.enabled().await,
            recovery_set_up: self.recovery_state().await?.is_some(),
            outdated: state.outdated,
            keys_total: counts.total as u64,
            keys_backed_up: counts.backed_up as u64,
        })
    }

    /// Stop uploading on this device (the server copy stays; deleting it is
    /// `DELETE /e2ee/backup/version/<v>` with an MFA ticket)
    pub async fn disable_backup(&self) -> Result<()> {
        self.olm()
            .backup_machine()
            .disable_backup()
            .await
            .map_err(store_err("disable backup"))?;
        self.set_backup_state(&BackupState::default()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Our recovery key text is the library's (and Matrix') for the same bytes
    #[test]
    fn recovery_key_matches_library_format() {
        for seed in [0u8, 9, 0xff] {
            let bytes = [seed; 32];
            let ours = recovery_key::encode(&bytes);
            // the library groups only the secret storage form
            assert_eq!(
                ours.replace(' ', ""),
                BackupDecryptionKey::from_bytes(&bytes).to_base58()
            );
            assert_eq!(BackupDecryptionKey::from_base58(&ours).unwrap().as_bytes(), &bytes);
        }
    }

    #[test]
    fn setup_debug_has_no_key() {
        let setup = RecoverySetup {
            recovery_key: Some(Zeroizing::new("EsSz ygLv VP1b".into())),
            request: OutgoingRequest {
                id: "x".into(),
                kind: RequestKind::BackupVersionCreate,
                method: "POST",
                path: paths::BACKUP_VERSION.into(),
                body: "{}".into(),
            },
        };
        let shown = format!("{setup:?}");
        assert!(!shown.contains("EsSz") && shown.contains("redacted"), "{shown}");
    }

    #[test]
    fn absurd_pbkdf2_rounds_are_refused_before_hashing() {
        let content = json!({
            "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
            "iv": "AAAAAAAAAAAAAAAAAAAAAA",
            "mac": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "passphrase": { "algorithm": "m.pbkdf2", "salt": "s", "iterations": 4_000_000_000u64 },
        });
        let e = unlock_key("a passphrase", "K", &content.to_string()).err();
        assert_eq!(e, Some(CryptoError::InvalidRecoveryData));
    }
}
