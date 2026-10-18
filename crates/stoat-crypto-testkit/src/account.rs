//! Users on the backend: registration (no e-mail verification on the test
//! stack), sessions (= E2EE devices), friends, DMs and groups.

use rand::Rng;
use rand::distributions::Alphanumeric;
use serde_json::{Value, json};
use stoat_crypto::ServerLimits;

use crate::Config;
use crate::http::{Http, HttpError};

/// The backend under test
#[derive(Clone, Debug)]
pub struct Stack {
    pub config: Config,
    /// `GET /` → `features.e2ee`
    pub limits: ServerLimits,
}

impl Stack {
    /// `None` when no backend is configured; panics if it is not E2EE-enabled
    pub async fn connect() -> Option<Self> {
        Self::connect_to(Config::from_env()?).await
    }

    /// Server 2 of T14 (`STOAT_API2`), if configured
    pub async fn connect_second() -> Option<Self> {
        Self::connect_to(Config::second_from_env()?).await
    }

    async fn connect_to(config: Config) -> Option<Self> {
        let root = Http::new(&config.api, None)
            .get("/")
            .await
            .unwrap_or_else(|e| panic!("backend at {} not reachable: {e}", config.api));
        let e2ee = &root["features"]["e2ee"];
        assert_eq!(e2ee["enabled"], true, "the backend has [features.e2ee] enabled = false");
        let defaults = ServerLimits::default();
        let limits = ServerLimits {
            max_to_device_batch: e2ee["max_to_device_batch"]
                .as_u64()
                .map_or(defaults.max_to_device_batch, |v| v as usize),
            max_request_bytes: e2ee["max_request_bytes"]
                .as_u64()
                .map_or(defaults.max_request_bytes, |v| v as usize),
        };
        Some(Self { config, limits })
    }

    pub fn anon(&self) -> Http {
        Http::new(&self.config.api, None)
    }

    /// A new verified, onboarded user with one session
    pub async fn register(&self, name: &str) -> Result<Account, HttpError> {
        let tag: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect::<String>()
            .to_lowercase();
        let email = format!("{name}-{tag}@testkit.invalid");
        let password = format!("testkit-{tag}-password");
        self.register_with(name, &tag, email, password).await
    }

    /// The same person (e-mail, password) on this server: a separate account
    pub async fn register_like(&self, name: &str, other: &Account) -> Result<Account, HttpError> {
        let tag = other
            .username
            .split('_')
            .next_back()
            .unwrap_or("x")
            .split('#')
            .next()
            .unwrap_or("x")
            .to_owned();
        self.register_with(name, &tag, other.email.clone(), other.password.clone())
            .await
    }

    async fn register_with(
        &self,
        name: &str,
        tag: &str,
        email: String,
        password: String,
    ) -> Result<Account, HttpError> {
        let anon = self.anon();
        anon.call(
            "POST",
            "/auth/account/create",
            Some(&json!({ "email": email, "password": password })),
        )
        .await?;
        let mut account = Account {
            stack: self.clone(),
            user_id: String::new(),
            username: String::new(),
            email,
            password,
            token: String::new(),
            session_id: String::new(),
        };
        account.login().await?;
        let user = account
            .http()
            .post("/onboard/complete", &json!({ "username": format!("{name}_{tag}") }))
            .await?;
        account.username = format!(
            "{}#{}",
            user["username"].as_str().unwrap_or_default(),
            user["discriminator"].as_str().unwrap_or_default()
        );
        Ok(account)
    }
}

/// A user and its current session
#[derive(Clone, Debug)]
pub struct Account {
    pub stack: Stack,
    pub user_id: String,
    /// `name#discriminator`
    pub username: String,
    pub email: String,
    pub password: String,
    pub token: String,
    /// Session id = E2EE device id
    pub session_id: String,
}

impl Account {
    pub fn http(&self) -> Http {
        Http::new(&self.stack.config.api, Some(self.token.clone()))
    }

    /// New session on this account (a new device); `self` switches to it
    pub async fn login(&mut self) -> Result<(), HttpError> {
        let r = self
            .stack
            .anon()
            .post(
                "/auth/session/login",
                &json!({ "email": self.email, "password": self.password, "friendly_name": "testkit" }),
            )
            .await?;
        assert_eq!(r["result"], "Success", "login: {r}");
        self.user_id = r["user_id"].as_str().unwrap_or_default().to_owned();
        self.token = r["token"].as_str().unwrap_or_default().to_owned();
        self.session_id = r["_id"].as_str().unwrap_or_default().to_owned();
        Ok(())
    }

    /// The same user on another device
    pub async fn new_device(&self) -> Result<Account, HttpError> {
        let mut other = self.clone();
        other.login().await?;
        Ok(other)
    }

    /// `POST /auth/session/logout`: the backend deletes the device, its keys
    /// and mailbox and announces `E2eeDeviceListUpdate`
    pub async fn logout(&self) -> Result<(), HttpError> {
        self.http().call("POST", "/auth/session/logout", None).await.map(|_| ())
    }

    /// Validated MFA ticket (password) for `x-mfa-ticket`
    pub async fn mfa_ticket(&self) -> Result<String, HttpError> {
        let r = self
            .http()
            .put("/auth/mfa/ticket", Some(&json!({ "password": self.password })))
            .await?;
        Ok(r["token"].as_str().unwrap_or_default().to_owned())
    }

    /// Friend request + accept
    pub async fn befriend(&self, other: &Account) -> Result<(), HttpError> {
        self.http()
            .post("/users/friend", &json!({ "username": other.username }))
            .await?;
        other
            .http()
            .put(&format!("/users/{}/friend", self.user_id), None)
            .await?;
        Ok(())
    }

    /// Encrypted DM with a friend (encryption switched on by `self`)
    pub async fn encrypted_dm(&self, other: &Account) -> Result<String, HttpError> {
        let dm = self.http().get(&format!("/users/{}/dm", other.user_id)).await?;
        let id = dm["_id"].as_str().unwrap_or_default().to_owned();
        self.enable_encryption(&id).await?;
        Ok(id)
    }

    /// Encrypted group with friends
    pub async fn encrypted_group(&self, name: &str, members: &[&Account]) -> Result<String, HttpError> {
        let users: Vec<&str> = members.iter().map(|m| m.user_id.as_str()).collect();
        let g = self
            .http()
            .post("/channels/create", &json!({ "name": name, "users": users }))
            .await?;
        let id = g["_id"].as_str().unwrap_or_default().to_owned();
        self.enable_encryption(&id).await?;
        Ok(id)
    }

    pub async fn enable_encryption(&self, channel: &str) -> Result<Value, HttpError> {
        self.http()
            .put(
                &format!("/channels/{channel}/encryption"),
                Some(&json!({ "algorithm": stoat_crypto::proto::ALGORITHM_MEGOLM })),
            )
            .await
    }

    pub async fn add_member(&self, group: &str, member: &Account) -> Result<(), HttpError> {
        self.http()
            .put(&format!("/channels/{group}/recipients/{}", member.user_id), None)
            .await
            .map(|_| ())
    }

    /// `POST /push/subscribe` as an FCM device of this session
    pub async fn subscribe_fcm(&self, token: &str) -> Result<(), HttpError> {
        self.http()
            .call(
                "POST",
                "/push/subscribe",
                Some(&json!({ "endpoint": "fcm", "p256dh": "", "auth": token })),
            )
            .await
            .map(|_| ())
    }

    pub async fn remove_member(&self, group: &str, member: &Account) -> Result<(), HttpError> {
        self.http()
            .call(
                "DELETE",
                &format!("/channels/{group}/recipients/{}", member.user_id),
                None,
            )
            .await
            .map(|_| ())
    }

    /// Member ids of a DM/group as the server reports them
    pub async fn members(&self, channel: &str) -> Result<Vec<String>, HttpError> {
        let c = self.http().get(&format!("/channels/{channel}")).await?;
        Ok(c["recipients"]
            .as_array()
            .map(|r| r.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
            .unwrap_or_default())
    }
}
