use reqwest::blocking::{Client, RequestBuilder};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::json;
use std::{
    io::Read,
    time::{Duration, Instant},
};
use url::Url;
use zeroize::Zeroizing;

pub const HOSTED_ORIGIN: &str = "https://accounts.raznet.online";
const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Origin,
    Protocol,
    Transport,
    Pending,
    SlowDown,
    Denied,
    Expired,
    LoginRequired,
    Conflict,
    NoActivePersona,
    NotFound,
    Storage,
    Rejected(u16),
}

fn origin(raw: &str) -> Result<String, Error> {
    let url = Url::parse(raw).map_err(|_| Error::Origin)?;
    let canonical = url.origin().ascii_serialization();
    if url.scheme() != "https"
        || raw.trim_end_matches('/') != canonical
        || raw.len() > canonical.len() + 1
    {
        return Err(Error::Origin);
    }
    Ok(canonical)
}

fn credential_binding(base: &str, ca_pem: Option<&[u8]>) -> String {
    use sha2::{Digest, Sha256};
    format!("{base}|{:x}", Sha256::digest(ca_pem.unwrap_or_default()))
}

fn receive<T: DeserializeOwned>(request: RequestBuilder, expected: u16) -> Result<T, Error> {
    let response = request.send().map_err(|_| Error::Transport)?;
    let status = response.status().as_u16();
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take(2_097_153)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Transport)?;
    if bytes.len() > 2_097_152 {
        return Err(Error::Protocol);
    }
    if status != expected {
        #[derive(Deserialize)]
        struct Failure {
            error: String,
        }
        let failure = serde_json::from_slice::<Failure>(&bytes).ok();
        return Err(match (status, failure.as_ref().map(|f| f.error.as_str())) {
            (400, Some("authorization_pending")) => Error::Pending,
            (400 | 429, Some("slow_down")) => Error::SlowDown,
            (400, Some("access_denied")) => Error::Denied,
            (400, Some("expired_token")) => Error::Expired,
            (400, Some("invalid_grant")) | (401, _) => Error::LoginRequired,
            (409, Some("revision_conflict")) => Error::Conflict,
            (409, Some("no_active_persona")) => Error::NoActivePersona,
            (404, _) => Error::NotFound,
            _ => Error::Rejected(status),
        });
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::Protocol)
}

#[derive(Deserialize, Clone)]
struct Discovery {
    protocol: String,
    version: u32,
    issuer: String,
    device_authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
    user_endpoint: String,
    verification_uri: String,
    grant_types_supported: Vec<String>,
    scopes_supported: Vec<String>,
}
impl Discovery {
    fn validate(&self, base: &str) -> Result<(), Error> {
        if self.protocol != "toastram.account-device"
            || self.version != 1
            || ![GRANT, "refresh_token"]
                .iter()
                .all(|x| self.grant_types_supported.iter().any(|s| s == x))
            || !["profile", "persona", "memory"]
                .iter()
                .all(|x| self.scopes_supported.iter().any(|s| s == x))
        {
            return Err(Error::Protocol);
        }
        if self.issuer != base {
            return Err(Error::Origin);
        }
        for (endpoint, path) in [
            (&self.device_authorization_endpoint, "/v1/auth/device"),
            (&self.token_endpoint, "/v1/auth/token"),
            (&self.revocation_endpoint, "/v1/auth/revoke"),
            (&self.user_endpoint, "/v1/auth/me"),
            (&self.verification_uri, "/device"),
        ] {
            if *endpoint != format!("{base}{path}") {
                return Err(Error::Origin);
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct AccountClient {
    client: Client,
    config: Discovery,
    binding: String,
}
impl AccountClient {
    /// Optional CA comes from the operator, independently of discovery.
    pub fn discover(server: &str, ca_pem: Option<&[u8]>) -> Result<Self, Error> {
        let base = origin(server)?;
        let mut builder = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(20));
        if let Some(pem) = ca_pem {
            builder = builder.tls_built_in_root_certs(false).add_root_certificate(
                reqwest::Certificate::from_pem(pem).map_err(|_| Error::Origin)?,
            );
        }
        let client = builder.build().map_err(|_| Error::Transport)?;
        let config: Discovery = receive(
            client.get(format!("{base}/.well-known/toastram-configuration")),
            200,
        )?;
        config.validate(&base)?;
        let binding = credential_binding(&base, ca_pem);
        Ok(Self {
            client,
            config,
            binding,
        })
    }
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }
    pub fn authorize(&self, name: &str) -> Result<DeviceGrant, Error> {
        if !(1..=100).contains(&name.trim().chars().count()) {
            return Err(Error::Protocol);
        }
        let reply: DeviceReply = receive(
            self.client
                .post(&self.config.device_authorization_endpoint)
                .json(&json!({"device_name":name})),
            200,
        )?;
        let code = reply.user_code.as_bytes();
        if code.len() != 9
            || code[4] != b'-'
            || !code
                .iter()
                .enumerate()
                .all(|(i, c)| i == 4 || c.is_ascii_uppercase() || c.is_ascii_digit())
            || !(32..=256).contains(&reply.device_code.len())
            || reply.verification_uri != self.config.verification_uri
            || reply.verification_uri_complete
                != format!("{}?code={}", self.config.verification_uri, reply.user_code)
            || !(1..=86400).contains(&reply.expires_in)
            || reply.interval > 86400
        {
            return Err(Error::Protocol);
        }
        let now = Instant::now();
        let interval = Duration::from_secs(reply.interval.max(5));
        Ok(DeviceGrant {
            client: self.clone(),
            secret: Zeroizing::new(reply.device_code),
            user_code: reply.user_code,
            verification_url: reply.verification_uri_complete,
            deadline: now + Duration::from_secs(reply.expires_in),
            interval,
            next: now + interval,
            finished: false,
        })
    }
}
#[derive(Deserialize)]
struct DeviceReply {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}
pub struct DeviceGrant {
    client: AccountClient,
    secret: Zeroizing<String>,
    pub user_code: String,
    pub verification_url: String,
    pub deadline: Instant,
    pub interval: Duration,
    next: Instant,
    finished: bool,
}
#[derive(Deserialize)]
pub struct Tokens {
    #[serde(skip)]
    binding: String,
    access_token: String,
    refresh_token: String,
    token_type: String,
    device_id: String,
    scope: String,
    expires_in: u64,
}
impl Drop for Tokens {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}
impl Tokens {
    fn validate(&self) -> Result<(), Error> {
        if self.token_type != "Bearer"
            || !(1..=86400).contains(&self.expires_in)
            || uuid::Uuid::parse_str(&self.device_id).is_err()
            || !["profile", "persona", "memory"]
                .iter()
                .all(|scope| self.scope.split_whitespace().any(|s| s == *scope))
            || [&self.access_token, &self.refresh_token].iter().any(|s| {
                !(32..=256).contains(&s.len())
                    || !s
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            })
        {
            return Err(Error::Protocol);
        }
        Ok(())
    }
}
impl DeviceGrant {
    pub fn poll(&mut self) -> Result<Tokens, Error> {
        let now = Instant::now();
        if self.finished || now >= self.deadline {
            return Err(Error::Expired);
        }
        if now < self.next {
            return Err(Error::Pending);
        }
        #[derive(serde::Serialize)]
        struct Poll<'a> {
            grant_type: &'a str,
            device_code: &'a str,
        }
        let result = receive::<Tokens>(
            self.client
                .client
                .post(&self.client.config.token_endpoint)
                .json(&Poll {
                    grant_type: GRANT,
                    device_code: &self.secret,
                }),
            200,
        );
        match &result {
            Err(Error::SlowDown) => self.interval += Duration::from_secs(5),
            Err(Error::Pending) => (),
            _ => self.finished = true,
        }
        self.next = Instant::now() + self.interval;
        let mut tokens = result?;
        tokens.validate()?;
        tokens.binding = self.client.binding.clone();
        Ok(tokens)
    }
}
#[derive(serde::Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Identity {
    pub account_id: uuid::Uuid,
    pub device_id: uuid::Uuid,
    pub username: String,
    pub scope: String,
}

#[derive(serde::Serialize, Deserialize)]
struct Stored {
    issuer: String,
    account_id: uuid::Uuid,
    device_id: uuid::Uuid,
    refresh: String,
}
impl Drop for Stored {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.refresh.zeroize();
    }
}

pub struct Session {
    client: AccountClient,
    identity: Identity,
    access: Zeroizing<String>,
    expires: Instant,
}
impl AccountClient {
    fn identity(&self, tokens: &Tokens) -> Result<Identity, Error> {
        tokens.validate()?;
        let identity: Identity = receive(
            self.client
                .get(&self.config.user_endpoint)
                .bearer_auth(&tokens.access_token),
            200,
        )?;
        if identity.device_id.to_string() != tokens.device_id || identity.scope != tokens.scope {
            return Err(Error::Protocol);
        }
        Ok(identity)
    }
    fn session(&self, identity: Identity, tokens: &Tokens) -> Session {
        Session {
            client: self.clone(),
            identity,
            access: Zeroizing::new(tokens.access_token.clone()),
            expires: Instant::now() + Duration::from_secs(tokens.expires_in.saturating_sub(15)),
        }
    }
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
mod platform_store {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs::{File, OpenOptions};
    struct Vault {
        entry: keyring::Entry,
        _lock: File,
    }
    impl Vault {
        fn open(binding: &str) -> Result<Self, Error> {
            let id = format!("{:x}", Sha256::digest(binding.as_bytes()));
            #[cfg(windows)]
            let root = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from);
            #[cfg(target_os = "macos")]
            let root = std::env::var_os("HOME")
                .map(|p| std::path::PathBuf::from(p).join("Library/Application Support"));
            #[cfg(target_os = "linux")]
            let root = std::env::var_os("XDG_DATA_HOME")
                .map(std::path::PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME")
                        .map(|p| std::path::PathBuf::from(p).join(".local/share"))
                });
            let dir = root
                .ok_or(Error::Storage)?
                .join("ToastRAMConnect")
                .join("account-locks");
            std::fs::create_dir_all(&dir).map_err(|_| Error::Storage)?;
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(dir.join(&id))
                .map_err(|_| Error::Storage)?;
            file.try_lock().map_err(|_| Error::Storage)?;
            Ok(Vault {
                entry: keyring::Entry::new("ToastRAM.Connect.Account.v1", &id)
                    .map_err(|_| Error::Storage)?,
                _lock: file,
            })
        }
    }
    impl AccountClient {
        fn vault(&self) -> Result<Vault, Error> {
            Vault::open(&self.binding)
        }
        pub fn forget_offline(server: &str, ca_pem: Option<&[u8]>) -> Result<(), Error> {
            let binding = credential_binding(&origin(server)?, ca_pem);
            match Vault::open(&binding)?.entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(_) => Err(Error::Storage),
            }
        }
        fn persist(&self, v: &Vault, identity: &Identity, tokens: &Tokens) -> Result<(), Error> {
            let record = Stored {
                issuer: self.binding.clone(),
                account_id: identity.account_id,
                device_id: identity.device_id,
                refresh: tokens.refresh_token.clone(),
            };
            let bytes = Zeroizing::new(serde_json::to_string(&record).map_err(|_| Error::Storage)?);
            v.entry.set_password(&bytes).map_err(|_| Error::Storage)
        }
        pub fn accept(&self, tokens: Tokens) -> Result<Session, Error> {
            if tokens.binding != self.binding {
                return Err(Error::Origin);
            }
            let v = self.vault()?;
            let identity = self.identity(&tokens)?;
            self.persist(&v, &identity, &tokens)?;
            Ok(self.session(identity, &tokens))
        }
        pub fn restore(&self) -> Result<Session, Error> {
            self.rotate(None)
        }
        fn rotate(&self, expected: Option<&Identity>) -> Result<Session, Error> {
            let v = self.vault()?;
            let data = Zeroizing::new(v.entry.get_password().map_err(|e| {
                if matches!(e, keyring::Error::NoEntry) {
                    Error::LoginRequired
                } else {
                    Error::Storage
                }
            })?);
            if *data == "rotating" {
                return Err(Error::LoginRequired);
            }
            let stored: Stored = serde_json::from_str(&data).map_err(|_| Error::Storage)?;
            if stored.issuer != self.binding
                || expected.is_some_and(|i| {
                    i.account_id != stored.account_id || i.device_id != stored.device_id
                })
            {
                return Err(Error::LoginRequired);
            }
            // Persist the in-flight state before transmission. A crash or lost response
            // requires a new browser approval; replaying the predecessor is unsafe.
            v.entry
                .set_password("rotating")
                .map_err(|_| Error::Storage)?;
            #[derive(serde::Serialize)]
            struct Refresh<'a> {
                grant_type: &'a str,
                refresh_token: &'a str,
            }
            let tokens: Tokens = receive(
                self.client
                    .post(&self.config.token_endpoint)
                    .json(&Refresh {
                        grant_type: "refresh_token",
                        refresh_token: &stored.refresh,
                    }),
                200,
            )?;
            let identity = self.identity(&tokens)?;
            if identity.account_id != stored.account_id || identity.device_id != stored.device_id {
                return Err(Error::LoginRequired);
            }
            self.persist(&v, &identity, &tokens)?;
            Ok(self.session(identity, &tokens))
        }
        pub fn forget_device(&self, identity: &Identity) -> Result<(), Error> {
            let vault = self.vault()?;
            let data = match vault.entry.get_password() {
                Ok(s) => Zeroizing::new(s),
                Err(keyring::Error::NoEntry) => return Ok(()),
                Err(_) => return Err(Error::Storage),
            };
            if *data == "rotating" {
                return Ok(());
            }
            let record: Stored = serde_json::from_str(&data).map_err(|_| Error::Storage)?;
            if record.device_id == identity.device_id
                && record.account_id == identity.account_id
                && record.issuer == self.binding
            {
                vault
                    .entry
                    .delete_credential()
                    .map_err(|_| Error::Storage)?;
            }
            Ok(())
        }
        pub fn forget_local(&self) -> Result<(), Error> {
            match self.vault()?.entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(_) => Err(Error::Storage),
            }
        }
    }
    impl Session {
        pub(super) fn ready(&mut self) -> Result<(), Error> {
            if self.access.is_empty() {
                return Err(Error::LoginRequired);
            }
            if Instant::now() >= self.expires {
                *self = self.client.rotate(Some(&self.identity))?;
            }
            Ok(())
        }
    }
}
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
impl Session {
    fn ready(&mut self) -> Result<(), Error> {
        Err(Error::Storage)
    }
}

const MAX_VISUAL_BYTES: usize = 2 * 1024 * 1024;

fn visual_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(serde::Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VisualKind {
    Avatar,
    Sprites,
    Expansion,
}
impl VisualKind {
    fn path(&self) -> &'static str {
        match self {
            Self::Avatar => "avatar",
            Self::Sprites => "sprites",
            Self::Expansion => "expansion",
        }
    }
}

#[derive(serde::Serialize, Deserialize)]
pub struct VisualAsset {
    pub sha256: String,
    pub mime: String,
}
impl VisualAsset {
    fn valid(&self) -> bool {
        visual_hash(&self.sha256) && matches!(self.mime.as_str(), "image/png" | "image/webp")
    }
}

#[derive(serde::Serialize, Deserialize)]
pub struct Visuals {
    pub revision: u64,
    pub avatar: Option<VisualAsset>,
    pub sprites: Option<VisualAsset>,
    pub manifest: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub studio_review: Option<serde_json::Value>,
}

#[derive(serde::Serialize, Deserialize)]
pub struct Persona {
    pub id: uuid::Uuid,
    pub name: String,
    pub profile: String,
    pub state: String,
    pub revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}
#[derive(serde::Serialize, Deserialize)]
pub struct Memory {
    pub id: uuid::Uuid,
    pub body: String,
    pub weight: f64,
    pub score: f64,
}
#[derive(serde::Serialize, Deserialize)]
pub struct RetrievedMemory {
    pub id: uuid::Uuid,
    pub created_at: String,
    pub retrieval_score: f64,
    pub retrieval_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_ref: Option<String>,
}
/// Keep omitted origin fields absent, so legacy writes retain their wire format.
fn memory_save_request(
    persona: uuid::Uuid,
    content: &str,
    weight: f64,
    origin_kind: Option<&str>,
    origin_ref: Option<&str>,
) -> serde_json::Value {
    let mut request = json!({"persona_id":persona,"content":content,"weight":weight});
    if let Some(kind) = origin_kind {
        request["origin_kind"] = json!(kind);
    }
    if let Some(reference) = origin_ref {
        request["origin_ref"] = json!(reference);
    }
    request
}

#[derive(serde::Serialize, Deserialize)]
pub struct Prepared {
    pub messages: Vec<serde_json::Value>,
    pub persona_id: Option<uuid::Uuid>,
    pub memory_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persona_revision: Option<u32>,
    // Old servers omit this; new servers return an array, including [].
    // Preserve the difference when crossing the JSON FFI boundary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrieved_memories: Option<Vec<RetrievedMemory>>,
}

#[derive(Deserialize)]
struct RestoredMemory {
    // serde normally treats missing Option<T> as None. That would mistake an
    // invalid {} response for an explicitly empty restore queue.
    #[serde(deserialize_with = "deserialize_required_memory_id")]
    memory_id: Option<uuid::Uuid>,
}

fn deserialize_required_memory_id<'de, D>(deserializer: D) -> Result<Option<uuid::Uuid>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<uuid::Uuid>::deserialize(deserializer)
}
#[derive(Deserialize)]
struct OnePersona {
    persona: Persona,
}
#[derive(serde::Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Actor {
    User,
    Model,
}
impl Session {
    fn api<T: DeserializeOwned>(
        &mut self,
        path: &str,
        body: Option<serde_json::Value>,
        status: u16,
    ) -> Result<T, Error> {
        self.ready()?;
        let url = format!("{}/v1/auth/{path}", self.client.issuer());
        let req = if let Some(data) = body {
            self.client.client.post(url).json(&data)
        } else {
            self.client.client.get(url)
        };
        let result = receive(req.bearer_auth(&*self.access), status);
        if matches!(result, Err(Error::LoginRequired)) {
            zeroize::Zeroize::zeroize(&mut *self.access);
        }
        result
    }
    pub fn personas(&mut self) -> Result<Vec<Persona>, Error> {
        #[derive(Deserialize)]
        struct List {
            personas: Vec<Persona>,
        }
        Ok(self.api::<List>("personas", None, 200)?.personas)
    }
    pub fn active_persona(&mut self) -> Result<Option<Persona>, Error> {
        #[derive(Deserialize)]
        struct Active {
            persona: Option<Persona>,
        }
        Ok(self.api::<Active>("personas/active", None, 200)?.persona)
    }
    pub fn persona(&mut self, id: uuid::Uuid) -> Result<Persona, Error> {
        Ok(self
            .api::<OnePersona>(&format!("personas/{id}"), None, 200)?
            .persona)
    }
    /// Read-only canonical account metadata; never consult legacy adapter identity.
    pub fn visuals(&mut self, id: uuid::Uuid) -> Result<Visuals, Error> {
        #[derive(Deserialize)]
        struct Envelope {
            visuals: Visuals,
        }
        let response = self
            .api::<Envelope>(&format!("personas/{id}/visuals"), None, 200)?
            .visuals;
        if response.avatar.as_ref().is_some_and(|a| !a.valid())
            || response.sprites.as_ref().is_some_and(|a| !a.valid())
            || response.sprites.is_some() != response.manifest.is_some()
            || response.manifest.as_ref().is_some_and(|m| !m.is_object())
            || response
                .studio_review
                .as_ref()
                .is_some_and(|m| !m.is_object())
            || (response.revision == 0
                && (response.avatar.is_some()
                    || response.sprites.is_some()
                    || response.studio_review.is_some()))
        {
            return Err(Error::Protocol);
        }
        Ok(response)
    }

    /// Optional V3.7 manifest; old servers return NotFound.
    pub fn expansion_manifest(&mut self, id: uuid::Uuid) -> Result<serde_json::Value, Error> {
        #[derive(Deserialize)]
        struct Envelope { expansion: serde_json::Value }
        let value = self.api::<Envelope>(&format!("personas/{id}/visuals/expansion-manifest"), None, 200)?.expansion;
        if !value.is_object() { return Err(Error::Protocol); }
        Ok(value)
    }

    /// Fetch only the bytes pinned by the caller's previously observed metadata.
    /// Redirects are disabled by the existing AccountClient. No bearer is exposed.
    pub fn visual_asset(
        &mut self,
        id: uuid::Uuid,
        kind: VisualKind,
        sha256: &str,
        mime: &str,
    ) -> Result<Vec<u8>, Error> {
        use sha2::{Digest, Sha256};
        if !visual_hash(sha256) || !matches!(mime, "image/png" | "image/webp") {
            return Err(Error::Protocol);
        }
        let max_bytes = if matches!(&kind, VisualKind::Expansion) { 8 * 1024 * 1024 } else { MAX_VISUAL_BYTES };
        if matches!(&kind, VisualKind::Expansion) && mime != "image/png" { return Err(Error::Protocol); }
        self.ready()?;
        let url = format!(
            "{}/v1/auth/personas/{id}/visuals/{}",
            self.client.issuer(),
            kind.path()
        );
        let response = self
            .client
            .client
            .get(url)
            .bearer_auth(&*self.access)
            .send()
            .map_err(|_| Error::Transport)?;
        match response.status().as_u16() {
            200 => (),
            401 => {
                zeroize::Zeroize::zeroize(&mut *self.access);
                return Err(Error::LoginRequired);
            }
            404 => return Err(Error::NotFound),
            status => return Err(Error::Rejected(status)),
        }
        let etag = format!("\"{sha256}\"");
        if response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some(mime)
            || response
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|v| v.to_str().ok())
                != Some(etag.as_str())
            || response
                .content_length()
                .is_some_and(|n| n > max_bytes as u64)
        {
            return Err(Error::Protocol);
        }
        let mut bytes = Vec::new();
        response
            .take((max_bytes + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Transport)?;
        if bytes.is_empty()
            || bytes.len() > max_bytes
            || format!("{:x}", Sha256::digest(&bytes)) != sha256
            || match mime {
                "image/png" => !bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
                "image/webp" => {
                    bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WEBP"
                }
                _ => true,
            }
        {
            return Err(Error::Protocol);
        }
        Ok(bytes)
    }

    fn change(
        &mut self,
        path: &str,
        data: serde_json::Value,
        status: u16,
    ) -> Result<Persona, Error> {
        Ok(self.api::<OnePersona>(path, Some(data), status)?.persona)
    }
    pub fn blank(&mut self, activate: bool) -> Result<Persona, Error> {
        self.change(
            "personas/create",
            json!({"mode":"blank","activate":activate}),
            201,
        )
    }
    pub fn generate(&mut self, model: &str, activate: bool) -> Result<Persona, Error> {
        self.change(
            "personas/create",
            json!({"mode":"generate","model":model,"activate":activate}),
            201,
        )
    }
    pub fn activate(&mut self, id: uuid::Uuid) -> Result<Persona, Error> {
        self.change("personas/activate", json!({"persona_id":id}), 200)
    }
    pub fn update(
        &mut self,
        id: uuid::Uuid,
        name: &str,
        profile: &str,
        revision: u64,
        actor: Actor,
    ) -> Result<Persona, Error> {
        self.change("personas/update",json!({"persona_id":id,"name":name,"profile":profile,"expected_revision":revision,"actor":actor}),200)
    }
    pub fn delete_persona(
        &mut self,
        id: uuid::Uuid,
        revision: u64,
        confirmation: &str,
    ) -> Result<bool, Error> {
        if confirmation != "DELETE" {
            return Err(Error::Protocol);
        }
        self.deleted(
            "personas/delete",
            json!({"persona_id":id,"expected_revision":revision,"confirm":confirmation}),
        )
    }
    fn deleted(&mut self, path: &str, data: serde_json::Value) -> Result<bool, Error> {
        #[derive(Deserialize)]
        struct Deleted {
            deleted: bool,
        }
        Ok(self.api::<Deleted>(path, Some(data), 200)?.deleted)
    }
    pub fn save_memory(
        &mut self,
        persona: uuid::Uuid,
        content: &str,
        weight: f64,
    ) -> Result<uuid::Uuid, Error> {
        self.save_memory_with_origin(persona, content, weight, None, None)
    }
    pub fn save_memory_with_origin(
        &mut self,
        persona: uuid::Uuid,
        content: &str,
        weight: f64,
        origin_kind: Option<&str>,
        origin_ref: Option<&str>,
    ) -> Result<uuid::Uuid, Error> {
        #[derive(Deserialize)]
        struct Saved {
            saved: bool,
            memory_id: uuid::Uuid,
        }
        let saved: Saved = self.api(
            "memories/save",
            Some(memory_save_request(
                persona,
                content,
                weight,
                origin_kind,
                origin_ref,
            )),
            201,
        )?;
        if !saved.saved {
            return Err(Error::Protocol);
        }
        Ok(saved.memory_id)
    }
    pub fn search(
        &mut self,
        persona: uuid::Uuid,
        query: &str,
        limit: u8,
    ) -> Result<Vec<Memory>, Error> {
        #[derive(Deserialize)]
        struct Rows {
            memories: Vec<Memory>,
            count: usize,
        }
        let rows: Rows = self.api(
            "memories/search",
            Some(json!({"persona_id":persona,"query":query,"limit":limit})),
            200,
        )?;
        if rows.count != rows.memories.len() {
            return Err(Error::Protocol);
        }
        Ok(rows.memories)
    }
    pub fn delete_memory(
        &mut self,
        persona: uuid::Uuid,
        memory: uuid::Uuid,
    ) -> Result<bool, Error> {
        self.deleted(
            "memories/delete",
            json!({"persona_id":persona,"memory_id":memory}),
        )
    }
    pub fn restore_last_memory(
        &mut self,
        persona: uuid::Uuid,
    ) -> Result<Option<uuid::Uuid>, Error> {
        let result: RestoredMemory = self.api(
            "memories/restore-last",
            Some(json!({"persona_id":persona})),
            200,
        )?;
        Ok(result.memory_id)
    }

    pub fn store_evidence(
        &mut self,
        persona: uuid::Uuid,
        answer: uuid::Uuid,
        revision: u32,
        evidence: &serde_json::Value,
    ) -> Result<serde_json::Value, Error> {
        self.api("evidence/store", Some(json!({"persona_id": persona, "answer_id": answer, "revision": revision, "evidence": evidence})), 200)
    }
    pub fn load_evidence(
        &mut self,
        persona: uuid::Uuid,
        answer: uuid::Uuid,
        revision: u32,
    ) -> Result<serde_json::Value, Error> {
        self.api(
            "evidence/load",
            Some(json!({"persona_id": persona, "answer_id": answer, "revision": revision})),
            200,
        )
    }
    pub fn prepare(
        &mut self,
        persona: Option<uuid::Uuid>,
        messages: &[serde_json::Value],
        query: &str,
        limit: u8,
    ) -> Result<Prepared, Error> {
        self.prepare_with_retrieval_mode(persona, messages, query, limit, None)
    }
    pub fn prepare_with_retrieval_mode(
        &mut self,
        persona: Option<uuid::Uuid>,
        messages: &[serde_json::Value],
        query: &str,
        limit: u8,
        retrieval_mode: Option<&str>,
    ) -> Result<Prepared, Error> {
        let mut request = json!({
            "persona_id": persona, "messages": messages,
            "memory_query": query, "memory_limit": limit,
        });
        if let Some(mode) = retrieval_mode {
            request["retrieval_mode"] = json!(mode);
        }
        self.api("prepare", Some(request), 200)
    }
    pub fn revoke(&mut self) -> Result<(), Error> {
        #[derive(Deserialize)]
        struct Revoked {
            revoked: bool,
        }
        let revoked: Revoked = self.api(
            "revoke",
            Some(json!({"device_id":self.identity.device_id})),
            200,
        )?;
        if !revoked.revoked {
            return Err(Error::Protocol);
        }
        zeroize::Zeroize::zeroize(&mut *self.access);
        Ok(())
    }
}

impl Session {
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn me(&mut self) -> Result<Identity, Error> {
        let found: Identity = self.api("me", None, 200)?;
        if found.account_id != self.identity.account_id
            || found.device_id != self.identity.device_id
        {
            zeroize::Zeroize::zeroize(&mut *self.access);
            return Err(Error::LoginRequired);
        }
        Ok(found)
    }
}
#[cfg(test)]
mod account_tests {
    use super::*;
    #[test]
    fn save_memory_request_forwards_optional_provenance() {
        let persona = uuid::Uuid::new_v4();
        let legacy = memory_save_request(persona, "memory", 0.5, None, None);
        assert_eq!(
            legacy,
            json!({"persona_id":persona,"content":"memory","weight":0.5})
        );
        assert!(legacy.get("origin_kind").is_none());
        assert!(legacy.get("origin_ref").is_none());
        let supplied = memory_save_request(
            persona,
            "memory",
            0.5,
            Some("assistant_saved"),
            Some("turn:123"),
        );
        assert_eq!(
            supplied,
            json!({
                "persona_id":persona,"content":"memory","weight":0.5,
                "origin_kind":"assistant_saved","origin_ref":"turn:123"
            })
        );
        let partial = memory_save_request(persona, "memory", 0.5, Some("user_saved"), None);
        assert_eq!(partial.get("origin_kind"), Some(&json!("user_saved")));
        assert!(partial.get("origin_ref").is_none());
    }
    #[test]
    fn only_canonical_https_origins() {
        for value in [
            "http://example.com",
            "https://name@example.com",
            "https://example.com/x",
            "https://example.com?foo",
            "https://example.com/#x",
            "https://example.com//",
            "https://example.com:443",
        ] {
            assert_eq!(origin(value), Err(Error::Origin));
        }
        assert_eq!(
            origin("https://example.com:444/").unwrap(),
            "https://example.com:444"
        );
    }
    #[test]
    fn restore_memory_response_requires_explicit_id_or_null() {
        let id = uuid::Uuid::new_v4();
        let found: RestoredMemory = serde_json::from_value(json!({"memory_id": id})).unwrap();
        assert_eq!(found.memory_id, Some(id));
        let empty: RestoredMemory = serde_json::from_value(json!({"memory_id": null})).unwrap();
        assert!(empty.memory_id.is_none());
        for invalid in [
            json!({}),
            json!({"memory_id": "not-a-uuid"}),
            json!({"memory_id": 7}),
            json!({"memory_id": false}),
        ] {
            assert!(serde_json::from_value::<RestoredMemory>(invalid).is_err());
        }
    }

    #[test]
    fn prepared_provenance_survives_typed_roundtrip_and_legacy_omission() {
        let persona = uuid::Uuid::new_v4();
        let memory = uuid::Uuid::new_v4();
        let input = json!({
            "messages": [{"role":"system","content":"untrusted references"}],
            "persona_id":persona,
            "memory_count":1,
            "retrieved_memories":[{
                "id":memory,
                "created_at":"2026-11-22T00:00:00Z",
                "retrieval_score":0.25,
                "retrieval_method":"postgresql_ts_rank_cd",
                "origin_kind":"assistant_saved",
                "origin_ref":"turn:123"
            }]
        });
        let parsed: Prepared = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), input);
        let no_origin = json!({
            "messages":[], "persona_id":persona, "memory_count":1,
            "retrieved_memories":[{
                "id":memory, "created_at":"2026-11-22T00:00:00Z",
                "retrieval_score":0.1, "retrieval_method":"postgresql_ts_rank_cd"
            }]
        });
        let parsed: Prepared = serde_json::from_value(no_origin.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), no_origin);
        let empty = json!({
            "messages":[], "persona_id":null,
            "memory_count":0, "retrieved_memories":[]
        });
        let parsed: Prepared = serde_json::from_value(empty.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), empty);
        let old = json!({"messages":[], "persona_id":null, "memory_count":0});
        let parsed: Prepared = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), old);
    }

    #[test]
    fn established_empty_persona_with_optional_status() {
        let value =
            json!({"id":uuid::Uuid::new_v4(),"profile":"","name":"","revision":1,"state":"blank"});
        let p: Persona = serde_json::from_value(value).unwrap();
        assert!(p.name.is_empty() && p.profile.is_empty() && p.active.is_none());
    }
}
