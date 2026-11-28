//! Bounded, device-scoped notice delivery. No conversation or memory integration.
use super::{receive_bounded, ConversationResponseBinding, Error, Session};
use chrono::{DateTime, FixedOffset};
use reqwest::blocking::RequestBuilder;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_BATCH: usize = 32;
const MAX_BODY: usize = 8192;
const MAX_RESPONSE: usize = 2 * 1024 * 1024;
const MAX_OFFER_AGE: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Notice {
    id: Uuid,
    body: String,
    starts_at: String,
    expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    server_time: String,
    announcements: Vec<Notice>,
}

pub(super) struct Candidate {
    notice: Notice,
    deadline: Instant,
}

fn timestamp(value: &str) -> Result<DateTime<FixedOffset>, Error> {
    DateTime::parse_from_rfc3339(value).map_err(|_| Error::Protocol)
}

fn candidates(batch: Batch, sent: Instant, received: Instant) -> Result<BTreeMap<Uuid, Candidate>, Error> {
    if batch.announcements.len() > MAX_BATCH {
        return Err(Error::Protocol);
    }
    let server = timestamp(&batch.server_time)?;
    let elapsed = received.saturating_duration_since(sent);
    let mut seen = HashSet::new();
    let mut out = BTreeMap::new();
    for notice in batch.announcements {
        if notice.id.is_nil()
            || !seen.insert(notice.id)
            || notice.body.trim().is_empty()
            || notice.body.len() > MAX_BODY
            || notice.body.contains('\0')
        {
            return Err(Error::Protocol);
        }
        let start = timestamp(&notice.starts_at)?;
        let expiry = timestamp(&notice.expires_at)?;
        if start >= expiry || start > server || expiry <= server {
            return Err(Error::Protocol);
        }
        // Subtract the whole request duration rather than trusting local wall
        // time or assuming negligible network delay.
        let remaining = (expiry - server).to_std().map_err(|_| Error::Protocol)?;
        let ttl = remaining.saturating_sub(elapsed).min(MAX_OFFER_AGE);
        if !ttl.is_zero() {
            out.insert(notice.id, Candidate { notice, deadline: received + ttl });
        }
    }
    Ok(out)
}

fn root() -> Result<PathBuf, Error> {
    #[cfg(windows)]
    let dir = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let dir = std::env::var_os("HOME")
        .map(|p| PathBuf::from(p).join("Library/Application Support"));
    #[cfg(target_os = "linux")]
    let dir = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| {
        std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/share"))
    });
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    let dir: Option<PathBuf> = None;
    Ok(dir.ok_or(Error::Storage)?.join("ToastRAMConnect").join("announcement-receipts-v1"))
}

fn scoped_dir(root: &Path, binding: &str, account: Uuid, device: Uuid) -> PathBuf {
    let key = format!("{binding}|{account}|{device}");
    root.join(format!("{:x}", Sha256::digest(key.as_bytes())))
}

fn private_dir(path: &Path) -> Result<(), Error> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|_| Error::Storage)?;
    let meta = fs::symlink_metadata(path).map_err(|_| Error::Storage)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(Error::Storage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Storage);
        }
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        File::open(path).and_then(|f| f.sync_all()).map_err(|_| Error::Storage)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn receipt_exists(dir: &Path, id: Uuid) -> Result<bool, Error> {
    match fs::symlink_metadata(dir.join(id.to_string())) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() && meta.len() == 0 => Ok(true),
        Ok(_) => Err(Error::Storage),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(Error::Storage),
    }
}

// Atomic create_new is the cross-process claim boundary. Never truncate,
// overwrite, or silently recover a malformed receipt. Only UUIDs are stored.
fn claim(dir: &Path, id: Uuid) -> Result<bool, Error> {
    private_dir(dir)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(dir.join(id.to_string())) {
        Ok(file) => {
            file.sync_all().map_err(|_| Error::Storage)?;
            sync_dir(dir)?;
            if let Some(parent) = dir.parent() {
                sync_dir(parent)?;
            }
            Ok(true)
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            if receipt_exists(dir, id)? { Ok(false) } else { Err(Error::Storage) }
        }
        Err(_) => Err(Error::Storage),
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Poll(u64),
    Ack(Uuid),
}

pub struct AnnouncementRequest {
    request: RequestBuilder,
    access: Zeroizing<String>,
    kind: Kind,
    sent: Instant,
}

pub struct AnnouncementResponse {
    binding: ConversationResponseBinding,
    kind: Kind,
    sent: Instant,
    received: Instant,
    result: Result<Value, Error>,
}

impl AnnouncementRequest {
    pub fn wait(self) -> AnnouncementResponse {
        let result = receive_bounded(self.request, 200, MAX_RESPONSE);
        AnnouncementResponse {
            binding: ConversationResponseBinding { access: self.access },
            kind: self.kind,
            sent: self.sent,
            received: Instant::now(),
            result,
        }
    }
}

// An optional endpoint must never rotate or invalidate shared credentials.
// The normal account health/foreground path owns refresh and authentication.
fn optional_access(access: &str, expires: Instant) -> Result<(), Error> {
    if access.is_empty() || Instant::now() >= expires {
        return Err(Error::LoginRequired);
    }
    Ok(())
}

fn finish_optional(access: &str, binding: ConversationResponseBinding,
                   result: Result<Value, Error>) -> Result<Value, Error> {
    if access.is_empty() || access != binding.access.as_str() {
        return Err(Error::LoginRequired);
    }
    result
}

impl Session {
    fn receipt_dir(&self) -> Result<PathBuf, Error> {
        Ok(scoped_dir(&root()?, &self.client.binding,
                      self.identity.account_id, self.identity.device_id))
    }

    pub fn announcement_poll_request(&mut self) -> Result<AnnouncementRequest, Error> {
        optional_access(&self.access, self.expires)?;
        self.announcement_epoch = self.announcement_epoch.checked_add(1).ok_or(Error::Protocol)?;
        self.announcement_candidates.clear();
        self.announcement_request(Kind::Poll(self.announcement_epoch), "poll", json!({}))
    }

    pub fn announcement_ack_request(&mut self, id: Uuid) -> Result<AnnouncementRequest, Error> {
        optional_access(&self.access, self.expires)?;
        let dir = self.receipt_dir()?;
        if !receipt_exists(&dir, id)? {
            return Err(Error::Denied);
        }
        if !self.announcement_candidates.get(&id).is_some_and(|c| Instant::now() < c.deadline) {
            return Err(Error::Expired);
        }
        self.announcement_request(Kind::Ack(id), "ack", json!({"id": id}))
    }

    fn announcement_request(&self, kind: Kind, path: &str, body: Value) -> Result<AnnouncementRequest, Error> {
        if !self.identity.scope.split_whitespace().any(|s| s == "profile") {
            return Err(Error::Denied);
        }
        let request = self.client.client
            .post(format!("{}/v1/announcements/{path}", self.client.issuer()))
            .bearer_auth(&*self.access).json(&body);
        Ok(AnnouncementRequest {
            request, access: Zeroizing::new(self.access.to_string()), kind, sent: Instant::now(),
        })
    }

    pub fn finish_announcement(&mut self, response: AnnouncementResponse) -> Result<Value, Error> {
        if let Kind::Poll(epoch) = response.kind {
            if epoch != self.announcement_epoch {
                return Err(Error::Expired);
            }
        }
        let value = finish_optional(&self.access, response.binding, response.result)?;
        match response.kind {
            Kind::Poll(_) => {
                let batch: Batch = serde_json::from_value(value).map_err(|_| Error::Protocol)?;
                let offers = candidates(batch, response.sent, response.received)?;
                let dir = self.receipt_dir()?;
                private_dir(&dir)?;
                let mut available = Vec::new();
                let mut pending_ack = Vec::new();
                for (id, candidate) in &offers {
                    if Instant::now() >= candidate.deadline { continue; }
                    if receipt_exists(&dir, *id)? {
                        pending_ack.push(*id);
                    } else {
                        available.push(*id);
                    }
                }
                self.announcement_candidates = offers;
                Ok(json!({"available": available, "pending_ack": pending_ack}))
            }
            Kind::Ack(id) => {
                if value != json!({"acknowledged": true}) {
                    return Err(Error::Protocol);
                }
                self.announcement_candidates.remove(&id);
                Ok(value)
            }
        }
    }

    /// Claim before exposing the text to the host UI. Duplicate claim returns null.
    pub fn claim_announcement(&mut self, id: Uuid) -> Result<Value, Error> {
        optional_access(&self.access, self.expires)?;
        let candidate = self.announcement_candidates.get(&id).ok_or(Error::Expired)?;
        if Instant::now() >= candidate.deadline {
            return Err(Error::Expired);
        }
        if !claim(&self.receipt_dir()?, id)? {
            return Ok(Value::Null);
        }
        let ttl = candidate.deadline.saturating_duration_since(Instant::now());
        if ttl.is_zero() {
            return Err(Error::Expired);
        }
        Ok(json!({
            "id": id, "body": candidate.notice.body,
            "starts_at": candidate.notice.starts_at, "expires_at": candidate.notice.expires_at,
            "valid_for_ms": ttl.as_millis() as u64
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(expiry: &str) -> Batch {
        Batch {
            server_time: "2026-11-27T00:00:00+00:00".into(),
            announcements: vec![Notice {
                id: Uuid::new_v4(), body: "Maintenance".into(),
                starts_at: "2026-11-26T23:00:00+00:00".into(), expires_at: expiry.into(),
            }],
        }
    }

    #[test]
    fn optional_auth_never_invalidates_or_rotates_shared_access() {
        let access = Zeroizing::new("current".to_string());
        let bound = |token: &str| ConversationResponseBinding { access: Zeroizing::new(token.to_string()) };
        assert!(matches!(finish_optional(&access, bound("current"), Err(Error::LoginRequired)), Err(Error::LoginRequired)));
        assert_eq!(access.as_str(), "current");
        assert!(matches!(finish_optional(&access, bound("old"), Ok(json!({}))), Err(Error::LoginRequired)));
        assert!(optional_access(&access, Instant::now() - Duration::from_secs(1)).is_err());
        assert!(optional_access(&access, Instant::now() + Duration::from_secs(10)).is_ok());
    }

    #[test]
    fn subtract_latency_and_reject_invalid_windows() {
        let start = Instant::now();
        assert!(candidates(batch("2026-11-27T00:00:01+00:00"), start,
                           start + Duration::from_secs(2)).unwrap().is_empty());
        assert!(matches!(candidates(batch("2026-11-26T23:30:00+00:00"), start, start),
                         Err(Error::Protocol)));
        let result = candidates(batch("2026-11-27T04:00:00+00:00"), start, start).unwrap();
        assert_eq!(result.values().next().unwrap().deadline, start + MAX_OFFER_AGE);
    }

    #[test]
    fn durable_receipts_are_scoped_and_atomic() {
        let root = std::env::temp_dir().join(format!("toast-notices-{}", Uuid::new_v4()));
        let account = Uuid::new_v4();
        let a = scoped_dir(&root, "server|ca", account, Uuid::new_v4());
        let b = scoped_dir(&root, "server|ca", account, Uuid::new_v4());
        let id = Uuid::new_v4();
        assert!(!receipt_exists(&a,id).unwrap());
        assert!(claim(&a,id).unwrap());
        assert!(receipt_exists(&a,id).unwrap());
        assert!(!claim(&a,id).unwrap());
        assert!(claim(&b,id).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_claims_have_one_winner() {
        let dir = std::env::temp_dir().join(format!("toast-notices-{}", Uuid::new_v4()));
        let id = Uuid::new_v4();
        private_dir(&dir).unwrap();
        let other = dir.clone();
        let thread = std::thread::spawn(move || claim(&other,id).unwrap());
        let first = claim(&dir,id).unwrap();
        assert_ne!(first, thread.join().unwrap());
        fs::remove_dir_all(dir).unwrap();
    }
}
