//! Offline import and integrity primitives for draft ToastRAM connection files.
//!
//! Import never contacts a server, validates server identity, or enrolls a
//! client. A digest can detect changes relative to a trusted issuance record;
//! it cannot authenticate the issuer by itself.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

pub const MAX_TOASTLINK_BYTES: usize = 65_536;
pub const CONNECTION_FORMAT: &str = "toastram.connection";
pub const CONNECTION_VERSION: u16 = 1;

#[derive(Debug)]
pub enum ImportError {
    TooLarge,
    InvalidFile,
    InvalidJson,
    UnsupportedFormat,
    InvalidField(&'static str),
    Expired,
    Io(std::io::Error),
}

impl fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(formatter, "connection file exceeds 64 KiB"),
            Self::InvalidFile => write!(formatter, "connection file is not a regular file"),
            Self::InvalidJson => write!(formatter, "connection file is not valid JSON"),
            Self::UnsupportedFormat => write!(formatter, "unsupported connection format/version"),
            Self::InvalidField(field) => write!(formatter, "invalid connection field: {field}"),
            Self::Expired => write!(formatter, "enrollment credential is expired"),
            Self::Io(err) => write!(formatter, "file access failed: {err}"),
        }
    }
}
impl std::error::Error for ImportError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFile {
    format: String,
    version: u16,
    server: Server,
    tls: Tls,
    enrollment: Enrollment,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Server {
    id: String,
    name: String,
    url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tls {
    ca_certificate_pem: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    id: String,
    token: String,
    expires_at: String,
}

impl Drop for Enrollment {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// An unverified enrollment file and its raw-byte SHA-256 fingerprint.
/// This type does not indicate trust, authentication, or a live connection.
pub struct ConnectionFile {
    wire: WireFile,
    digest: [u8; 32],
}

impl fmt::Debug for ConnectionFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionFile")
            .field("status", &"unverified")
            .field("format", &self.wire.format)
            .field("version", &self.wire.version)
            .finish_non_exhaustive()
    }
}

impl ConnectionFile {
    /// Parse only. This does not authenticate the issuing server.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ImportError> {
        if bytes.is_empty() {
            return Err(ImportError::InvalidJson);
        }
        if bytes.len() > MAX_TOASTLINK_BYTES {
            return Err(ImportError::TooLarge);
        }
        let wire: WireFile = serde_json::from_slice(bytes).map_err(|_| ImportError::InvalidJson)?;
        validate(&wire)?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        Ok(Self { wire, digest })
    }

    /// Bounded file read, rejecting a symlink as the immediate path.
    /// Like any ordinary filesystem read, this alone does not provide
    /// race-free path identity or guarantee file authenticity.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ImportError> {
        let path = path.as_ref();
        let stat = std::fs::symlink_metadata(path).map_err(ImportError::Io)?;
        if !stat.file_type().is_file() || stat.len() > MAX_TOASTLINK_BYTES as u64 {
            return Err(if stat.len() > MAX_TOASTLINK_BYTES as u64 {
                ImportError::TooLarge
            } else {
                ImportError::InvalidFile
            });
        }
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(ImportError::Io)?
            .take(MAX_TOASTLINK_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(ImportError::Io)?;
        Self::from_bytes(&bytes)
    }

    /// Hex SHA-256 of the exact source bytes, including whitespace.
    /// The issuer must compare this against an independently stored record.
    pub fn sha256_hex(&self) -> String {
        self.digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Intentionally excludes the enrollment token and CA private key.
    /// Status is always unverified, even for a syntactically valid file.
    pub fn public_metadata_json(&self) -> String {
        serde_json::json!({
            "format": CONNECTION_FORMAT,
            "version": CONNECTION_VERSION,
            "status": "unverified",
            "server": {
                "id": self.wire.server.id,
                "name": self.wire.server.name,
                "url": self.wire.server.url
            },
            "enrollment_id": self.wire.enrollment.id,
            "expires_at": self.wire.enrollment.expires_at,
            "file_sha256": self.sha256_hex()
        })
        .to_string()
    }

    pub fn server_url(&self) -> &str {
        &self.wire.server.url
    }
}

fn validate(wire: &WireFile) -> Result<(), ImportError> {
    if wire.format != CONNECTION_FORMAT || wire.version != CONNECTION_VERSION {
        return Err(ImportError::UnsupportedFormat);
    }
    let name = &wire.server.name;
    if name.is_empty()
        || name.len() > 128
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err(ImportError::InvalidField("server.name"));
    }
    if wire.server.id.len() != 32
        || !wire
            .server
            .id
            .bytes()
            .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
    {
        return Err(ImportError::InvalidField("server.id"));
    }
    let url = Url::parse(&wire.server.url).map_err(|_| ImportError::InvalidField("server.url"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(ImportError::InvalidField("server.url"));
    }
    if wire.tls.ca_certificate_pem.len() > 16_384
        || wire.tls.ca_certificate_pem.contains("PRIVATE KEY")
        || !wire
            .tls
            .ca_certificate_pem
            .starts_with("-----BEGIN CERTIFICATE-----")
        || !wire
            .tls
            .ca_certificate_pem
            .trim_end()
            .ends_with("-----END CERTIFICATE-----")
    {
        return Err(ImportError::InvalidField("tls.ca_certificate_pem"));
    }
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::Cursor::new(
        wire.tls.ca_certificate_pem.as_bytes(),
    ))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| ImportError::InvalidField("tls.ca_certificate_pem"))?;
    if certs.len() != 1 {
        return Err(ImportError::InvalidField("tls.ca_certificate_pem"));
    }
    let id = &wire.enrollment.id;
    let parsed = Uuid::parse_str(id).map_err(|_| ImportError::InvalidField("enrollment.id"))?;
    if parsed.get_version_num() != 4 || parsed.to_string() != *id {
        return Err(ImportError::InvalidField("enrollment.id"));
    }
    let token = &wire.enrollment.token;
    if !(32..=256).contains(&token.len())
        || !token
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-')
    {
        return Err(ImportError::InvalidField("enrollment.token"));
    }
    let deadline = DateTime::parse_from_rfc3339(&wire.enrollment.expires_at)
        .map_err(|_| ImportError::InvalidField("enrollment.expires_at"))?;
    if deadline <= Utc::now() {
        return Err(ImportError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::{json, Value};
    use uuid::Uuid;

    fn fixture() -> Value {
        json!({
            "format": CONNECTION_FORMAT,
            "version": 1,
            "server": {
                "id": "8f694b5238e9a11b86c4cb003b1b346a",
                "name": "Local ToastRAM",
                "url": "https://memory.example.lan:18443"
            },
            "tls": {
                "ca_certificate_pem": include_str!("../../../tests/fixtures/ca.pem")
            },
            "enrollment": {
                "id": Uuid::new_v4().to_string(),
                "token": "this_is_only_a_disposable_test_enrollment_token",
                "expires_at": (Utc::now() + Duration::days(2)).to_rfc3339()
            }
        })
    }

    #[test]
    fn import_provides_raw_digest_and_no_secrets_in_metadata_or_debug() {
        let case = fixture();
        let input = serde_json::to_vec_pretty(&case).unwrap();
        let connection = ConnectionFile::from_bytes(&input).unwrap();
        assert_eq!(connection.sha256_hex().len(), 64);
        assert_eq!(
            connection.sha256_hex(),
            format!("{:x}", Sha256::digest(&input))
        );
        let metadata = connection.public_metadata_json();
        assert!(metadata.contains("\"status\":\"unverified\""));
        assert!(!metadata.contains("disposable_test_enrollment"));
        assert!(!metadata.contains("BEGIN CERTIFICATE"));
        assert!(!format!("{connection:?}").contains("disposable_test_enrollment"));
        let compact = serde_json::to_vec(&case).unwrap();
        assert_ne!(
            ConnectionFile::from_bytes(&compact).unwrap().sha256_hex(),
            connection.sha256_hex()
        );
    }

    #[test]
    fn refuses_http_userinfo_and_unexpected_urls() {
        for url in [
            "http://memory.example.lan:18443",
            "https://user:pass@memory.example.lan",
            "https://memory.example.lan/api",
            "https://memory.example.lan/?token=secret",
            "https://memory.example.lan/#fragment",
        ] {
            let mut value = fixture();
            value["server"]["url"] = json!(url);
            assert!(matches!(
                ConnectionFile::from_bytes(&serde_json::to_vec(&value).unwrap()),
                Err(ImportError::InvalidField("server.url"))
            ));
        }
    }

    #[test]
    fn rejects_expired_and_weak_secrets() {
        let mut value = fixture();
        value["enrollment"]["expires_at"] = json!("2020-01-01T00:00:00Z");
        assert!(matches!(
            ConnectionFile::from_bytes(&serde_json::to_vec(&value).unwrap()),
            Err(ImportError::Expired)
        ));
        let mut value = fixture();
        value["enrollment"]["token"] = json!("short");
        assert!(matches!(
            ConnectionFile::from_bytes(&serde_json::to_vec(&value).unwrap()),
            Err(ImportError::InvalidField("enrollment.token"))
        ));
    }

    #[test]
    fn rejects_unknown_fields_and_oversized_files() {
        let mut value = fixture();
        value["unexpected"] = json!("payload");
        assert!(matches!(
            ConnectionFile::from_bytes(&serde_json::to_vec(&value).unwrap()),
            Err(ImportError::InvalidJson)
        ));
        assert!(matches!(
            ConnectionFile::from_bytes(&vec![b'a'; MAX_TOASTLINK_BYTES + 1]),
            Err(ImportError::TooLarge)
        ));
    }

    #[test]
    fn rejects_private_key_substitution_and_invalid_ca() {
        let mut value = fixture();
        value["tls"]["ca_certificate_pem"] =
            json!("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----");
        assert!(matches!(
            ConnectionFile::from_bytes(&serde_json::to_vec(&value).unwrap()),
            Err(ImportError::InvalidField("tls.ca_certificate_pem"))
        ));
    }

    #[test]
    fn path_import_rejects_regular_file_oversize() {
        let temp = std::env::temp_dir().join(format!("toastlink-{}.toastlink", Uuid::new_v4()));
        std::fs::write(&temp, vec![b'a'; MAX_TOASTLINK_BYTES + 2]).unwrap();
        assert!(matches!(
            ConnectionFile::from_path(&temp),
            Err(ImportError::TooLarge)
        ));
        std::fs::remove_file(&temp).unwrap();
    }
}
