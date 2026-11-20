use super::*;
use reqwest::blocking::{Client, Response};
use serde_json::json;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    server_id: String,
    origin: String,
    ca_der_sha256: String,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    TrustMismatch,
    Expired,
    Transport,
    Denied,
    RateLimited(Option<u64>),
    Unavailable,
    Protocol,
    RedemptionUncertain,
}

pub struct Pairing<'a> {
    file: &'a ConnectionFile,
    client: Client,
}
pub struct Eligible<'a>(Pairing<'a>);

#[derive(Deserialize)]
struct Preflight {
    status: String,
    enrollment_id: String,
}

#[derive(Deserialize)]
struct Grant {
    token_type: String,
    access_token: String,
    client_id: String,
    server_id: String,
    scopes: Vec<String>,
    expires_at: String,
}
impl Drop for Grant {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}
fn decode<T: serde::de::DeserializeOwned>(response: Response) -> Result<T, Error> {
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Transport)?;
    if bytes.len() > 16384 {
        return Err(Error::Protocol);
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::Protocol)
}
impl<'a> Pairing<'a> {
    pub fn new(file: &'a ConnectionFile, trust: &Trust) -> Result<Self, Error> {
        let pem = file.wire.tls.ca_certificate_pem.as_bytes();
        let der = rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
            .next()
            .and_then(Result::ok)
            .ok_or(Error::Protocol)?;
        if trust.origin != file.server_url()
            || trust.server_id != file.wire.server.id
            || trust.ca_der_sha256 != format!("{:x}", Sha256::digest(der.as_ref()))
        {
            return Err(Error::TrustMismatch);
        }
        let cert = reqwest::Certificate::from_der(der.as_ref()).map_err(|_| Error::Protocol)?;
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| Error::Transport)?;
        Ok(Self { file, client })
    }
    fn post(&self, operation: &str, expected: u16) -> Result<Response, Error> {
        let e = &self.file.wire.enrollment;
        if DateTime::parse_from_rfc3339(&e.expires_at).map_err(|_| Error::Protocol)? <= Utc::now() {
            return Err(Error::Expired);
        }
        let response = self.client.post(format!("{}/api/connect/v1/{}", self.file.server_url(), operation))
            .bearer_auth(&e.token).header("Accept","application/json")
            .json(&json!({"server_id":self.file.wire.server.id,"enrollment_id":e.id,"file_sha256":self.file.sha256_hex()}))
            .send().map_err(|_| Error::Transport)?;
        match response.status().as_u16() {
            n if n == expected => Ok(response),
            401 => Err(Error::Denied),
            429 => Err(Error::RateLimited(
                response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok()?.parse().ok()),
            )),
            503 => Err(Error::Unavailable),
            _ => Err(Error::Protocol),
        }
    }
    pub fn preflight(self) -> Result<Eligible<'a>, Error> {
        let reply = match self.post("preflight", 200) {
            Err(Error::Transport | Error::Unavailable) => self.post("preflight", 200),
            result => result,
        }?;
        let body: Preflight = decode(reply)?;
        if body.status != "eligible" || body.enrollment_id != self.file.wire.enrollment.id {
            return Err(Error::Protocol);
        }
        Ok(Eligible(self))
    }
}

#[cfg(windows)]
impl Eligible<'_> {
    /// Consumes preflight eligibility. Returns the protected credential locator after durable storage.
    pub fn redeem_windows(self) -> Result<String, Error> {
        let pairing = self.0;
        let response = pairing.post("redeem", 201).map_err(|err| match err {
            Error::Transport | Error::Protocol => Error::RedemptionUncertain,
            other => other,
        })?;
        let grant: Grant = decode(response).map_err(|_| Error::RedemptionUncertain)?;
        let valid_id = Uuid::parse_str(&grant.client_id).is_ok_and(|id| {
            id.get_version_num() == 4
                && id.get_variant() == uuid::Variant::RFC4122
                && id.to_string() == grant.client_id
        });
        let scopes: std::collections::HashSet<_> = grant.scopes.iter().collect();
        if grant.token_type != "Bearer"
            || grant.server_id != pairing.file.wire.server.id
            || !valid_id
            || !DateTime::parse_from_rfc3339(&grant.expires_at)
                .is_ok_and(|date| date > Utc::now() && date.offset().local_minus_utc() == 0)
            || scopes.is_empty()
            || scopes.len() != grant.scopes.len()
            || scopes
                .iter()
                .any(|s| !matches!(s.as_str(), "read" | "chat" | "write"))
            || !(43..=256).contains(&grant.access_token.len())
            || !grant
                .access_token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(Error::RedemptionUncertain);
        }
        let locator = format!(
            "{}|{}|{}|{:x}",
            pairing.file.server_url(),
            grant.server_id,
            grant.client_id,
            Sha256::digest(
                rustls_pemfile::certs(&mut std::io::Cursor::new(
                    pairing.file.wire.tls.ca_certificate_pem.as_bytes()
                ))
                .next()
                .and_then(Result::ok)
                .ok_or(Error::RedemptionUncertain)?
                .as_ref()
            )
        );
        keyring::Entry::new("ToastRAM Connect v1", &locator)
            .and_then(|entry| entry.set_password(&grant.access_token))
            .map_err(|_| Error::RedemptionUncertain)?;
        Ok(locator)
    }
}
