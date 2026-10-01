use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair as RingKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::{Error, Result};
use crate::provider::{BackgroundGuard, CertProvider};
#[cfg(feature = "s3-sync")]
use crate::s3_sync::S3CertSync;

const DEFAULT_PROPAGATION_SECS: u64 = 60;
const DEFAULT_RENEW_WITHIN_DAYS: u64 = 30;
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_ORDER_POLL_DELAY: Duration = Duration::from_secs(30);
const MAX_RENEWAL_RETRY_DELAY: Duration = Duration::from_secs(86_400);
const STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const PRODUCTION_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

// ---------------------------------------------------------------------------
// Runtime-independent HTTP transport
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

#[async_trait]
trait HttpTransport: Send + Sync {
    async fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<(String, Vec<u8>)>,
    ) -> Result<HttpResponse>;
}

struct NagoTransport;

#[async_trait]
impl HttpTransport for NagoTransport {
    async fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<(String, Vec<u8>)>,
    ) -> Result<HttpResponse> {
        let client = nago_http::Client::global()
            .map_err(|error| Error::HttpClient(error.to_string()))?;
        let headers: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let response = match body.as_ref() {
            Some((content_type, bytes)) => {
                client
                    .send(
                        method,
                        url,
                        &headers,
                        Some((content_type.as_str(), bytes.as_slice())),
                    )
                    .await
            }
            None => client.send(method, url, &headers, None).await,
        }
        .map_err(|error| Error::HttpClient(error.to_string()))?;
        Ok(HttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }
}

fn http_status_error(service: &str, response: &HttpResponse) -> Error {
    let body = String::from_utf8_lossy(&response.body);
    Error::HttpClient(format!("{service} returned HTTP {}: {body}", response.status))
}

fn parse_json<T: for<'de> Deserialize<'de>>(response: &HttpResponse, service: &str) -> Result<T> {
    if !response.is_success() {
        return Err(http_status_error(service, response));
    }
    serde_json::from_slice(&response.body).map_err(|error| {
        Error::AcmeProtocol(format!("{service} returned invalid JSON: {error}"))
    })
}

// ---------------------------------------------------------------------------
// DNS provider API
// ---------------------------------------------------------------------------

/// Implement this to plug in any DNS provider.
///
/// Both methods receive the fully-qualified _acme-challenge.<domain> name and
/// the TXT record value (the ACME key authorization digest).
#[async_trait]
pub trait DnsProvider: Send + Sync + 'static {
    /// Remove TXT records left by previous interrupted challenges at this name.
    /// Providers that cannot list records may keep the default no-op. This is
    /// called once per unique challenge name before a new TXT record is added.
    async fn cleanup_txt_records(&self, _fqdn: &str) -> Result<()> {
        Ok(())
    }

    async fn add_txt_record(&self, fqdn: &str, value: &str) -> Result<()>;
    async fn remove_txt_record(&self, fqdn: &str, value: &str) -> Result<()>;
}

#[async_trait]
impl<T: DnsProvider> DnsProvider for Arc<T> {
    async fn cleanup_txt_records(&self, fqdn: &str) -> Result<()> {
        self.as_ref().cleanup_txt_records(fqdn).await
    }

    async fn add_txt_record(&self, fqdn: &str, value: &str) -> Result<()> {
        self.as_ref().add_txt_record(fqdn, value).await
    }

    async fn remove_txt_record(&self, fqdn: &str, value: &str) -> Result<()> {
        self.as_ref().remove_txt_record(fqdn, value).await
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct BunnyZone {
    id: u64,
    domain: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct BunnyZoneList {
    items: Vec<BunnyZone>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct BunnyRecord {
    id: u64,
    #[serde(rename = "Type")]
    record_type: u8,
    name: String,
    value: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct BunnyZoneDetail {
    #[serde(rename = "Records")]
    dns_records: Vec<BunnyRecord>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct BunnyAddRecord<'a> {
    #[serde(rename = "Type")]
    record_type: u8,
    name: &'a str,
    value: &'a str,
    ttl: u32,
}

/// DNS-01 provider backed by the bunny.net DNS API.
///
/// Obtain an API key from the bunny.net dashboard -> Account -> API.
pub struct BunnyDns {
    api_key: String,
    transport: Arc<dyn HttpTransport>,
}

impl BunnyDns {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            transport: Arc::new(NagoTransport),
        }
    }

    fn base(&self) -> &'static str {
        "https://api.bunny.net"
    }

    async fn find_zone(&self, fqdn: &str) -> Result<(u64, String)> {
        let name = fqdn.trim_end_matches('.');
        let parts: Vec<&str> = name.split('.').collect();
        for index in 0..parts.len().saturating_sub(1) {
            let candidate = parts[index..].join(".");
            let url = format!(
                "{}/dnszone?search={}&page=1&perPage=10",
                self.base(),
                candidate
            );
            let response = self
                .transport
                .request(
                    "GET",
                    &url,
                    &[
                        ("AccessKey".to_owned(), self.api_key.clone()),
                        ("accept".to_owned(), "application/json".to_owned()),
                    ],
                    None,
                )
                .await?;
            if !response.is_success() {
                continue;
            }
            let zones: BunnyZoneList = serde_json::from_slice(&response.body).map_err(|error| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    error.to_string(),
                ))
            })?;
            for zone in zones.items {
                let lower_name = name.to_ascii_lowercase();
                let lower_domain = zone.domain.trim_end_matches('.').to_ascii_lowercase();
                if lower_name == lower_domain
                    || lower_name
                        .strip_suffix(&lower_domain)
                        .is_some_and(|prefix| prefix.ends_with('.'))
                {
                    return Ok((zone.id, zone.domain));
                }
            }
        }
        Err(Error::Config(format!(
            "bunny.net: no DNS zone found for {fqdn}"
        )))
    }

    fn relative_name<'a>(&self, fqdn: &'a str, zone_domain: &str) -> &'a str {
        let name = fqdn.trim_end_matches('.');
        let zone = zone_domain.trim_end_matches('.');
        name.strip_suffix(&format!(".{zone}"))
            .or_else(|| name.strip_suffix(zone))
            .unwrap_or(name)
    }

    async fn records(&self, zone_id: u64) -> Result<Vec<BunnyRecord>> {
        let url = format!("{}/dnszone/{zone_id}", self.base());
        let response = self
            .transport
            .request(
                "GET",
                &url,
                &[
                    ("AccessKey".to_owned(), self.api_key.clone()),
                    ("accept".to_owned(), "application/json".to_owned()),
                ],
                None,
            )
            .await?;
        if !response.is_success() {
            return Err(http_status_error("bunny.net zone fetch", &response));
        }
        let detail: BunnyZoneDetail = serde_json::from_slice(&response.body).map_err(|error| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            ))
        })?;
        Ok(detail.dns_records)
    }

    async fn delete_record(&self, zone_id: u64, record_id: u64) -> Result<()> {
        let url = format!("{}/dnszone/{zone_id}/records/{record_id}", self.base());
        let response = self
            .transport
            .request(
                "DELETE",
                &url,
                &[("AccessKey".to_owned(), self.api_key.clone())],
                None,
            )
            .await?;
        if !response.is_success() {
            return Err(http_status_error("bunny.net record delete", &response));
        }
        Ok(())
    }
}

#[async_trait]
impl DnsProvider for BunnyDns {
    async fn cleanup_txt_records(&self, fqdn: &str) -> Result<()> {
        let (zone_id, zone_domain) = self.find_zone(fqdn).await?;
        let record_name = self.relative_name(fqdn, &zone_domain);
        let records = self.records(zone_id).await?;

        let conflicts: Vec<String> = records
            .iter()
            .filter(|record| record.name == record_name && record.record_type != 3)
            .map(|record| format!("id={} type={}", record.id, record.record_type))
            .collect();
        if !conflicts.is_empty() {
            return Err(Error::Config(format!(
                "bunny.net: non-TXT record conflicts with {fqdn}: {}",
                conflicts.join(", ")
            )));
        }

        for record in records
            .iter()
            .filter(|record| record.name == record_name && record.record_type == 3)
        {
            self.delete_record(zone_id, record.id).await?;
            tracing::debug!(record_id = record.id, "bunny.net: removed stale TXT {fqdn}");
        }
        Ok(())
    }

    async fn add_txt_record(&self, fqdn: &str, value: &str) -> Result<()> {
        let (zone_id, zone_domain) = self.find_zone(fqdn).await?;
        let record_name = self.relative_name(fqdn, &zone_domain);
        let payload = BunnyAddRecord {
            record_type: 3,
            name: record_name,
            value,
            ttl: 120,
        };
        let body = serde_json::to_vec(&payload)
            .map_err(|error| Error::Config(format!("serialize Bunny record: {error}")))?;
        let url = format!("{}/dnszone/{zone_id}/records", self.base());
        let response = self
            .transport
            .request(
                "PUT",
                &url,
                &[
                    ("AccessKey".to_owned(), self.api_key.clone()),
                    ("accept".to_owned(), "application/json".to_owned()),
                ],
                Some(("application/json".to_owned(), body)),
            )
            .await?;
        if !response.is_success() {
            return Err(http_status_error("bunny.net TXT add", &response));
        }
        tracing::debug!("bunny.net: added TXT {fqdn} = {value}");
        Ok(())
    }

    async fn remove_txt_record(&self, fqdn: &str, value: &str) -> Result<()> {
        let (zone_id, zone_domain) = self.find_zone(fqdn).await?;
        let record_name = self.relative_name(fqdn, &zone_domain);
        let records = self.records(zone_id).await?;
        let matching: Vec<&BunnyRecord> = records
            .iter()
            .filter(|record| {
                record.record_type == 3 && record.name == record_name && record.value == value
            })
            .collect();
        if matching.is_empty() {
            warn!("bunny.net: TXT record {fqdn}={value} not found for cleanup");
            return Ok(());
        }
        for record in matching {
            self.delete_record(zone_id, record.id).await?;
            tracing::debug!("bunny.net: removed TXT {fqdn} (id={})", record.id);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ACME account key, JWS and account cache
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AccountKey {
    pkcs8: Vec<u8>,
    x: String,
    y: String,
}

impl AccountKey {
    fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| Error::Account("could not generate the ES256 account key".into()))?;
        Self::from_pkcs8(pkcs8.as_ref().to_vec())
    }

    fn from_pkcs8(pkcs8: Vec<u8>) -> Result<Self> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &pkcs8,
            &rng,
        )
        .map_err(|_| Error::Account("cached account key is not a P-256 key".into()))?;
        let public = pair.public_key().as_ref();
        if public.len() != 65 || public[0] != 4 {
            return Err(Error::Account("account key has an unexpected public point".into()));
        }
        Ok(Self {
            pkcs8,
            x: base64url_encode(&public[1..33]),
            y: base64url_encode(&public[33..65]),
        })
    }

    fn jwk(&self) -> Value {
        json!({"kty":"EC", "crv":"P-256", "x":self.x, "y":self.y})
    }

    fn thumbprint(&self) -> String {
        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            self.x, self.y
        );
        sha256_base64url(canonical.as_bytes())
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &self.pkcs8,
            &rng,
        )
        .map_err(|_| Error::Account("could not load the ES256 account key".into()))?;
        pair.sign(&rng, message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| Error::Account("could not sign the ACME request".into()))
    }

    fn jws(
        &self,
        nonce: &str,
        url: &str,
        payload: &[u8],
        kid: Option<&str>,
    ) -> Result<(Vec<u8>, String)> {
        let protected = match kid {
            Some(kid) => json!({"alg":"ES256", "nonce":nonce, "url":url, "kid":kid}),
            None => json!({"alg":"ES256", "nonce":nonce, "url":url, "jwk":self.jwk()}),
        };
        let protected = serde_json::to_vec(&protected)
            .map_err(|error| Error::AcmeProtocol(format!("serialize JWS header: {error}")))?;
        let protected = base64url_encode(&protected);
        let payload = base64url_encode(payload);
        let signing_input = format!("{protected}.{payload}");
        let signature = base64url_encode(&self.sign(signing_input.as_bytes())?);
        let flattened = json!({
            "protected":protected,
            "payload":payload,
            "signature":signature
        });
        let body = serde_json::to_vec(&flattened)
            .map_err(|error| Error::AcmeProtocol(format!("serialize JWS: {error}")))?;
        Ok((body, signing_input))
    }
}

fn sha256_base64url(bytes: &[u8]) -> String {
    base64url_encode(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

fn key_authorization(token: &str, account_thumbprint: &str) -> String {
    format!("{token}.{account_thumbprint}")
}

fn dns_txt_value(key_authorization: &str) -> String {
    sha256_base64url(key_authorization.as_bytes())
}

fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let (chunks, remainder) = bytes.as_chunks::<3>();
    for chunk in chunks {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk[1]) << 8)
            | u32::from(chunk[2]);
        output.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
        output.push(ALPHABET[((value >> 6) & 0x3f) as usize] as char);
        output.push(ALPHABET[(value & 0x3f) as usize] as char);
    }
    match remainder {
        [a] => {
            output.push(ALPHABET[(a >> 2) as usize] as char);
            output.push(ALPHABET[((a & 0x03) << 4) as usize] as char);
        }
        [a, b] => {
            output.push(ALPHABET[(a >> 2) as usize] as char);
            output.push(ALPHABET[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
            output.push(ALPHABET[((b & 0x0f) << 2) as usize] as char);
        }
        _ => {}
    }
    output
}

#[cfg(test)]
fn base64url_decode(encoded: &str) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(encoded.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in encoded.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(Error::AcmeProtocol("invalid base64url value".into())),
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
        }
    }
    if bits >= 6 || (bits > 0 && (buffer & ((1 << bits) - 1)) != 0) {
        return Err(Error::AcmeProtocol("invalid base64url padding bits".into()));
    }
    Ok(output)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode(encoded: &str) -> Option<Vec<u8>> {
    if !encoded.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().as_chunks::<2>().0 {
        let high = (pair[0] as char).to_digit(16)? as u8;
        let low = (pair[1] as char).to_digit(16)? as u8;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcmeDirectory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

#[derive(Serialize, Deserialize)]
struct CachedCredentials {
    directory_url: String,
    kid: String,
    account_key_pkcs8_hex: String,
}

struct AcmeClient {
    transport: Arc<dyn HttpTransport>,
    directory: AcmeDirectory,
    key: AccountKey,
    kid: Mutex<Option<String>>,
    replay_nonce: Mutex<Option<String>>,
}

impl AcmeClient {
    fn new(
        transport: Arc<dyn HttpTransport>,
        directory: AcmeDirectory,
        key: AccountKey,
        kid: Option<String>,
        replay_nonce: Option<String>,
    ) -> Self {
        Self {
            transport,
            directory,
            key,
            kid: Mutex::new(kid),
            replay_nonce: Mutex::new(replay_nonce),
        }
    }

    fn set_kid(&self, kid: String) {
        *self.kid.lock().expect("ACME kid mutex poisoned") = Some(kid);
    }

    fn remember_nonce(&self, response: &HttpResponse) {
        if let Some(nonce) = response.header("Replay-Nonce") {
            *self
                .replay_nonce
                .lock()
                .expect("ACME nonce mutex poisoned") = Some(nonce.to_owned());
        }
    }

    async fn fetch_nonce(&self) -> Result<String> {
        let response = self
            .transport
            .request("HEAD", &self.directory.new_nonce, &[], None)
            .await?;
        if !response.is_success() {
            return Err(http_status_error("ACME newNonce", &response));
        }
        let nonce = response
            .header("Replay-Nonce")
            .ok_or_else(|| Error::AcmeProtocol("newNonce response omitted Replay-Nonce".into()))?
            .to_owned();
        *self
            .replay_nonce
            .lock()
            .expect("ACME nonce mutex poisoned") = Some(nonce.clone());
        Ok(nonce)
    }

    async fn next_nonce(&self) -> Result<String> {
        if let Some(nonce) = self
            .replay_nonce
            .lock()
            .expect("ACME nonce mutex poisoned")
            .take()
        {
            return Ok(nonce);
        }
        self.fetch_nonce().await
    }

    async fn signed_post(&self, url: &str, payload: &[u8]) -> Result<HttpResponse> {
        for attempt in 0..=1 {
            let nonce = self.next_nonce().await?;
            let kid = self.kid.lock().expect("ACME kid mutex poisoned").clone();
            let (body, _) = self.key.jws(&nonce, url, payload, kid.as_deref())?;
            let response = self
                .transport
                .request(
                    "POST",
                    url,
                    &[(
                        "Content-Type".to_owned(),
                        "application/jose+json".to_owned(),
                    )],
                    Some(("application/jose+json".to_owned(), body)),
                )
                .await?;
            self.remember_nonce(&response);
            if attempt == 0 && response_is_bad_nonce(&response) {
                continue;
            }
            return Ok(response);
        }
        Err(Error::AcmeProtocol(
            "ACME server rejected a request nonce twice".into(),
        ))
    }

    async fn post_json(&self, url: &str, payload: &Value) -> Result<HttpResponse> {
        let body = serde_json::to_vec(payload)
            .map_err(|error| Error::AcmeProtocol(format!("serialize ACME payload: {error}")))?;
        self.signed_post(url, &body).await
    }

    async fn post_as_get(&self, url: &str) -> Result<HttpResponse> {
        self.signed_post(url, &[]).await
    }
}

fn response_is_bad_nonce(response: &HttpResponse) -> bool {
    if response.status != 400 {
        return false;
    }
    serde_json::from_slice::<Value>(&response.body)
        .ok()
        .and_then(|problem| problem.get("type").and_then(Value::as_str).map(str::to_owned))
        .is_some_and(|problem_type| problem_type.ends_with(":badNonce"))
}

async fn load_or_create_account(
    cache_dir: &Path,
    email: &str,
    production: bool,
) -> Result<Arc<AcmeClient>> {
    let directory_url = if production {
        PRODUCTION_DIRECTORY
    } else {
        STAGING_DIRECTORY
    };
    let credentials_path = cache_dir.join("acme_account_credentials.json");
    let cached = std::fs::read_to_string(&credentials_path)
        .ok()
        .and_then(|json| serde_json::from_str::<CachedCredentials>(&json).ok());
    let (key, cached_kid) = match cached {
        Some(credentials) if credentials.directory_url == directory_url => {
            match hex_decode(&credentials.account_key_pkcs8_hex)
                .and_then(|bytes| AccountKey::from_pkcs8(bytes).ok())
            {
                Some(key) => (key, Some(credentials.kid)),
                None => (AccountKey::generate()?, None),
            }
        }
        _ => (AccountKey::generate()?, None),
    };

    let transport: Arc<dyn HttpTransport> = Arc::new(NagoTransport);
    let directory_response = transport
        .request("GET", directory_url, &[("Accept".into(), "application/json".into())], None)
        .await?;
    let replay_nonce = directory_response
        .header("Replay-Nonce")
        .map(str::to_owned);
    let directory: AcmeDirectory = parse_json(&directory_response, "ACME directory")?;
    let client = Arc::new(AcmeClient::new(
        transport,
        directory,
        key,
        cached_kid,
        replay_nonce,
    ));

    let needs_registration = client.kid.lock().expect("ACME kid mutex poisoned").is_none();
    if needs_registration {
        let contact = format!("mailto:{email}");
        let response = client
            .post_json(
                &client.directory.new_account,
                &json!({"contact":[contact], "termsOfServiceAgreed":true}),
            )
            .await?;
        if !response.is_success() {
            return Err(Error::Account(format!(
                "ACME newAccount failed: {}",
                String::from_utf8_lossy(&response.body)
            )));
        }
        let kid = response
            .header("Location")
            .ok_or_else(|| Error::Account("newAccount response omitted Location".into()))?
            .to_owned();
        client.set_kid(kid);
        let credentials = CachedCredentials {
            directory_url: directory_url.to_owned(),
            kid: client
                .kid
                .lock()
                .expect("ACME kid mutex poisoned")
                .clone()
                .expect("kid was just set"),
            account_key_pkcs8_hex: hex_encode(&client.key.pkcs8),
        };
        let encoded = serde_json::to_vec_pretty(&credentials)
            .map_err(|error| Error::Account(format!("serialize account credentials: {error}")))?;
        std::fs::write(credentials_path, encoded)?;
        info!("Created and cached ACME account");
    } else {
        info!("Loaded ACME account from cache");
    }
    Ok(client)
}

// ---------------------------------------------------------------------------
// CSR, expiry and ACME order flow
// ---------------------------------------------------------------------------

fn generate_csr(domains: &[String]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_pair = KeyPair::generate().map_err(|error| Error::Config(format!("CSR key gen: {error}")))?;
    let mut params = CertificateParams::new(domains.to_vec())
        .map_err(|error| Error::Config(format!("CSR params: {error}")))?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|error| Error::Config(format!("CSR serialize: {error}")))?;
    Ok((csr.der().to_vec(), key_pair.serialize_pem().into_bytes()))
}

fn read_cert_not_after(fullchain_path: &Path) -> Result<SystemTime> {
    let pem_bytes = std::fs::read(fullchain_path)?;
    let (_, pem) =
        parse_x509_pem(&pem_bytes).map_err(|error| Error::Config(format!("cert PEM parse: {error}")))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|error| Error::Config(format!("cert DER parse: {error}")))?;
    let timestamp = cert.validity().not_after.timestamp();
    if timestamp < 0 {
        return Err(Error::Config("cert NotAfter is before Unix epoch".into()));
    }
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp as u64))
}

#[derive(Deserialize)]
struct AcmeOrder {
    status: String,
    #[serde(default)]
    authorizations: Vec<String>,
    #[serde(default)]
    finalize: String,
    certificate: Option<String>,
    error: Option<Value>,
}

#[derive(Deserialize)]
struct AcmeAuthorization {
    status: String,
    identifier: AcmeIdentifier,
    #[serde(default)]
    challenges: Vec<AcmeChallenge>,
    error: Option<Value>,
}

#[derive(Deserialize)]
struct AcmeIdentifier {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

#[derive(Deserialize)]
struct AcmeChallenge {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    token: String,
}

struct ChallengeInfo {
    fqdn: String,
    dns_value: String,
}

async fn issue_certificate<D: DnsProvider>(
    dns: &D,
    account: &AcmeClient,
    domains: &[String],
    propagation_secs: u64,
    cert_dir: &Path,
    cancel: Option<&AtomicBool>,
    notify: Option<&nagoya::sync::Notify>,
) -> Result<()> {
    let mut challenges = Vec::new();
    let result = issue_certificate_inner(
        dns,
        account,
        domains,
        propagation_secs,
        cert_dir,
        cancel,
        notify,
        &mut challenges,
    )
    .await;
    for challenge in &challenges {
        if let Err(error) = dns
            .remove_txt_record(&challenge.fqdn, &challenge.dns_value)
            .await
        {
            warn!(
                "Failed to remove TXT record {} after ACME attempt: {error}",
                challenge.fqdn
            );
        }
    }
    result
}

#[allow(clippy::too_many_arguments)] // the issuance context: transport, account, order inputs, cancellation, cleanup
async fn issue_certificate_inner<D: DnsProvider>(
    dns: &D,
    account: &AcmeClient,
    domains: &[String],
    propagation_secs: u64,
    cert_dir: &Path,
    cancel: Option<&AtomicBool>,
    notify: Option<&nagoya::sync::Notify>,
    cleanup: &mut Vec<ChallengeInfo>,
) -> Result<()> {
    check_cancelled(cancel)?;
    let identifiers: Vec<Value> = domains
        .iter()
        .map(|domain| json!({"type":"dns", "value":domain}))
        .collect();
    let response = account
        .post_json(
            &account.directory.new_order,
            &json!({"identifiers":identifiers}),
        )
        .await?;
    let mut order: AcmeOrder = parse_json(&response, "ACME newOrder")?;
    let order_url = response
        .header("Location")
        .ok_or_else(|| Error::Order("newOrder response omitted Location".into()))?
        .to_owned();

    let mut cleaned_names = HashSet::new();
    let mut challenge_urls = Vec::new();
    for authorization_url in &order.authorizations {
        check_cancelled(cancel)?;
        let response = account.post_as_get(authorization_url).await?;
        let authorization: AcmeAuthorization = parse_json(&response, "ACME authorization")?;
        if authorization.status == "valid" {
            continue;
        }
        if authorization.status == "invalid" {
            return Err(Error::Challenge(
                authorization
                    .error
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "ACME authorization became invalid".into()),
            ));
        }
        if authorization.identifier.kind != "dns" {
            return Err(Error::Config("ACME authorization identifier is not DNS".into()));
        }
        let challenge = authorization
            .challenges
            .iter()
            .find(|challenge| challenge.kind == "dns-01")
            .ok_or_else(|| Error::Challenge("ACME server offered no DNS-01 challenge".into()))?;
        if challenge.token.is_empty() {
            return Err(Error::Challenge("ACME DNS-01 challenge token was empty".into()));
        }
        let fqdn = format!("_acme-challenge.{}", authorization.identifier.value);
        if cleaned_names.insert(fqdn.clone()) {
            dns.cleanup_txt_records(&fqdn).await?;
        }
        let key_authorization = key_authorization(&challenge.token, &account.key.thumbprint());
        let dns_value = dns_txt_value(&key_authorization);
        dns.add_txt_record(&fqdn, &dns_value).await?;
        cleanup.push(ChallengeInfo { fqdn, dns_value });
        challenge_urls.push(challenge.url.clone());
    }

    if !cleanup.is_empty() {
        tracing::debug!("DNS-01: waiting {propagation_secs}s for TXT propagation");
        if wait_or_cancel(cancel, notify, Duration::from_secs(propagation_secs)).await {
            return Err(Error::Cancelled);
        }
    }
    check_cancelled(cancel)?;

    for challenge_url in challenge_urls {
        let response = account.post_json(&challenge_url, &json!({})).await?;
        if !response.is_success() {
            return Err(Error::Challenge(format!(
                "ACME challenge acknowledgement failed: {}",
                String::from_utf8_lossy(&response.body)
            )));
        }
    }

    order = poll_order(
        account,
        &order_url,
        OrderGoal::Ready,
        Duration::from_secs(1),
        cancel,
        notify,
    )
    .await?;

    let (csr, private_key) = generate_csr(domains)?;
    check_cancelled(cancel)?;
    let finalize = if order.finalize.is_empty() {
        return Err(Error::Order("ACME order omitted finalize URL".into()));
    } else {
        order.finalize.clone()
    };
    let response = account
        .post_json(&finalize, &json!({"csr":base64url_encode(&csr)}))
        .await?;
    if !response.is_success() {
        return Err(Error::Order(format!(
            "ACME finalize failed: {}",
            String::from_utf8_lossy(&response.body)
        )));
    }

    order = poll_order(
        account,
        &order_url,
        OrderGoal::Valid,
        Duration::from_secs(1),
        cancel,
        notify,
    )
    .await?;
    let certificate_url = order
        .certificate
        .ok_or_else(|| Error::Order("valid ACME order omitted certificate URL".into()))?;
    let response = account.post_as_get(&certificate_url).await?;
    if !response.is_success() {
        return Err(http_status_error("ACME certificate download", &response));
    }
    if !response.body.windows(b"-----BEGIN CERTIFICATE-----".len()).any(|window| {
        window == b"-----BEGIN CERTIFICATE-----"
    }) {
        return Err(Error::Pem("ACME certificate response was not a PEM chain".into()));
    }
    std::fs::write(cert_dir.join("fullchain.pem"), &response.body)?;
    std::fs::write(cert_dir.join("privkey.pem"), private_key)?;
    info!("DNS-01 certificate written to {:?}", cert_dir);
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OrderGoal {
    Ready,
    Valid,
}

async fn poll_order(
    account: &AcmeClient,
    order_url: &str,
    goal: OrderGoal,
    first_delay: Duration,
    cancel: Option<&AtomicBool>,
    notify: Option<&nagoya::sync::Notify>,
) -> Result<AcmeOrder> {
    let mut delay = first_delay;
    loop {
        check_cancelled(cancel)?;
        let response = account.post_as_get(order_url).await?;
        let order: AcmeOrder = parse_json(&response, "ACME order status")?;
        if order.status == "invalid" {
            let detail = order
                .error
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "ACME order became invalid".into());
            return Err(Error::Challenge(detail));
        }
        let reached = match goal {
            OrderGoal::Ready => order.status == "ready" || order.status == "valid",
            OrderGoal::Valid => order.status == "valid",
        };
        if reached {
            return Ok(order);
        }
        if !matches!(order.status.as_str(), "pending" | "processing" | "ready") {
            return Err(Error::Order(format!(
                "unexpected ACME order status {}",
                order.status
            )));
        }
        if wait_or_cancel(cancel, notify, delay).await {
            return Err(Error::Cancelled);
        }
        delay = delay.saturating_mul(2).min(MAX_ORDER_POLL_DELAY);
    }
}

fn check_cancelled(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

async fn wait_or_cancel(
    cancel: Option<&AtomicBool>,
    notify: Option<&nagoya::sync::Notify>,
    duration: Duration,
) -> bool {
    if cancel.is_none() {
        if !duration.is_zero() {
            nagoya::sleep(duration).await;
        }
        return false;
    }
    let Some(cancel) = cancel else {
        return false;
    };
    if let Some(notify) = notify {
        let mut notified = std::pin::pin!(notify.notified());
        let mut timer = std::pin::pin!(nagoya::sleep(duration));
        return std::future::poll_fn(|context| {
            if cancel.load(Ordering::Acquire) {
                return std::task::Poll::Ready(true);
            }
            if notified.as_mut().poll(context).is_ready() {
                return std::task::Poll::Ready(true);
            }
            if timer.as_mut().poll(context).is_ready() {
                return std::task::Poll::Ready(cancel.load(Ordering::Acquire));
            }
            std::task::Poll::Pending
        })
        .await;
    }
    let mut remaining = duration;
    while !remaining.is_zero() && !cancel.load(Ordering::Acquire) {
        let slice = remaining.min(CANCEL_POLL_INTERVAL);
        nagoya::sleep(slice).await;
        remaining = remaining.saturating_sub(slice);
    }
    cancel.load(Ordering::Acquire)
}

async fn renewal_loop<F, Fut>(
    cancel: Arc<AtomicBool>,
    notify: Arc<nagoya::sync::Notify>,
    mut next: F,
)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Duration>,
{
    loop {
        if cancel.load(Ordering::Acquire) {
            return;
        }
        let delay = next().await;
        if wait_or_cancel(Some(cancel.as_ref()), Some(notify.as_ref()), delay).await {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// DnsAcmeProvider
// ---------------------------------------------------------------------------

/// ACME provider using DNS-01 challenges.
///
/// Requires programmatic access to your DNS provider.
///
/// # Usage
///
/// ```no_run
/// use cert_provider::provider::dns01::{DnsAcmeProvider, BunnyDns};
/// use cert_provider::provider::CertProvider;
/// use std::path::PathBuf;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let cert_dir = PathBuf::from("/data/certs");
/// let domains = vec!["example.com".to_owned()];
/// let dns = BunnyDns::new(std::env::var("BUNNY_API_KEY").unwrap());
/// let mut provider = DnsAcmeProvider::new("admin@example.com", dns)
///     .production()
///     .propagation_secs(90)
///     .max_retries(3);
/// let _guard = provider.init(cert_dir, Some(domains)).await?;
/// # Ok(())
/// # }
/// ```
pub struct DnsAcmeProvider<D: DnsProvider> {
    contact_email: String,
    dns: Arc<D>,
    production: bool,
    propagation_secs: u64,
    renew_within_days: u64,
    max_retries: u32,
    #[cfg(feature = "s3-sync")]
    s3_sync: Option<Arc<S3CertSync>>,
}

impl<D: DnsProvider> DnsAcmeProvider<D> {
    /// Create a new provider backed by the given DNS implementation.
    /// Defaults to the Let's Encrypt staging environment. Call production()
    /// before deploying for real.
    pub fn new(contact_email: impl Into<String>, dns: D) -> Self {
        Self {
            contact_email: contact_email.into(),
            dns: Arc::new(dns),
            production: false,
            propagation_secs: DEFAULT_PROPAGATION_SECS,
            renew_within_days: DEFAULT_RENEW_WITHIN_DAYS,
            max_retries: 0,
            #[cfg(feature = "s3-sync")]
            s3_sync: None,
        }
    }

    /// Create a new provider with a pre-wrapped shared DNS backend.
    pub fn from_arc(contact_email: impl Into<String>, dns: Arc<D>) -> Self {
        Self {
            contact_email: contact_email.into(),
            dns,
            production: false,
            propagation_secs: DEFAULT_PROPAGATION_SECS,
            renew_within_days: DEFAULT_RENEW_WITHIN_DAYS,
            max_retries: 0,
            #[cfg(feature = "s3-sync")]
            s3_sync: None,
        }
    }

    /// Attach an S3 sync handle for the certificate directory.
    #[cfg(feature = "s3-sync")]
    pub fn with_s3_sync(mut self, s3_sync: Arc<S3CertSync>) -> Self {
        self.s3_sync = Some(s3_sync);
        self
    }

    /// Switch to the Let's Encrypt production directory.
    pub fn production(mut self) -> Self {
        self.production = true;
        self
    }

    /// Seconds to wait after adding TXT records before notifying Let's Encrypt.
    pub fn propagation_secs(mut self, secs: u64) -> Self {
        self.propagation_secs = secs;
        self
    }

    /// Days before certificate expiry at which to begin renewal.
    pub fn renew_within_days(mut self, days: u64) -> Self {
        self.renew_within_days = days;
        self
    }

    /// Number of DNS-01 challenge retries after the initial attempt.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }
}

#[async_trait]
impl<D: DnsProvider> CertProvider for DnsAcmeProvider<D> {
    async fn init(
        &mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard> {
        let domains = domains.ok_or_else(|| Error::Config("domains required".into()))?;
        if domains.is_empty() {
            return Err(Error::Config("at least one domain required".into()));
        }
        std::fs::create_dir_all(&cert_dir)?;
        let cache_dir = cert_dir.join("acme_cache");
        std::fs::create_dir_all(&cache_dir)?;
        let fullchain_path = cert_dir.join("fullchain.pem");
        let privkey_path = cert_dir.join("privkey.pem");

        if !fullchain_path.exists() || !privkey_path.exists() {
            let account =
                load_or_create_account(&cache_dir, &self.contact_email, self.production).await?;
            #[cfg(feature = "s3-sync")]
            if let Some(sync) = &self.s3_sync {
                if let Err(error) = sync.push_from(&cert_dir).await {
                    tracing::debug!(error = %error, "Failed to push ACME credentials to S3");
                }
            }
            let mut retries_left = self.max_retries;
            let mut retry_number = 0u64;
            loop {
                match issue_certificate(
                    &self.dns,
                    &account,
                    &domains,
                    self.propagation_secs,
                    &cert_dir,
                    None,
                    None,
                )
                .await
                {
                    Ok(()) => break,
                    Err(Error::Challenge(detail)) if retries_left > 0 => {
                        retries_left -= 1;
                        retry_number += 1;
                        let delay = Duration::from_secs(
                            self.propagation_secs.saturating_mul(retry_number),
                        );
                        tracing::debug!(
                            "DNS-01 challenge failed ({detail}), retrying in {}s ({retries_left} retries left)",
                            delay.as_secs()
                        );
                        nagoya::sleep(delay).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        } else {
            tracing::debug!("Existing cert files found in {:?}", cert_dir);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(nagoya::sync::Notify::new());
        let task_stop = stop.clone();
        let task_notify = notify.clone();
        let dns = self.dns.clone();
        let task_cert_dir = cert_dir.clone();
        let task_cache_dir = cache_dir.clone();
        let contact_email = self.contact_email.clone();
        let task_domains = domains.clone();
        let production = self.production;
        let propagation_secs = self.propagation_secs;
        let renew_within = Duration::from_secs(self.renew_within_days.saturating_mul(86_400));
        let retry_delay = Arc::new(Mutex::new(Duration::from_secs(3_600)));
        #[cfg(feature = "s3-sync")]
        let s3_sync = self.s3_sync.clone();

        drop(nagoya::spawn({
            let retry_delay = retry_delay.clone();
            let dns = dns.clone();
            let task_cert_dir = task_cert_dir.clone();
            let task_cache_dir = task_cache_dir.clone();
            let contact_email = contact_email.clone();
            let task_domains = task_domains.clone();
            let task_stop = task_stop.clone();
            let task_notify = task_notify.clone();
            #[cfg(feature = "s3-sync")]
            let s3_sync = s3_sync.clone();
            async move {
                renewal_loop(task_stop.clone(), task_notify.clone(), move || {
                    let retry_delay = retry_delay.clone();
                    let dns = dns.clone();
                    let task_cert_dir = task_cert_dir.clone();
                    let task_cache_dir = task_cache_dir.clone();
                    let contact_email = contact_email.clone();
                    let task_domains = task_domains.clone();
                    let task_stop = task_stop.clone();
                    let task_notify = task_notify.clone();
                    #[cfg(feature = "s3-sync")]
                    let s3_sync = s3_sync.clone();
                    async move {
                        let current_retry = *retry_delay.lock().expect("retry mutex poisoned");
                        let until_renewal = match read_cert_not_after(&task_cert_dir.join("fullchain.pem")) {
                            Ok(not_after) => {
                                *retry_delay.lock().expect("retry mutex poisoned") =
                                    Duration::from_secs(3_600);
                                let renew_at = not_after.checked_sub(renew_within).unwrap_or(not_after);
                                renew_at
                                    .duration_since(SystemTime::now())
                                    .unwrap_or(Duration::ZERO)
                            }
                            Err(error) => {
                                tracing::debug!(
                                    "Failed to read cert expiry: {error}, retrying in {:?}",
                                    current_retry
                                );
                                *retry_delay.lock().expect("retry mutex poisoned") =
                                    (current_retry * 2).min(MAX_RENEWAL_RETRY_DELAY);
                                return current_retry;
                            }
                        };
                        if !until_renewal.is_zero() {
                            return until_renewal;
                        }
                        if task_stop.load(Ordering::Acquire) {
                            return Duration::ZERO;
                        }
                        let account = match load_or_create_account(
                            &task_cache_dir,
                            &contact_email,
                            production,
                        )
                        .await
                        {
                            Ok(account) => account,
                            Err(error) => {
                                tracing::debug!(
                                    "Renewal account load failed ({error}), retrying in {:?}",
                                    current_retry
                                );
                                *retry_delay.lock().expect("retry mutex poisoned") =
                                    (current_retry * 2).min(MAX_RENEWAL_RETRY_DELAY);
                                return current_retry;
                            }
                        };
                        match issue_certificate(
                            &dns,
                            &account,
                            &task_domains,
                            propagation_secs,
                            &task_cert_dir,
                            Some(task_stop.as_ref()),
                            Some(task_notify.as_ref()),
                        )
                        .await
                        {
                            Ok(()) => {
                                tracing::debug!("DNS-01 certificate renewed successfully");
                                *retry_delay.lock().expect("retry mutex poisoned") =
                                    Duration::from_secs(3_600);
                                #[cfg(feature = "s3-sync")]
                                if let Some(sync) = &s3_sync {
                                    if let Err(error) = sync.push_from(&task_cert_dir).await {
                                        tracing::debug!(
                                            error = %error,
                                            "Failed to push renewed certificate to S3"
                                        );
                                    }
                                }
                                Duration::ZERO
                            }
                            Err(Error::Cancelled) => Duration::ZERO,
                            Err(error) => {
                                tracing::debug!(
                                    "Renewal failed: {error}, retrying in {:?}",
                                    current_retry
                                );
                                *retry_delay.lock().expect("retry mutex poisoned") =
                                    (current_retry * 2).min(MAX_RENEWAL_RETRY_DELAY);
                                current_retry
                            }
                        }
                    }
                })
                .await;
            }
        }));
        Ok(BackgroundGuard::with_atomic_cancel(stop, notify))
    }
}

// ---------------------------------------------------------------------------
// Offline unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Clone)]
    struct RecordedRequest {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Option<(String, Vec<u8>)>,
    }

    #[derive(Default)]
    struct FakeTransport {
        responses: Mutex<VecDeque<HttpResponse>>,
        requests: Mutex<Vec<RecordedRequest>>,
    }

    impl FakeTransport {
        fn with_responses(responses: Vec<HttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl HttpTransport for FakeTransport {
        async fn request(
            &self,
            method: &str,
            url: &str,
            headers: &[(String, String)],
            body: Option<(String, Vec<u8>)>,
        ) -> Result<HttpResponse> {
            self.requests.lock().unwrap().push(RecordedRequest {
                method: method.to_owned(),
                url: url.to_owned(),
                headers: headers.to_vec(),
                body,
            });
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| Error::HttpClient("fake transport response queue is empty".into()))
        }
    }

    fn response(status: u16, headers: &[(&str, &str)], body: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn test_client(transport: Arc<dyn HttpTransport>, nonce: &str) -> AcmeClient {
        AcmeClient::new(
            transport,
            AcmeDirectory {
                new_nonce: "https://ca.example/new-nonce".into(),
                new_account: "https://ca.example/new-account".into(),
                new_order: "https://ca.example/new-order".into(),
            },
            AccountKey::generate().unwrap(),
            Some("https://ca.example/account/1".into()),
            Some(nonce.into()),
        )
    }

    #[test]
    fn jws_has_expected_signing_input_and_protected_header_shape() {
        let key = AccountKey::generate().unwrap();
        let (body, signing_input) = key
            .jws("nonce-value", "https://ca.example/new-account", br#"{"termsOfServiceAgreed":true}"#, None)
            .unwrap();
        let flattened: Value = serde_json::from_slice(&body).unwrap();
        let protected = flattened["protected"].as_str().unwrap();
        let payload = flattened["payload"].as_str().unwrap();
        assert_eq!(signing_input, format!("{protected}.{payload}"));
        assert_eq!(base64url_decode(payload).unwrap(), br#"{"termsOfServiceAgreed":true}"#);
        let header: Value = serde_json::from_slice(&base64url_decode(protected).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["nonce"], "nonce-value");
        assert_eq!(header["url"], "https://ca.example/new-account");
        assert_eq!(header["jwk"]["kty"], "EC");
        assert_eq!(header["jwk"]["crv"], "P-256");
        assert!(header.get("kid").is_none());
        assert_eq!(base64url_decode(flattened["signature"].as_str().unwrap()).unwrap().len(), 64);
    }

    #[test]
    fn jwk_thumbprint_matches_the_rfc_7638_example() {
        let canonical = concat!(
            "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"",
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt",
            "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6",
            "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD",
            "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9",
            "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH",
            "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}"
        );
        assert_eq!(sha256_base64url(canonical.as_bytes()), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn key_authorization_and_dns_txt_value_follow_rfc_8555() {
        let authorization = key_authorization("token", "thumb");
        assert_eq!(authorization, "token.thumb");
        assert_eq!(dns_txt_value(&authorization), "lCdftpJCXapaZHkBGIZbcubeKW8RmA0jSG_aZN01zbU");
    }

    #[test]
    fn bad_nonce_retries_once_with_the_replay_nonce() {
        let fake = Arc::new(FakeTransport::with_responses(vec![
            response(
                400,
                &[("Replay-Nonce", "nonce-retry")],
                r#"{"type":"urn:ietf:params:acme:error:badNonce"}"#,
            ),
            response(200, &[("Replay-Nonce", "nonce-next")], "{}"),
        ]));
        let client = test_client(fake.clone(), "nonce-first");
        let result = nagoya::block_on(client.post_json("https://ca.example/action", &json!({"x":1})));
        assert_eq!(result.unwrap().status, 200);
        let requests = fake.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].url, "https://ca.example/action");
        assert!(requests[0]
            .headers
            .iter()
            .any(|(name, value)| name == "Content-Type" && value == "application/jose+json"));
        assert_eq!(
            requests[0].body.as_ref().unwrap().0,
            "application/jose+json"
        );
        let first: Value = serde_json::from_slice(&requests[0].body.as_ref().unwrap().1).unwrap();
        let second: Value = serde_json::from_slice(&requests[1].body.as_ref().unwrap().1).unwrap();
        let first_header: Value = serde_json::from_slice(
            &base64url_decode(first["protected"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let second_header: Value = serde_json::from_slice(
            &base64url_decode(second["protected"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(first_header["nonce"], "nonce-first");
        assert_eq!(second_header["nonce"], "nonce-retry");
    }

    #[test]
    fn order_polling_observes_pending_ready_processing_valid_transitions() {
        let fake = Arc::new(FakeTransport::with_responses(vec![
            response(200, &[("Replay-Nonce", "n1")], r#"{"status":"pending"}"#),
            response(200, &[("Replay-Nonce", "n2")], r#"{"status":"ready"}"#),
            response(200, &[("Replay-Nonce", "n3")], r#"{"status":"processing"}"#),
            response(
                200,
                &[("Replay-Nonce", "n4")],
                r#"{"status":"valid","certificate":"https://ca.example/cert/1"}"#,
            ),
        ]));
        let client = test_client(fake.clone(), "n0");
        let ready = nagoya::block_on(poll_order(
            &client,
            "https://ca.example/order/1",
            OrderGoal::Ready,
            Duration::ZERO,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(ready.status, "ready");
        let valid = nagoya::block_on(poll_order(
            &client,
            "https://ca.example/order/1",
            OrderGoal::Valid,
            Duration::ZERO,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(valid.status, "valid");
        assert_eq!(valid.certificate.as_deref(), Some("https://ca.example/cert/1"));
        assert_eq!(fake.requests().len(), 4);
    }

    #[test]
    fn cancellation_stops_the_renewal_loop() {
        let cancel = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(nagoya::sync::Notify::new());
        let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let guard = BackgroundGuard::with_atomic_cancel(cancel.clone(), notify.clone());
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            drop(guard);
        });
        let tick_counter = ticks.clone();
        nagoya::block_on(renewal_loop(cancel, notify, move || {
            tick_counter.fetch_add(1, Ordering::Relaxed);
            async { Duration::from_secs(3_600) }
        }));
        canceller.join().unwrap();
        assert_eq!(ticks.load(Ordering::Relaxed), 1);
    }
}
