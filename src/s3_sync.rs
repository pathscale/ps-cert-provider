use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use awscreds::Credentials;
use awsregion::Region;
use s3::Bucket;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};
use crate::provider::BackgroundGuard;
use crate::secret_file::write_secret;

#[derive(Clone)]
pub struct S3Config {
    pub bucket_name: String,
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub region: Option<String>,
    pub prefix: Option<String>,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("bucket_name", &self.bucket_name)
            .field("endpoint", &"<redacted>")
            .field("access_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .field("region", &self.region)
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl S3Config {
    pub fn is_configured(&self) -> bool {
        !self.bucket_name.is_empty()
            && !self.endpoint.is_empty()
            && !self.access_key.is_empty()
            && !self.secret_key.is_empty()
    }
}

#[derive(Clone)]
pub struct S3CertSync {
    bucket: Arc<Box<Bucket>>,
    config: S3Config,
}

impl std::fmt::Debug for S3CertSync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3CertSync")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub struct PullResult {
    pub fullchain_found: bool,
    pub privkey_found: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum StatusClass {
    Success,
    NotFound,
    Failure(u16),
}

#[derive(Debug, PartialEq, Eq)]
enum RequestErrorClass {
    NotFound,
    HttpFailure(u16),
    RequestFailure,
}

impl S3CertSync {
    fn classify_status(status: u16) -> StatusClass {
        if (200..300).contains(&status) {
            StatusClass::Success
        } else if status == 404 {
            StatusClass::NotFound
        } else {
            StatusClass::Failure(status)
        }
    }

    pub fn new(config: S3Config) -> Result<Self> {
        let bucket = Self::create_bucket(&config)?;
        Ok(Self {
            bucket: Arc::new(bucket),
            config,
        })
    }

    fn create_bucket(config: &S3Config) -> Result<Box<Bucket>> {
        let credentials = Credentials::new(
            Some(&config.access_key),
            Some(&config.secret_key),
            None,
            None,
            None,
        )?;

        let region = if let Some(region) = &config.region {
            Region::Custom {
                region: region.clone(),
                endpoint: config.endpoint.clone(),
            }
        } else {
            Region::Custom {
                region: "auto".to_string(),
                endpoint: config.endpoint.clone(),
            }
        };

        let bucket = Bucket::new(&config.bucket_name, region, credentials)?.with_path_style();
        Ok(bucket)
    }

    fn s3_key(&self, filename: &str) -> String {
        let prefix = self.config.prefix.as_deref().unwrap_or("");
        let prefix = prefix.trim_end_matches('/');
        if prefix.is_empty() {
            filename.to_string()
        } else {
            format!("{prefix}/{filename}")
        }
    }

    fn http_status(error: &s3::error::S3Error) -> Option<u16> {
        match error {
            s3::error::S3Error::HttpFailWithBody(status, _) => Some(*status),
            _ => None,
        }
    }

    fn classify_request_error(error: &s3::error::S3Error) -> RequestErrorClass {
        match Self::http_status(error) {
            Some(404) => RequestErrorClass::NotFound,
            Some(status) => RequestErrorClass::HttpFailure(status),
            None => RequestErrorClass::RequestFailure,
        }
    }

    fn status_error(operation: &str, name: &str, status: u16) -> Error {
        Error::S3(format!("S3 {operation} failed for {name} (HTTP {status})"))
    }

    fn request_error(operation: &str, name: &str) -> Error {
        Error::S3(format!("S3 {operation} failed for {name} (request error)"))
    }

    pub async fn pull_to(&self, cert_dir: &Path) -> Result<PullResult> {
        let filenames = [
            "fullchain.pem",
            "privkey.pem",
            "acme_cache/acme_account_credentials.json",
        ];
        // Finish every remote read before publishing any fetched object locally.
        // This protects local files from a later GET failure, but does not make
        // the subsequent independent file writes an atomic multi-file publish.
        let mut contents = Vec::with_capacity(filenames.len());
        for name in filenames {
            let s3_key = self.s3_key(name);
            match self.bucket.get_object(&s3_key).await {
                Ok(response) => {
                    let status = response.status_code();
                    match Self::classify_status(status) {
                        StatusClass::Success => contents.push(Some(response.to_vec())),
                        StatusClass::NotFound => contents.push(None),
                        StatusClass::Failure(status) => {
                            return Err(Self::status_error("GET", name, status));
                        }
                    }
                }
                Err(error) => match Self::classify_request_error(&error) {
                    RequestErrorClass::NotFound => contents.push(None),
                    RequestErrorClass::HttpFailure(status) => {
                        return Err(Self::status_error("GET", name, status));
                    }
                    RequestErrorClass::RequestFailure => {
                        return Err(Self::request_error("GET", name));
                    }
                },
            }
        }

        let [fullchain, privkey, account] = contents.as_slice() else {
            unreachable!("one result is collected for each S3 restore object");
        };

        if let Some(content) = account {
            let path = cert_dir.join(filenames[2]);
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                        .await?;
                }
            }
            write_secret(&path, content).await?;
            tracing::debug!(path = %path.display(), "Downloaded ACME credentials from S3");
        }

        let mut result = PullResult::default();
        if let (Some(fullchain), Some(privkey)) = (fullchain, privkey) {
            tokio::fs::create_dir_all(cert_dir).await?;
            let fullchain_path = cert_dir.join(filenames[0]);
            let privkey_path = cert_dir.join(filenames[1]);
            tokio::fs::write(&fullchain_path, fullchain).await?;
            write_secret(&privkey_path, privkey).await?;
            tracing::debug!(path = %fullchain_path.display(), "Downloaded cert file from S3");
            tracing::debug!(path = %privkey_path.display(), "Downloaded cert file from S3");
            result.fullchain_found = true;
            result.privkey_found = true;
        } else if fullchain.is_some() || privkey.is_some() {
            tracing::debug!("S3 certificate pair is incomplete; preserving local PEM files");
        }
        Ok(result)
    }

    pub async fn push_from(&self, cert_dir: &Path) -> Result<()> {
        let filenames = [
            "fullchain.pem",
            "privkey.pem",
            "acme_cache/acme_account_credentials.json",
        ];
        for name in &filenames {
            let path = cert_dir.join(name);
            if !path.exists() {
                tracing::debug!(path = %path.display(), "Skipping S3 push — file does not exist");
                continue;
            }
            let content = tokio::fs::read(&path).await?;
            let s3_key = self.s3_key(name);
            match self.bucket.put_object(&s3_key, &content).await {
                Ok(response) => match Self::classify_status(response.status_code()) {
                    StatusClass::Success => {}
                    StatusClass::NotFound | StatusClass::Failure(_) => {
                        return Err(Self::status_error("PUT", name, response.status_code()));
                    }
                },
                Err(error) => match Self::classify_request_error(&error) {
                    RequestErrorClass::NotFound => {
                        return Err(Self::status_error("PUT", name, 404));
                    }
                    RequestErrorClass::HttpFailure(status) => {
                        return Err(Self::status_error("PUT", name, status));
                    }
                    RequestErrorClass::RequestFailure => {
                        return Err(Self::request_error("PUT", name));
                    }
                },
            }
            tracing::debug!(key = %s3_key, "Uploaded cert file to S3");
        }
        Ok(())
    }

    pub async fn push_credentials_only(&self, cert_dir: &Path) -> Result<()> {
        let filename = "acme_cache/acme_account_credentials.json";
        let path = cert_dir.join(filename);
        if !path.exists() {
            tracing::debug!(path = %path.display(), "Skipping credentials push — file does not exist");
            return Ok(());
        }
        let content = tokio::fs::read(&path).await?;
        let s3_key = self.s3_key(filename);
        match self.bucket.put_object(&s3_key, &content).await {
            Ok(response) => match Self::classify_status(response.status_code()) {
                StatusClass::Success => {}
                StatusClass::NotFound | StatusClass::Failure(_) => {
                    return Err(Self::status_error("PUT", filename, response.status_code()));
                }
            },
            Err(error) => match Self::classify_request_error(&error) {
                RequestErrorClass::NotFound => {
                    return Err(Self::status_error("PUT", filename, 404));
                }
                RequestErrorClass::HttpFailure(status) => {
                    return Err(Self::status_error("PUT", filename, status));
                }
                RequestErrorClass::RequestFailure => {
                    return Err(Self::request_error("PUT", filename));
                }
            },
        }
        tracing::debug!(key = %s3_key, "Uploaded ACME credentials to S3");
        Ok(())
    }

    pub fn start_background_sync(
        self: Arc<Self>,
        cert_dir: std::path::PathBuf,
        interval: Duration,
    ) -> BackgroundGuard {
        let cancel = CancellationToken::new();
        let bg_cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = bg_cancel.cancelled() => {
                        tracing::debug!("S3 background sync stopped");
                        return;
                    }
                    _ = tokio::time::sleep(interval) => {}
                }

                if let Err(e) = self.push_from(&cert_dir).await {
                    tracing::warn!(error = %e, "S3 background sync failed");
                }
            }
        });

        BackgroundGuard::new(cancel)
    }
}

pub fn env_config() -> S3Config {
    S3Config {
        bucket_name: std::env::var("CERT_S3_BUCKET").unwrap_or_default(),
        endpoint: std::env::var("CERT_S3_ENDPOINT").unwrap_or_default(),
        access_key: std::env::var("CERT_S3_ACCESS_KEY").unwrap_or_default(),
        secret_key: std::env::var("CERT_S3_SECRET_KEY").unwrap_or_default(),
        region: std::env::var("CERT_S3_REGION").ok(),
        prefix: std::env::var("CERT_S3_PREFIX").ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::{S3CertSync, S3Config};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn config() -> S3Config {
        S3Config {
            bucket_name: "test-bucket".into(),
            endpoint: "https://endpoint-secret.example.invalid".into(),
            access_key: "access-key-secret-value".into(),
            secret_key: "secret-key-secret-value".into(),
            region: Some("test-region".into()),
            prefix: Some("test-prefix".into()),
        }
    }

    async fn serve_responses(
        listener: TcpListener,
        responses: Vec<(&'static str, &'static str, u16, &'static [u8])>,
    ) {
        tokio::time::timeout(Duration::from_secs(8), async {
            for (expected_method, expected_path, status, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                let header_end = tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        let n = stream.read(&mut chunk).await.unwrap();
                        assert!(n > 0, "client closed before sending request headers");
                        request.extend_from_slice(&chunk[..n]);
                        if let Some(end) =
                            request.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            break end + 4;
                        }
                    }
                })
                .await
                .expect("fixture request read timed out");
                let request_text = String::from_utf8_lossy(&request[..header_end]).into_owned();
                let content_length = request_text
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("valid Content-Length"))
                    })
                    .unwrap_or(0);
                tokio::time::timeout(Duration::from_secs(3), async {
                    while request.len() - header_end < content_length {
                        let n = stream.read(&mut chunk).await.unwrap();
                        assert!(n > 0, "client closed before sending request body");
                        request.extend_from_slice(&chunk[..n]);
                    }
                })
                .await
                .expect("fixture request body read timed out");
                let request = request_text;
                let mut first_line = request.lines().next().unwrap().split_whitespace();
                assert_eq!(first_line.next().unwrap(), expected_method);
                assert_eq!(first_line.next().unwrap(), expected_path);
                let response = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
            }
        })
        .await
        .expect("fixture request loop timed out");
    }

    async fn loopback_sync(listener: &TcpListener) -> S3CertSync {
        let mut config = config();
        config.endpoint = format!("http://{}", listener.local_addr().unwrap());
        S3CertSync::new(config).unwrap()
    }

    #[tokio::test]
    async fn pull_writes_private_secrets_and_public_chain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = config();
        config.endpoint = format!("http://{address}");
        let sync = S3CertSync::new(config).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("privkey.pem");
        let account_dir = dir.path().join("acme_cache");
        tokio::fs::create_dir_all(&account_dir).await.unwrap();
        let account_path = account_dir.join("acme_account_credentials.json");
        tokio::fs::write(&key_path, b"old-key").await.unwrap();
        tokio::fs::write(&account_path, b"old-account")
            .await
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
                .await
                .unwrap();
            tokio::fs::set_permissions(&account_path, std::fs::Permissions::from_mode(0o644))
                .await
                .unwrap();
        }
        let fixture = async {
            let server = tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(20), async {
                    for _ in 0..3 {
                        let (mut stream, _) = listener.accept().await.unwrap();
                        let mut request = Vec::new();
                        let mut chunk = [0u8; 1024];
                        loop {
                            let n = stream.read(&mut chunk).await.unwrap();
                            if n == 0 {
                                break;
                            }
                            request.extend_from_slice(&chunk[..n]);
                            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        let request = String::from_utf8_lossy(&request);
                        let path = request
                            .lines()
                            .next()
                            .unwrap()
                            .split_whitespace()
                            .nth(1)
                            .unwrap();
                        let body: &[u8] = match path {
                            "/test-bucket/test-prefix/fullchain.pem" => b"public-chain",
                            "/test-bucket/test-prefix/privkey.pem" => b"private-key",
                            "/test-bucket/test-prefix/acme_cache/acme_account_credentials.json" => {
                                b"account-secret"
                            }
                            unexpected => panic!("unexpected S3 request target: {unexpected}"),
                        };
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        stream.write_all(response.as_bytes()).await.unwrap();
                        stream.write_all(body).await.unwrap();
                    }
                })
                .await
                .expect("S3 fixture request I/O timed out");
            });
            let result = tokio::time::timeout(Duration::from_secs(15), sync.pull_to(dir.path()))
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(Duration::from_secs(20), server)
                .await
                .unwrap()
                .unwrap();
            result
        };
        let result = tokio::time::timeout(Duration::from_secs(35), fixture)
            .await
            .unwrap();
        assert!(result.fullchain_found && result.privkey_found);
        assert_eq!(
            tokio::fs::read(dir.path().join("fullchain.pem"))
                .await
                .unwrap(),
            b"public-chain"
        );
        assert_eq!(
            tokio::fs::read(dir.path().join("privkey.pem"))
                .await
                .unwrap(),
            b"private-key"
        );
        assert_eq!(
            tokio::fs::read(dir.path().join("acme_cache/acme_account_credentials.json"))
                .await
                .unwrap(),
            b"account-secret"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [
                dir.path().join("privkey.pem"),
                dir.path().join("acme_cache/acme_account_credentials.json"),
            ] {
                assert_eq!(
                    tokio::fs::metadata(path)
                        .await
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
    }

    #[tokio::test]
    async fn public_pull_treats_typed_404_as_absence_after_retries() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sync = loopback_sync(&listener).await;
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("missing/child");
        let server = tokio::spawn(serve_responses(
            listener,
            vec![
                (
                    "GET",
                    "/test-bucket/test-prefix/fullchain.pem",
                    404,
                    b"private diagnostic marker",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/fullchain.pem",
                    404,
                    b"private diagnostic marker",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/privkey.pem",
                    404,
                    b"private diagnostic marker",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/privkey.pem",
                    404,
                    b"private diagnostic marker",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/acme_cache/acme_account_credentials.json",
                    404,
                    b"private diagnostic marker",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/acme_cache/acme_account_credentials.json",
                    404,
                    b"private diagnostic marker",
                ),
            ],
        ));

        let result = tokio::time::timeout(Duration::from_secs(8), sync.pull_to(&child))
            .await
            .expect("pull timed out")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(8), server)
            .await
            .expect("fixture timed out")
            .unwrap();
        assert!(!result.fullchain_found && !result.privkey_found);
        assert!(!child.exists());
    }

    #[tokio::test]
    async fn public_pull_restores_complete_pair_into_missing_child() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sync = loopback_sync(&listener).await;
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("new/nested/certs");
        let server = tokio::spawn(serve_responses(
            listener,
            vec![
                (
                    "GET",
                    "/test-bucket/test-prefix/fullchain.pem",
                    200,
                    b"restored-chain",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/privkey.pem",
                    200,
                    b"restored-key",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/acme_cache/acme_account_credentials.json",
                    404,
                    b"missing",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/acme_cache/acme_account_credentials.json",
                    404,
                    b"missing",
                ),
            ],
        ));

        let result = tokio::time::timeout(Duration::from_secs(8), sync.pull_to(&child))
            .await
            .expect("pull timed out")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(8), server)
            .await
            .expect("fixture timed out")
            .unwrap();
        assert!(result.fullchain_found && result.privkey_found);
        assert_eq!(
            tokio::fs::read(child.join("fullchain.pem")).await.unwrap(),
            b"restored-chain"
        );
        assert_eq!(
            tokio::fs::read(child.join("privkey.pem")).await.unwrap(),
            b"restored-key"
        );
        assert!(!child
            .join("acme_cache/acme_account_credentials.json")
            .exists());
    }

    #[tokio::test]
    async fn public_pull_http_failure_is_sanitized_and_preserves_local_pair() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sync = loopback_sync(&listener).await;
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("fullchain.pem"), b"old-chain")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("privkey.pem"), b"old-key")
            .await
            .unwrap();
        let marker = b"private diagnostic marker";
        let server = tokio::spawn(serve_responses(
            listener,
            vec![
                ("GET", "/test-bucket/test-prefix/fullchain.pem", 403, marker),
                ("GET", "/test-bucket/test-prefix/fullchain.pem", 403, marker),
            ],
        ));

        let error = tokio::time::timeout(Duration::from_secs(8), sync.pull_to(dir.path()))
            .await
            .expect("pull timed out")
            .unwrap_err();
        tokio::time::timeout(Duration::from_secs(8), server)
            .await
            .expect("fixture timed out")
            .unwrap();
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("HTTP 403"));
        assert!(!diagnostic.contains(std::str::from_utf8(marker).unwrap()));
        assert_eq!(
            tokio::fs::read(dir.path().join("fullchain.pem"))
                .await
                .unwrap(),
            b"old-chain"
        );
        assert_eq!(
            tokio::fs::read(dir.path().join("privkey.pem"))
                .await
                .unwrap(),
            b"old-key"
        );
    }

    #[tokio::test]
    async fn account_http_failure_does_not_publish_previously_fetched_pems() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sync = loopback_sync(&listener).await;
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(dir.path().join("acme_cache"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("fullchain.pem"), b"old-chain")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("privkey.pem"), b"old-key")
            .await
            .unwrap();
        let account_path = dir.path().join("acme_cache/acme_account_credentials.json");
        tokio::fs::write(&account_path, b"old-account")
            .await
            .unwrap();
        let marker = b"private account diagnostic marker";
        let server = tokio::spawn(serve_responses(
            listener,
            vec![
                (
                    "GET",
                    "/test-bucket/test-prefix/fullchain.pem",
                    200,
                    b"new-chain",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/privkey.pem",
                    200,
                    b"new-key",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/acme_cache/acme_account_credentials.json",
                    503,
                    marker,
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/acme_cache/acme_account_credentials.json",
                    503,
                    marker,
                ),
            ],
        ));

        let error = tokio::time::timeout(Duration::from_secs(8), sync.pull_to(dir.path()))
            .await
            .expect("pull timed out")
            .unwrap_err();
        tokio::time::timeout(Duration::from_secs(8), server)
            .await
            .expect("fixture timed out")
            .unwrap();
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("HTTP 503"));
        assert!(diagnostic.contains("GET"));
        assert!(diagnostic.contains("acme_account_credentials.json"));
        assert!(!diagnostic.contains(std::str::from_utf8(marker).unwrap()));
        assert_eq!(
            tokio::fs::read(dir.path().join("fullchain.pem"))
                .await
                .unwrap(),
            b"old-chain"
        );
        assert_eq!(
            tokio::fs::read(dir.path().join("privkey.pem"))
                .await
                .unwrap(),
            b"old-key"
        );
        assert_eq!(tokio::fs::read(account_path).await.unwrap(), b"old-account");
    }

    #[tokio::test]
    async fn incomplete_remote_pair_preserves_pems_but_restores_account() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sync = loopback_sync(&listener).await;
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(dir.path().join("acme_cache"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("fullchain.pem"), b"old-chain")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("privkey.pem"), b"old-key")
            .await
            .unwrap();
        let account_path = dir.path().join("acme_cache/acme_account_credentials.json");
        tokio::fs::write(&account_path, b"old-account")
            .await
            .unwrap();
        let server = tokio::spawn(serve_responses(
            listener,
            vec![
                (
                    "GET",
                    "/test-bucket/test-prefix/fullchain.pem",
                    200,
                    b"new-chain",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/privkey.pem",
                    404,
                    b"missing",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/privkey.pem",
                    404,
                    b"missing",
                ),
                (
                    "GET",
                    "/test-bucket/test-prefix/acme_cache/acme_account_credentials.json",
                    200,
                    b"new-account",
                ),
            ],
        ));

        let result = tokio::time::timeout(Duration::from_secs(8), sync.pull_to(dir.path()))
            .await
            .expect("pull timed out")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(8), server)
            .await
            .expect("fixture timed out")
            .unwrap();
        assert!(!result.fullchain_found && !result.privkey_found);
        assert_eq!(
            tokio::fs::read(dir.path().join("fullchain.pem"))
                .await
                .unwrap(),
            b"old-chain"
        );
        assert_eq!(
            tokio::fs::read(dir.path().join("privkey.pem"))
                .await
                .unwrap(),
            b"old-key"
        );
        assert_eq!(tokio::fs::read(account_path).await.unwrap(), b"new-account");
    }

    #[tokio::test]
    async fn push_from_reports_bad_status_and_accepts_success() {
        for (status, expected_error) in [(403, true), (200, false)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let sync = loopback_sync(&listener).await;
            let dir = tempfile::tempdir().unwrap();
            tokio::fs::write(dir.path().join("fullchain.pem"), b"chain")
                .await
                .unwrap();
            let mut responses: Vec<(&str, &str, u16, &[u8])> = vec![(
                "PUT",
                "/test-bucket/test-prefix/fullchain.pem",
                status,
                b"private diagnostic marker",
            )];
            if status == 403 {
                responses.push((
                    "PUT",
                    "/test-bucket/test-prefix/fullchain.pem",
                    status,
                    b"private diagnostic marker",
                ));
            }
            let server = tokio::spawn(serve_responses(listener, responses));
            let result = tokio::time::timeout(Duration::from_secs(8), sync.push_from(dir.path()))
                .await
                .expect("push_from timed out");
            tokio::time::timeout(Duration::from_secs(8), server)
                .await
                .expect("fixture timed out")
                .unwrap();
            assert_eq!(result.is_err(), expected_error);
            if let Err(error) = result {
                assert!(error.to_string().contains("HTTP 403"));
                assert!(!error.to_string().contains("private diagnostic marker"));
            }
        }
    }

    #[tokio::test]
    async fn push_credentials_only_reports_bad_status_and_accepts_success() {
        for (status, expected_error) in [(403, true), (200, false)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let sync = loopback_sync(&listener).await;
            let dir = tempfile::tempdir().unwrap();
            tokio::fs::create_dir_all(dir.path().join("acme_cache"))
                .await
                .unwrap();
            tokio::fs::write(
                dir.path().join("acme_cache/acme_account_credentials.json"),
                b"account credentials",
            )
            .await
            .unwrap();
            let mut responses: Vec<(&str, &str, u16, &[u8])> = vec![(
                "PUT",
                "/test-bucket/test-prefix/acme_cache/acme_account_credentials.json",
                status,
                b"private diagnostic marker",
            )];
            if status == 403 {
                responses.push((
                    "PUT",
                    "/test-bucket/test-prefix/acme_cache/acme_account_credentials.json",
                    status,
                    b"private diagnostic marker",
                ));
            }
            let server = tokio::spawn(serve_responses(listener, responses));
            let result = tokio::time::timeout(
                Duration::from_secs(8),
                sync.push_credentials_only(dir.path()),
            )
            .await
            .expect("push_credentials_only timed out");
            tokio::time::timeout(Duration::from_secs(8), server)
                .await
                .expect("fixture timed out")
                .unwrap();
            assert_eq!(result.is_err(), expected_error);
            if let Err(error) = result {
                assert!(error.to_string().contains("HTTP 403"));
                assert!(!error.to_string().contains("private diagnostic marker"));
            }
        }
    }

    #[test]
    fn s3_debug_output_redacts_credentials_and_endpoint() {
        let config = config();
        let sync = S3CertSync::new(config.clone()).expect("dummy S3 config is constructible");

        for debug in [format!("{config:?}"), format!("{sync:?}")] {
            for secret in [
                "endpoint-secret.example.invalid",
                "access-key-secret-value",
                "secret-key-secret-value",
            ] {
                assert!(!debug.contains(secret), "debug output leaked {secret}");
            }
            assert!(debug.contains("<redacted>"));
        }
    }

    #[test]
    fn status_classifier_accepts_only_success_and_treats_404_as_absence() {
        use super::{S3CertSync, StatusClass};

        assert_eq!(S3CertSync::classify_status(200), StatusClass::Success);
        assert_eq!(S3CertSync::classify_status(299), StatusClass::Success);
        assert_eq!(S3CertSync::classify_status(404), StatusClass::NotFound);
        assert_eq!(S3CertSync::classify_status(403), StatusClass::Failure(403));
        assert_eq!(S3CertSync::classify_status(503), StatusClass::Failure(503));
    }

    #[test]
    fn typed_http_failures_are_classified_without_exposing_response_body() {
        use super::{RequestErrorClass, S3CertSync};
        use s3::error::S3Error;

        let missing = S3Error::HttpFailWithBody(404, "private response body".into());
        let forbidden = S3Error::HttpFailWithBody(403, "private response body".into());
        assert_eq!(
            S3CertSync::classify_request_error(&missing),
            RequestErrorClass::NotFound
        );
        assert_eq!(
            S3CertSync::classify_request_error(&forbidden),
            RequestErrorClass::HttpFailure(403)
        );

        let error = S3CertSync::status_error("GET", "privkey.pem", 403);
        let rendered = error.to_string();
        assert!(rendered.contains("GET failed for privkey.pem (HTTP 403)"));
        assert!(!rendered.contains("private response body"));
    }
}
