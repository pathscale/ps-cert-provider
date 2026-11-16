use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::error::Result;
use crate::provider::{BackgroundGuard, CertProvider};
use crate::s3_sync::S3CertSync;

const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(300);

pub struct S3CertProvider<C: CertProvider> {
    inner: C,
    s3_sync: Arc<S3CertSync>,
    sync_interval: Duration,
}

#[cfg(test)]
mod tests {
    use super::S3CertProvider;
    use crate::error::Result;
    use crate::provider::{BackgroundGuard, CertProvider};
    use crate::s3_sync::{S3CertSync, S3Config};
    use async_trait::async_trait;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    struct CountingProvider(Arc<AtomicUsize>, CancellationToken);

    #[async_trait]
    impl CertProvider for CountingProvider {
        async fn init(
            &mut self,
            _cert_dir: PathBuf,
            _domains: Option<Vec<String>>,
        ) -> Result<BackgroundGuard> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(BackgroundGuard::new(self.1.clone()))
        }
    }

    async fn serve_responses(
        listener: TcpListener,
        responses: Vec<(&'static str, u16, &'static [u8])>,
    ) {
        tokio::time::timeout(Duration::from_secs(8), async {
            for (expected_path, status, body) in responses {
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
                assert_eq!(first_line.next().unwrap(), "GET");
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

    fn config(endpoint: String) -> S3Config {
        S3Config {
            bucket_name: "test-bucket".into(),
            endpoint,
            access_key: "test-access".into(),
            secret_key: "test-secret".into(),
            region: Some("test-region".into()),
            prefix: None,
        }
    }

    #[tokio::test]
    async fn restore_error_prevents_inner_provider_call_and_returns_sanitized_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(serve_responses(
            listener,
            vec![
                (
                    "/test-bucket/fullchain.pem",
                    403,
                    b"private diagnostic marker",
                ),
                (
                    "/test-bucket/fullchain.pem",
                    403,
                    b"private diagnostic marker",
                ),
            ],
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingProvider(calls.clone(), CancellationToken::new());
        let sync = S3CertSync::new(config(endpoint)).unwrap();
        let mut provider = S3CertProvider::new(inner, sync);
        let dir = tempfile::tempdir().unwrap();

        let result = tokio::time::timeout(
            Duration::from_secs(8),
            provider.init(dir.path().to_path_buf(), None),
        )
        .await
        .expect("provider init timed out");
        let error = match result {
            Ok(_) => panic!("provider init unexpectedly succeeded"),
            Err(error) => error,
        };
        tokio::time::timeout(Duration::from_secs(8), server)
            .await
            .expect("fixture timed out")
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(error.to_string().contains("HTTP 403"));
        assert!(!error.to_string().contains("private diagnostic marker"));
    }

    #[tokio::test]
    async fn all_typed_404_misses_reach_inner_provider_after_retries() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(serve_responses(
            listener,
            vec![
                ("/test-bucket/fullchain.pem", 404, b"missing"),
                ("/test-bucket/fullchain.pem", 404, b"missing"),
                ("/test-bucket/privkey.pem", 404, b"missing"),
                ("/test-bucket/privkey.pem", 404, b"missing"),
                (
                    "/test-bucket/acme_cache/acme_account_credentials.json",
                    404,
                    b"missing",
                ),
                (
                    "/test-bucket/acme_cache/acme_account_credentials.json",
                    404,
                    b"missing",
                ),
            ],
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        let inner_cancel = CancellationToken::new();
        let inner = CountingProvider(calls.clone(), inner_cancel.clone());
        let sync = S3CertSync::new(config(endpoint)).unwrap();
        let mut provider = S3CertProvider::new(inner, sync);
        let dir = tempfile::tempdir().unwrap();

        let guard = tokio::time::timeout(
            Duration::from_secs(8),
            provider.init(dir.path().to_path_buf(), None),
        )
        .await
        .expect("provider init timed out")
        .unwrap();
        tokio::time::timeout(Duration::from_secs(8), server)
            .await
            .expect("fixture timed out")
            .unwrap();
        drop(guard);
        tokio::time::timeout(Duration::from_secs(8), inner_cancel.cancelled())
            .await
            .expect("inner provider guard cancellation was not observed");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

impl<C: CertProvider> S3CertProvider<C> {
    pub fn new(inner: C, s3_sync: S3CertSync) -> Self {
        Self {
            inner,
            s3_sync: Arc::new(s3_sync),
            sync_interval: DEFAULT_SYNC_INTERVAL,
        }
    }

    pub fn from_arc(inner: C, s3_sync: Arc<S3CertSync>) -> Self {
        Self {
            inner,
            s3_sync,
            sync_interval: DEFAULT_SYNC_INTERVAL,
        }
    }

    pub fn sync_interval(mut self, interval: Duration) -> Self {
        self.sync_interval = interval;
        self
    }
}

#[async_trait]
impl<C: CertProvider> CertProvider for S3CertProvider<C> {
    async fn init(
        &mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard> {
        tokio::fs::create_dir_all(&cert_dir).await?;

        let pull_result = self.s3_sync.pull_to(&cert_dir).await?;
        let certs_pulled_from_s3 = pull_result.fullchain_found && pull_result.privkey_found;

        let init_result = self.inner.init(cert_dir.clone(), domains).await;

        // Push credentials to S3 to ensure ACME account survives restarts.
        // Only newly created credentials are pushed; cert files pulled from S3
        // are not re-uploaded (redundant).
        if let Err(e) = self.s3_sync.push_credentials_only(&cert_dir).await {
            tracing::debug!(error = %e, "Failed to push credentials to S3");
        }

        let inner_guard = init_result?;

        // Push cert files only if they were newly created/issued, not if they were
        // pulled from S3. If certs were in S3, they're already backed up. If certs
        // are renewed later, the background loop will sync them.
        if !certs_pulled_from_s3 {
            self.s3_sync.push_from(&cert_dir).await?;
        }

        let stop_token = CancellationToken::new();
        let bg_stop = stop_token.clone();
        let bg_sync = self.s3_sync.clone();
        let bg_dir = cert_dir;
        let interval = self.sync_interval;

        let inner = Arc::new(std::sync::Mutex::new(Some(inner_guard)));
        let bg_inner = inner.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = bg_stop.cancelled() => break,
                    _ = tokio::time::sleep(interval) => {}
                }
                if let Err(e) = bg_sync.push_from(&bg_dir).await {
                    tracing::debug!(error = %e, "S3 background sync failed");
                }
            }

            if let Some(guard) = bg_inner.lock().unwrap().take() {
                drop(guard);
            }
        });

        Ok(BackgroundGuard::new(stop_token))
    }
}
