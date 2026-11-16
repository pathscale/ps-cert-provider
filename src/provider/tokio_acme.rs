use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::Stream;
use futures::TryStreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls_acme::{caches::DirCache, AccountCache, AcmeConfig, CertCache};
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};
use crate::provider::{BackgroundGuard, CertProvider};
use crate::secret_file::write_secret;

const CHALLENGE_TIMEOUT_SECS: u64 = 5 * 60;

// ---------------------------------------------------------------------------
// TCP stream adapter
// ---------------------------------------------------------------------------

struct ListenerStream {
    listener: TcpListener,
}

impl Stream for ListenerStream {
    type Item = std::result::Result<TcpStream, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.listener.poll_accept(cx) {
            Poll::Ready(Ok((socket, _))) => Poll::Ready(Some(Ok(socket))),
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// PEM-writing cache wrapper
// ---------------------------------------------------------------------------

/// Wraps `DirCache` and additionally writes standard `privkey.pem` / `fullchain.pem`
/// files whenever a certificate is stored or loaded from the ACME cache.
struct PemWritingCache {
    dir_cache: DirCache<PathBuf>,
    cert_dir: PathBuf,
    cert_ready: Arc<Notify>,
}

impl PemWritingCache {
    fn new(cache_dir: PathBuf, cert_dir: PathBuf, cert_ready: Arc<Notify>) -> Self {
        Self {
            dir_cache: DirCache::new(cache_dir),
            cert_dir,
            cert_ready,
        }
    }

    async fn write_pem_files(&self, pem: &[u8]) -> std::io::Result<()> {
        let (privkey, chain) = split_pem(pem).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ACME cert PEM did not contain a CERTIFICATE block",
            )
        })?;
        write_secret(&self.cert_dir.join("privkey.pem"), &privkey).await?;
        tokio::fs::write(self.cert_dir.join("fullchain.pem"), chain).await?;
        Ok(())
    }
}

#[async_trait]
impl CertCache for PemWritingCache {
    type EC = std::io::Error;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> std::result::Result<Option<Vec<u8>>, Self::EC> {
        let result = self.dir_cache.load_cert(domains, directory_url).await?;
        if let Some(pem) = &result {
            // Cert already cached from a previous run – write PEM files and signal immediately.
            self.write_pem_files(pem).await?;
            self.cert_ready.notify_one();
        }
        Ok(result)
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> std::result::Result<(), Self::EC> {
        self.dir_cache
            .store_cert(domains, directory_url, cert)
            .await?;
        self.write_pem_files(cert).await?;
        self.cert_ready.notify_one();
        Ok(())
    }
}

#[async_trait]
impl AccountCache for PemWritingCache {
    type EA = std::io::Error;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> std::result::Result<Option<Vec<u8>>, Self::EA> {
        self.dir_cache.load_account(contact, directory_url).await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> std::result::Result<(), Self::EA> {
        self.dir_cache
            .store_account(contact, directory_url, account)
            .await
    }
}

/// Split the combined PEM blob produced by tokio-rustls-acme into
/// `(privkey_pem, fullchain_pem)`.
///
/// The blob layout is: `<PKCS8 private key PEM>\n<leaf cert PEM>\n[<intermediate PEM>…]`.
fn split_pem(pem: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let text = std::str::from_utf8(pem).ok()?;
    let chain_start = text.find("-----BEGIN CERTIFICATE-----")?;
    let privkey = text[..chain_start].trim_end().as_bytes().to_vec();
    let chain = text[chain_start..].as_bytes().to_vec();
    Some((privkey, chain))
}

#[cfg(test)]
mod tests {
    use super::PemWritingCache;
    use std::sync::Arc;
    use tokio::sync::Notify;

    #[tokio::test]
    async fn pem_export_keeps_chain_and_restricts_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PemWritingCache::new(
            dir.path().join("cache"),
            dir.path().to_owned(),
            Arc::new(Notify::new()),
        );
        let key_path = dir.path().join("privkey.pem");
        tokio::fs::write(&key_path, b"stale-key").await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
                .await
                .unwrap();
        }
        let pem = b"-----BEGIN PRIVATE KEY-----\nsynthetic-key\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nsynthetic-cert\n-----END CERTIFICATE-----\n";
        cache.write_pem_files(pem).await.unwrap();
        assert_eq!(
            tokio::fs::read(dir.path().join("privkey.pem"))
                .await
                .unwrap(),
            b"-----BEGIN PRIVATE KEY-----\nsynthetic-key\n-----END PRIVATE KEY-----"
        );
        assert_eq!(
            tokio::fs::read(dir.path().join("fullchain.pem"))
                .await
                .unwrap(),
            b"-----BEGIN CERTIFICATE-----\nsynthetic-cert\n-----END CERTIFICATE-----\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                tokio::fs::metadata(dir.path().join("privkey.pem"))
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

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// ACME provider backed by [`tokio-rustls-acme`] using TLS-ALPN-01 challenges.
///
/// Binds a TCP listener on [`port`] (default `443`). Let's Encrypt's validation
/// servers must reach that port on your domain. On fly.io this is the
/// `internal_port` for a service with `handlers = []` (raw TCP passthrough).
///
/// `init()` blocks until the certificate is issued or loaded from cache, then
/// returns. `fullchain.pem` and `privkey.pem` are written to `cert_dir`. The
/// returned [`BackgroundGuard`] keeps the ACME renewal loop alive.
///
/// # Staging vs production
///
/// The default constructor uses the Let's Encrypt **staging** environment so
/// that testing never hits production rate limits. Call `.production()` before
/// deploying for real.
#[derive(Clone)]
pub struct TokioAcmeProvider {
    contact_email: String,
    port: u16,
    production: bool,
}

impl TokioAcmeProvider {
    /// Create a provider pointed at the Let's Encrypt **staging** environment.
    pub fn new(contact_email: impl Into<String>) -> Self {
        Self {
            contact_email: contact_email.into(),
            port: 443,
            production: false,
        }
    }

    /// Switch to the Let's Encrypt **production** directory.
    ///
    /// Production certificates are browser-trusted but strictly rate-limited.
    pub fn production(mut self) -> Self {
        self.production = true;
        self
    }

    /// Override the port the ACME TLS-ALPN-01 listener binds on (default `443`).
    ///
    /// On fly.io with TCP passthrough, this should match the `internal_port`
    /// value in your `fly.toml` service block for port 443.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
}

#[async_trait]
impl CertProvider for TokioAcmeProvider {
    async fn init(
        &mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard> {
        let domains = domains.ok_or_else(|| Error::Config("domains required".into()))?;
        if domains.is_empty() {
            return Err(Error::Config("at least one domain required".into()));
        }

        tokio::fs::create_dir_all(&cert_dir).await?;
        let cache_dir = cert_dir.join("acme_cache");
        tokio::fs::create_dir_all(&cache_dir).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o700)).await?;
        }

        // The notify fires as soon as a cert is available (cached or freshly issued).
        let cert_ready = Arc::new(Notify::new());
        let cache = PemWritingCache::new(cache_dir, cert_dir.clone(), cert_ready.clone());

        let config = AcmeConfig::new(domains.clone())
            .contact_push(format!("mailto:{}", self.contact_email))
            .directory_lets_encrypt(self.production)
            .cache_with_boxed_err(cache);

        let listener = TcpListener::bind(("0.0.0.0", self.port))
            .await
            .map_err(|e| {
                Error::Config(format!(
                    "ACME: failed to bind 0.0.0.0:{}: {}. \
                 Ensure the port is not already in use and the process has permission.",
                    self.port, e
                ))
            })?;
        tracing::debug!("ACME TLS-ALPN-01 listener bound on 0.0.0.0:{}", self.port);

        let stream = ListenerStream { listener };
        let mut tls_incoming = config.incoming(stream, Vec::new());

        let cancel = CancellationToken::new();
        let bg_cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = bg_cancel.cancelled() => {
                        tracing::debug!("ACME renewal loop stopped");
                        return;
                    }
                    next = tls_incoming.try_next() => {
                        match next {
                            Ok(Some(_tls)) => {
                                // A non-ACME TLS connection arrived (e.g. a browser hit port 443).
                                // We drop it here; the application TLS server runs on a separate port.
                            }
                            Ok(None) => {
                                tracing::debug!("ACME TLS stream closed unexpectedly");
                                return;
                            }
                            Err(e) => {
                                tracing::debug!("ACME listener error: {}", e);
                            }
                        }
                    }
                }
            }
        });

        // Wait for the first certificate to be ready.
        // If a cached cert exists it is available almost immediately.
        // A fresh issuance requires Let's Encrypt to connect and validate – typically < 30 s.
        tokio::time::timeout(
            Duration::from_secs(CHALLENGE_TIMEOUT_SECS),
            cert_ready.notified(),
        )
        .await
        .map_err(|_| {
            Error::Challenge(format!(
                "Timed out after {CHALLENGE_TIMEOUT_SECS}s waiting for ACME certificate. \
                 Check that port {} is publicly reachable on the domain and that DNS is correct.",
                self.port
            ))
        })?;

        tracing::info!("ACME certificate ready – files written to {:?}", cert_dir);
        Ok(BackgroundGuard::new(cancel))
    }
}
