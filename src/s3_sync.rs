use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use awscreds::Credentials;
use awsregion::Region;
use s3::Bucket;
use tokio_util::sync::CancellationToken;

use crate::error::Result;
use crate::provider::BackgroundGuard;

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

impl S3CertSync {
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

    pub async fn pull_to(&self, cert_dir: &Path) -> Result<PullResult> {
        let filenames = [
            "fullchain.pem",
            "privkey.pem",
            "acme_cache/acme_account_credentials.json",
        ];
        let mut result = PullResult::default();
        for name in &filenames {
            let s3_key = self.s3_key(name);
            match self.bucket.get_object(&s3_key).await {
                Ok(content) => {
                    let path = cert_dir.join(name);
                    if let Some(parent) = path.parent() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                    tokio::fs::write(&path, content.to_vec()).await?;
                    tracing::debug!(path = %path.display(), "Downloaded cert file from S3");
                    if *name == "fullchain.pem" {
                        result.fullchain_found = true;
                    } else if *name == "privkey.pem" {
                        result.privkey_found = true;
                    }
                }
                Err(e) => {
                    tracing::debug!(key = %s3_key, error = %e, "Cert file not found in S3");
                }
            }
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
            self.bucket.put_object(&s3_key, &content).await?;
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
        self.bucket.put_object(&s3_key, &content).await?;
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
}
