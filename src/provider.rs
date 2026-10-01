#[cfg(feature = "tokio-acme")]
pub mod tokio_acme;
#[cfg(feature = "rfc8555")]
pub mod rfc8555;
#[cfg(feature = "dns01")]
pub mod dns01;
#[cfg(feature = "s3-sync")]
pub mod s3;

use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(any(feature = "tokio-acme", feature = "s3-sync"))]
use tokio_util::sync::CancellationToken;
use crate::error::Result;

#[async_trait]
pub trait CertProvider: Send + Sync + 'static {
    /// Prepare the certificate directory, obtain or renew certs if needed.
    /// `cert_dir` – path where PEM files will be written (e.g. `/certs`).
    /// `domains` – list of domains to request (e.g. `["example.com"]`); `None` = default.
    /// Returns a `BackgroundGuard` that stops renewal on drop.
    async fn init(
        &mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard>;
}

/// Opaque handle – keep it alive for the process lifetime.
pub struct BackgroundGuard {
    #[cfg(any(feature = "tokio-acme", feature = "s3-sync"))]
    cancel: Option<CancellationToken>,
    stop: Option<Arc<AtomicBool>>,
    #[cfg(feature = "dns01")]
    notify: Option<Arc<nagoya::sync::Notify>>,
}

#[allow(dead_code)]
impl BackgroundGuard {
    #[cfg(any(feature = "tokio-acme", feature = "s3-sync"))]
    pub(crate) fn new(cancel: CancellationToken) -> Self {
        Self {
            cancel: Some(cancel),
            stop: None,
            #[cfg(feature = "dns01")]
            notify: None,
        }
    }

    #[cfg(feature = "dns01")]
    pub(crate) fn with_atomic_cancel(
        stop: Arc<AtomicBool>,
        notify: Arc<nagoya::sync::Notify>,
    ) -> Self {
        Self {
            #[cfg(any(feature = "tokio-acme", feature = "s3-sync"))]
            cancel: None,
            stop: Some(stop),
            #[cfg(feature = "dns01")]
            notify: Some(notify),
        }
    }
}

impl Drop for BackgroundGuard {
    fn drop(&mut self) {
        #[cfg(any(feature = "tokio-acme", feature = "s3-sync"))]
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        if let Some(stop) = &self.stop {
            stop.store(true, Ordering::Release);
        }
        #[cfg(feature = "dns01")]
        if let Some(notify) = &self.notify {
            notify.notify_waiters();
        }
    }
}
