mod error;
pub mod provider;
#[cfg(feature = "s3-sync")]
pub mod s3_sync;
#[cfg(any(feature = "dns01", feature = "tokio-acme", feature = "s3-sync"))]
mod secret_file;

pub use error::Error;
#[cfg(feature = "s3-sync")]
pub use provider::s3::S3CertProvider;
pub use provider::{BackgroundGuard, CertProvider};
