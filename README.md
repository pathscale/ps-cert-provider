# ps-cert-provider

`ps-cert-provider` is a Rust library crate that provides a unified, async interface for automatic TLS certificate provisioning and renewal using the ACME protocol. It abstracts over two popular ACME backends, allowing you to embed "certbot-like" functionality entirely within your application.

The crate guarantees that valid certificate and key files are present in a given directory before your TLS server starts, and keeps them renewed for as long as you hold onto the returned guard.

---

## Features

- **Three backends** (selectable via Cargo features):
  - `tokio-acme` – backed by [`tokio-rustls-acme`], uses `TLS-ALPN-01` challenges. Requires port 443 to be publicly reachable.
  - `rfc8555` – backed by [`acme-rfc8555`], uses `HTTP-01` challenges. Requires port 80 to be publicly reachable.
  - `dns01` – implements ACME over [`nago-http`] and uses `DNS-01` challenges. Requires DNS API access (bring your own DNS provider impl).
- **S3 / R2 sync** (optional `s3-sync` feature) – pull certs from S3-compatible storage on startup, push after issuance, and periodically upload renewed certs.
- **Uniform API** – all backends implement the `CertProvider` trait.
- **Persistent caching** – ACME account keys and certs survive restarts, avoiding rate-limit issues.
- **Background renewal** – a spawned task renews certificates automatically before expiry.
- **Minimal intrusion** – you own your TLS server; this crate only writes PEM files and returns a guard.

---

## Installation

```toml
[dependencies]
cert-provider = { package = "ps-cert-provider", version = "0.1", features = ["tokio-acme"] }
# or
cert-provider = { package = "ps-cert-provider", version = "0.1", features = ["rfc8555"] }
# or
cert-provider = { package = "ps-cert-provider", version = "0.1", features = ["dns01"] }
# or (with S3 sync)
cert-provider = { package = "ps-cert-provider", version = "0.1", features = ["dns01", "s3-sync"] }
```

The `dns01` feature uses nagoya and nago-http and does not enable Tokio. Check
the dependency tree with `cargo tree -e features -i tokio --features dns01`;
it should be empty. The separate `s3-sync`, `tokio-acme`, and `rfc8555`
features keep their own runtime dependencies.

---

## Quick Start

```rust
use std::path::PathBuf;
use cert_provider::provider::CertProvider;
use cert_provider::provider::tokio_acme::TokioAcmeProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut provider: Box<dyn CertProvider> = Box::new(
        TokioAcmeProvider::new("admin@example.com")
            .production()          // omit during testing to use LE staging
            .with_port(443),       // must be publicly reachable from Let's Encrypt
    );

    // Blocks until fullchain.pem and privkey.pem are written to cert_dir.
    // On first run this takes ~10-30 s for ACME issuance.
    // On subsequent runs the cached cert loads in milliseconds.
    let _guard = provider.init(
        PathBuf::from("/data/certs"),
        Some(vec!["myapp.example.com".into()]),
    ).await?;

    // Load the PEM files and start your TLS server.
    // Keep _guard alive for the process lifetime – dropping it stops renewal.
    run_server("/data/certs").await
}
```

---

## Provider Details & Port Requirements

### `tokio-acme` — TLS-ALPN-01

- **How it works:** The provider binds a TCP listener on `port` (default `443`) and serves TLS-ALPN-01 challenge responses. Let's Encrypt connects to your domain on **port 443** to validate ownership. Once validated, the certificate is written to `cert_dir` and the listener stays alive in the background for renewals.
- **Required external port:** `443` must be publicly reachable.
- **App TLS port:** Your application's TLS server must bind on a **separate** port (e.g., `8080`) using the cert files written by this provider. The provider holds port 443 for ACME.

```rust
let mut provider = TokioAcmeProvider::new("admin@example.com")
    .production()
    .with_port(443);   // cert-provider occupies this port

let _guard = provider.init(cert_dir.clone(), Some(domains)).await?;

// Now start your TLS server on a different port using the written cert files.
let tls_listener = TcpListener::bind("0.0.0.0:8080").await?;
```

### `rfc8555` — HTTP-01

- **How it works:** The provider starts a temporary HTTP server on port 80 to answer ACME challenges, then shuts it down after the certificate is issued. The certificate is written to `cert_dir`.
- **Required external port:** `80` must be publicly reachable during issuance and renewal.
- **App TLS port:** Your application's TLS server can bind on any port (typically `443`) independently.

> **Staging:** The default constructor for both providers uses the Let's Encrypt **staging** environment. Call `.production()` only when deploying for real. Staging certs are not browser-trusted but are subject to much looser rate limits.

---

## Deployment on Fly.io (TCP passthrough)

Because `cert-provider` handles TLS itself, Fly must forward raw TCP to your app without terminating TLS at the edge. Set `handlers = []` on the relevant service ports.

> **Custom domain required.** `*.fly.dev` subdomains are not valid for Let's Encrypt certificate issuance via TCP passthrough. Allocate a dedicated IPv4 (`fly ips allocate-v4`) and point your custom domain's A record at it.

### `tokio-acme` – ACME on 443, app on a separate port

The provider occupies port 443 for TLS-ALPN-01 validation. The app TLS server runs on a separate internal port (here `8080`) and loads the cert files written by the provider.

```toml
# fly.toml

app = "my-app"
primary_region = "lhr"

# ── ACME TLS-ALPN-01 listener (cert-provider) ─────────────────────────────────
# Let's Encrypt validates your domain by connecting here.
# Must stay alive (min_machines_running = 1) so renewals work.
[[services]]
  internal_port = 443            # matches TokioAcmeProvider::with_port(443)
  protocol      = "tcp"
  auto_stop_machines   = "stop"
  auto_start_machines  = true
  min_machines_running = 1

  [[services.ports]]
    port     = 443
    handlers = []                # raw TCP – no Fly TLS termination

# ── App TLS server (your application) ─────────────────────────────────────────
# Loads fullchain.pem / privkey.pem written by cert-provider.
[[services]]
  internal_port = 8080           # your app binds here
  protocol      = "tcp"
  auto_stop_machines  = "stop"
  auto_start_machines = true

  [[services.ports]]
    port     = 8080
    handlers = []                # raw TCP passthrough; app does its own TLS
```

Corresponding Rust setup:

```rust
// cert-provider occupies port 443 for ACME.
let mut provider = TokioAcmeProvider::new("admin@example.com")
    .production()
    .with_port(443);

let _guard = provider.init(
    PathBuf::from("/data/certs"),
    Some(vec!["myapp.example.com".into()]),
).await?;

// App TLS server on port 8080 using cert files.
let certs  = load_certs("/data/certs/fullchain.pem")?;
let key    = load_key("/data/certs/privkey.pem")?;
let tls_config = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
let listener = TcpListener::bind("0.0.0.0:8080").await?;
// ... accept and handle TLS connections
```

### `rfc8555` – HTTP-01 challenge, app TLS on 443

HTTP-01 only needs port 80 for validation, so the app's TLS server can run on the standard port 443 independently.

```toml
# fly.toml

app = "my-app"
primary_region = "lhr"

# ── App TLS server (your application) ─────────────────────────────────────────
[[services]]
  internal_port = 443
  protocol      = "tcp"
  auto_stop_machines   = "stop"
  auto_start_machines  = true
  min_machines_running = 1

  [[services.ports]]
    port     = 443
    handlers = []

# ── HTTP-01 ACME challenge server (cert-provider) ─────────────────────────────
# Only active during issuance and renewal. Must be publicly reachable.
[[services]]
  internal_port = 80
  protocol      = "tcp"
  auto_stop_machines  = "stop"
  auto_start_machines = true

  [[services.ports]]
    port     = 80
    handlers = []
```

### `dns01` – DNS-01 challenge, bring-your-own DNS provider

DNS-01 uses domain control via DNS TXT records. Useful when you cannot expose port 443 or 80 (e.g., shared hosting, Fly.io without dedicated IPv4). Requires programmatic access to your DNS provider.

You can implement the `DnsProvider` trait (add TXT / remove TXT records) for your DNS service. A ready-made `BunnyDns` implementation for bunny.net DNS is included.

```rust
use std::path::PathBuf;
use cert_provider::provider::CertProvider;
use cert_provider::provider::dns01::{DnsAcmeProvider, BunnyDns};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dns = BunnyDns::new(std::env::var("BUNNY_API_KEY")?);
    let mut provider = DnsAcmeProvider::new("admin@example.com", dns)
        .production()
        .propagation_secs(90);   // adjust for your DNS provider's TTL

    let _guard = provider.init(
        PathBuf::from("/data/certs"),
        Some(vec!["myapp.example.com".into()]),
    ).await?;

    // App TLS server runs on any port (typically 443 or 8080)
    run_server("/data/certs").await
}
```

**Bring your own DNS provider:**

```rust
use async_trait::async_trait;
use cert_provider::provider::dns01::DnsProvider;

struct MyDnsProvider { /* ... */ }

#[async_trait]
impl DnsProvider for MyDnsProvider {
    async fn add_txt_record(&self, fqdn: &str, value: &str) -> Result<()> {
        // POST TXT record to your DNS API
        Ok(())
    }

    async fn remove_txt_record(&self, fqdn: &str, value: &str) -> Result<()> {
        // DELETE TXT record from your DNS API
        Ok(())
    }
}
```

On fly.io, DNS-01 doesn't require a dedicated IPv4 – it works with shared IPs via your custom domain's DNS:

```toml
# fly.toml – DNS-01 does not require port 443 listener

app = "my-app"
primary_region = "sjc"

[[services]]
  internal_port = 443
  protocol      = "tcp"
  auto_stop_machines   = "stop"
  auto_start_machines  = true

  [[services.ports]]
    port     = 443
    handlers = []
```

---

## S3 / R2 Sync (`s3-sync` feature)

The `s3-sync` feature enables pulling certificates from S3-compatible storage (AWS S3, Cloudflare R2, MinIO, etc.) before ACME issuance, pushing after issuance, and keeping renewed certs synced.

### API

Two layers are provided:

**Low-level** – `S3CertSync` for direct pull/push control:

```rust
use cert_provider::s3_sync::{S3CertSync, S3Config};

let sync = S3CertSync::new(S3Config {
    bucket_name: env("CERT_S3_BUCKET"),
    endpoint:    env("CERT_S3_ENDPOINT"),
    access_key:  env("CERT_S3_ACCESS_KEY"),
    secret_key:  env("CERT_S3_SECRET_KEY"),
    region:      None,                          // "auto" when None
    prefix:      Some("certs".into()),          // optional key prefix
})?;

sync.pull_to(&cert_dir).await?;   // download fullchain.pem + privkey.pem
sync.push_from(&cert_dir).await?; // upload fullchain.pem + privkey.pem

// Periodic background sync for renewals:
let _bg = sync.start_background_sync(cert_dir, Duration::from_secs(300));
```

**High-level wrapper** – `S3CertProvider<C>` decorates any `CertProvider`:

```rust
use cert_provider::S3CertProvider;
use cert_provider::s3_sync::{S3CertSync, S3Config};

let sync = S3CertSync::new(s3_config)?;
let mut provider = S3CertProvider::new(
    DnsAcmeProvider::new(email, dns).production(),
    sync,
)
.sync_interval(Duration::from_secs(300));  // default: 5 min

let _guard = provider.init(cert_dir, Some(domains)).await?;
// On init:
//   1. pull certs from S3 (if they exist)
//   2. run ACME issuance (skipped if certs are already on disk)
//   3. push certs to S3
//   4. spawn periodic background sync for renewals
// On drop: background sync and ACME renewal are both cancelled.
```

### Environment variable helper

```rust
use cert_provider::s3_sync::env_config;

let s3_config = env_config(); // reads CERT_S3_* vars
```

| Env var | Field |
|---------|-------|
| `CERT_S3_BUCKET` | bucket name |
| `CERT_S3_ENDPOINT` | S3-compatible endpoint URL |
| `CERT_S3_ACCESS_KEY` | access key |
| `CERT_S3_SECRET_KEY` | secret key |
| `CERT_S3_REGION` | region (optional) |
| `CERT_S3_PREFIX` | key prefix (optional) |

### S3 key convention

Cert files are stored at `{prefix}/fullchain.pem` and `{prefix}/privkey.pem`. Simple and predictable for manual inspection or access from other tools.

### Usage with ws-echo example

Using `S3CertProvider` to wrap a `DnsAcmeProvider`:

```rust
use cert_provider::S3CertProvider;
use cert_provider::provider::dns01::{BunnyDns, DnsAcmeProvider};
use cert_provider::s3_sync::{S3CertSync, S3Config};

let s3_config = S3Config {
    bucket_name: std::env::var("CERT_S3_BUCKET")
        .expect("CERT_S3_BUCKET must be set"),
    endpoint: std::env::var("CERT_S3_ENDPOINT")
        .expect("CERT_S3_ENDPOINT must be set"),
    access_key: std::env::var("CERT_S3_ACCESS_KEY")
        .expect("CERT_S3_ACCESS_KEY must be set"),
    secret_key: std::env::var("CERT_S3_SECRET_KEY")
        .expect("CERT_S3_SECRET_KEY must be set"),
    region: std::env::var("CERT_S3_REGION").ok(),
    prefix: Some("ws-echo".into()),
};

let dns = BunnyDns::new(std::env::var("BUNNY_API_KEY")?);
let mut provider = S3CertProvider::new(
    DnsAcmeProvider::new("admin@example.com", dns)
        .production(),
    S3CertSync::new(s3_config)?,
);

let _cert_guard = provider.init(cert_dir, Some(domains)).await?;
// certs are now on disk AND in S3; renewals sync back automatically
```

---

## File Layout

After a successful `init`, `cert_dir` will contain:

```
/data/certs/
├── fullchain.pem        # certificate chain (leaf + intermediates)
├── privkey.pem          # private key
└── acme_cache/          # ACME account keys and cached cert – do not delete
```

Pass `fullchain.pem` and `privkey.pem` to `rustls::ServerConfig`, `tokio-rustls`, or any TLS library that accepts PEM files.

---

## API Reference

```rust
#[async_trait]
pub trait CertProvider: Send + Sync + 'static {
    async fn init(
        &mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<BackgroundGuard>;
}
```

| Parameter | Description |
|-----------|-------------|
| `cert_dir` | Writable directory where `fullchain.pem` and `privkey.pem` are written. |
| `domains` | SANs to request (e.g. `["example.com", "www.example.com"]`). `None` returns an error. |
| Returns | `BackgroundGuard` – cancel-on-drop handle. Keep alive for the process lifetime. |

### `S3CertProvider<C>` (feature `s3-sync`)

A decorator that wraps any `CertProvider` to sync cert files to/from S3.

| Method | Default | Description |
|--------|---------|-------------|
| `new(inner, sync)` | – | Wrap an ACME provider with an `S3CertSync`. |
| `from_arc(inner, arc_sync)` | – | Wrap with a shared `Arc<S3CertSync>`. |
| `.sync_interval(dur)` | 5 min | How often to upload renewed certs to S3. |

### Builder methods (`TokioAcmeProvider`)

| Method | Default | Description |
|--------|---------|-------------|
| `new(email)` | – | Staging environment, port 443. |
| `.production()` | staging | Switch to Let's Encrypt production. |
| `.with_port(u16)` | `443` | Internal port the ACME listener binds. Must match `internal_port` in `fly.toml`. |

---

## Error Handling

All errors are `cert_provider::Error` variants: `Io`, `AcmeProtocol`, `Challenge`, `Config`, etc. The `Challenge` variant is returned when an ACME challenge or order becomes invalid. For DNS-01, the provider polls order state with increasing delays until the server returns a terminal state.

---

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

---

[`tokio-rustls-acme`]: https://crates.io/crates/tokio-rustls-acme
[`acme-rfc8555`]: https://crates.io/crates/acme-rfc8555
[`nago-http`]: https://crates.io/crates/nago-http
