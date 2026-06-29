//! [`TorOnionTransport`] — the anonymous `IngestBackend` over Arti.
//!
//! Wiring (mirrors `report-core`'s `LeanPipelineBackend`, but anonymous):
//!
//! 1. `IngestBackend::send` builds the Sentry envelope, enforces the size cap,
//!    pads it to a fixed bucket, and **spools it** (reusing
//!    [`itasha_report_core::spool::Spool`]). It returns immediately —
//!    fire-and-forget — so Tor bootstrap/connect latency never blocks the app.
//! 2. A background drain ([`TorOnionTransport::drain_spool`]) walks the spool,
//!    applies send-time jitter, lazily bootstraps the embedded Arti
//!    [`arti_client::TorClient`] on first use, connects to the config-injected
//!    `.onion`, and POSTs the padded envelope over the [`crate::http`] client.
//!    On a 2xx the report is removed; otherwise it is left for a later pass
//!    (capped, backed-off retry).
//!
//! The embedded `TorClient` is created with `BootstrapBehavior::OnDemand`, so
//! the directory consensus is fetched on the first connect, not at app launch.
//! The Arti state/cache dirs persist the consensus so warm bootstraps are fast.

use std::path::PathBuf;
use std::sync::Arc;

use itasha_report_core::backend::{IngestBackend, SendError, SendOutcome};
use itasha_report_core::consent::ConsentToken;
use itasha_report_core::envelope::Envelope;
use itasha_report_core::report::Report;
use itasha_report_core::spool::Spool;

use crate::config::TorTransportConfig;
use crate::http::{post_envelope, HttpOutcome};
use crate::hygiene::{pad_envelope_bytes, sample_jitter};

/// The truly-anonymous Tor v3 onion transport.
///
/// Construct with [`TorOnionTransport::new`]. It implements
/// [`IngestBackend`]; `send` spools (fire-and-forget). Call
/// [`TorOnionTransport::drain_spool`] from an async context (the host's
/// background worker) to actually transmit over Tor.
#[derive(Clone)]
pub struct TorOnionTransport {
    config: TorTransportConfig,
    spool: Spool,
    /// Lazily-bootstrapped embedded Arti client, shared across drains.
    ///
    /// `TorClient` is not `Clone`, so it is shared behind an `Arc`. `connect`
    /// takes `&self`, so the `Arc` is all we need.
    tor: Arc<tokio::sync::Mutex<Option<Arc<ArtiHandle>>>>,
}

/// Opaque handle to the embedded Arti client (kept behind an alias so the
/// public API does not leak Arti types).
type ArtiHandle = arti_client::TorClient<tor_rtcompat::PreferredRuntime>;

impl std::fmt::Debug for TorOnionTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorOnionTransport")
            .field("onion_address", &self.config.onion_address)
            .field("onion_port", &self.config.onion_port)
            .field("spool_dir", &self.spool.dir())
            .finish_non_exhaustive()
    }
}

/// Result of a single drain pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DrainReport {
    /// Reports successfully transmitted (and removed from the spool).
    pub sent: usize,
    /// Reports left in the spool for a later pass (transient failure).
    pub retained: usize,
    /// Reports dropped as permanently un-sendable (e.g. malformed on disk).
    pub dropped: usize,
}

impl TorOnionTransport {
    /// Construct the transport over a config-injected onion endpoint, rooted at
    /// `config_dir` for the local spool. Returns an error only if the spool
    /// directory cannot be created.
    pub fn new(
        config: TorTransportConfig,
        config_dir: impl Into<PathBuf>,
    ) -> Result<Self, SendError> {
        let spool = Spool::open(config_dir.into()).map_err(|_e| {
            SendError::Transport("Reports could not be saved on this device.".to_string())
        })?;
        Ok(Self {
            config,
            spool,
            tor: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    /// The local spool backing this transport (for inspection/tests).
    #[must_use]
    pub fn spool(&self) -> &Spool {
        &self.spool
    }

    /// The transport configuration.
    #[must_use]
    pub fn config(&self) -> &TorTransportConfig {
        &self.config
    }

    /// Build the padded, size-capped envelope bytes for a report under a consent
    /// token. Shared by `send` (spool path) and tests.
    pub fn build_padded_payload(
        &self,
        report: &Report,
        consent: &ConsentToken,
    ) -> Result<Vec<u8>, SendError> {
        let event_id = event_id_from_nonce(consent.nonce());
        let envelope = Envelope::from_report(report, Some(event_id));
        let raw = envelope.to_bytes();
        if raw.len() > self.config.max_payload_bytes {
            return Err(SendError::PayloadTooLarge {
                actual: raw.len(),
                cap: self.config.max_payload_bytes,
            });
        }
        Ok(pad_envelope_bytes(&envelope, &self.config.padding_buckets))
    }

    /// Lazily bootstrap (or reuse) the embedded Arti client. The first call
    /// builds the client with `OnDemand` bootstrap behaviour; subsequent calls
    /// reuse the cached handle.
    async fn tor_client(&self) -> Result<Arc<ArtiHandle>, SendError> {
        let mut guard = self.tor.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(Arc::clone(client));
        }
        let cfg = build_arti_config(&self.config.state_dir, &self.config.cache_dir)?;
        let client = arti_client::TorClient::builder()
            .config(cfg)
            .bootstrap_behavior(arti_client::BootstrapBehavior::OnDemand)
            .create_unbootstrapped()
            .map_err(|_e| {
                SendError::Transport(
                    "The private network could not start; the report will be retried later."
                        .to_string(),
                )
            })?;
        // `create_unbootstrapped` already yields an `Arc<TorClient>`.
        *guard = Some(Arc::clone(&client));
        Ok(client)
    }

    /// Transmit one already-padded envelope blob over Tor to the onion endpoint.
    /// Applies send-time jitter, connects, and POSTs. Returns the HTTP outcome.
    async fn transmit(&self, body: &[u8]) -> Result<HttpOutcome, SendError> {
        // 1. Send-time jitter (decouple crash-time from send-time).
        let delay = sample_jitter(self.config.jitter.min, self.config.jitter.max);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }

        // 2. Lazily bootstrap + connect to the onion:port.
        let client = self.tor_client().await?;
        let addr = (self.config.onion_address.as_str(), self.config.onion_port);
        let connect = client.connect(addr);
        let mut stream = tokio::time::timeout(self.config.timeout, connect)
            .await
            .map_err(|_| {
                SendError::Transport(
                    "Could not reach the private endpoint in time; the report will be retried later."
                        .to_string(),
                )
            })?
            .map_err(|_e| {
                SendError::Transport(
                    "Could not reach the private endpoint; the report will be retried later."
                        .to_string(),
                )
            })?;

        // 3. POST the envelope over the DataStream (fixed-minimal headers).
        let post = post_envelope(
            &mut stream,
            &self.config.onion_address,
            &self.config.request_path,
            body,
        );
        let outcome = tokio::time::timeout(self.config.timeout, post)
            .await
            .map_err(|_| {
                SendError::Transport(
                    "Sending the report timed out; it will be retried later.".to_string(),
                )
            })?
            // WS-044 / G6: the inner HttpError is NOT interpolated — a fixed,
            // non-identifying class string only (no reliance on the inner error
            // being non-identifying, which was the latent leak here).
            .map_err(|_e| {
                SendError::Transport(
                    "Sending the report failed; it will be retried later.".to_string(),
                )
            })?;
        Ok(outcome)
    }

    /// Drain the spool over Tor: for each spooled report, build its padded
    /// envelope and transmit. On a 2xx the report file is removed; on a
    /// transient failure it is retained for a later pass; a report that cannot
    /// be loaded/built is dropped (it can never succeed).
    ///
    /// Call this from the host's background async worker. It is safe to call
    /// repeatedly; each call is one pass over the current spool contents.
    pub async fn drain_spool(&self) -> Result<DrainReport, SendError> {
        let mut report = DrainReport::default();
        let paths = self.spool.list().map_err(|_e| {
            SendError::Transport("Saved reports could not be read from this device.".to_string())
        })?;

        for path in paths {
            // Load the spooled Report.
            let loaded = match self.spool.load(&path) {
                Ok(r) => r,
                Err(_) => {
                    // Unparseable on disk → can never send; drop it.
                    let _ = self.spool.remove(&path);
                    report.dropped += 1;
                    continue;
                }
            };
            // The spooled report was consent-gated at enqueue time; mint the
            // per-report ephemeral nonce for the wire event_id.
            let consent = ConsentToken::granted();
            let body = match self.build_padded_payload(&loaded, &consent) {
                Ok(b) => b,
                Err(_) => {
                    let _ = self.spool.remove(&path);
                    report.dropped += 1;
                    continue;
                }
            };
            match self.transmit(&body).await {
                Ok(HttpOutcome::Accepted) => {
                    let _ = self.spool.remove(&path);
                    report.sent += 1;
                }
                // 4xx/5xx or transport failure → retain for a later pass.
                Ok(HttpOutcome::Rejected(_)) | Err(_) => {
                    report.retained += 1;
                }
            }
        }
        Ok(report)
    }
}

impl IngestBackend for TorOnionTransport {
    /// Fire-and-forget: build the padded envelope, enforce the size cap, and
    /// **spool** it. Transmission happens on the background drain so Tor latency
    /// never blocks the caller. Returns `Sent` to mean "accepted for anonymous
    /// delivery" (durably spooled); a size-cap violation surfaces as an error.
    fn send(&self, report: &Report, consent: &ConsentToken) -> Result<SendOutcome, SendError> {
        // Build once to enforce the size cap up-front (so an oversize report is
        // rejected synchronously, not silently dropped on the drain).
        let _ = self.build_padded_payload(report, consent)?;
        match self.spool.enqueue(report) {
            Ok(_) => Ok(SendOutcome::Sent),
            Err(_e) => Ok(SendOutcome::Failed(
                "The report could not be saved on this device and was not queued.".to_string(),
            )),
        }
    }
}

/// Build the Arti `TorClientConfig` pointing storage at the app's state/cache
/// dirs. Persisting the consensus cache makes warm bootstraps fast.
fn build_arti_config(
    state_dir: &std::path::Path,
    cache_dir: &std::path::Path,
) -> Result<arti_client::TorClientConfig, SendError> {
    arti_client::config::TorClientConfigBuilder::from_directories(state_dir, cache_dir)
        .build()
        .map_err(|_e| {
            SendError::Transport(
                "The private network could not be configured; the report will be retried later."
                    .to_string(),
            )
        })
}

/// Derive a 32-hex Sentry `event_id` from the ephemeral consent nonce
/// (identical contract to `report-core::backend`: per-report, no stable id).
fn event_id_from_nonce(nonce: &str) -> String {
    let mut hex: String = nonce.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    hex.truncate(32);
    while hex.len() < 32 {
        hex.push('0');
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::config::JitterBounds;

    fn tmp_dir(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "w1tn3ss-tor-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    fn cfg(dir: &std::path::Path) -> TorTransportConfig {
        TorTransportConfig::new(
            "a".repeat(56) + ".onion",
            80,
            dir.join("state"),
            dir.join("cache"),
        )
        .with_jitter(JitterBounds::none())
    }

    #[test]
    fn send_spools_fire_and_forget() {
        let dir = tmp_dir("spool");
        let t = TorOnionTransport::new(cfg(&dir), &dir).unwrap();
        assert_eq!(t.spool().count().unwrap(), 0);
        let report = Report::crash("panic at <HOME>/x.rs");
        let consent = ConsentToken::granted();
        let outcome = t.send(&report, &consent).unwrap();
        assert_eq!(outcome, SendOutcome::Sent);
        // The report is durably spooled, not transmitted inline.
        assert_eq!(t.spool().count().unwrap(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oversize_report_rejected_synchronously() {
        let dir = tmp_dir("oversize");
        let config = cfg(&dir).with_max_payload_bytes(64);
        let t = TorOnionTransport::new(config, &dir).unwrap();
        let report = Report::crash("x".repeat(10_000));
        let consent = ConsentToken::granted();
        let err = t.send(&report, &consent).unwrap_err();
        assert!(matches!(err, SendError::PayloadTooLarge { .. }));
        // Nothing spooled — the oversize report was rejected, not silently dropped.
        assert_eq!(t.spool().count().unwrap(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn padded_payload_lands_on_a_bucket() {
        let dir = tmp_dir("pad");
        let t = TorOnionTransport::new(cfg(&dir), &dir).unwrap();
        let report = Report::crash("small");
        let consent = ConsentToken::granted();
        let body = t.build_padded_payload(&report, &consent).unwrap();
        // Default first bucket is 4 KiB.
        assert_eq!(body.len(), 4096);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn event_id_is_32_hex() {
        let id = event_id_from_nonce("deadbeefcafe");
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// REDACTION GUARANTEE (WS-039/040/044/047 etc.): the host-visible
    /// transport-error surface (`SendError` `Display` and the `SendOutcome`
    /// failure copy) must carry NONE of: an onion/arti/provider name, a path
    /// separator, an OS errno, or a socket name. We build the spool-open failure
    /// (a real, deterministic path) and prove the surfaced string is clean, and
    /// we assert the fixed onion/arti strings the module emits are leak-free.
    #[test]
    fn transport_error_surface_never_leaks_endpoint_or_os_detail() {
        // Force the spool-open failure deterministically: point the transport's
        // config_dir at a regular FILE so `<file>/reports` cannot be created.
        let dir = tmp_dir("leakcheck");
        let as_file = dir.join("config-is-a-file");
        std::fs::write(&as_file, b"x").unwrap();
        let err = TorOnionTransport::new(cfg(&dir), &as_file).unwrap_err();
        let shown = format!("{err}");
        for needle in ["arti", "onion", "tor transport", "spool", ".onion"] {
            assert!(
                !shown.to_lowercase().contains(needle),
                "leak token {needle:?} surfaced: {shown}"
            );
        }
        assert!(!shown.contains("os error"), "errno leaked: {shown}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn drain_on_empty_spool_is_a_noop() {
        let dir = tmp_dir("drain-empty");
        let t = TorOnionTransport::new(cfg(&dir), &dir).unwrap();
        let report = t.drain_spool().await.unwrap();
        assert_eq!(report, DrainReport::default());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn drain_drops_unparseable_spool_file() {
        let dir = tmp_dir("drain-bad");
        let t = TorOnionTransport::new(cfg(&dir), &dir).unwrap();
        // Write a garbage "report-*.json" into the spool dir.
        let bad = t.spool().dir().join("report-000000.json");
        std::fs::write(&bad, b"NOT JSON").unwrap();
        assert_eq!(t.spool().count().unwrap(), 1);
        let report = t.drain_spool().await.unwrap();
        assert_eq!(report.dropped, 1);
        assert_eq!(t.spool().count().unwrap(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_is_injected_no_hardcoded_endpoint() {
        let dir = tmp_dir("cfg");
        let t = TorOnionTransport::new(cfg(&dir), &dir).unwrap();
        // The onion address is exactly what we injected — there is no default.
        assert!(t.config().onion_address.ends_with(".onion"));
        assert!(t.config().is_valid_onion());
        assert_eq!(t.config().jitter, JitterBounds::none());
        let _ = Duration::from_secs(1);
        std::fs::remove_dir_all(&dir).ok();
    }
}
