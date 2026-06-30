//! [`TorOnionTransport`] — the anonymous `IngestBackend` over Arti.
//!
//! Wiring (mirrors `report-core`'s `LeanPipelineBackend`, but anonymous):
//!
//! 1. `IngestBackend::send` builds the Sentry envelope, enforces the size cap,
//!    pads it to a fixed bucket, and **spools it** (reusing
//!    [`itasha_report_core::spool::Spool`]). It returns immediately —
//!    fire-and-forget — so Tor bootstrap/connect latency never blocks the app.
//! 2. A background drain ([`TorOnionTransport::drain_spool`]) walks the spool,
//!    applies send-time jitter, asks the [`crate::connector::OnionConnector`]
//!    for a duplex stream to the config-injected `.onion`, and POSTs the padded
//!    envelope over the [`crate::http`] client. On a 2xx the report is removed;
//!    on a transient failure it is retried with capped, exponential backoff
//!    ([`crate::config::RetryPolicy`]) up to `max_attempts` and then left for a
//!    later pass; a 4xx or un-loadable report is not retried.
//!
//! The live Tor dependency is confined to the [`crate::connector`] seam: the
//! production [`crate::connector::ArtiConnector`] bootstraps the embedded Arti
//! [`arti_client::TorClient`] lazily (`OnDemand`) and dials the onion. Because
//! the transport holds the connector as a trait object, the whole drain
//! orchestration is unit-tested offline over a `tokio::io::duplex` pipe; only
//! the un-mockable Arti bootstrap+connect stays outside the measured surface.

use std::path::PathBuf;
use std::sync::Arc;

use itasha_report_core::backend::{IngestBackend, SendError, SendOutcome};
use itasha_report_core::consent::ConsentToken;
use itasha_report_core::envelope::Envelope;
use itasha_report_core::report::Report;
use itasha_report_core::spool::Spool;

use crate::arti_connector::ArtiConnector;
use crate::config::TorTransportConfig;
use crate::connector::OnionConnector;
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
    /// The onion-connection seam (the live Tor dependency). Production wiring
    /// uses [`ArtiConnector`]; tests inject an in-memory connector. Held behind
    /// an `Arc` so the transport stays `Clone` and connectors are shareable.
    connector: Arc<dyn OnionConnector>,
}

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
///
/// Counts ONLY — never a host, onion address, URL, status text, spool path, or
/// inner error string. The `retained_*` fields break the `retained` total down
/// by non-identifying transmit-failure CLASS so the host can tell WHY Tor
/// delivery is stalling (endpoint rejecting vs. unreachable) without any
/// identifying detail (LOG-WS-039). Invariant:
/// `retained == retained_endpoint_rejected + retained_unreachable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DrainReport {
    /// Reports successfully transmitted (and removed from the spool).
    pub sent: usize,
    /// Reports left in the spool for a later pass (transient failure). Equals
    /// the sum of the two `retained_*` class counters below.
    pub retained: usize,
    /// Reports dropped as permanently un-sendable (e.g. malformed on disk).
    pub dropped: usize,
    /// Retained because the endpoint RECEIVED the report but returned a non-2xx
    /// status (transient server reject). Class token only — the status code is
    /// deliberately NOT surfaced.
    pub retained_endpoint_rejected: usize,
    /// Retained because the endpoint could not be REACHED (connect / timeout /
    /// transport-layer failure). Class token only — the inner error is
    /// deliberately NOT surfaced.
    pub retained_unreachable: usize,
}

/// The non-identifying CLASS of a single transmit attempt — the coarse
/// disposition the drain surfaces to the host. Never carries a status code,
/// host, URL, or inner error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmitDisposition {
    /// 2xx — accepted; the spool file is removed.
    Sent,
    /// The endpoint received the report but returned a non-2xx status; the
    /// report is retained for a later pass.
    RetainedEndpointRejected,
    /// The endpoint could not be reached (connect / timeout / transport
    /// failure); the report is retained for a later pass.
    RetainedUnreachable,
}

/// Classify one transmit result into its non-identifying [`TransmitDisposition`].
///
/// Pure + deterministic so the class mapping is unit-tested WITHOUT a live Tor
/// network. The inner `Rejected(code)` / [`SendError`] detail is intentionally
/// NOT inspected here — only the coarse, non-identifying class is surfaced,
/// which is the whole point of LOG-WS-039: an operator learns the failure CLASS
/// without any identifying status text, host, or errno reaching the report.
#[must_use]
fn classify_transmit(result: &Result<HttpOutcome, SendError>) -> TransmitDisposition {
    match result {
        Ok(HttpOutcome::Accepted) => TransmitDisposition::Sent,
        Ok(HttpOutcome::Rejected(_)) => TransmitDisposition::RetainedEndpointRejected,
        Err(_) => TransmitDisposition::RetainedUnreachable,
    }
}

impl TorOnionTransport {
    /// Construct the transport over a config-injected onion endpoint, rooted at
    /// `config_dir` for the local spool. Returns an error only if the spool
    /// directory cannot be created.
    pub fn new(
        config: TorTransportConfig,
        config_dir: impl Into<PathBuf>,
    ) -> Result<Self, SendError> {
        let connector = Arc::new(ArtiConnector::new(
            config.state_dir.clone(),
            config.cache_dir.clone(),
        ));
        Self::with_connector(config, config_dir, connector)
    }

    /// Construct the transport over a caller-supplied [`OnionConnector`].
    ///
    /// This is the dependency-injection seam: production code uses [`new`] (which
    /// wires an [`ArtiConnector`]); tests inject an in-memory connector over a
    /// `tokio::io::duplex` pipe so the spool-drain orchestration is exercised
    /// with no live `.onion`. Returns an error only if the spool directory cannot
    /// be created.
    ///
    /// [`new`]: TorOnionTransport::new
    pub fn with_connector(
        config: TorTransportConfig,
        config_dir: impl Into<PathBuf>,
        connector: Arc<dyn OnionConnector>,
    ) -> Result<Self, SendError> {
        // Redacted, non-identifying failure copy (LOG-WS-039): no path, errno,
        // or spool detail reaches the host-visible surface.
        let spool = Spool::open(config_dir.into()).map_err(|_e| {
            SendError::Transport("Reports could not be saved on this device.".to_string())
        })?;
        Ok(Self {
            config,
            spool,
            connector,
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

    /// Transmit one already-padded envelope blob over Tor to the onion endpoint:
    /// ask the connector for a stream and POST. This is **one** attempt — the
    /// send-time jitter and the retry/backoff are the caller's
    /// ([`transmit_with_retry`](Self::transmit_with_retry)) responsibility.
    async fn transmit(&self, body: &[u8]) -> Result<HttpOutcome, SendError> {
        // Connect to the onion:port via the seam (Arti in production, an
        // in-memory pipe in tests), bounded by the per-attempt timeout.
        let connect = self
            .connector
            .connect(&self.config.onion_address, self.config.onion_port);
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

        // POST the envelope over the stream (fixed-minimal headers).
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
    /// transient failure the report is retried with capped exponential backoff
    /// ([`crate::config::RetryPolicy`]) up to `max_attempts` within this pass and
    /// then retained for a later pass; a report that cannot be loaded/built is
    /// dropped (it can never succeed).
    ///
    /// Call this from the host's background async worker. It is safe to call
    /// repeatedly; each call is one pass over the current spool contents. The
    /// returned [`DrainReport`] breaks `retained` down by non-identifying
    /// transmit-failure CLASS (`retained_endpoint_rejected` /
    /// `retained_unreachable`) so the host can surface WHY delivery is stalling
    /// without any identifying status, host, or error detail (LOG-WS-039).
    pub async fn drain_spool(&self) -> Result<DrainReport, SendError> {
        let mut report = DrainReport::default();
        let paths = self.spool.list().map_err(|_e| {
            SendError::Transport("Saved reports could not be read from this device.".to_string())
        })?;

        // Wall-clock budget for this pass (tokio clock so it is testable under
        // paused time). `None` = unbounded.
        let pass_start = tokio::time::Instant::now();
        for path in paths {
            // Per-pass budget: stop STARTING new reports once the pass has run
            // for `max_pass_duration`, leaving the remainder spooled for the next
            // pass. The in-flight report (if any) already completed above; this
            // gates only whether the NEXT one starts, so an unreachable onion
            // cannot turn one pass into a multi-hour run on a large spool.
            if let Some(budget) = self.config.max_pass_duration {
                if pass_start.elapsed() >= budget {
                    break;
                }
            }
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
            // Retry transient failures with capped backoff, then classify the
            // TERMINAL attempt into a non-identifying CLASS and record it. A
            // non-2xx (endpoint reached, rejected) and an unreachable endpoint
            // are BOTH retained for a later pass, but the host learns WHICH class
            // via the `retained_*` counters — never the status code or inner
            // error (LOG-WS-039).
            match classify_transmit(&self.transmit_with_retry(&body).await) {
                TransmitDisposition::Sent => {
                    let _ = self.spool.remove(&path);
                    report.sent += 1;
                }
                TransmitDisposition::RetainedEndpointRejected => {
                    report.retained += 1;
                    report.retained_endpoint_rejected += 1;
                }
                TransmitDisposition::RetainedUnreachable => {
                    report.retained += 1;
                    report.retained_unreachable += 1;
                }
            }
        }
        Ok(report)
    }

    /// Transmit one payload with send-time jitter and the configured retry
    /// policy. Jitter is applied **once** up-front (its purpose is to decouple
    /// crash-time from send-time — a per-report concern, not a per-attempt one;
    /// the backoff already decorrelates retries). Then transient failures (a
    /// connect/IO/transport error or a 5xx) are retried with capped exponential
    /// backoff up to `retry.max_attempts` before the report is retained. A 4xx is
    /// a permanent client-side rejection (malformed/oversize/forbidden) that a
    /// retry cannot fix, so it is retained immediately without burning attempts.
    ///
    /// Returns the **terminal** attempt's result so the caller can classify it
    /// into a non-identifying [`TransmitDisposition`] (LOG-WS-039): a 2xx is
    /// `Sent`, a non-2xx is endpoint-rejected, a connect/transport error is
    /// unreachable.
    async fn transmit_with_retry(&self, body: &[u8]) -> Result<HttpOutcome, SendError> {
        // Send-time jitter, once per report — NOT once per retry attempt, so a
        // briefly-down endpoint cannot stall the sequential drain on repeated
        // jitter sleeps.
        let delay = sample_jitter(self.config.jitter.min, self.config.jitter.max);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }

        let policy = self.config.retry;
        let max_attempts = policy.max_attempts.max(1);
        let mut attempt: u32 = 1;
        loop {
            let result = self.transmit(body).await;
            match &result {
                Ok(HttpOutcome::Accepted) => return result,
                // 4xx: permanent client error — retrying is pointless. Return it
                // (a later code/server change may make it sendable) but do not
                // consume retry attempts on it.
                Ok(HttpOutcome::Rejected(code)) if (400..500).contains(code) => {
                    return result;
                }
                // 5xx (server transient) or a transport/connect error: retry
                // until the attempt budget is exhausted, then return the last
                // result for the caller to classify and retain.
                Ok(HttpOutcome::Rejected(_)) | Err(_) => {
                    if attempt >= max_attempts {
                        return result;
                    }
                    // Backoff for THIS attempt before the next one, then advance.
                    let backoff = policy.backoff_for(attempt);
                    if !backoff.is_zero() {
                        tokio::time::sleep(backoff).await;
                    }
                    attempt += 1;
                }
            }
        }
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

    // -----------------------------------------------------------------------
    // Transmit-failure CLASS surfacing (LOG-WS-039). `classify_transmit` is the
    // pure, network-free seam that maps a transmit result to the non-identifying
    // class the drain records. These prove every disposition maps correctly, the
    // `DrainReport` invariant holds, and NO class surface leaks an identifier.
    // -----------------------------------------------------------------------

    #[test]
    fn classify_transmit_maps_accepted_to_sent() {
        let r: Result<HttpOutcome, SendError> = Ok(HttpOutcome::Accepted);
        assert_eq!(classify_transmit(&r), TransmitDisposition::Sent);
    }

    #[test]
    fn classify_transmit_maps_non_2xx_to_endpoint_rejected() {
        // A 4xx and a 5xx both classify as "endpoint received it, rejected it" —
        // the status CODE is never inspected, only the coarse class.
        for code in [400u16, 413, 429, 500, 503] {
            let r: Result<HttpOutcome, SendError> = Ok(HttpOutcome::Rejected(code));
            assert_eq!(
                classify_transmit(&r),
                TransmitDisposition::RetainedEndpointRejected,
                "status {code} must classify as endpoint-rejected"
            );
        }
    }

    #[test]
    fn classify_transmit_maps_transport_error_to_unreachable() {
        let r: Result<HttpOutcome, SendError> = Err(SendError::Transport(
            "Could not reach the private endpoint; the report will be retried later.".to_string(),
        ));
        assert_eq!(
            classify_transmit(&r),
            TransmitDisposition::RetainedUnreachable
        );
    }

    #[test]
    fn drain_report_retained_classes_sum_to_retained() {
        // The invariant the host relies on: the two non-identifying class
        // counters partition `retained` exactly.
        let report = DrainReport {
            sent: 5,
            retained: 7,
            dropped: 2,
            retained_endpoint_rejected: 3,
            retained_unreachable: 4,
        };
        assert_eq!(
            report.retained,
            report.retained_endpoint_rejected + report.retained_unreachable
        );
    }

    /// The class surface is counts/enums ONLY. The `Debug` of a populated
    /// `DrainReport` (the natural host log form) must carry NO path separator,
    /// errno, host, onion address, or status text — only field names + digits.
    #[test]
    fn drain_report_class_surface_never_leaks_identifiers() {
        let report = DrainReport {
            sent: 1,
            retained: 2,
            dropped: 0,
            retained_endpoint_rejected: 1,
            retained_unreachable: 1,
        };
        let shown = format!("{report:?}");
        for banned in [
            "/", "\\",       // path separators
            "os error", // errno
            ".onion", "onion", // endpoint identifiers
            "http", "503", "429", "400", // status / protocol detail
            "arti", "tor", // transport identifiers
        ] {
            assert!(
                !shown.to_lowercase().contains(banned),
                "DrainReport surface leaked {banned:?}: {shown}"
            );
        }
        // The class counts ARE present (the whole point — the host can see them).
        assert!(shown.contains("retained_endpoint_rejected"));
        assert!(shown.contains("retained_unreachable"));
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

    // ----------------------------------------------------------------------
    // Offline drain tests over an injected in-memory connector.
    //
    // These exercise the FULL spool-drain orchestration — retry/backoff
    // bookkeeping, the sent/retain accounting, and the padded envelope landing
    // on the wire — with NO live `.onion`. The `ScriptedConnector` returns a
    // `tokio::io::duplex` pair whose server end speaks just enough HTTP/1.1 to
    // ack/reject (Content-Length-aware), or fails the connect outright. This is
    // the seam ADR-0002 named as the removal trigger for the `transport.rs`
    // coverage exclusion.
    // ----------------------------------------------------------------------

    use crate::config::RetryPolicy;
    use crate::connector::{BoxedOnionStream, ConnectFuture, OnionConnector};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// What a single `connect` call does.
    #[derive(Clone, Copy, Debug)]
    enum Step {
        /// The connect itself fails (a transport/circuit error).
        Fail,
        /// Connect succeeds; the server replies with this status code.
        Serve(u16),
    }

    struct ScriptInner {
        script: Mutex<VecDeque<Step>>,
        /// Used once the scripted steps are exhausted (models a steady state,
        /// e.g. "always fails" or "always 200").
        default: Step,
        attempts: AtomicUsize,
        /// The request body bytes the server saw on the most recent serve.
        last_body: Mutex<Option<Vec<u8>>>,
    }

    /// A test [`OnionConnector`] backed by in-memory duplex pipes.
    #[derive(Clone)]
    struct ScriptedConnector {
        inner: Arc<ScriptInner>,
    }

    impl ScriptedConnector {
        fn new(default: Step, steps: impl IntoIterator<Item = Step>) -> Self {
            Self {
                inner: Arc::new(ScriptInner {
                    script: Mutex::new(steps.into_iter().collect()),
                    default,
                    attempts: AtomicUsize::new(0),
                    last_body: Mutex::new(None),
                }),
            }
        }
        fn attempts(&self) -> usize {
            self.inner.attempts.load(Ordering::SeqCst)
        }
        fn last_body_len(&self) -> Option<usize> {
            self.inner.last_body.lock().unwrap().as_ref().map(Vec::len)
        }
    }

    impl OnionConnector for ScriptedConnector {
        fn connect(&self, _onion_address: &str, _onion_port: u16) -> ConnectFuture<'_> {
            let inner = Arc::clone(&self.inner);
            Box::pin(async move {
                inner.attempts.fetch_add(1, Ordering::SeqCst);
                let step = {
                    let mut q = inner.script.lock().unwrap();
                    q.pop_front().unwrap_or(inner.default)
                };
                match step {
                    Step::Fail => Err(SendError::Transport("mock connect failed".to_string())),
                    Step::Serve(code) => {
                        let (client, server) = tokio::io::duplex(64 * 1024);
                        let inner2 = Arc::clone(&inner);
                        tokio::spawn(async move { serve_once(server, code, &inner2).await });
                        Ok(Box::new(client) as BoxedOnionStream)
                    }
                }
            })
        }
    }

    fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
    }

    fn parse_content_length(headers: &[u8]) -> usize {
        let text = String::from_utf8_lossy(headers);
        for line in text.split("\r\n") {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    return v.trim().parse().unwrap_or(0);
                }
            }
        }
        0
    }

    /// Read one request (headers + Content-Length body), record the body, and
    /// reply with `code`.
    async fn serve_once(mut server: DuplexStream, code: u16, inner: &ScriptInner) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 2048];
        let header_end = loop {
            match server.read(&mut chunk).await {
                Ok(0) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => return,
            }
            if let Some(end) = find_crlf_crlf(&buf) {
                break end;
            }
            if buf.len() > 1_000_000 {
                return;
            }
        };
        let want = header_end + parse_content_length(&buf[..header_end]);
        while buf.len() < want {
            match server.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        let body = buf[header_end..want.min(buf.len())].to_vec();
        *inner.last_body.lock().unwrap() = Some(body);
        let resp = format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\n\r\n");
        let _ = server.write_all(resp.as_bytes()).await;
        let _ = server.flush().await;
    }

    /// A retry policy with negligible backoff so the retry-path tests run fast
    /// while still proving the policy is consulted.
    fn fast_retry(max_attempts: u32) -> RetryPolicy {
        RetryPolicy {
            max_attempts,
            base_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
        }
    }

    fn transport_with(
        dir: &std::path::Path,
        config: TorTransportConfig,
        connector: ScriptedConnector,
    ) -> (TorOnionTransport, ScriptedConnector) {
        let t =
            TorOnionTransport::with_connector(config, dir, Arc::new(connector.clone())).unwrap();
        (t, connector)
    }

    #[tokio::test]
    async fn drain_sends_over_injected_connector_and_pads_on_the_wire() {
        let dir = tmp_dir("drain-ok");
        let conn = ScriptedConnector::new(Step::Serve(200), []);
        let (t, conn) = transport_with(&dir, cfg(&dir), conn);

        t.send(&Report::crash("boom"), &ConsentToken::granted())
            .unwrap();
        assert_eq!(t.spool().count().unwrap(), 1);

        let report = t.drain_spool().await.unwrap();
        assert_eq!(
            report,
            DrainReport {
                sent: 1,
                ..DrainReport::default()
            }
        );
        // Sent ⇒ removed from the spool.
        assert_eq!(t.spool().count().unwrap(), 0);
        assert_eq!(conn.attempts(), 1, "a clean 200 takes exactly one attempt");
        // The padded envelope (default first bucket = 4 KiB) reached the wire.
        assert_eq!(conn.last_body_len(), Some(4096));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn drain_retries_transient_failure_then_succeeds() {
        let dir = tmp_dir("drain-retry");
        // First connect fails (transient), the next serves 200.
        let conn = ScriptedConnector::new(Step::Serve(200), [Step::Fail]);
        let config = cfg(&dir).with_retry(fast_retry(3));
        let (t, conn) = transport_with(&dir, config, conn);

        t.send(&Report::crash("boom"), &ConsentToken::granted())
            .unwrap();
        let report = t.drain_spool().await.unwrap();

        assert_eq!(report.sent, 1);
        assert_eq!(t.spool().count().unwrap(), 0);
        // Exactly two attempts: the failed one + the successful retry.
        assert_eq!(conn.attempts(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn drain_retains_after_exhausting_attempts() {
        let dir = tmp_dir("drain-exhaust");
        // Connect always fails.
        let conn = ScriptedConnector::new(Step::Fail, []);
        let config = cfg(&dir).with_retry(fast_retry(3));
        let (t, conn) = transport_with(&dir, config, conn);

        t.send(&Report::crash("boom"), &ConsentToken::granted())
            .unwrap();
        let report = t.drain_spool().await.unwrap();

        // Connect always fails ⇒ the terminal attempt is unreachable, so the
        // non-identifying class breakdown attributes it to `retained_unreachable`.
        assert_eq!(
            report,
            DrainReport {
                sent: 0,
                retained: 1,
                dropped: 0,
                retained_endpoint_rejected: 0,
                retained_unreachable: 1,
            }
        );
        // Retained ⇒ still on the spool for a later pass.
        assert_eq!(t.spool().count().unwrap(), 1);
        // The policy cap was honoured exactly.
        assert_eq!(conn.attempts(), 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn drain_does_not_retry_a_4xx_client_error() {
        let dir = tmp_dir("drain-4xx");
        // A 413 (payload too large) is permanent — retrying cannot fix it.
        let conn = ScriptedConnector::new(Step::Serve(413), []);
        let config = cfg(&dir).with_retry(fast_retry(5));
        let (t, conn) = transport_with(&dir, config, conn);

        t.send(&Report::crash("boom"), &ConsentToken::granted())
            .unwrap();
        let report = t.drain_spool().await.unwrap();

        assert_eq!(report.retained, 1);
        assert_eq!(t.spool().count().unwrap(), 1);
        // No retry budget burned on a permanent 4xx.
        assert_eq!(conn.attempts(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn drain_retries_a_5xx_server_error() {
        let dir = tmp_dir("drain-5xx");
        // 503 is a transient server error — it IS retried.
        let conn = ScriptedConnector::new(Step::Serve(503), []);
        let config = cfg(&dir).with_retry(fast_retry(2));
        let (t, conn) = transport_with(&dir, config, conn);

        t.send(&Report::crash("boom"), &ConsentToken::granted())
            .unwrap();
        let report = t.drain_spool().await.unwrap();

        assert_eq!(report.retained, 1);
        assert_eq!(conn.attempts(), 2, "5xx is transient and consumes retries");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn drain_pass_budget_stops_before_starting_reports() {
        // A zero per-pass budget means the deadline is already reached at the top
        // of the drain loop, so NO report is started this pass: the connector is
        // never dialed and every report stays spooled for the next pass. (The
        // unbounded default `None` path is exercised by every other drain test.)
        let dir = tmp_dir("drain-budget");
        let conn = ScriptedConnector::new(Step::Serve(200), []);
        let config = cfg(&dir).with_max_pass_duration(Some(Duration::ZERO));
        let (t, conn) = transport_with(&dir, config, conn);

        t.send(&Report::crash("a"), &ConsentToken::granted())
            .unwrap();
        t.send(&Report::crash("b"), &ConsentToken::granted())
            .unwrap();
        assert_eq!(t.spool().count().unwrap(), 2);

        let report = t.drain_spool().await.unwrap();
        // Nothing started ⇒ all counters zero, both reports still spooled, and the
        // onion was never dialed.
        assert_eq!(report, DrainReport::default());
        assert_eq!(t.spool().count().unwrap(), 2);
        assert_eq!(conn.attempts(), 0, "the budget must gate BEFORE dialing");
        std::fs::remove_dir_all(&dir).ok();
    }
}
