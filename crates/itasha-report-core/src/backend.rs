//! The `IngestBackend` boundary and its implementations.
//!
//! [`IngestBackend`] is the seam every host calls. Two implementations ship:
//!
//! * [`LeanPipelineBackend`] — the hardened `ureq` HTTP transport that POSTs a
//!   Sentry envelope to a config-driven self-hosted endpoint. No redirects,
//!   bounded timeout, size-capped, static User-Agent, **no persistent
//!   identifier** (only the consent token's ephemeral per-report nonce).
//! * [`SentryStubBackend`] — a future-Sentry placeholder over the identical
//!   envelope wire; it accepts the same payload so the swap is a config change,
//!   never a client rebuild.
//!
//! Every [`IngestBackend::send`] call **requires a [`ConsentToken`]**. There is
//! no transmission path that does not pass an explicit, host-minted consent
//! decision — a report cannot be sent without one.

use std::time::Duration;

use crate::consent::ConsentToken;
use crate::envelope::Envelope;
use crate::report::Report;

/// The static User-Agent the transport sends. Carries the SDK name + version
/// only — no machine, user, or install identity.
fn static_user_agent() -> String {
    format!("{}/{}", crate::SDK_NAME, crate::SDK_VERSION)
}

/// Structured outcome of a send attempt. The host logs this (counts/enums only,
/// no PII) — never a silent drop, never a fake success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// The report was accepted by the endpoint.
    Sent,
    /// The send failed; the host may retain/retry. Carries a non-identifying reason.
    Failed(String),
}

/// Errors a backend can surface before/while sending.
#[derive(Debug)]
pub enum SendError {
    /// The payload exceeded the configured size cap.
    PayloadTooLarge {
        /// Actual payload size in bytes.
        actual: usize,
        /// Configured cap in bytes.
        cap: usize,
    },
    /// The transport failed (network, TLS, status). Non-identifying message.
    Transport(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::PayloadTooLarge { actual, cap } => {
                write!(f, "payload {actual} bytes exceeds cap {cap} bytes")
            }
            SendError::Transport(m) => write!(f, "transport error: {m}"),
        }
    }
}

impl std::error::Error for SendError {}

/// Configuration for the hardened transport.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// The single self-hosted ingest endpoint. There is **no default** — a host
    /// must configure one, so a mis-build cannot phone home.
    pub endpoint: String,
    /// Request timeout. Default 30s (mirrors the SCR1B3 net pattern).
    pub timeout: Duration,
    /// Maximum envelope size in bytes. Default 8 MiB.
    pub max_payload_bytes: usize,
}

impl TransportConfig {
    /// Construct a transport config for a self-hosted endpoint with safe defaults.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout: Duration::from_secs(30),
            max_payload_bytes: 8 * 1024 * 1024,
        }
    }

    /// Override the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the max payload size.
    #[must_use]
    pub fn with_max_payload_bytes(mut self, cap: usize) -> Self {
        self.max_payload_bytes = cap;
        self
    }
}

/// The ingestion seam. Implementors transmit a report's Sentry envelope to a
/// backend. **`send` requires a `&ConsentToken`** — the type-level guarantee
/// that the host obtained explicit user consent for this transmission.
pub trait IngestBackend {
    /// Transmit the report. The `consent` argument is mandatory: there is no
    /// send overload without it. Implementors MUST NOT attach any persistent
    /// identifier; the only per-report token is `consent.nonce()`.
    fn send(&self, report: &Report, consent: &ConsentToken) -> Result<SendOutcome, SendError>;
}

/// The lean in-house pipeline transport (build-now). POSTs a Sentry envelope
/// over hardened `ureq`.
#[derive(Debug, Clone)]
pub struct LeanPipelineBackend {
    config: TransportConfig,
}

impl LeanPipelineBackend {
    /// Construct the backend for a configured endpoint.
    #[must_use]
    pub fn new(config: TransportConfig) -> Self {
        Self { config }
    }

    /// Build a hardened `ureq` agent: bounded global timeout, **zero
    /// redirects**, no automatic identity headers.
    fn agent(&self) -> ureq::Agent {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(self.config.timeout))
            .max_redirects(0)
            .user_agent(static_user_agent())
            .build();
        config.into()
    }

    /// Serialize the report to an envelope, enforce the size cap, and return
    /// the wire bytes + the per-report event id derived from the consent nonce.
    fn build_payload(&self, report: &Report, consent: &ConsentToken) -> Result<Vec<u8>, SendError> {
        // The event_id is derived solely from the ephemeral consent nonce — it
        // is per-report and carries no stable identity. Pad/trim to the 32-hex
        // shape Sentry expects.
        let event_id = event_id_from_nonce(consent.nonce());
        let envelope = Envelope::from_report(report, Some(event_id));
        let bytes = envelope.to_bytes();
        if bytes.len() > self.config.max_payload_bytes {
            return Err(SendError::PayloadTooLarge {
                actual: bytes.len(),
                cap: self.config.max_payload_bytes,
            });
        }
        Ok(bytes)
    }
}

impl IngestBackend for LeanPipelineBackend {
    fn send(&self, report: &Report, consent: &ConsentToken) -> Result<SendOutcome, SendError> {
        let body = self.build_payload(report, consent)?;
        let agent = self.agent();
        // Static UA is set on the agent; content-type is the Sentry envelope MIME.
        // No X-Forwarded, no geo, no identity headers are attached.
        match agent
            .post(&self.config.endpoint)
            .header("content-type", "application/x-sentry-envelope")
            .send(&body[..])
        {
            Ok(_resp) => Ok(SendOutcome::Sent),
            Err(e) => Ok(SendOutcome::Failed(transport_reason(&e))),
        }
    }
}

/// The future self-hosted Sentry backend (stub). It speaks the identical
/// envelope wire, so promoting it is a config change. The stub does not
/// transmit; it validates the consent + payload contract and reports the
/// outcome, so hosts can wire against it today.
#[derive(Debug, Clone)]
pub struct SentryStubBackend {
    config: TransportConfig,
}

impl SentryStubBackend {
    /// Construct the stub for a (future) DSN-style endpoint.
    #[must_use]
    pub fn new(config: TransportConfig) -> Self {
        Self { config }
    }
}

impl IngestBackend for SentryStubBackend {
    fn send(&self, report: &Report, consent: &ConsentToken) -> Result<SendOutcome, SendError> {
        // Build the identical envelope the lean pipeline would, enforcing the
        // same size cap — proving wire-format parity — but do not transmit.
        let event_id = event_id_from_nonce(consent.nonce());
        let envelope = Envelope::from_report(report, Some(event_id));
        let bytes = envelope.to_bytes();
        if bytes.len() > self.config.max_payload_bytes {
            return Err(SendError::PayloadTooLarge {
                actual: bytes.len(),
                cap: self.config.max_payload_bytes,
            });
        }
        Ok(SendOutcome::Failed(
            "sentry-stub: not yet enabled (wire-format parity verified)".to_string(),
        ))
    }
}

/// Derive a 32-hex-char Sentry `event_id` from the ephemeral consent nonce.
///
/// Anonymity hardening #1 (gap D-2): the nonce is now 16 bytes of OS-CSPRNG
/// output (32 lowercase hex chars), so this is effectively a passthrough —
/// the wire `event_id` inherits the nonce's UNLINKABLE property. There is no
/// time component and no monotonic counter to leak: the id carries no stable
/// identity AND cannot be used to reconstruct submission ordering/timing. The
/// hex-filter + pad/truncate is retained defensively so any future nonce shape
/// still yields a well-formed 32-hex id.
fn event_id_from_nonce(nonce: &str) -> String {
    let mut hex: String = nonce.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    hex.truncate(32);
    while hex.len() < 32 {
        hex.push('0');
    }
    hex
}

/// Map a transport error to a non-identifying reason string (no URLs, no host).
fn transport_reason(e: &ureq::Error) -> String {
    match e {
        ureq::Error::StatusCode(code) => format!("http status {code}"),
        ureq::Error::Timeout(_) => "timeout".to_string(),
        _ => "transport failure".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_ua_has_no_identity() {
        let ua = static_user_agent();
        assert!(ua.starts_with("itasha-report-core/"));
        // No machine/user identity tokens; exactly one '/' (name/version).
        assert!(!ua.contains('@'));
        assert_eq!(ua.matches('/').count(), 1);
    }

    #[test]
    fn event_id_is_32_hex_and_nonce_derived() {
        let id = event_id_from_nonce("deadbeef-1");
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // Two different nonces give different ids (per-report, not stable).
        assert_ne!(event_id_from_nonce("aaaa"), event_id_from_nonce("bbbb"));
    }

    #[test]
    fn payload_carries_no_stable_id_only_nonce_event_id() {
        // The ONLY id in the wire is the per-report event_id derived from the
        // ephemeral nonce. Two sends of the same report under fresh consent
        // tokens produce different event_ids — there is no stable identifier.
        let backend = LeanPipelineBackend::new(TransportConfig::new("https://x.invalid/"));
        let report = Report::crash("panic");
        let t1 = ConsentToken::granted();
        let t2 = ConsentToken::granted();
        let p1 = backend.build_payload(&report, &t1).unwrap();
        let p2 = backend.build_payload(&report, &t2).unwrap();
        assert_ne!(
            p1, p2,
            "event_id must vary per consent token (no stable id)"
        );
    }

    #[test]
    fn oversize_payload_is_rejected() {
        let backend = LeanPipelineBackend::new(
            TransportConfig::new("https://x.invalid/").with_max_payload_bytes(16),
        );
        let report = Report::crash("x".repeat(10_000));
        let consent = ConsentToken::granted();
        let err = backend.build_payload(&report, &consent).unwrap_err();
        assert!(matches!(err, SendError::PayloadTooLarge { .. }));
    }

    #[test]
    fn sentry_stub_verifies_wire_parity_without_sending() {
        let stub = SentryStubBackend::new(TransportConfig::new("https://sentry.invalid/"));
        let report = Report::crash("panic");
        let consent = ConsentToken::granted();
        let outcome = stub.send(&report, &consent).unwrap();
        // The stub does not transmit; it reports a non-enabled outcome.
        match outcome {
            SendOutcome::Failed(reason) => assert!(reason.contains("sentry-stub")),
            SendOutcome::Sent => panic!("stub must not claim Sent"),
        }
    }
}
