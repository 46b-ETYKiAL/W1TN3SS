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
    // Plain, host-visible copy only. The raw byte counts (PayloadTooLarge) and
    // the inner transport reason (Transport) are kept on the struct/variant for
    // a host-side log toggle, but are NEVER interpolated into the user-facing
    // string — a fixed non-identifying class string is shown instead.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::PayloadTooLarge { .. } => {
                f.write_str("This report is too large to send and was not sent.")
            }
            SendError::Transport(_) => {
                f.write_str("The report could not be sent right now; it will be retried later.")
            }
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
        build_capped_envelope_bytes(report, consent, self.config.max_payload_bytes)
    }
}

/// Serialize `report` to a Sentry envelope under the ephemeral consent nonce and
/// enforce the size cap. The single source of truth for the wire payload, shared
/// by [`LeanPipelineBackend`] and [`SentryStubBackend`] so the two backends can
/// never drift in how they build or size-check the envelope.
///
/// The `event_id` is derived solely from the ephemeral consent nonce — it is
/// per-report and carries no stable identity (pad/trim to the 32-hex shape
/// Sentry expects).
fn build_capped_envelope_bytes(
    report: &Report,
    consent: &ConsentToken,
    cap: usize,
) -> Result<Vec<u8>, SendError> {
    let event_id = event_id_from_nonce(consent.nonce());
    let envelope = Envelope::from_report(report, Some(event_id));
    let bytes = envelope.to_bytes();
    if bytes.len() > cap {
        return Err(SendError::PayloadTooLarge {
            actual: bytes.len(),
            cap,
        });
    }
    Ok(bytes)
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
        let _bytes = build_capped_envelope_bytes(report, consent, self.config.max_payload_bytes)?;
        // Host-visible outcome: no provider name, no implementation jargon.
        Ok(SendOutcome::Failed(
            "sending is not enabled in this build.".to_string(),
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

/// Map a transport error to a plain, non-identifying host-visible reason (no
/// URLs, no host, no status numbers, no bare protocol tokens). Each arm is a
/// fixed user-facing class string with a recovery expectation.
fn transport_reason(e: &ureq::Error) -> String {
    match e {
        ureq::Error::StatusCode(_) => {
            "The report could not be delivered (server rejected it); it will be retried later."
                .to_string()
        }
        ureq::Error::Timeout(_) => {
            "Sending the report timed out; it will be retried later.".to_string()
        }
        _ => "The report could not be sent right now; it will be retried later.".to_string(),
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
            SendOutcome::Failed(reason) => {
                assert!(
                    reason.contains("not enabled in this build"),
                    "got: {reason}"
                );
                // DE-BRAND (WS-015): the provider name must not appear, nor any
                // implementation jargon.
                let lower = reason.to_lowercase();
                assert!(!lower.contains("sentry"), "provider name leaked: {reason}");
                assert!(!lower.contains("stub"), "impl jargon leaked: {reason}");
                assert!(
                    !lower.contains("wire-format"),
                    "impl jargon leaked: {reason}"
                );
            }
            SendOutcome::Sent => panic!("stub must not claim Sent"),
        }
    }

    #[test]
    fn send_error_display_renders_both_arms() {
        // PayloadTooLarge arm: plain copy, NO raw byte counts (WS-013).
        let too_large = SendError::PayloadTooLarge {
            actual: 9_000,
            cap: 8_000,
        };
        let s = format!("{too_large}");
        assert_eq!(s, "This report is too large to send and was not sent.");
        assert!(!s.contains("9000"), "raw byte count leaked: {s}");
        assert!(!s.contains("8000"), "raw byte cap leaked: {s}");

        // Transport arm: plain copy, NO inner reason / "transport error:" jargon
        // (WS-014).
        let transport = SendError::Transport("connection refused".to_string());
        let t = format!("{transport}");
        assert_eq!(
            t,
            "The report could not be sent right now; it will be retried later."
        );
        assert!(!t.contains("transport error"), "dev jargon leaked: {t}");
        assert!(
            !t.contains("connection refused"),
            "inner reason leaked: {t}"
        );
    }

    /// REDACTION GUARANTEE (WS-014): even when a `SendError::Transport` is built
    /// with a deliberately leaky inner message (errno + local path), the
    /// host-visible `Display` shows the fixed class string only — the inner
    /// content can never reach a host log via `Display`.
    #[test]
    fn send_error_transport_display_never_leaks_inner_message() {
        let leaky = SendError::Transport(
            "os error 13 at /home/jane/.config/app/sock: permission denied".to_string(),
        );
        let shown = format!("{leaky}");
        assert!(!shown.contains('/'), "path separator leaked: {shown}");
        assert!(!shown.contains("os error"), "errno leaked: {shown}");
        assert!(!shown.contains("jane"), "username leaked: {shown}");
        assert!(!shown.contains("sock"), "socket name leaked: {shown}");
    }

    #[test]
    fn send_error_implements_std_error_trait() {
        // Exercise the std::error::Error impl (line 64) through a trait object so
        // `source()`/`Display` are reachable as an error value.
        let err = SendError::Transport("x".to_string());
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err
            .to_string()
            .starts_with("The report could not be sent"));
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn with_timeout_overrides_the_timeout() {
        // with_timeout (lines 90-93) returns a config with the new timeout and
        // leaves the other fields intact.
        let cfg =
            TransportConfig::new("https://x.invalid/").with_timeout(Duration::from_millis(250));
        assert_eq!(cfg.timeout, Duration::from_millis(250));
        assert_eq!(cfg.endpoint, "https://x.invalid/");
        // Default max payload is preserved by the builder.
        assert_eq!(cfg.max_payload_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn lean_send_to_closed_port_returns_failed_not_err() {
        // send() (lines 158-171) builds the hardened agent (lines 129-136) and
        // POSTs. Pointing at a closed local port makes ureq return Err, which the
        // backend maps to Ok(SendOutcome::Failed(reason)) — never a panic, never
        // a fake Sent. Port 1 is the well-known unroutable/closed port.
        let backend = LeanPipelineBackend::new(
            TransportConfig::new("http://127.0.0.1:1/").with_timeout(Duration::from_millis(500)),
        );
        let report = Report::crash("panic at <HOME>/x.rs:1");
        let consent = ConsentToken::granted();
        let outcome = backend.send(&report, &consent).unwrap();
        match outcome {
            SendOutcome::Failed(reason) => {
                // The reason is non-identifying: it carries no URL/host, only a
                // transport-class token from transport_reason().
                assert!(!reason.contains("127.0.0.1"), "endpoint leaked: {reason}");
                assert!(!reason.is_empty());
            }
            SendOutcome::Sent => panic!("a send to a closed port must not claim Sent"),
        }
    }

    #[test]
    fn lean_send_oversize_payload_is_payload_too_large_before_network() {
        // The size cap is enforced in build_payload before any network touch, so
        // send() surfaces PayloadTooLarge (the early-return at line 159 via `?`).
        let backend = LeanPipelineBackend::new(
            TransportConfig::new("http://127.0.0.1:1/").with_max_payload_bytes(8),
        );
        let report = Report::crash("x".repeat(10_000));
        let consent = ConsentToken::granted();
        let err = backend.send(&report, &consent).unwrap_err();
        match err {
            SendError::PayloadTooLarge { actual, cap } => {
                assert!(actual > cap);
                assert_eq!(cap, 8);
            }
            SendError::Transport(_) => panic!("oversize must fail before the network"),
        }
    }

    #[test]
    fn sentry_stub_oversize_payload_is_payload_too_large() {
        // SentryStubBackend::send (lines 199-202): the same size cap is enforced
        // on the stub path, proving wire-format parity for the reject case.
        let stub = SentryStubBackend::new(
            TransportConfig::new("https://sentry.invalid/").with_max_payload_bytes(16),
        );
        let report = Report::crash("y".repeat(50_000));
        let consent = ConsentToken::granted();
        let err = stub.send(&report, &consent).unwrap_err();
        match err {
            SendError::PayloadTooLarge { actual, cap } => {
                assert!(actual > 16);
                assert_eq!(cap, 16);
            }
            SendError::Transport(_) => panic!("stub oversize must be PayloadTooLarge"),
        }
    }

    #[test]
    fn transport_reason_maps_status_code_arm() {
        // transport_reason (lines 230-231): a real HTTP error status maps to the
        // non-identifying "http status {code}" token. We stand up a one-shot
        // local server that returns 500, point the backend at it, and assert the
        // Failed reason names the status class (and never the host/URL).
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Fully drain the client's request (headers + Content-Length body)
                // BEFORE replying. A partial read (e.g. a single fixed buffer) lets
                // the server close mid-write, which ureq surfaces as a generic
                // transport/IO error instead of a clean StatusCode(500) — the
                // flaky failure this drain fixes. We read until we have seen the
                // end-of-headers and consumed the declared body length.
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut raw = Vec::new();
                let mut chunk = [0u8; 4096];
                let mut content_length: Option<usize> = None;
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            raw.extend_from_slice(&chunk[..n]);
                            if content_length.is_none() {
                                if let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n")
                                {
                                    let head = String::from_utf8_lossy(&raw[..hdr_end]);
                                    content_length = head
                                        .lines()
                                        .find_map(|l| {
                                            let (k, v) = l.split_once(':')?;
                                            k.trim()
                                                .eq_ignore_ascii_case("content-length")
                                                .then(|| v.trim().parse::<usize>().ok())
                                                .flatten()
                                        })
                                        .or(Some(0));
                                }
                            }
                            if let Some(clen) = content_length {
                                if let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n")
                                {
                                    if raw.len() >= hdr_end + 4 + clen {
                                        break; // full request drained
                                    }
                                }
                            }
                        }
                        Err(_) => break, // timeout/closed — drained what we could
                    }
                }
                let body = "err";
                let resp = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });

        let backend = LeanPipelineBackend::new(
            TransportConfig::new(format!("http://127.0.0.1:{port}/"))
                .with_timeout(Duration::from_secs(5)),
        );
        let report = Report::crash("panic");
        let consent = ConsentToken::granted();
        let outcome = backend.send(&report, &consent).unwrap();
        handle.join().ok();
        match outcome {
            SendOutcome::Failed(reason) => {
                // ureq 3.x defaults to http_status_as_error, so a 500 surfaces as
                // Error::StatusCode → the plain "server rejected it" class copy
                // (WS-016): no status NUMBER, no host/URL.
                assert_eq!(
                    reason,
                    "The report could not be delivered (server rejected it); it will be retried later.",
                    "got: {reason}"
                );
                assert!(!reason.contains("500"), "raw status code leaked: {reason}");
                assert!(!reason.contains("127.0.0.1"), "host leaked: {reason}");
            }
            SendOutcome::Sent => panic!("a 500 response must not claim Sent"),
        }
    }

    #[test]
    fn transport_reason_maps_timeout_arm() {
        // transport_reason (line 232): a server that accepts the connection but
        // never responds trips the global timeout, which maps to the typeless
        // "timeout" token. A very short with_timeout makes this deterministic.
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            // Accept and then hold the connection open without replying so the
            // client's global timeout fires.
            if let Ok((stream, _)) = listener.accept() {
                std::thread::sleep(Duration::from_millis(800));
                drop(stream);
            }
        });

        let backend = LeanPipelineBackend::new(
            TransportConfig::new(format!("http://127.0.0.1:{port}/"))
                .with_timeout(Duration::from_millis(150)),
        );
        let report = Report::crash("panic");
        let consent = ConsentToken::granted();
        let outcome = backend.send(&report, &consent).unwrap();
        handle.join().ok();
        match outcome {
            SendOutcome::Failed(reason) => {
                // WS-017: plain timeout copy with a retry expectation, never the
                // bare "timeout" token.
                assert_eq!(
                    reason, "Sending the report timed out; it will be retried later.",
                    "expected the plain timeout class, got: {reason}"
                );
            }
            SendOutcome::Sent => panic!("a stalled server must not claim Sent"),
        }
    }
}
