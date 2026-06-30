//! Tier-A submission wiring (the `tor` feature).
//!
//! The truly-anonymous tier needs truly-anonymous *transport*: a STAR message
//! removes the per-user **identifier**, but the **network** still sees the
//! client IP unless the report travels over Tor. So Tier-A submits its STAR
//! message over `itasha-report-transport-tor`'s [`TorOnionTransport`] — the same
//! Arti v3-onion `IngestBackend` Tier-B uses, giving sender-anonymity by
//! construction. Content-anonymity (STAR, no identifier) + sender-anonymity
//! (Tor, no IP) together are what make Tier-A honestly "anonymous".
//!
//! ## How a STAR message rides the existing transport
//!
//! The transport's [`IngestBackend`] sends a
//! [`itasha_report_core::report::Report`] (serialized to a Sentry envelope). A
//! STAR message is opaque bytes, so we wrap it as a single **attachment** on a
//! minimal [`Report`] tagged with the aggregate content-type. The transport then
//! spools + pads + jitters + POSTs it over Tor exactly like any other report —
//! no transport change. The server-side Tier-A collector pulls the
//! `application/x-w1tn3ss-star` attachment back out and feeds it to the STAR
//! aggregation server.
//!
//! ## Independence from Tier-B
//!
//! This path is gated by [`AggregateConsentToken`] (Tier-A's OWN consent),
//! NEVER by Tier-B's crash-report / manual-issue modes. A Tier-A submission
//! carries no event text, no metadata `extra`, no minidump — only the opaque
//! STAR message. The two tiers share the transport crate but nothing else.

use itasha_report_core::backend::{IngestBackend, SendError, SendOutcome};
use itasha_report_core::consent::ConsentToken;
use itasha_report_core::report::{Attachment, Report, Stream};

use crate::consent::AggregateConsentToken;
use crate::measurement::AggregateMeasurement;
use crate::star::{StarError, StarProducer};

/// The attachment name + content-type the STAR message rides under, so the
/// server-side Tier-A collector can distinguish it from a Tier-B payload.
pub const STAR_ATTACHMENT_NAME: &str = "w1tn3ss-star";

/// The content-type of the opaque STAR message attachment.
pub const STAR_CONTENT_TYPE: &str = "application/x-w1tn3ss-star";

/// Errors submitting a Tier-A measurement.
#[derive(Debug)]
pub enum SubmitError {
    /// The STAR message could not be produced.
    Star(StarError),
    /// The transport failed to accept the message.
    Transport(SendError),
}

impl std::fmt::Display for SubmitError {
    // No internal tier/protocol jargon ("tier-a", "star") and no inner error
    // interpolation. The inner error stays on the variant for a host-side log
    // toggle.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitError::Star(_) => {
                f.write_str("The anonymous signal could not be prepared and was not sent.")
            }
            SubmitError::Transport(_) => f.write_str(
                "The anonymous signal could not be sent right now; it will be retried later.",
            ),
        }
    }
}

impl std::error::Error for SubmitError {}

impl From<StarError> for SubmitError {
    fn from(e: StarError) -> Self {
        SubmitError::Star(e)
    }
}

impl From<SendError> for SubmitError {
    fn from(e: SendError) -> Self {
        SubmitError::Transport(e)
    }
}

/// Wrap an opaque STAR message-bytes blob as a minimal [`Report`] the transport
/// can carry. The report has NO event text and NO metadata — only the opaque
/// STAR attachment. It is tagged [`Stream::CrashReports`] solely so the envelope
/// serializer has a stream; the operator never reads an `event` item because the
/// only item is the opaque STAR attachment (the lean envelope's `event` item
/// here carries an empty body + empty allowlisted metadata).
#[must_use]
pub fn star_message_report(star_bytes: Vec<u8>) -> Report {
    Report {
        stream: Stream::CrashReports,
        // No human-readable title/body — a Tier-A submission is pure signal.
        title: String::new(),
        body: String::new(),
        metadata: Vec::new(),
        attachments: vec![Attachment {
            name: STAR_ATTACHMENT_NAME.to_string(),
            content_type: STAR_CONTENT_TYPE.to_string(),
            bytes: star_bytes,
        }],
    }
}

/// Submit a Tier-A measurement over the given anonymous transport.
///
/// Flow: produce the STAR message (`producer`) → wrap it as an opaque report →
/// hand it to the transport's [`IngestBackend`] (which spools it for anonymous
/// Tor delivery). Requires BOTH:
///
/// * an [`AggregateConsentToken`] — Tier-A's own consent (the user opted the
///   aggregate stream in); and
/// * the transport's [`ConsentToken`] — the per-submission consent the
///   `IngestBackend` contract requires.
///
/// The double-token shape is deliberate: it keeps Tier-A's stream consent
/// (`AggregateConsentToken`) distinct from the transport's per-send consent, so
/// neither can be satisfied by the other's grant.
pub fn submit_over_transport<B: IngestBackend>(
    producer: &StarProducer,
    measurement: &AggregateMeasurement,
    transport: &B,
    _aggregate_consent: &AggregateConsentToken,
    send_consent: &ConsentToken,
) -> Result<SendOutcome, SubmitError> {
    let star_bytes = producer.produce_bytes(measurement)?;
    let report = star_message_report(star_bytes);
    Ok(transport.send(&report, send_consent)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measurement::AggregateMeasurement;
    use crate::star::StarProducer;

    /// WS-034/035: `SubmitError` Display carries no internal tier/protocol jargon
    /// ("tier-a", "star") and never interpolates the inner error.
    #[test]
    fn submit_error_display_is_plain_and_jargon_free() {
        let star = SubmitError::Star(StarError::Generate("0xdead inner".to_string()));
        let star_shown = format!("{star}");
        assert_eq!(
            star_shown,
            "The anonymous signal could not be prepared and was not sent."
        );
        let transport = SubmitError::Transport(SendError::Transport(
            "os error 2 at /home/jane/sock".to_string(),
        ));
        let transport_shown = format!("{transport}");
        assert_eq!(
            transport_shown,
            "The anonymous signal could not be sent right now; it will be retried later."
        );
        for shown in [&star_shown, &transport_shown] {
            let lower = shown.to_lowercase();
            for needle in [
                "tier-a",
                "star error",
                "transport error",
                "0xdead",
                "os error",
            ] {
                assert!(
                    !lower.contains(needle),
                    "jargon/inner detail leaked: {shown}"
                );
            }
            assert!(!shown.contains('/'), "path separator leaked: {shown}");
        }
    }

    fn measurement() -> AggregateMeasurement {
        AggregateMeasurement::new(
            "f".repeat(64),
            &[("app_version".to_string(), "1.0.0".to_string())],
        )
    }

    #[test]
    fn star_report_carries_only_the_opaque_attachment() {
        let report = star_message_report(vec![1, 2, 3, 4]);
        assert!(report.title.is_empty());
        assert!(report.body.is_empty());
        assert!(report.metadata.is_empty());
        assert_eq!(report.attachments.len(), 1);
        assert_eq!(report.attachments[0].content_type, STAR_CONTENT_TYPE);
        assert_eq!(report.attachments[0].bytes, vec![1, 2, 3, 4]);
    }

    /// A fake transport that records what it was asked to send, so the
    /// submission wiring can be tested without a live `.onion`.
    #[derive(Default)]
    struct RecordingTransport {
        last: std::sync::Mutex<Option<Report>>,
    }

    impl IngestBackend for RecordingTransport {
        fn send(&self, report: &Report, _consent: &ConsentToken) -> Result<SendOutcome, SendError> {
            *self.last.lock().unwrap() = Some(report.clone());
            Ok(SendOutcome::Sent)
        }
    }

    #[test]
    fn submit_produces_star_and_hands_it_to_transport() {
        let producer = StarProducer::new("2026-W25").unwrap();
        let transport = RecordingTransport::default();
        let outcome = submit_over_transport(
            &producer,
            &measurement(),
            &transport,
            &AggregateConsentToken::granted(),
            &ConsentToken::granted(),
        )
        .unwrap();
        assert_eq!(outcome, SendOutcome::Sent);

        // The transport received exactly one opaque STAR attachment, no text.
        let sent = transport.last.lock().unwrap().clone().unwrap();
        assert_eq!(sent.attachments.len(), 1);
        assert_eq!(sent.attachments[0].content_type, STAR_CONTENT_TYPE);
        assert!(sent.body.is_empty());
        // The STAR message round-trips out of the attachment.
        let back = sta_rs::Message::from_bytes(&sent.attachments[0].bytes);
        assert!(back.is_some(), "attachment carries a valid STAR message");
    }

    #[test]
    fn submission_is_consent_gated_by_both_tokens() {
        // The signature requires BOTH an AggregateConsentToken (stream consent)
        // AND a ConsentToken (per-send consent) — there is no path with neither.
        let producer = StarProducer::new("ep").unwrap();
        let transport = RecordingTransport::default();
        let _ = submit_over_transport(
            &producer,
            &measurement(),
            &transport,
            &AggregateConsentToken::granted(),
            &ConsentToken::granted(),
        )
        .unwrap();
    }

    /// A transport that always fails, to exercise the `SendError → SubmitError`
    /// conversion that `RecordingTransport` (always-`Ok`) cannot reach.
    struct FailingTransport;

    impl IngestBackend for FailingTransport {
        fn send(
            &self,
            _report: &Report,
            _consent: &ConsentToken,
        ) -> Result<SendOutcome, SendError> {
            Err(SendError::Transport("simulated onion down".to_string()))
        }
    }

    #[test]
    fn transport_failure_surfaces_as_submit_error_transport() {
        let producer = StarProducer::new("2026-W25").unwrap();
        let err = submit_over_transport(
            &producer,
            &measurement(),
            &FailingTransport,
            &AggregateConsentToken::granted(),
            &ConsentToken::granted(),
        )
        .unwrap_err();

        // The `?` on `transport.send(...)` routes the SendError through
        // `From<SendError> for SubmitError` into the Transport variant…
        assert!(
            matches!(err, SubmitError::Transport(SendError::Transport(_))),
            "expected SubmitError::Transport, got {err:?}"
        );
        // …and the Display impl surfaces a fixed, non-identifying class string:
        // no tier/protocol jargon and — crucially — the inner error reason is
        // NEVER interpolated, so a transport-layer detail cannot leak to the host.
        let shown = err.to_string();
        assert_eq!(
            shown, "The anonymous signal could not be sent right now; it will be retried later.",
            "got {shown:?}"
        );
        assert!(
            !shown.contains("simulated onion down"),
            "inner transport detail leaked to the host surface: {shown:?}"
        );
    }
}
