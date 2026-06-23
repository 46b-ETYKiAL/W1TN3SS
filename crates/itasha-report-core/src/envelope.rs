//! Sentry envelope wire serialization.
//!
//! The W1TN3SS client wire contract **is** the Sentry envelope format from day
//! one, so a future self-hosted Sentry ingests identical payloads with no
//! client change (the lean in-house pipeline ingests the same bytes today).
//!
//! ## Format
//!
//! A Sentry envelope is newline-delimited:
//!
//! ```text
//! { envelope headers, JSON }\n
//! { item headers, JSON }\n
//! ...item payload bytes...\n
//! { item headers, JSON }\n
//! ...item payload bytes...
//! ```
//!
//! Each item header carries at least a `type` and a `length` (byte length of
//! the payload that follows). We emit the `length` on every item so a strict
//! parser can read payloads without scanning for the next newline — this is the
//! robust, attachment-safe form (binary minidump bytes may themselves contain
//! newlines).
//!
//! Reference: Sentry "Envelopes" + "Minidump" ingestion docs (the
//! `event` item + `attachment` item with `attachment_type =
//! event.minidump`).

use serde::{Deserialize, Serialize};

use crate::e2e::SealedPayload;
use crate::report::{Report, Stream};

/// A single item within an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeItem {
    /// The item type (e.g. `"event"`, `"attachment"`).
    pub item_type: String,
    /// Optional `attachment_type` header (e.g. `"event.minidump"`).
    pub attachment_type: Option<String>,
    /// Optional filename header for attachment items.
    pub filename: Option<String>,
    /// Optional content-type header for attachment items.
    pub content_type: Option<String>,
    /// The raw payload bytes for this item.
    pub payload: Vec<u8>,
}

/// A Sentry envelope: a header object plus an ordered list of items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The `event_id` envelope header (a 32-char hex id, no dashes). This is a
    /// **per-event** id, NOT a stable device/install identifier.
    pub event_id: Option<String>,
    /// Ordered items.
    pub items: Vec<EnvelopeItem>,
}

/// Errors parsing an envelope from bytes.
#[derive(Debug)]
pub enum EnvelopeError {
    /// The envelope was empty or malformed at the structural level.
    Malformed(String),
    /// A header line was not valid JSON.
    Json(serde_json::Error),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::Malformed(m) => write!(f, "malformed envelope: {m}"),
            EnvelopeError::Json(e) => write!(f, "envelope json error: {e}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl From<serde_json::Error> for EnvelopeError {
    fn from(e: serde_json::Error) -> Self {
        EnvelopeError::Json(e)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EnvelopeHeader {
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ItemHeader {
    #[serde(rename = "type")]
    item_type: String,
    length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    attachment_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
}

impl Envelope {
    /// Build an envelope from a (already-sanitized) report.
    ///
    /// The report body + metadata become an `event` item (the Tier-1 text);
    /// each opaque attachment becomes an `attachment` item. A crash report's
    /// first minidump-typed attachment is tagged `attachment_type =
    /// event.minidump` so Sentry symbolicates it.
    ///
    /// Anonymity hardening #2 (gap D-4): the `extra` metadata is NOT a raw
    /// passthrough. It is filtered through the fail-closed allowlist
    /// [`crate::quasi::safe_fields`], which emits ONLY the pre-approved,
    /// COARSENED keys (`app_version`→minor, `os`→major.minor, `locale`→language)
    /// and DROPS every unknown key + the always-dropped quasi/direct identifiers
    /// (timezone, build-hash, argv, env, hostname, MAC, machine-GUID, the full
    /// module list, …). A future host that attaches a new metadata key cannot
    /// leak it to the wire by default — this is the structural fingerprint floor
    /// for the lean (non-sealed) path.
    #[must_use]
    pub fn from_report(report: &Report, event_id: Option<String>) -> Self {
        let safe = crate::quasi::safe_fields(&report.metadata);
        let event_json = serde_json::json!({
            "level": match report.stream {
                Stream::CrashReports => "error",
                Stream::ManualIssues => "info",
            },
            "message": report.title,
            "logentry": { "formatted": report.body },
            "extra": safe
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect::<serde_json::Map<_, _>>(),
        });
        let event_payload = serde_json::to_vec(&event_json).unwrap_or_default();

        let mut items = vec![EnvelopeItem {
            item_type: "event".to_string(),
            attachment_type: None,
            filename: None,
            content_type: Some("application/json".to_string()),
            payload: event_payload,
        }];

        for att in &report.attachments {
            let is_minidump =
                att.name == "minidump" || att.content_type == "application/x-minidump";
            items.push(EnvelopeItem {
                item_type: "attachment".to_string(),
                attachment_type: is_minidump.then(|| "event.minidump".to_string()),
                filename: Some(att.name.clone()),
                content_type: Some(att.content_type.clone()),
                payload: att.bytes.clone(),
            });
        }

        Self { event_id, items }
    }

    /// Build an envelope carrying an **E2E-sealed** payload as a single opaque
    /// `attachment` item.
    ///
    /// This is the privacy-keystone wire shape (hardening control #1): after the
    /// client scrubs + previews + seals the report via
    /// [`crate::e2e::seal_report`], the resulting [`SealedPayload`] rides inside
    /// the **same** Sentry envelope format as an opaque attachment
    /// (`attachment_type = "application/age-encrypted"`). The lean pipeline and
    /// a future self-hosted Sentry ingest the identical envelope unchanged — and
    /// neither can read the attachment, because only the developer private key
    /// decrypts it.
    ///
    /// No plaintext `event` item is emitted: the *whole* report (Tier-1 text +
    /// Tier-2 attachment bytes) is inside the ciphertext, so the operator stores
    /// only ciphertext. The event_id is still a per-report (non-stable) id.
    #[must_use]
    pub fn sealed(sealed: &SealedPayload, event_id: Option<String>) -> Self {
        let items = vec![EnvelopeItem {
            item_type: "attachment".to_string(),
            attachment_type: Some(SealedPayload::CONTENT_TYPE.to_string()),
            filename: Some(SealedPayload::ATTACHMENT_NAME.to_string()),
            content_type: Some(SealedPayload::CONTENT_TYPE.to_string()),
            payload: sealed.bytes().to_vec(),
        }];
        Self { event_id, items }
    }

    /// Recover the opaque [`SealedPayload`] from an envelope built by
    /// [`Envelope::sealed`] — the single `application/age-encrypted` attachment
    /// item. Returns `None` if the envelope carries no such item (e.g. a plain
    /// event envelope).
    ///
    /// This is what the developer triage tooling calls after pulling the
    /// envelope off the wire/store, before decrypting with the developer key.
    #[must_use]
    pub fn sealed_payload(&self) -> Option<SealedPayload> {
        self.items
            .iter()
            .find(|i| {
                i.item_type == "attachment"
                    && i.attachment_type.as_deref() == Some(SealedPayload::CONTENT_TYPE)
            })
            .map(|i| SealedPayload::from_bytes(i.payload.clone()))
    }

    /// Serialize to the newline-delimited Sentry envelope wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let header = EnvelopeHeader {
            event_id: self.event_id.clone(),
        };
        // serde_json on a struct with only Option fields never fails.
        out.extend_from_slice(&serde_json::to_vec(&header).unwrap_or_else(|_| b"{}".to_vec()));
        out.push(b'\n');

        for item in &self.items {
            let ih = ItemHeader {
                item_type: item.item_type.clone(),
                length: item.payload.len(),
                attachment_type: item.attachment_type.clone(),
                filename: item.filename.clone(),
                content_type: item.content_type.clone(),
            };
            out.extend_from_slice(&serde_json::to_vec(&ih).unwrap_or_else(|_| b"{}".to_vec()));
            out.push(b'\n');
            out.extend_from_slice(&item.payload);
            out.push(b'\n');
        }
        out
    }

    /// Parse a Sentry envelope from wire bytes (the inverse of [`Envelope::to_bytes`]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        // First line: envelope header.
        let nl = bytes
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| EnvelopeError::Malformed("missing envelope header newline".into()))?;
        let header: EnvelopeHeader = serde_json::from_slice(&bytes[..nl])?;

        let mut items = Vec::new();
        let mut pos = nl + 1;
        while pos < bytes.len() {
            // Item header line.
            let rel = bytes[pos..]
                .iter()
                .position(|&b| b == b'\n')
                .ok_or_else(|| EnvelopeError::Malformed("missing item header newline".into()))?;
            let header_end = pos + rel;
            let ih: ItemHeader = serde_json::from_slice(&bytes[pos..header_end])?;
            let payload_start = header_end + 1;
            let payload_end = payload_start + ih.length;
            if payload_end > bytes.len() {
                return Err(EnvelopeError::Malformed(format!(
                    "item payload length {} exceeds remaining bytes",
                    ih.length
                )));
            }
            let payload = bytes[payload_start..payload_end].to_vec();
            items.push(EnvelopeItem {
                item_type: ih.item_type,
                attachment_type: ih.attachment_type,
                filename: ih.filename,
                content_type: ih.content_type,
                payload,
            });
            // Skip the trailing newline after the payload, if present.
            pos = payload_end;
            if pos < bytes.len() && bytes[pos] == b'\n' {
                pos += 1;
            }
        }

        Ok(Self {
            event_id: header.event_id,
            items,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Attachment, Report};

    #[test]
    fn event_only_envelope_round_trips() {
        let report = Report::crash("thread 'main' panicked at <HOME>/main.rs:1")
            .with_metadata("os", "linux");
        let env = Envelope::from_report(&report, Some("a".repeat(32)));
        let bytes = env.to_bytes();
        let back = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(env, back);
        assert_eq!(back.items.len(), 1);
        assert_eq!(back.items[0].item_type, "event");
    }

    #[test]
    fn lean_envelope_allowlists_and_coarsens_metadata() {
        // Anonymity hardening #2: on the lean (plaintext) path the `extra`
        // metadata must be the fail-closed allowlist output — coarsened
        // allowlisted keys only, every unknown/quasi-identifier key dropped.
        let report = Report::crash("panic")
            .with_metadata("app_version", "1.4.37-rc2+sha")
            .with_metadata("os", "Windows 11 26100.1234")
            .with_metadata("locale", "en-US")
            .with_metadata("timezone", "America/New_York")
            .with_metadata("hostname", "ada-laptop")
            .with_metadata("modules", "ntdll.dll,evil-av.dll")
            .with_metadata("brand_new_field", "leak me");
        let env = Envelope::from_report(&report, Some("e".repeat(32)));
        let wire = String::from_utf8(env.to_bytes()).unwrap();

        // Coarsened allowlisted values are present.
        assert!(wire.contains("\"app_version\":\"1.4\""));
        assert!(wire.contains("\"os\":\"Windows 11\""));
        assert!(wire.contains("\"locale\":\"en\""));
        // The exact patch/build/region must be gone.
        assert!(!wire.contains("1.4.37"));
        assert!(!wire.contains("26100"));
        assert!(!wire.contains("en-US"));
        // Every dropped quasi/unknown key + value is absent from the wire.
        for needle in [
            "timezone",
            "America",
            "hostname",
            "ada-laptop",
            "modules",
            "evil-av",
            "brand_new_field",
            "leak me",
        ] {
            assert!(
                !wire.contains(needle),
                "dropped content leaked to wire: {needle}"
            );
        }
    }

    #[test]
    fn minidump_attachment_round_trips_with_embedded_newlines() {
        // Binary minidump bytes containing newlines must survive — this is why
        // the item header carries an explicit `length`.
        let dump = vec![0u8, b'\n', 1, 2, b'\n', 255, b'\n'];
        let report = Report {
            stream: Stream::CrashReports,
            title: "crash".into(),
            body: "panic".into(),
            metadata: vec![],
            attachments: vec![Attachment {
                name: "minidump".into(),
                content_type: "application/x-minidump".into(),
                bytes: dump.clone(),
            }],
        };
        let env = Envelope::from_report(&report, Some("b".repeat(32)));
        let bytes = env.to_bytes();
        let back = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(env, back);
        let att = &back.items[1];
        assert_eq!(att.item_type, "attachment");
        assert_eq!(att.attachment_type.as_deref(), Some("event.minidump"));
        assert_eq!(att.payload, dump);
    }

    #[test]
    fn wire_starts_with_header_json_line() {
        let report = Report::crash("x");
        let env = Envelope::from_report(&report, Some("c".repeat(32)));
        let bytes = env.to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        let first_line = text.lines().next().unwrap();
        // The first line is the envelope header JSON object carrying event_id.
        assert!(first_line.starts_with('{'));
        assert!(first_line.contains("event_id"));
    }

    #[test]
    fn item_header_carries_type_and_length() {
        let report = Report::crash("boom");
        let env = Envelope::from_report(&report, None);
        let bytes = env.to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        let item_header = text.lines().nth(1).unwrap();
        assert!(item_header.contains("\"type\":\"event\""));
        assert!(item_header.contains("\"length\":"));
    }

    #[test]
    fn malformed_input_errors_not_panics() {
        assert!(Envelope::from_bytes(b"no newline here").is_err());
        assert!(Envelope::from_bytes(b"").is_err());
    }

    // ---- E2E sealed-payload envelope contract (hardening control #1, T1.2) ----

    use crate::e2e::{open_report, seal_report, DeveloperIdentity, SealedPayload};

    fn test_identity() -> DeveloperIdentity {
        // Fresh in-process identity; the secret never lands in the repo. Build
        // the developer identity from its public recipient + secret via the
        // shared e2e test seam (round-tripping through the string forms).
        crate::e2e::testutil::generated_identity()
    }

    #[test]
    fn sealed_payload_rides_inside_envelope_and_round_trips() {
        let id = test_identity();
        let recipient = id.to_recipient();

        // A crash report with an opaque minidump attachment.
        let report = Report {
            stream: Stream::CrashReports,
            title: "crash".into(),
            body: "thread 'main' panicked at <HOME>/main.rs:1".into(),
            metadata: vec![("os".into(), "linux".into())],
            attachments: vec![Attachment {
                name: "minidump".into(),
                content_type: "application/x-minidump".into(),
                bytes: vec![0u8, b'\n', 1, 2, b'\n', 255],
            }],
        };

        // CLIENT: scrub+preview happened upstream; seal, then wrap in envelope.
        let sealed = seal_report(&report, &[recipient]).unwrap();
        let env = Envelope::sealed(&sealed, Some("d".repeat(32)));

        // WIRE: the envelope round-trips through the Sentry wire format unchanged.
        let bytes = env.to_bytes();
        let back = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(
            env, back,
            "sealed envelope must survive the wire round-trip"
        );

        // It carries exactly one opaque age-encrypted attachment, no event item.
        assert_eq!(back.items.len(), 1);
        assert_eq!(back.items[0].item_type, "attachment");
        assert_eq!(
            back.items[0].attachment_type.as_deref(),
            Some(SealedPayload::CONTENT_TYPE)
        );

        // DEVELOPER: pull the sealed payload back out and decrypt it.
        let recovered_sealed = back
            .sealed_payload()
            .expect("envelope carries a sealed payload");
        let opened = open_report(&recovered_sealed, &id).unwrap();
        assert_eq!(opened, report, "developer recovers the exact sealed report");
    }

    #[test]
    fn operator_sees_only_ciphertext_in_sealed_envelope() {
        let id = test_identity();
        let report = Report::manual_issue("title", "secret note WIREMARKER body");
        let sealed = seal_report(&report, &[id.to_recipient()]).unwrap();
        let env = Envelope::sealed(&sealed, None);
        let wire = env.to_bytes();
        // The operator stores these wire bytes; the plaintext must not appear.
        assert!(!contains_subslice(&wire, b"WIREMARKER"));
        assert!(!contains_subslice(&wire, b"secret note"));
    }

    #[test]
    fn plain_event_envelope_has_no_sealed_payload() {
        // A non-sealed envelope must report no sealed payload (the discriminator
        // is the application/age-encrypted attachment_type).
        let report = Report::crash("plain");
        let env = Envelope::from_report(&report, None);
        assert!(env.sealed_payload().is_none());
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn envelope_error_display_renders_both_arms() {
        // EnvelopeError Display (lines 69-74): the Malformed arm names the detail.
        let malformed = EnvelopeError::Malformed("missing newline".into());
        assert_eq!(
            format!("{malformed}"),
            "malformed envelope: missing newline"
        );
        let dyn_err: &dyn std::error::Error = &malformed;
        assert!(dyn_err.to_string().starts_with("malformed envelope:"));

        // The Json arm: a real serde_json error wraps via From (lines 80-82) and
        // formats with the "envelope json error:" prefix.
        let json_err: serde_json::Error = serde_json::from_str::<EnvelopeHeader>("{").unwrap_err();
        let wrapped: EnvelopeError = json_err.into();
        let shown = format!("{wrapped}");
        assert!(shown.starts_with("envelope json error:"), "got: {shown}");
        match wrapped {
            EnvelopeError::Json(_) => {}
            EnvelopeError::Malformed(_) => panic!("From must yield the Json variant"),
        }
    }

    #[test]
    fn manual_issue_event_level_is_info() {
        // from_report (line 127): a ManualIssues-stream report serializes the
        // event `level` as "info" (the crash path is "error"). This exercises the
        // ManualIssues match arm that the crash-only tests never reached.
        let report = Report::manual_issue("feedback", "the button is misaligned");
        let env = Envelope::from_report(&report, None);
        let wire = String::from_utf8(env.to_bytes()).unwrap();
        assert!(wire.contains("\"level\":\"info\""), "got: {wire}");
        assert!(!wire.contains("\"level\":\"error\""));
    }

    #[test]
    fn from_bytes_rejects_item_length_exceeding_buffer() {
        // from_bytes (lines 254-258): an item header claiming a payload longer
        // than the remaining bytes is malformed and errors (never panics / never
        // over-reads).
        let bytes = b"{}\n{\"type\":\"event\",\"length\":9999}\nshort";
        let err = Envelope::from_bytes(bytes).unwrap_err();
        match err {
            EnvelopeError::Malformed(m) => {
                assert!(m.contains("exceeds remaining bytes"), "got: {m}");
            }
            EnvelopeError::Json(_) => panic!("expected a Malformed length error"),
        }
    }

    #[test]
    fn from_bytes_handles_missing_item_header_newline() {
        // from_bytes: an item region with no terminating newline after the header
        // is malformed (the `position(... '\n')` ok_or path).
        let bytes = b"{}\n{\"type\":\"event\",\"length\":0}";
        let err = Envelope::from_bytes(bytes).unwrap_err();
        assert!(matches!(err, EnvelopeError::Malformed(_)));
    }
}
