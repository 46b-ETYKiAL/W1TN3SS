//! Spool + Sentry-envelope emission for a captured minidump.
//!
//! This module is the bridge from a written minidump file to the
//! `itasha-report-core` contracts (plan-731): it builds a [`Report`] carrying
//! the minidump as an opaque Tier-2 attachment, persists it to the LOCAL spool
//! (never auto-sent), and produces the Sentry minidump-[`Envelope`] the host
//! transmits **after** Tier-2 consent.
//!
//! The cardinal guarantee: nothing here transmits. There is no network code in
//! this crate at all — [`spool_minidump`] writes to disk; [`build_envelope`]
//! returns bytes the host hands to `itasha-report-core`'s `IngestBackend`.

use std::path::{Path, PathBuf};

use itasha_report_core::envelope::Envelope;
use itasha_report_core::report::{Attachment, Report};
use itasha_report_core::spool::{Spool, SpoolError};

use crate::consent::Tier2ConsentToken;

/// The MIME type used for the minidump attachment part (the Sentry-recognised
/// minidump content type; the envelope emitter tags it `event.minidump`).
pub const MINIDUMP_CONTENT_TYPE: &str = "application/x-minidump";

/// The logical attachment name. `itasha-report-core`'s envelope emitter treats
/// an attachment named `"minidump"` (or this content-type) as `event.minidump`.
pub const MINIDUMP_ATTACHMENT_NAME: &str = "minidump";

/// Build a Tier-2 crash [`Report`] carrying `minidump_bytes` as an opaque,
/// non-previewable attachment.
///
/// The report body is a short, non-identifying note (NOT the minidump content,
/// which is binary and never inlined as text). Metadata is caller-supplied and
/// already-sanitized key/values (e.g. `os`, `app_version`); this function adds
/// nothing identifying.
#[must_use]
pub fn build_crash_report(minidump_bytes: Vec<u8>, metadata: &[(String, String)]) -> Report {
    let mut report = Report::crash(
        "Native crash captured out-of-process. A minimized-memory minidump is attached.",
    );
    for (k, v) in metadata {
        report = report.with_metadata(k.clone(), v.clone());
    }
    report.attachments.push(Attachment {
        name: MINIDUMP_ATTACHMENT_NAME.to_string(),
        content_type: MINIDUMP_CONTENT_TYPE.to_string(),
        bytes: minidump_bytes,
    });
    report
}

/// Persist a captured minidump to the LOCAL spool (reusing
/// `itasha-report-core`'s budgeted, atomic spool). Returns the spooled report
/// path.
///
/// This NEVER transmits — it only writes to `<config_dir>/reports/`. The host
/// drains the spool and sends on Tier-2 consent.
///
/// # Errors
///
/// Returns a [`SpoolError`] if the spool directory or report file cannot be
/// written.
pub fn spool_minidump(
    config_dir: impl AsRef<Path>,
    minidump_bytes: Vec<u8>,
    metadata: &[(String, String)],
) -> Result<PathBuf, SpoolError> {
    let spool = Spool::open(config_dir)?;
    let report = build_crash_report(minidump_bytes, metadata);
    spool.enqueue(&report)
}

/// Build the Sentry minidump-[`Envelope`] for a spooled crash report.
///
/// Requires a [`Tier2ConsentToken`] — there is NO envelope-emit path without
/// heightened consent. The envelope's `event_id` is the token's ephemeral
/// per-capture nonce (NOT a stable device/install id), so the wire carries no
/// persistent identifier.
///
/// The returned [`Envelope`] is `itasha-report-core`'s type; the host serializes
/// it via [`Envelope::to_bytes`] and hands the bytes to the `IngestBackend`
/// transport. This function performs no I/O and no transmission.
#[must_use]
pub fn build_envelope(report: &Report, consent: &Tier2ConsentToken) -> Envelope {
    // The event_id is the ephemeral nonce — never a stable identifier.
    Envelope::from_report(report, Some(normalize_event_id(consent.nonce())))
}

/// Normalize an ephemeral nonce into a Sentry `event_id` (32 hex chars, no
/// dashes). Pads/truncates the hex-ish nonce deterministically; carries no
/// stable identity (the nonce itself is per-capture).
fn normalize_event_id(nonce: &str) -> String {
    let hex: String = nonce
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(32)
        .collect();
    // Pad to 32 chars with '0' so the id is well-formed even for a short nonce.
    format!("{hex:0<32}").chars().take(32).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use itasha_report_core::report::Stream;

    #[test]
    fn crash_report_carries_minidump_attachment_not_inlined_text() {
        let dump = vec![0u8, 1, 2, 3, b'\n', 255];
        let report = build_crash_report(dump.clone(), &[("os".into(), "windows".into())]);
        assert_eq!(report.stream, Stream::CrashReports);
        // The minidump bytes are an attachment, never inlined into the body text.
        assert!(!report.body.contains('\u{0}'));
        assert_eq!(report.attachments.len(), 1);
        assert_eq!(report.attachments[0].name, MINIDUMP_ATTACHMENT_NAME);
        assert_eq!(report.attachments[0].bytes, dump);
        assert_eq!(
            report.metadata,
            vec![("os".to_string(), "windows".to_string())]
        );
    }

    #[test]
    fn spool_minidump_writes_locally_and_round_trips() {
        let dir = std::env::temp_dir().join(format!(
            "w1tn3ss-emit-test-{}-{}",
            std::process::id(),
            crate::consent::Tier2ConsentToken::granted().nonce()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dump = vec![9u8; 128];
        let path = spool_minidump(&dir, dump.clone(), &[]).unwrap();
        assert!(path.exists());
        let spool = Spool::open(&dir).unwrap();
        let back = spool.load(&path).unwrap();
        assert_eq!(back.attachments[0].bytes, dump);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn envelope_event_id_is_ephemeral_nonce_not_stable_id() {
        let report = build_crash_report(vec![1, 2, 3], &[]);
        let token_a = Tier2ConsentToken::granted();
        let token_b = Tier2ConsentToken::granted();
        let env_a = build_envelope(&report, &token_a);
        let env_b = build_envelope(&report, &token_b);
        // Two captures of the identical report get DIFFERENT event_ids — the id
        // is per-capture, never a stable device/install fingerprint.
        assert_ne!(env_a.event_id, env_b.event_id);
        // Well-formed: 32 hex chars.
        let id = env_a.event_id.unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// `spool_minidump` propagates a `SpoolError` when the spool cannot be
    /// opened (emit.rs 68): pointing `config_dir` at a regular FILE makes
    /// `Spool::open`'s `create_dir_all("<file>/reports")` fail, so the `?` on the
    /// `Spool::open` line returns the error rather than spooling.
    #[test]
    fn spool_minidump_propagates_spool_open_error() {
        let base = std::env::temp_dir().join(format!(
            "w1tn3ss-emit-openfail-{}-{}",
            std::process::id(),
            crate::consent::Tier2ConsentToken::granted().nonce()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let config_file = base.join("config-is-a-file");
        std::fs::write(&config_file, b"not a directory").unwrap();

        let result = spool_minidump(&config_file, vec![1, 2, 3], &[]);
        assert!(
            result.is_err(),
            "spooling under a non-directory config path must error, not panic"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn envelope_round_trips_with_minidump_attachment() {
        let dump = vec![0u8, b'\n', 7, b'\n', 200, b'\n']; // newlines in binary
        let report = build_crash_report(dump.clone(), &[("app_version".into(), "0.1.0".into())]);
        let token = Tier2ConsentToken::granted();
        let env = build_envelope(&report, &token);
        let bytes = env.to_bytes();
        let back = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(env, back);
        // The minidump attachment survived and is tagged event.minidump.
        let att = back
            .items
            .iter()
            .find(|i| i.item_type == "attachment")
            .unwrap();
        assert_eq!(att.attachment_type.as_deref(), Some("event.minidump"));
        assert_eq!(att.payload, dump);
    }
}
