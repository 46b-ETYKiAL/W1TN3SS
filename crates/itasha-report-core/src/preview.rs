//! The preview API.
//!
//! Before any send, the host shows the user the **literal, editable Tier-1 text
//! payload** via [`Preview`]. The user can read exactly what would be
//! transmitted and redact spans they do not wish to share. Tier-2 binary
//! attachments are NOT previewable (they are opaque) — the preview lists their
//! presence and size so the user can decide on the heightened-consent tier.

use crate::report::Report;

/// A previewable rendering of a report's Tier-1 text payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    text: String,
    attachment_summary: Vec<String>,
}

impl Preview {
    /// Build a preview of a (already-sanitized) report.
    #[must_use]
    pub fn of(report: &Report) -> Self {
        let mut text = String::new();
        text.push_str(&report.title);
        text.push('\n');
        text.push('\n');
        text.push_str(&report.body);
        if !report.metadata.is_empty() {
            text.push_str("\n\n--- metadata ---\n");
            for (k, v) in &report.metadata {
                text.push_str(&format!("{k}: {v}\n"));
            }
        }

        let attachment_summary = report
            .attachments
            .iter()
            .map(|a| {
                format!(
                    "{} ({}, {} bytes, not previewable)",
                    a.name,
                    a.content_type,
                    a.bytes.len()
                )
            })
            .collect();

        Self {
            text,
            attachment_summary,
        }
    }

    /// The literal editable text the user sees and may modify before consenting.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Human-readable summaries of the opaque (non-previewable) Tier-2 attachments.
    #[must_use]
    pub fn attachment_summary(&self) -> &[String] {
        &self.attachment_summary
    }

    /// Replace the literal substring `span` with `replacement` everywhere it
    /// occurs in the preview text — the user-driven redaction primitive.
    /// Returns `self` for chaining.
    #[must_use]
    pub fn redact(mut self, span: &str, replacement: &str) -> Self {
        if !span.is_empty() {
            self.text = self.text.replace(span, replacement);
        }
        self
    }

    /// Replace `span` with the default `[redacted]` marker.
    #[must_use]
    pub fn redact_default(self, span: &str) -> Self {
        self.redact(span, "[redacted]")
    }

    /// Build a [`Report`] carrying the (possibly user-edited / redacted) preview
    /// text back into the body, ready to spool/send. Metadata and attachments
    /// are preserved from the original report.
    #[must_use]
    pub fn into_edited_report(self, original: &Report) -> Report {
        // The preview's editable surface is the body text; reconstruct a report
        // whose body IS exactly what the user approved.
        let body = self
            .text
            .split_once("\n\n")
            .map(|(_title, rest)| rest)
            .unwrap_or(&self.text)
            .split("\n\n--- metadata ---\n")
            .next()
            .unwrap_or(&self.text)
            .to_string();
        Report {
            stream: original.stream,
            title: original.title.clone(),
            body,
            metadata: original.metadata.clone(),
            attachments: original.attachments.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Attachment, Report, Stream};

    #[test]
    fn preview_returns_literal_text() {
        let r = Report::manual_issue("My title", "the body text");
        let p = Preview::of(&r);
        assert!(p.text().contains("My title"));
        assert!(p.text().contains("the body text"));
    }

    #[test]
    fn preview_includes_metadata() {
        let r = Report::crash("panic").with_metadata("os", "linux");
        let p = Preview::of(&r);
        assert!(p.text().contains("os: linux"));
    }

    #[test]
    fn redaction_removes_span() {
        let r = Report::manual_issue("issue", "my email is ada@example.com please");
        let p = Preview::of(&r).redact("ada@example.com", "[email]");
        assert!(!p.text().contains("ada@example.com"));
        assert!(p.text().contains("[email]"));
    }

    #[test]
    fn redact_default_uses_marker() {
        let r = Report::manual_issue("issue", "secret hunter2 here");
        let p = Preview::of(&r).redact_default("hunter2");
        assert!(p.text().contains("[redacted]"));
        assert!(!p.text().contains("hunter2"));
    }

    #[test]
    fn attachments_are_listed_not_inlined() {
        let r = Report {
            stream: Stream::CrashReports,
            title: "crash".into(),
            body: "panic".into(),
            metadata: vec![],
            attachments: vec![Attachment {
                name: "minidump".into(),
                content_type: "application/x-minidump".into(),
                bytes: vec![0u8; 4096],
            }],
        };
        let p = Preview::of(&r);
        assert_eq!(p.attachment_summary().len(), 1);
        assert!(p.attachment_summary()[0].contains("not previewable"));
        assert!(p.attachment_summary()[0].contains("4096 bytes"));
        // Binary bytes never appear in the previewable text.
        assert!(!p.text().contains("minidump"));
    }

    #[test]
    fn redact_with_empty_span_is_a_noop() {
        // redact (line 72): an empty `span` must be a no-op — `replace("", x)`
        // would otherwise splice the replacement between every char.
        let r = Report::manual_issue("title", "untouched body");
        let before = Preview::of(&r);
        let after = before.clone().redact("", "[x]");
        assert_eq!(after.text(), before.text());
        assert!(!after.text().contains("[x]"));
    }

    #[test]
    fn edited_preview_round_trips_into_report_body() {
        let r = Report::manual_issue("title", "original body");
        let edited = Preview::of(&r)
            .redact("original", "scrubbed")
            .into_edited_report(&r);
        assert!(edited.body.contains("scrubbed"));
        assert!(!edited.body.contains("original"));
        assert_eq!(edited.stream, r.stream);
    }
}
