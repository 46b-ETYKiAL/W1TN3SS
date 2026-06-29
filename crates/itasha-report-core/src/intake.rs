//! Manual-issue intake helpers.
//!
//! These build the deep links the host opens when a user files an issue:
//!
//! * a prefilled **GitHub Issue-Form** URL (percent-encoded title / body /
//!   template / labels),
//! * a **`mailto:`** link to a support alias,
//! * a **clipboard fallback** for the URL-too-long case (GitHub returns HTTP
//!   414 on very long query strings — the [`GITHUB_URL_LENGTH_THRESHOLD`]
//!   constant names the safe ceiling),
//! * a thin [`launch`] wrapper over the `webbrowser` crate.
//!
//! Nothing here transmits anything to our infrastructure — they hand off to the
//! user's browser / mail client. The intake helpers honour
//! `S4F3_DISABLE_TELEMETRY=1` by never emitting counters.

/// The conservative URL-length ceiling for a prefilled GitHub Issue-Form deep
/// link. GitHub (and intermediate proxies) reject very long query strings with
/// **HTTP 414 URI Too Long**; ~2000 chars is the broadly-safe ceiling (the
/// VS Code clipboard-fallback pattern uses the same threshold). Above this,
/// callers should use [`clipboard_fallback_body`] instead of opening the URL.
pub const GITHUB_URL_LENGTH_THRESHOLD: usize = 2000;

/// Fields for a prefilled GitHub Issue-Form deep link.
#[derive(Debug, Clone, Default)]
pub struct IssueFormRequest {
    /// `owner/repo` slug, e.g. `46b-ETYKiAL/Itasha.Corp_S4F3-W1TN3SS`.
    pub repo: String,
    /// Issue title (host-provided; may be localized).
    pub title: String,
    /// Issue body (host-provided; the previewed/redacted text).
    pub body: String,
    /// Optional issue-form template filename (e.g. `bug_report.yml`).
    pub template: Option<String>,
    /// Labels to apply (server-side `labels:`).
    pub labels: Vec<String>,
}

impl IssueFormRequest {
    /// Build the prefilled GitHub Issue-Form URL with every field
    /// percent-encoded. The result targets
    /// `https://github.com/<repo>/issues/new?...`.
    #[must_use]
    pub fn to_url(&self) -> String {
        let mut url = format!("https://github.com/{}/issues/new?", self.repo);
        let mut params: Vec<(String, String)> = Vec::new();
        params.push(("title".to_string(), self.title.clone()));
        params.push(("body".to_string(), self.body.clone()));
        if let Some(t) = &self.template {
            params.push(("template".to_string(), t.clone()));
        }
        if !self.labels.is_empty() {
            params.push(("labels".to_string(), self.labels.join(",")));
        }

        let query = params
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        url.push_str(&query);
        url
    }

    /// Whether the built URL is short enough to open directly (`true`) or must
    /// fall back to the clipboard path (`false`) to avoid an HTTP 414.
    #[must_use]
    pub fn fits_url_length(&self) -> bool {
        self.to_url().len() <= GITHUB_URL_LENGTH_THRESHOLD
    }
}

/// The plain-text body a host copies to the clipboard when the issue-form URL
/// would exceed [`GITHUB_URL_LENGTH_THRESHOLD`]. The user pastes it into a
/// blank GitHub issue.
#[must_use]
pub fn clipboard_fallback_body(req: &IssueFormRequest) -> String {
    let mut s = String::new();
    s.push_str(&req.title);
    s.push('\n');
    s.push('\n');
    s.push_str(&req.body);
    s
}

/// Build a `mailto:` URL to a support alias with a prefilled subject + body.
#[must_use]
pub fn mailto_url(address: &str, subject: &str, body: &str) -> String {
    format!(
        "mailto:{}?subject={}&body={}",
        address,
        percent_encode(subject),
        percent_encode(body)
    )
}

/// Open a URL in the user's default browser via the `webbrowser` crate.
///
/// Returns `Err` with a non-identifying message if the browser could not be
/// launched (e.g. headless / offline) — the caller should then use the
/// clipboard fallback.
///
/// The actual `webbrowser::open` syscall is the only line here that touches the
/// OS; the error mapping is delegated to the pure [`map_launch_error`] helper so
/// the non-identifying-message contract is unit-testable WITHOUT spawning a real
/// browser process (a real spawn would leak a child process past test end).
pub fn launch(url: &str) -> Result<(), String> {
    webbrowser::open(url).map_err(|e| map_launch_error(&e))
}

/// Map a browser-launch failure to a plain, non-identifying message with a
/// recovery step. Pure; the inner OS error is NOT interpolated (it can embed an
/// errno / path), and the user is told exactly what to do instead.
fn map_launch_error(_e: &impl std::fmt::Display) -> String {
    "Could not open your browser. Copy the report text and paste it into a new issue instead."
        .to_string()
}

/// Percent-encode a string for a URL query component (RFC 3986). Encodes
/// everything except the unreserved set `A-Z a-z 0-9 - _ . ~`.
#[must_use]
pub fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for &byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_upper(byte >> 4));
            out.push(hex_upper(byte & 0x0F));
        }
    }
    out
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_handles_spaces_and_specials() {
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("a/b?c=d&e"), "a%2Fb%3Fc%3Dd%26e");
        // Unreserved set is passed through.
        assert_eq!(percent_encode("Aa0-_.~"), "Aa0-_.~");
    }

    #[test]
    fn percent_encode_is_utf8_safe() {
        // Multi-byte chars encode each byte.
        let enc = percent_encode("é");
        assert_eq!(enc, "%C3%A9");
    }

    #[test]
    fn issue_form_url_encodes_all_fields() {
        let req = IssueFormRequest {
            repo: "owner/repo".into(),
            title: "crash: it broke".into(),
            body: "steps & details".into(),
            template: Some("bug_report.yml".into()),
            labels: vec!["bug".into(), "community-unverified".into()],
        };
        let url = req.to_url();
        assert!(url.starts_with("https://github.com/owner/repo/issues/new?"));
        assert!(url.contains("title=crash%3A%20it%20broke"));
        assert!(url.contains("body=steps%20%26%20details"));
        assert!(url.contains("template=bug_report.yml"));
        assert!(url.contains("labels=bug%2Ccommunity-unverified"));
    }

    #[test]
    fn short_url_fits_long_url_does_not() {
        let short = IssueFormRequest {
            repo: "o/r".into(),
            title: "hi".into(),
            body: "short".into(),
            ..Default::default()
        };
        assert!(short.fits_url_length());

        let long = IssueFormRequest {
            repo: "o/r".into(),
            title: "x".into(),
            body: "y".repeat(GITHUB_URL_LENGTH_THRESHOLD + 500),
            ..Default::default()
        };
        assert!(!long.fits_url_length());
    }

    #[test]
    fn url_length_boundary_is_exact() {
        // Construct a body so the URL length lands just at / just over the cap.
        let base = IssueFormRequest {
            repo: "o/r".into(),
            title: "t".into(),
            body: String::new(),
            ..Default::default()
        };
        let base_len = base.to_url().len();
        // Each body char that needs no encoding adds exactly one byte.
        let pad = GITHUB_URL_LENGTH_THRESHOLD - base_len;
        let at_cap = IssueFormRequest {
            body: "a".repeat(pad),
            ..base.clone()
        };
        assert_eq!(at_cap.to_url().len(), GITHUB_URL_LENGTH_THRESHOLD);
        assert!(at_cap.fits_url_length());

        let over_cap = IssueFormRequest {
            body: "a".repeat(pad + 1),
            ..base
        };
        assert_eq!(over_cap.to_url().len(), GITHUB_URL_LENGTH_THRESHOLD + 1);
        assert!(!over_cap.fits_url_length());
    }

    #[test]
    fn clipboard_fallback_carries_title_and_body() {
        let req = IssueFormRequest {
            repo: "o/r".into(),
            title: "the title".into(),
            body: "the body".into(),
            ..Default::default()
        };
        let text = clipboard_fallback_body(&req);
        assert!(text.contains("the title"));
        assert!(text.contains("the body"));
    }

    #[test]
    fn mailto_encodes_subject_and_body() {
        let url = mailto_url("support@example.com", "crash report", "a & b");
        assert!(url.starts_with("mailto:support@example.com?"));
        assert!(url.contains("subject=crash%20report"));
        assert!(url.contains("body=a%20%26%20b"));
    }

    #[test]
    fn map_launch_error_produces_non_identifying_message() {
        // map_launch_error is the pure error-mapping half of `launch`. We test it
        // directly — without invoking `webbrowser::open`, which on a desktop would
        // spawn a real browser child process that outlives the test (a leak). The
        // mapped message is plain copy with a recovery step (WS-029) and carries
        // NONE of the inner OS error — even when that error embeds an errno/path.
        let msg = map_launch_error(&"os error 2 at /home/jane/.cache: no display server");
        assert_eq!(
            msg,
            "Could not open your browser. Copy the report text and paste it into a new issue instead."
        );
        // REDACTION: no inner OS detail survives.
        assert!(!msg.contains('/'), "path separator leaked: {msg}");
        assert!(!msg.contains("os error"), "errno leaked: {msg}");
        assert!(
            !msg.contains("display server"),
            "inner reason leaked: {msg}"
        );
    }
}
