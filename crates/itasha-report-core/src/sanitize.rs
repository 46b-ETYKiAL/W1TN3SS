//! The sanitizer — the privacy heart of the SDK.
//!
//! Every report passes through [`Sanitizer::sanitize`] before preview, spool,
//! or transmission. The sanitizer is a **pure, deterministic transform**:
//!
//! * the user's home directory is normalized to the literal `<HOME>`,
//! * the OS username and hostname are dropped (replaced with placeholders),
//! * environment-variable *values* are scrubbed,
//! * every string is size-capped.
//!
//! Backtrace redaction is **allowlist-not-denylist**: a frame is kept only if
//! it matches a known-safe shape (a code path with a normalized file location
//! and a symbol). Anything that does not match the safe shape is replaced with
//! a `<redacted>` marker rather than risk leaking a quasi-identifier.

use crate::redact::{self, PathRoots};
use crate::report::Report;

/// Replacement marker for the user's home directory.
pub const HOME_PLACEHOLDER: &str = "<HOME>";
/// Replacement marker for the OS username.
pub const USER_PLACEHOLDER: &str = "<USER>";
/// Replacement marker for the machine hostname.
pub const HOST_PLACEHOLDER: &str = "<HOST>";
/// Replacement marker for a scrubbed environment-variable value.
pub const ENV_VALUE_PLACEHOLDER: &str = "<scrubbed>";
/// Replacement marker for a backtrace line that failed the safe-shape allowlist.
pub const REDACTED_MARKER: &str = "<redacted>";

/// Default maximum length (bytes) of any single sanitized string field.
pub const DEFAULT_MAX_FIELD_BYTES: usize = 16 * 1024;
/// Default maximum number of backtrace lines kept.
pub const DEFAULT_MAX_LINES: usize = 512;

/// Configurable size caps for the sanitizer.
#[derive(Debug, Clone, Copy)]
pub struct SizeCaps {
    /// Max bytes per string field after sanitization.
    pub max_field_bytes: usize,
    /// Max lines kept in a multi-line body (e.g. a backtrace).
    pub max_lines: usize,
}

impl Default for SizeCaps {
    fn default() -> Self {
        Self {
            max_field_bytes: DEFAULT_MAX_FIELD_BYTES,
            max_lines: DEFAULT_MAX_LINES,
        }
    }
}

/// The host machine's identifying strings the sanitizer strips. Detected once
/// from the environment (or injected explicitly in tests for determinism).
#[derive(Debug, Clone, Default)]
pub struct HostIdentity {
    /// Absolute home directory path, e.g. `/home/ada` or `C:\Users\ada`.
    pub home_dir: Option<String>,
    /// OS username, e.g. `ada`.
    pub username: Option<String>,
    /// Machine hostname.
    pub hostname: Option<String>,
    /// OS temp directory, e.g. `/tmp` or `C:\Users\ada\AppData\Local\Temp`.
    /// Used to anchor recognized temp paths to `<tmp>` (anonymity hardening #3).
    pub tmp_dir: Option<String>,
    /// OS cache directory (per-user). Anchored to `<cache>`.
    pub cache_dir: Option<String>,
    /// OS config directory (per-user). Anchored to `<cache>`.
    pub config_dir: Option<String>,
}

impl HostIdentity {
    /// Detect the host identity from the platform (home dir, username, host,
    /// tmp/cache/config dirs).
    ///
    /// Uses `directories` for a platform-aware home + cache/config dirs and the
    /// standard `USER`/`USERNAME` and `HOSTNAME`/`COMPUTERNAME` environment
    /// variables. The tmp dir comes from `std::env::temp_dir()`.
    #[must_use]
    pub fn detect() -> Self {
        let base = directories::BaseDirs::new();
        let home_dir = base
            .as_ref()
            .map(|d| d.home_dir().to_string_lossy().into_owned())
            .filter(|s| !s.is_empty());
        let cache_dir = base
            .as_ref()
            .map(|d| d.cache_dir().to_string_lossy().into_owned())
            .filter(|s| !s.is_empty());
        let config_dir = base
            .as_ref()
            .map(|d| d.config_dir().to_string_lossy().into_owned())
            .filter(|s| !s.is_empty());
        let tmp_dir = {
            let t = std::env::temp_dir().to_string_lossy().into_owned();
            // temp_dir may carry a trailing separator; trim it so the anchor
            // covers the prefix cleanly.
            let trimmed = t.trim_end_matches(['/', '\\']).to_string();
            (!trimmed.is_empty()).then_some(trimmed)
        };

        let username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .ok()
            .filter(|s| !s.is_empty());

        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .ok()
            .filter(|s| !s.is_empty());

        Self {
            home_dir,
            username,
            hostname,
            tmp_dir,
            cache_dir,
            config_dir,
        }
    }

    /// Build the recognized-path-root set this identity anchors to symbolic
    /// roots (`<home>`/`<tmp>`/`<cache>`). Unrecognized absolute paths are
    /// dropped downstream (fail-closed, anonymity hardening #3).
    #[must_use]
    pub fn path_roots(&self) -> PathRoots {
        PathRoots::new(
            self.home_dir.as_deref(),
            self.tmp_dir.as_deref(),
            self.cache_dir.as_deref(),
            self.config_dir.as_deref(),
        )
    }
}

/// The privacy sanitizer.
#[derive(Debug, Clone, Default)]
pub struct Sanitizer {
    identity: HostIdentity,
    caps: SizeCaps,
    roots: PathRoots,
}

impl Sanitizer {
    /// A sanitizer that detects the host identity from the environment.
    #[must_use]
    pub fn new() -> Self {
        let identity = HostIdentity::detect();
        let roots = identity.path_roots();
        Self {
            identity,
            caps: SizeCaps::default(),
            roots,
        }
    }

    /// A sanitizer with an explicit host identity (for deterministic tests).
    #[must_use]
    pub fn with_identity(identity: HostIdentity) -> Self {
        let roots = identity.path_roots();
        Self {
            identity,
            caps: SizeCaps::default(),
            roots,
        }
    }

    /// Override the size caps.
    #[must_use]
    pub fn with_caps(mut self, caps: SizeCaps) -> Self {
        self.caps = caps;
        self
    }

    /// Sanitize a whole report: title, body, and metadata values. Tier-2
    /// opaque attachments are carried through unchanged (they are binary and
    /// minimized/server-scrubbed downstream, never inspected here).
    #[must_use]
    pub fn sanitize(&self, mut report: Report) -> Report {
        report.title = self.scrub_field(&report.title);
        report.body = self.scrub_backtrace(&report.body);
        report.metadata = report
            .metadata
            .into_iter()
            .map(|(k, v)| (self.scrub_field(&k), self.scrub_field(&v)))
            .collect();
        report
    }

    /// Scrub a single short field: strip identity tokens, anchor/drop paths,
    /// redact free-text PII/secrets, then size-cap.
    ///
    /// Anonymity hardenings #3 and #4: a short field (title, metadata value) is
    /// free text that may carry a foreign path or a secret. After identity-strip
    /// and path-anchoring (in [`strip_identity`]) the field passes through
    /// [`redact::redact_free_text`] so emails / IPs / tokens / high-entropy
    /// secrets become the uniform typeless `<redacted>` token.
    #[must_use]
    pub fn scrub_field(&self, input: &str) -> String {
        let stripped = self.strip_identity(input);
        let redacted = redact::redact_free_text(&stripped);
        cap_bytes(&redacted, self.caps.max_field_bytes)
    }

    /// Scrub a multi-line backtrace/body with the allowlist redaction policy,
    /// then size-cap line count and total bytes.
    #[must_use]
    pub fn scrub_backtrace(&self, input: &str) -> String {
        let mut out_lines: Vec<String> = Vec::new();
        for line in input.lines().take(self.caps.max_lines) {
            out_lines.push(self.scrub_line(line));
        }
        let joined = out_lines.join("\n");
        cap_bytes(&joined, self.caps.max_field_bytes)
    }

    /// Replace every occurrence of a host-identity token in `input`.
    ///
    /// Order is **most-specific-first**: home path, then hostname, then
    /// username. The hostname often *contains* the username (`ada-laptop`
    /// contains `ada`), so the username must be stripped LAST — otherwise the
    /// username replacement would shatter the hostname token before it can be
    /// matched.
    fn strip_identity(&self, input: &str) -> String {
        let mut s = input.to_string();
        if let Some(home) = self.identity.home_dir.as_deref() {
            if !home.is_empty() {
                s = replace_path_prefixes(&s, home, HOME_PLACEHOLDER);
            }
        }
        if let Some(host) = self.identity.hostname.as_deref() {
            if !host.is_empty() {
                s = replace_token(&s, host, HOST_PLACEHOLDER);
            }
        }
        if let Some(user) = self.identity.username.as_deref() {
            if !user.is_empty() {
                s = replace_token(&s, user, USER_PLACEHOLDER);
            }
        }
        // Anonymity hardening #3 (fail-closed path anchoring): after the local
        // identity tokens are gone, anchor recognized roots to <home>/<tmp>/
        // <cache>/<src> and DROP any UNRECOGNIZED absolute path (a foreign
        // user's path, a mounted share, a cloud path) to <path>. The legacy
        // <HOME> form above stays for backward-compat with existing tests; the
        // anchoring is additive and catches everything <HOME> alone misses.
        redact::anchor_paths(&s, &self.roots)
    }

    /// Apply the allowlist redaction to a single backtrace line.
    ///
    /// After identity-stripping, a line is KEPT verbatim only if it matches a
    /// known-safe shape (see [`is_safe_shape`]). Otherwise the whole line is
    /// replaced with [`REDACTED_MARKER`] — the conservative default that
    /// guarantees an unrecognized line cannot leak a quasi-identifier.
    fn scrub_line(&self, line: &str) -> String {
        let stripped = self.strip_identity(line);
        // Frame-symbol lines (`   3: core::panicking::panic_fmt`) are kept
        // verbatim — they are *your* code, the dedup signal, and must not be
        // mangled by free-text redaction (a long symbol could otherwise trip the
        // entropy detector).
        if is_frame_symbol_line(stripped.trim()) {
            return stripped;
        }
        // Panic messages + error chains are the HIGHEST free-text leak vector in
        // a backtrace (devs interpolate user data into `panic!`/`expect!`).
        // Anonymity hardening #4: redact secrets/PII to the uniform token before
        // the allowlist check.
        let redacted = redact::redact_free_text(&stripped);
        if is_safe_shape(&redacted) {
            redacted
        } else {
            REDACTED_MARKER.to_string()
        }
    }

    /// Scrub a list of `KEY=VALUE` environment pairs: keep the key, replace the
    /// value with [`ENV_VALUE_PLACEHOLDER`]. Values are where secrets/paths/
    /// identity hide, so they are dropped wholesale (denylist of values is
    /// unsafe; we scrub ALL values).
    #[must_use]
    pub fn scrub_env(&self, pairs: &[(String, String)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, _v)| (self.scrub_field(k), ENV_VALUE_PLACEHOLDER.to_string()))
            .collect()
    }
}

/// The allowlist predicate: is this (already identity-stripped) line a
/// known-safe backtrace shape?
///
/// Safe shapes are deliberately narrow:
/// * a normalized path (one that begins with a placeholder or a non-user
///   system root and contains no remaining absolute home-style segment), or
/// * a stack-frame symbol line (`N: module::function`), or
/// * a panic header that references only a normalized location.
///
/// A line containing a still-absolute user-home-style path, an `@`-style
/// email, or a Windows `C:\Users\<name>` segment fails the allowlist.
#[must_use]
pub fn is_safe_shape(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true; // blank lines are safe and preserve readability
    }

    // Reject any residual identity-bearing path segment outright.
    if contains_unnormalized_home(trimmed) {
        return false;
    }

    // Frame index line: "   3: core::panicking::panic_fmt"
    if is_frame_symbol_line(trimmed) {
        return true;
    }

    // A normalized location: "at <HOME>/src/main.rs:12:5" or "at src/main.rs:1".
    if is_normalized_location_line(trimmed) {
        return true;
    }

    // A panic header that has already been normalized.
    if trimmed.starts_with("thread '") && trimmed.contains("panicked") {
        return true;
    }

    // Generic prose with no path/identity markers and no '/' '\\' that looks
    // like an absolute path is permitted (short, no separators).
    !trimmed.contains('/') && !trimmed.contains('\\') && !trimmed.contains('@')
}

/// True if the line still contains an absolute home-style path the sanitizer
/// failed to normalize (defense-in-depth against the allowlist letting one
/// slip through).
fn contains_unnormalized_home(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("/home/")
        || lower.contains("/users/")
        || lower.contains("\\users\\")
        || lower.contains("/root/")
        || lower.contains("c:\\users")
}

/// `   N: symbol::path` — a stack-frame index line.
fn is_frame_symbol_line(line: &str) -> bool {
    let mut parts = line.splitn(2, ':');
    let idx = parts.next().unwrap_or("").trim();
    let rest = parts.next().unwrap_or("").trim();
    !idx.is_empty()
        && idx.chars().all(|c| c.is_ascii_digit())
        && !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_alphanumeric() || "_:<>{}(), &*'.+-[]".contains(c))
}

/// `at <normalized>/path:line[:col]` — a normalized source location.
fn is_normalized_location_line(line: &str) -> bool {
    let body = line.strip_prefix("at ").unwrap_or(line);
    // After normalization, an `at` location may start with the HOME placeholder
    // or be a relative path. It must NOT contain an unnormalized home segment
    // (already rejected above). Accept it.
    body.contains(HOME_PLACEHOLDER) || !body.starts_with('/')
}

/// Replace a home-directory prefix wherever it appears, including inside a
/// longer path. Handles both `/`- and `\`-separated forms.
fn replace_path_prefixes(haystack: &str, home: &str, placeholder: &str) -> String {
    if home.is_empty() {
        return haystack.to_string();
    }
    // Replace the literal home path, and also a forward-slash-normalized form
    // (so a Windows home `C:\Users\ada` is caught even if a tool emitted it
    // with forward slashes).
    let mut s = haystack.replace(home, placeholder);
    let alt = home.replace('\\', "/");
    if alt != home {
        s = s.replace(&alt, placeholder);
    }
    s
}

/// Replace standalone occurrences of `token` (bounded by non-word chars) with
/// `placeholder`. Avoids replacing substrings inside larger identifiers.
fn replace_token(haystack: &str, token: &str, placeholder: &str) -> String {
    if token.is_empty() {
        return haystack.to_string();
    }
    let bytes = haystack.as_bytes();
    let tlen = token.len();
    let mut out = String::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(token) {
            let before_ok = i == 0 || !is_word_byte(bytes[i - 1]);
            let after_idx = i + tlen;
            let after_ok = after_idx >= haystack.len() || !is_word_byte(bytes[after_idx]);
            if before_ok && after_ok {
                out.push_str(placeholder);
                i = after_idx;
                continue;
            }
        }
        // advance one char (handle UTF-8 boundaries)
        let ch_len = haystack[i..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&haystack[i..i + ch_len]);
        i += ch_len;
    }
    out
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Truncate a string to at most `max` bytes, never splitting a UTF-8 char,
/// appending an ellipsis marker when truncation occurred.
fn cap_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let marker = "…[truncated]";
    let budget = max.saturating_sub(marker.len());
    let mut end = budget.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    out.push_str(marker);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_identity() -> HostIdentity {
        HostIdentity {
            home_dir: Some("/home/ada".to_string()),
            username: Some("ada".to_string()),
            hostname: Some("ada-laptop".to_string()),
            tmp_dir: Some("/tmp".to_string()),
            cache_dir: Some("/home/ada/.cache".to_string()),
            config_dir: Some("/home/ada/.config".to_string()),
        }
    }

    fn sanitizer() -> Sanitizer {
        Sanitizer::with_identity(fixed_identity())
    }

    #[test]
    fn home_is_normalized() {
        let s = sanitizer();
        let out = s.scrub_field("opened /home/ada/notes.txt");
        assert!(out.contains(HOME_PLACEHOLDER));
        assert!(!out.contains("/home/ada"));
    }

    #[test]
    fn username_is_dropped_as_standalone_token() {
        let s = sanitizer();
        let out = s.scrub_field("user ada logged in");
        assert!(out.contains(USER_PLACEHOLDER));
        assert!(!out.split_whitespace().any(|w| w == "ada"));
    }

    #[test]
    fn hostname_is_dropped() {
        let s = sanitizer();
        let out = s.scrub_field("host ada-laptop reporting");
        assert!(out.contains(HOST_PLACEHOLDER));
        assert!(!out.contains("ada-laptop"));
    }

    #[test]
    fn env_values_are_scrubbed_keys_kept() {
        let s = sanitizer();
        let pairs = vec![
            ("PATH".to_string(), "/home/ada/bin:/usr/bin".to_string()),
            ("SECRET_TOKEN".to_string(), "hunter2".to_string()),
        ];
        let out = s.scrub_env(&pairs);
        assert_eq!(out[0].0, "PATH");
        assert_eq!(out[0].1, ENV_VALUE_PLACEHOLDER);
        assert_eq!(out[1].1, ENV_VALUE_PLACEHOLDER);
        // No value content survived.
        assert!(out.iter().all(|(_, v)| v == ENV_VALUE_PLACEHOLDER));
    }

    #[test]
    fn unsafe_backtrace_line_is_redacted() {
        let s = sanitizer();
        // A line with a foreign user's absolute path the sanitizer cannot
        // attribute to the known home. With fail-closed path anchoring
        // (hardening #3) the foreign absolute path is dropped to the typeless
        // <path> marker; if any residual still trips the allowlist, the whole
        // line collapses to <redacted>. Either way the privacy invariant holds:
        // the foreign username never survives, and no raw absolute path leaks.
        let out = s.scrub_backtrace("leaked /home/otheruser/secret/path.rs");
        assert!(!out.contains("otheruser"), "foreign username leaked: {out}");
        assert!(
            !out.contains("/home/otheruser"),
            "raw foreign path leaked: {out}"
        );
        assert!(
            out.contains(crate::redact::PATH_DROP) || out.contains(REDACTED_MARKER),
            "foreign path was neither anchored-dropped nor redacted: {out}"
        );
    }

    #[test]
    fn safe_frame_line_is_kept() {
        let s = sanitizer();
        let out = s.scrub_backtrace("   3: core::panicking::panic_fmt");
        assert!(out.contains("panic_fmt"));
        assert!(!out.contains(REDACTED_MARKER));
    }

    #[test]
    fn normalized_panic_header_is_kept() {
        let s = sanitizer();
        let raw = "thread 'main' panicked at /home/ada/src/main.rs:12:5";
        let out = s.scrub_backtrace(raw);
        assert!(out.contains("panicked"));
        assert!(out.contains(HOME_PLACEHOLDER));
        assert!(!out.contains("/home/ada"));
    }

    #[test]
    fn size_cap_truncates_long_field() {
        let s = sanitizer().with_caps(SizeCaps {
            max_field_bytes: 32,
            max_lines: 10,
        });
        let out = s.scrub_field(&"x".repeat(1000));
        assert!(out.len() <= 32);
        assert!(out.contains("truncated"));
    }

    #[test]
    fn line_cap_limits_backtrace_lines() {
        let s = sanitizer().with_caps(SizeCaps {
            max_field_bytes: DEFAULT_MAX_FIELD_BYTES,
            max_lines: 3,
        });
        let body = (0..100)
            .map(|i| format!("   {i}: sym::f"))
            .collect::<Vec<_>>()
            .join("\n");
        let out = s.scrub_backtrace(&body);
        assert_eq!(out.lines().count(), 3);
    }

    #[test]
    fn sanitize_report_strips_all_surfaces() {
        let s = sanitizer();
        let r = Report::crash("at /home/ada/x.rs:1").with_metadata("cwd", "/home/ada/project");
        let out = s.sanitize(r);
        assert!(!out.body.contains("/home/ada"));
        assert!(!out.metadata[0].1.contains("/home/ada"));
    }

    #[test]
    fn foreign_absolute_path_is_dropped_not_passed_through() {
        // Anonymity hardening #3: a path for a DIFFERENT user / a mounted share /
        // a cloud path is not attributable to the local home → it must be DROPPED
        // (fail closed), not passed through, even though it's not the local home.
        let s = sanitizer();
        let out = s.scrub_field("config at /mnt/share/teamjane/app.toml loaded");
        assert!(!out.contains("teamjane"), "foreign path leaked: {out}");
        assert!(
            !out.contains("/mnt/share"),
            "raw foreign path leaked: {out}"
        );
        assert!(
            out.contains(crate::redact::PATH_DROP),
            "path not dropped: {out}"
        );
    }

    #[test]
    fn tmp_path_anchors_to_symbol() {
        let s = sanitizer();
        let out = s.scrub_field("spooled /tmp/.org.app/cache.bin ok");
        assert!(
            out.contains(crate::redact::TMP_ANCHOR),
            "tmp not anchored: {out}"
        );
        assert!(!out.contains("/tmp/.org.app"));
    }

    #[test]
    fn high_entropy_secret_in_panic_message_is_redacted_to_uniform_token() {
        // Anonymity hardening #4: a dev `panic!`/`expect!` that interpolated a
        // secret/token. The secret is redacted to the uniform, typeless token.
        let s = sanitizer();
        let body = "thread 'main' panicked: bad bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcDEFghiJKL at lib.rs";
        let out = s.scrub_backtrace(body);
        assert!(
            out.contains(crate::redact::REDACTED),
            "secret not redacted: {out}"
        );
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"), "JWT leaked: {out}");
        // The token is typeless — no "jwt"/"token"/"bearer-type" tag leaks.
        assert!(!out.to_lowercase().contains("[jwt]"));
    }

    #[test]
    fn redaction_token_carries_no_type_or_count() {
        // The uniform redaction token must reveal neither the TYPE nor the COUNT
        // of what was redacted (both are quasi-identifiers).
        let s = sanitizer();
        let out = s.scrub_field("ada@example.com 10.0.0.5 00:11:22:33:44:55");
        // Typeless: none of the detector type names appear.
        for tag in ["email", "ipv4", "mac", "[ip]", "[email]"] {
            assert!(!out.to_lowercase().contains(tag), "type tag leaked: {out}");
        }
        // Count-collapsed: the three adjacent redactions become ONE token.
        assert_eq!(
            out.matches(crate::redact::REDACTED).count(),
            1,
            "redaction count not collapsed: {out}"
        );
    }
}
