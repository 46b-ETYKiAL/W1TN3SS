//! Fail-closed path anchoring + hardened free-text redaction.
//!
//! Two anonymity hardenings live here, both deterministic and regex-free (no
//! `regex` dependency — hand-written scanners keep the supply chain minimal and
//! `#![forbid(unsafe_code)]`-clean):
//!
//! * **#3 — Fail-closed path anchoring (gap D-4).** `<HOME>` normalization alone
//!   is insufficient: a path for a *different* user, a mounted share, a cloud
//!   path, or a temp dir embedding a username slips through. [`anchor_paths`]
//!   maps recognized roots to symbolic anchors (`<home>` / `<tmp>` / `<cache>` /
//!   `<src>`) and replaces any UNRECOGNIZED absolute path with the typeless
//!   `<path>` marker — fail closed: an absolute path the anchoring did not
//!   recognize is presumed identifying and dropped.
//!
//! * **#4 — Hardened free-text redaction (gap D-5).** [`redact_free_text`] runs
//!   over panic messages, error chains, and any user/free-text field. It detects
//!   emails, IPv4/IPv6, MAC addresses, URLs, JWT/bearer tokens, AWS-style keys,
//!   UUIDs, and high-Shannon-entropy hex/base64 blobs (gitleaks-style), and
//!   replaces EVERY hit with a single UNIFORM, TYPELESS token ([`REDACTED`]).
//!   The count and type of redactions are deliberately discarded — a
//!   `[email]×3, [path]×1` redaction profile is itself a quasi-identifier, so
//!   adjacent tokens are COLLAPSED to one. Client-side is the authoritative gate.

/// The single uniform redaction token. Typeless by design: emitting the *type*
/// or *count* of what was redacted is itself a fingerprint, so every detector —
/// email, key, path, high-entropy blob — collapses to this one marker.
pub const REDACTED: &str = "<redacted>";

/// Symbolic anchors for recognized path roots. Order matters: longer/more
/// specific roots (cache/config under home) are matched before home itself.
pub const HOME_ANCHOR: &str = "<home>";
/// Anchor for the OS temp directory.
pub const TMP_ANCHOR: &str = "<tmp>";
/// Anchor for the OS cache/config directory.
pub const CACHE_ANCHOR: &str = "<cache>";
/// Anchor for the build/source prefix (`--remap-path-prefix` target).
pub const SRC_ANCHOR: &str = "<src>";
/// Replacement for an UNRECOGNIZED absolute path (fail-closed drop).
pub const PATH_DROP: &str = "<path>";

/// The set of recognized path roots to anchor, longest-first. Each entry maps a
/// concrete absolute prefix (already lossy-stringified per-OS) to its anchor.
#[derive(Debug, Clone, Default)]
pub struct PathRoots {
    /// (absolute-prefix, anchor) pairs, sorted longest-prefix-first at build time.
    roots: Vec<(String, &'static str)>,
}

impl PathRoots {
    /// Build the recognized-root set from explicit per-OS directories. Empty
    /// strings are ignored. Roots are sorted longest-first so a cache dir nested
    /// under home anchors as `<cache>`, not `<home>`.
    #[must_use]
    pub fn new(
        home: Option<&str>,
        tmp: Option<&str>,
        cache: Option<&str>,
        config: Option<&str>,
    ) -> Self {
        let mut roots: Vec<(String, &'static str)> = Vec::new();
        let mut push = |p: Option<&str>, anchor: &'static str| {
            if let Some(p) = p {
                let p = p.trim();
                if !p.is_empty() {
                    roots.push((p.to_string(), anchor));
                    // Also register a forward-slash-normalized form so a Windows
                    // root emitted with '/' separators still anchors.
                    let alt = p.replace('\\', "/");
                    if alt != p {
                        roots.push((alt, anchor));
                    }
                }
            }
        };
        // Cache/config first (they nest under home) then tmp then home.
        push(cache, CACHE_ANCHOR);
        push(config, CACHE_ANCHOR);
        push(tmp, TMP_ANCHOR);
        push(home, HOME_ANCHOR);
        // Longest prefix first.
        roots.sort_by_key(|r| core::cmp::Reverse(r.0.len()));
        Self { roots }
    }
}

/// Anchor recognized path roots and DROP unrecognized absolute paths.
///
/// Pass 1: replace each recognized root prefix (longest-first) with its anchor.
/// Pass 2: any remaining absolute-path token (a `/…`-rooted or `X:\…`/`X:/…`
/// drive-rooted run, or a `\\host\share` UNC run) that was not anchored is
/// replaced wholesale with [`PATH_DROP`] — fail closed.
#[must_use]
pub fn anchor_paths(input: &str, roots: &PathRoots) -> String {
    // Pass 1 — anchor known roots.
    let mut s = input.to_string();
    for (prefix, anchor) in &roots.roots {
        if s.contains(prefix.as_str()) {
            s = s.replace(prefix.as_str(), anchor);
        }
    }
    // Pass 2 — drop any surviving absolute path run, token by token. We scan and
    // rebuild, replacing absolute-path-shaped runs with PATH_DROP.
    drop_unrecognized_absolute_paths(&s)
}

/// Scan `s` and replace each maximal absolute-path-shaped run with [`PATH_DROP`].
///
/// An absolute-path run starts at one of:
///   * `/` that is the start of a path segment (preceded by start/space/quote/`(`/`=`),
///   * a Windows drive root `X:\` or `X:/`,
///   * a UNC root `\\`.
///
/// A run extends over path characters (anything except whitespace and a small
/// set of delimiters). Anchored runs (already replaced, starting with `<`) are
/// left untouched because `<` is not a path-start.
fn drop_unrecognized_absolute_paths(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let n = s.len();
    while i < n {
        if let Some(run_len) = absolute_path_run_at(s, bytes, i) {
            out.push_str(PATH_DROP);
            i += run_len;
        } else {
            let ch_len = s[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&s[i..i + ch_len]);
            i += ch_len;
        }
    }
    out
}

/// If an absolute-path run starts exactly at byte `i`, return its byte length.
fn absolute_path_run_at(s: &str, bytes: &[u8], i: usize) -> Option<usize> {
    let prev_ok = i == 0
        || matches!(
            bytes[i - 1],
            b' ' | b'\t' | b'"' | b'\'' | b'(' | b'=' | b':' | b','
        );

    // Start shapes:
    let start_len = if bytes[i] == b'/' {
        // Unix absolute: a '/' that begins a segment AND is followed by a path
        // char (avoid matching a lone '/' or "a/b" relative — require prev_ok).
        if prev_ok && i + 1 < bytes.len() && is_path_char(bytes[i + 1]) {
            1
        } else {
            return None;
        }
    } else if i + 1 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'\\' {
        // UNC: \\host\share
        2
    } else if i + 2 < bytes.len()
        && bytes[i].is_ascii_alphabetic()
        && bytes[i + 1] == b':'
        && (bytes[i + 2] == b'\\' || bytes[i + 2] == b'/')
    {
        // Windows drive root X:\ or X:/
        if prev_ok || i == 0 {
            3
        } else {
            return None;
        }
    } else {
        return None;
    };

    // Extend over path chars.
    let mut j = i + start_len;
    while j < s.len() && is_path_char(bytes[j]) {
        j += 1;
    }
    // A bare drive root or "/" with no following segment is not worth dropping;
    // require at least one path char beyond the start marker.
    if j > i + start_len || start_len > 1 {
        Some(j - i)
    } else {
        None
    }
}

/// Path-body characters: anything that is not whitespace or a path-terminating
/// delimiter. Kept broad so an entire absolute path (incl. spaces-free) is one
/// run; a space ends the run.
fn is_path_char(b: u8) -> bool {
    !matches!(
        b,
        b' ' | b'\t'
            | b'\n'
            | b'\r'
            | b'"'
            | b'\''
            | b'('
            | b')'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b','
            | b';'
    )
}

/// Redact PII/secret shapes from free text, replacing every hit with the
/// uniform, typeless [`REDACTED`] token and collapsing adjacent tokens so the
/// redaction count is not preserved.
///
/// Detectors (deterministic, regex-free): email, IPv4, IPv6, MAC, URL,
/// JWT/bearer, AWS-style access keys, UUID, and high-entropy hex/base64 blobs.
#[must_use]
pub fn redact_free_text(input: &str) -> String {
    // Tokenize on whitespace, redact each token, rejoin. Punctuation that hugs a
    // token (trailing '.', ',', ')') is preserved around the redaction so prose
    // stays readable, but the token's identifying core is replaced.
    let mut pieces: Vec<String> = Vec::new();
    for raw in split_keep_ws(input) {
        if raw.chars().all(char::is_whitespace) {
            pieces.push(raw.to_string());
            continue;
        }
        pieces.push(redact_token(raw));
    }
    let joined = pieces.concat();
    collapse_redactions(&joined)
}

/// Split into a sequence of alternating non-whitespace / whitespace pieces,
/// preserving the original whitespace runs so rejoining is lossless.
fn split_keep_ws(input: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut in_ws = input
        .chars()
        .next()
        .map(char::is_whitespace)
        .unwrap_or(false);
    for (idx, ch) in input.char_indices() {
        let is_ws = ch.is_whitespace();
        if is_ws != in_ws {
            out.push(&input[start..idx]);
            start = idx;
            in_ws = is_ws;
        }
    }
    if start < input.len() {
        out.push(&input[start..]);
    }
    out
}

/// Redact a single whitespace-free token if it matches any sensitive shape.
/// Leading/trailing prose punctuation is preserved around the replacement.
fn redact_token(token: &str) -> String {
    // Peel leading/trailing punctuation that is not part of the identifier core.
    let lead: String = token.chars().take_while(|c| is_edge_punct(*c)).collect();
    let trail: String = token
        .chars()
        .rev()
        .take_while(|c| is_edge_punct(*c))
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    // When the whole token is edge punctuation, `lead` and `trail` count the
    // SAME characters (e.g. "." is both a leading and a trailing edge-punct), so
    // `lead.len() + trail.len()` can meet or exceed `token.len()`. There is no
    // identifier core to inspect in that case — return the token unchanged
    // rather than slicing with begin > end.
    if lead.len() + trail.len() >= token.len() {
        return token.to_string();
    }
    let core = &token[lead.len()..token.len() - trail.len()];
    if core.is_empty() {
        return token.to_string();
    }
    if is_sensitive(core) {
        format!("{lead}{REDACTED}{trail}")
    } else {
        token.to_string()
    }
}

fn is_edge_punct(c: char) -> bool {
    matches!(
        c,
        '.' | ',' | ';' | ':' | '!' | '?' | ')' | '(' | '"' | '\'' | '<' | '>'
    )
}

/// The detector union for a single token core.
fn is_sensitive(core: &str) -> bool {
    is_email(core)
        || is_url(core)
        || is_ipv4(core)
        || is_ipv6(core)
        || is_mac(core)
        || is_jwt(core)
        || is_aws_key(core)
        || is_uuid(core)
        || is_high_entropy_secret(core)
}

fn is_email(s: &str) -> bool {
    // local@domain.tld — exactly one '@', a dot in the domain, no spaces.
    let mut parts = s.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty()
        && local
            .chars()
            .all(|c| c.is_alphanumeric() || "._%+-".contains(c))
        && domain.contains('.')
        && domain.split('.').all(|p| !p.is_empty())
        && domain
            .chars()
            .all(|c| c.is_alphanumeric() || ".-".contains(c))
}

fn is_url(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("http://") || l.starts_with("https://") || l.starts_with("ftp://")
}

fn is_ipv4(s: &str) -> bool {
    let octets: Vec<&str> = s.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|o| {
            !o.is_empty()
                && o.len() <= 3
                && o.chars().all(|c| c.is_ascii_digit())
                && o.parse::<u16>().map(|v| v <= 255).unwrap_or(false)
        })
}

fn is_ipv6(s: &str) -> bool {
    // Heuristic: contains "::" or has >=3 ':'-separated hextet groups.
    let colon_groups = s.split(':').count();
    if colon_groups < 3 {
        return false;
    }
    let core = s.trim_matches(|c| c == '[' || c == ']');
    core.contains("::")
        || core
            .split(':')
            .filter(|g| !g.is_empty())
            .all(|g| g.len() <= 4 && g.chars().all(|c| c.is_ascii_hexdigit()))
            && core.split(':').filter(|g| !g.is_empty()).count() >= 3
            && core.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

fn is_mac(s: &str) -> bool {
    // 6 groups of 2 hex, ':' or '-' separated.
    let sep = if s.contains(':') { ':' } else { '-' };
    let groups: Vec<&str> = s.split(sep).collect();
    groups.len() == 6
        && groups
            .iter()
            .all(|g| g.len() == 2 && g.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_jwt(s: &str) -> bool {
    // header.payload.signature — 3 base64url segments, the first decoding-ish.
    let segs: Vec<&str> = s.split('.').collect();
    segs.len() == 3
        && segs.iter().all(|seg| {
            seg.len() >= 4 && seg.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
        })
        // JWTs conventionally start with the base64url of '{"' = "eyJ".
        && segs[0].starts_with("eyJ")
}

fn is_aws_key(s: &str) -> bool {
    // AKIA/ASIA + 16 uppercase alnum = 20 chars total (access key id), or a
    // 40-char base64-ish secret.
    s.len() == 20
        && (s.starts_with("AKIA") || s.starts_with("ASIA"))
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

fn is_uuid(s: &str) -> bool {
    // 8-4-4-4-12 hex.
    let groups: Vec<&str> = s.split('-').collect();
    let lens = [8usize, 4, 4, 4, 12];
    groups.len() == 5
        && groups
            .iter()
            .zip(lens.iter())
            .all(|(g, &l)| g.len() == l && g.chars().all(|c| c.is_ascii_hexdigit()))
}

/// High-entropy secret heuristic (gitleaks-style): a long hex or base64-ish run
/// whose Shannon entropy exceeds a threshold is a probable key/token, even with
/// no named format. Catches API keys, session tokens, password-like values.
fn is_high_entropy_secret(s: &str) -> bool {
    // Only consider long, separator-free, identifier-shaped tokens.
    if s.len() < 20 {
        return false;
    }
    let is_b64ish = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(c));
    let is_hexish = s.chars().all(|c| c.is_ascii_hexdigit());
    if !is_b64ish && !is_hexish {
        return false;
    }
    // Must contain at least one digit AND one letter (pure words/numbers are not
    // secrets — avoids redacting long English words or decimal counters).
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let has_alpha = s.chars().any(|c| c.is_ascii_alphabetic());
    if (!has_digit || !has_alpha) && !is_hexish {
        return false;
    }
    shannon_entropy_bits_per_char(s) >= 3.0
}

/// Shannon entropy in bits per character over the token's byte distribution.
fn shannon_entropy_bits_per_char(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Collapse adjacent redaction tokens (separated only by whitespace or simple
/// punctuation) into a single token, so the *count* of redactions is not
/// preserved (a redaction-count is itself a quasi-identifier).
fn collapse_redactions(s: &str) -> String {
    // Replace any run of `<redacted>` (optionally separated by spaces / simple
    // joining punctuation) with a single `<redacted>`.
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find(REDACTED) {
        out.push_str(&rest[..pos]);
        out.push_str(REDACTED);
        rest = &rest[pos + REDACTED.len()..];
        // Skip a following run of [whitespace / simple-join punct]* <redacted> …
        loop {
            let trimmed = rest.trim_start_matches(|c: char| {
                c.is_whitespace() || matches!(c, ',' | ';' | ':' | '/' | '-' | '.')
            });
            if let Some(stripped) = trimmed.strip_prefix(REDACTED) {
                rest = stripped;
            } else {
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> PathRoots {
        PathRoots::new(
            Some("/home/ada"),
            Some("/tmp"),
            Some("/home/ada/.cache"),
            Some("/home/ada/.config"),
        )
    }

    #[test]
    fn recognized_roots_anchor_to_symbols() {
        let r = roots();
        assert_eq!(
            anchor_paths("opened /home/ada/notes.txt now", &r),
            "opened <home>/notes.txt now"
        );
        assert_eq!(
            anchor_paths("tmp /tmp/x.sock here", &r),
            "tmp <tmp>/x.sock here"
        );
        // Cache nested under home anchors as <cache>, not <home>.
        assert_eq!(
            anchor_paths("c /home/ada/.cache/db end", &r),
            "c <cache>/db end"
        );
    }

    #[test]
    fn unrecognized_absolute_path_is_dropped_fail_closed() {
        let r = roots();
        // A foreign user's absolute path the anchoring cannot recognize → <path>.
        let out = anchor_paths("leaked /mnt/data/jane/secret.rs trailing", &r);
        assert!(out.contains(PATH_DROP), "got: {out}");
        assert!(!out.contains("jane"), "foreign path leaked: {out}");
        // A Windows foreign path too.
        let out2 = anchor_paths("at D:\\Projects\\AcmeCorp\\m.rs:1", &r);
        assert!(out2.contains(PATH_DROP), "got: {out2}");
        assert!(!out2.contains("AcmeCorp"));
    }

    #[test]
    fn relative_paths_are_not_dropped() {
        let r = roots();
        // A relative path is the dedup signal (src/main.rs:1) — keep it.
        let out = anchor_paths("at src/main.rs:12:5", &r);
        assert_eq!(out, "at src/main.rs:12:5");
    }

    #[test]
    fn email_is_redacted_to_uniform_token() {
        let out = redact_free_text("contact ada@example.com please");
        assert!(out.contains(REDACTED));
        assert!(!out.contains("ada@example.com"));
        // The token is typeless — no "[email]" leak.
        assert!(!out.to_lowercase().contains("email"));
    }

    #[test]
    fn high_entropy_secret_is_redacted() {
        // A panic message echoing a session token / API key.
        let secret = "AKIA1234567890ABCDEF"; // AWS access key id shape (20).
        let out = redact_free_text(&format!("auth failed for key {secret}"));
        assert!(out.contains(REDACTED), "secret not redacted: {out}");
        assert!(!out.contains(secret));

        // A generic high-entropy base64-ish token.
        let tok = "aB3xZ9qLpW2mN8rT5vK1cJ7hD4fG6sY0"; // 32 mixed alnum.
        let out2 = redact_free_text(&format!("token={tok} expired"));
        assert!(
            out2.contains(REDACTED),
            "high-entropy token not redacted: {out2}"
        );
        assert!(!out2.contains(tok));
    }

    #[test]
    fn jwt_and_ipv4_and_mac_and_uuid_are_redacted() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N";
        let ip = "192.168.1.42";
        let mac = "00:11:22:33:44:55";
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        for secret in [jwt, ip, mac, uuid] {
            let out = redact_free_text(&format!("value {secret} end"));
            assert!(out.contains(REDACTED), "{secret} not redacted: {out}");
            assert!(!out.contains(secret), "{secret} leaked: {out}");
        }
    }

    #[test]
    fn redaction_token_is_typeless_and_count_collapsed() {
        // Multiple different PII types in one string → all become the SAME token,
        // and adjacent tokens collapse so the COUNT is not preserved.
        let out = redact_free_text("a@b.com 10.0.0.1 00:11:22:33:44:55");
        // No type names leak.
        for t in ["email", "ip", "mac", "addr"] {
            assert!(!out.to_lowercase().contains(t), "type tag leaked: {out}");
        }
        // The three adjacent redactions collapse to a single token.
        let count = out.matches(REDACTED).count();
        assert_eq!(
            count, 1,
            "redaction count not collapsed (got {count}): {out}"
        );
    }

    #[test]
    fn benign_prose_is_untouched() {
        // Ordinary words and short numbers must survive — over-redaction would
        // destroy the diagnostic value AND its own redaction-profile is a leak.
        let prose = "the application crashed after 3 retries at startup";
        assert_eq!(redact_free_text(prose), prose);
    }

    #[test]
    fn english_words_are_not_high_entropy_redacted() {
        // A long English word is below the entropy/has-digit bar → kept.
        let out = redact_free_text("internationalization failed unexpectedly");
        assert_eq!(out, "internationalization failed unexpectedly");
    }
}
