//! Property tests for the privacy sanitizer.
//!
//! These assert the core privacy invariant over **arbitrary inputs**: for any
//! string the sanitizer is given — and for any home-dir / username / hostname
//! the host machine might have — the sanitized output never leaks the home
//! path, the username, or the hostname.

use itasha_report_core::redact::{self, PATH_DROP, REDACTED};
use itasha_report_core::report::Report;
use itasha_report_core::sanitize::{HostIdentity, Sanitizer};

use proptest::prelude::*;

/// A sanitizer with a fully-specified host identity (home + tmp + cache) so the
/// path-anchoring property tests are deterministic.
fn anchoring_sanitizer(user: &str) -> Sanitizer {
    Sanitizer::with_identity(HostIdentity {
        home_dir: Some(format!("/home/{user}")),
        username: Some(user.to_string()),
        hostname: Some(format!("{user}-host")),
        tmp_dir: Some("/tmp".to_string()),
        cache_dir: Some(format!("/home/{user}/.cache")),
        config_dir: Some(format!("/home/{user}/.config")),
    })
}

/// A username/hostname token: non-empty, alphanumeric + a few path-safe chars,
/// long enough that accidental substring collisions are vanishingly unlikely.
fn ident_token() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9_-]{3,12}".prop_filter("non-empty", |s| !s.is_empty())
}

/// A plausible home directory built from a username token.
fn home_for(user: &str) -> String {
    format!("/home/{user}")
}

proptest! {
    /// For an arbitrary body that EMBEDS the host's home path, the sanitized
    /// body never contains the literal home path.
    #[test]
    fn home_path_never_leaks(
        user in ident_token(),
        prefix in ".{0,40}",
        suffix in "[a-zA-Z0-9/_.-]{0,40}",
    ) {
        let home = home_for(&user);
        let identity = HostIdentity {
            home_dir: Some(home.clone()),
            username: Some(user.clone()),
            hostname: Some(format!("{user}-host")),
            ..Default::default()
        };
        let s = Sanitizer::with_identity(identity);

        let raw = format!("{prefix}{home}/{suffix}");
        let out = s.scrub_field(&raw);
        // The literal home path must be gone (the security guarantee). A visible
        // placeholder must stand in (no silent deletion that could fuse adjacent
        // tokens). Depending on the surrounding prefix/suffix the sanitizer
        // pipeline legitimately emits ANY of these non-leaking substitutions:
        // the legacy `<HOME>` (well-formed prefix match), a fail-closed path
        // anchor (`<home>`/`<tmp>`/`<cache>`/`<src>`), the typeless `<path>` drop
        // (malformed/foreign absolute path), the identity placeholders
        // (`<USER>`/`<HOST>`), the whole-field `<redacted>` (a sensitive-looking
        // field), or the size-cap `truncated` marker.
        prop_assert!(!out.contains(&home), "home path leaked: {out}");
        const PLACEHOLDERS: &[&str] = &[
            "<HOME>", "<home>", "<tmp>", "<cache>", "<src>", "<path>", "<USER>", "<HOST>",
            "<scrubbed>", "<redacted>", "truncated",
        ];
        prop_assert!(
            PLACEHOLDERS.iter().any(|p| out.contains(p)),
            "no placeholder stood in for the home path: {out}"
        );
    }

    /// For an arbitrary body that mentions the username as a standalone token,
    /// the sanitized field never contains that standalone username.
    #[test]
    fn username_never_leaks_as_standalone(
        user in ident_token(),
        pre in "[a-zA-Z0-9 ]{0,20}",
        post in "[a-zA-Z0-9 ]{0,20}",
    ) {
        let identity = HostIdentity {
            home_dir: Some(home_for(&user)),
            username: Some(user.clone()),
            hostname: Some(format!("{user}-host")),
            ..Default::default()
        };
        let s = Sanitizer::with_identity(identity);

        // Username appears bounded by spaces (standalone).
        let raw = format!("{pre} {user} {post}");
        let out = s.scrub_field(&raw);
        // No standalone whitespace-delimited token equals the username.
        let leaked = out.split_whitespace().any(|w| w == user);
        prop_assert!(!leaked, "username leaked as standalone token in: {out}");
    }

    /// The full-report sanitizer strips the home path from EVERY surface
    /// (title, body, metadata) for arbitrary inputs.
    #[test]
    fn full_report_sanitize_strips_home_everywhere(
        user in ident_token(),
        title_tail in "[a-zA-Z0-9/_.-]{0,30}",
        body_tail in "[a-zA-Z0-9/_.-]{0,30}",
        meta_tail in "[a-zA-Z0-9/_.-]{0,30}",
    ) {
        let home = home_for(&user);
        let identity = HostIdentity {
            home_dir: Some(home.clone()),
            username: Some(user.clone()),
            hostname: Some(format!("{user}-host")),
            ..Default::default()
        };
        let s = Sanitizer::with_identity(identity);

        let report = Report::manual_issue(
            format!("{home}/{title_tail}"),
            format!("at {home}/{body_tail}:1"),
        )
        .with_metadata("cwd", format!("{home}/{meta_tail}"));

        let out = s.sanitize(report);
        prop_assert!(!out.title.contains(&home));
        prop_assert!(!out.body.contains(&home));
        for (_k, v) in &out.metadata {
            prop_assert!(!v.contains(&home), "home leaked in metadata: {v}");
        }
    }

    /// Environment-variable scrubbing never lets a VALUE through, regardless of
    /// what the value contains (paths, secrets, identity).
    #[test]
    fn env_values_never_leak(
        key in "[A-Z][A-Z0-9_]{1,16}",
        value in ".{0,60}",
    ) {
        let s = Sanitizer::new();
        let pairs = vec![(key.clone(), value.clone())];
        let out = s.scrub_env(&pairs);
        prop_assert_eq!(out.len(), 1);
        // The key is preserved; the value is the placeholder, never the input.
        prop_assert_eq!(&out[0].1, "<scrubbed>");
        // Only assert leakage when the value is itself non-trivial.
        if !value.is_empty() && value != "<scrubbed>" {
            prop_assert!(out[0].1 != value || value == "<scrubbed>");
        }
    }

    /// Size caps hold for arbitrary-length inputs — the sanitized field is never
    /// larger than the configured cap.
    #[test]
    fn size_cap_always_holds(input in ".{0,5000}") {
        use itasha_report_core::sanitize::SizeCaps;
        let s = Sanitizer::new().with_caps(SizeCaps { max_field_bytes: 256, max_lines: 100 });
        let out = s.scrub_field(&input);
        prop_assert!(out.len() <= 256, "size cap exceeded: {} > 256", out.len());
    }

    /// Anonymity hardening #3: an absolute path belonging to a DIFFERENT user
    /// (one the sanitizer cannot attribute to the local home) never survives —
    /// it is either anchored to a symbol or dropped to <path>. The foreign
    /// username segment never appears in the output.
    #[test]
    fn foreign_user_absolute_path_never_leaks(
        local in ident_token(),
        foreign in ident_token(),
        tail in "[a-zA-Z0-9/_.-]{1,30}",
    ) {
        prop_assume!(local != foreign);
        let s = anchoring_sanitizer(&local);
        // A foreign user's home-style path under a DIFFERENT root the anchoring
        // does not recognize (/data/<foreign>/...).
        let raw = format!("opened /data/{foreign}/{tail} now");
        let out = s.scrub_field(&raw);
        prop_assert!(!out.contains(&foreign), "foreign username leaked: {out}");
        prop_assert!(!out.contains(&format!("/data/{foreign}")), "raw foreign path leaked: {out}");
        prop_assert!(out.contains(PATH_DROP), "foreign path not dropped: {out}");
    }

    /// Anonymity hardening #4: an email embedded in arbitrary surrounding prose
    /// is always redacted to the uniform token; the email never survives, and
    /// the token carries no type tag.
    #[test]
    fn embedded_email_never_leaks(
        pre in "[a-zA-Z ]{0,20}",
        local in "[a-z][a-z0-9]{1,10}",
        domain in "[a-z][a-z0-9]{1,8}",
        post in "[a-zA-Z ]{0,20}",
    ) {
        let s = Sanitizer::new();
        let email = format!("{local}@{domain}.com");
        let raw = format!("{pre} {email} {post}");
        let out = s.scrub_field(&raw);
        prop_assert!(!out.contains(&email), "email leaked: {out}");
        prop_assert!(out.contains(REDACTED), "email not redacted: {out}");
        // Typeless: the literal "email" type tag must not be emitted as a marker.
        prop_assert!(!out.contains("[email]"), "type tag leaked: {out}");
    }
}

/// Anonymity hardening #4 (non-proptest): the redaction token reveals neither
/// the TYPE nor the COUNT of redactions — a run of distinct PII shapes collapses
/// to exactly one uniform token.
#[test]
fn redaction_is_typeless_and_count_collapsed() {
    let out = redact::redact_free_text(
        "a@b.com 10.0.0.1 00:11:22:33:44:55 550e8400-e29b-41d4-a716-446655440000",
    );
    // Exactly one token despite four distinct sensitive shapes.
    assert_eq!(
        out.matches(REDACTED).count(),
        1,
        "count not collapsed: {out}"
    );
    // No type tag of any kind leaked.
    for tag in ["email", "ipv4", "mac", "uuid", "[ip]", "[email]"] {
        assert!(!out.to_lowercase().contains(tag), "type tag leaked: {out}");
    }
}
