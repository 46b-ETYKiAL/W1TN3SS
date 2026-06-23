//! Quasi-identifier coarsening + the fail-closed allowlist envelope filter.
//!
//! Anonymity hardening #2 (gap D-4): a desktop crash report is
//! browser-fingerprintable. The tuple `app-version × OS-build × locale ×
//! timezone × module-set × hostname × …` compounds toward global uniqueness
//! (~30 bits identifies every individual on Earth — web.dev / W3C fingerprinting
//! guidance). Two structural defenses live here:
//!
//! 1. **A fail-closed allowlist.** [`safe_fields`] emits ONLY a small set of
//!    pre-approved, COARSENED keys. Any key not on the allowlist is DROPPED — a
//!    future dev who attaches a new metadata key cannot leak it to the wire by
//!    default (the "zero-day field" denylists let through; the allowlist refuses
//!    it). This is the OneUptime "block unknown fields, don't redact after the
//!    fact" rule.
//!
//! 2. **Coarsening of the quasi-identifiers that ARE kept.** Exact version → its
//!    MAJOR.MINOR (drop patch/build/commit). OS → MAJOR.MINOR (drop the build
//!    number). Locale → LANGUAGE only (drop region + script). High-entropy
//!    direct/quasi identifiers — timezone, build-hash, argv, env, hostname, MAC,
//!    machine-GUID, the full module list — are dropped ENTIRELY (they are not on
//!    the allowlist, so #1 already drops them; the explicit drop-set below
//!    documents the intent and guards against an allowlist mistake).
//!
//! The whole point: minimize the surviving fingerprint surface. Even after
//! coarsening, the residual tuple is gated downstream by k-anonymity; this layer
//! makes that tuple as low-entropy as possible.

/// The allowlist of metadata keys that may reach the wire, each paired with the
/// coarsening function applied to its value. A key NOT in this list is dropped.
///
/// Keep this list tiny and justified — every entry costs anonymity-set entropy.
/// The three entries below are the minimum needed to triage a crash to a
/// version + platform class without singling out a device.
/// A value-coarsening function: maps a raw metadata value to its low-entropy
/// form, or `None` to drop it.
type CoarsenFn = fn(&str) -> Option<String>;

const ALLOWED_FIELDS: &[(&str, CoarsenFn)] = &[
    // App version, coarsened to MAJOR.MINOR (drops patch / build / +sha).
    ("app_version", coarsen_version),
    // OS, coarsened to NAME MAJOR.MINOR (drops the build/patch number).
    ("os", coarsen_os),
    // Locale, coarsened to the LANGUAGE subtag only (drops region/script/tz).
    ("locale", coarsen_locale),
];

/// Keys that are ALWAYS dropped, named explicitly for intent + defense-in-depth.
///
/// These are direct identifiers or high-entropy quasi-identifiers. They are not
/// on [`ALLOWED_FIELDS`], so [`safe_fields`] already drops them; listing them
/// makes a regression (someone adding one to the allowlist) loud in review and
/// lets [`is_explicitly_dropped`] assert the contract in tests.
pub const ALWAYS_DROPPED: &[&str] = &[
    "timezone",
    "tz",
    "build_hash",
    "build",
    "commit",
    "commit_sha",
    "sha",
    "argv",
    "args",
    "cmdline",
    "command_line",
    "env",
    "environment",
    "hostname",
    "host",
    "mac",
    "mac_address",
    "machine_guid",
    "machine_id",
    "install_id",
    "device_id",
    "modules",
    "module_list",
    "loaded_modules",
    "cpu",
    "cpu_model",
    "gpu",
    "ram",
    "memory",
    "screen",
    "resolution",
    "user",
    "username",
];

/// Apply the fail-closed allowlist to a report's metadata, returning ONLY the
/// pre-approved, coarsened key/value pairs in a stable (allowlist) order.
///
/// * A key not on [`ALLOWED_FIELDS`] is **dropped** (fail closed).
/// * A key on the allowlist whose value coarsens to `None` (empty / unparseable)
///   is also dropped — we never emit a placeholder that itself carries entropy.
/// * The output order follows the allowlist, so two reports with the same
///   coarsened tuple serialize identically (no key-order fingerprint).
#[must_use]
pub fn safe_fields(metadata: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (allowed_key, coarsen) in ALLOWED_FIELDS {
        // Take the FIRST occurrence of the allowed key (case-insensitive on the
        // key name); duplicates beyond the first are dropped.
        if let Some((_, raw)) = metadata
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(allowed_key))
        {
            if let Some(coarse) = coarsen(raw) {
                out.push(((*allowed_key).to_string(), coarse));
            }
        }
    }
    out
}

/// True if `key` is on the always-dropped set (case-insensitive). Used by tests
/// to lock the drop contract.
#[must_use]
pub fn is_explicitly_dropped(key: &str) -> bool {
    ALWAYS_DROPPED.iter().any(|k| k.eq_ignore_ascii_case(key))
}

/// Coarsen an app version to `MAJOR.MINOR`, dropping patch / pre-release / build
/// metadata. `"1.4.37-rc2+sha"` → `"1.4"`. Returns `None` if no major.minor can
/// be parsed.
#[must_use]
pub fn coarsen_version(raw: &str) -> Option<String> {
    // Strip a leading 'v'/'V' and any leading whitespace.
    let s = raw.trim().trim_start_matches(['v', 'V']);
    // Cut at the first '-' (pre-release) or '+' (build metadata).
    let core = s.split(['-', '+']).next().unwrap_or(s);
    let mut parts = core.split('.');
    let major = parts.next()?.trim();
    let minor = parts.next().unwrap_or("0").trim();
    if major.is_empty() || !major.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let minor = if minor.chars().all(|c| c.is_ascii_digit()) && !minor.is_empty() {
        minor
    } else {
        "0"
    };
    Some(format!("{major}.{minor}"))
}

/// Coarsen an OS string to a platform name + `MAJOR.MINOR`, dropping the build
/// number. `"Windows 11 26100.1234"` → `"Windows 11"`;
/// `"macOS 14.5 23F79"` → `"macOS 14.5"`; `"linux"` → `"linux"`.
///
/// The strategy: keep the leading alphabetic platform words and at most the
/// first `MAJOR[.MINOR]` numeric token; drop everything after (build numbers,
/// patch builds like `23F79`).
#[must_use]
pub fn coarsen_os(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let mut words: Vec<String> = Vec::new();
    let mut took_version = false;
    for tok in s.split_whitespace() {
        let first = tok.chars().next().unwrap_or(' ');
        if first.is_ascii_alphabetic() && !took_version {
            // A platform name word (e.g. "Windows", "macOS", "linux").
            words.push(tok.to_string());
        } else if first.is_ascii_digit() && !took_version {
            // The first numeric token → keep only MAJOR.MINOR of it.
            if let Some(v) = coarsen_os_version_token(tok) {
                words.push(v);
            }
            took_version = true;
        } else {
            // Anything after the version token (build numbers, patch builds) is
            // dropped — fail closed against a build-number fingerprint.
            break;
        }
    }
    if words.is_empty() {
        None
    } else {
        Some(words.join(" "))
    }
}

/// Reduce a numeric OS version token to MAJOR.MINOR. `"26100.1234"` → `"26100"`
/// (no minor present after the build split), `"14.5.1"` → `"14.5"`.
fn coarsen_os_version_token(tok: &str) -> Option<String> {
    let mut parts = tok.split('.');
    let major = parts.next()?.trim();
    if major.is_empty() || !major.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    match parts.next() {
        Some(minor) if !minor.is_empty() && minor.chars().all(|c| c.is_ascii_digit()) => {
            Some(format!("{major}.{minor}"))
        }
        _ => Some(major.to_string()),
    }
}

/// Coarsen a locale to its LANGUAGE subtag only, dropping region / script /
/// variant / extension. `"en-US"` → `"en"`, `"zh-Hant-TW"` → `"zh"`,
/// `"pt_BR.UTF-8"` → `"pt"`. Returns `None` if no language subtag survives.
#[must_use]
pub fn coarsen_locale(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // The language subtag is the leading run before the first '-', '_', or '.'.
    let lang = s.split(['-', '_', '.']).next().unwrap_or(s).trim();
    // BCP-47 language subtags are 2–3 ASCII letters (allow "und"); lowercase it.
    if lang.is_empty() || !lang.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(lang.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_coarsened_to_major_minor() {
        assert_eq!(coarsen_version("1.4.37-rc2+abcdef").as_deref(), Some("1.4"));
        assert_eq!(coarsen_version("v2.10.0").as_deref(), Some("2.10"));
        assert_eq!(coarsen_version("3").as_deref(), Some("3.0"));
        assert_eq!(coarsen_version("0.2.0").as_deref(), Some("0.2"));
        // Build metadata / commit sha never survive.
        assert_eq!(coarsen_version("1.4.37+build.99").as_deref(), Some("1.4"));
        assert_eq!(coarsen_version("garbage").as_deref(), None);
    }

    #[test]
    fn os_is_coarsened_dropping_build_number() {
        assert_eq!(
            coarsen_os("Windows 11 26100.1234").as_deref(),
            Some("Windows 11")
        );
        assert_eq!(
            coarsen_os("macOS 14.5 23F79").as_deref(),
            Some("macOS 14.5")
        );
        assert_eq!(coarsen_os("linux").as_deref(), Some("linux"));
        assert_eq!(
            coarsen_os("Ubuntu 24.04.1 LTS").as_deref(),
            Some("Ubuntu 24.04")
        );
        assert_eq!(coarsen_os("   ").as_deref(), None);
        // The raw build number must never appear.
        assert!(!coarsen_os("Windows 11 26100.1234")
            .unwrap()
            .contains("26100"));
        assert!(!coarsen_os("macOS 14.5 23F79").unwrap().contains("23F79"));
    }

    #[test]
    fn locale_is_coarsened_to_language_only() {
        assert_eq!(coarsen_locale("en-US").as_deref(), Some("en"));
        assert_eq!(coarsen_locale("zh-Hant-TW").as_deref(), Some("zh"));
        assert_eq!(coarsen_locale("pt_BR.UTF-8").as_deref(), Some("pt"));
        assert_eq!(coarsen_locale("de").as_deref(), Some("de"));
        assert_eq!(coarsen_locale("EN").as_deref(), Some("en"));
        assert_eq!(coarsen_locale("123").as_deref(), None);
        // The region/timezone-bearing suffix must never survive.
        assert!(!coarsen_locale("en-US").unwrap().contains("US"));
    }

    #[test]
    fn safe_fields_keeps_only_allowlisted_coarsened_keys() {
        let meta = vec![
            ("app_version".to_string(), "1.4.37-rc2".to_string()),
            ("os".to_string(), "Windows 11 26100.1234".to_string()),
            ("locale".to_string(), "en-US".to_string()),
            // Everything below is a quasi/direct identifier → must be DROPPED.
            ("timezone".to_string(), "America/New_York".to_string()),
            ("hostname".to_string(), "ada-laptop".to_string()),
            ("mac".to_string(), "00:11:22:33:44:55".to_string()),
            ("machine_guid".to_string(), "deadbeef".to_string()),
            ("modules".to_string(), "a.dll,b.dll,evil-av.dll".to_string()),
            ("a_totally_new_field".to_string(), "leak me".to_string()),
        ];
        let out = safe_fields(&meta);
        let keys: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["app_version", "os", "locale"]);
        // Values are coarsened.
        assert_eq!(out[0].1, "1.4");
        assert_eq!(out[1].1, "Windows 11");
        assert_eq!(out[2].1, "en");
        // No dropped key or value content survived anywhere.
        let flat = format!("{out:?}");
        for needle in [
            "timezone",
            "America",
            "ada-laptop",
            "00:11",
            "deadbeef",
            "evil-av",
            "leak me",
        ] {
            assert!(!flat.contains(needle), "dropped content leaked: {needle}");
        }
    }

    #[test]
    fn unknown_key_is_dropped_fail_closed() {
        // The single most important property: a key the allowlist does not know
        // about NEVER reaches the output.
        let meta = vec![("future_zero_day_field".to_string(), "secret".to_string())];
        let out = safe_fields(&meta);
        assert!(out.is_empty(), "unknown key must be dropped, got {out:?}");
    }

    #[test]
    fn always_dropped_set_is_never_emitted() {
        for key in ALWAYS_DROPPED {
            assert!(is_explicitly_dropped(key));
            let meta = vec![((*key).to_string(), "value".to_string())];
            let out = safe_fields(&meta);
            assert!(out.is_empty(), "ALWAYS_DROPPED key {key} leaked: {out:?}");
        }
    }

    #[test]
    fn allowlisted_key_with_uncoarsenable_value_is_dropped() {
        // safe_fields (line 109): an allowlisted key whose value coarsens to None
        // (here app_version="garbage" → None) is DROPPED, not emitted as a
        // placeholder. Only the coarsenable os survives.
        let meta = vec![
            ("app_version".to_string(), "garbage".to_string()),
            ("os".to_string(), "linux".to_string()),
            ("locale".to_string(), "123".to_string()),
        ];
        let out = safe_fields(&meta);
        let keys: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["os"], "uncoarsenable allowlisted keys must drop");
        assert_eq!(out[0].1, "linux");
    }

    #[test]
    fn version_minor_defaults_to_zero_when_non_numeric() {
        // coarsen_version (lines 137-141): a non-numeric minor token falls back to
        // "0" rather than leaking the raw text.
        assert_eq!(coarsen_version("2.x").as_deref(), Some("2.0"));
        assert_eq!(coarsen_version("2.beta").as_deref(), Some("2.0"));
        // An empty minor (trailing dot) also defaults to 0.
        assert_eq!(coarsen_version("5.").as_deref(), Some("5.0"));
    }

    #[test]
    fn coarsen_os_breaks_on_non_alnum_after_name() {
        // coarsen_os (line 169 — the `break`): a token whose first char is neither
        // alphabetic nor a digit (and no version taken yet) terminates the scan.
        // Here the leading "(" token stops accumulation before any version.
        assert_eq!(coarsen_os("Debian (sid) 13").as_deref(), Some("Debian"));
    }

    #[test]
    fn coarsen_os_returns_none_when_no_words_survive() {
        // coarsen_os (line 178 — `if words.is_empty()`): an input whose only
        // tokens are non-alpha/non-digit yields no words → None.
        assert_eq!(coarsen_os("(((").as_deref(), None);
        assert_eq!(coarsen_os("-- ::").as_deref(), None);
    }

    #[test]
    fn coarsen_os_version_token_rejects_non_numeric_major() {
        // coarsen_os hitting coarsen_os_version_token (line 189-190): a numeric-led
        // OS token whose major segment is empty/non-numeric is rejected. A token
        // starting with a digit but with an empty major (".5") returns None and is
        // skipped, leaving only the platform name.
        assert_eq!(coarsen_os("Plan9 .5").as_deref(), Some("Plan9"));
    }

    #[test]
    fn coarsen_locale_rejects_empty_and_non_alpha_language() {
        // coarsen_locale (line 207 — `if lang.is_empty() || ...`): a leading
        // separator yields an empty language subtag → None; a numeric leading run
        // also fails the all-alphabetic check.
        assert_eq!(coarsen_locale("-US").as_deref(), None);
        assert_eq!(coarsen_locale("_BR").as_deref(), None);
        assert_eq!(coarsen_locale("9x-YZ").as_deref(), None);
        // Whitespace-only coarsens to None via the earlier empty guard.
        assert_eq!(coarsen_locale("   ").as_deref(), None);
    }

    #[test]
    fn allowlist_output_order_is_stable_regardless_of_input_order() {
        let a = vec![
            ("locale".to_string(), "fr-FR".to_string()),
            ("app_version".to_string(), "9.9.9".to_string()),
            ("os".to_string(), "linux".to_string()),
        ];
        let b = vec![
            ("os".to_string(), "linux".to_string()),
            ("locale".to_string(), "fr-FR".to_string()),
            ("app_version".to_string(), "9.9.9".to_string()),
        ];
        // Same coarsened tuple → identical serialized field order (no key-order
        // fingerprint between two devices reporting the same class).
        assert_eq!(safe_fields(&a), safe_fields(&b));
    }
}
