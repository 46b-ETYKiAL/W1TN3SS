//! The Tier-2 **heightened-consent** gate.
//!
//! Native minidump capture is a SEPARATE, higher-sensitivity consent stream
//! from the Tier-1 previewable text the safe `itasha-report-core` crate
//! handles. A minidump embeds raw thread-stack memory that — for a note
//! editor — can hold fragments of the user's open documents, and (unlike
//! Tier-1 text) it is binary and therefore NOT user-previewable before it is
//! written. Because the user cannot inspect-and-edit the exact captured bytes,
//! arming this stream requires an explicit, heightened acceptance of that
//! documented tradeoff.
//!
//! This module encodes that gate at the type level: a [`Tier2ConsentToken`]
//! can only be minted by the host calling [`Tier2ConsentToken::granted`],
//! which the host does **only after** the user has accepted the heightened
//! disclosure. Every capture-arming and minidump-emit path in this crate
//! requires a `&Tier2ConsentToken`, so there is no code path that captures or
//! emits a minidump without an explicit, host-minted heightened-consent
//! decision.
//!
//! The token is deliberately NOT `Default`, NOT `Deserialize`, and NOT
//! constructible from untrusted input — mirroring `itasha-report-core`'s
//! Tier-1 `ConsentToken`, but as an independent, non-interchangeable type so
//! the two streams can never be conflated under one toggle.

use itasha_report_core::consent::ephemeral_nonce;

/// The default heightened-consent disclosure string.
///
/// Hosts (e.g. the SCR1B3 consent dialog, plan-732) render this — or an
/// override via [`Tier2ConsentToken::granted_with_disclosure`] — verbatim to
/// the user before minting a token. It is a centralized, host-overridable
/// constant (NOT inlined in capture logic) so a future locale pack needs no
/// code change. It uses consent language ("may contain fragments of your open
/// documents"), never beacon/telemetry/always-on/tracking wording.
pub const TIER2_CONSENT_DISCLOSURE: &str =
    "A crash report may contain fragments of your open documents. \
It stays on this device and is never sent automatically — you choose whether to send it.";

/// A non-forgeable, non-serializable marker proving the host obtained explicit
/// **heightened** (Tier-2) user consent for native minidump capture.
///
/// Construct via [`Tier2ConsentToken::granted`]. The token carries no
/// identifying data — only an ephemeral per-capture nonce ([`Self::nonce`])
/// for receive-side de-duplication, never a stable device/install id. It also
/// records the exact disclosure string the user accepted, so the audit trail
/// can prove which wording was shown.
#[derive(Debug, Clone)]
pub struct Tier2ConsentToken {
    nonce: String,
    disclosure: String,
}

impl Tier2ConsentToken {
    /// Mint a Tier-2 consent token against the default disclosure
    /// ([`TIER2_CONSENT_DISCLOSURE`]).
    ///
    /// The host calls this **only after** the user has explicitly accepted the
    /// heightened disclosure for a capture session. Each call yields a fresh
    /// ephemeral nonce; the token carries no persistent identity.
    #[must_use]
    pub fn granted() -> Self {
        Self::granted_with_disclosure(TIER2_CONSENT_DISCLOSURE)
    }

    /// Mint a Tier-2 consent token against a host-overridden disclosure string
    /// (e.g. a localized rendering). The string the user actually accepted is
    /// recorded on the token.
    #[must_use]
    pub fn granted_with_disclosure(disclosure: impl Into<String>) -> Self {
        Self {
            nonce: ephemeral_nonce(),
            disclosure: disclosure.into(),
        }
    }

    /// The ephemeral per-capture nonce. Used once for receive-side
    /// de-duplication, then discarded. NEVER a stable device/install id.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// The exact disclosure string the user accepted when this token was
    /// minted.
    #[must_use]
    pub fn disclosure(&self) -> &str {
        &self.disclosure
    }
}

// The ephemeral per-capture nonce is minted by `itasha-report-core`'s single
// canonical `ephemeral_nonce` generator (imported at the top of this module),
// NOT a second, divergent copy.
//
// This crate previously had its own `SystemTime::now()`-nanos + `AtomicU64`
// counter generator. That form was both time-orderable AND sequence-orderable —
// exactly the linkage primitive that report-core's gap-D-2 hardening removed —
// so the Tier-2 stream silently regressed below the Tier-1 unlinkability bar
// while its doc-comment claimed it "mirrors" the core generator. Reusing the
// one CSPRNG implementation makes that claim literally true and structurally
// prevents the two streams from drifting apart again.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disclosure_uses_consent_language_not_surveillance() {
        let d = TIER2_CONSENT_DISCLOSURE.to_lowercase();
        // Heightened-consent wording must disclose the document-fragment risk.
        assert!(d.contains("fragments of your open documents"));
        assert!(d.contains("never sent automatically"));
        // And must NOT imply surveillance / always-on telemetry.
        for banned in [
            "beacon",
            "telemetry",
            "always-on",
            "tracking",
            "surveillance",
        ] {
            assert!(
                !d.contains(banned),
                "disclosure must not contain {banned:?}"
            );
        }
    }

    #[test]
    fn granted_token_has_nonempty_nonce_and_default_disclosure() {
        let t = Tier2ConsentToken::granted();
        assert!(!t.nonce().is_empty());
        assert_eq!(t.disclosure(), TIER2_CONSENT_DISCLOSURE);
    }

    #[test]
    fn nonces_are_ephemeral_and_unique() {
        let a = Tier2ConsentToken::granted();
        let b = Tier2ConsentToken::granted();
        assert_ne!(a.nonce(), b.nonce());
    }

    #[test]
    fn nonce_is_the_unlinkable_csprng_shape_not_a_time_counter() {
        // Regression guard for the gap-D-2 divergence: the Tier-2 nonce MUST be
        // the same unlinkable 32-lowercase-hex CSPRNG shape as report-core's
        // Tier-1 nonce. The old `{nanos:x}-{seq:x}` form carried a `-`
        // separator, was variable-length, and was time/sequence-orderable — all
        // of which these assertions reject.
        for _ in 0..256 {
            let nonce = Tier2ConsentToken::granted().nonce().to_string();
            assert_eq!(
                nonce.len(),
                32,
                "nonce must be 32 hex chars (128 bits), got {nonce:?}"
            );
            assert!(
                nonce.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "nonce must be pure lowercase hex (no '-' separator, no time/seq structure), got {nonce:?}"
            );
        }
    }

    #[test]
    fn host_can_override_disclosure_for_localization() {
        let localized = "Un vidage mémoire peut contenir des fragments de vos documents ouverts.";
        let t = Tier2ConsentToken::granted_with_disclosure(localized);
        assert_eq!(t.disclosure(), localized);
        assert!(!t.nonce().is_empty());
    }

    #[test]
    fn many_nonces_are_all_distinct() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(Tier2ConsentToken::granted().nonce().to_string()));
        }
    }
}
