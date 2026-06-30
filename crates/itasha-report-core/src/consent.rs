//! The consent token — the type-level gate on transmission.
//!
//! A [`ConsentToken`] can only be constructed by the host calling
//! [`ConsentToken::granted`], which the host does **only after** the user
//! has explicitly agreed to send a specific report. Because every
//! [`crate::backend::IngestBackend::send`] call requires a `&ConsentToken`
//! argument, there is no transmission path that does not pass through an
//! explicit, host-minted consent decision.
//!
//! The token carries **no identifying data** — it is a pure capability marker
//! plus an ephemeral per-report nonce used once and discarded. It is
//! deliberately NOT `Default`, NOT `Deserialize`, and NOT constructible from
//! untrusted input.

/// A non-forgeable, non-serializable marker proving the host obtained explicit
/// user consent for a single transmission.
///
/// Construct via [`ConsentToken::granted`]. The token holds a fresh ephemeral
/// nonce ([`ConsentToken::nonce`]) for de-duplication on the receiving side;
/// the nonce is per-report and is never a stable device/install identifier.
#[derive(Debug, Clone)]
pub struct ConsentToken {
    nonce: String,
}

impl ConsentToken {
    /// Mint a consent token. The host calls this **only after** the user has
    /// explicitly agreed to send a report. Each call yields a fresh ephemeral
    /// nonce; the token carries no persistent identity.
    #[must_use]
    pub fn granted() -> Self {
        Self {
            nonce: ephemeral_nonce(),
        }
    }

    /// The ephemeral per-report nonce. Used once for receive-side
    /// de-duplication, then discarded. NEVER a stable device/install id.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}

/// Number of random bytes drawn for the ephemeral nonce. 16 bytes = 128 bits of
/// CSPRNG entropy → collision-free in practice and unlinkable by construction.
const NONCE_BYTES: usize = 16;

/// Generate a fresh, non-identifying, **unlinkable** ephemeral nonce — the
/// single SDK-wide nonce generator shared by every W1TN3SS consent stream.
///
/// This is the **one** canonical implementation. The Tier-2 heightened-consent
/// token in the sibling `itasha-crash-capture` crate calls straight into this
/// function, so both streams are guaranteed to carry the identical unlinkable
/// nonce shape (32 lowercase-hex chars) — there is no second, divergent copy to
/// drift out of sync.
///
/// Anonymity hardening #1 (gap D-2): the nonce is `NONCE_BYTES` of OS-CSPRNG
/// output, hex-encoded. There is **no time component and no monotonic counter**
/// — the previous `SystemTime::now()`-nanos + sequence form was both
/// time-orderable AND sequence-orderable, a linkage primitive that let a passive
/// store-holder reconstruct submission timing/ordering and cluster reports to a
/// session. A CSPRNG value reveals nothing: two nonces minted back-to-back are
/// not ordered, not adjacent, and not correlated. It is still ephemeral
/// (per-report, used once for de-dup then discarded) and deliberately NOT a
/// stable machine fingerprint, MAC, or install id.
#[must_use]
pub fn ephemeral_nonce() -> String {
    use rand::RngCore;

    let mut bytes = [0u8; NONCE_BYTES];
    // `thread_rng` is the OS-seeded CSPRNG; `fill_bytes` is infallible.
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(NONCE_BYTES * 2);
    for b in bytes {
        // Lowercase hex, zero-padded — pure [0-9a-f], directly usable as the
        // Sentry event_id hex source with no time/sequence structure to leak.
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn granted_token_has_nonempty_nonce() {
        let t = ConsentToken::granted();
        assert!(!t.nonce().is_empty());
    }

    #[test]
    fn nonces_are_ephemeral_and_unique() {
        let a = ConsentToken::granted();
        let b = ConsentToken::granted();
        // Two tokens minted in the same process differ — the nonce is NOT a
        // stable identifier.
        assert_ne!(a.nonce(), b.nonce());
    }

    #[test]
    fn many_nonces_are_all_distinct() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(ConsentToken::granted().nonce().to_string()));
        }
    }

    #[test]
    fn nonce_is_fixed_width_lowercase_hex() {
        // 16 bytes → 32 lowercase hex chars, no separators, no structure.
        let n = ConsentToken::granted();
        assert_eq!(n.nonce().len(), NONCE_BYTES * 2);
        assert!(
            n.nonce()
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "nonce must be pure lowercase hex: {}",
            n.nonce()
        );
        // The old form carried a '-' separating nanos from the sequence counter;
        // the random form must not.
        assert!(!n.nonce().contains('-'), "nonce must carry no separator");
    }

    /// Anonymity invariant (gap D-2): nonces have NO time component. The old
    /// `SystemTime::now()`-nanos form made nonces minted close in time share a
    /// long common prefix (the high-order nanosecond digits move slowly). A
    /// CSPRNG nonce shares no such prefix: across many back-to-back mints the
    /// average shared leading-hex-digit run is ~0, never the long run a clock
    /// would produce.
    #[test]
    fn nonces_close_in_time_share_no_time_prefix() {
        // Mint pairs back-to-back (minimal wall-clock gap between a & b).
        let mut total_shared_prefix = 0usize;
        let pairs = 200;
        for _ in 0..pairs {
            let a = ConsentToken::granted();
            let b = ConsentToken::granted();
            let shared = a
                .nonce()
                .chars()
                .zip(b.nonce().chars())
                .take_while(|(x, y)| x == y)
                .count();
            total_shared_prefix += shared;
        }
        // With 16-symbol (hex) alphabet, the expected shared prefix of two
        // independent random strings is ~1/15 per position → mean well under 1.
        // A time-ordered nonce would share many high-order digits (mean ≫ 4).
        let mean = total_shared_prefix as f64 / pairs as f64;
        assert!(
            mean < 1.5,
            "nonces minted close in time share a long common prefix (mean {mean:.3}) \
             — a time component is leaking"
        );
    }

    /// Anonymity invariant (gap D-2): nonces have NO monotonic-counter
    /// structure. The old form appended a per-process `seq` that strictly
    /// increased; interpreting each nonce as a big integer, the sequence was
    /// monotone. A CSPRNG sequence is NOT monotone — across many mints the
    /// numeric order is uncorrelated with mint order (both ascending and
    /// descending adjacent pairs occur).
    #[test]
    fn nonces_are_not_sequence_ordered() {
        let n = 400;
        let nonces: Vec<String> = (0..n)
            .map(|_| ConsentToken::granted().nonce().to_string())
            .collect();
        // Compare adjacent nonces lexicographically (valid since fixed-width hex
        // makes lexicographic order == big-integer order). A monotone counter
        // would make every adjacent pair ascending (descents == 0).
        let mut ascending = 0usize;
        let mut descending = 0usize;
        for w in nonces.windows(2) {
            match w[0].cmp(&w[1]) {
                std::cmp::Ordering::Less => ascending += 1,
                std::cmp::Ordering::Greater => descending += 1,
                std::cmp::Ordering::Equal => {}
            }
        }
        // Both directions must occur in meaningful numbers — neither near zero.
        // A monotonic counter yields descending == 0.
        assert!(
            descending > n / 8 && ascending > n / 8,
            "nonce ordering looks monotonic (asc={ascending}, desc={descending}) \
             — a sequence counter is leaking"
        );
    }
}
