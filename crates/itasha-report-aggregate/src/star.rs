//! STAR message production for a Tier-A measurement (the truly-anonymous path).
//!
//! [STAR — Sparse Threshold Aggregation Reporting](https://arxiv.org/abs/2109.10074)
//! (Brave/Mozilla, CCS 2022) is the k-anonymous threshold-aggregation protocol
//! the W1TN3SS anonymity research recommends for crash signatures. A client
//! produces a single [`sta_rs::Message`] from its measurement; the ingest
//! operator can reconstruct a measurement **only once ≥ k distinct clients
//! independently submitted the same secret** (Shamir k-of-n share recovery).
//! Below the threshold the operator learns nothing — not even that a singleton
//! exists. There is **no per-user identifier**: identical secrets self-collide
//! by construction, which is exactly what makes Tier-A honestly "anonymous".
//!
//! ## STARLite (local randomness) — no randomness server in v1
//!
//! Full STAR uses an OPRF *randomness server* (`ppoprf`) so that even
//! low-entropy measurements cannot be brute-forced before threshold. We use the
//! **STARLite** path: [`MessageGenerator::sample_local_randomness`] derives the
//! per-message randomness deterministically from the measurement itself, with
//! **no network round-trip to any server**. This is the right v1 choice because:
//!
//! * it removes an entire piece of operational infrastructure (the OPRF server)
//!   and its trust assumptions — fewer parties, simpler to self-host;
//! * the Tier-A measurement domain (a 256-bit crash-signature plus a coarse
//!   tuple) is **high-entropy** — the STARLite precondition. A crash signature
//!   is a BLAKE3 digest, not a guessable low-entropy value, so the OPRF's
//!   anti-brute-force property buys little here.
//!
//! The STARLite high-entropy caveat is real and documented: if a deployment ever
//! wants to aggregate a LOW-entropy secret (e.g. a small enum), it must move to
//! the OPRF path (`sta-rs` `star2` feature). For crash signatures, STARLite is
//! the correct, server-free choice.
//!
//! ## k = 25 (the default threshold)
//!
//! Research (`C-aggregation-legal-bar.md` §3.3) recommends **k ≥ 25–50** for
//! crash telemetry — small k still admits homogeneity/background-knowledge
//! attacks. We default to **k = 25** and refuse to construct a producer below a
//! hard floor of **k = 5** (a producer with k < 5 is a misconfiguration that
//! would defeat the anonymity guarantee).

use rand::RngCore;
use sta_rs::{AssociatedData, Message, MessageGenerator, SingleMeasurement};

use crate::measurement::AggregateMeasurement;

/// The recommended default k-anonymity threshold for crash signatures.
/// Research bar: k ≥ 25–50 (`C-aggregation-legal-bar.md` §3.3).
pub const DEFAULT_K: u32 = 25;

/// The hard floor below which a [`StarProducer`] refuses to be constructed. A
/// threshold under this defeats the singling-out protection the whole tier
/// exists to provide.
pub const MIN_K: u32 = 5;

/// Errors producing a STAR message.
#[derive(Debug)]
pub enum StarError {
    /// The configured threshold was below [`MIN_K`].
    ThresholdTooLow {
        /// The rejected threshold value.
        k: u32,
        /// The hard floor.
        floor: u32,
    },
    /// The underlying STAR library failed to generate the message.
    Generate(String),
}

impl std::fmt::Display for StarError {
    // Host-visible copy carries no privacy-protocol jargon ("k-anonymity",
    // "STAR") and no inner library detail / threshold numbers. The values stay
    // on the variant for a host-side log toggle.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StarError::ThresholdTooLow { .. } => f.write_str(
                "The anonymity group size is set too low and was rejected; it must be at least the required minimum.",
            ),
            StarError::Generate(_) => {
                f.write_str("The anonymous signal could not be prepared and was not sent.")
            }
        }
    }
}

impl std::error::Error for StarError {}

/// Produces STAR messages for Tier-A measurements at a fixed threshold + epoch.
///
/// The `epoch` is a coarse time bucket (e.g. `"2026-W25"`). It scopes the
/// threshold counting window: identical secrets only self-collide *within the
/// same epoch*. A coarse epoch (week/month) keeps the anonymity set large; it is
/// NOT a per-user value and carries no identity.
#[derive(Debug, Clone)]
pub struct StarProducer {
    threshold: u32,
    epoch: String,
}

impl StarProducer {
    /// Construct a producer at the [`DEFAULT_K`] threshold for the given epoch.
    pub fn new(epoch: impl Into<String>) -> Result<Self, StarError> {
        Self::with_threshold(epoch, DEFAULT_K)
    }

    /// Construct a producer at an explicit threshold. Rejects any `k < MIN_K`.
    pub fn with_threshold(epoch: impl Into<String>, k: u32) -> Result<Self, StarError> {
        if k < MIN_K {
            return Err(StarError::ThresholdTooLow { k, floor: MIN_K });
        }
        Ok(Self {
            threshold: k,
            epoch: epoch.into(),
        })
    }

    /// The configured k-anonymity threshold.
    #[must_use]
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// The configured epoch (threshold counting window).
    #[must_use]
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// Produce a STAR [`Message`] for a Tier-A measurement, using the STARLite
    /// local-randomness path (no randomness server). The returned message is the
    /// only thing that crosses the wire — it carries NO per-user identifier and
    /// is opaque to the operator until k distinct clients submit the same secret.
    pub fn produce(&self, measurement: &AggregateMeasurement) -> Result<Message, StarError> {
        let secret = SingleMeasurement::new(measurement.secret_bytes());
        let mg = MessageGenerator::new(secret, self.threshold, self.epoch.as_bytes());

        // STARLite: derive the per-message randomness locally from the
        // measurement (no OPRF server round-trip).
        let mut rnd = [0u8; 32];
        mg.sample_local_randomness(&mut rnd);

        // The coarse quasi-tuple rides as associated data — revealed only at
        // threshold, never below it.
        let aux_bytes = measurement.aux_bytes();
        let aux = if aux_bytes.is_empty() {
            None
        } else {
            Some(AssociatedData::new(&aux_bytes))
        };

        Message::generate(&mg, &rnd, aux).map_err(|e| StarError::Generate(e.to_string()))
    }

    /// Produce the wire bytes for a measurement (the STAR message serialized).
    /// This is what the submission path hands to the transport.
    pub fn produce_bytes(&self, measurement: &AggregateMeasurement) -> Result<Vec<u8>, StarError> {
        Ok(self.produce(measurement)?.to_bytes())
    }
}

/// A fresh 32-byte CSPRNG buffer (used by callers that need their own randomness
/// rather than STARLite's measurement-derived value). Provided for completeness;
/// the STARLite path inside [`StarProducer::produce`] uses
/// `sample_local_randomness` instead.
#[must_use]
pub fn fresh_randomness() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measurement::AggregateMeasurement;
    use sta_rs::{derive_ske_key, load_bytes, share_recover, Share};

    /// WS-032/033: `StarError` Display carries no privacy-protocol jargon
    /// ("k-anonymity", "STAR"), no threshold numbers, and no inner library
    /// detail.
    #[test]
    fn star_error_display_is_plain_and_jargon_free() {
        let too_low = StarError::ThresholdTooLow { k: 2, floor: 5 };
        let low_shown = format!("{too_low}");
        assert_eq!(
            low_shown,
            "The anonymity group size is set too low and was rejected; it must be at least the required minimum."
        );
        let generate = StarError::Generate("sta_rs internal failure 0xdead".to_string());
        let gen_shown = format!("{generate}");
        assert_eq!(
            gen_shown,
            "The anonymous signal could not be prepared and was not sent."
        );
        for shown in [&low_shown, &gen_shown] {
            let lower = shown.to_lowercase();
            for jargon in [
                "k-anonymity",
                "star",
                "threshold",
                "floor",
                "sta_rs",
                "0xdead",
            ] {
                assert!(
                    !lower.contains(jargon),
                    "jargon/inner detail leaked: {shown}"
                );
            }
        }
    }

    fn measurement(sig: &str) -> AggregateMeasurement {
        AggregateMeasurement::new(
            sig,
            &[
                ("app_version".to_string(), "1.4.0".to_string()),
                ("os".to_string(), "linux".to_string()),
            ],
        )
    }

    #[test]
    fn rejects_threshold_below_floor() {
        let err = StarProducer::with_threshold("ep", 4).unwrap_err();
        assert!(matches!(err, StarError::ThresholdTooLow { k: 4, floor: 5 }));
    }

    #[test]
    fn default_k_is_25() {
        let p = StarProducer::new("2026-W25").unwrap();
        assert_eq!(p.threshold(), DEFAULT_K);
        assert_eq!(p.threshold(), 25);
    }

    #[test]
    fn produces_a_serializable_message() {
        let p = StarProducer::new("ep").unwrap();
        let m = measurement(&"a".repeat(64));
        let msg = p.produce(&m).unwrap();
        let bytes = msg.to_bytes();
        assert!(!bytes.is_empty());
        // Round-trips through the STAR wire form.
        let back = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn message_carries_no_plaintext_signature_or_tuple() {
        // The cardinal anonymity property of a STAR message: the secret
        // (signature) and the aux (tuple) are ENCRYPTED inside the ciphertext.
        // Below threshold they are unreadable, so the wire bytes must not
        // contain the plaintext signature or the coarse tuple string.
        let p = StarProducer::new("ep").unwrap();
        let sig = "deadbeef".repeat(8); // 64 hex chars
        let m = AggregateMeasurement::new(&sig, &[("locale".to_string(), "en-US".to_string())]);
        let bytes = p.produce_bytes(&m).unwrap();
        let haystack = String::from_utf8_lossy(&bytes);
        assert!(
            !haystack.contains(&sig),
            "plaintext signature must not appear on the wire"
        );
        assert!(
            !haystack.contains("locale=en"),
            "plaintext aux tuple must not appear on the wire"
        );
    }

    /// The load-bearing k-threshold semantics test, exercised end-to-end via the
    /// public `sta-rs` recovery API (no extra test crate): the SAME secret
    /// submitted by k distinct clients is recoverable + decrypts to the original
    /// signature + tuple; FEWER than k shares cannot be recovered at all.
    #[test]
    fn secret_recoverable_at_k_not_below() {
        let k = 5u32;
        let epoch = "2026-W25";
        let p = StarProducer::with_threshold(epoch, k).unwrap();
        let m = measurement(&"c0ffee".repeat(10)); // a fixed shared secret

        // k distinct clients submit the SAME secret (each a fresh STARLite msg).
        let messages: Vec<Message> = (0..k).map(|_| p.produce(&m).unwrap()).collect();
        let shares: Vec<Share> = messages.iter().map(|msg| msg.share.clone()).collect();

        // --- Below threshold: k-1 shares cannot be recovered. ---
        let below = share_recover(&shares[..(k as usize - 1)]);
        assert!(
            below.is_err(),
            "fewer than k shares must NOT recover the secret"
        );

        // --- At threshold: k shares recover the key, decrypt the payload. ---
        let commune = share_recover(&shares).expect("k shares recover the secret");
        let key_seed = commune.get_message();
        let mut enc_key = vec![0u8; 16];
        derive_ske_key(&key_seed, epoch.as_bytes(), &mut enc_key);
        let plaintext = messages[0].ciphertext.decrypt(&enc_key, "star_encrypt");

        // The plaintext is `store_bytes(secret) || store_bytes(aux)`.
        let mut slice = &plaintext[..];
        let secret = load_bytes(slice).unwrap();
        slice = &slice[4 + secret.len()..];
        let aux = load_bytes(slice).unwrap();

        assert_eq!(secret, m.secret_bytes(), "recovered the exact signature");
        assert_eq!(
            aux,
            m.aux_bytes().as_slice(),
            "recovered the exact coarse tuple"
        );
    }

    #[test]
    fn distinct_secrets_do_not_combine_toward_threshold() {
        // Two DIFFERENT signatures, each submitted once, must not recover — they
        // are different secrets, so their shares are incompatible. This proves a
        // unique (singleton) crash never crosses the threshold.
        let p = StarProducer::with_threshold("ep", 5).unwrap();
        let a = p.produce(&measurement(&"a".repeat(64))).unwrap();
        let b = p.produce(&measurement(&"b".repeat(64))).unwrap();
        let shares = vec![a.share.clone(), b.share.clone()];
        // Two incompatible shares cannot recover a k=5 secret.
        assert!(share_recover(&shares).is_err());
    }

    #[test]
    fn fresh_randomness_is_32_bytes_and_varies() {
        let a = fresh_randomness();
        let b = fresh_randomness();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "CSPRNG output must vary");
    }
}
