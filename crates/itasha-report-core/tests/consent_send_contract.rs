//! The consent + no-stable-identifier contract test.
//!
//! Two privacy invariants are asserted here against a recording backend:
//!
//! 1. **No send without consent.** `IngestBackend::send` requires a
//!    `&ConsentToken` at the type level — there is no overload that omits it.
//!    This test proves the recording backend never observes a transmission
//!    that was not accompanied by a host-minted consent token, and that a
//!    `send` call cannot even be expressed without one (the commented line
//!    below does not compile).
//! 2. **No stable identifier.** The only per-report identifier is the
//!    ephemeral consent nonce; two sends of the *same* report under fresh
//!    consent tokens carry different identifiers, so nothing stable leaks.

use std::cell::RefCell;

use itasha_report_core::backend::{IngestBackend, SendError, SendOutcome};
use itasha_report_core::consent::ConsentToken;
use itasha_report_core::report::Report;

/// A backend that records the nonces it was asked to send under (proving every
/// send carried a consent token) and never transmits.
#[derive(Default)]
struct RecordingBackend {
    seen_nonces: RefCell<Vec<String>>,
}

impl IngestBackend for RecordingBackend {
    fn send(&self, _report: &Report, consent: &ConsentToken) -> Result<SendOutcome, SendError> {
        // The mere fact this method ran means a ConsentToken was supplied — the
        // signature makes a consent-free send unrepresentable.
        self.seen_nonces
            .borrow_mut()
            .push(consent.nonce().to_string());
        Ok(SendOutcome::Sent)
    }
}

#[test]
fn send_requires_consent_token_at_type_level() {
    let backend = RecordingBackend::default();
    let report = Report::crash("panic");

    // This is the ONLY way to call send — a consent token is mandatory:
    let token = ConsentToken::granted();
    let outcome = backend.send(&report, &token).unwrap();
    assert_eq!(outcome, SendOutcome::Sent);

    // The following line is intentionally NOT compilable — uncommenting it is a
    // type error, which is the static proof that send refuses without consent:
    //
    //   let _ = backend.send(&report);   // error[E0061]: missing `consent`
    //
    assert_eq!(backend.seen_nonces.borrow().len(), 1);
}

#[test]
fn every_send_carries_a_fresh_ephemeral_nonce_not_a_stable_id() {
    let backend = RecordingBackend::default();
    let report = Report::crash("panic");

    // Send the SAME report three times under fresh consent tokens.
    for _ in 0..3 {
        let token = ConsentToken::granted();
        backend.send(&report, &token).unwrap();
    }

    let nonces = backend.seen_nonces.borrow();
    assert_eq!(nonces.len(), 3);
    // All three nonces differ — there is no stable per-install identifier.
    let unique: std::collections::HashSet<_> = nonces.iter().collect();
    assert_eq!(unique.len(), 3, "nonces must be ephemeral, not a stable id");
}

/// Anonymity hardening #1 (gap D-2): nonces minted back-to-back over many sends
/// carry NO time component and NO monotonic-counter structure — they are
/// unlinkable. The previous `SystemTime::now()`-nanos + seq form let a passive
/// store-holder reconstruct submission ordering/timing; the CSPRNG form cannot.
#[test]
fn nonces_have_no_time_or_sequence_structure_across_sends() {
    let backend = RecordingBackend::default();
    let report = Report::crash("panic");

    let n = 300;
    for _ in 0..n {
        let token = ConsentToken::granted();
        backend.send(&report, &token).unwrap();
    }
    let nonces = backend.seen_nonces.borrow();

    // (a) All fixed-width lowercase hex, no separators (no "nanos-seq" shape).
    for nonce in nonces.iter() {
        assert_eq!(nonce.len(), 32, "nonce not fixed 32-hex width: {nonce}");
        assert!(
            nonce
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "nonce not pure lowercase hex: {nonce}"
        );
        assert!(
            !nonce.contains('-'),
            "nonce carries a separator (time/seq shape): {nonce}"
        );
    }

    // (b) NOT monotonic. A sequence counter would make every adjacent nonce
    //     (interpreted as a big integer via fixed-width hex) strictly ascending.
    //     A CSPRNG sequence has descents too.
    let mut descents = 0usize;
    for w in nonces.windows(2) {
        if w[0] > w[1] {
            descents += 1;
        }
    }
    assert!(
        descents > n / 8,
        "nonce sequence looks monotonic (descents={descents}/{n}) — a counter is leaking"
    );

    // (c) No shared time-prefix between consecutive nonces. A clock-derived
    //     nonce shares many high-order hex digits between close mints.
    let mut total_prefix = 0usize;
    for w in nonces.windows(2) {
        total_prefix += w[0]
            .chars()
            .zip(w[1].chars())
            .take_while(|(a, b)| a == b)
            .count();
    }
    let mean_prefix = total_prefix as f64 / (nonces.len() - 1) as f64;
    assert!(
        mean_prefix < 1.5,
        "consecutive nonces share a long common prefix (mean {mean_prefix:.3}) — time is leaking"
    );
}
