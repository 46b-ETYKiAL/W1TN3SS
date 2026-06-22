//! Client-side end-to-end encryption of the scrubbed report payload to a
//! **developer** public key (W1TN3SS hardening control #1, the privacy
//! keystone).
//!
//! After the host has run the report through [`crate::sanitize::Sanitizer`]
//! (the client scrub) and shown the user [`crate::preview::Preview`] (the
//! preview boundary), it **seals** the report — the Tier-1 text *and* any
//! opaque Tier-2 attachment bytes — to a developer public key with the audited
//! [`age`] library (X25519, multi-recipient). The ingest operator/host then
//! stores **only ciphertext**: it cannot read the minidump or the note text
//! even with full database access. Only the holder of the developer **private**
//! key — which lives ONLY in the developer's triage tooling, NEVER in this
//! crate or on the ingest box — can decrypt.
//!
//! ## Ordering invariant (scrub → preview → encrypt)
//!
//! Sealing is the **last** client step before the payload leaves the device.
//! [`seal_report`] takes a [`Report`] that is already sanitized + user-approved
//! and produces a [`SealedPayload`]; it performs **no** sanitization itself, so
//! it can only ever encrypt post-scrub data. The
//! [`scrub_happens_before_encrypt`](#tests) test pins this: a pre-scrub home
//! path in the plaintext would survive into the ciphertext, so the test seals a
//! sanitized report and asserts the decrypted plaintext is the scrubbed form.
//!
//! ## Wire shape
//!
//! The sealed bytes are the raw `age` binary format (no armor) over a canonical
//! JSON encoding of the report ([`SealablePayload`]). The ciphertext rides
//! inside the Sentry envelope as an **opaque attachment** item
//! (`attachment_type = "application/age-encrypted"`) via
//! [`Envelope::sealed`](crate::envelope::Envelope::sealed), so the lean
//! pipeline and a future self-hosted Sentry ingest the same envelope unchanged
//! — neither can read the attachment, which is exactly the point.
//!
//! ## Why `age`
//!
//! `age` is an audited, pure-safe-Rust, modern file-encryption library
//! (X25519 + ChaCha20-Poly1305 under the hood). We pull it with
//! `default-features = false` so no `ssh` / `rsa` / `cli-common` surface is
//! compiled — keeping the dependency minimal and this crate
//! `#![forbid(unsafe_code)]`-clean. We do NOT roll our own crypto
//! (`decision_contract.duplicate_module_found`).

use std::io::{Read, Write};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::report::Report;

/// A developer **public** key recipient the client seals reports to.
///
/// Parsed from the standard `age` recipient string (`age1...`). The client
/// embeds one or more of these (a build/config constant); the matching
/// **private** key (`AGE-SECRET-KEY-1...`) lives ONLY in the developer triage
/// tooling and is never present in this crate or on the ingest server.
#[derive(Clone)]
pub struct DeveloperRecipient {
    inner: age::x25519::Recipient,
}

impl std::fmt::Debug for DeveloperRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key material; a recipient is public but we keep
        // Debug noise-free and identity-free.
        f.write_str("DeveloperRecipient(<age x25519 public key>)")
    }
}

impl DeveloperRecipient {
    /// Parse a developer recipient from an `age` public-key string (`age1...`).
    ///
    /// # Errors
    /// Returns [`E2eError::InvalidRecipient`] when the string is not a valid
    /// `age` X25519 recipient.
    pub fn from_public_key(public_key: &str) -> Result<Self, E2eError> {
        let inner = age::x25519::Recipient::from_str(public_key.trim())
            .map_err(|e| E2eError::InvalidRecipient(e.to_string()))?;
        Ok(Self { inner })
    }
}

/// A developer **private** identity that can decrypt sealed payloads.
///
/// This type exists so the developer triage tooling (and this crate's
/// round-trip tests) can decrypt. **It is never constructed from an embedded
/// constant in a shipping client** — the private key is supplied out-of-band to
/// the triage tooling only. The ingest server never holds one.
#[derive(Clone)]
pub struct DeveloperIdentity {
    inner: age::x25519::Identity,
}

impl std::fmt::Debug for DeveloperIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print private key material.
        f.write_str("DeveloperIdentity(<age x25519 secret key, redacted>)")
    }
}

impl DeveloperIdentity {
    /// Parse a developer identity from an `age` secret-key string
    /// (`AGE-SECRET-KEY-1...`).
    ///
    /// # Errors
    /// Returns [`E2eError::InvalidIdentity`] when the string is not a valid
    /// `age` X25519 identity.
    pub fn from_secret_key(secret_key: &str) -> Result<Self, E2eError> {
        let inner = age::x25519::Identity::from_str(secret_key.trim())
            .map_err(|e| E2eError::InvalidIdentity(e.to_string()))?;
        Ok(Self { inner })
    }

    /// The public recipient corresponding to this identity (for tests / for a
    /// developer to publish the recipient string the client embeds).
    #[must_use]
    pub fn to_recipient(&self) -> DeveloperRecipient {
        DeveloperRecipient {
            inner: self.inner.to_public(),
        }
    }
}

/// Errors from the E2E seal / open path.
#[derive(Debug)]
pub enum E2eError {
    /// The supplied developer public key was not a valid `age` recipient.
    InvalidRecipient(String),
    /// The supplied developer secret key was not a valid `age` identity.
    InvalidIdentity(String),
    /// No recipients were supplied to [`seal_report`].
    NoRecipients,
    /// Encryption failed (an internal `age` error).
    Encrypt(String),
    /// Decryption failed (wrong key, corrupt ciphertext, or tampering).
    Decrypt(String),
    /// The decrypted bytes did not deserialize to a [`SealablePayload`].
    Payload(String),
}

impl std::fmt::Display for E2eError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            E2eError::InvalidRecipient(m) => write!(f, "invalid developer recipient: {m}"),
            E2eError::InvalidIdentity(m) => write!(f, "invalid developer identity: {m}"),
            E2eError::NoRecipients => write!(f, "no developer recipients supplied"),
            E2eError::Encrypt(m) => write!(f, "e2e encrypt failed: {m}"),
            E2eError::Decrypt(m) => write!(f, "e2e decrypt failed: {m}"),
            E2eError::Payload(m) => write!(f, "e2e payload error: {m}"),
        }
    }
}

impl std::error::Error for E2eError {}

/// The canonical, serializable plaintext that gets sealed.
///
/// This is the *whole* report payload — the Tier-1 text (`title`/`body`/
/// `metadata`) and every opaque Tier-2 attachment's bytes — so that **nothing**
/// the operator could read is left outside the ciphertext. The developer, after
/// decrypting, reconstructs the original [`Report`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealablePayload {
    /// The report, exactly as it was after scrub + preview (its `attachments`
    /// bytes are carried here and therefore encrypted too).
    pub report: Report,
}

impl SealablePayload {
    /// Build a sealable payload from an already-sanitized, user-approved report.
    #[must_use]
    pub fn from_report(report: Report) -> Self {
        Self { report }
    }
}

/// The opaque, encrypted result of sealing a report. The ingest operator stores
/// exactly these bytes and cannot read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPayload {
    /// Raw `age` ciphertext bytes (binary format, no armor).
    pub ciphertext: Vec<u8>,
}

impl SealedPayload {
    /// The content-type the envelope tags the sealed attachment with.
    pub const CONTENT_TYPE: &'static str = "application/age-encrypted";

    /// The attachment filename used inside the Sentry envelope.
    pub const ATTACHMENT_NAME: &'static str = "report.age";

    /// Borrow the raw ciphertext bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consume into the raw ciphertext bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.ciphertext
    }

    /// Wrap pre-existing ciphertext bytes (e.g. read back off the wire).
    #[must_use]
    pub fn from_bytes(ciphertext: Vec<u8>) -> Self {
        Self { ciphertext }
    }
}

/// Seal an already-sanitized, user-previewed report to one or more developer
/// recipients (multi-recipient: any one developer private key can decrypt).
///
/// This performs **no** sanitization — by contract it is the last client step,
/// after scrub + preview — so it can only ever encrypt post-scrub data. The
/// returned [`SealedPayload`] is opaque to the operator/host.
///
/// # Errors
/// * [`E2eError::NoRecipients`] when `recipients` is empty.
/// * [`E2eError::Encrypt`] when serialization or `age` encryption fails.
pub fn seal_report(
    report: &Report,
    recipients: &[DeveloperRecipient],
) -> Result<SealedPayload, E2eError> {
    if recipients.is_empty() {
        return Err(E2eError::NoRecipients);
    }

    let payload = SealablePayload::from_report(report.clone());
    let plaintext = serde_json::to_vec(&payload).map_err(|e| E2eError::Encrypt(e.to_string()))?;

    // age::Encryptor::with_recipients wants an iterator of &dyn Recipient.
    let recipient_refs: Vec<&dyn age::Recipient> = recipients
        .iter()
        .map(|r| &r.inner as &dyn age::Recipient)
        .collect();

    let encryptor = age::Encryptor::with_recipients(recipient_refs.into_iter())
        .map_err(|e| E2eError::Encrypt(e.to_string()))?;

    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| E2eError::Encrypt(e.to_string()))?;
    writer
        .write_all(&plaintext)
        .map_err(|e| E2eError::Encrypt(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| E2eError::Encrypt(e.to_string()))?;

    Ok(SealedPayload { ciphertext })
}

/// Open (decrypt) a sealed payload with a developer identity, recovering the
/// original [`Report`]. Used by the developer triage tooling and the round-trip
/// tests; the shipping client never decrypts.
///
/// # Errors
/// * [`E2eError::Decrypt`] when the identity does not match, or the ciphertext
///   is corrupt / tampered.
/// * [`E2eError::Payload`] when the decrypted bytes are not a valid
///   [`SealablePayload`].
pub fn open_report(
    sealed: &SealedPayload,
    identity: &DeveloperIdentity,
) -> Result<Report, E2eError> {
    let decryptor = age::Decryptor::new(&sealed.ciphertext[..])
        .map_err(|e| E2eError::Decrypt(e.to_string()))?;

    let mut reader = decryptor
        .decrypt(std::iter::once(&identity.inner as &dyn age::Identity))
        .map_err(|e| E2eError::Decrypt(e.to_string()))?;

    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| E2eError::Decrypt(e.to_string()))?;

    let payload: SealablePayload =
        serde_json::from_slice(&plaintext).map_err(|e| E2eError::Payload(e.to_string()))?;
    Ok(payload.report)
}

/// Test-only helpers shared across this crate's test modules (e.g. the
/// envelope contract test in `envelope.rs`). Compiled only under `cfg(test)`,
/// so no key-generation surface ships in the production crate.
#[cfg(test)]
pub(crate) mod testutil {
    use super::DeveloperIdentity;

    /// Generate a fresh in-process developer identity. NOT a real key — it
    /// never lands in the repo; each call yields a new keypair.
    #[must_use]
    pub(crate) fn generated_identity() -> DeveloperIdentity {
        DeveloperIdentity {
            inner: age::x25519::Identity::generate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Attachment, Report, Stream};
    use crate::sanitize::{HostIdentity, Sanitizer};

    /// A deterministic developer identity for the tests. NOT a real key — it is
    /// generated fresh in-process, so the secret never lands in the repo.
    fn test_identity() -> DeveloperIdentity {
        super::testutil::generated_identity()
    }

    #[test]
    fn round_trip_recovers_exact_report() {
        let id = test_identity();
        let recipient = id.to_recipient();

        let report = Report::crash("thread 'main' panicked at <HOME>/main.rs:1")
            .with_metadata("os", "linux");

        let sealed = seal_report(&report, &[recipient]).unwrap();
        let opened = open_report(&sealed, &id).unwrap();
        assert_eq!(opened, report, "decrypted report must match the sealed one");
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let id = test_identity();
        let report = Report::manual_issue("title", "super secret note body PLAINMARKER");
        let sealed = seal_report(&report, &[id.to_recipient()]).unwrap();
        // The operator stores ONLY this — it must not contain the plaintext.
        let haystack = String::from_utf8_lossy(sealed.bytes());
        assert!(
            !haystack.contains("PLAINMARKER"),
            "plaintext must not survive into the ciphertext"
        );
        assert!(!haystack.contains("super secret note"));
    }

    #[test]
    fn attachment_bytes_are_encrypted_too() {
        let id = test_identity();
        // A minidump-shaped attachment with a recognizable marker.
        let dump = b"MDMP\x00MARKER_IN_DUMP\x00\xff".to_vec();
        let report = Report {
            stream: Stream::CrashReports,
            title: "crash".into(),
            body: "panic".into(),
            metadata: vec![],
            attachments: vec![Attachment {
                name: "minidump".into(),
                content_type: "application/x-minidump".into(),
                bytes: dump.clone(),
            }],
        };
        let sealed = seal_report(&report, &[id.to_recipient()]).unwrap();
        let haystack = sealed.bytes();
        // The dump marker must not appear in the ciphertext.
        assert!(
            !contains_subslice(haystack, b"MARKER_IN_DUMP"),
            "attachment bytes must be inside the ciphertext"
        );
        // And it round-trips back byte-for-byte.
        let opened = open_report(&sealed, &id).unwrap();
        assert_eq!(opened.attachments[0].bytes, dump);
    }

    #[test]
    fn scrub_happens_before_encrypt() {
        // This is the ORDERING test: sealing operates on the *sanitized* report,
        // so the home path is already <HOME> in the plaintext that gets sealed.
        let identity = HostIdentity {
            home_dir: Some("/home/ada".to_string()),
            username: Some("ada".to_string()),
            hostname: Some("ada-laptop".to_string()),
            ..Default::default()
        };
        let sanitizer = Sanitizer::with_identity(identity);
        let id = test_identity();

        // Raw report carries the user's home path.
        let raw = Report::crash("thread 'main' panicked at /home/ada/secret/notes.rs:9");
        // Correct client order: SCRUB first.
        let scrubbed = sanitizer.sanitize(raw);
        assert!(
            scrubbed.body.contains("<HOME>"),
            "precondition: scrub normalized the home path"
        );
        assert!(!scrubbed.body.contains("/home/ada"));

        // THEN seal the scrubbed report.
        let sealed = seal_report(&scrubbed, &[id.to_recipient()]).unwrap();
        // Decrypting yields the scrubbed form, proving scrub ran before encrypt.
        let opened = open_report(&sealed, &id).unwrap();
        assert!(opened.body.contains("<HOME>"));
        assert!(
            !opened.body.contains("/home/ada"),
            "the un-scrubbed home path must NOT be inside the ciphertext — \
             scrub must precede encrypt"
        );
    }

    #[test]
    fn wrong_identity_cannot_decrypt() {
        let owner = test_identity();
        let attacker = test_identity();
        let report = Report::crash("panic");
        let sealed = seal_report(&report, &[owner.to_recipient()]).unwrap();
        // A different developer key must NOT decrypt.
        let err = open_report(&sealed, &attacker).unwrap_err();
        assert!(matches!(err, E2eError::Decrypt(_)));
    }

    #[test]
    fn multi_recipient_any_developer_can_open() {
        let dev_a = test_identity();
        let dev_b = test_identity();
        let report = Report::crash("multi-recipient panic");
        // Seal to BOTH developers.
        let sealed = seal_report(&report, &[dev_a.to_recipient(), dev_b.to_recipient()]).unwrap();
        // EITHER private key decrypts.
        assert_eq!(open_report(&sealed, &dev_a).unwrap(), report);
        assert_eq!(open_report(&sealed, &dev_b).unwrap(), report);
    }

    #[test]
    fn empty_recipients_is_rejected() {
        let report = Report::crash("x");
        let err = seal_report(&report, &[]).unwrap_err();
        assert!(matches!(err, E2eError::NoRecipients));
    }

    #[test]
    fn invalid_public_key_is_rejected() {
        let err = DeveloperRecipient::from_public_key("not-an-age-key").unwrap_err();
        assert!(matches!(err, E2eError::InvalidRecipient(_)));
    }

    #[test]
    fn invalid_secret_key_is_rejected() {
        let err = DeveloperIdentity::from_secret_key("AGE-SECRET-KEY-1-bogus").unwrap_err();
        assert!(matches!(err, E2eError::InvalidIdentity(_)));
    }

    #[test]
    fn recipient_round_trips_through_string_form() {
        // A developer publishes a recipient string; the client parses it; it
        // encrypts; the developer's identity decrypts.
        let id = test_identity();
        let recipient_str = id.to_recipient().inner.to_string();
        let parsed = DeveloperRecipient::from_public_key(&recipient_str).unwrap();
        let report = Report::crash("string-form panic");
        let sealed = seal_report(&report, &[parsed]).unwrap();
        assert_eq!(open_report(&sealed, &id).unwrap(), report);
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let id = test_identity();
        let report = Report::crash("integrity");
        let mut sealed = seal_report(&report, &[id.to_recipient()]).unwrap();
        // Flip a byte deep in the ciphertext body (past the header).
        let n = sealed.ciphertext.len();
        let idx = n - 1;
        sealed.ciphertext[idx] ^= 0xFF;
        assert!(open_report(&sealed, &id).is_err());
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
