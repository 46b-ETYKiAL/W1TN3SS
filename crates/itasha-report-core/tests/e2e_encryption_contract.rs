//! Integration contract for the client E2E-encryption keystone (hardening
//! control #1, plan task T1.1/T1.2).
//!
//! These tests exercise the FULL client flow end to end through the public API
//! only: a developer publishes a recipient string, the client scrubs → previews
//! → seals to that recipient → wraps the sealed payload in the Sentry envelope,
//! the operator sees only ciphertext on the wire, and the developer (holding
//! the matching private key) recovers the exact scrubbed report.
//!
//! The test keypair is generated fresh in-process via `age` (a dev-dependency).
//! No secret key is ever committed to the repo.

use itasha_report_core::e2e::{
    open_report, seal_report, DeveloperIdentity, DeveloperRecipient, SealedPayload,
};
use itasha_report_core::envelope::Envelope;
use itasha_report_core::preview::Preview;
use itasha_report_core::report::{Attachment, Report, Stream};
use itasha_report_core::sanitize::{HostIdentity, Sanitizer};

use age::secrecy::ExposeSecret;

/// Generate a fresh developer keypair and expose it the way production does:
/// a PUBLIC recipient string (embedded in the client) + a SECRET string (lives
/// only in the triage tooling). We parse both back through the crate's PUBLIC
/// API so the test only ever touches the supported surface.
fn developer_keypair() -> (DeveloperRecipient, DeveloperIdentity) {
    let id = age::x25519::Identity::generate();
    let secret_string = id.to_string(); // age::secrecy::SecretString
    let public_string = id.to_public().to_string();

    let recipient = DeveloperRecipient::from_public_key(&public_string).unwrap();
    let identity = DeveloperIdentity::from_secret_key(secret_string.expose_secret()).unwrap();
    (recipient, identity)
}

#[test]
fn full_client_flow_scrub_preview_seal_envelope_then_developer_decrypts() {
    let (recipient, identity) = developer_keypair();

    // 1. Raw crash report carrying the user's real home path + a minidump.
    let raw = Report {
        stream: Stream::CrashReports,
        title: "crash report".into(),
        body: "thread 'main' panicked at /home/ada/secret/notes.rs:42".into(),
        metadata: vec![("cwd".into(), "/home/ada/project".into())],
        attachments: vec![Attachment {
            name: "minidump".into(),
            content_type: "application/x-minidump".into(),
            bytes: b"MDMP\x00stack-fragment-of-open-doc\x00".to_vec(),
        }],
    };

    // 2. CLIENT SCRUB (deterministic identity for the test).
    let sanitizer = Sanitizer::with_identity(HostIdentity {
        home_dir: Some("/home/ada".into()),
        username: Some("ada".into()),
        hostname: Some("ada-laptop".into()),
        ..Default::default()
    });
    let scrubbed = sanitizer.sanitize(raw);
    assert!(scrubbed.body.contains("<HOME>"));
    assert!(!scrubbed.body.contains("/home/ada"));

    // 3. PREVIEW boundary — the user reads the literal Tier-1 text before send.
    let preview = Preview::of(&scrubbed);
    assert!(preview.text().contains("<HOME>"));
    let approved = preview.into_edited_report(&scrubbed);

    // 4. SEAL — the LAST client step, after scrub + preview.
    let sealed = seal_report(&approved, &[recipient]).unwrap();

    // 5. Wrap in the Sentry envelope as an opaque attachment + go to the wire.
    let envelope = Envelope::sealed(&sealed, Some("e".repeat(32)));
    let wire = envelope.to_bytes();

    // 6. OPERATOR view: the stored wire bytes are ciphertext only — neither the
    //    scrubbed text nor the minidump fragment is readable.
    assert!(
        !contains(&wire, b"<HOME>"),
        "scrubbed text leaked to operator"
    );
    assert!(
        !contains(&wire, b"panicked"),
        "crash text leaked to operator"
    );
    assert!(
        !contains(&wire, b"stack-fragment-of-open-doc"),
        "minidump bytes leaked to operator"
    );

    // 7. DEVELOPER triage: parse the envelope off the wire, pull the sealed
    //    payload, decrypt with the private key, recover the exact report.
    let back = Envelope::from_bytes(&wire).unwrap();
    let recovered = back.sealed_payload().expect("sealed payload present");
    let opened = open_report(&recovered, &identity).unwrap();
    assert_eq!(
        opened, approved,
        "developer recovers the exact sealed report"
    );
    // The developer (who already debugs the app) can read the residual stack
    // fragment — the operator never could.
    assert_eq!(
        opened.attachments[0].bytes,
        b"MDMP\x00stack-fragment-of-open-doc\x00".to_vec()
    );
}

#[test]
fn the_operator_cannot_decrypt_without_the_developer_key() {
    let (recipient, _developer) = developer_keypair();
    // The operator generates their OWN, different key and tries to open the
    // sealed payload — it must fail.
    let (_other_recipient, operator) = developer_keypair();
    let report = Report::crash("panic");
    let sealed = seal_report(&report, &[recipient]).unwrap();
    assert!(open_report(&sealed, &operator).is_err());
}

#[test]
fn sealed_attachment_uses_the_documented_content_type() {
    let (recipient, _id) = developer_keypair();
    let report = Report::manual_issue("t", "b");
    let sealed = seal_report(&report, &[recipient]).unwrap();
    let env = Envelope::sealed(&sealed, None);
    let item = &env.items[0];
    assert_eq!(item.item_type, "attachment");
    assert_eq!(
        item.attachment_type.as_deref(),
        Some(SealedPayload::CONTENT_TYPE)
    );
    assert_eq!(SealedPayload::CONTENT_TYPE, "application/age-encrypted");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
