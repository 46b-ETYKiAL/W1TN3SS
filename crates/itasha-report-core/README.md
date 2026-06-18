# itasha-report-core

The safe, `#![forbid(unsafe_code)]` spine of the W1TN3SS reporting SDK. It turns
the five W1TN3SS privacy invariants into code and **transmits nothing on its
own** — the host application calls its APIs only after the user consents.

## The five privacy invariants

1. **Opt-in, default-OFF** — `ReportingConfig` defaults both the crash-report
   and manual-issue streams to `ReportingMode::Off`. The two streams are never
   bundled under one toggle.
2. **Sanitized** — `Sanitizer` normalizes the home directory to `<HOME>`, drops
   the username and hostname, scrubs environment values, and caps sizes.
   Backtrace redaction is **allowlist-not-denylist**.
3. **No persistent identifier** — the transport attaches no install-id /
   fingerprint / session-id. Each report carries an **ephemeral per-report
   nonce** only.
4. **No client network identity** — a static User-Agent, zero redirects, no
   `X-Forwarded` / geo headers.
5. **Consent-gated** — every `IngestBackend::send` requires a `ConsentToken`
   the host mints only after the user agrees; `Preview` returns the literal
   editable payload first.

## Module map

| Module | Responsibility |
|---|---|
| `config` | Two-stream `ReportingMode` model (serde, default `Off`). |
| `report` | The in-memory `Report` model (Tier-1 text + opaque Tier-2 attachments). |
| `sanitize` | The privacy core — home/username/host/env scrubbing + size caps. |
| `spool` | Local-first atomic file-per-report spool with count + byte budgets. |
| `e2e` | **E2E-encrypt** the scrubbed payload to a developer public key (`age` X25519, multi-recipient) — the operator stores ciphertext only. |
| `envelope` | Sentry envelope wire serialization (round-trip); `Envelope::sealed` rides the E2E ciphertext as an opaque attachment. |
| `backend` | `IngestBackend` trait + hardened `ureq` lean-pipeline impl + Sentry stub. |
| `consent` | The `ConsentToken` capability gate (non-forgeable, ephemeral nonce). |
| `preview` | The literal editable Tier-1 payload + user redaction. |
| `intake` | GitHub Issue-Form URL builder, `mailto:`, clipboard fallback, browser launch. |

## Integration snippet — how a host wires consent → preview → send

```rust
use itasha_report_core::{
    backend::{IngestBackend, LeanPipelineBackend, TransportConfig},
    consent::ConsentToken,
    preview::Preview,
    report::Report,
    sanitize::Sanitizer,
    spool::Spool,
};

// 1. Build + sanitize a report (strips home/username/host/env).
let raw = Report::crash("thread 'main' panicked at /home/ada/notes.rs:12");
let report = Sanitizer::new().sanitize(raw);

// 2. Spool it locally first (durable, offline-first; transmits nothing).
let spool = Spool::open("/path/to/app/config/dir")?;
spool.enqueue(&report)?;

// 3. Show the user the literal, editable Tier-1 text. They may redact spans.
let preview = Preview::of(&report).redact_default("any-span-the-user-picks");
println!("{}", preview.text());
let approved = preview.into_edited_report(&report);

// 4. The host gets explicit user consent, THEN mints a token and sends.
let user_agreed = true; // ← from the consent dialog
if user_agreed {
    let token = ConsentToken::granted();
    let backend = LeanPipelineBackend::new(
        TransportConfig::new("https://ingest.example.invalid/api/1/envelope/"),
    );
    let outcome = backend.send(&approved, &token)?;
    // Log the structured outcome (counts/enums only, no PII).
    eprintln!("report outcome: {outcome:?}");
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`send` cannot even be *called* without a `&ConsentToken` — a consent-free send
is a type error, which is the static proof of the consent gate.

## End-to-end encryption to a developer key (the privacy keystone)

The `e2e` module **seals** the scrubbed, previewed report payload — the Tier-1
text *and* every opaque Tier-2 attachment's bytes — to a **developer public
key** with the audited [`age`](https://crates.io/crates/age) library (X25519,
multi-recipient). This is the last client step, **after** the scrub + preview
boundary, so it can only ever encrypt post-scrub data. The ingest operator/host
then stores **only ciphertext** and cannot read the minidump or the note text
even with full database access — only the holder of the developer **private**
key can decrypt.

```rust
use itasha_report_core::{
    e2e::{seal_report, DeveloperRecipient},
    envelope::Envelope,
    preview::Preview,
    report::Report,
    sanitize::Sanitizer,
};

// 1. SCRUB (strip home/username/host/env) — as before.
let raw = Report::crash("thread 'main' panicked at /home/ada/notes.rs:12");
let report = Sanitizer::new().sanitize(raw);

// 2. PREVIEW — the user reads + redacts the literal Tier-1 text — as before.
let approved = Preview::of(&report).into_edited_report(&report);

// 3. SEAL to the developer public key the client embeds (a build constant).
//    The PRIVATE key never lives here — only in the developer triage tooling.
let dev = DeveloperRecipient::from_public_key(
    "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
)?;
let sealed = seal_report(&approved, &[dev])?;

// 4. The ciphertext rides INSIDE the same Sentry envelope as an opaque
//    `application/age-encrypted` attachment — the lean pipeline and a future
//    self-hosted Sentry ingest it unchanged, and neither can read it.
let envelope = Envelope::sealed(&sealed, None);
let _wire = envelope.to_bytes(); // store / transmit this — ciphertext only
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Developer-key decrypt workflow (triage tooling)

The developer holds the matching `age` **secret** key
(`AGE-SECRET-KEY-1...`), generated once with `age-keygen` and kept **only** in
the triage tooling — never embedded in a client, never on the ingest box. To
decrypt a stored report:

```rust
use itasha_report_core::{
    e2e::{open_report, DeveloperIdentity},
    envelope::Envelope,
};

// Pull the envelope off the store/wire, lift out the sealed attachment, decrypt.
let envelope = Envelope::from_bytes(&wire_bytes)?;
let sealed = envelope.sealed_payload().expect("an E2E-sealed report");
let identity = DeveloperIdentity::from_secret_key(&developer_secret_key_string)?;
let report = open_report(&sealed, &identity)?; // the plaintext Report
# Ok::<(), Box<dyn std::error::Error>>(())
```

**Key management:** generate the keypair with `age-keygen -o dev.key`; publish
the `age1...` recipient string for the client to embed; inject the
`AGE-SECRET-KEY-1...` secret into the triage tooling out-of-band (env var /
deploy secret), never commit it. Seal to **multiple** recipients
(`seal_report(&report, &[dev_a, dev_b])`) so any one developer key can decrypt
and a lost key does not strand reports.

Reports remain honestly **pseudonymous**, not "anonymous": a developer
key-holder can decrypt, so a residual stack fragment in a native minidump is
readable by the developer who already debugs the app — but never by the
operator/host, who sees only ciphertext.

## external_dependencies

This crate calls **no external service of its own**. The transport has **no
default endpoint** — a host must configure one, so a mis-build cannot phone
home. The wire format is the open Sentry envelope, ingested today by a
self-hosted lean pipeline and (unchanged) by a future self-hosted Sentry. There
is **no vendor LLM / telemetry / SaaS SDK** (AES Clause 5).

| Dependency | Purpose | Service implied |
|---|---|---|
| `serde` / `serde_json` | Config + envelope (de)serialization | none |
| `ureq` (rustls, pure-Rust) | The single hardened HTTP transport | a self-hosted endpoint the **host** configures |
| `age` (X25519, pure-safe-Rust, `default-features = false`) | E2E-encrypt the scrubbed payload to a developer public key | none (local crypto; the developer private key is out-of-band) |
| `webbrowser` | Launch the user's browser for the GitHub Issue-Form | none (hands off to the user's browser) |
| `directories` | Platform-aware home / config-dir detection | none |
| `proptest` (dev-only) | Sanitizer property tests | none |
| `age` (dev-only) | Generate a fresh test keypair in the E2E integration contract | none |

All dependencies are pinned exact in `Cargo.toml`. `age` is pulled with
`default-features = false` (no `ssh` / `rsa` / `cli-common` surface) so this
crate stays `#![forbid(unsafe_code)]`-clean. Supply-chain hardening
(`cargo audit` + `cargo vet` + `cargo auditable`) runs in
`.github/workflows/release-sign.yml`; the one documented `cargo audit` ignore
(`.cargo/audit.toml`, RUSTSEC-2026-0173) is a build-time-only unmaintained
advisory on `age`'s localization proc-macro with no runtime exposure and no
available fix.
