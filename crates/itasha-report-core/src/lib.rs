//! `itasha-report-core` — the safe spine of the W1TN3SS reporting SDK.
//!
//! This crate turns the five W1TN3SS privacy invariants into code. It
//! transmits **nothing on its own** — the host application calls its APIs
//! only after the user has consented. The crate is `#![forbid(unsafe_code)]`
//! by construction; native crash capture (which requires `unsafe`) lives in
//! the isolated sibling crate `itasha-crash-capture`.
//!
//! # The five privacy invariants
//!
//! 1. **Opt-in, default-OFF** — [`config::ReportingConfig`] defaults both the
//!    crash-report and manual-issue streams to [`config::ReportingMode::Off`].
//!    No constructor yields an on-by-default config.
//! 2. **Sanitized** — [`sanitize::Sanitizer`] normalizes the home directory to
//!    `<HOME>`, drops the username and hostname, scrubs environment values, and
//!    caps sizes. Backtrace frame redaction is **allowlist-not-denylist**.
//! 3. **No persistent identifier** — the [`backend::IngestBackend`] transport
//!    attaches no install-id / fingerprint / session-id. Each report carries an
//!    **ephemeral per-report nonce** only.
//! 4. **No client network identity** — the transport sets a static User-Agent,
//!    forbids redirects, and adds no `X-Forwarded` / geo headers.
//! 5. **Consent-gated** — every [`backend::IngestBackend::send`] call requires a
//!    [`consent::ConsentToken`] the host constructs only after the user agrees;
//!    [`preview::Preview`] returns the literal editable payload first.
//!
//! # Host wiring (consent → preview → send)
//!
//! ```no_run
//! use itasha_report_core::{
//!     backend::{IngestBackend, LeanPipelineBackend, TransportConfig},
//!     consent::ConsentToken,
//!     preview::Preview,
//!     report::Report,
//!     sanitize::Sanitizer,
//! };
//!
//! // 1. Build a report and sanitize it (strips home/username/host/env).
//! let raw = Report::crash("thread 'main' panicked at /home/ada/notes.rs:12");
//! let report = Sanitizer::new().sanitize(raw);
//!
//! // 2. Show the user the literal, editable Tier-1 text payload.
//! let preview = Preview::of(&report);
//! println!("{}", preview.text());
//!
//! // 3. The host gets explicit user consent, THEN mints a token.
//! let user_agreed = true; // ← from the consent dialog
//! if user_agreed {
//!     let token = ConsentToken::granted();
//!     let backend = LeanPipelineBackend::new(
//!         TransportConfig::new("https://ingest.example.invalid/api/1/envelope/"),
//!     );
//!     let _outcome = backend.send(&report, &token);
//! }
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
pub mod config;
pub mod consent;
pub mod e2e;
pub mod envelope;
pub mod intake;
pub mod preview;
pub mod quasi;
pub mod redact;
pub mod report;
pub mod sanitize;
pub mod spool;

/// The crate / SDK name, surfaced in the transport User-Agent.
pub const SDK_NAME: &str = "itasha-report-core";

/// The crate version, surfaced in the transport User-Agent.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
