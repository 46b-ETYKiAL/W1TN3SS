//! `itasha-report-transport-tor` — the truly-anonymous Tor v3 onion transport
//! for the W1TN3SS reporting SDK.
//!
//! This crate gives **sender-anonymity by construction**: the ingest server
//! never learns the client's IP, because the report travels over an embedded,
//! in-process [Arti](https://crates.io/crates/arti-client) (pure-Rust Tor)
//! client to a v3 `.onion` endpoint. The server's inbound connection arrives
//! from a Tor rendezvous point — there is structurally no client IP to drop.
//! This is the architecture the W1TN3SS transport-anonymity research
//! (`B-transport-metadata-anonymity.md`, gap D-3) recommends.
//!
//! # Why a separate crate (not a feature on `itasha-report-core`)
//!
//! Arti pulls a large `tor-*` dependency tree (~280 crates) and a substantial
//! `cargo-vet` burden. Gating it behind a default-OFF feature on
//! `itasha-report-core` would still drag that tree into the base crate's
//! `--all-features` CI compile, its `Cargo.lock`, and its vet surface. A
//! **separate crate** keeps `itasha-report-core`'s dependency tree and vet
//! burden *completely unchanged* for any app that does not opt into Tor — the
//! base crate's `Cargo.toml` is untouched. Apps that want anonymous transport
//! add this one crate; everyone else pays nothing.
//!
//! # What it provides
//!
//! [`TorOnionTransport`] implements `itasha-report-core`'s
//! [`itasha_report_core::backend::IngestBackend`] trait, so a host swaps to
//! anonymous transport by swapping the backend object — zero `report-core`
//! change. It connects to a **config-injected** `.onion` address (no hardcoded
//! endpoint), POSTs the existing Sentry envelope, and applies three metadata
//! hygiene defenses (research item 9):
//!
//! * **Fixed minimal HTTP headers** — a hand-rolled HTTP/1.1 request with no
//!   `User-Agent` (no OS/arch/locale leak), no `Accept-*`, no `X-Forwarded`.
//! * **Fixed-size body padding** — the envelope is padded up to the next size
//!   bucket so an on-path size observer cannot correlate report size to a
//!   specific crash.
//! * **Randomized send-time jitter** — a random delay before sending decouples
//!   crash-time from send-time.
//!
//! It is **fire-and-forget**: reports are spooled (reusing
//! [`itasha_report_core::spool::Spool`]) and drained on a background worker, so
//! Tor bootstrap/connect latency never blocks the app. Bootstrap is lazy
//! (`OnDemand`).
//!
//! # Threat-model scope
//!
//! True sender-anonymity holds **once the ingest server runs as a `.onion`
//! service** (a standard `tor` daemon `HiddenService` fronting the Axum app, or
//! Arti's `onion-service-service`). That server-side onion front is the
//! `-S3RV3R` repo's wave; this crate delivers the **client** half.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod arti_connector;
pub mod config;
pub mod connector;
pub mod http;
pub mod hygiene;
pub mod transport;

pub use arti_connector::ArtiConnector;
pub use config::TorTransportConfig;
pub use connector::{BoxedOnionStream, OnionConnector, OnionStream};
pub use transport::TorOnionTransport;

/// The crate / transport name (diagnostics only — never sent on the wire; the
/// hand-rolled request deliberately carries no `User-Agent`).
pub const TRANSPORT_NAME: &str = "itasha-report-transport-tor";

/// The crate version (diagnostics only — never sent on the wire).
pub const TRANSPORT_VERSION: &str = env!("CARGO_PKG_VERSION");
