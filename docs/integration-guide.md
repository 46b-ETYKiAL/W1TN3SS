# W1TN3SS Host-App Integration Guide

- **Version:** 1.1.0
- **Updated:** 2026-06-30
- **Audience:** maintainers of an Itasha fleet app (SCR1B3 / C0PL4ND / ST3N0 /
  V14 / F0RG3 / TR4C3) wiring opt-in reporting via the W1TN3SS SDK.

This guide describes how a host application consumes `itasha-report-core` to add
**opt-in, default-OFF, previewable** crash/error/issue reporting — and how to
state the resulting privacy posture honestly in the app's own `PRIVACY.md`. The
SDK implements all of the privacy behavior; the host writes only thin glue at a
few well-defined seams.

The companion canonical pages are [privacy-policy.md](privacy-policy.md) and
[what-we-collect.md](what-we-collect.md). A host app's `PRIVACY.md` should link
to these rather than re-deriving them.

---

## 1. Pin the SDK by exact git tag

The SDK is consumed as an exact-tag git dependency (per the fleet
dependency-pinning rule). Never track a branch.

```toml
[dependencies]
itasha-report-core = { git = "https://github.com/46b-ETYKiAL/Itasha.Corp_S4F3-W1TN3SS", tag = "itasha-report-core-v0.2.0" }
```

Add a `cargo-vet` entry for this first-party git dependency. An SDK change cannot
affect the host until the host bumps the tag, which keeps the host's audited
privacy surface stable.

The `itasha-report-core` crate is `#![forbid(unsafe_code)]`. **Do not** vendor
native crash capture (which needs `unsafe`) into an app crate — consume the
isolated sibling crate `itasha-crash-capture` for the Tier-2 minidump path, so
every app binary stays unsafe-free.

---

## 2. The reporting model the host wires

Two **independent, default-OFF** streams, never bundled under one toggle:

| Stream | Default | Consent | Host seam |
|---|---|---|---|
| Crash / error reports (Tier-1 text; Tier-2 minidump) | `Off` | per-event, previewable; or `Always` after the user chooses it | capture → spool → consent dialog → send |
| Manual issue / feedback (user-typed) | n/a (always user-initiated) | per-submission, explicit | in-app "Report an issue" → prefilled GitHub Issue Form + clipboard fallback |

Usage telemetry is **out of scope** — do not add a usage-telemetry stream; the
fleet stays telemetry-free by default.

---

## 3. Wire consent → preview → send

The send path is consent-gated **at the type level**: `IngestBackend::send`
requires a `&ConsentToken`, and a `ConsentToken` is constructible only via
`ConsentToken::granted()`, which the host calls **only after the user agrees** in
the consent dialog (or because the stream's mode is `Always`). A consent-free
send does not compile.

The host glue is four seams:

1. **Capture** — in the panic hook (or error path), build a Tier-1 `Report` from
   the `&'static str` message + the host's own `file:line` site, run it through
   `Sanitizer::sanitize`, and write it to the local `Spool`. **Transmit nothing
   here** — capture is local-first and offline-safe. Deliberately suppress any
   `String` payload that could embed buffer text.
2. **Preview** — when a report is available and the stream is on, show the consent
   dialog. Render the literal, editable Tier-1 text from `Preview::of` so the user
   can review and redact it before anything leaves the machine.
3. **Consent** — on the user's explicit "Send", mint a token with
   `ConsentToken::granted()`. Present **equal-weight** Send / Don't-send choices
   (no dark-pattern asymmetry, no pre-selected default) and an optional
   "Always / Never / Ask" memory that defaults to "Ask".
4. **Send** — pass the spooled report and the token to `IngestBackend::send`. The
   call returns `Ok(SendOutcome::Sent)` or `Ok(SendOutcome::Failed(reason))`, or an
   `Err(SendError)` (`PayloadTooLarge` / `Transport`). Map these — together with the
   host's own pre-send states (consent refused before a token is minted, nothing
   spooled) — to a **counts-only, no-PII** entry in the app's action log. Never a
   silent drop, never a fake success. De-spool a report only after `Sent`; a
   `Failed`/`Err` report stays spooled for a later attempt.

```rust
// Sketch — the host glue at the consent dialog's "Send" handler.
let pending = spool.list()?;                     // paths of reports captured + sanitized earlier
let Some(path) = pending.first() else { return Ok(()); };
let report = spool.load(path)?;                  // load the spooled Report
let editable = Preview::of(&report);             // literal Tier-1 text (editable.text()), shown to the user
// … user reviews / redacts `editable`, then clicks Send …
let token = ConsentToken::granted();             // exists ONLY after explicit agreement
match backend.send(&report, &token) {            // &ConsentToken is required at the type level
    Ok(SendOutcome::Sent)        => { spool.remove(path)?; log_sent(); }   // de-spool only on accept
    Ok(SendOutcome::Failed(why)) => log_failed(&why),  // structured reason; report stays spooled
    Err(e)                       => log_send_error(e), // PayloadTooLarge / Transport — never a silent drop
}
```

### Endpoint configuration

There is **no hardcoded endpoint** in the SDK. `TransportConfig::new(endpoint)`
requires the self-hosted ingest URL, injected through the host's own config/env
seam — there is no default and no constructor without it. A build with no endpoint
configured therefore never constructs a backend at all: captured reports stay in
the local `Spool` and the host simply never calls `send`, so a mis-build cannot
phone home. Reports drain only once an endpoint is supplied.

---

## 4. Isolate native capture (Tier-2 minidump)

For the Tier-2 minidump path, depend on `itasha-crash-capture` (the `unsafe`
sibling crate) rather than writing native capture in your app crate. It runs the
crash monitor **out-of-process**, captures minimized memory (stacks + registers,
heap dropped where possible), and **spools locally — never auto-sends**. Gate
Tier-2 behind a **separate, heightened** consent string that states a crash dump
may contain fragments of the user's open documents.

---

## 5. The end-to-end developer-key model

As of `itasha-report-core-v0.2.0`, the SDK seals the sanitized, previewed payload
(Tier-1 text + opaque Tier-2 attachment bytes) to a **developer public key** (age
X25519 multi-recipient) **after** the client scrub and preview, **before**
transmission. The ingest operator stores only ciphertext and cannot read the
payload; only the developer private key — which lives solely in triage tooling,
never in any client crate — can decrypt it. The ciphertext rides inside the same
open Sentry minidump-envelope as an opaque encrypted attachment, so the lean
in-house pipeline and a future self-hosted Sentry ingest it unchanged.

The host configures the developer recipient public key (it is public, so it may
ship in the app); it must **never** embed a private key.

---

## 6. Manual issue intake

Use the SDK's intake helpers to deep-link the in-app "Report an issue" dialog into
the fleet's shared GitHub Issue-Form templates
([`.github/ISSUE_TEMPLATE/`](../.github/ISSUE_TEMPLATE)): build a prefilled
`…/issues/new?template=bug.yml&title=…&body=…&labels=…` URL, open it in the user's
browser, and fall back to copying the body to the clipboard when the URL would
exceed the safe length ceiling. A `mailto:` alias is the no-backend fallback. This
stream is always user-initiated and per-submission — there is no background path.

---

## 7. State the privacy posture in the host app's PRIVACY.md

Once reporting is wired, reframe the host app's `PRIVACY.md` from "telemetry-free
by construction" to the honest **"telemetry-free by default, opt-in only,
previewable"** posture, and **link to the canonical pages** here rather than
duplicating them:

- describe reporting as **opt-in, default-OFF, per stream** (never on by default,
  never opt-out);
- state **no persistent identifier**, **no retained client IP**, **sanitized**
  payloads, **previewable + redactable** Tier-1, **heightened consent** Tier-2,
  **end-to-end encrypted** to a developer key, **self-hosted** ingest;
- label the data **pseudonymous, never "anonymous"**;
- link [privacy-policy.md](privacy-policy.md) and
  [what-we-collect.md](what-we-collect.md);
- keep the copy free of surveillant framing — the only permitted use of the
  word "telemetry" is the exact phrase "telemetry-free by default" and literal
  negations such as "no usage telemetry"; the framing is consent, not
  surveillance (per the W1TN3SS brand condition that bars surveillance copy and
  iconography).

Each claim a host app makes must be accurate to what that app actually ships. A
fleet app that has not yet wired reporting must **not** pre-emptively reframe its
`PRIVACY.md` — it reframes only when it integrates the SDK.

---

## 8. Opt-in anonymous transport over Tor (`itasha-report-transport-tor`)

The lean `ureq` backend above POSTs directly to the self-hosted endpoint, so the
ingest server sees the client IP. For the **opt-in anonymous** posture, depend on
the separate `itasha-report-transport-tor` crate: `TorOnionTransport` is an
`IngestBackend` that POSTs the same Sentry envelope over an embedded Arti
(pure-Rust Tor) v3 onion, so the server never learns the client IP. It lives in
its own crate so the Arti dependency tree never touches the base crate.
**MSRV note:** this crate requires rustc **1.89** (Arti), higher than the base
crate's floor.

```rust
use itasha_report_transport_tor::{TorOnionTransport, TorTransportConfig};

let config = TorTransportConfig::new(onion_host, 80, state_dir, cache_dir);
let transport = TorOnionTransport::new(config, config_dir)?;   // wires the live ArtiConnector
// … capture + consent exactly as in §3; then drain in the background:
let report = transport.drain_spool().await?;                   // DrainReport: sent / retained counts
```

- **Privacy defaults** (all override-able via `TorTransportConfig::with_*`):
  send-time jitter in `[0, 60s]` (decouples crash-time from send-time),
  fixed-bucket body padding (hides true report size), a 120s per-attempt timeout,
  and an 8 MiB max payload. The onion address is **config-injected** — there is no
  default endpoint.
- **Background drain.** `drain_spool()` drains the local spool with capped,
  backed-off retry (`RetryPolicy` default: 5 attempts, 2s base, 300s cap). A
  transient failure (connect error / 5xx) is retried; a 4xx is retained without
  retry. `with_max_pass_duration(Some(d))` bounds a single pass's wall-clock
  against an unreachable onion — the in-flight report always completes; the budget
  only gates whether the **next** one starts (default `None` = unbounded).
- **DI seam.** The live-Tor dial sits behind the `OnionConnector` trait:
  `new()` wires the production `ArtiConnector`; `with_connector()` injects a test
  connector so the drain orchestration is exercised offline. See
  [ADR-0002](adr-0002-coverage-floor-and-exclusions.md).

---

## 9. References

- [privacy-policy.md](privacy-policy.md) · [what-we-collect.md](what-we-collect.md)
- [ADR-0001](adr-0001-report-core-ingest-boundary.md) — `IngestBackend` boundary,
  Sentry-envelope wire, consent-gated send contract.
- [WIRING.md](WIRING.md) — the declarative wiring contract and the test that
  proves the seam fires.
