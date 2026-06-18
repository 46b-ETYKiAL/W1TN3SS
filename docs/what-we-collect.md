# What We Collect — and What We Never Collect

- **Version:** 1.0.0
- **Updated:** 2026-06-18
- **Applies to:** the W1TN3SS opt-in reporting SDK and its self-hosted ingest
  service, as consumed by the Itasha app fleet.

This is the single highest-trust page we ship: a concrete, public list of exactly
what a report can contain and what it can never contain. It is the companion to
the full [privacy-policy.md](privacy-policy.md). Everything below happens **only
after you opt a stream in and consent to a specific report** — the resting state
of every fleet app is that nothing is captured for transmission and nothing is
sent.

W1TN3SS report data is **pseudonymous, not anonymous** (see
[privacy-policy.md §2](privacy-policy.md)). The lists below are written with that
honest classification in mind.

---

## What we collect (only on your opt-in)

### Tier 1 — sanitized text report (default opt-in stream)

A previewable, editable text backtrace of the fault:

- the panic / error message (captured from a `&'static str`, so a buffer-text or
  path-bearing `String` payload is deliberately suppressed at capture);
- our own `file:line` fault site;
- a sanitized backtrace: home directory normalized to `<HOME>`, username and
  hostname dropped, environment **values** scrubbed, every field size-capped, and
  any unrecognized backtrace line replaced with `<redacted>` (allowlist, not
  denylist).

You see the literal payload and can edit or delete fields **before** it is sent.

### Tier 2 — native minidump (separate, heightened opt-in)

A native crash dump (for segfaults / aborts that a Rust panic hook can't catch),
captured out-of-process in the isolated `itasha-crash-capture` crate. It **may
contain fragments of your open documents** in stack/register memory — so it
requires a **separate, explicit, heightened consent** with that exact wording. It
is captured with **minimized memory** (stacks + registers, heap dropped where
possible), spooled locally, **never auto-sent**, and scrubbed server-side after
decryption by the developer.

Both tiers are **sanitized first, then end-to-end encrypted** to a developer key
before transmission. The ingest operator stores only ciphertext.

---

## What we NEVER collect

The client never gathers or transmits any of the following, in any tier:

- ❌ **Persistent install-id** — no stable per-install identifier of any kind.
- ❌ **Machine fingerprint** — no hardware id, MAC, or unique config fingerprint.
- ❌ **Retained client IP** — the upload connection's IP is dropped at the ingest
  edge; it is never logged, retained, or used for identity or rate-limiting.
- ❌ **Raw document / note / buffer content** — your actual notes, messages, and
  files are never read into a Tier-1 report.
- ❌ **Usage telemetry** — no feature-usage counters, no command-frequency, no
  error "pings." Usage telemetry is **out of scope for v1**; the fleet stays
  telemetry-free by default.
- ❌ **Account data** — there is no account, sign-in, name, or email.

The only per-report value that exists at all is an **ephemeral nonce** generated
fresh for one report and never stored — so reports cannot be linked to each other
or back to your machine.

---

## The data flow: capture → scrub → preview → consent → encrypt → self-hosted ingest

```
  ┌─────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────────┐
  │ capture │ → │  scrub   │ → │ preview  │ → │ consent  │ → │   E2E    │ → │  self-hosted     │
  │ (fault) │   │(sanitize)│   │(you edit)│   │(you say  │   │ encrypt  │   │  ingest          │
  │         │   │          │   │          │   │  yes)    │   │(to dev   │   │ (ciphertext only,│
  │         │   │          │   │          │   │          │   │  key)    │   │  no IP, no id)   │
  └─────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────────────┘
       │             │              │              │              │                  │
   local spool   <HOME>/no       literal,      ConsentToken    age X25519        edge-drops IP;
   first; never  username/       editable      (mints only     multi-recipient;  stores ciphertext;
   transmits     hostname/env    Tier-1 text   after you       operator can't    bounded retention
   on its own    stripped                      agree)          read payload      + crypto-shred
```

1. **Capture.** A fault is captured into a Tier-1 text report (or, with separate
   heightened consent, a Tier-2 minidump) and written to a **local spool**. This
   step transmits nothing — it is local-first and offline-safe.
2. **Scrub.** The sanitizer normalizes home paths to `<HOME>` and strips username,
   hostname, and environment values. This is the privacy heart, shared by every
   app and auditable in the public crate.
3. **Preview.** For Tier-1, the literal, editable payload is shown to you so you
   can review and redact it before anything is sent.
4. **Consent.** Transmission requires a consent token the host mints only after
   you explicitly agree (or because you previously chose "Always" for that
   stream). A consent-free send is unrepresentable.
5. **End-to-end encrypt.** The sanitized, previewed payload is sealed to a
   developer public key (age X25519 multi-recipient) **after** the scrub. Only the
   developer private key — kept in triage tooling, never in the client — can
   decrypt it.
6. **Self-hosted ingest.** The ciphertext rides inside the open Sentry
   minidump-envelope to a **self-hosted** service (no third-party SaaS). The
   service drops the source IP at the edge, assigns no identifier, stores only
   ciphertext, holds it under a bounded retention TTL, and suppresses singleton
   crash signatures via k-anonymity (k ≥ 3–5) before any grouping.

---

## Verify it yourself

The client is public and auditable:

- the sanitizer, spool, preview, consent token, envelope, and E2E sealing live in
  [`crates/itasha-report-core`](../crates/itasha-report-core);
- native capture is quarantined in
  [`crates/itasha-crash-capture`](../crates/itasha-crash-capture);
- the consent-gated send contract and the `IngestBackend` boundary are described
  in [ADR-0001](adr-0001-report-core-ingest-boundary.md) and proven by the wiring
  contract in [WIRING.md](WIRING.md).
