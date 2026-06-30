<p align="center"><img src=".github/header.svg" alt="W1TN3SS" width="100%"></p>

# W1TN3SS <sub>(証 · witness)</sub>

Privacy-first, **opt-in** crash / error / issue reporting SDK for the Itasha app
fleet. The sealed witness testifies only when you permit it — never a beacon,
never always-on.

## Principles

- **Opt-in, default-OFF, per stream.** Crash reports and manual issues are
  separate consented streams. Nothing is sent without your explicit consent.
- **Data-minimized.** No persistent install-id, no fingerprint; reports carry an
  ephemeral per-report nonce or nothing. Backtraces are path/username/env
  sanitized (allowlist redaction). Reports are honestly **pseudonymous**, never
  marketed as "anonymous."
- **Previewable + redactable.** You see and can edit the literal report payload
  before it is ever sent.
- **Self-hosted, no SaaS.** The client speaks the Sentry minidump-envelope wire
  behind an `IngestBackend` boundary — point it at the in-house pipeline now, a
  self-hosted Sentry later, with no client change.
- **`#![forbid(unsafe_code)]`.** All native crash capture is quarantined in the
  isolated `itasha-crash-capture` sibling crate so consuming apps stay unsafe-free.

## Crates

| Crate | What |
|---|---|
| [`itasha-report-core`](crates/itasha-report-core) | Safe SDK spine: two-stream config, sanitizer, local spool, hardened transport, `IngestBackend` + Sentry-envelope wire, previewable payload, GitHub-issue / clipboard / mailto intake helpers. `send` requires a non-forgeable `ConsentToken`. |
| [`itasha-crash-capture`](crates/itasha-crash-capture) | Unsafe-isolated native minidump capture (Tier-2), out-of-process. Spooled locally, never auto-sent; gated on heightened consent. |
| [`itasha-report-transport-tor`](crates/itasha-report-transport-tor) | **Opt-in** anonymous transport: an `IngestBackend` that POSTs the envelope over an embedded Arti (pure-Rust Tor) v3 onion, so the server never learns the client IP. Fixed-minimal headers, fixed-bucket body padding, send-time jitter; fire-and-forget spool drain with capped backed-off retry. Behind the live-Tor `OnionConnector` seam. Separate crate so the Arti tree never touches the base crate. |
| [`itasha-report-aggregate`](crates/itasha-report-aggregate) | **Opt-in Tier-A**: the only stream that is honestly *anonymous*. Submits a k-anonymous [STAR](https://arxiv.org/abs/2109.10074) message over a low-dimensional crash-signature + coarse quasi-tuple — the operator learns a signature only once ≥ k (default 25) distinct clients report it, with no per-user identifier. Its own consent (`AggregateMode`, default-OFF), separate from Tier-B. Separate crate so the STAR crypto tree never touches the base crate. |

### The honest two-tier model

A detailed scrubbed report (Tier-B: `itasha-report-core` + the Tor transport) is
irreducibly high-dimensional and stays honestly **pseudonymous** — no scrubbing
makes a unique stack "anonymous". Only the *aggregate* k-anonymous signal
(`itasha-report-aggregate`, Tier-A) is **truly anonymous**. Both tiers are
default-OFF and separately consented; opting into one never opts into the other.

## Use

```toml
[dependencies]
itasha-report-core = { git = "https://github.com/46b-ETYKiAL/Itasha.Corp_S4F3-W1TN3SS", tag = "itasha-report-core-v0.1.0" }
```

Apache-2.0. The self-hosted server is private (`Itasha.Corp_S4F3-W1TN3SS-S3RV3R`).

## Shared issue templates

[`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE) holds the fleet's shared
GitHub Issue-Form templates — `bug.yml`, `feature.yml`, and `other.yml`, plus a
`config.yml` chooser. Each form declares a server-side `labels:` key, so the
right label (`bug` / `enhancement` / `question`) is applied on submission
**regardless of the submitter's permissions** — a drive-by reporter does not
need write access for the label to stick.

A fleet app's in-app "Report an issue" dialog deep-links into these forms via
`itasha-report-core`'s intake helpers: it builds a prefilled
`…/issues/new?template=bug.yml&title=…&body=…&labels=…` URL, opens it in the
user's browser, and falls back to copying the body to the clipboard when the URL
would exceed the safe length ceiling (`GITHUB_URL_LENGTH_THRESHOLD`). The forms
are equally usable on their own — every fleet repo can reuse this set unchanged.

<p align="center"><img src=".github/footer.svg" alt="" width="100%"></p>
