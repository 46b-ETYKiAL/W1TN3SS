# W1TN3SS Privacy Policy

- **Version:** 1.0.0
- **Effective date:** 2026-06-18
- **Applies to:** the W1TN3SS opt-in crash / error / issue reporting SDK
  (`itasha-report-core`, `itasha-crash-capture`) and the self-hosted ingest
  service it transmits to, as consumed by the Itasha app fleet.

> **Plain-language summary.** W1TN3SS reporting is **off by default**. Nothing
> ever leaves your machine unless you explicitly turn a stream on and consent to
> a specific report. When you do consent, the report is sanitized, shown to you
> first, end-to-end encrypted to a developer key, and sent to a self-hosted
> service that keeps no IP address and assigns you no identifier. We label the
> data you may send us **pseudonymous, never "anonymous"** — because a stack
> trace or a memory snapshot can carry indirect identifiers, the honest legal
> classification keeps the data in scope of the protections below.

This policy is grounded in **GDPR Article 25 (data protection by design and by
default)** and the **ePrivacy Directive** (terminal-equipment / stored-identifier
consent). It exceeds **CCPA** (no sale of personal information, no cross-context
behavioral profiling).

---

## 1. Privacy by design and by default (GDPR Art. 25)

W1TN3SS is built so that the privacy-protective state is the **resting state**:

- **Default-OFF, per stream.** Crash reports and manual issue reports are two
  separate consented streams, each defaulting to off. Usage telemetry is out of
  scope for v1 — the fleet stays telemetry-free by default. The two streams are
  never bundled under one switch.
- **Data minimization.** A report carries only what is needed to diagnose a
  fault. Backtraces are sanitized with an allowlist redaction (home directory
  normalized to `<HOME>`, username and hostname dropped, environment values
  scrubbed, every field size-capped). A native crash dump, when you separately
  consent to one, is captured with **minimized memory** (stacks and registers,
  heap dropped where possible) and is further scrubbed server-side.
- **No persistent identifier.** No install-id, no machine fingerprint, no
  per-session id. The only per-report value is an **ephemeral nonce** generated
  fresh for that one report and never stored — so two reports from the same
  machine cannot be linked to each other.
- **No server-side IP retention.** The ingest service terminates the connection,
  extracts the report, and **discards the source IP** at the edge. We do not log
  it, retain it, or build IP-based features.
- **Consent-gated transmission.** Transmission is unrepresentable without a
  consent token the host application mints only after you agree (enforced at the
  type level in `itasha-report-core` — a consent-free send does not compile).

These are not marketing claims; each is implemented in the public client crate,
which the community can audit. See [what-we-collect.md](what-we-collect.md) for
the concrete collected / never-collected lists and the data-flow.

---

## 2. The data is pseudonymous, not anonymous

Under GDPR, **personal data** is anything that can identify a person directly or
indirectly, and indirect elements can combine to identify someone even when no
single field looks sensitive.

A crash or error report can carry such indirect (quasi-) identifiers — a stack
trace, a memory snapshot, an IP address present at the TCP layer of the upload.
W1TN3SS minimizes all of these (sanitizes the text, drops the IP at the edge,
assigns no stable id), but we do **not** claim the result is *anonymous*:

- **Anonymous** data has its links to a person removed in a way that is
  practically irreversible, and falls outside GDPR. Proving genuine anonymity
  requires rigorous, ongoing re-identification testing that a crash payload —
  with worst-case memory fragments — cannot pass.
- **Pseudonymous** data has direct identifiers replaced or stripped but
  re-identification remains conceivable by combining quasi-identifiers.
  Pseudonymous data **is still personal data and stays in scope of GDPR.**

We therefore classify W1TN3SS report data as **pseudonymous** and treat it as
personal data throughout this policy. Calling it "anonymous" would be
dishonest — a stack frame or a minidump fragment is exactly the kind of
quasi-identifier that keeps the data in scope. This honest labeling is the
load-bearing legal line of the whole program.

---

## 3. What we collect (only on your opt-in)

A full, concrete breakdown lives in [what-we-collect.md](what-we-collect.md).
In summary, only after you opt a stream in **and** consent to a specific report:

| Tier | What | Consent | Minimization |
|---|---|---|---|
| **Tier 1 — sanitized text report** | A previewable, editable text backtrace of the fault (panic message + `file:line` site), with home paths, username, hostname, and environment values stripped. | Per-event, previewable + redactable before send. | Allowlist redaction; no raw note content; no keys; no paths beyond `<HOME>`. |
| **Tier 2 — native minidump** | A native crash dump, which **may contain fragments of your open documents** in stack/register memory. | **Separate, heightened** consent ("a crash dump may contain fragments of your open documents"). | Minimized-memory capture (heap dropped where possible) + server-side scrubbing. |

Both tiers are **sanitized first, then end-to-end encrypted** to a developer
public key (age X25519 multi-recipient) **before** they leave your machine. The
ingest operator stores only ciphertext and cannot read the payload; only the
developer private key — which lives solely in triage tooling, never in the
client — can decrypt it.

---

## 4. What we never collect

We never collect, and the client never transmits:

- ❌ a persistent install-id, machine fingerprint, or per-session id;
- ❌ a retained client IP address (dropped at the ingest edge);
- ❌ raw document, note, or buffer content (the panic path deliberately suppresses
  any `String` payload that could embed buffer text, capturing only the
  `&'static str` message);
- ❌ usage telemetry, feature-usage counters, command-frequency, or "pings";
- ❌ your name, email, or account (W1TN3SS has no account system).

---

## 5. How your data is handled

- **Local-first spool.** Reports are written to a local spool first. Transmission
  happens only on consent — a build with no endpoint configured can spool but can
  never phone home, and a consented report with no endpoint stays spooled and
  returns a structured `no-endpoint` outcome (never a silent drop, never a fake
  success).
- **Self-hosted ingestion.** Reports are sent to a **self-hosted** ingest service
  (no third-party SaaS, no vendor data processor). The client speaks the open
  Sentry minidump-envelope wire behind an `IngestBackend` boundary, so the
  in-house pipeline today and a self-hosted Sentry later ingest identical bytes.
- **End-to-end encryption.** The sanitized, previewed payload is sealed to a
  developer key before transmission; the operator stores ciphertext only.
- **Bounded retention + crypto-shred.** Stored reports carry a hard retention TTL
  and are erased on expiry; per-record envelope encryption lets a single record
  be surgically crypto-shredded (relevant to your GDPR Art. 17 erasure right).
- **k-anonymity.** A crash signature is not grouped or relayed until it is seen
  across enough distinct installs (k ≥ 3–5), via an ephemeral salted per-window
  counter — not a persistent identifier — so a singleton fingerprint cannot
  single you out.
- **Tor / proxy friendly.** The reporter works over anonymizing networks and
  never uses the source IP for identity or rate-limiting.

---

## 6. Your consent and your rights

- **Freely given, specific, informed, unambiguous.** Consent is a clear
  affirmative action. There are no pre-ticked boxes, no silent defaults, and no
  dark-pattern asymmetry between Send and Don't-send. You may decline every time,
  and the app works exactly the same.
- **Preview and redact.** For Tier-1 text reports, you see the literal payload and
  can edit or delete fields before anything is sent.
- **Withdraw.** You can set a stream back to off at any time in the host app's
  privacy settings; off means no capture transmits.
- **ePrivacy.** Because we store no persistent identifier on your device, the
  ePrivacy terminal-storage consent rule is satisfied by the opt-in,
  no-stored-id posture.

---

## 7. Self-hosted, no third-party processor

W1TN3SS does not send your data to any third-party crash-reporting SaaS. The
ingest service is operated by us on infrastructure we control. The client wire is
an open envelope format behind a swappable backend boundary; it names no vendor
endpoint.

---

## 8. Changes to this policy

This policy is **versioned and dated** (see the header). Any change to what is
collected, how it is consented, retention, or the no-IP / no-id / pseudonymous
posture is published as a new version with an updated effective date, so revisions
are auditable.

---

## 9. References

- Companion pages: [what-we-collect.md](what-we-collect.md) ·
  [integration-guide.md](integration-guide.md)
- Client crate (auditable): [`crates/itasha-report-core`](../crates/itasha-report-core) ·
  [`crates/itasha-crash-capture`](../crates/itasha-crash-capture)
- Design of record: `IngestBackend` boundary + consent-gated send
  ([ADR-0001](adr-0001-report-core-ingest-boundary.md)).
