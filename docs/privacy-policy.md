# W1TN3SS Privacy Policy

- **Version:** 2.0.0
- **Effective date:** 2026-06-22
- **Applies to:** the W1TN3SS opt-in crash / error / issue reporting SDK
  (`itasha-report-core`, `itasha-crash-capture`, `itasha-report-aggregate`,
  `itasha-report-transport-tor`) and the self-hosted ingest service it transmits
  to, as consumed by the Itasha app fleet.

> **Plain-language summary.** W1TN3SS reporting is **off by default**. Nothing
> ever leaves your machine unless you explicitly turn a stream on and consent.
> W1TN3SS now has **two honestly-labeled tiers**, each with its own separate
> opt-in:
>
> - **Tier A — anonymous aggregate signals.** A truly *anonymous* count of which
>   crash *signatures* are common across the whole fleet. It carries no
>   identifier, is revealed to us only once **at least 25 different devices**
>   independently hit the same signature (k-anonymity, via the STAR protocol),
>   and travels over Tor so we never see your IP. This tier may honestly use the
>   word **anonymous**.
> - **Tier B — detailed reports.** A sanitized, previewable stack/dump for fixing
>   a specific bug, end-to-end encrypted to a developer key. Even maximally
>   hardened, a stack or memory snapshot can carry indirect identifiers, so we
>   honestly label Tier B **pseudonymous** (personal data) — never "anonymous".
>
> The honest split is the load-bearing legal line of the program: **only the
> aggregate tier is anonymous; the detailed tier is pseudonymous and stays in
> scope of the protections below.**

This policy is grounded in **GDPR Article 25 (data protection by design and by
default)** and the **ePrivacy Directive** (terminal-equipment / stored-identifier
consent). It exceeds **CCPA** (no sale of personal information, no cross-context
behavioral profiling).

---

## 1. Privacy by design and by default (GDPR Art. 25)

W1TN3SS is built so that the privacy-protective state is the **resting state**:

- **Default-OFF, per stream.** The anonymous aggregate signal (Tier A), crash
  reports, and manual issue reports are **separate consented streams**, each
  defaulting to off. Usage telemetry is out of scope for v1 — the fleet stays
  telemetry-free by default. The streams are never bundled under one switch:
  opting into the anonymous aggregate tier never opts you into a detailed
  report, and vice-versa.
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

## 2. The two honest tiers: anonymous aggregate vs pseudonymous detail

Under GDPR, **personal data** is anything that can identify a person directly or
indirectly, and indirect elements can combine to identify someone even when no
single field looks sensitive. The standard for truly *anonymous* data
(**GDPR Recital 26**) is strict: the data must not relate to an identifiable
person taking account of **all the means reasonably likely to be used** —
judged against the singling-out, linkability, and inference tests of
Art-29 WP **Opinion 05/2014 (WP216)** and the ICO 2025 *motivated-intruder*
test.

The honest finding — and the reason W1TN3SS is built as two tiers — is that
**aggregate signals can meet that bar, and detailed payloads cannot:**

### Tier A — aggregate signals: truly anonymous

Tier A submits only a **crash *signature*** (a one-way hash of the *symbol names*
of the top stack frames, with every address, source path, line number, and build
hash stripped *before* hashing) plus a **coarse class** (`app_version`→minor,
`os`→major.minor, `locale`→language). This is low-dimensional and bounded, so it
can be made genuinely anonymous via **k-anonymous threshold aggregation
(STAR)**:

- **No singling out.** A signature is revealed to us **only once at least k = 25
  *distinct* devices** independently submit it. A unique (singleton) crash is
  never revealed — it stays cryptographically hidden.
- **No linkability.** There is **no per-user identifier anywhere** in this path.
  Identical signatures self-collide by construction; nothing ties two
  submissions to one device.
- **No inference.** The only quasi-identifiers carried are the three coarse
  dimensions above, revealed only at threshold; no timezone, build hash,
  timestamp, hostname, or module list ever rides along.
- **Sender-anonymity.** Submission travels over **Tor** (a v3 onion service), so
  we never see your IP.

Because Tier A survives singling-out, linkability, and inference under the
"reasonably-likely-means" / motivated-intruder bar, it may honestly carry the
word **anonymous**.

### Tier B — detailed reports: honestly pseudonymous

A detailed report (a sanitized stack trace or a native minidump) is **irreducibly
high-dimensional**: almost every full stack is unique, so it never reaches a
k-anonymity threshold, and a minidump can structurally carry fragments of open
documents, usernames, and paths in stack/register memory. No amount of scrubbing
makes such a payload anonymous:

- **Anonymous** data has its links to a person removed in a way that is
  practically irreversible, and falls outside GDPR. A detailed crash payload —
  with worst-case memory fragments — cannot pass that test.
- **Pseudonymous** data has direct identifiers replaced or stripped but
  re-identification remains conceivable by combining quasi-identifiers.
  Pseudonymous data **is still personal data and stays in scope of GDPR.**

We therefore classify Tier-B report data as **pseudonymous** and treat it as
personal data throughout this policy. Calling a scrubbed stack or minidump
"anonymous" would be dishonest — it is exactly the kind of indirect identifier
that keeps the data in scope (consistent with GDPR Recital 26 and the EDPB
Guidelines 01/2025 on pseudonymisation, which hold that data re-identifiable via
additional information remains personal data). **This honest split — anonymous
aggregate, pseudonymous detail — is the load-bearing legal line of the whole
program.**

---

## 3. What we collect (only on your opt-in)

A full, concrete breakdown lives in [what-we-collect.md](what-we-collect.md).
In summary, only after you opt a stream in **and** consent:

| Tier | What | Honest label | Consent | Minimization |
|---|---|---|---|---|
| **Tier A — anonymous aggregate signal** | A crash *signature* (one-way hash of symbol-only stack frames) + a coarse class (`app_version`→minor, `os`→major.minor, `locale`→language). No identifier; revealed to us only at k ≥ 25 distinct devices; over Tor. | **Anonymous** | Separate, default-OFF aggregate opt-in. | STAR k-anonymity (k = 25); no addresses/paths/lines in the signature; coarse class only; no per-user id; Tor transport (no IP). |
| **Tier B-1 — sanitized text report** | A previewable, editable text backtrace of the fault (panic message + `file:line` site), with home paths, username, hostname, and environment values stripped. | **Pseudonymous** | Per-event, previewable + redactable before send. | Allowlist redaction; no raw note content; no keys; no paths beyond `<HOME>`. |
| **Tier B-2 — native minidump** | A native crash dump, which **may contain fragments of your open documents** in stack/register memory. | **Pseudonymous** | **Separate, heightened** consent ("a crash dump may contain fragments of your open documents"). | Minimized-memory capture (heap dropped where possible) + server-side scrubbing. |

The three tiers are **three separate opt-ins** — opting into one never opts you
into another. Tier A is the truly-anonymous stream. The two Tier-B streams are
**sanitized first, then end-to-end encrypted** to a developer public key
(age X25519 multi-recipient) **before** they leave your machine; the ingest
operator stores only ciphertext and cannot read the payload (only the developer
private key, kept in triage tooling, can decrypt it). Tier A needs no encryption
of its own — its STAR message is already opaque below the k-threshold and carries
no identifier.

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
- **k-anonymity (Tier A — cryptographically enforced).** A Tier-A crash
  signature is revealed to us **only once at least k = 25 distinct devices**
  independently submit it, enforced cryptographically by the **STAR** threshold-
  aggregation protocol (Shamir k-of-n secret sharing) with **no per-user
  identifier** — below the threshold the signature stays cryptographically
  hidden, so a singleton crash can never single you out. For Tier-B detailed
  reports, the server additionally suppresses singleton signatures before any
  grouping as defense-in-depth (it does not make Tier B anonymous — Tier B stays
  pseudonymous).
- **Tor sender-anonymity.** Tier A submits its STAR message over a **Tor v3 onion
  service** (embedded pure-Rust Arti), so the ingest service never sees a client
  IP. Tier-B transmission is likewise Tor-friendly and never uses the source IP
  for identity or rate-limiting.

---

## 6. Your consent and your rights

- **Freely given, specific, informed, unambiguous.** Consent is a clear
  affirmative action. There are no pre-ticked boxes, no silent defaults, and no
  dark-pattern asymmetry between Send and Don't-send. You may decline every time,
  and the app works exactly the same.
- **Preview and redact.** For Tier-B text reports, you see the literal payload and
  can edit or delete fields before anything is sent. (Tier A carries no editable
  text — it is a single opaque, non-reversible aggregate signal.)
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
- Client crates (auditable): [`crates/itasha-report-core`](../crates/itasha-report-core) ·
  [`crates/itasha-crash-capture`](../crates/itasha-crash-capture) ·
  [`crates/itasha-report-aggregate`](../crates/itasha-report-aggregate) (Tier A) ·
  [`crates/itasha-report-transport-tor`](../crates/itasha-report-transport-tor) (Tor)
- Design of record: `IngestBackend` boundary + consent-gated send
  ([ADR-0001](adr-0001-report-core-ingest-boundary.md)).
- Legal / technical grounding for the two-tier split: GDPR **Recital 26**
  (means reasonably likely to be used); Art-29 WP **Opinion 05/2014 (WP216)**
  (singling-out / linkability / inference); **EDPB Guidelines 01/2025** on
  pseudonymisation (data re-identifiable via additional information remains
  personal data); ICO 2025 *motivated-intruder* test. Tier-A anonymity model:
  the **STAR** k-anonymous threshold-aggregation protocol (Brave/Mozilla,
  arXiv 2109.10074, CCS 2022; crate `sta-rs`).
