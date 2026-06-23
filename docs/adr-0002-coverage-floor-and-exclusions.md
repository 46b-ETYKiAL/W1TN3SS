# ADR-0002 — SDK coverage floor + the structurally-uncoverable exclusion list

- Status: Accepted
- Date: 2026-06-23
- Scope: workspace (`itasha-report-core`, `itasha-crash-capture`, `itasha-report-transport-tor`, `itasha-report-aggregate`)

## Context

The W1TN3SS client SDK is the privacy-implementing code every fleet app
consumes. Its correctness is load-bearing: a sanitizer gap leaks PII, a consent
gap transmits without authorization, a spool/envelope bug drops or corrupts a
report. The `ci.yml` code-quality gate already runs `fmt` + `clippy` + `test` +
`gitleaks`, and `release-sign.yml` runs the supply-chain gate (`cargo-audit` /
`cargo-vet` / `cargo-auditable`). What was missing was a **coverage floor** —
a gate that fails the build if the *testable* surface of the SDK regresses
below a line-coverage threshold.

A naive "100% line coverage" floor is dishonest: parts of this SDK are
**structurally uncoverable in an offline, hermetic test harness** because they
require a live Tor onion, a live native crash, or a live browser/desktop. The
correct gate measures the testable surface and explicitly excludes — with named
justification — only the code that no in-process test can reach. That is the
discipline this ADR fixes in place.

## Decision

### 1. The floor: `cargo llvm-cov --fail-under-lines 95`

The coverage gate (a new `coverage` job in `ci.yml`, and the canonical local
gate) runs:

```bash
cargo llvm-cov nextest --all-features --workspace --locked \
  --ignore-filename-regex '(crash-capture[\\/]src[\\/](client|bin[\\/]monitor)\.rs|transport-tor[\\/]src[\\/]transport\.rs)' \
  --fail-under-lines 95
```

A workspace line coverage below **95%** (measured **with** the exclusions
below) **fails the build**. At adoption the workspace measures **96.96%** lines
with exclusions (**94.76%** with none), so the floor carries a ~2-point margin
against test-ordering / instrumentation jitter while still gating real
regressions. The floor is proven non-vacuous: raising it to 99 fails the gate.

### 2. The exclusion list (`--ignore-filename-regex`)

Only **structurally-uncoverable** files are excluded. Each is dominated by a
live-resource side effect that no in-process, network-free test can drive. The
testable logic in each crate stays in the measured surface.

| Excluded file | Why it is structurally uncoverable |
|---|---|
| `crates/itasha-crash-capture/src/client.rs` | Arms the **native out-of-process crash handler** and connects to the monitor over `minidumper` IPC. `arm_capture` / `spawn_monitor` / `connect_with_retry` require a real per-OS fault handler + a spawned monitor child process + a live IPC socket. The covered, hermetic surface (config builder, error-`Display`, the type-level Tier-2-token requirement) is duplicated into measured tests; the live arm is not reachable in-process. |
| `crates/itasha-crash-capture/src/bin/monitor.rs` | The **monitor binary entry point** (`main`). A binary `main` that blocks on an IPC server cannot be exercised by a library test. The monitor's testable logic lives in `monitor.rs` (the lib module, which **is** measured at 96.7%). |
| `crates/itasha-report-transport-tor/src/transport.rs` | The **live Tor onion bootstrap + connect**. `tor_client` / `transmit` / `build_arti_config` / the live half of `drain_spool` need an embedded Arti `TorClient` to bootstrap the directory consensus and connect to a real `.onion` — impossible offline. The transport's offline logic (spool, fixed-bucket padding, jitter sampling, drain bookkeeping, payload build) is covered by measured tests; the live round-trip is proven out-of-band by the `#[ignore]`d `live_onion_e2e` test. |

### 3. NOT excluded — and why

- `transport-tor/src/http.rs` (86.7%) is a hand-rolled HTTP/1.1 client generic
  over `AsyncRead + AsyncWrite`; it is exercised over an in-memory
  `tokio::io::duplex` pipe (no `.onion` needed) and therefore stays measured.
- `report-core/src/intake.rs` (98.4%) stays measured. Its one uncoverable line
  is the `webbrowser::open` syscall inside `launch`; the error-mapping logic is
  factored into the pure `map_launch_error` helper, which **is** unit-tested,
  so the live browser spawn is the only uncovered line — not worth a file
  exclusion.

### 4. `#![forbid(unsafe_code)]` is unchanged

`itasha-report-core` and `itasha-report-aggregate` remain
`#![forbid(unsafe_code)]`. The `forbid_unsafe_audit` belt-and-suspenders test
(a `src/`-tree scan for the `unsafe` keyword) stays green; the coverage work
added no `unsafe` and no `#[allow(unsafe_code)]` escape hatch.

## Coverage at adoption (per crate)

Line coverage, `cargo llvm-cov nextest --all-features`:

| Crate | Without exclusions | With exclusions |
|---|---|---|
| `itasha-report-core` | 98.60% | 98.60% (no file excluded) |
| `itasha-crash-capture` | 93.59% | 97.50% (excl. `client.rs`, `bin/monitor.rs`) |
| `itasha-report-transport-tor` | 83.65% | 91.47% (excl. `transport.rs`) |
| `itasha-report-aggregate` | 94.80% | 94.80% (no file excluded) |
| **workspace** | **94.76%** | **96.96%** |

## Consequences

- A coverage regression on the testable surface fails the build locally and in
  CI; the SDK's privacy-critical logic cannot silently lose its test cover.
- The live-resource surfaces (Tor, native capture, browser) remain proven
  out-of-band: the `#[ignore]`d `live_onion_e2e` test for the onion round-trip,
  and the duplicated hermetic tests for the crash-capture config/error/type
  contracts.
- **Removal triggers.** Drop an exclusion when its surface becomes testable —
  e.g. if a mock-Arti seam is introduced for `transport.rs`, or an injectable
  IPC transport for `client.rs`. Removing an exclusion can only *raise* the
  measured floor; the floor is never lowered to accommodate new untested code.

## Notes on the WIP that produced this ADR

The coverage tests were authored across the four crates by a prior session. This
ADR's adoption pass fixed four genuine defects in that WIP before the gate could
go green: (a) an `is_safe_shape` test asserting the wrong branch outcome,
(b) an `unsafe`-keyword string literal that tripped the forbid-unsafe audit,
(c) a non-hermetic `launch` test that spawned a real browser (a nextest LEAK),
fixed by extracting `map_launch_error`, and (d) a flaky `transport_reason`
status-code test whose one-shot server under-drained the request and surfaced a
transport error instead of a clean `StatusCode(500)`, fixed by fully draining
the request before replying.
