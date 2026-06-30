# Wiring contract — itasha-report-core

This crate exposes host-facing seams the W1TN3SS apps call. The integration
point that must always have a live call-site is `IngestBackend::send`.

> Scope: this contract covers `itasha-report-core` only. The opt-in
> `itasha-report-transport-tor` crate adds its own seams — the `OnionConnector`
> trait DI port, the `RetryPolicy`/`transmit_with_retry` drain loop, and the
> `ArtiConnector` adapter — documented in
> [ADR-0002](adr-0002-coverage-floor-and-exclusions.md).

```yaml
wiring:
  runtime_surface: live
  integration_points:
    - symbol: IngestBackend::send
      called_from: host application consent dialog (plan-732/733) → backend.send
      wiring_test: crates/itasha-report-core/tests/consent_send_contract.rs
      proves: >
        send requires a &ConsentToken at the type level; the recording-backend
        test observes exactly one send per host-minted token and zero sends
        without one. A consent-free send does not compile.
    - symbol: Envelope::to_bytes / Envelope::from_bytes
      called_from: backend.build_payload → Envelope::from_report → to_bytes
      wiring_test: crates/itasha-report-core/src/envelope.rs (round-trip tests)
      proves: the Sentry-envelope wire round-trips byte-for-byte, incl. a
        minidump attachment with embedded newlines.
    - symbol: Sanitizer::sanitize
      called_from: host capture path → Sanitizer::sanitize → Preview / Spool / send
      wiring_test: crates/itasha-report-core/tests/sanitizer_properties.rs
      proves: no home-path / username / hostname / env-value leak for arbitrary
        inputs.
    - symbol: Preview::of
      called_from: host consent dialog → Preview::of → user redaction → send
      wiring_test: crates/itasha-report-core/src/preview.rs
      proves: the literal editable Tier-1 text is returned and redactable.
  flags: []          # no feature flags; no default-on path exists (default-OFF config)
  data_flows:
    - from: ConsentToken.nonce
      to: backend (event_id_from_nonce → Envelope event_id)
      proves: the only per-report id is the ephemeral nonce — no stable id.
```

## Verification

```bash
cargo test  -p itasha-report-core            # unit + property + contract tests
cargo clippy -p itasha-report-core --all-targets -- -D warnings
cargo fmt --all --check
```

`#![forbid(unsafe_code)]` at the crate root is a compile-time gate; the build
fails if any `unsafe` is introduced.
