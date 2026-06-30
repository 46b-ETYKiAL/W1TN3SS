//! `itasha-crash-capture` — the UNSAFE-ISOLATED native crash-capture sibling.
//!
//! This is the **only** W1TN3SS crate permitted to use `unsafe`. It delivers
//! Tier-2 NATIVE crash capture — the segfaults, aborts, illegal instructions,
//! stack overflows, and FFI/GPU-driver faults that the safe Tier-1 panic hook
//! in `itasha-report-core` cannot catch. Capturing those needs the Embark
//! `crash-handler` + `minidumper` + `minidump-writer` stack, which is
//! unsafe-heavy (signal handlers, SEH, Mach ports, FFI). Isolating that unsafe
//! HERE — in a sibling crate whose minidump is written by a SEPARATE monitor
//! process — is what lets every consuming app and `itasha-report-core` itself
//! stay `#![forbid(unsafe_code)]`.
//!
//! # The privacy posture
//!
//! Native capture is the most sensitive stream W1TN3SS has: a minidump embeds
//! raw thread-stack memory that can hold fragments of the user's open
//! documents, and it is binary (NOT user-previewable like Tier-1 text). The
//! defense-in-depth controls are:
//!
//! 1. **OFF by default** — there is no constructor that arms capture; arming
//!    requires an explicit [`Tier2ConsentToken`].
//! 2. **Heightened consent** — [`Tier2ConsentToken`] is a SEPARATE, more
//!    sensitive consent type than Tier-1 text, minted only after the user
//!    accepts an explicit disclosure ([`TIER2_CONSENT_DISCLOSURE`]).
//! 3. **Minimized-memory capture, ENFORCED on every platform** —
//!    [`MinidumpPolicy::Minimized`] sets the Windows `MinidumpType` flags, and
//!    [`scrub::scrub_minidump_in_place`] then minimizes the WRITTEN dump bytes
//!    on every platform before they are spooled: it drops the environment
//!    block, command line, full-memory/heap, memory-map, and handle-name
//!    streams (which the live `minidumper` writer emits and offers no flag to
//!    suppress on Linux/macOS) and coarsens the module list. The raw pre-scrub
//!    dump is deleted in-handler — only the scrubbed bytes ever reach disk.
//! 4. **Local-spool-only, NEVER auto-send** — the monitor writes minidumps to
//!    the local `itasha-report-core` spool; this crate has NO network code at
//!    all. The host transmits the Sentry envelope only after Tier-2 consent.
//! 5. **No persistent identifier** — the emitted Sentry envelope carries only
//!    an ephemeral per-capture nonce, never a device/install fingerprint.
//!
//! # Out-of-process model
//!
//! A crashing process's own memory may be corrupted, so the minidump is written
//! by a SEPARATE [`w1tn3ss-crash-monitor`](crate::run_monitor_main) process the
//! host spawns. The crashing app holds a `minidumper` client; on a fault the
//! `crash-handler` callback forwards the crash context to the monitor over IPC,
//! and the monitor writes the dump from a clean address space.
//!
//! # Host wiring
//!
//! ```no_run
//! use itasha_crash_capture::{arm_capture, CaptureConfig, Tier2ConsentToken};
//!
//! // The host's `main` dispatches the monitor sentinel arg FIRST, so the same
//! // binary can serve as both app and monitor (or pass an explicit monitor exe).
//! if itasha_crash_capture::is_monitor_invocation(std::env::args()) {
//!     std::process::exit(itasha_crash_capture::run_monitor_main(std::env::args()));
//! }
//!
//! // ... later, AFTER the user accepts the Tier-2 heightened-consent disclosure:
//! let user_accepted_tier2 = true; // ← from the consent dialog (plan-732)
//! if user_accepted_tier2 {
//!     let consent = Tier2ConsentToken::granted();
//!     let config = CaptureConfig::new(std::env::temp_dir().join("w1tn3ss"));
//!     let _armed = arm_capture(&config, &consent).expect("arm native capture");
//!     // `_armed` stays alive for the capture's lifetime; drop disarms.
//! }
//! ```

use std::io::Write;

pub mod client;
pub mod consent;
pub mod emit;
pub mod monitor;
pub mod policy;
pub mod scrub;

pub use client::{arm_capture, ArmError, ArmedCapture, CaptureConfig};
pub use consent::{Tier2ConsentToken, TIER2_CONSENT_DISCLOSURE};
pub use emit::{build_crash_report, build_envelope, spool_minidump};
pub use monitor::{run_monitor, CaptureOutcome, MonitorHandler, DEFAULT_SOCKET_NAME};
pub use policy::MinidumpPolicy;
pub use scrub::{scrub_minidump_in_place, ScrubError, ScrubReport};

/// The crate / SDK name.
pub const CRATE_NAME: &str = "itasha-crash-capture";

/// The crate version.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The sentinel argument a host's `main` checks to dispatch the monitor role.
/// When present, the binary runs as the out-of-process crash monitor instead of
/// the app.
pub const MONITOR_SENTINEL_ARG: &str = "--w1tn3ss-crash-monitor";

/// Returns `true` if `args` indicate this process was launched as the crash
/// monitor (i.e. contains [`MONITOR_SENTINEL_ARG`]). The host calls this at the
/// very top of `main` to route to [`run_monitor_main`].
pub fn is_monitor_invocation(args: impl IntoIterator<Item = String>) -> bool {
    args.into_iter().any(|a| a == MONITOR_SENTINEL_ARG)
}

/// Process exit code: a clean monitor run — the loop exited with no capture
/// failure.
pub const EXIT_OK: i32 = 0;
/// Process exit code: the monitor server could not be created or its loop
/// failed (the IPC bind / server-error path). The monitor never ran a capture.
pub const EXIT_RUN_ERROR: i32 = 1;
/// Process exit code: the monitor loop ran but at least one capture genuinely
/// FAILED (a scrub / spool / delete / write fail-closed). Distinct from
/// [`EXIT_RUN_ERROR`] so the host can tell "the monitor never ran" from "the
/// monitor ran but a crash report was discarded" (LOG-WS-002).
pub const EXIT_CAPTURE_FAILED: i32 = 2;

/// Run the monitor role: parse the `--socket` / `--config-dir` args the client
/// passed and block on the monitor server loop until one crash is captured,
/// then SURFACE the recorded [`monitor::CaptureOutcome`]s to the monitor
/// process's stderr (which the spawning host captures) and SIGNAL the result
/// through the exit code.
///
/// Returns a process exit code: [`EXIT_OK`] on a clean run, [`EXIT_RUN_ERROR`]
/// if the server could not start, or [`EXIT_CAPTURE_FAILED`] if the loop ran but
/// a capture failed fail-closed. Before this surfacing existed a fail-closed
/// capture was computed-then-discarded (LOG-WS-001) and the loop always exited 0
/// (LOG-WS-002) — silent to both operator and host.
///
/// The library crates stay `tracing`-free by design; this surfacing happens
/// ONLY here, at the out-of-band monitor-PROCESS boundary, as a structured
/// stderr line carrying COUNTS / ENUMS / sanitized class strings only.
///
/// The host calls this from `main` when [`is_monitor_invocation`] is true.
#[must_use]
pub fn run_monitor_main(args: impl IntoIterator<Item = String>) -> i32 {
    let argv: Vec<String> = args.into_iter().collect();
    let socket = arg_value(&argv, "--socket").unwrap_or_else(|| DEFAULT_SOCKET_NAME.to_string());
    let config_dir = arg_value(&argv, "--config-dir").unwrap_or_else(|| {
        std::env::temp_dir()
            .join("w1tn3ss")
            .to_string_lossy()
            .into_owned()
    });
    let shutdown = std::sync::atomic::AtomicBool::new(false);
    match run_monitor(&socket, config_dir, &shutdown) {
        Ok(outcomes) => surface_outcomes(&outcomes, &mut std::io::stderr().lock()),
        Err(_e) => {
            // The IPC server could not be created / the loop failed. Surface a
            // non-identifying run-error line — NO inner error (it can embed the
            // socket path / OS errno) — and signal the run-error exit code.
            let _ = writeln!(
                std::io::stderr(),
                "level=error target=w1tn3ss-crash-monitor event=monitor_run_error"
            );
            EXIT_RUN_ERROR
        }
    }
}

/// Format a single [`monitor::CaptureOutcome`] as a non-identifying, structured
/// log line for the host-captured monitor sink.
///
/// COUNTS / ENUMS / sanitized class strings ONLY — never a spool path, minidump
/// bytes, OS errno, socket name, or PII. The `MinidumpWritten` spool `path` is
/// deliberately NOT surfaced; only the scrub counters that prove the
/// minimization gate ran are emitted. The `CaptureFailed` `reason` is the
/// already-de-leaked plain-English copy (asserted PII-free by the redaction
/// tests), surfaced verbatim so the operator learns the failure class.
fn outcome_log_line(outcome: &monitor::CaptureOutcome) -> String {
    match outcome {
        monitor::CaptureOutcome::MinidumpWritten { scrub, .. } => format!(
            "level=info target=w1tn3ss-crash-monitor event=capture_succeeded \
             streams_dropped={} modules_coarsened={} bytes_zeroed={}",
            scrub.streams_dropped, scrub.modules_coarsened, scrub.bytes_zeroed
        ),
        monitor::CaptureOutcome::CaptureFailed { reason } => format!(
            "level=error target=w1tn3ss-crash-monitor event=capture_failed reason={reason:?}"
        ),
    }
}

/// Surface every recorded [`monitor::CaptureOutcome`] to `sink` (the monitor
/// process's stderr in production, a buffer in tests) and return the process
/// exit code: [`EXIT_CAPTURE_FAILED`] if ANY outcome is a
/// [`monitor::CaptureOutcome::CaptureFailed`], else [`EXIT_OK`].
///
/// This is the missing surface that previously left every fail-closed capture
/// result computed-then-discarded (LOG-WS-001) and the loop always exiting 0
/// (LOG-WS-002). The write is best-effort: a broken stderr pipe must not crash
/// the monitor nor mask the capture signal the exit code carries.
fn surface_outcomes<W: Write>(outcomes: &[monitor::CaptureOutcome], sink: &mut W) -> i32 {
    let mut exit = EXIT_OK;
    for outcome in outcomes {
        let _ = writeln!(sink, "{}", outcome_log_line(outcome));
        if matches!(outcome, monitor::CaptureOutcome::CaptureFailed { .. }) {
            exit = EXIT_CAPTURE_FAILED;
        }
    }
    exit
}

/// Extract the value following `flag` in `argv` (e.g. `--socket NAME`).
fn arg_value(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_invocation_detected_by_sentinel() {
        assert!(is_monitor_invocation([
            "app".to_string(),
            MONITOR_SENTINEL_ARG.to_string(),
        ]));
        assert!(!is_monitor_invocation([
            "app".to_string(),
            "--other".to_string()
        ]));
    }

    #[test]
    fn arg_value_extracts_flag_argument() {
        let argv = vec![
            "app".to_string(),
            "--socket".to_string(),
            "the-socket".to_string(),
            "--config-dir".to_string(),
            "/tmp/cfg".to_string(),
        ];
        assert_eq!(arg_value(&argv, "--socket").as_deref(), Some("the-socket"));
        assert_eq!(
            arg_value(&argv, "--config-dir").as_deref(),
            Some("/tmp/cfg")
        );
        assert_eq!(arg_value(&argv, "--missing"), None);
    }

    #[test]
    fn crate_name_and_version_are_set() {
        assert_eq!(CRATE_NAME, "itasha-crash-capture");
        assert!(!CRATE_VERSION.is_empty());
    }

    /// A socket name that deterministically fails `minidumper::Server::with_name`
    /// WITHOUT binding any real OS resource or blocking. minidumper copies the
    /// path into a fixed 108-byte `sockaddr_un.sun_path`; a longer-than-107-byte
    /// path is rejected with `InvalidData` on every platform before any
    /// socket/pipe syscall, so `run_monitor` returns `Err` immediately.
    fn unbindable_socket_name() -> String {
        format!("w1tn3ss-{}", "x".repeat(200))
    }

    /// `run_monitor_main` returns exit code 1 when the underlying `run_monitor`
    /// fails. We force a fast `Err` with an over-long socket name (rejected
    /// before any blocking server loop), so the server never starts. Exercises
    /// the `Err(_e) => 1` arm and the `--config-dir` default branch (no
    /// `--config-dir` passed → lib.rs 109-114).
    #[test]
    fn run_monitor_main_returns_one_on_run_error() {
        let argv = vec![
            "w1tn3ss-crash-monitor".to_string(),
            "--socket".to_string(),
            unbindable_socket_name(),
        ];
        let code = run_monitor_main(argv);
        assert_eq!(code, 1, "an invalid socket must yield exit code 1");
    }

    /// `run_monitor_main` honours an explicit `--config-dir` (the non-default
    /// branch). We still force a fast error via an unbindable socket so the call
    /// returns without blocking; the assertion is on the exit code.
    #[test]
    fn run_monitor_main_uses_explicit_config_dir_and_reports_error() {
        let cfg =
            std::env::temp_dir().join(format!("w1tn3ss-run-monitor-cfg-{}", std::process::id()));
        let argv = vec![
            "w1tn3ss-crash-monitor".to_string(),
            "--socket".to_string(),
            unbindable_socket_name(),
            "--config-dir".to_string(),
            cfg.to_string_lossy().into_owned(),
        ];
        let code = run_monitor_main(argv);
        assert_eq!(code, 1);
    }

    // -----------------------------------------------------------------------
    // Monitor outcome-surfacing harness (LOG-WS-001 / LOG-WS-002).
    //
    // These tests are the capture harness for the monitor process's structured
    // sink: `surface_outcomes` writes into a `Vec<u8>` buffer we can assert on.
    // They prove a failed capture is SURFACED (not silent) AND signals a
    // non-zero exit code, a clean run surfaces success, and NO surfaced line
    // carries a path byte / errno / crash-content marker / PII.
    // -----------------------------------------------------------------------

    #[test]
    fn exit_codes_are_distinct_and_canonical() {
        assert_eq!(EXIT_OK, 0);
        assert_eq!(EXIT_RUN_ERROR, 1);
        assert_eq!(EXIT_CAPTURE_FAILED, 2);
    }

    #[test]
    fn surface_outcomes_empty_is_silent_and_ok() {
        let mut sink: Vec<u8> = Vec::new();
        let code = surface_outcomes(&[], &mut sink);
        assert_eq!(code, EXIT_OK);
        assert!(sink.is_empty(), "no outcomes must surface no lines");
    }

    #[test]
    fn surface_outcomes_clean_run_exits_ok() {
        let outcomes = vec![monitor::CaptureOutcome::MinidumpWritten {
            path: std::path::PathBuf::from("ignored"),
            scrub: scrub::ScrubReport {
                streams_dropped: 2,
                modules_coarsened: 4,
                bytes_zeroed: 128,
            },
        }];
        let mut sink: Vec<u8> = Vec::new();
        let code = surface_outcomes(&outcomes, &mut sink);
        assert_eq!(code, EXIT_OK);
        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("level=info"));
        assert!(text.contains("event=capture_succeeded"));
        // The scrub counters that prove the minimization gate ran ARE surfaced.
        assert!(text.contains("streams_dropped=2"));
        assert!(text.contains("modules_coarsened=4"));
        assert!(text.contains("bytes_zeroed=128"));
    }

    #[test]
    fn surface_outcomes_failure_is_surfaced_and_signals_nonzero() {
        let outcomes = vec![monitor::CaptureOutcome::CaptureFailed {
            reason: "A crash report could not be created and was discarded.".to_string(),
        }];
        let mut sink: Vec<u8> = Vec::new();
        let code = surface_outcomes(&outcomes, &mut sink);
        // LOG-WS-002: a failed capture is NO LONGER silent / exit-0.
        assert_eq!(
            code, EXIT_CAPTURE_FAILED,
            "a failed capture must signal a non-zero exit code"
        );
        assert_ne!(code, EXIT_OK);
        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("level=error"));
        assert!(text.contains("event=capture_failed"));
    }

    /// The no-PII guarantee for the surfaced sink. A success outcome whose spool
    /// PATH embeds a username, a secret-looking token, and a `.dmp` marker — and
    /// a fail-closed outcome — are surfaced together; the buffer must carry the
    /// COUNTS/ENUMS but NONE of the path bytes, PII, errno, or crash-content
    /// markers. Mirrors the redaction-assert style of the error-copy tests.
    #[test]
    fn surfaced_lines_never_leak_path_bytes_or_pii() {
        let leaky_path = std::path::PathBuf::from(
            "/home/jane/.config/w1tn3ss/reports/crash-deadbeef-AKIAhunter2.dmp",
        );
        let outcomes = vec![
            monitor::CaptureOutcome::MinidumpWritten {
                path: leaky_path,
                scrub: scrub::ScrubReport {
                    streams_dropped: 3,
                    modules_coarsened: 7,
                    bytes_zeroed: 512,
                },
            },
            monitor::CaptureOutcome::CaptureFailed {
                reason: "A crash report could not be safely cleaned and was \
                         discarded; nothing was saved or sent."
                    .to_string(),
            },
        ];
        let mut sink: Vec<u8> = Vec::new();
        let code = surface_outcomes(&outcomes, &mut sink);
        let text = String::from_utf8(sink).unwrap();

        // The counts ARE surfaced (proving the gate ran)...
        assert!(text.contains("streams_dropped=3"));
        assert!(text.contains("bytes_zeroed=512"));
        assert!(text.contains("event=capture_succeeded"));
        assert!(text.contains("event=capture_failed"));

        // ...but NO path byte, PII, errno, spool-dir, or crash-content marker leaks.
        for banned in [
            "jane",        // username embedded in the spool path
            "AKIAhunter2", // secret-looking token embedded in the path
            ".dmp",        // raw-dump file marker
            ".config",     // path component
            "/",           // POSIX path separator
            "\\",          // Windows path separator
            "os error",    // errno
            "reports",     // spool-directory component
        ] {
            assert!(
                !text.contains(banned),
                "surfaced monitor sink leaked {banned:?}: {text}"
            );
        }

        // A genuine capture failure in the batch still signals non-zero.
        assert_eq!(code, EXIT_CAPTURE_FAILED);
    }
}
