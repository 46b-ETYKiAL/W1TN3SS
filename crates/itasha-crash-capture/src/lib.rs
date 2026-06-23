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

/// Run the monitor role: parse the `--socket` / `--config-dir` args the client
/// passed and block on the monitor server loop until one crash is captured.
/// Returns a process exit code (`0` on clean capture/shutdown, `1` on error).
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
    // The `Err(_e) => 1` arm is unit-tested via an unbindable socket (see the
    // tests below). The `Ok(()) => 0` arm is NOT directly unit-testable: this
    // entry point constructs its own `shutdown=false` and then blocks in
    // `run_monitor`'s server loop until a real OS crash drives the handler to
    // `LoopAction::Exit`, so a clean `Ok` return requires either a genuine
    // native fault or an externally-set shutdown that this signature does not
    // expose. The `Ok` path of the underlying `run_monitor` IS covered directly
    // in `monitor::tests::run_monitor_returns_ok_when_shutdown_already_set`.
    match run_monitor(&socket, config_dir, &shutdown) {
        Ok(()) => 0,
        Err(_e) => 1,
    }
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
}
