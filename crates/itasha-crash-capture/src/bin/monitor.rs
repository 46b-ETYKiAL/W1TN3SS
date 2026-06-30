//! The `w1tn3ss-crash-monitor` binary — the SEPARATE out-of-process minidump
//! writer.
//!
//! This is a thin entry point: all logic lives in the library
//! (`itasha_crash_capture::run_monitor_main`) so it is unit-testable. Keeping
//! the monitor a distinct `[[bin]]` is load-bearing — the unsafe-isolation
//! structural test asserts it is a separate binary, so the unsafe native write
//! happens in a different process from the host app.
//!
//! Hosts that re-exec their own binary as the monitor (the self-spawn pattern)
//! should instead dispatch `itasha_crash_capture::is_monitor_invocation` /
//! `run_monitor_main` from their own `main`; this standalone binary is for hosts
//! that ship the monitor as a separate executable.
//!
//! `run_monitor_main` SURFACES each capture outcome as a structured line on this
//! process's stderr (which the spawning host captures) and returns a process
//! exit code that SIGNALS the result: `0` clean, `1` server/IPC run error, `2`
//! a fail-closed capture failure (LOG-WS-001 / LOG-WS-002). The exit code below
//! propagates that signal to the host's `wait()` — so a discarded crash report
//! is no longer silent to the operator or the host.

fn main() {
    let code = itasha_crash_capture::run_monitor_main(std::env::args());
    std::process::exit(code);
}
