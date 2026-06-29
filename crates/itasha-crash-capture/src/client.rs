//! The in-app capture CLIENT — arming the native crash-handler.
//!
//! The host calls [`arm_capture`] from inside the application process **only
//! after** it has obtained Tier-2 heightened consent (it must pass a
//! [`Tier2ConsentToken`]). Arming:
//!
//! 1. spawns the separate `w1tn3ss-crash-monitor` process (the out-of-process
//!    writer), and
//! 2. attaches the per-OS `crash-handler` so a native fault hands the
//!    [`crash_context::CrashContext`] to the monitor over `minidumper` IPC.
//!
//! Capture is OFF by default: there is no constructor that arms capture, and
//! [`arm_capture`] cannot be called without a `&Tier2ConsentToken`. Dropping
//! the returned [`ArmedCapture`] detaches the handler and stops the monitor.
//!
//! ## `panic = "abort"` interaction (per OS)
//!
//! * **Linux**: a Rust `panic = "abort"` lowers to `SIGABRT`, which the
//!   `crash-handler` signal handler catches — so an aborting panic IS captured.
//! * **Windows**: `std::process::abort` uses the `__fastfail` intrinsic, which
//!   raises neither `SIGABRT` nor a catchable SEH exception; the structured
//!   faults this crate targets (access violation, illegal instruction, stack
//!   overflow) arrive via `SetUnhandledExceptionFilter` and ARE captured. A
//!   bare `__fastfail` is intentionally not interceptable.
//! * **macOS**: faults arrive via Mach exception ports.
//!
//! The Tier-1 safe panic hook (`itasha-report-core`) covers ordinary
//! `panic = "unwind"` panics; this crate covers the native faults it cannot.

use std::path::PathBuf;
use std::process::Child;

use crash_handler::CrashHandler;
use minidumper::Client;

use crate::consent::Tier2ConsentToken;

/// Errors arming native capture.
#[derive(Debug)]
pub enum ArmError {
    /// The monitor process could not be spawned.
    SpawnMonitor(std::io::Error),
    /// The IPC client could not connect to the monitor.
    Connect(minidumper::Error),
    /// The OS crash handler could not be attached.
    AttachHandler(crash_handler::Error),
}

impl std::fmt::Display for ArmError {
    // Host-visible copy carries NO inner OS error: the inner `io::Error` /
    // `minidumper::Error` / `crash_handler::Error` can embed a local executable
    // path, an OS errno, or the IPC socket/pipe name. We surface a fixed,
    // non-identifying class string with a plain recovery step instead (mirrors
    // the `non_identifying()` discipline in the Tor transport). The inner error
    // is still available structurally on the variant for a host-side log toggle.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArmError::SpawnMonitor(_) => f.write_str(
                "Crash protection could not start. Restart the app; if it keeps happening, reinstall.",
            ),
            ArmError::Connect(_) => {
                f.write_str("Crash protection could not start. Restart the app to try again.")
            }
            ArmError::AttachHandler(_) => f.write_str(
                "Crash protection could not start on this system. The app will run normally without it.",
            ),
        }
    }
}

impl std::error::Error for ArmError {}

/// Configuration for arming native capture.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// The IPC socket / pipe name shared with the monitor.
    pub socket_name: String,
    /// The host config dir the monitor roots its spool under.
    pub config_dir: PathBuf,
    /// Path to the `w1tn3ss-crash-monitor` executable. Defaults to the current
    /// exe with a `--w1tn3ss-crash-monitor` arg if `None` (host opts in to the
    /// self-spawn pattern), otherwise an explicit monitor binary path.
    pub monitor_exe: Option<PathBuf>,
}

impl CaptureConfig {
    /// Build a config with the default socket name.
    #[must_use]
    pub fn new(config_dir: impl Into<PathBuf>) -> Self {
        Self {
            socket_name: crate::monitor::DEFAULT_SOCKET_NAME.to_string(),
            config_dir: config_dir.into(),
            monitor_exe: None,
        }
    }
}

/// A live native-capture arming. While held, the per-OS crash handler is
/// attached and the monitor process is running. Drop to detach + stop.
///
/// The `crash_handler::CrashHandler` is kept alive in this struct: dropping it
/// detaches the OS handler. The monitor `Child` is killed on drop.
pub struct ArmedCapture {
    _handler: CrashHandler,
    monitor: Child,
}

impl ArmedCapture {
    /// The monitor process id (useful for host supervision / Linux ptrace
    /// scoping).
    #[must_use]
    pub fn monitor_pid(&self) -> u32 {
        self.monitor.id()
    }
}

impl Drop for ArmedCapture {
    fn drop(&mut self) {
        // Best-effort: stop the monitor when capture is disarmed. The handler
        // detaches via its own Drop.
        let _ = self.monitor.kill();
        let _ = self.monitor.wait();
    }
}

/// Arm native out-of-process crash capture.
///
/// **Requires a [`Tier2ConsentToken`]** — there is no arming path without
/// heightened consent. This spawns the monitor process and attaches the OS
/// crash handler; on a native fault the handler hands the crash context to the
/// monitor, which writes a minimized-memory minidump to the local spool. It
/// NEVER transmits.
///
/// # Errors
///
/// Returns [`ArmError`] if the monitor cannot be spawned, the IPC client cannot
/// connect, or the OS handler cannot be attached.
pub fn arm_capture(
    config: &CaptureConfig,
    _consent: &Tier2ConsentToken,
) -> Result<ArmedCapture, ArmError> {
    // 1. Spawn the separate monitor process.
    let monitor = spawn_monitor(config).map_err(ArmError::SpawnMonitor)?;

    // 2. Connect the IPC client, retrying briefly while the monitor starts.
    let client = connect_with_retry(&config.socket_name).map_err(ArmError::Connect)?;

    // 3. Attach the per-OS crash handler. The closure runs in a COMPROMISED
    //    context on crash — it does only the minimal async-signal-safe work of
    //    forwarding the crash context to the monitor over IPC.
    // SAFETY: `make_crash_event` is `unsafe` because the supplied closure runs
    // inside the OS crash handler — a compromised context where heap
    // allocation, locking, and most std calls are unsound. Our closure does
    // ONLY async-signal-safe work: it calls `client.request_dump`, which sends
    // the already-populated `crash_context` over the pre-established IPC
    // connection (no allocation on the crash path) and returns. We allocate
    // nothing, take no lock, and call no re-entrant std API inside it, so the
    // `CrashEvent` safety contract is upheld.
    let on_crash = unsafe {
        crash_handler::make_crash_event(move |cc: &crash_handler::CrashContext| {
            crash_handler::CrashEventResult::Handled(client.request_dump(cc).is_ok())
        })
    };
    // SAFETY: `CrashHandler::attach` installs the process-wide OS fault handler
    // (SetUnhandledExceptionFilter on Windows / signal handlers on Linux / Mach
    // ports on macOS). It is sound to call here: we install exactly one handler
    // per `ArmedCapture`, the `on_crash` event satisfies the `CrashEvent`
    // contract justified above, and the returned handle is retained in
    // `ArmedCapture` so the handler stays installed for the capture's lifetime
    // and is detached on drop.
    let handler = CrashHandler::attach(on_crash).map_err(ArmError::AttachHandler)?;

    Ok(ArmedCapture {
        _handler: handler,
        monitor,
    })
}

/// Spawn the monitor process. If `monitor_exe` is set, run it directly;
/// otherwise re-exec the current binary with the monitor sentinel arg (the
/// host's `main` must dispatch that arg to [`crate::run_monitor_main`]).
fn spawn_monitor(config: &CaptureConfig) -> Result<Child, std::io::Error> {
    use std::process::Command;
    let mut cmd = match &config.monitor_exe {
        Some(exe) => Command::new(exe),
        None => Command::new(std::env::current_exe()?),
    };
    cmd.arg(crate::MONITOR_SENTINEL_ARG)
        .arg("--socket")
        .arg(&config.socket_name)
        .arg("--config-dir")
        .arg(&config.config_dir);
    cmd.spawn()
}

/// Connect the IPC client to the monitor, retrying for a short startup window.
fn connect_with_retry(socket_name: &str) -> Result<Client, minidumper::Error> {
    let mut last_err = None;
    for _ in 0..50 {
        match Client::with_name(minidumper::SocketName::path(socket_name)) {
            Ok(c) => return Ok(c),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
    Err(last_err.unwrap_or(minidumper::Error::InvalidName))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_config_defaults_to_monitor_socket() {
        let cfg = CaptureConfig::new("/tmp/cfg");
        assert_eq!(cfg.socket_name, crate::monitor::DEFAULT_SOCKET_NAME);
        assert!(cfg.monitor_exe.is_none());
    }

    /// `CaptureConfig` fields are all settable + readable: the default socket,
    /// an explicit config_dir, and an explicit monitor_exe override.
    #[test]
    fn capture_config_fields_are_settable() {
        let mut cfg = CaptureConfig::new("/tmp/witness-cfg");
        assert_eq!(cfg.config_dir, std::path::PathBuf::from("/tmp/witness-cfg"));
        assert_eq!(cfg.socket_name, crate::monitor::DEFAULT_SOCKET_NAME);
        assert!(cfg.monitor_exe.is_none());

        cfg.socket_name = "custom-socket".to_string();
        cfg.monitor_exe = Some(std::path::PathBuf::from("/opt/w1tn3ss/monitor"));
        assert_eq!(cfg.socket_name, "custom-socket");
        assert_eq!(
            cfg.monitor_exe.as_deref(),
            Some(std::path::Path::new("/opt/w1tn3ss/monitor"))
        );
        // CaptureConfig is Clone + Debug (used by host wiring + logs).
        let cloned = cfg.clone();
        assert_eq!(cloned.socket_name, cfg.socket_name);
        assert!(format!("{cfg:?}").contains("custom-socket"));
    }

    /// `ArmError`'s `Display` (client.rs 50-56) renders each variant with a
    /// human-readable, non-empty message wrapping the inner error. We can
    /// construct `SpawnMonitor` from a real `std::io::Error` without spawning a
    /// process; the other two arms are exercised via their inner error types.
    #[test]
    fn arm_error_display_renders_each_variant() {
        let spawn = ArmError::SpawnMonitor(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "monitor exe missing",
        ));
        let spawn_msg = format!("{spawn}");
        assert!(spawn_msg.contains("Crash protection could not start"));
        assert!(spawn_msg.contains("reinstall"));

        let connect = ArmError::Connect(minidumper::Error::InvalidName);
        let connect_msg = format!("{connect}");
        assert!(connect_msg.contains("Crash protection could not start"));
        assert!(connect_msg.contains("Restart the app"));

        let attach = ArmError::AttachHandler(crash_handler::Error::OutOfMemory);
        let attach_msg = format!("{attach}");
        assert!(attach_msg.contains("run normally without it"));

        // ArmError implements std::error::Error + Debug (host bubbles it up).
        let e: &dyn std::error::Error = &spawn;
        assert!(e.source().is_none());
        assert!(format!("{spawn:?}").contains("SpawnMonitor"));
    }

    /// REDACTION GUARANTEE (WS-001/002/003): the host-visible `Display` of an
    /// `ArmError` must NEVER carry the inner OS error — no local path, no errno,
    /// no socket/pipe name, no internal helper-process name. We construct each
    /// variant with a deliberately leaky inner error and prove none of it
    /// survives into the user-facing string.
    #[test]
    fn arm_error_display_never_leaks_inner_os_detail() {
        let leaky_path = "/home/jane/.config/app/w1tn3ss-crash-monitor";
        let spawn = ArmError::SpawnMonitor(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("os error 13: cannot exec {leaky_path}"),
        ));
        for err in [
            spawn,
            ArmError::Connect(minidumper::Error::InvalidName),
            ArmError::AttachHandler(crash_handler::Error::OutOfMemory),
        ] {
            let shown = format!("{err}");
            assert!(!shown.contains(leaky_path), "path leaked: {shown}");
            assert!(!shown.contains('/'), "a path separator leaked: {shown}");
            assert!(!shown.contains("os error"), "an errno leaked: {shown}");
            assert!(
                !shown.contains("monitor"),
                "internal helper-process name leaked: {shown}"
            );
        }
    }

    #[test]
    fn arm_capture_requires_a_tier2_token_at_the_type_level() {
        // This test documents the type-level gate: `arm_capture`'s signature
        // takes `&Tier2ConsentToken`, so it is impossible to call without one.
        // (We don't actually arm here — that would spawn a process — we assert
        // the gate is a compile-time fact via a function pointer coercion.)
        let _gate: fn(&CaptureConfig, &Tier2ConsentToken) -> Result<ArmedCapture, ArmError> =
            arm_capture;
    }
}
