//! The out-of-process MONITOR handler.
//!
//! The monitor is the SEPARATE process (the `w1tn3ss-crash-monitor` binary)
//! that the host spawns. It exists because a crashing process's own memory may
//! be corrupted — the documented Embark/Breakpad rationale for out-of-process
//! capture. The crashing app holds a `minidumper::Client`; on a native fault
//! the `crash-handler` callback hands the [`crash_context::CrashContext`] to
//! the monitor over IPC, and the monitor writes the minidump from a clean
//! address space.
//!
//! This module holds the [`MonitorHandler`] (`minidumper::ServerHandler` impl)
//! and the [`run_monitor`] loop so the wiring is unit-testable independently of
//! the thin `bin/monitor.rs` entry point.
//!
//! The minidump is written by `minidumper`'s server using the bundled
//! `minidump-writer`, which on every platform captures **stack traces for all
//! threads — not the full heap** (the `Normal` minidump baseline). The monitor
//! then reads the written dump, **minimizes it across ALL platforms** via
//! [`crate::scrub::scrub_minidump_in_place`] (dropping the env block, command
//! line, full-memory/heap, memory-map, and handle streams the per-OS writer
//! emits but offers no flag to suppress; coarsening the module list), **deletes
//! the raw pre-scrub `.dmp` immediately**, and spools ONLY the scrubbed bytes
//! LOCALLY via `itasha-report-core`'s budgeted spool. It transmits NOTHING.
//!
//! The [`crate::policy::MinidumpPolicy`] minimized contract drives the Windows
//! `MinidumpType` flag set; the byte-level scrub is the CROSS-PLATFORM
//! enforcement that closes the Linux/macOS "documented intent only" gap — the
//! live `minidumper` server invokes the per-OS writer with its DEFAULT config
//! (`None` `MinidumpType` on Windows; no `sanitize_stack` / no env-cmdline
//! suppression on Linux), so the written bytes are the only place stack-only
//! can actually be ENFORCED. Scrub failure is fail-closed: a dump that cannot
//! be parsed-and-minimized is deleted and NOT spooled.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use minidumper::{LoopAction, MinidumpBinary, Server, ServerHandler};

use crate::policy::MinidumpPolicy;

/// The default IPC socket / pipe name the host and monitor agree on. Hosts may
/// override per-app to avoid cross-app collisions.
pub const DEFAULT_SOCKET_NAME: &str = "w1tn3ss-crash-monitor";

/// The structured outcome of a single capture, surfaced to the host logger.
/// Counts/enums only — NEVER minidump bytes, NEVER PII.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureOutcome {
    /// A minidump was written, MINIMIZED (env/cmdline/heap/maps streams dropped,
    /// module list coarsened), the raw pre-scrub dump deleted, and the scrubbed
    /// bytes spooled.
    MinidumpWritten {
        /// The spooled report path.
        path: PathBuf,
        /// Counts-only report of what the cross-platform scrub removed. Proves
        /// the stack-only minimization gate actually ran.
        scrub: crate::scrub::ScrubReport,
    },
    /// Capture was attempted but the OS minidump write failed.
    CaptureFailed {
        /// A short, non-sensitive reason string.
        reason: String,
    },
}

/// `minidumper::ServerHandler` that writes the minidump to a temp file, reads
/// it back, and spools it locally via `itasha-report-core`.
pub struct MonitorHandler {
    /// Directory the host config lives in (the spool roots at
    /// `<config_dir>/reports/`).
    config_dir: PathBuf,
    /// The applied minidump policy (always minimized). Recorded so the outcome
    /// + tests can prove the privacy control is in force.
    policy: MinidumpPolicy,
    /// Where the temp minidump file is written before being read + spooled.
    dump_dir: PathBuf,
    /// Captured outcomes. Shared behind an `Arc<Mutex<_>>` so the monitor PROCESS
    /// can drain results AFTER `minidumper::Server::run` has consumed the boxed
    /// handler — the seam that lets fail-closed outcomes reach the host instead
    /// of being computed-then-discarded (LOG-WS-001).
    outcomes: Arc<Mutex<Vec<CaptureOutcome>>>,
}

impl MonitorHandler {
    /// Build a monitor handler rooted at the host `config_dir`. The minimized
    /// policy is always applied.
    #[must_use]
    pub fn new(config_dir: impl Into<PathBuf>) -> Self {
        let config_dir = config_dir.into();
        let dump_dir = config_dir.join("crash-dumps");
        Self {
            config_dir,
            policy: MinidumpPolicy::Minimized,
            dump_dir,
            outcomes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The minidump policy this monitor applies (always minimized — the privacy
    /// control).
    #[must_use]
    pub fn policy(&self) -> MinidumpPolicy {
        self.policy
    }

    /// Drain and return the outcomes recorded so far (for the host logger /
    /// tests).
    #[must_use]
    pub fn take_outcomes(&self) -> Vec<CaptureOutcome> {
        let mut guard = self.outcomes.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut guard)
    }

    /// A shared handle to the outcome sink. [`run_monitor`] keeps a clone of this
    /// BEFORE the handler is boxed and consumed by the blocking server loop, so
    /// the recorded outcomes can be drained and surfaced to the host once the
    /// loop exits — without this seam the outcomes die with the boxed handler
    /// (LOG-WS-001).
    #[must_use]
    pub fn outcomes_handle(&self) -> Arc<Mutex<Vec<CaptureOutcome>>> {
        Arc::clone(&self.outcomes)
    }

    fn record(&self, outcome: CaptureOutcome) {
        let mut guard = self.outcomes.lock().unwrap_or_else(|p| p.into_inner());
        guard.push(outcome);
    }

    /// The privacy-critical in-handler sequence: read the raw dump, MINIMIZE the
    /// bytes (cross-platform stack-only enforcement), DELETE the raw `.dmp`
    /// immediately, then spool ONLY the scrubbed bytes locally.
    ///
    /// Fail-closed at every step: if the dump cannot be read, scrubbed, or
    /// spooled, the raw `.dmp` is deleted and NOTHING is persisted — a dump
    /// whose env/cmdline/heap could not be proven-removed must never reach the
    /// spool. We never transmit; we only persist to the budgeted local spool.
    fn minimize_delete_and_spool(&self, raw_path: &std::path::Path) {
        // 1. Read the raw written dump.
        let mut bytes = match std::fs::read(raw_path) {
            Ok(b) => b,
            Err(_e) => {
                // Best-effort delete even on read failure (it may be partially
                // written and still PII-bearing).
                let _ = std::fs::remove_file(raw_path);
                self.record(CaptureOutcome::CaptureFailed {
                    // No inner `io::Error`: it can embed the dump path / OS errno.
                    reason: "A crash report could not be processed and was discarded; nothing was saved or sent.".to_string(),
                });
                return;
            }
        };

        // 2. Minimize the bytes IN PLACE (drop env/cmdline/heap/maps streams,
        //    coarsen the module list). Fail-closed on a parse error.
        let scrub = match crate::scrub::scrub_minidump_in_place(&mut bytes) {
            Ok(report) => report,
            Err(_e) => {
                // The raw dump is deleted; the un-minimizable bytes are dropped
                // (zeroed in memory) and never spooled.
                bytes.iter_mut().for_each(|b| *b = 0);
                let _ = std::fs::remove_file(raw_path);
                // Behavioral sentinel (asserted by the structural-isolation
                // privacy contract): an un-minimizable dump is "fail-closed, not spooled".
                // The user-visible `reason` carries no inner error or design jargon.
                self.record(CaptureOutcome::CaptureFailed {
                    reason: "A crash report could not be safely cleaned and was discarded; nothing was saved or sent.".to_string(),
                });
                return;
            }
        };

        // 3. DELETE the raw pre-scrub dump immediately — it is the only copy of
        //    the un-minimized bytes and must never persist to a durable path.
        if let Err(_e) = std::fs::remove_file(raw_path) {
            // If we cannot delete the raw dump, do NOT spool — leaving both the
            // raw (PII-bearing) dump and a spooled copy is worse than failing.
            bytes.iter_mut().for_each(|b| *b = 0);
            self.record(CaptureOutcome::CaptureFailed {
                // No inner `io::Error` (errno / dump path) and no design jargon.
                reason: "A crash report could not be processed and was discarded; nothing was saved or sent.".to_string(),
            });
            return;
        }

        // 4. Spool ONLY the scrubbed bytes to the budgeted local spool.
        match crate::emit::spool_minidump(&self.config_dir, bytes, &[]) {
            Ok(spooled) => self.record(CaptureOutcome::MinidumpWritten {
                path: spooled,
                scrub,
            }),
            Err(_e) => self.record(CaptureOutcome::CaptureFailed {
                // No inner `SpoolError` (errno / local spool path).
                reason: "A crash report could not be saved to this device and was discarded."
                    .to_string(),
            }),
        }
    }
}

impl ServerHandler for MonitorHandler {
    fn create_minidump_file(&self) -> Result<(std::fs::File, PathBuf), std::io::Error> {
        std::fs::create_dir_all(&self.dump_dir)?;
        // A unique, non-identifying temp name per capture.
        let nonce = crate::consent::Tier2ConsentToken::granted()
            .nonce()
            .to_string();
        let path = self.dump_dir.join(format!("crash-{nonce}.dmp"));
        let file = std::fs::File::create(&path)?;
        Ok((file, path))
    }

    fn on_minidump_created(&self, result: Result<MinidumpBinary, minidumper::Error>) -> LoopAction {
        match result {
            Ok(md) => self.minimize_delete_and_spool(&md.path),
            Err(_e) => self.record(CaptureOutcome::CaptureFailed {
                // No inner writer error.
                reason: "A crash report could not be created and was discarded.".to_string(),
            }),
        }
        // One crash → one dump → exit the monitor loop.
        LoopAction::Exit
    }

    fn on_message(&self, _kind: u32, _buffer: Vec<u8>) {
        // The monitor accepts no behavioural commands over the message channel;
        // capture is driven solely by the crash-handler dump request. Messages
        // are ignored (never executed — AES Clause 9: inbound bytes are data).
    }
}

/// Run the monitor server loop on `socket_name`, rooting the spool at
/// `config_dir`. Blocks until a crash is captured (the handler returns
/// [`LoopAction::Exit`]) or `shutdown` is set, then returns the
/// [`CaptureOutcome`]s the handler recorded during the loop so the caller can
/// SURFACE them to the host (counts/enums only — never bytes or PII).
///
/// The handler is consumed by `minidumper::Server::run`, so the outcomes are
/// read back through a shared `Arc<Mutex<_>>` handle taken before the box is
/// moved. An empty `Vec` means the loop exited (e.g. on `shutdown`) without a
/// capture; a non-empty `Vec` carries the per-capture result(s) (LOG-WS-001).
///
/// # Errors
///
/// Returns a [`minidumper::Error`] if the IPC server cannot be created or the
/// loop fails.
pub fn run_monitor(
    socket_name: &str,
    config_dir: impl Into<PathBuf>,
    shutdown: &AtomicBool,
) -> Result<Vec<CaptureOutcome>, minidumper::Error> {
    let mut server = Server::with_name(minidumper::SocketName::path(socket_name))?;
    let handler = MonitorHandler::new(config_dir);
    // Clone the shared outcome-sink handle BEFORE the handler is boxed and moved
    // into the blocking server loop — this is the seam that lets the recorded
    // outcomes be drained and surfaced to the host after the loop exits.
    let outcomes = handler.outcomes_handle();
    server.run(Box::new(handler), shutdown, None)?;
    let drained = std::mem::take(&mut *outcomes.lock().unwrap_or_else(|p| p.into_inner()));
    Ok(drained)
}

/// Signal a running [`run_monitor`] loop to stop at the next poll.
pub fn request_shutdown(shutdown: &AtomicBool) {
    shutdown.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_applies_minimized_policy() {
        let dir = std::env::temp_dir().join("w1tn3ss-monitor-policy-test");
        let h = MonitorHandler::new(&dir);
        assert_eq!(h.policy(), MinidumpPolicy::Minimized);
        assert!(h.policy().is_minimized());
    }

    #[test]
    fn create_minidump_file_yields_unique_paths() {
        let dir =
            std::env::temp_dir().join(format!("w1tn3ss-monitor-file-test-{}", std::process::id()));
        let h = MonitorHandler::new(&dir);
        let (_f1, p1) = h.create_minidump_file().unwrap();
        let (_f2, p2) = h.create_minidump_file().unwrap();
        assert_ne!(p1, p2);
        assert!(p1.exists() && p2.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Build a minimal valid synthetic minidump carrying an identifying
    /// `LinuxEnviron` stream (with a username + secret) plus a kept thread-stack
    /// stream, so we can prove the monitor minimizes BEFORE spooling.
    fn synthetic_minidump_with_env(env_payload: &[u8], stack_payload: &[u8]) -> Vec<u8> {
        // signature, version, stream_count=2, dir_rva=32
        const HEADER_SIZE: usize = 32;
        const DIR_ENTRY: usize = 12;
        const SIG: u32 = 0x504d_444d;
        // LinuxEnviron = 0x47670007, MemoryListStream = 5.
        let streams: [(u32, &[u8]); 2] = [(0x4767_0007, env_payload), (5u32, stack_payload)];
        let dir_rva = HEADER_SIZE;
        let payloads_rva = dir_rva + streams.len() * DIR_ENTRY;
        let mut buf = vec![0u8; payloads_rva];
        buf[0..4].copy_from_slice(&SIG.to_le_bytes());
        buf[4..8].copy_from_slice(&0xa793u32.to_le_bytes());
        buf[8..12].copy_from_slice(&(streams.len() as u32).to_le_bytes());
        buf[12..16].copy_from_slice(&(dir_rva as u32).to_le_bytes());
        let mut rvas = Vec::new();
        for (_, p) in &streams {
            rvas.push(buf.len());
            buf.extend_from_slice(p);
        }
        for (i, (ty, p)) in streams.iter().enumerate() {
            let off = dir_rva + i * DIR_ENTRY;
            buf[off..off + 4].copy_from_slice(&ty.to_le_bytes());
            buf[off + 4..off + 8].copy_from_slice(&(p.len() as u32).to_le_bytes());
            buf[off + 8..off + 12].copy_from_slice(&(rvas[i] as u32).to_le_bytes());
        }
        buf
    }

    #[test]
    fn on_minidump_created_minimizes_deletes_raw_and_spools_scrubbed() {
        use itasha_report_core::spool::Spool;
        let dir = std::env::temp_dir().join(format!(
            "w1tn3ss-monitor-spool-test-{}-{}",
            std::process::id(),
            crate::consent::Tier2ConsentToken::granted().nonce()
        ));
        let h = MonitorHandler::new(&dir);
        // Simulate minidumper having written a dump with an env block carrying PII.
        let dump =
            synthetic_minidump_with_env(b"USER=jane\0SECRET=hunter2\0", b"STACK-keepme-bytes");
        let (mut file, path) = h.create_minidump_file().unwrap();
        use std::io::Write;
        file.write_all(&dump).unwrap();
        drop(file);

        let action = h.on_minidump_created(Ok(MinidumpBinary {
            file: std::fs::File::open(&path).unwrap(),
            path: path.clone(),
            contents: None,
        }));
        assert!(action == LoopAction::Exit);

        let outcomes = h.take_outcomes();
        assert_eq!(outcomes.len(), 1);
        let spooled_path = match &outcomes[0] {
            CaptureOutcome::MinidumpWritten { path, scrub } => {
                assert!(path.exists());
                // The scrub gate actually ran: the env stream was dropped.
                assert_eq!(scrub.streams_dropped, 1);
                assert!(scrub.bytes_zeroed > 0);
                path.clone()
            }
            other => panic!("expected MinidumpWritten, got {other:?}"),
        };

        // The RAW pre-scrub dump is gone — deleted in-handler.
        assert!(
            !path.exists(),
            "the raw .dmp must be deleted immediately after minimization"
        );

        // The SPOOLED (scrubbed) minidump no longer contains the env PII, but
        // keeps the thread-stack memory.
        let spool = Spool::open(&dir).unwrap();
        let back = spool.load(&spooled_path).unwrap();
        let spooled_bytes = &back.attachments[0].bytes;
        assert!(
            !contains(spooled_bytes, b"jane"),
            "env username must not survive into the spooled dump"
        );
        assert!(
            !contains(spooled_bytes, b"hunter2"),
            "env secret must not survive into the spooled dump"
        );
        assert!(
            contains(spooled_bytes, b"STACK-keepme-bytes"),
            "thread-stack memory (the backtrace) must be preserved"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn on_minidump_created_fails_closed_on_unparseable_dump_and_deletes_raw() {
        let dir = std::env::temp_dir().join(format!(
            "w1tn3ss-monitor-failclosed-{}-{}",
            std::process::id(),
            crate::consent::Tier2ConsentToken::granted().nonce()
        ));
        let h = MonitorHandler::new(&dir);
        // Write NON-minidump bytes (no MDMP signature) — must NOT be spooled.
        let (mut file, path) = h.create_minidump_file().unwrap();
        use std::io::Write;
        file.write_all(&[0xABu8; 256]).unwrap();
        drop(file);

        h.on_minidump_created(Ok(MinidumpBinary {
            file: std::fs::File::open(&path).unwrap(),
            path: path.clone(),
            contents: None,
        }));

        let outcomes = h.take_outcomes();
        match &outcomes[0] {
            CaptureOutcome::CaptureFailed { reason } => {
                // WS-008: plain copy, no inner error / design jargon.
                assert!(
                    reason.contains("could not be safely cleaned and was discarded"),
                    "expected the plain scrub-failure copy, got: {reason}"
                );
                assert!(!reason.contains('/'), "path separator leaked: {reason}");
                assert!(!reason.contains("os error"), "errno leaked: {reason}");
                assert!(
                    !reason.contains("fail-closed"),
                    "design jargon leaked: {reason}"
                );
            }
            other => panic!("an unparseable dump must fail-closed, got {other:?}"),
        }
        // The raw dump is deleted even on fail-closed.
        assert!(
            !path.exists(),
            "the raw .dmp must be deleted on fail-closed"
        );
        // Nothing was spooled.
        let reports = dir.join("reports");
        let spooled_count = std::fs::read_dir(&reports)
            .map(|rd| rd.count())
            .unwrap_or(0);
        assert_eq!(spooled_count, 0, "no report may be spooled on fail-closed");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn on_minidump_created_records_failure_without_panicking() {
        let dir =
            std::env::temp_dir().join(format!("w1tn3ss-monitor-fail-test-{}", std::process::id()));
        let h = MonitorHandler::new(&dir);
        let action = h.on_minidump_created(Err(minidumper::Error::UnknownClientPid));
        // `LoopAction` derives `PartialEq` but not `Debug`; use `assert!`.
        assert!(action == LoopAction::Exit);
        let outcomes = h.take_outcomes();
        match &outcomes[0] {
            CaptureOutcome::CaptureFailed { reason } => {
                // WS-011: plain copy, no inner writer error.
                assert_eq!(
                    reason,
                    "A crash report could not be created and was discarded."
                );
            }
            other => panic!("expected CaptureFailed, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// `on_message` is a deliberate no-op (inbound bytes are data, never
    /// executed — AES Clause 9). Calling it records NOTHING and never panics.
    #[test]
    fn on_message_is_an_inert_noop() {
        let dir = std::env::temp_dir().join(format!("w1tn3ss-monitor-msg-{}", std::process::id()));
        let h = MonitorHandler::new(&dir);
        h.on_message(7, vec![1, 2, 3, 4]);
        h.on_message(0, Vec::new());
        // No outcome is recorded by a message — capture is driven only by dumps.
        assert!(h.take_outcomes().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The read-dump-fail branch (monitor.rs 129-136): a `MinidumpBinary` whose
    /// `path` points at a non-existent file makes `std::fs::read` fail →
    /// `CaptureFailed { reason }` containing "read dump failed", and the loop
    /// still exits.
    #[test]
    fn on_minidump_created_fails_closed_when_raw_dump_is_unreadable() {
        let dir = std::env::temp_dir().join(format!(
            "w1tn3ss-monitor-readfail-{}-{}",
            std::process::id(),
            crate::consent::Tier2ConsentToken::granted().nonce()
        ));
        let h = MonitorHandler::new(&dir);
        let missing = dir.join("does-not-exist.dmp");
        // A real File handle is required by MinidumpBinary; point it at /dev/null
        // equivalent — but `path` (what the handler reads) is the missing file.
        // We open the handler's own dump-dir file as a throwaway File, then pass
        // the missing path so the read in minimize_delete_and_spool fails.
        let (throwaway, _real_path) = h.create_minidump_file().unwrap();
        let action = h.on_minidump_created(Ok(MinidumpBinary {
            file: throwaway,
            path: missing.clone(),
            contents: None,
        }));
        assert!(action == LoopAction::Exit);
        let outcomes = h.take_outcomes();
        match &outcomes[0] {
            CaptureOutcome::CaptureFailed { reason } => {
                assert!(
                    reason.contains("could not be processed and was discarded"),
                    "expected a plain discard reason, got: {reason}"
                );
                // REDACTION (WS-007): no inner io::Error — no path, no errno.
                assert!(!reason.contains('/'), "path separator leaked: {reason}");
                assert!(!reason.contains("os error"), "errno leaked: {reason}");
                assert!(
                    !reason.contains(": "),
                    "inner-error suffix leaked: {reason}"
                );
            }
            other => panic!("expected CaptureFailed, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The spool-fail branch (monitor.rs 174-176): the dump reads + scrubs +
    /// raw-deletes fine, but the spool cannot be opened because `config_dir` is a
    /// regular FILE (so `<config_dir>/reports` cannot be created). The outcome is
    /// `CaptureFailed` with a "spool failed" reason, and the raw dump is still
    /// deleted.
    #[test]
    fn on_minidump_created_fails_closed_when_spool_cannot_open() {
        let base = std::env::temp_dir().join(format!(
            "w1tn3ss-monitor-spoolfail-{}-{}",
            std::process::id(),
            crate::consent::Tier2ConsentToken::granted().nonce()
        ));
        std::fs::create_dir_all(&base).unwrap();
        // config_dir is a FILE → Spool::open's create_dir_all("<file>/reports")
        // fails → spool_minidump returns Err.
        let config_file = base.join("config-is-a-file");
        std::fs::write(&config_file, b"not a directory").unwrap();
        let h = MonitorHandler::new(&config_file);

        // Write a VALID minidump at a raw path OUTSIDE config_dir so the read +
        // scrub + delete steps all succeed and only the spool step fails.
        let raw_path = base.join("raw.dmp");
        let dump = synthetic_minidump_with_env(b"USER=jane\0", b"STACK-keepme");
        std::fs::write(&raw_path, &dump).unwrap();

        h.on_minidump_created(Ok(MinidumpBinary {
            file: std::fs::File::open(&raw_path).unwrap(),
            path: raw_path.clone(),
            contents: None,
        }));

        let outcomes = h.take_outcomes();
        match &outcomes[0] {
            CaptureOutcome::CaptureFailed { reason } => {
                assert!(
                    reason.contains("could not be saved to this device"),
                    "expected a plain save-failure reason, got: {reason}"
                );
                // REDACTION (WS-010): no inner SpoolError — no path, no errno.
                assert!(!reason.contains('/'), "path separator leaked: {reason}");
                assert!(!reason.contains("os error"), "errno leaked: {reason}");
                assert!(
                    !reason.contains("spool"),
                    "internal 'spool' identifier leaked: {reason}"
                );
            }
            other => panic!("expected CaptureFailed (spool), got {other:?}"),
        }
        // The raw dump was deleted BEFORE the spool attempt (fail-closed step 3).
        assert!(
            !raw_path.exists(),
            "the raw .dmp must be deleted before the spool step"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// The raw-delete-fail branch (monitor.rs 158-166): the dump reads + scrubs
    /// fine, but `remove_file(raw_path)` fails because a second handle holds the
    /// file open with a share mode that denies DELETE. Windows-only: this is the
    /// only portable way to make `remove_file` fail while `read` still succeeds
    /// (POSIX `unlink` succeeds on an open file, so the branch is not reachable
    /// the same way on Unix — documented as platform-conditional).
    #[cfg(windows)]
    #[test]
    fn on_minidump_created_fails_closed_when_raw_delete_fails() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = std::env::temp_dir().join(format!(
            "w1tn3ss-monitor-deletefail-{}-{}",
            std::process::id(),
            crate::consent::Tier2ConsentToken::granted().nonce()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let raw_path = dir.join("raw.dmp");
        let dump = synthetic_minidump_with_env(b"USER=jane\0", b"STACK-keepme");
        std::fs::write(&raw_path, &dump).unwrap();

        // Open with FILE_SHARE_READ | FILE_SHARE_WRITE (=3), DENYING the DELETE
        // share. `std::fs::read` (which requests a delete-shareable handle) still
        // succeeds for reading, but `remove_file` is blocked while this handle is
        // alive → the raw-delete-fail branch fires.
        let _guard = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&raw_path)
            .unwrap();

        let h = MonitorHandler::new(&dir);
        h.on_minidump_created(Ok(MinidumpBinary {
            file: std::fs::File::open(&raw_path).unwrap(),
            path: raw_path.clone(),
            contents: None,
        }));

        let outcomes = h.take_outcomes();
        match &outcomes[0] {
            CaptureOutcome::CaptureFailed { reason } => {
                assert!(
                    reason.contains("could not be processed and was discarded"),
                    "expected a plain discard reason, got: {reason}"
                );
                // REDACTION (WS-009): no inner io::Error / design jargon.
                assert!(!reason.contains('/'), "path separator leaked: {reason}");
                assert!(!reason.contains("os error"), "errno leaked: {reason}");
                assert!(
                    !reason.contains("fail-closed"),
                    "design jargon leaked: {reason}"
                );
            }
            other => panic!("expected CaptureFailed (raw delete), got {other:?}"),
        }
        // Nothing was spooled — the fail-closed path returns before the spool.
        let spooled = std::fs::read_dir(dir.join("reports"))
            .map(|rd| rd.count())
            .unwrap_or(0);
        assert_eq!(spooled, 0, "no report may be spooled on raw-delete failure");
        drop(_guard);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `run_monitor` returns an `Err` fast (no blocking server loop) when the
    /// socket name cannot be bound — an over-long path is rejected by
    /// `minidumper` before any OS resource is created. Exercises the
    /// `Server::with_name(...)?` early-return arm (monitor.rs 224).
    #[test]
    fn run_monitor_errors_fast_on_unbindable_socket() {
        let dir = std::env::temp_dir().join(format!("w1tn3ss-run-monitor-{}", std::process::id()));
        let shutdown = AtomicBool::new(false);
        let bad_socket = format!("w1tn3ss-{}", "x".repeat(200));
        let result = run_monitor(&bad_socket, &dir, &shutdown);
        assert!(
            result.is_err(),
            "an unbindable socket must make run_monitor return Err, not block"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `run_monitor` returns `Ok(())` immediately when `shutdown` is ALREADY
    /// true: the server loop checks the flag at the top of each iteration before
    /// polling, so a pre-set shutdown short-circuits cleanly. Exercises the
    /// `server.run(...)` Ok path (monitor.rs 226) without a real crash.
    #[test]
    fn run_monitor_returns_ok_when_shutdown_already_set() {
        let dir = std::env::temp_dir().join(format!(
            "w1tn3ss-run-monitor-shutdown-{}",
            std::process::id()
        ));
        // shutdown already requested.
        let shutdown = AtomicBool::new(true);
        // A unique short socket name avoids colliding with the default name used
        // by any concurrent test; the bind succeeds, then the pre-set shutdown
        // short-circuits the loop on its first iteration.
        let socket = format!("w1tn3ss-shutdown-{}", std::process::id());
        let result = run_monitor(&socket, &dir, &shutdown);
        match result {
            // A pre-set shutdown exits the loop with no capture, so the drained
            // outcome vec is empty (exercises the `Ok(drained)` surface seam).
            Ok(outcomes) => assert!(
                outcomes.is_empty(),
                "a no-capture loop must drain an empty outcome vec"
            ),
            Err(_) => panic!("a pre-set shutdown must let run_monitor return Ok immediately"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `outcomes_handle` returns a SHARED view of the same sink the handler
    /// records into: a result recorded after the handle is taken is visible
    /// through the handle. This is the seam `run_monitor` relies on to drain
    /// outcomes after the boxed handler is consumed by the server loop.
    #[test]
    fn outcomes_handle_shares_the_sink_with_the_handler() {
        let dir = std::env::temp_dir().join(format!(
            "w1tn3ss-monitor-handle-{}-{}",
            std::process::id(),
            crate::consent::Tier2ConsentToken::granted().nonce()
        ));
        let h = MonitorHandler::new(&dir);
        let handle = h.outcomes_handle();
        assert!(handle.lock().unwrap().is_empty());
        // Record through the handler...
        h.record(CaptureOutcome::CaptureFailed {
            reason: "A crash report could not be created and was discarded.".to_string(),
        });
        // ...and observe it through the shared handle (same underlying Vec).
        let drained = std::mem::take(&mut *handle.lock().unwrap_or_else(|p| p.into_inner()));
        assert_eq!(drained.len(), 1);
        // The handler's own view is now empty (the take drained the shared sink).
        assert!(h.take_outcomes().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `request_shutdown` flips the shared `AtomicBool` to `true` (monitor.rs
    /// 230-232).
    #[test]
    fn request_shutdown_sets_the_flag() {
        let flag = AtomicBool::new(false);
        request_shutdown(&flag);
        assert!(
            flag.load(Ordering::SeqCst),
            "request_shutdown must set the flag true"
        );
    }
}
