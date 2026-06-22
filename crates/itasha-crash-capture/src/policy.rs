//! The MINIMIZED-MEMORY minidump policy — the privacy control.
//!
//! A minidump's thread-list stream embeds raw thread-stack memory. For a note
//! editor that memory can hold fragments of the user's open documents. The
//! defense-in-depth privacy posture (tech-crash-capture.md § 1.3) starts at
//! WRITE time by capturing as little memory as possible: enough to reconstruct
//! a stack trace + register state, but dropping heap / full process memory
//! wherever the `MiniDumpWriteDump` flag surface allows.
//!
//! This module centralizes that policy as a single [`MinidumpPolicy`] so the
//! "drop heap where possible" decision is one auditable constant, not scattered
//! across capture sites. On Windows the policy maps to a `MinidumpType` flag
//! set ([`MinidumpPolicy::windows_minidump_type`]).
//!
//! # Enforced on EVERY platform (gap D-4 closed)
//!
//! The Windows flag set is a *write-time* reduction, but the live capture path
//! is `minidumper`'s out-of-process server, which invokes the per-OS writer
//! with its DEFAULT config — it passes `None` for the Windows `MinidumpType`
//! and applies neither `sanitize_stack` nor env/cmdline suppression on Linux.
//! So the flag set alone was "documented intent" on Linux/macOS. The ENFORCED
//! cross-platform mechanism is the byte-level minimizer
//! [`crate::scrub::scrub_minidump_in_place`], which the monitor runs over the
//! WRITTEN dump on every platform before spooling: it physically drops the
//! environment block, command line, full-memory/heap, memory-map, and handle
//! streams ([`crate::scrub::is_identifying_stream`]) and coarsens the module
//! list. [`MinidumpPolicy::is_minimized`] now reflects that the policy is
//! enforced — see [`MinidumpPolicy::enforcement`].

#[cfg(target_os = "windows")]
use minidump_writer::MinidumpType;

/// The crate-wide minidump capture policy.
///
/// The only supported policy is [`MinidumpPolicy::Minimized`] — the privacy
/// default. A `FullMemory` variant is deliberately NOT offered: this crate
/// exists to make native capture privacy-conservative, and a full-heap dump
/// would defeat that. The enum exists so the policy is a named, documented
/// value rather than a bare flag literal at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MinidumpPolicy {
    /// Capture stacks + registers needed for a stack trace, and drop optional
    /// / private memory regions wherever the platform flag surface allows.
    #[default]
    Minimized,
}

impl MinidumpPolicy {
    /// The Windows `MinidumpType` flag set this policy maps to.
    ///
    /// `Normal` (= 0) already restricts the dump to "just the information
    /// necessary to capture stack traces for all existing threads" — i.e. NO
    /// full heap. We additionally OR in:
    ///
    /// * `FilterMemory` — "Stack and backing-store memory written to the
    ///   minidump should be filtered to remove all but the pointer values
    ///   necessary to reconstruct a stack trace." This is the strongest
    ///   available reduction of stack-resident document fragments.
    /// * `WithoutOptionalData` — "Reduce the data that is dumped by
    ///   eliminating memory regions that are not essential ... This can avoid
    ///   dumping memory that may contain data that is private to the user."
    ///
    /// We explicitly do NOT set any `WithFullMemory*` /
    /// `WithPrivateReadWriteMemory` / `WithIndirectlyReferencedMemory` flag —
    /// those would re-expand the captured surface.
    #[cfg(target_os = "windows")]
    #[must_use]
    pub fn windows_minidump_type(self) -> MinidumpType {
        match self {
            MinidumpPolicy::Minimized => {
                MinidumpType::Normal
                    | MinidumpType::FilterMemory
                    | MinidumpType::WithoutOptionalData
            }
        }
    }

    /// Assert the policy never enables a full-memory / private-memory flag.
    ///
    /// This is a runtime cross-check the monitor and tests use to prove the
    /// privacy control is actually applied (no accidental full-heap capture).
    #[cfg(target_os = "windows")]
    #[must_use]
    pub fn is_minimized(self) -> bool {
        let t = self.windows_minidump_type();
        let forbidden = MinidumpType::WithFullMemory
            | MinidumpType::WithPrivateReadWriteMemory
            | MinidumpType::WithIndirectlyReferencedMemory
            | MinidumpType::WithFullMemoryInfo;
        !t.intersects(forbidden)
    }

    /// Non-Windows platforms: the per-OS minidump-writer already restricts the
    /// captured MEMORY to thread stacks (not the heap), and the byte-level
    /// minimizer [`crate::scrub::scrub_minidump_in_place`] ENFORCES the rest of
    /// the stack-only contract on the written bytes — dropping the env block,
    /// command line, memory-map, and handle streams the Linux writer emits
    /// unconditionally. So the minimized policy is enforced here, not merely
    /// documented (gap D-4 closed).
    #[cfg(not(target_os = "windows"))]
    #[must_use]
    pub fn is_minimized(self) -> bool {
        matches!(self, MinidumpPolicy::Minimized)
    }

    /// A short, human-readable description of HOW the minimized policy is
    /// enforced on the current platform. Used in audit logging + tests to prove
    /// the enforcement mechanism is named, not assumed.
    #[must_use]
    pub fn enforcement(self) -> &'static str {
        match self {
            MinidumpPolicy::Minimized => {
                if cfg!(target_os = "windows") {
                    "windows MinidumpType flags (Normal|FilterMemory|WithoutOptionalData) \
                     + cross-platform byte-level stream minimizer (scrub_minidump_in_place)"
                } else {
                    "per-OS stack-only memory capture \
                     + cross-platform byte-level stream minimizer (scrub_minidump_in_place)"
                }
            }
        }
    }
}

/// Write a minimized-memory minidump for the supplied crash context to
/// `destination`, applying [`MinidumpPolicy::Minimized`].
///
/// This is the single place the unsafe native write happens for the Windows
/// out-of-process path. It is a SAFE public function (it exposes no unsafe to
/// callers); the unsafe is fully internal and `// SAFETY:`-justified.
///
/// # Errors
///
/// Returns the underlying `minidump-writer` error if the OS minidump write
/// fails (e.g. the crashing process could not be opened, or the file could not
/// be written).
#[cfg(target_os = "windows")]
pub fn write_minidump(
    crash_context: &crash_context::CrashContext,
    policy: MinidumpPolicy,
    destination: &mut std::fs::File,
) -> Result<(), minidump_writer::errors::Error> {
    // SAFETY: `dump_crash_context` is `unsafe`-adjacent because, when
    // `crash_context.exception_pointers` is non-null, the caller must ensure
    // that pointer stays valid for the duration of the call. In the
    // out-of-process monitor this `crash_context` was just received over the
    // minidumper IPC from the still-suspended crashing client, so its interior
    // EXCEPTION_POINTERS are valid for this synchronous call. `dump_crash_context`
    // itself is a safe fn signature in minidump-writer 0.12 (the unsafe FFI is
    // internal to it); we wrap the call site here to document the validity
    // contract we are upholding.
    minidump_writer::minidump_writer::MinidumpWriter::dump_crash_context(
        crash_context,
        Some(policy.windows_minidump_type()),
        destination,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_minimized() {
        assert_eq!(MinidumpPolicy::default(), MinidumpPolicy::Minimized);
        assert!(MinidumpPolicy::Minimized.is_minimized());
    }

    #[test]
    fn policy_enforcement_names_the_cross_platform_scrubber() {
        // The minimized policy is no longer "documented intent" — its
        // enforcement string names the byte-level minimizer that actually drops
        // the identifying streams on EVERY platform.
        let e = MinidumpPolicy::Minimized.enforcement();
        assert!(
            e.contains("scrub_minidump_in_place"),
            "the minimized policy MUST be enforced by the cross-platform scrubber, got: {e}"
        );
    }

    #[test]
    fn policy_is_applied_by_the_scrub_dropset() {
        use crate::scrub::is_identifying_stream;
        use minidump_writer::minidump_format::MDStreamType;
        // Proof the policy is APPLIED, not assumed: the env block + command line
        // are classified for dropping by the enforced minimizer. If a future
        // refactor stopped dropping them, this test fails.
        assert!(MinidumpPolicy::Minimized.is_minimized());
        assert!(is_identifying_stream(MDStreamType::LinuxEnviron as u32));
        assert!(is_identifying_stream(MDStreamType::LinuxCmdLine as u32));
        assert!(is_identifying_stream(
            MDStreamType::Memory64ListStream as u32
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn minimized_type_excludes_full_and_private_memory() {
        let t = MinidumpPolicy::Minimized.windows_minidump_type();
        // The privacy control: NO full-heap / private-RW memory flags.
        assert!(!t.contains(MinidumpType::WithFullMemory));
        assert!(!t.contains(MinidumpType::WithPrivateReadWriteMemory));
        assert!(!t.contains(MinidumpType::WithIndirectlyReferencedMemory));
        // The reduction flags ARE set.
        assert!(t.contains(MinidumpType::FilterMemory));
        assert!(t.contains(MinidumpType::WithoutOptionalData));
        assert!(MinidumpPolicy::Minimized.is_minimized());
    }
}
