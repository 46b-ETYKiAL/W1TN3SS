//! Cross-platform, byte-level minidump MINIMIZER — the enforced stack-only gate.
//!
//! # Why a byte-level scrubber (the gap this closes)
//!
//! The privacy intent of [`crate::policy::MinidumpPolicy::Minimized`] was, until
//! now, only *enforced on Windows* (via the `MinidumpType` flag set) and was
//! merely *documented intent* on Linux/macOS (gap D-4 in the anonymity research:
//! `D-current-architecture-gaps.md`). The reason is structural: the live
//! out-of-process writer is `minidumper`'s server, and on every platform it
//! invokes the per-OS `minidump-writer` with its **default** configuration —
//! `minidumper-0.10.1/src/ipc/server.rs` calls
//! `MinidumpWriter::dump_crash_context(&cc, None, …)` on Windows (the `None`
//! discards our policy flags) and `MinidumpWriterConfig::new(pid, tid).write(…)`
//! on Linux/macOS (no `sanitize_stack`, no env/cmdline suppression). The Linux
//! writer (`minidump-writer-0.12.0/src/linux/minidump_writer/mod.rs::write_dump`)
//! **unconditionally** emits a `LinuxEnviron` stream (`/proc/$pid/environ`), a
//! `LinuxCmdLine` stream (`/proc/$pid/cmdline`), `LinuxProcStatus`, and
//! `LinuxMaps` — there is no builder flag to drop them. So the only way to
//! ENFORCE stack-only on every platform is to minimize the *written dump bytes*
//! before they are ever spooled.
//!
//! This module does exactly that, with no new dependency: it parses the
//! minidump header + stream directory (the stable, Microsoft-defined binary
//! layout) and, for every stream whose type is an identifying reservoir
//! ([`is_identifying_stream`]), it **zeroes the stream payload bytes and
//! neutralizes the directory entry** so the environment block / command line /
//! memory-map / heap can never reach disk. It additionally **coarsens the module
//! list** ([`coarsen_module_list`]) to drop the per-module path/timestamp
//! fingerprint while keeping the base/size/debug-id the stackwalker needs.
//!
//! The scrubber runs in the monitor's `on_minidump_created`, BEFORE the spool,
//! on all platforms — it is the cross-platform backstop the per-OS writer cannot
//! provide. The raw pre-scrub dump is deleted in-handler (see
//! [`crate::monitor`]); only the scrubbed bytes are ever persisted.
//!
//! # The stream classification
//!
//! * **DROP (identifying reservoirs):** `LinuxEnviron`, `LinuxCmdLine`,
//!   `LinuxProcStatus`, `LinuxMaps`, `LinuxAuxv`, `MozLinuxLimits`,
//!   `Memory64ListStream` (a full/heap memory list), `MemoryInfoListStream`
//!   (region map = fingerprint), `HandleDataStream` (handle names can embed
//!   document/file names), `CommentStreamA`/`CommentStreamW` (free text).
//! * **COARSEN:** `ModuleListStream` — strip module-name paths to a basename and
//!   zero the machine-specific `checksum` / `time_date_stamp` PE fields.
//! * **KEEP (needed to symbolicate, low PII):** `ThreadListStream`,
//!   `MemoryListStream` (the thread STACKS — the only memory we keep, already
//!   reduced by `FilterMemory` on Windows and stack-only on Linux),
//!   `ExceptionStream`, `SystemInfoStream`, `ThreadNamesStream`.

use minidump_writer::minidump_format::MDStreamType;

/// The minidump file signature ("MDMP" little-endian) — `MINIDUMP_SIGNATURE`.
const MINIDUMP_SIGNATURE: u32 = 0x504d_444d;

/// Byte size of the `MINIDUMP_HEADER` (signature, version, stream_count,
/// stream_directory_rva, checksum, time_date_stamp = 6×u32, flags = u64).
const HEADER_SIZE: usize = 32;

/// Byte size of one `MINIDUMP_DIRECTORY` entry (stream_type:u32 +
/// location{data_size:u32, rva:u32}).
const DIRECTORY_ENTRY_SIZE: usize = 12;

/// Byte size of one `MINIDUMP_MODULE` entry in a `ModuleListStream`.
///
/// Layout (`minidump_common::format::MINIDUMP_MODULE`): base_of_image:u64,
/// size_of_image:u32, checksum:u32, time_date_stamp:u32, module_name_rva:u32,
/// version_info(VS_FIXEDFILEINFO = 13×u32 = 52), cv_record(8),
/// misc_record(8), reserved0(8), reserved1(8) = 8+4+4+4+4+52+8+8+8+8 = 108.
const MODULE_ENTRY_SIZE: usize = 108;

/// Offset within a `MINIDUMP_MODULE` of `checksum` (after base_of_image:u64 +
/// size_of_image:u32).
const MODULE_CHECKSUM_OFFSET: usize = 12;
/// Offset within a `MINIDUMP_MODULE` of `time_date_stamp` (after checksum).
const MODULE_TIME_DATE_STAMP_OFFSET: usize = 16;
/// Offset within a `MINIDUMP_MODULE` of `module_name_rva` (after
/// time_date_stamp).
const MODULE_NAME_RVA_OFFSET: usize = 20;

/// A sentinel stream type written over a dropped directory entry so a parser
/// sees an inert, empty `ReservedStream0`-style slot rather than the original
/// identifying stream. `MINIDUMP_STREAM_TYPE::UnusedStream == 0`.
const DROPPED_STREAM_SENTINEL: u32 = 0;

/// The outcome of scrubbing a minidump — counts only, NEVER bytes/PII. Surfaced
/// to the monitor outcome log so a test/operator can prove the gate ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScrubReport {
    /// Number of identifying streams dropped (payload zeroed + entry
    /// neutralized).
    pub streams_dropped: u32,
    /// Number of module entries coarsened (path→basename, checksum/timestamp
    /// zeroed).
    pub modules_coarsened: u32,
    /// Total bytes of identifying stream payload zeroed.
    pub bytes_zeroed: u32,
}

/// Errors from parsing a minidump for scrubbing. The monitor treats ANY error
/// as fail-closed: a dump that cannot be parsed-and-minimized is NOT spooled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScrubError {
    /// The bytes are too short to contain a minidump header.
    TooShort,
    /// The signature is not `MDMP` — not a minidump.
    BadSignature,
    /// The stream directory is out of bounds for the buffer.
    DirectoryOutOfBounds,
}

impl std::fmt::Display for ScrubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScrubError::TooShort => write!(f, "buffer too short for a minidump header"),
            ScrubError::BadSignature => write!(f, "not a minidump (bad signature)"),
            ScrubError::DirectoryOutOfBounds => {
                write!(f, "minidump stream directory out of bounds")
            }
        }
    }
}

impl std::error::Error for ScrubError {}

/// Returns `true` if a stream of `stream_type` is an identifying reservoir that
/// MUST be dropped to enforce stack-only capture (environment block, command
/// line, full memory map / heap, handle names, free-text comments).
///
/// This is the heart of the cross-platform stack-only enforcement: it names the
/// EXACT stream-type constants (from `minidump_common`'s
/// `MINIDUMP_STREAM_TYPE`) the per-OS writer emits but that carry no
/// stack-trace value and high PII.
#[must_use]
pub fn is_identifying_stream(stream_type: u32) -> bool {
    // Compare against the canonical enum discriminants (re-exported via
    // minidump-writer) so a future format change can't silently desync.
    stream_type == MDStreamType::LinuxEnviron as u32          // /proc/$pid/environ
        || stream_type == MDStreamType::LinuxCmdLine as u32   // /proc/$pid/cmdline
        || stream_type == MDStreamType::LinuxProcStatus as u32 // uid/gid/proc status
        || stream_type == MDStreamType::LinuxMaps as u32      // full memory-map paths
        || stream_type == MDStreamType::LinuxAuxv as u32      // auxv (paths/addresses)
        || stream_type == MDStreamType::MozLinuxLimits as u32 // rlimits
        || stream_type == MDStreamType::Memory64ListStream as u32 // full/heap memory
        || stream_type == MDStreamType::MemoryInfoListStream as u32 // region map fingerprint
        || stream_type == MDStreamType::HandleDataStream as u32 // handle names (doc/file names)
        || stream_type == MDStreamType::CommentStreamA as u32 // free-text comment
        || stream_type == MDStreamType::CommentStreamW as u32 // free-text comment
}

/// Read a little-endian `u32` at `offset`, or `None` if out of bounds.
fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = buf.get(offset..end)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

/// Write a little-endian `u32` at `offset`. Caller guarantees bounds.
fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Minimize a written minidump IN PLACE: drop identifying streams (zeroing the
/// payload and neutralizing the directory entry) and coarsen the module list.
/// Returns a counts-only [`ScrubReport`].
///
/// This is the ENFORCED, cross-platform stack-only gate — it runs on the dump
/// bytes the per-OS writer produced, on EVERY platform, so the privacy posture
/// no longer depends on a per-OS writer flag the live `minidumper` path ignores.
///
/// # Errors
///
/// Returns [`ScrubError`] if the buffer is not a parseable minidump. The caller
/// (monitor) MUST treat any error as fail-closed and refuse to spool.
pub fn scrub_minidump_in_place(buf: &mut [u8]) -> Result<ScrubReport, ScrubError> {
    if buf.len() < HEADER_SIZE {
        return Err(ScrubError::TooShort);
    }
    let signature = read_u32_le(buf, 0).ok_or(ScrubError::TooShort)?;
    if signature != MINIDUMP_SIGNATURE {
        return Err(ScrubError::BadSignature);
    }
    let stream_count = read_u32_le(buf, 8).ok_or(ScrubError::TooShort)? as usize;
    let dir_rva = read_u32_le(buf, 12).ok_or(ScrubError::TooShort)? as usize;

    // Bounds-check the whole directory array up front.
    let dir_end = dir_rva
        .checked_add(
            stream_count
                .checked_mul(DIRECTORY_ENTRY_SIZE)
                .ok_or(ScrubError::DirectoryOutOfBounds)?,
        )
        .ok_or(ScrubError::DirectoryOutOfBounds)?;
    if dir_end > buf.len() {
        return Err(ScrubError::DirectoryOutOfBounds);
    }

    let mut report = ScrubReport::default();

    // First pass: collect each entry's (dir_offset, type, data_size, rva) so we
    // can mutate payloads without holding overlapping &mut borrows.
    struct Entry {
        dir_offset: usize,
        stream_type: u32,
        data_size: usize,
        rva: usize,
    }
    let mut entries = Vec::with_capacity(stream_count);
    for i in 0..stream_count {
        let dir_offset = dir_rva + i * DIRECTORY_ENTRY_SIZE;
        let stream_type = read_u32_le(buf, dir_offset).ok_or(ScrubError::DirectoryOutOfBounds)?;
        let data_size =
            read_u32_le(buf, dir_offset + 4).ok_or(ScrubError::DirectoryOutOfBounds)? as usize;
        let rva =
            read_u32_le(buf, dir_offset + 8).ok_or(ScrubError::DirectoryOutOfBounds)? as usize;
        entries.push(Entry {
            dir_offset,
            stream_type,
            data_size,
            rva,
        });
    }

    for e in &entries {
        if is_identifying_stream(e.stream_type) {
            // Zero the payload bytes (the env/cmdline/heap content) if they are
            // in bounds. A stream whose location is out of bounds is just
            // neutralized at the directory level (no payload to zero).
            if let Some(end) = e.rva.checked_add(e.data_size) {
                if end <= buf.len() {
                    for b in &mut buf[e.rva..end] {
                        *b = 0;
                    }
                    report.bytes_zeroed = report.bytes_zeroed.saturating_add(e.data_size as u32);
                }
            }
            // Neutralize the directory entry: sentinel type + empty location so a
            // parser sees an inert slot, not the original identifying stream.
            write_u32_le(buf, e.dir_offset, DROPPED_STREAM_SENTINEL);
            write_u32_le(buf, e.dir_offset + 4, 0); // data_size
            write_u32_le(buf, e.dir_offset + 8, 0); // rva
            report.streams_dropped = report.streams_dropped.saturating_add(1);
        } else if e.stream_type == MDStreamType::ModuleListStream as u32 {
            report.modules_coarsened = report
                .modules_coarsened
                .saturating_add(coarsen_module_list(buf, e.rva, e.data_size));
        }
    }

    Ok(report)
}

/// Coarsen a `ModuleListStream` in place: for every `MINIDUMP_MODULE` entry,
/// zero the machine-specific `checksum` + `time_date_stamp` PE fields and
/// rewrite the module-name string in place to its BASENAME (dropping the
/// directory path that embeds the OS username / custom dir layout). Returns the
/// count of modules coarsened.
///
/// The base/size/`cv_record` (debug-id) the symbolicator keys on are left
/// intact; only the fingerprinting fields and the path prefix are removed.
///
/// The stream layout is a 4-byte `u32` count followed by `count` fixed-size
/// `MINIDUMP_MODULE` records. The `module_name_rva` points to a UTF-16LE
/// length-prefixed string (`u32` byte-length, then the UTF-16 code units).
fn coarsen_module_list(buf: &mut [u8], rva: usize, data_size: usize) -> u32 {
    // The stream must at least hold the u32 count. NOTE: `rva` + `data_size` are
    // both u32-sourced (≤ ~4 GiB each), so this `checked_add` never overflows
    // `usize` on a 64-bit target — the `else { return 0 }` arm is a defensive
    // guard that is structurally unreachable here, kept for 32-bit safety.
    let Some(stream_end) = rva.checked_add(data_size) else {
        return 0;
    };
    if stream_end > buf.len() || data_size < 4 {
        return 0;
    }
    // `data_size >= 4` and `stream_end <= buf.len()` were just asserted, so
    // `read_u32_le(buf, rva)` (which needs `rva..rva+4`) always succeeds — the
    // `else { return 0 }` arm is likewise a defensive, structurally-unreachable
    // guard on this path.
    let Some(count) = read_u32_le(buf, rva) else {
        return 0;
    };
    let count = count as usize;

    let mut coarsened = 0u32;
    for i in 0..count {
        // The `None => break` arm fires only on a `usize` overflow of
        // `i * MODULE_ENTRY_SIZE` — unreachable for any in-bounds count on a
        // 64-bit target (the truncated-buffer case is caught by the
        // `entry_offset + MODULE_ENTRY_SIZE > buf.len()` break below, which IS
        // exercised by `module_list_with_truncated_entry_breaks_without_coarsening`).
        let entry_offset = match rva
            .checked_add(4)
            .and_then(|base| base.checked_add(i.checked_mul(MODULE_ENTRY_SIZE)?))
        {
            Some(o) => o,
            None => break,
        };
        if entry_offset + MODULE_ENTRY_SIZE > buf.len() {
            break;
        }
        // Zero the machine-specific PE fingerprint fields.
        write_u32_le(buf, entry_offset + MODULE_CHECKSUM_OFFSET, 0);
        write_u32_le(buf, entry_offset + MODULE_TIME_DATE_STAMP_OFFSET, 0);

        // Coarsen the module-name string to its basename, in place.
        if let Some(name_rva) = read_u32_le(buf, entry_offset + MODULE_NAME_RVA_OFFSET) {
            coarsen_module_name_to_basename(buf, name_rva as usize);
        }
        coarsened = coarsened.saturating_add(1);
    }
    coarsened
}

/// Rewrite a minidump UTF-16LE length-prefixed module-name string to its
/// basename IN PLACE (keeping the same byte length so no offsets shift).
///
/// The string is `[u32 byte_length][UTF-16LE code units]`. We find the last
/// path separator (`/` or `\`) and shift the basename code units to the front,
/// zero-filling the freed tail. This strips `C:\Users\jane\app\` →
/// `app.dll` while preserving the byte_length field and the stream size.
fn coarsen_module_name_to_basename(buf: &mut [u8], name_rva: usize) {
    let Some(byte_len) = read_u32_le(buf, name_rva) else {
        return;
    };
    let byte_len = byte_len as usize;
    // Number of UTF-16 code units.
    if byte_len == 0 || byte_len % 2 != 0 {
        return;
    }
    let units = byte_len / 2;
    let data_start = name_rva + 4;
    // `data_start` and `byte_len` are both u32-derived (≤ ~4 GiB), so this
    // `checked_add` cannot overflow `usize` on a 64-bit target — the
    // `else { return }` arm is a defensive guard kept for 32-bit safety, not
    // reachable on this path. The `data_end > buf.len()` OOB guard below IS
    // exercised by `module_name_out_of_bounds_length_is_left_untouched`.
    let Some(data_end) = data_start.checked_add(byte_len) else {
        return;
    };
    if data_end > buf.len() {
        return;
    }

    // Decode code units (LE), find the last separator.
    let mut last_sep: Option<usize> = None;
    for i in 0..units {
        let lo = buf[data_start + i * 2] as u16;
        let hi = buf[data_start + i * 2 + 1] as u16;
        let cu = lo | (hi << 8);
        if cu == u16::from(b'/') || cu == u16::from(b'\\') {
            last_sep = Some(i);
        }
    }
    let Some(sep_idx) = last_sep else {
        return; // no path separator → already a basename, nothing to strip.
    };
    let base_start_unit = sep_idx + 1;
    if base_start_unit >= units {
        return; // trailing separator; leave as-is.
    }
    let base_units = units - base_start_unit;
    // Shift the basename code units to the front (byte-wise, 2 bytes per unit).
    for j in 0..base_units {
        let src = data_start + (base_start_unit + j) * 2;
        let dst = data_start + j * 2;
        buf[dst] = buf[src];
        buf[dst + 1] = buf[src + 1];
    }
    // Zero-fill the freed tail so no path-prefix bytes survive.
    for k in base_units..units {
        buf[data_start + k * 2] = 0;
        buf[data_start + k * 2 + 1] = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic minidump: a header + a directory with the
    /// supplied `(stream_type, payload)` streams. Returns the bytes. Layout:
    /// `[header][directory][payloads...]`.
    fn build_minidump(streams: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let stream_count = streams.len();
        let dir_rva = HEADER_SIZE;
        let payloads_rva = dir_rva + stream_count * DIRECTORY_ENTRY_SIZE;

        let mut buf = vec![0u8; payloads_rva];
        // Header.
        write_u32_le(&mut buf, 0, MINIDUMP_SIGNATURE);
        write_u32_le(&mut buf, 4, 0xa793); // version
        write_u32_le(&mut buf, 8, stream_count as u32);
        write_u32_le(&mut buf, 12, dir_rva as u32);

        // Append payloads, recording their rvas.
        let mut payload_rvas = Vec::new();
        for (_ty, payload) in streams {
            let rva = buf.len();
            payload_rvas.push(rva);
            buf.extend_from_slice(payload);
        }
        // Directory entries.
        for (i, (ty, payload)) in streams.iter().enumerate() {
            let dir_off = dir_rva + i * DIRECTORY_ENTRY_SIZE;
            write_u32_le(&mut buf, dir_off, *ty);
            write_u32_le(&mut buf, dir_off + 4, payload.len() as u32);
            write_u32_le(&mut buf, dir_off + 8, payload_rvas[i] as u32);
        }
        buf
    }

    #[test]
    fn rejects_non_minidump_bytes() {
        let mut not_a_dump = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            scrub_minidump_in_place(&mut not_a_dump),
            Err(ScrubError::TooShort)
        );
        let mut bad_sig = vec![0u8; 64];
        assert_eq!(
            scrub_minidump_in_place(&mut bad_sig),
            Err(ScrubError::BadSignature)
        );
    }

    #[test]
    fn drops_environ_and_cmdline_streams_zeroing_payload() {
        let environ = b"USER=jane\0HOME=/home/jane\0SECRET=hunter2\0".to_vec();
        let cmdline = b"/home/jane/app --token=abc123\0".to_vec();
        let stack = b"STACKMEMORY-keepme".to_vec();
        let mut dump = build_minidump(&[
            (MDStreamType::LinuxEnviron as u32, environ.clone()),
            (MDStreamType::LinuxCmdLine as u32, cmdline.clone()),
            (MDStreamType::MemoryListStream as u32, stack.clone()),
        ]);

        let report = scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(report.streams_dropped, 2);
        assert!(report.bytes_zeroed >= (environ.len() + cmdline.len()) as u32);

        // The identifying payloads are physically gone (zeroed) from the bytes.
        assert!(
            !contains_subslice(&dump, b"jane"),
            "username must not survive in the scrubbed dump"
        );
        assert!(
            !contains_subslice(&dump, b"hunter2"),
            "env secret must not survive in the scrubbed dump"
        );
        assert!(
            !contains_subslice(&dump, b"--token=abc123"),
            "cmdline token must not survive in the scrubbed dump"
        );
        // The kept thread-stack stream survives untouched (it is the only memory
        // we keep — needed for the backtrace).
        assert!(
            contains_subslice(&dump, b"STACKMEMORY-keepme"),
            "the thread-stack stream (the backtrace memory) MUST be preserved"
        );
    }

    #[test]
    fn drops_full_memory_and_handle_and_maps_streams() {
        let heap = vec![0xEEu8; 64]; // a Memory64 (heap) blob
        let handles = b"\\Device\\NamedPipe\\jane-secret-doc".to_vec();
        let maps = b"/home/jane/.ssh/id_rsa r-xp".to_vec();
        let mut dump = build_minidump(&[
            (MDStreamType::Memory64ListStream as u32, heap),
            (MDStreamType::HandleDataStream as u32, handles),
            (MDStreamType::LinuxMaps as u32, maps),
            (MDStreamType::ThreadListStream as u32, b"threads".to_vec()),
        ]);
        let report = scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(report.streams_dropped, 3);
        assert!(!contains_subslice(&dump, b"jane-secret-doc"));
        assert!(!contains_subslice(&dump, b"id_rsa"));
        assert!(contains_subslice(&dump, b"threads"));
    }

    #[test]
    fn directory_entry_for_dropped_stream_is_neutralized() {
        let mut dump =
            build_minidump(&[(MDStreamType::LinuxEnviron as u32, b"USER=jane\0".to_vec())]);
        scrub_minidump_in_place(&mut dump).unwrap();
        // The single directory entry now reads sentinel type + empty location.
        let dir_off = HEADER_SIZE;
        assert_eq!(
            read_u32_le(&dump, dir_off).unwrap(),
            DROPPED_STREAM_SENTINEL
        );
        assert_eq!(read_u32_le(&dump, dir_off + 4).unwrap(), 0);
        assert_eq!(read_u32_le(&dump, dir_off + 8).unwrap(), 0);
    }

    #[test]
    fn coarsens_module_name_to_basename_and_zeros_pe_fields() {
        // Build a ModuleListStream payload: [count:u32=1][MINIDUMP_MODULE]
        // with a module_name_rva pointing at a UTF-16LE string later in the dump.
        let module_name = "C:\\Users\\jane\\AppData\\app.dll";
        let name_utf16: Vec<u8> = encode_utf16_lenprefixed(module_name);

        // The module entry has placeholder checksum + timestamp we expect zeroed.
        let mut module_entry = vec![0u8; MODULE_ENTRY_SIZE];
        write_u32_le(&mut module_entry, MODULE_CHECKSUM_OFFSET, 0xDEAD_BEEF);
        write_u32_le(
            &mut module_entry,
            MODULE_TIME_DATE_STAMP_OFFSET,
            0x1234_5678,
        );
        // module_name_rva is patched after we know the layout; placeholder now.

        let mut module_stream = Vec::new();
        module_stream.extend_from_slice(&1u32.to_le_bytes()); // count = 1
        module_stream.extend_from_slice(&module_entry);

        // Lay out: header + dir(2 entries: ModuleList, name-holder) + payloads.
        // Put the name string in a second stream so it has a real rva.
        let mut dump = build_minidump(&[
            (MDStreamType::ModuleListStream as u32, module_stream),
            (MDStreamType::ThreadNamesStream as u32, name_utf16.clone()),
        ]);

        // Patch module_name_rva to point at the name string's rva. The name
        // string is the SECOND stream's payload; find its rva from the directory.
        let dir_rva = HEADER_SIZE;
        let name_dir_off = dir_rva + DIRECTORY_ENTRY_SIZE; // second entry
        let name_rva = read_u32_le(&dump, name_dir_off + 8).unwrap();
        // The module entry lives at: module-stream rva + 4 (after the count).
        let module_stream_rva = read_u32_le(&dump, dir_rva + 8).unwrap() as usize;
        let module_entry_off = module_stream_rva + 4;
        write_u32_le(
            &mut dump,
            module_entry_off + MODULE_NAME_RVA_OFFSET,
            name_rva,
        );

        let report = scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(report.modules_coarsened, 1);

        // PE fingerprint fields are zeroed.
        assert_eq!(
            read_u32_le(&dump, module_entry_off + MODULE_CHECKSUM_OFFSET).unwrap(),
            0
        );
        assert_eq!(
            read_u32_le(&dump, module_entry_off + MODULE_TIME_DATE_STAMP_OFFSET).unwrap(),
            0
        );

        // The path prefix (username) is gone; the basename survives.
        let scrubbed_name = decode_utf16_lenprefixed(&dump, name_rva as usize);
        assert_eq!(scrubbed_name, "app.dll");
        assert!(!scrubbed_name.contains("jane"));
        assert!(!contains_utf16(&dump, "jane"));
    }

    #[test]
    fn out_of_bounds_directory_is_rejected_fail_closed() {
        let mut dump = build_minidump(&[(MDStreamType::ThreadListStream as u32, b"x".to_vec())]);
        // Corrupt the stream_count to claim more entries than the buffer holds.
        write_u32_le(&mut dump, 8, 9999);
        assert_eq!(
            scrub_minidump_in_place(&mut dump),
            Err(ScrubError::DirectoryOutOfBounds)
        );
    }

    #[test]
    fn every_declared_identifying_stream_is_classified() {
        for ty in [
            MDStreamType::LinuxEnviron,
            MDStreamType::LinuxCmdLine,
            MDStreamType::LinuxProcStatus,
            MDStreamType::LinuxMaps,
            MDStreamType::LinuxAuxv,
            MDStreamType::MozLinuxLimits,
            MDStreamType::Memory64ListStream,
            MDStreamType::MemoryInfoListStream,
            MDStreamType::HandleDataStream,
            MDStreamType::CommentStreamA,
            MDStreamType::CommentStreamW,
        ] {
            assert!(
                is_identifying_stream(ty as u32),
                "{ty:?} must be classified as an identifying stream to drop"
            );
        }
        // The keep-set is NOT identifying.
        for ty in [
            MDStreamType::ThreadListStream,
            MDStreamType::MemoryListStream, // thread stacks — kept
            MDStreamType::ModuleListStream, // coarsened, not dropped
            MDStreamType::ExceptionStream,
            MDStreamType::SystemInfoStream,
            MDStreamType::ThreadNamesStream,
        ] {
            assert!(
                !is_identifying_stream(ty as u32),
                "{ty:?} must NOT be dropped — it is needed to symbolicate"
            );
        }
    }

    // ---- test helpers ----

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn encode_utf16_lenprefixed(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let byte_len = (units.len() * 2) as u32;
        let mut out = byte_len.to_le_bytes().to_vec();
        for u in units {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    fn decode_utf16_lenprefixed(buf: &[u8], name_rva: usize) -> String {
        let byte_len = read_u32_le(buf, name_rva).unwrap() as usize;
        let units = byte_len / 2;
        let data_start = name_rva + 4;
        let mut code_units = Vec::with_capacity(units);
        for i in 0..units {
            let lo = buf[data_start + i * 2] as u16;
            let hi = buf[data_start + i * 2 + 1] as u16;
            let cu = lo | (hi << 8);
            if cu == 0 {
                break; // stop at the first zeroed (freed) unit.
            }
            code_units.push(cu);
        }
        String::from_utf16_lossy(&code_units)
    }

    fn contains_utf16(buf: &[u8], s: &str) -> bool {
        let needle: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        contains_subslice(buf, &needle)
    }

    // ---- ScrubError Display (scrub.rs 114-119) ----

    #[test]
    fn scrub_error_display_strings_are_distinct_and_descriptive() {
        assert_eq!(
            format!("{}", ScrubError::TooShort),
            "buffer too short for a minidump header"
        );
        assert_eq!(
            format!("{}", ScrubError::BadSignature),
            "not a minidump (bad signature)"
        );
        assert_eq!(
            format!("{}", ScrubError::DirectoryOutOfBounds),
            "minidump stream directory out of bounds"
        );
        // The error implements std::error::Error (source defaults to None).
        let e: &dyn std::error::Error = &ScrubError::TooShort;
        assert!(e.source().is_none());
    }

    /// A directory `rva` past the end of the buffer is rejected as
    /// `DirectoryOutOfBounds` (the `dir_end > buf.len()` guard), exercising the
    /// Display arm via a real parse error too.
    #[test]
    fn directory_rva_past_buffer_is_directory_out_of_bounds() {
        let mut dump = build_minidump(&[(MDStreamType::ThreadListStream as u32, b"x".to_vec())]);
        // Point the directory rva far past the buffer end.
        write_u32_le(&mut dump, 12, 1_000_000);
        let err = scrub_minidump_in_place(&mut dump).unwrap_err();
        assert_eq!(err, ScrubError::DirectoryOutOfBounds);
    }

    // ---- identifying-stream payload zeroing (scrub.rs 228-235) ----

    /// An identifying stream whose declared location is OUT OF BOUNDS is still
    /// neutralized at the directory level, but NO payload is zeroed (the
    /// in-bounds guard at 228-229 is false), so `bytes_zeroed` stays 0 while
    /// `streams_dropped` increments. This pins the in-bounds branch's negative
    /// arm.
    #[test]
    fn identifying_stream_with_oob_payload_is_neutralized_without_zeroing() {
        let mut dump =
            build_minidump(&[(MDStreamType::LinuxEnviron as u32, b"USER=jane\0".to_vec())]);
        // Corrupt the single entry's rva to point past the buffer; keep its
        // data_size non-zero so the `checked_add` succeeds but `end > buf.len()`.
        let dir_off = HEADER_SIZE;
        write_u32_le(&mut dump, dir_off + 8, 1_000_000); // rva far past end
        let report = scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(report.streams_dropped, 1);
        assert_eq!(
            report.bytes_zeroed, 0,
            "an out-of-bounds payload location must not zero any bytes"
        );
        // The directory entry is still neutralized to the sentinel.
        assert_eq!(
            read_u32_le(&dump, dir_off).unwrap(),
            DROPPED_STREAM_SENTINEL
        );
    }

    // ---- coarsen_module_list guards (scrub.rs 266-287) ----

    /// A `ModuleListStream` shorter than the 4-byte count header (`data_size < 4`)
    /// coarsens ZERO modules (the early `data_size < 4` return at scrub.rs 269).
    #[test]
    fn module_list_too_short_for_count_coarsens_nothing() {
        let mut dump = build_minidump(&[(MDStreamType::ModuleListStream as u32, vec![0u8, 0, 0])]); // 3 bytes < 4
        let report = scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(report.modules_coarsened, 0);
    }

    /// A `ModuleListStream` whose count claims more fixed-size module entries
    /// than the stream actually holds breaks out of the per-entry loop at the
    /// first entry that would read past the buffer (scrub.rs 286-287), coarsening
    /// zero modules.
    #[test]
    fn module_list_with_truncated_entry_breaks_without_coarsening() {
        // count = 1, but no room for a full 108-byte MINIDUMP_MODULE after it.
        let mut stream = Vec::new();
        stream.extend_from_slice(&1u32.to_le_bytes());
        stream.extend_from_slice(&[0u8; 10]); // far short of MODULE_ENTRY_SIZE
        let mut dump = build_minidump(&[(MDStreamType::ModuleListStream as u32, stream)]);
        let report = scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(
            report.modules_coarsened, 0,
            "a truncated module entry must break the loop, coarsening nothing"
        );
    }

    /// A `ModuleListStream` with `count == 0` coarsens nothing but is still
    /// counted as a module-list stream (the loop body never runs).
    #[test]
    fn module_list_with_zero_count_coarsens_nothing() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&0u32.to_le_bytes()); // count = 0
        let mut dump = build_minidump(&[(MDStreamType::ModuleListStream as u32, stream)]);
        let report = scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(report.modules_coarsened, 0);
    }

    // ---- coarsen_module_name_to_basename guards (scrub.rs 310-342) ----

    /// Helper: build a dump with one module whose name_rva points at the supplied
    /// length-prefixed UTF-16 name bytes (placed in a second stream), returning
    /// the dump + the name string's rva so a test can assert on the result.
    fn dump_with_module_name(name_bytes: Vec<u8>) -> (Vec<u8>, usize) {
        let mut module_entry = vec![0u8; MODULE_ENTRY_SIZE];
        write_u32_le(&mut module_entry, MODULE_CHECKSUM_OFFSET, 0xDEAD_BEEF);
        let mut module_stream = Vec::new();
        module_stream.extend_from_slice(&1u32.to_le_bytes()); // count = 1
        module_stream.extend_from_slice(&module_entry);

        let mut dump = build_minidump(&[
            (MDStreamType::ModuleListStream as u32, module_stream),
            (MDStreamType::ThreadNamesStream as u32, name_bytes),
        ]);
        let dir_rva = HEADER_SIZE;
        let name_dir_off = dir_rva + DIRECTORY_ENTRY_SIZE;
        let name_rva = read_u32_le(&dump, name_dir_off + 8).unwrap() as usize;
        let module_stream_rva = read_u32_le(&dump, dir_rva + 8).unwrap() as usize;
        let module_entry_off = module_stream_rva + 4;
        write_u32_le(
            &mut dump,
            module_entry_off + MODULE_NAME_RVA_OFFSET,
            name_rva as u32,
        );
        (dump, name_rva)
    }

    /// A module name with `byte_len == 0` is left untouched (scrub.rs 315): the
    /// module is still counted coarsened (PE fields zeroed) but the empty name
    /// short-circuits before any shift.
    #[test]
    fn module_name_zero_length_is_left_untouched() {
        let name_bytes = 0u32.to_le_bytes().to_vec(); // byte_len = 0, no units
        let (mut dump, name_rva) = dump_with_module_name(name_bytes);
        let report = scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(report.modules_coarsened, 1);
        assert_eq!(read_u32_le(&dump, name_rva).unwrap(), 0, "byte_len stays 0");
    }

    /// A module name with an ODD `byte_len` (not a whole number of UTF-16 code
    /// units) is left untouched (scrub.rs 315 `byte_len % 2 != 0`).
    #[test]
    fn module_name_odd_byte_len_is_left_untouched() {
        let mut name_bytes = 3u32.to_le_bytes().to_vec(); // odd byte_len = 3
        name_bytes.extend_from_slice(&[b'a', 0, b'b']); // 3 trailing bytes
        let (mut dump, name_rva) = dump_with_module_name(name_bytes);
        let report = scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(report.modules_coarsened, 1);
        // The odd-length name field is unchanged (byte_len still 3).
        assert_eq!(read_u32_le(&dump, name_rva).unwrap(), 3);
    }

    /// A module name whose declared `byte_len` runs PAST the end of the buffer is
    /// left untouched (scrub.rs 323 `data_end > buf.len()`): no shift, no panic.
    #[test]
    fn module_name_out_of_bounds_length_is_left_untouched() {
        // byte_len claims 1000 bytes but only a few follow.
        let mut name_bytes = 1000u32.to_le_bytes().to_vec();
        name_bytes.extend_from_slice(&[b'a', 0, b'b', 0]); // a tiny real tail
        let (mut dump, _name_rva) = dump_with_module_name(name_bytes);
        // Must not panic; the OOB name is skipped.
        let report = scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(report.modules_coarsened, 1);
    }

    /// A module whose `module_name_rva` points so close to the END of the buffer
    /// that the 4-byte length prefix cannot even be read makes `read_u32_le`
    /// return `None` (the early-return arm of `coarsen_module_name_to_basename`):
    /// the name is left untouched, no panic, and the module is still counted as
    /// coarsened (its PE fields were zeroed before the name step).
    #[test]
    fn module_name_rva_with_unreadable_length_prefix_is_left_untouched() {
        let mut module_entry = vec![0u8; MODULE_ENTRY_SIZE];
        write_u32_le(&mut module_entry, MODULE_CHECKSUM_OFFSET, 0xDEAD_BEEF);
        let mut module_stream = Vec::new();
        module_stream.extend_from_slice(&1u32.to_le_bytes()); // count = 1
        module_stream.extend_from_slice(&module_entry);
        let mut dump = build_minidump(&[(MDStreamType::ModuleListStream as u32, module_stream)]);

        // Point module_name_rva at `buf.len() - 2` so a 4-byte read is OOB.
        let dir_rva = HEADER_SIZE;
        let module_stream_rva = read_u32_le(&dump, dir_rva + 8).unwrap() as usize;
        let module_entry_off = module_stream_rva + 4;
        let oob_name_rva = (dump.len() - 2) as u32;
        write_u32_le(
            &mut dump,
            module_entry_off + MODULE_NAME_RVA_OFFSET,
            oob_name_rva,
        );

        // Must not panic; the unreadable name is skipped, the module still
        // counts as coarsened (PE fingerprint fields were zeroed).
        let report = scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(report.modules_coarsened, 1);
        assert_eq!(
            read_u32_le(&dump, module_entry_off + MODULE_CHECKSUM_OFFSET).unwrap(),
            0
        );
    }

    /// A module name with NO path separator is already a basename and is left
    /// unchanged (scrub.rs 338 `last_sep == None`).
    #[test]
    fn module_name_without_separator_is_unchanged() {
        let name_bytes = encode_utf16_lenprefixed("app.dll"); // no '/' or '\\'
        let (mut dump, name_rva) = dump_with_module_name(name_bytes);
        scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(decode_utf16_lenprefixed(&dump, name_rva), "app.dll");
    }

    /// A module name ENDING in a path separator (`base_start_unit >= units`) is
    /// left as-is (scrub.rs 342 trailing-separator guard).
    #[test]
    fn module_name_with_trailing_separator_is_left_as_is() {
        let name_bytes = encode_utf16_lenprefixed("C:\\Users\\jane\\"); // trailing '\\'
        let (mut dump, name_rva) = dump_with_module_name(name_bytes);
        scrub_minidump_in_place(&mut dump).unwrap();
        // Unchanged: the trailing-separator case does not shift.
        assert_eq!(
            decode_utf16_lenprefixed(&dump, name_rva),
            "C:\\Users\\jane\\"
        );
    }

    /// A forward-slash separated path coarsens to its basename too (the `/` arm
    /// of the separator match), complementing the existing back-slash test.
    #[test]
    fn module_name_forward_slash_path_coarsens_to_basename() {
        let name_bytes = encode_utf16_lenprefixed("/usr/lib/jane/libfoo.so");
        let (mut dump, name_rva) = dump_with_module_name(name_bytes);
        scrub_minidump_in_place(&mut dump).unwrap();
        assert_eq!(decode_utf16_lenprefixed(&dump, name_rva), "libfoo.so");
        assert!(!contains_utf16(&dump, "jane"));
    }
}
