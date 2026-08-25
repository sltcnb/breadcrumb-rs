//! Windows artefacts that record when a file was deleted.
//!
//! NTFS itself has no deletion timestamp: `$STANDARD_INFORMATION` carries
//! created, modified, changed and accessed, and the record's change time is
//! only a proxy for when the file went away. Two artefacts record it directly:
//!
//! - `$Recycle.Bin/$I*` — one per Explorer-deleted file: deletion time,
//!   original size and the full original path
//! - `$Extend/$UsnJrnl:$J` — the change journal, with an explicit
//!   `FILE_DELETE` reason and a timestamp per record
//!
//! Both are parsed here so a timeline can say when something was deleted
//! instead of inferring it.

use std::fmt::Write as _;

/// USN change reasons (winioctl.h). Only the ones a timeline cares about are
/// named; anything left over is reported as its hex value.
pub const USN_REASONS: &[(u32, &str)] = &[
    (0x0000_0001, "data-overwrite"),
    (0x0000_0002, "data-extend"),
    (0x0000_0004, "data-truncation"),
    (0x0000_0010, "named-data-overwrite"),
    (0x0000_0020, "named-data-extend"),
    (0x0000_0040, "named-data-truncation"),
    (0x0000_0100, "file-create"),
    (0x0000_0200, "file-delete"),
    (0x0000_0400, "ea-change"),
    (0x0000_0800, "security-change"),
    (0x0000_1000, "rename-old-name"),
    (0x0000_2000, "rename-new-name"),
    (0x0000_4000, "indexable-change"),
    (0x0000_8000, "basic-info-change"),
    (0x0001_0000, "hard-link-change"),
    (0x0002_0000, "compression-change"),
    (0x0004_0000, "encryption-change"),
    (0x0008_0000, "object-id-change"),
    (0x0010_0000, "reparse-point-change"),
    (0x0020_0000, "stream-change"),
    (0x0040_0000, "transacted-change"),
    (0x0080_0000, "integrity-change"),
    (0x8000_0000, "close"),
];

pub const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;

const FILETIME_EPOCH_SECS: u64 = 11_644_473_600;

fn u16le(b: &[u8], o: usize) -> u64 {
    if o + 2 > b.len() {
        return 0;
    }
    u16::from_le_bytes([b[o], b[o + 1]]) as u64
}

fn u32le(b: &[u8], o: usize) -> u64 {
    if o + 4 > b.len() {
        return 0;
    }
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as u64
}

fn u64le(b: &[u8], o: usize) -> u64 {
    if o + 8 > b.len() {
        return 0;
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

/// Windows FILETIME (100 ns units since 1601) as a Unix timestamp.
pub fn filetime_to_unix(ft: u64) -> u64 {
    if ft == 0 {
        return 0;
    }
    (ft / 10_000_000).saturating_sub(FILETIME_EPOCH_SECS)
}

/// A reason bitmask as a readable, stable string.
pub fn describe_reasons(reason: u32) -> String {
    let mut names: Vec<&str> = Vec::new();
    let mut known = 0u32;
    for &(bit, name) in USN_REASONS {
        known |= bit;
        if reason & bit != 0 {
            names.push(name);
        }
    }
    let mut out = names.join("|");
    let left = reason & !known;
    if left != 0 {
        if !out.is_empty() {
            out.push('|');
        }
        let _ = write!(out, "{left:#010x}");
    }
    if out.is_empty() {
        "none".into()
    } else {
        out
    }
}

// ------------------------------------------------------- $Recycle.Bin/$I

#[derive(Debug, Clone)]
pub struct RecycleEntry {
    /// Unix seconds.
    pub deleted: u64,
    /// Original file size in bytes.
    pub size: u64,
    /// Original full path.
    pub path: String,
    pub version: u64,
}

fn utf16_string(raw: &[u8]) -> String {
    let mut units = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

/// Parse one `$I` record from the recycle bin.
///
/// Version 1 (Vista..8.1) stores the original path as a fixed 260-character
/// field; version 2 (Windows 10+) precedes it with a character count. Anything
/// else, or a record whose path runs past the end, is refused rather than
/// guessed at.
pub fn parse_recycle_i(data: &[u8]) -> Option<RecycleEntry> {
    if data.len() < 24 {
        return None;
    }
    let version = u64le(data, 0);
    let size = u64le(data, 8);
    let deleted = filetime_to_unix(u64le(data, 16));
    let raw: &[u8] = match version {
        1 => {
            let end = (24 + 520).min(data.len());
            &data[24..end]
        }
        2 => {
            if data.len() < 28 {
                return None;
            }
            let chars = u32le(data, 24) as usize;
            if !(1..=32768).contains(&chars) {
                return None;
            }
            let end = 28usize.checked_add(chars.checked_mul(2)?)?;
            if end > data.len() {
                return None;
            }
            &data[28..end]
        }
        _ => return None,
    };
    let path = utf16_string(raw);
    if path.is_empty() {
        return None;
    }
    Some(RecycleEntry {
        deleted,
        size,
        path,
        version,
    })
}

// --------------------------------------------------- $Extend/$UsnJrnl:$J

#[derive(Debug, Clone)]
pub struct UsnRecord {
    pub usn: u64,
    /// Unix seconds.
    pub timestamp: u64,
    pub reason: u32,
    pub name: String,
    /// MFT reference; the low 48 bits are the record number.
    pub file_ref: u64,
    pub parent_ref: u64,
    pub version: (u16, u16),
}

impl UsnRecord {
    pub fn mft_record(&self) -> u64 {
        self.file_ref & 0x0000_FFFF_FFFF_FFFF
    }

    pub fn deleted(&self) -> bool {
        self.reason & USN_REASON_FILE_DELETE != 0
    }
}

/// One record's declared length, if a record plausibly starts at `pos`.
///
/// The journal has no magic number, so this is the only handle on where a
/// record begins: a length inside the possible range, a version the format
/// defines, and a name that fits inside the record it belongs to.
fn record_length(data: &[u8], pos: usize) -> Option<usize> {
    let length = u32le(data, pos) as usize;
    if !(56..=1024).contains(&length) {
        return None;
    }
    let major = u16le(data, pos + 4);
    if !(major == 2 || major == 3) || u16le(data, pos + 6) != 0 {
        return None;
    }
    let head = if major == 2 { 24 } else { 40 };
    let name_len = u16le(data, pos + head + 32) as usize;
    let name_off = u16le(data, pos + head + 34) as usize;
    if name_len == 0 || name_len % 2 != 0 || name_off < head + 36 || name_off + name_len > length {
        return None;
    }
    Some(length)
}

/// Parse USN records from a `$J` stream.
///
/// The journal is a sparse file that usually opens with a large hole, and a
/// carved copy can begin anywhere inside a record, so this steps over zero runs
/// and hunts for the next plausible record rather than giving up at the first
/// bad length. The hunt is byte-by-byte on purpose: a stream that starts at an
/// odd offset never lines up with the record grid, so stepping in 8-byte units
/// would walk past every record in it. V2 records carry 64-bit file references,
/// V3 128-bit ones.
///
/// The return value is how many bytes were consumed to a record boundary, so a
/// caller feeding the journal in blocks can carry the remainder forward. A
/// return of 0 means no boundary was reached: keep the block and read more.
pub fn parse_usn_journal(data: &[u8], out: &mut Vec<UsnRecord>) -> usize {
    let mut pos = 0usize;
    let end = data.len();
    let mut boundary = 0usize;
    while pos + 60 <= end {
        // Sparse hole, or the padding at the end of a record: skip it whole.
        if data[pos..pos + 8].iter().all(|&b| b == 0) {
            pos += 8;
            boundary = pos;
            continue;
        }
        let Some(length) = record_length(data, pos) else {
            pos += 1; // not a record start: hunt for the next one
            continue;
        };
        if pos + length > end {
            // A plausible record cut off by the end of this block: leave it for
            // the next one rather than half-parsing it.
            break;
        }
        let major = u16le(data, pos + 4) as u16;
        let minor = u16le(data, pos + 6) as u16;
        let (file_ref, parent_ref, head) = if major == 2 {
            (u64le(data, pos + 8), u64le(data, pos + 16), 24usize)
        } else {
            // V3 uses 128-bit references; the low 64 bits hold the record.
            (u64le(data, pos + 8), u64le(data, pos + 24), 40usize)
        };
        let usn = u64le(data, pos + head);
        let timestamp = filetime_to_unix(u64le(data, pos + head + 8));
        let reason = u32le(data, pos + head + 16) as u32;
        // From the Usn field: timestamp +8, reason +16, source info +20,
        // security id +24, attributes +28, name length +32, name offset +34.
        let name_len = u16le(data, pos + head + 32) as usize;
        let name_off = u16le(data, pos + head + 34) as usize;
        let name = utf16_string(&data[pos + name_off..pos + name_off + name_len]);
        out.push(UsnRecord {
            usn,
            timestamp,
            reason,
            name,
            file_ref,
            parent_ref,
            version: (major, minor),
        });
        pos += length;
        boundary = pos;
    }
    boundary
}

// ------------------------------------------------------------- reporting

#[derive(Debug, Clone)]
pub struct DeletionEvent {
    /// Unix seconds.
    pub when: u64,
    /// `$I` or `$UsnJrnl`.
    pub source: &'static str,
    /// File name, or the original full path for `$I`.
    pub name: String,
    pub size: u64,
    /// Reason flags, or the `$I` version.
    pub detail: String,
}

pub fn events_from_recycle(data: &[u8], label: &str) -> Vec<DeletionEvent> {
    match parse_recycle_i(data) {
        None => Vec::new(),
        Some(e) => vec![DeletionEvent {
            when: e.deleted,
            source: "$I",
            name: e.path,
            size: e.size,
            detail: if label.is_empty() {
                format!("v{}", e.version)
            } else {
                format!("v{} {label}", e.version)
            },
        }],
    }
}

pub fn events_from_usn(data: &[u8], deletions_only: bool) -> Vec<DeletionEvent> {
    let mut recs = Vec::new();
    parse_usn_journal(data, &mut recs);
    recs.into_iter()
        .filter(|r| !deletions_only || r.deleted())
        .map(|r| {
            let detail = format!("mft {} {}", r.mft_record(), describe_reasons(r.reason));
            DeletionEvent {
                when: r.timestamp,
                source: "$UsnJrnl",
                name: r.name,
                size: 0,
                detail,
            }
        })
        .collect()
}

fn iso_utc(unix: u64) -> String {
    if unix == 0 {
        return String::new();
    }
    // Days since the epoch to a civil date (Howard Hinnant's algorithm).
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Write deletion events sorted oldest first. Returns the row count.
pub fn write_events_csv(events: &[DeletionEvent], path: &str) -> std::io::Result<usize> {
    let mut rows: Vec<&DeletionEvent> = events.iter().collect();
    rows.sort_by(|a, b| a.when.cmp(&b.when).then_with(|| a.name.cmp(&b.name)));
    let mut buf = String::from("deleted_utc,unix,source,name,size,detail\n");
    for e in &rows {
        let _ = writeln!(
            buf,
            "{},{},{},{},{},{}",
            iso_utc(e.when),
            e.when,
            e.source,
            csv_field(&e.name),
            e.size,
            csv_field(&e.detail)
        );
    }
    std::fs::write(path, buf)?;
    Ok(rows.len())
}

/// Find `$I` records and `$UsnJrnl` streams in a directory tree.
///
/// Point this at an `--ntfs` output tree, or at a folder of files pulled off a
/// live machine: the artefacts keep their names, so they can be found.
pub fn scan_tree(root: &str, deletions_only: bool) -> Vec<DeletionEvent> {
    let mut events = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(root)];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let low = name.to_lowercase();
            if low.starts_with("$i") && name.len() > 2 {
                if let Ok(data) = std::fs::read(&path) {
                    events.extend(events_from_recycle(&data[..data.len().min(4096)], &name));
                }
            } else if low.contains("usnjrnl") {
                if let Ok(data) = std::fs::read(&path) {
                    events.extend(events_from_usn(&data, deletions_only));
                }
            }
        }
    }
    events
}
