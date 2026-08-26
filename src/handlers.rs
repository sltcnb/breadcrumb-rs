//! Per-type carving handlers, ported from BreadCrumb's `handlers.py`.
//!
//! Each handler receives a `Window` based at the candidate header and returns
//! `Some(Carve)` or `None` to reject the candidate. `validated` means the
//! structure parsed cleanly to a definite end; `false` means a best-effort
//! size that may carry junk at the tail.

use crate::window::Window;

pub struct Carve {
    pub size: u64,
    pub ext: &'static str,
    pub validated: bool,
}

fn carve(size: u64, ext: &'static str, validated: bool) -> Option<Carve> {
    Some(Carve {
        size,
        ext,
        validated,
    })
}

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
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}
fn u16be(b: &[u8], o: usize) -> u64 {
    if o + 2 > b.len() {
        return 0;
    }
    u16::from_be_bytes([b[o], b[o + 1]]) as u64
}
fn u32be(b: &[u8], o: usize) -> u64 {
    if o + 4 > b.len() {
        return 0;
    }
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as u64
}
fn u64be(b: &[u8], o: usize) -> u64 {
    if o + 8 > b.len() {
        return 0;
    }
    u64::from_be_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

// ------------------------------------------------------------------- JPEG

pub fn carve_jpeg(w: &mut Window) -> Option<Carve> {
    let mut pos: u64 = 2;
    while pos < w.limit {
        let hdr = w.read(pos, 4);
        if hdr.len() < 2 || hdr[0] != 0xFF {
            return None;
        }
        let marker = hdr[1];
        if marker == 0xD9 {
            return carve(pos + 2, "jpg", true);
        }
        if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            pos += 2;
            continue;
        }
        if marker == 0xFF {
            pos += 1;
            continue;
        }
        if hdr.len() < 4 {
            return None;
        }
        let seglen = u16be(&hdr, 2);
        if seglen < 2 {
            return None;
        }
        if marker == 0xDA {
            // SOS: walk the entropy-coded scan looking for the next real marker
            pos += 2 + seglen;
            loop {
                let idx = w.find(b"\xff", pos, None)?;
                let nxt = w.read(idx + 1, 1);
                if nxt.is_empty() {
                    return None;
                }
                let b = nxt[0];
                if b == 0xD9 {
                    return carve(idx + 2, "jpg", true);
                }
                if b == 0x00 || (0xD0..=0xD7).contains(&b) {
                    pos = idx + 2;
                    continue;
                }
                if b == 0xFF {
                    pos = idx + 1;
                    continue;
                }
                pos = idx; // real marker: resume the segment walk
                break;
            }
            continue;
        }
        pos += 2 + seglen;
    }
    None
}

// -------------------------------------------------------------------- PNG

pub fn carve_png(w: &mut Window) -> Option<Carve> {
    let mut pos: u64 = 8;
    while pos + 12 <= w.limit {
        let h = w.exact(pos, 8)?;
        let length = u32be(&h, 0);
        let ctype = &h[4..8];
        let type_ok = ctype
            .iter()
            .all(|&c| (0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c));
        if length > 0x7FFF_FFFF || !type_ok {
            return None;
        }
        pos = pos.saturating_add(12).saturating_add(length);
        if pos > w.limit {
            return None; // a chunk length that runs off the end: truncated
        }
        if ctype == b"IEND" {
            return carve(pos, "png", true);
        }
    }
    None
}

// -------------------------------------------------------------------- GIF

pub fn carve_gif(w: &mut Window) -> Option<Carve> {
    let head = w.exact(0, 13)?;
    let mut pos: u64 = 13;
    let packed = head[10];
    if packed & 0x80 != 0 {
        pos = pos.saturating_add(3u64.saturating_mul(2u64 << (packed & 0x07)));
    }

    fn skip_subblocks(w: &mut Window, mut p: u64) -> Option<u64> {
        loop {
            let sz = w.read(p, 1);
            if sz.is_empty() {
                return None;
            }
            p += 1;
            if sz[0] == 0 {
                return Some(p);
            }
            p += sz[0] as u64;
        }
    }

    while pos < w.limit {
        let b = w.read(pos, 1);
        if b.is_empty() {
            return None;
        }
        let tag = b[0];
        pos += 1;
        if tag == 0x3B {
            return carve(pos, "gif", true);
        }
        if tag == 0x21 {
            pos = skip_subblocks(w, pos + 1)?;
        } else if tag == 0x2C {
            let desc = w.exact(pos, 9)?;
            pos += 9;
            if desc[8] & 0x80 != 0 {
                pos = pos.saturating_add(3u64.saturating_mul(2u64 << (desc[8] & 0x07)));
            }
            pos += 1; // LZW minimum code size
            pos = skip_subblocks(w, pos)?;
        } else {
            return None;
        }
    }
    None
}

// -------------------------------------------------------------------- BMP

pub fn carve_bmp(w: &mut Window) -> Option<Carve> {
    let h = w.exact(0, 26)?;
    if &h[..2] != b"BM" {
        return None;
    }
    let size = u32le(&h, 2);
    if !(26..=w.limit).contains(&size) {
        return None;
    }
    if !matches!(u32le(&h, 14), 12 | 40 | 52 | 56 | 64 | 108 | 124) {
        return None;
    }
    let data_off = u32le(&h, 10);
    if !(26..=size).contains(&data_off) {
        return None;
    }
    carve(size, "bmp", true)
}

// -------------------------------------------------------------------- TIFF

fn tiff_type_size(t: u64) -> Option<u64> {
    Some(match t {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 | 13 => 4,
        5 | 10 | 12 | 16 | 17 | 18 => 8,
        _ => return None,
    })
}

pub fn carve_tiff(w: &mut Window) -> Option<Carve> {
    let h = w.exact(0, 8)?;
    let le = match &h[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let g16 = |b: &[u8], o: usize| if le { u16le(b, o) } else { u16be(b, o) };
    let g32 = |b: &[u8], o: usize| if le { u32le(b, o) } else { u32be(b, o) };

    let mut end: u64 = 8;
    let mut ifd = g32(&h, 4);
    let mut seen: Vec<u64> = Vec::new();
    while ifd != 0 && !seen.contains(&ifd) {
        seen.push(ifd);
        let nb = w.exact(ifd, 2)?;
        let n = g16(&nb, 0);
        if n == 0 || n > 4096 {
            return None;
        }
        let table = w.exact(ifd + 2, (n * 12 + 4) as usize)?;
        end = end.max(
            ifd.saturating_add(2)
                .saturating_add(n.saturating_mul(12))
                .saturating_add(4),
        );
        let mut offsets: Vec<u64> = Vec::new();
        let mut counts: Vec<u64> = Vec::new();
        for i in 0..n as usize {
            let e = &table[i * 12..(i + 1) * 12];
            let tag = g16(e, 0);
            let typ = g16(e, 2);
            let cnt = g32(e, 4);
            let tsz = match tiff_type_size(typ) {
                Some(s) => s,
                None => continue,
            };
            let total = tsz.saturating_mul(cnt);
            if total > 4 {
                end = end.max(g32(e, 8).saturating_add(total));
            }
            if tag == 273 || tag == 324 || tag == 279 || tag == 325 {
                // SHORT/LONG values, inline when they fit in the 4-byte field
                if typ != 3 && typ != 4 {
                    continue;
                }
                let raw = if total <= 4 {
                    e[8..8 + total as usize].to_vec()
                } else {
                    match w.exact(g32(e, 8), total as usize) {
                        Some(v) => v,
                        None => continue,
                    }
                };
                let vals: Vec<u64> = (0..cnt as usize)
                    .map(|k| {
                        if typ == 3 {
                            g16(&raw, k * 2)
                        } else {
                            g32(&raw, k * 4)
                        }
                    })
                    .collect();
                if tag == 273 || tag == 324 {
                    offsets = vals;
                } else {
                    counts = vals;
                }
            }
        }
        for (o, c) in offsets.iter().zip(counts.iter()) {
            end = end.max(o.saturating_add(*c));
        }
        ifd = g32(&table, (n * 12) as usize);
    }
    if end <= 8 || end > w.limit {
        return None;
    }
    carve(end, "tif", true)
}

// -------------------------------------------------------------------- PDF

pub fn carve_pdf(w: &mut Window) -> Option<Carve> {
    // Bound the search at the next PDF header, if any, to avoid merging files.
    let horizon = w.find(b"%PDF-", 5, None);
    let end_limit = horizon.filter(|&h| h > 0).unwrap_or(w.limit);

    // Every `%%EOF` in the window is a candidate end, newest first. The last one
    // is usually right -- a PDF revised in place has several -- but not always:
    // on a live scan the last one belonged to unrelated data further along and
    // produced a 23 MB "PDF" whose cross-reference table sat at 1.8 MB. A real
    // end is one the document agrees with, so each candidate is checked against
    // the startxref that precedes it.
    let mut candidates: Vec<u64> = Vec::new();
    let mut at = 0u64;
    while let Some(found) = w.find(b"%%EOF", at, Some(end_limit)) {
        candidates.push(found);
        at = found + 5;
        // Enough to cover a document's revision history without walking a
        // window full of stray matches.
        if candidates.len() >= 32 {
            break;
        }
    }
    let last = *candidates.last()?;
    let consistent = candidates
        .iter()
        .rev()
        .find(|&&eof| pdf_end_is_consistent(w, eof));
    let (eof, validated) = match consistent {
        Some(&eof) => (eof, true),
        // Nothing self-consistent: keep the last one, but do not call it
        // verified. A PDF whose middle was overwritten looks like this.
        None => (last, false),
    };

    let mut end = eof + 5;
    // Take the single line terminator that ends the %%EOF line -- CRLF, or a
    // bare CR/LF. Consuming every EOL byte here also swallows trailing data
    // that merely happens to start with one.
    let tail = w.read(end, 2);
    if tail.len() >= 2 && &tail[..2] == b"\r\n" {
        end += 2;
    } else if !tail.is_empty() && (tail[0] == b'\r' || tail[0] == b'\n') {
        end += 1;
    }
    carve(end, "pdf", validated)
}

/// Does the `startxref` before this `%%EOF` point at something real?
///
/// The offset is from the start of the file, so on a correctly bounded carve it
/// lands on the cross-reference table or on an object. If it points past the
/// end, or at neither, this `%%EOF` is not this document's end -- or the
/// document is damaged.
fn pdf_end_is_consistent(w: &mut Window, eof: u64) -> bool {
    // startxref, its offset, and the line endings all fit comfortably here.
    let back = eof.min(64);
    let tail = w.read(eof - back, back as usize);
    let Some(at) = crate::window::find_sub(&tail, b"startxref") else {
        return false;
    };
    let digits: Vec<u8> = tail[at + 9..]
        .iter()
        .copied()
        .skip_while(|b| b.is_ascii_whitespace())
        .take_while(|b| b.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return false; // a NUL or nothing where the offset should be
    }
    let Ok(text) = std::str::from_utf8(&digits) else {
        return false;
    };
    let Ok(off) = text.parse::<u64>() else {
        return false;
    };
    if off == 0 || off >= eof {
        return false;
    }
    let there = w.read(off, 24);
    // Either the classic table, or a cross-reference stream object.
    there.starts_with(b"xref") || crate::window::find_sub(&there, b"obj").is_some_and(|i| i <= 12)
}

// -------------------------------------------------------------------- RTF

/// RTF ends where its outermost group closes.
///
/// Brace counting, with two wrinkles that matter on real documents: a
/// backslash escapes the next byte (`\{` is a literal brace), and `\binN`
/// introduces N raw bytes that must be skipped whole -- embedded objects
/// routinely contain unbalanced braces.
pub fn carve_rtf(w: &mut Window) -> Option<Carve> {
    if w.read(0, 5) != b"{\\rtf" {
        return None;
    }
    let mut pos: u64 = 0;
    let mut depth: i64 = 0;
    while pos < w.limit {
        let buf = w.read(pos, 1 << 16);
        if buf.is_empty() {
            break;
        }
        let mut i = 0usize;
        let mut jumped = false;
        while i < buf.len() {
            match buf[i] {
                0x5C => {
                    // \binN<space> => skip N bytes of raw data
                    let tail = &buf[i..(i + 24).min(buf.len())];
                    if tail.len() > 4 && &tail[1..4] == b"bin" {
                        let mut j = 4usize;
                        let mut digits = String::new();
                        while j < tail.len() && tail[j].is_ascii_digit() {
                            digits.push(tail[j] as char);
                            j += 1;
                        }
                        if let Ok(skip) = digits.parse::<u64>() {
                            if tail.get(j) == Some(&b' ') {
                                j += 1;
                            }
                            pos += i as u64 + j as u64 + skip;
                            jumped = true;
                            break; // re-read from the new position
                        }
                    }
                    i += 2; // ordinary escape
                }
                0x7B => {
                    depth += 1;
                    i += 1;
                }
                0x7D => {
                    depth -= 1;
                    if depth == 0 {
                        return carve(pos + i as u64 + 1, "rtf", true);
                    }
                    i += 1;
                }
                _ => i += 1,
            }
        }
        if !jumped {
            pos += buf.len() as u64;
        }
    }
    None
}

// -------------------------------------------------------------- OLE2 / CFB

/// Stream names that identify what an OLE2 container actually holds, as they
/// appear in the directory: UTF-16LE. Order matters -- an .msg carries a
/// Workbook-shaped attachment often enough that Outlook is tested first.
const OLE_HINTS: &[(&str, &str)] = &[
    ("__substg1.0_", "msg"),
    ("__properties_version1.0", "msg"),
    ("VisioDocument", "vsd"),
    ("WordDocument", "doc"),
    ("Workbook", "xls"),
    ("Book", "xls"),
    ("PowerPoint Document", "ppt"),
];

/// Root-entry CLSIDs, the authoritative statement of what an OLE2 file is.
/// GUID bytes are Data1/2/3 little-endian then Data4 big-endian, e.g.
/// {00020820-0000-0000-C000-000000000046} -> 2008020000000000c000000000000046.
const OLE_CLSIDS: &[([u8; 16], &str)] = &[
    (hex16(0x0002_0906), "doc"), // Word 8+
    (hex16(0x0002_0900), "doc"), // Word 6/7
    (hex16(0x0002_0820), "xls"), // Excel Book8
    (hex16(0x0002_0810), "xls"), // Excel Book5
    (hex16(0x0002_1A13), "vsd"), // Visio
    (hex16(0x0002_1A20), "vsd"),
    (hex16(0x0002_123D), "pub"), // Publisher
    (hex16(0x0002_0D0B), "msg"), // Outlook message
    (hex16(0x000C_1084), "msi"), // Windows Installer
    (hex16(0x000C_1086), "msp"), // installer patch
    (hex16(0x000C_1082), "mst"), // installer transform
    // PowerPoint uses a different Data2/3/4 triplet.
    (
        [
            0x10, 0x8D, 0x81, 0x64, 0x9B, 0x4F, 0xCF, 0x11, 0x86, 0xEA, 0x00, 0xAA, 0x00, 0xB9,
            0x29, 0xE8,
        ],
        "ppt",
    ),
    (
        [
            0x11, 0x8D, 0x81, 0x64, 0x9B, 0x4F, 0xCF, 0x11, 0x86, 0xEA, 0x00, 0xAA, 0x00, 0xB9,
            0x29, 0xE8,
        ],
        "ppt",
    ),
];

/// A {xxxxxxxx-0000-0000-C000-000000000046} CLSID, the shape Microsoft uses for
/// most Office class ids, in on-disk byte order.
const fn hex16(data1: u32) -> [u8; 16] {
    let b = data1.to_le_bytes();
    [
        b[0], b[1], b[2], b[3], 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
    ]
}

const FREESECT: u64 = 0xFFFF_FFFF;
const ENDOFCHAIN: u64 = 0xFFFF_FFFE;

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

pub fn carve_ole(w: &mut Window) -> Option<Carve> {
    let h = w.exact(0, 512)?;
    let shift = u16le(&h, 30);
    if shift != 9 && shift != 12 {
        return None;
    }
    let sector: u64 = 1 << shift;
    let per_sector = (sector / 4) as usize;

    // Every OLE file's directory begins with an entry named "Root Entry". A
    // D0CF11E0 signature without one is not the start of a file: it is an
    // embedded object inside another document, or a coincidence. On a live scan
    // four of fifteen carved OLE files were exactly that -- structurally
    // plausible, and unopenable.
    let dir_sect = u32le(&h, 48);
    if dir_sect == FREESECT {
        return None;
    }
    // "Root Entry" is ten UTF-16 code units: twenty bytes, then the NUL.
    let root_name = w.read((dir_sect + 1) * sector, 20);
    if root_name != utf16le("Root Entry") {
        return None;
    }

    let fallback = |w: &Window| carve(w.limit.min(8 << 20), "ole", false);

    // FAT sector locations: 109 header DIFAT entries, then the DIFAT chain.
    let mut fat_sectors: Vec<u64> = Vec::new();
    for i in 0..109usize {
        let v = u32le(&h, 76 + i * 4);
        if v != FREESECT {
            fat_sectors.push(v);
        }
    }
    let mut dif_sect = u32le(&h, 68);
    let dif_count = u32le(&h, 72);
    // dif_count is untrusted: bound the walk by the sectors actually available
    // and reject cycles so a crafted chain cannot spin the loop.
    let max_hops = (dif_count + 4).min(w.limit / sector + 1);
    let mut seen: Vec<u64> = Vec::new();
    let mut hops: u64 = 0;
    while dif_sect != ENDOFCHAIN
        && dif_sect != FREESECT
        && hops < max_hops
        && !seen.contains(&dif_sect)
    {
        seen.push(dif_sect);
        let blk = match w.exact((dif_sect + 1) * sector, sector as usize) {
            Some(b) => b,
            None => return fallback(w),
        };
        for i in 0..per_sector - 1 {
            let v = u32le(&blk, i * 4);
            if v != FREESECT {
                fat_sectors.push(v);
            }
        }
        dif_sect = u32le(&blk, (per_sector - 1) * 4);
        hops += 1;
    }
    if fat_sectors.is_empty() {
        return fallback(w);
    }

    let mut max_used: i64 = -1;
    let mut idx_base: i64 = 0;
    for fs in fat_sectors {
        let blk = match w.exact((fs + 1) * sector, sector as usize) {
            Some(b) => b,
            None => return fallback(w),
        };
        for i in 0..per_sector {
            if u32le(&blk, i * 4) != FREESECT {
                max_used = max_used.max(idx_base + i as i64);
            }
        }
        idx_base += per_sector as i64;
    }
    if max_used < 0 {
        return fallback(w);
    }
    // the header occupies "sector -1"
    let end = (max_used as u64).saturating_add(2).saturating_mul(sector);
    if end > w.limit {
        return fallback(w);
    }
    // The root directory entry names the application outright; stream names are
    // the fallback for containers that leave the CLSID zeroed.
    let mut ext = "ole";
    let root = w.read((dir_sect + 1) * sector, 128);
    if root.len() == 128 {
        if let Some((_, hint)) = OLE_CLSIDS.iter().find(|(id, _)| id[..] == root[80..96]) {
            ext = hint;
        }
    }
    if ext == "ole" {
        for (name, hint) in OLE_HINTS {
            if w.find(&utf16le(name), 0, Some(end)).is_some() {
                ext = hint;
                break;
            }
        }
    }
    carve(end, ext, true)
}

// ------------------------------------------------------------- ZIP family

const ZIP_HINTS: &[(&[u8], &str)] = &[
    (b"visio/", "vsdx"),
    (b"word/", "docx"),
    (b"xl/", "xlsx"),
    (b"ppt/", "pptx"),
    (b"AndroidManifest.xml", "apk"),
    (b"META-INF/MANIFEST.MF", "jar"),
    (b"mimetypeapplication/epub+zip", "epub"),
    (b"mimetypeapplication/vnd.oasis.opendocument", "odf"),
];

/// Follow local file headers from the archive start.
///
/// Returns (offset just past the last member, whether the chain stayed intact).
/// Each member is 30 bytes of header + name + extra + compressed data, so the
/// members can be accounted for exactly -- no searching. A zip written to a
/// non-seekable stream defers its sizes to a data descriptor and cannot be
/// walked, so the caller falls back to the EOCD.
/// Largest member size to trust from a local header alone.
const ZIP_MEMBER_SANITY: u64 = 64 << 20;
/// Cap on a carve that never resolved a central directory.
const ZIP_UNRESOLVED_CAP: u64 = 16 << 20;

/// Whether to keep a ZIP-family carve that has no central directory of its own.
///
/// Off by default, and that default was learned the hard way. A scan of a 238 GB
/// Windows disk wrote 3192 files of exactly 16 MiB -- this cap, hit dead on --
/// totalling 49.9 GB, which was 74% of everything it produced. They were not
/// archives: a window opening part-way inside a real archive (an installer
/// payload, a nested zip) walks genuine member headers, never reaches that
/// archive's directory, and gets clamped here. Sampling them found "not a zip
/// file" far more often than not.
///
/// A central directory is what makes a run of bytes an archive rather than a
/// fragment of one, so without it there is nothing to carve. `--zip-partial`
/// brings the old behaviour back for an examination that wants the fragments.
static ZIP_PARTIAL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Keep ZIP fragments that have no central directory (`--zip-partial`).
pub fn set_zip_partial(on: bool) {
    ZIP_PARTIAL.store(on, std::sync::atomic::Ordering::Relaxed);
}

fn zip_partial() -> bool {
    ZIP_PARTIAL.load(std::sync::atomic::Ordering::Relaxed)
}

fn zip_walk_members(w: &mut Window) -> (u64, bool) {
    let mut pos: u64 = 0;
    loop {
        let hdr = w.read(pos, 30);
        if hdr.len() < 30 || &hdr[..4] != b"PK\x03\x04" {
            return (pos, true);
        }
        let flags = u16le(&hdr, 6);
        let csize = u32le(&hdr, 18);
        let name_len = u16le(&hdr, 26);
        let extra_len = u16le(&hdr, 28);
        if flags & 0x08 != 0 && csize == 0 {
            return (pos, false); // streamed: size lives in the data descriptor
        }
        if csize == 0xFFFF_FFFF {
            return (pos, false); // zip64: real size is in the extra field
        }
        // A member size only means something if the header is really a header.
        // In carved data a stray PK\x03\x04 declares whatever the next bytes
        // say, and following that walked hundreds of megabytes of unrelated
        // disk on a real image. A genuine archive that large still resolves
        // through its central directory, which is checked by the caller.
        if csize > ZIP_MEMBER_SANITY {
            return (pos, false);
        }
        let nxt = pos + 30 + name_len + extra_len + csize;
        if nxt <= pos || nxt > w.limit {
            return (pos, false); // runs off the end: truncated or fragmented
        }
        pos = nxt;
    }
}

fn zip_ext(w: &mut Window, end: u64) -> &'static str {
    let head = w.read(0, 4096.min(end) as usize);
    for (needle, hint) in ZIP_HINTS {
        if crate::window::find_sub(&head, needle).is_some() {
            return hint;
        }
    }
    "zip"
}

pub fn carve_zip(w: &mut Window) -> Option<Carve> {
    // Walk the members, then the central directory, to the EOCD. This keeps the
    // carve inside the archive: hunting for a trailing PK\x05\x06 finds the
    // *next* archive's directory when this one is truncated or fragmented, and
    // carves everything in between.
    let (mut accounted, intact) = zip_walk_members(w);
    let mut saw_directory = false;
    if intact && accounted > 0 && w.read(accounted, 4) == b"PK\x01\x02" {
        saw_directory = true;
        let mut pos = accounted;
        while w.read(pos, 4) == b"PK\x01\x02" {
            let ent = w.read(pos, 46);
            if ent.len() < 46 {
                break;
            }
            pos += 46 + u16le(&ent, 28) + u16le(&ent, 30) + u16le(&ent, 32);
            if pos > w.limit {
                pos = accounted; // directory runs off the end
                break;
            }
        }
        // Where the archive says its own records are, so a carve that started
        // part-way inside one can be told apart from a whole archive. Both
        // numbers are relative to the start of the archive, so on a whole
        // archive they equal the offsets in this window.
        let mut zip64_eocd_at: Option<u64> = None;
        let mut declared_zip64_eocd: Option<u64> = None;
        if w.read(pos, 4) == b"PK\x06\x06" {
            // zip64 end of central directory
            zip64_eocd_at = Some(pos);
            let rec = w.read(pos, 12);
            if rec.len() == 12 {
                pos += 12 + u64le(&rec, 4);
            }
            if w.read(pos, 4) == b"PK\x06\x07" {
                let loc = w.read(pos, 20);
                if loc.len() == 20 {
                    // The locator carries the offset of the record above.
                    declared_zip64_eocd = Some(u64le(&loc, 8));
                }
                pos += 20; // zip64 locator
            }
        }
        if pos <= w.limit && w.read(pos, 4) == b"PK\x05\x06" {
            let rec = w.read(pos, 22);
            if rec.len() == 22 {
                let end = pos + 22 + u16le(&rec, 20); // + archive comment
                                                      // A carve that began inside an archive walks that archive's
                                                      // real central directory and its real end record, and looks
                                                      // perfect -- while missing everything before the member it
                                                      // started on. On a live scan that was 821 of 825 carved
                                                      // archives: every one structurally sound and unreadable,
                                                      // because the archive's own offsets point before its start.
                let starts_here = match (zip64_eocd_at, declared_zip64_eocd) {
                    (Some(found), Some(declared)) => found == declared,
                    // No zip64 records: the plain end record says where the
                    // central directory is, and the walk knows where it found
                    // it.
                    _ => u32le(&rec, 16) == accounted,
                };
                if end <= w.limit && starts_here {
                    let ext = zip_ext(w, end);
                    return carve(end, ext, true);
                }
                if !starts_here {
                    // A fragment of a larger archive. The archive's own start
                    // is earlier in the image and is carved there, whole.
                    return if zip_partial() {
                        let ext = zip_ext(w, end.min(w.limit));
                        carve(end.min(w.limit), ext, false)
                    } else {
                        None
                    };
                }
            }
        }
        // Directory parsed but no EOCD behind it: an archive whose last record
        // was lost. Keep what is accounted for -- the directory itself is the
        // evidence that this is an archive.
        accounted = accounted.max(pos).min(w.limit);
    }

    // Fallback: an EOCD whose central-directory arithmetic lines up with this
    // start really is this archive's end. Anything else belongs to another.
    //
    // Bounded by what the member walk accounted for: an archive's directory
    // follows its members, so an EOCD far beyond them belongs to a different
    // archive. Without a bound this search runs to the end of the window -- 512
    // MB for a ZIP -- and on an encrypted image inside a compressed container
    // every byte of it must be decrypted and inflated to be looked at. That is
    // what a stray PK header cost on a live scan, once per stray header.
    //
    // The walk accounts for nothing when the first member is streamed (its size
    // lives in a trailing data descriptor), which is ordinary in archives
    // written on the fly, so the bound has to leave room for that rather than
    // the carve being refused outright.
    let search_end = accounted.saturating_add(ZIP_UNRESOLVED_CAP).min(w.limit);
    let mut search = 0u64;
    while let Some(eocd) = w.find(b"PK\x05\x06", search, Some(search_end)) {
        let rec = w.read(eocd, 22);
        if rec.len() == 22 {
            let cd_size = u32le(&rec, 12);
            let cd_off = u32le(&rec, 16);
            let end = eocd + 22 + u16le(&rec, 20);
            if cd_off + cd_size == eocd && end <= w.limit {
                let ext = zip_ext(w, end);
                return carve(end, ext, true);
            }
        }
        search = eocd + 1;
    }

    // No end-of-central-directory record. Nothing can open such a file: every
    // reader starts from that record, so a carve without one is bytes rather
    // than an archive, whatever structure precedes it. On a live scan 25 of 32
    // carved archives were this -- local headers, central entries, no end
    // record, and "File is not a zip file" from every tool.
    //
    // Kept only when fragments were asked for, and never called validated.
    if !zip_partial() {
        return None;
    }
    let _ = saw_directory;
    let accounted = accounted.min(w.limit).min(ZIP_UNRESOLVED_CAP);
    if accounted == 0 {
        return None;
    }
    let ext = zip_ext(w, accounted);
    carve(accounted, ext, false)
}

// ------------------------------------------------------------------- GZIP

/// Size of the gzip member header at `pos`, or None if it is malformed.
fn gzip_header_len(w: &mut Window, pos: u64) -> Option<u64> {
    let h = w.exact(pos, 10)?;
    if h[0] != 0x1F || h[1] != 0x8B || h[2] != 8 {
        return None;
    }
    let flg = h[3];
    let mut off = pos + 10;
    if flg & 0x04 != 0 {
        // FEXTRA: 2-byte length then that many bytes
        let xlen = u16le(&w.exact(off, 2)?, 0);
        off += 2 + xlen;
    }
    for flag in [0x08u8, 0x10u8] {
        if flg & flag != 0 {
            // FNAME / FCOMMENT: NUL-terminated
            let end = w.find(b"\x00", off, None)?;
            off = end + 1;
        }
    }
    if flg & 0x02 != 0 {
        off += 2; // FHCRC
    }
    Some(off - pos)
}

pub fn carve_gzip(w: &mut Window) -> Option<Carve> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut pos: u64 = 0;
    while pos < w.limit {
        let hlen = match gzip_header_len(w, pos) {
            Some(n) => n,
            None => {
                return if pos > 0 {
                    carve(pos, "gz", true)
                } else {
                    None
                }
            }
        };
        // Raw inflate over the deflate stream: total_in gives the exact
        // compressed length, which is what bounds the member on disk.
        let mut dec = Decompress::new(false);
        let mut scratch = vec![0u8; 1 << 20];
        let mut fed = pos + hlen;
        let mut ended = false;
        loop {
            let buf = w.read(fed, 1 << 20);
            if buf.is_empty() {
                return if pos > 0 {
                    carve(pos, "gz", true)
                } else {
                    None
                };
            }
            let mut used = 0usize;
            while used < buf.len() {
                let before = dec.total_in();
                let status = dec.decompress(&buf[used..], &mut scratch, FlushDecompress::None);
                used += (dec.total_in() - before) as usize;
                match status {
                    Ok(Status::StreamEnd) => {
                        ended = true;
                        break;
                    }
                    Ok(Status::BufError) | Ok(Status::Ok) => {
                        if dec.total_in() == before && dec.total_out() == 0 {
                            break; // no progress: need more input
                        }
                    }
                    Err(_) => {
                        return if pos > 0 {
                            carve(pos, "gz", true)
                        } else {
                            None
                        };
                    }
                }
            }
            fed += used as u64;
            if ended {
                break;
            }
            if used == 0 {
                return if pos > 0 {
                    carve(pos, "gz", true)
                } else {
                    None
                };
            }
        }
        // member = header + deflate stream + CRC32 + ISIZE
        let member_end = pos + hlen + dec.total_in() + 8;
        if member_end > w.limit {
            return if pos > 0 {
                carve(pos, "gz", true)
            } else {
                None
            };
        }
        pos = member_end;
        if w.read(pos, 2) != b"\x1f\x8b" {
            return carve(pos, "gz", true); // multi-member support
        }
    }
    if w.limit > 0 {
        carve(w.limit, "gz", false)
    } else {
        None
    }
}

// --------------------------------------------------------------------- 7z

pub fn carve_7z(w: &mut Window) -> Option<Carve> {
    let h = w.exact(0, 32)?;
    let nh_off = u64le(&h, 12);
    let nh_size = u64le(&h, 20);
    let end = 32u64.checked_add(nh_off)?.checked_add(nh_size)?;
    if nh_size == 0 || end > w.limit {
        return None;
    }
    carve(end, "7z", true)
}

// ----------------------------------------------------------------- SQLite

pub fn carve_sqlite(w: &mut Window) -> Option<Carve> {
    let h = w.exact(0, 100)?;
    let mut page_size = u16be(&h, 16);
    if page_size == 1 {
        page_size = 65536;
    }
    if page_size < 512 || page_size & (page_size - 1) != 0 {
        return None;
    }
    if !matches!(h[18], 1 | 2) || !matches!(h[19], 1 | 2) {
        return None;
    }
    let page_count = u32be(&h, 28);
    if page_count == 0 {
        return carve(w.limit, "sqlite", false); // legacy: header count unset
    }
    let size = page_size.saturating_mul(page_count);
    if size > w.limit {
        return None;
    }
    carve(size, "sqlite", true)
}

// -------------------------------------------------------------- MP4 / MOV

const MP4_BOXES: &[&[u8]] = &[
    b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"pnot", b"udta", b"uuid", b"moof",
    b"mfra", b"meta", b"styp", b"sidx", b"ssix", b"prft", b"pdin",
];

const BMFF_BRANDS: &[(&[u8], &str)] = &[
    (b"qt  ", "mov"),
    (b"heic", "heic"),
    (b"heix", "heic"),
    (b"heim", "heic"),
    (b"heis", "heic"),
    (b"hevc", "heic"),
    (b"mif1", "heic"),
    (b"msf1", "heic"),
    (b"avif", "avif"),
    (b"avis", "avif"),
    (b"3gp", "3gp"),
    (b"3g2", "3g2"),
    (b"M4A ", "m4a"),
    (b"M4V ", "m4v"),
    (b"f4v", "f4v"),
];

fn bmff_ext(w: &mut Window) -> &'static str {
    let ftyp_len = u32be(&w.read(0, 4), 0);
    let want = ftyp_len.min(64).saturating_sub(8) as usize;
    let brands = w.read(8, want);
    if brands.len() >= 4 {
        for (b, ext) in BMFF_BRANDS {
            if &brands[..4] == *b {
                return ext;
            }
        }
    }
    let mut i = 0usize;
    while i + 4 <= brands.len() {
        for (b, ext) in BMFF_BRANDS {
            if &brands[i..i + 4] == *b {
                return ext;
            }
        }
        i += 4;
    }
    if brands.len() >= 2 && &brands[..2] == b"qt" {
        return "mov";
    }
    "mp4"
}

pub fn carve_mp4(w: &mut Window) -> Option<Carve> {
    let mut pos: u64 = 0;
    let mut boxes = 0;
    while pos + 8 <= w.limit {
        let h = w.read(pos, 16);
        if h.len() < 8 {
            break;
        }
        let mut size = u32be(&h, 0);
        let btype = &h[4..8];
        if !MP4_BOXES.contains(&btype) {
            break;
        }
        if size == 1 {
            if h.len() < 16 {
                return None;
            }
            size = u64be(&h, 8);
        } else if size == 0 {
            size = w.limit - pos; // box extends to end of file
        }
        if size < 8 || pos.saturating_add(size) > w.limit {
            return None;
        }
        pos += size;
        boxes += 1;
    }
    if boxes < 2 {
        return None; // require ftyp plus at least one more box
    }
    let ext = bmff_ext(w);
    carve(pos, ext, true)
}

// ------------------------------------------------------------------- RIFF

pub fn carve_riff(w: &mut Window) -> Option<Carve> {
    let h = w.exact(0, 12)?;
    let ext = match &h[8..12] {
        b"WAVE" => "wav",
        b"AVI " => "avi",
        b"WEBP" => "webp",
        _ => return None,
    };
    let size = u32le(&h, 4).saturating_add(8);
    if size > w.limit {
        return None;
    }
    carve(size, ext, true)
}

// ------------------------------------------------------------ MP3 (ID3v2)

const MP3_BITRATES: [[u64; 15]; 6] = [
    [
        0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448,
    ], // v1 l1
    [
        0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384,
    ], // v1 l2
    [
        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
    ], // v1 l3
    [
        0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256,
    ], // v2 l1
    [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160], // v2 l2
    [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160], // v2 l3
];

fn mp3_rate(version: u8, sr_idx: usize) -> Option<u64> {
    let table: [u64; 3] = match version {
        3 => [44100, 48000, 32000],
        2 => [22050, 24000, 16000],
        0 => [11025, 12000, 8000],
        _ => return None,
    };
    table.get(sr_idx).copied()
}

/// Frame length and stream profile for a frame header, or None.
///
/// The profile -- MPEG version, layer, sample rate -- is fixed for the whole
/// stream; only the bitrate may change frame to frame (VBR). The frame walk
/// uses it to tell a real next frame from trailing data that happens to sync.
fn mp3_frame(h: &[u8]) -> Option<(u64, (u8, u8, usize))> {
    if h.len() < 4 || h[0] != 0xFF || (h[1] & 0xE0) != 0xE0 {
        return None;
    }
    let version = (h[1] >> 3) & 0x03; // 0=2.5, 2=2, 3=1
    let layer = (h[1] >> 1) & 0x03; // 1=III, 2=II, 3=I
    if version == 1 || layer == 0 {
        return None;
    }
    let vgroup: usize = if version == 3 { 0 } else { 1 };
    let lnum = 4 - layer; // 1=I, 2=II, 3=III
    let br_idx = ((h[2] >> 4) & 0x0F) as usize;
    let sr_idx = ((h[2] >> 2) & 0x03) as usize;
    let pad = ((h[2] >> 1) & 0x01) as u64;
    if br_idx == 0 || br_idx == 15 || sr_idx == 3 {
        return None;
    }
    let bitrate = MP3_BITRATES[vgroup * 3 + (lnum as usize - 1)][br_idx] * 1000;
    let rate = mp3_rate(version, sr_idx)?;
    let profile = (version, layer, sr_idx);
    if lnum == 1 {
        return Some(((12 * bitrate / rate + pad) * 4, profile));
    }
    let coeff = if lnum == 2 || vgroup == 0 { 144 } else { 72 };
    Some((coeff * bitrate / rate + pad, profile))
}

pub fn carve_mp3(w: &mut Window) -> Option<Carve> {
    let h = w.exact(0, 10)?;
    if h[3] >= 0x10 || h[4] >= 0x10 {
        return None;
    }
    if h[6..10].iter().any(|b| b & 0x80 != 0) {
        return None;
    }
    let mut pos =
        10 + (((h[6] as u64) << 21) | ((h[7] as u64) << 14) | ((h[8] as u64) << 7) | h[9] as u64);
    let mut frames = 0u64;
    let mut profile: Option<(u8, u8, usize)> = None;
    while pos + 4 <= w.limit {
        let frame = mp3_frame(&w.read(pos, 4));
        // A header whose profile differs from the first frame's ends the
        // stream: it is trailing data that happens to sync, not a frame.
        let bad_profile = matches!((&frame, &profile), (Some((_, p)), Some(want)) if p != want);
        if frame.is_none() || bad_profile {
            if w.read(pos, 3) == b"TAG" && pos + 128 <= w.limit {
                pos += 128; // trailing ID3v1
            }
            break;
        }
        let (flen, prof) = frame.unwrap();
        profile = Some(prof);
        if pos + flen > w.limit {
            break; // frame truncated at EOF/limit
        }
        pos += flen;
        frames += 1;
    }
    if frames < 1 {
        return None;
    }
    carve(pos, "mp3", frames > 10)
}

// ------------------------------------------------------------ PE (EXE/DLL)

pub fn carve_pe(w: &mut Window) -> Option<Carve> {
    let dos = w.exact(0, 64)?;
    let e_lfanew = u32le(&dos, 60);
    if !(64..=0x10000).contains(&e_lfanew) {
        return None;
    }
    let pe = w.exact(e_lfanew, 24)?;
    if &pe[..4] != b"PE\x00\x00" {
        return None;
    }
    let nsections = u16le(&pe, 6);
    let opt_size = u16le(&pe, 20);
    if !(1..=96).contains(&nsections) || opt_size < 64 {
        return None;
    }
    let opt = w.exact(e_lfanew + 24, opt_size as usize)?;
    let magic = u16le(&opt, 0);
    if magic != 0x10B && magic != 0x20B {
        return None;
    }
    let mut end = e_lfanew
        .saturating_add(24)
        .saturating_add(opt_size)
        .saturating_add(nsections.saturating_mul(40));
    let sects = w.exact(e_lfanew + 24 + opt_size, (nsections * 40) as usize)?;
    for i in 0..nsections as usize {
        let raw_size = u32le(&sects, i * 40 + 16);
        let raw_ptr = u32le(&sects, i * 40 + 20);
        if raw_ptr != 0 {
            end = end.max(raw_ptr.saturating_add(raw_size));
        }
    }
    // The Authenticode certificate table sits beyond the sections, and its
    // address is a file offset rather than an RVA.
    let dd_off = if magic == 0x10B { 96 } else { 112 };
    if opt_size >= dd_off + 40 {
        let cert_off = u32le(&opt, (dd_off + 32) as usize);
        let cert_size = u32le(&opt, (dd_off + 36) as usize);
        if cert_off != 0 && cert_size != 0 {
            end = end.max(cert_off.saturating_add(cert_size));
        }
    }
    if end > w.limit {
        return None;
    }
    let ext = if u16le(&pe, 22) & 0x2000 != 0 {
        "dll"
    } else {
        "exe"
    };
    carve(end, ext, true)
}

// ------------------------------------------------------------------ Mach-O

/// (bits, little-endian) for each thin Mach-O magic.
fn macho_variant(magic: &[u8]) -> Option<(u8, bool)> {
    Some(match magic {
        b"\xcf\xfa\xed\xfe" => (64, true),
        b"\xce\xfa\xed\xfe" => (32, true),
        b"\xfe\xed\xfa\xcf" => (64, false),
        b"\xfe\xed\xfa\xce" => (32, false),
        _ => return None,
    })
}

fn macho_thin_size(w: &mut Window, base: u64) -> Option<u64> {
    let h = w.exact(base, 32)?;
    let (bits, le) = macho_variant(&h[..4])?;
    let g32 = |b: &[u8], o: usize| if le { u32le(b, o) } else { u32be(b, o) };
    let g64 = |b: &[u8], o: usize| if le { u64le(b, o) } else { u64be(b, o) };
    let ncmds = g32(&h, 16);
    let sizeofcmds = g32(&h, 20);
    if !(1..=4096).contains(&ncmds) {
        return None;
    }
    let hdr_len: u64 = if bits == 64 { 32 } else { 28 };
    let cmds = w.exact(base + hdr_len, sizeofcmds as usize)?;
    let mut end = hdr_len + sizeofcmds;
    let mut pos = 0usize;
    for _ in 0..ncmds {
        if pos + 8 > cmds.len() {
            return None;
        }
        let cmd = g32(&cmds, pos);
        let cmdsize = g32(&cmds, pos + 4) as usize;
        if cmdsize < 8 || pos + cmdsize > cmds.len() {
            return None;
        }
        match cmd {
            0x19 if cmdsize >= 56 => {
                // LC_SEGMENT_64: fileoff + filesize
                end = end.max(g64(&cmds, pos + 40).saturating_add(g64(&cmds, pos + 48)));
            }
            0x01 if cmdsize >= 40 => {
                // LC_SEGMENT
                end = end.max(g32(&cmds, pos + 32).saturating_add(g32(&cmds, pos + 36)));
            }
            0x02 if cmdsize >= 24 => {
                // LC_SYMTAB: symbol table and string table
                let nlist = if bits == 64 { 16 } else { 12 };
                end = end.max(
                    g32(&cmds, pos + 8).saturating_add(g32(&cmds, pos + 12).saturating_mul(nlist)),
                );
                end = end.max(g32(&cmds, pos + 16).saturating_add(g32(&cmds, pos + 20)));
            }
            0x1D | 0x1E | 0x26 | 0x29 | 0x2B | 0x2E | 0x2F if cmdsize >= 16 => {
                // linkedit_data commands: dataoff + datasize
                end = end.max(g32(&cmds, pos + 8).saturating_add(g32(&cmds, pos + 12)));
            }
            _ => {}
        }
        pos += cmdsize;
    }
    if end > hdr_len {
        Some(end)
    } else {
        None
    }
}

pub fn carve_macho(w: &mut Window) -> Option<Carve> {
    let h = w.exact(0, 8)?;
    if &h[..4] == b"\xca\xfe\xba\xbe" {
        // Fat/universal binary. A Java .class shares this magic but puts a
        // version word where the architecture count goes, so the bound rejects it.
        let nfat = u32be(&h, 4);
        if !(1..=18).contains(&nfat) {
            return None;
        }
        let table = w.exact(8, (nfat * 20) as usize)?;
        let mut end = 0u64;
        for i in 0..nfat as usize {
            let a_off = u32be(&table, i * 20 + 8);
            let a_size = u32be(&table, i * 20 + 12);
            if a_off.saturating_add(a_size) > w.limit {
                return None;
            }
            macho_thin_size(w, a_off)?; // every slice must itself be Mach-O
            end = end.max(a_off.saturating_add(a_size));
        }
        return carve(end, "macho", true);
    }
    let end = macho_thin_size(w, 0)?;
    if end > w.limit {
        return None;
    }
    carve(end, "macho", true)
}

// -------------------------------------------------------------------- RAR

pub fn carve_rar(w: &mut Window) -> Option<Carve> {
    // No cheap exact-size structure; carve a capped window, unvalidated.
    if w.limit < 20 {
        return None; // smaller than any real archive
    }
    carve(w.limit, "rar", false)
}

// ------------------------------------------------------------------- FLAC

pub fn carve_flac(w: &mut Window) -> Option<Carve> {
    let mut pos: u64 = 4; // past "fLaC"
    loop {
        let h = w.exact(pos, 4)?;
        let last = h[0] & 0x80 != 0;
        let block_len = ((h[1] as u64) << 16) | ((h[2] as u64) << 8) | h[3] as u64;
        pos += 4 + block_len;
        if last {
            break;
        }
    }
    // Frames follow with no length field: run to the next stream, or EOF.
    match w.find(b"fLaC", pos, None) {
        Some(nxt) if nxt > 0 => carve(nxt, "flac", true),
        _ => carve(w.limit, "flac", false),
    }
}

// -------------------------------------------------------------------- PSD

pub fn carve_psd(w: &mut Window) -> Option<Carve> {
    let h = w.exact(0, 26)?;
    if &h[..4] != b"8BPS" {
        return None;
    }
    let mut pos: u64 = 26;
    // colour mode data, image resources, layer/mask info, then image data
    for _ in 0..4 {
        let seclen = u32be(&w.read(pos, 4), 0);
        pos += 4 + seclen;
        if pos > w.limit {
            return None;
        }
    }
    // The image data section carries no length; best-effort to the next file.
    let end = match w.find(b"8BPS", pos, None) {
        Some(nxt) if nxt > 0 => nxt,
        _ => w.limit,
    };
    carve(end, "psd", false)
}

// -------------------------------------------------------------------- ELF

pub fn carve_elf(w: &mut Window) -> Option<Carve> {
    let h = w.read(0, 64);
    if h.len() < 52 {
        return None;
    }
    let (ei_class, ei_data) = (h[4], h[5]);
    if !matches!(ei_class, 1 | 2) || !matches!(ei_data, 1 | 2) {
        return None;
    }
    let le = ei_data == 1;
    let g16 = |b: &[u8], o: usize| if le { u16le(b, o) } else { u16be(b, o) };
    let g32 = |b: &[u8], o: usize| if le { u32le(b, o) } else { u32be(b, o) };
    let g64 = |b: &[u8], o: usize| if le { u64le(b, o) } else { u64be(b, o) };

    let (e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum);
    if ei_class == 1 {
        e_phoff = g32(&h, 28);
        e_shoff = g32(&h, 32);
        e_phentsize = g16(&h, 42);
        e_phnum = g16(&h, 44);
        e_shentsize = g16(&h, 46);
        e_shnum = g16(&h, 48);
    } else {
        if h.len() < 64 {
            return None;
        }
        e_phoff = g64(&h, 32);
        e_shoff = g64(&h, 40);
        e_phentsize = g16(&h, 54);
        e_phnum = g16(&h, 56);
        e_shentsize = g16(&h, 58);
        e_shnum = g16(&h, 60);
    }
    let mut end: u64 = 0;
    if e_shoff != 0 && e_shnum != 0 {
        end = e_shoff.saturating_add(e_shnum.saturating_mul(e_shentsize));
    } else if e_phoff != 0 && e_phnum != 0 {
        let want = e_phnum.saturating_mul(e_phentsize);
        if want > w.limit {
            return None; // a program header table larger than the window
        }
        let ph = w.exact(e_phoff, want as usize)?;
        for i in 0..e_phnum as usize {
            let base = i * e_phentsize as usize;
            let (p_offset, p_filesz) = if ei_class == 1 {
                (g32(&ph, base + 4), g32(&ph, base + 16))
            } else {
                (g64(&ph, base + 8), g64(&ph, base + 32))
            };
            end = end.max(p_offset.saturating_add(p_filesz));
        }
    }
    if end <= 52 || end > w.limit {
        return None;
    }
    carve(end, "elf", true)
}

// --------------------------------------------------------------- ICO / CUR

pub fn carve_ico(w: &mut Window) -> Option<Carve> {
    let h = w.exact(0, 6)?;
    let rtype = u16le(&h, 2);
    let count = u16le(&h, 4);
    if !matches!(rtype, 1 | 2) || !(1..=512).contains(&count) {
        return None;
    }
    let mut end = 6u64.saturating_add(count.saturating_mul(16));
    let entries = w.exact(6, (count * 16) as usize)?;
    for i in 0..count as usize {
        let size = u32le(&entries, i * 16 + 8);
        let off = u32le(&entries, i * 16 + 12);
        if off < end || size == 0 {
            return None;
        }
        end = end.max(off.saturating_add(size));
    }
    if end > w.limit {
        return None;
    }
    carve(end, if rtype == 1 { "ico" } else { "cur" }, true)
}

// -------------------------------------------------------------------- OGG

pub fn carve_ogg(w: &mut Window) -> Option<Carve> {
    let mut pos: u64 = 0;
    let mut last_end: u64 = 0;
    let mut pages: u64 = 0;
    loop {
        if w.read(pos, 4) != b"OggS" {
            break;
        }
        let seg_count = w.read(pos + 26, 1);
        if seg_count.is_empty() {
            break;
        }
        let nseg = seg_count[0] as usize;
        let table = w.read(pos + 27, nseg);
        if table.len() < nseg {
            break;
        }
        let body: u64 = table.iter().map(|&b| b as u64).sum();
        let header = w.read(pos + 5, 1).first().copied().unwrap_or(0);
        pos = pos
            .saturating_add(27)
            .saturating_add(nseg as u64)
            .saturating_add(body);
        if pos > w.limit {
            break; // page body runs past EOF/limit
        }
        last_end = pos;
        pages += 1;
        if header & 0x04 != 0 {
            break; // last page of the logical stream
        }
        if pages > 1_000_000 {
            break;
        }
    }
    if pages == 0 {
        return None;
    }
    carve(last_end, "ogg", true)
}

// --------------------------------------------------------------- PST / OST

/// Outlook personal folders (.pst) and offline stores (.ost).
///
/// The header carries the file size in ROOT.ibFileEof: 8 bytes at 0xB8 for
/// Unicode stores, 4 bytes at 0xA8 for the older ANSI ones (MS-PST 2.2.2.6).
/// A store whose recorded size is not plausible is still carved -- mailboxes
/// are worth recovering truncated -- but capped and flagged unvalidated.
pub fn carve_pst(w: &mut Window) -> Option<Carve> {
    let h = w.read(0, 0x100);
    if h.len() < 0x100 || &h[..4] != b"!BDN" {
        return None;
    }
    if u16le(&h, 8) != 0x4D53 {
        return None; // wMagicClient "SM"
    }
    let (size, floor) = match u16le(&h, 10) {
        14 | 15 => (u32le(&h, 0xA8), 0x1000u64),   // ANSI store
        23 | 36 | 37 => (u64le(&h, 0xB8), 0x4400), // Unicode store
        _ => return None,
    };
    if size >= floor && size <= w.limit {
        return carve(size, "pst", true);
    }
    carve(w.limit.min(2 << 30), "pst", false)
}

// ------------------------------------------------------- Matroska / WebM

fn ebml_vint(w: &mut Window, pos: u64) -> (Option<u64>, u64) {
    let b = w.read(pos, 1);
    if b.is_empty() || b[0] == 0 {
        return (None, 1);
    }
    let first = b[0];
    let len = first.leading_zeros() as u64 + 1;
    let raw = w.read(pos, len as usize);
    if (raw.len() as u64) < len {
        return (None, len);
    }
    // Widen before shifting: an 8-byte vint shifts the mask out of a u8.
    let mut val = (first as u32 & (0xFFu32 >> len)) as u64;
    for &byte in &raw[1..] {
        val = (val << 8) | byte as u64;
    }
    (Some(val), len)
}

pub fn carve_mkv(w: &mut Window) -> Option<Carve> {
    // EBML header: 0x1A45DFA3, then a Segment (0x18538067) sized by its vint.
    let (hdr_size, n) = ebml_vint(w, 4);
    let hdr_size = hdr_size?;
    if hdr_size > (1 << 20) {
        return None;
    }
    let mut pos = 4 + n + hdr_size;
    if w.read(pos, 4) != b"\x18\x53\x80\x67" {
        return None;
    }
    let (seg_size, n2) = ebml_vint(w, pos + 4);
    pos += 4 + n2;
    let unknown = match seg_size {
        None => true,
        Some(s) => s >= (1u64 << (7 * n2)) - 1,
    };
    let ext = if w.find(b"webm", 0, Some(64)).is_some() {
        "webm"
    } else {
        "mkv"
    };
    if unknown {
        return carve(w.limit.min(256 << 20), ext, false); // live stream: no size
    }
    let end = pos + seg_size.unwrap();
    if end > w.limit {
        return None;
    }
    carve(end, ext, true)
}

// ------------------------------------------------------------------- EVTX

pub fn carve_evtx(w: &mut Window) -> Option<Carve> {
    let h = w.exact(0, 48)?;
    if &h[..8] != b"ElfFile\x00" {
        return None;
    }
    let num_chunks = u16le(&h, 40);
    if !(1..=0x10000).contains(&num_chunks) {
        return None;
    }
    // 4096-byte file header + 65536 bytes per chunk
    let end = 4096u64.saturating_add(num_chunks.saturating_mul(65536));
    if end > w.limit {
        return None;
    }
    carve(end, "evtx", true)
}

// ------------------------------------------------------- Registry hive

pub fn carve_regf(w: &mut Window) -> Option<Carve> {
    let h = w.exact(0, 48)?;
    if &h[..4] != b"regf" {
        return None;
    }
    let hbins_size = u32le(&h, 40);
    if hbins_size == 0 || hbins_size > w.limit {
        return None;
    }
    let end = 4096u64.saturating_add(hbins_size); // 4 KiB base block + hbins
    if end > w.limit {
        return None;
    }
    carve(end, "hive", true)
}

// ----------------------------------------------------------- Binary plist

pub fn carve_bplist(w: &mut Window) -> Option<Carve> {
    if w.read(0, 8) != b"bplist00" {
        return None;
    }
    // File = header | objects | offset table | 32-byte trailer. The trailer's
    // offset_table_start + num_objects*offset_size points at the trailer, so a
    // candidate end is valid iff that identity holds. Walk back from the next
    // plist header (or EOF), bounded, to tolerate trailing junk.
    let horizon = w
        .find(b"bplist00", 8, None)
        .filter(|&n| n > 0)
        .unwrap_or(w.limit);
    let floor = 40u64.max(horizon.saturating_sub(1 << 20));
    let mut end = horizon;
    while end > floor {
        if let Some(tr) = w.exact(end - 32, 32) {
            let offset_size = tr[6] as u64;
            let num_objects = u64be(&tr, 8);
            let ot_start = u64be(&tr, 24);
            if (1..=8).contains(&offset_size)
                && num_objects > 0
                && num_objects < (1 << 32)
                && ot_start >= 8
                && ot_start < end - 32
                && ot_start + num_objects * offset_size == end - 32
            {
                return carve(end, "plist", true);
            }
        }
        end -= 1;
    }
    None
}
