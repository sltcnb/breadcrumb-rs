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
        pos += 12 + length;
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
        pos += 3 * (2u64 << (packed & 0x07));
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
                pos += 3 * (2u64 << (desc[8] & 0x07));
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
        end = end.max(ifd + 2 + n * 12 + 4);
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
            let total = tsz * cnt;
            if total > 4 {
                end = end.max(g32(e, 8) + total);
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
            end = end.max(o + c);
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
    let last = w.find_last(b"%%EOF", 0, Some(end_limit))?;
    let mut end = last + 5;
    // Take the single line terminator that ends the %%EOF line -- CRLF, or a
    // bare CR/LF. Consuming every EOL byte here also swallows trailing data
    // that merely happens to start with one.
    let tail = w.read(end, 2);
    if tail.len() >= 2 && &tail[..2] == b"\r\n" {
        end += 2;
    } else if !tail.is_empty() && (tail[0] == b'\r' || tail[0] == b'\n') {
        end += 1;
    }
    carve(end, "pdf", true)
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
    let end = (max_used as u64 + 2) * sector; // the header occupies "sector -1"
    if end > w.limit {
        return fallback(w);
    }
    // The root directory entry names the application outright; stream names are
    // the fallback for containers that leave the CLSID zeroed.
    let mut ext = "ole";
    let dir_sect = u32le(&h, 48);
    if dir_sect != FREESECT {
        let root = w.read((dir_sect + 1) * sector, 128);
        if root.len() == 128 {
            if let Some((_, hint)) = OLE_CLSIDS.iter().find(|(id, _)| id[..] == root[80..96]) {
                ext = hint;
            }
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
    if intact && accounted > 0 && w.read(accounted, 4) == b"PK\x01\x02" {
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
        if w.read(pos, 4) == b"PK\x06\x06" {
            // zip64 end of central directory
            let rec = w.read(pos, 12);
            if rec.len() == 12 {
                pos += 12 + u64le(&rec, 4);
            }
            if w.read(pos, 4) == b"PK\x06\x07" {
                pos += 20; // zip64 locator
            }
        }
        if pos <= w.limit && w.read(pos, 4) == b"PK\x05\x06" {
            let rec = w.read(pos, 22);
            if rec.len() == 22 {
                let end = pos + 22 + u16le(&rec, 20); // + archive comment
                if end <= w.limit {
                    let ext = zip_ext(w, end);
                    return carve(end, ext, true);
                }
            }
        }
        // Directory parsed but no EOCD behind it: keep what is accounted for.
        accounted = accounted.max(pos).min(w.limit);
    }

    // Fallback: an EOCD whose central-directory arithmetic lines up with this
    // start really is this archive's end. Anything else belongs to another.
    let mut search = 0u64;
    while let Some(eocd) = w.find(b"PK\x05\x06", search, None) {
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

    // Nothing conclusive: carve only the bytes actually accounted for, flagged
    // unvalidated. The data is at the front; the tail is elsewhere on disk.
    let accounted = accounted.min(w.limit);
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
    let size = page_size * page_count;
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
        if size < 8 || pos + size > w.limit {
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
    let size = u32le(&h, 4) + 8;
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
        end = e_shoff + e_shnum * e_shentsize;
    } else if e_phoff != 0 && e_phnum != 0 {
        let ph = w.exact(e_phoff, (e_phnum * e_phentsize) as usize)?;
        for i in 0..e_phnum as usize {
            let base = i * e_phentsize as usize;
            let (p_offset, p_filesz) = if ei_class == 1 {
                (g32(&ph, base + 4), g32(&ph, base + 16))
            } else {
                (g64(&ph, base + 8), g64(&ph, base + 32))
            };
            end = end.max(p_offset + p_filesz);
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
    let mut end = 6 + count * 16;
    let entries = w.exact(6, (count * 16) as usize)?;
    for i in 0..count as usize {
        let size = u32le(&entries, i * 16 + 8);
        let off = u32le(&entries, i * 16 + 12);
        if off < end || size == 0 {
            return None;
        }
        end = end.max(off + size);
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
        pos += 27 + nseg as u64 + body;
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
    let mut val = (first & (0xFF >> len)) as u64;
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
    let end = 4096 + num_chunks * 65536;
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
    let end = 4096 + hbins_size; // 4 KiB base block + hbins
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
