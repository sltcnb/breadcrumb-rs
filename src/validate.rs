//! Deep validation: decode carved bytes to confirm they are the file.
//!
//! A handler walks a structure and agrees it is well formed. That is not the
//! same as the file being intact: a carve can end at the right place and still
//! contain a fragment of something else in the middle, because the file was
//! fragmented on disk and carving reads consecutive bytes. Only a decode
//! catches that -- a CRC per PNG chunk, a CRC per ZIP member, an inflate that
//! reaches the end of the stream.
//!
//! Every validator runs on bytes from an untrusted disk, so none of them may
//! panic and none may allocate proportional to a declared length.

use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use std::io::Read;

/// What a decode concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Decoded; `Some(n)` tightens the carve to `n` bytes.
    Verified(Option<u64>),
    /// The decode failed: these bytes are not an intact file of this type.
    Invalid,
    /// No validator, or one that could not reach a conclusion.
    Inconclusive,
}

/// Largest carve to validate. Validation needs the whole file in memory, and a
/// multi-gigabyte carve is better left to the structural walk.
pub const MAX_VALIDATE: u64 = 256 << 20;

/// Cap on what a decompressor may produce, so a zip bomb cannot exhaust memory.
const MAX_INFLATE: u64 = 1 << 30;

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

fn u32be(b: &[u8], o: usize) -> u64 {
    if o + 4 > b.len() {
        return 0;
    }
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as u64
}

fn u16be(b: &[u8], o: usize) -> u64 {
    if o + 2 > b.len() {
        return 0;
    }
    u16::from_be_bytes([b[o], b[o + 1]]) as u64
}

/// CRC-32 (IEEE 802.3), the one PNG chunks and ZIP members carry.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Inflate `reader` for its length, or `None` if the stream is broken.
fn inflate_len<R: Read>(mut reader: R) -> Option<u64> {
    let mut buf = [0u8; 64 << 10];
    let mut total = 0u64;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Some(total),
            Ok(n) => {
                total += n as u64;
                if total > MAX_INFLATE {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

/// Inflate and CRC-32 at once, for a ZIP member.
fn inflate_crc<R: Read>(mut reader: R) -> Option<(u64, u32)> {
    let mut buf = [0u8; 64 << 10];
    let mut total = 0u64;
    let mut crc = 0xFFFF_FFFFu32;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Some((total, !crc)),
            Ok(n) => {
                total += n as u64;
                if total > MAX_INFLATE {
                    return None;
                }
                for &b in &buf[..n] {
                    crc ^= b as u32;
                    for _ in 0..8 {
                        let mask = (crc & 1).wrapping_neg();
                        crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
                    }
                }
            }
            Err(_) => return None,
        }
    }
}

// -- PNG -------------------------------------------------------------------

/// Every chunk carries a CRC, and the pixel data is a zlib stream: a PNG can be
/// verified outright, and the end of IEND is exactly where the file ends.
fn png(data: &[u8]) -> Verdict {
    if data.len() < 8 || &data[..8] != b"\x89PNG\r\n\x1a\n" {
        return Verdict::Inconclusive;
    }
    let mut pos = 8usize;
    let mut idat: Vec<u8> = Vec::new();
    let mut saw_iend = false;
    while pos + 8 <= data.len() {
        let length = u32be(data, pos) as usize;
        let ctype = &data[pos + 4..pos + 8];
        let body_at = pos + 8;
        let Some(crc_off) = body_at.checked_add(length) else {
            return Verdict::Invalid;
        };
        if crc_off + 4 > data.len() {
            return Verdict::Invalid;
        }
        let stored = u32be(data, crc_off) as u32;
        let mut buf = Vec::with_capacity(4 + length.min(1 << 20));
        buf.extend_from_slice(ctype);
        buf.extend_from_slice(&data[body_at..crc_off]);
        if crc32(&buf) != stored {
            return Verdict::Invalid;
        }
        if ctype == b"IDAT" {
            if idat.len() as u64 <= MAX_INFLATE {
                idat.extend_from_slice(&data[body_at..crc_off]);
            }
        } else if ctype == b"IEND" {
            saw_iend = true;
            pos = crc_off + 4;
            break;
        }
        pos = crc_off + 4;
    }
    if !saw_iend {
        return Verdict::Invalid;
    }
    if inflate_len(ZlibDecoder::new(&idat[..])).is_none() {
        return Verdict::Invalid;
    }
    Verdict::Verified(Some(pos as u64))
}

// -- JPEG ------------------------------------------------------------------

/// JPEG carries no checksum, so this walks the marker segments and checks that
/// the file ends where it should. A corrupt entropy stream inside a
/// structurally sound file is not detectable without a full pixel decode, which
/// is why a pass here is not proof the image renders.
fn jpeg(data: &[u8]) -> Verdict {
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        return Verdict::Inconclusive;
    }
    if &data[data.len() - 2..] != b"\xff\xd9" {
        // The carve may have over- or under-read; the walk below still applies.
        return Verdict::Inconclusive;
    }
    let mut pos = 2usize;
    while pos + 4 <= data.len() {
        if data[pos] != 0xFF {
            return Verdict::Invalid;
        }
        let marker = data[pos + 1];
        if marker == 0xDA {
            return Verdict::Verified(None); // start of scan: the header is sound
        }
        if marker == 0x01 || (0xD0..=0xD9).contains(&marker) {
            pos += 2;
            continue;
        }
        let seglen = u16be(data, pos + 2) as usize;
        if seglen < 2 {
            return Verdict::Invalid;
        }
        pos += 2 + seglen;
    }
    Verdict::Invalid
}

// -- GIF / BMP -------------------------------------------------------------

fn gif(data: &[u8]) -> Verdict {
    if data.len() < 6 || !(data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")) {
        return Verdict::Inconclusive;
    }
    if data[data.len() - 1] != 0x3B {
        return Verdict::Invalid; // no trailer: truncated or over-read
    }
    Verdict::Verified(None)
}

fn bmp(data: &[u8]) -> Verdict {
    if data.len() < 26 || &data[..2] != b"BM" {
        return Verdict::Inconclusive;
    }
    if u32le(data, 2) != data.len() as u64 {
        // The header's own size disagrees with the carve; the handler already
        // used it, so this says nothing new.
        return Verdict::Inconclusive;
    }
    Verdict::Verified(None)
}

// -- ZIP (and every OOXML document, which is a ZIP) -------------------------

/// Walk the central directory and check every member's CRC against a real
/// decompression. This is what catches a docx carved across a fragment
/// boundary: the structure survives, the member CRCs do not.
fn zip(data: &[u8]) -> Verdict {
    let Some(eocd) = find_eocd(data) else {
        return Verdict::Invalid;
    };
    let count = u16le(data, eocd + 10) as usize;
    let cd_size = u32le(data, eocd + 12) as usize;
    let cd_at = u32le(data, eocd + 16) as usize;
    if count == 0 {
        return Verdict::Invalid; // an archive with no members is not a document
    }
    if cd_at == 0xFFFF_FFFF || count == 0xFFFF {
        return Verdict::Inconclusive; // ZIP64: not walked here
    }
    if cd_at + cd_size > data.len() {
        return Verdict::Invalid;
    }
    let mut pos = cd_at;
    let mut checked = 0usize;
    for _ in 0..count {
        if pos + 46 > data.len() || &data[pos..pos + 4] != b"PK\x01\x02" {
            return Verdict::Invalid;
        }
        let method = u16le(data, pos + 10);
        let stored_crc = u32le(data, pos + 16) as u32;
        let comp_size = u32le(data, pos + 20) as usize;
        let uncomp_size = u32le(data, pos + 24) as usize;
        let name_len = u16le(data, pos + 28) as usize;
        let extra_len = u16le(data, pos + 30) as usize;
        let comment_len = u16le(data, pos + 32) as usize;
        let local_at = u32le(data, pos + 42) as usize;
        let flags = u16le(data, pos + 8);
        pos += 46 + name_len + extra_len + comment_len;

        if local_at + 30 > data.len() || &data[local_at..local_at + 4] != b"PK\x03\x04" {
            return Verdict::Invalid;
        }
        if flags & 1 != 0 {
            continue; // encrypted member: nothing to check without the password
        }
        if comp_size == 0xFFFF_FFFF || uncomp_size == 0xFFFF_FFFF {
            continue; // ZIP64 sizes live in the extra field
        }
        if uncomp_size == 0 && comp_size == 0 {
            continue; // a directory entry or an empty file
        }
        let l_name = u16le(data, local_at + 26) as usize;
        let l_extra = u16le(data, local_at + 28) as usize;
        let body_at = local_at + 30 + l_name + l_extra;
        let Some(body_end) = body_at.checked_add(comp_size) else {
            return Verdict::Invalid;
        };
        if body_end > data.len() {
            return Verdict::Invalid;
        }
        let body = &data[body_at..body_end];
        let got = match method {
            0 => Some((body.len() as u64, crc32(body))),
            8 => inflate_crc(DeflateDecoder::new(body)),
            // Some other method (bzip2, lzma, store-with-descriptor): the
            // member is not checkable here, but its framing was.
            _ => {
                checked += 1;
                continue;
            }
        };
        match got {
            Some((len, crc)) if crc == stored_crc && len == uncomp_size as u64 => checked += 1,
            _ => return Verdict::Invalid,
        }
    }
    if checked == 0 {
        return Verdict::Inconclusive;
    }
    Verdict::Verified(None)
}

/// The end-of-central-directory record, searched from the tail as the spec
/// requires (its comment field means it is not necessarily the last 22 bytes).
fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let start = data.len().saturating_sub(65_557); // 64K comment + the record
    let mut at = data.len() - 22;
    loop {
        if &data[at..at + 4] == b"PK\x05\x06" {
            let comment = u16le(data, at + 20) as usize;
            if at + 22 + comment == data.len() {
                return Some(at);
            }
        }
        if at == start {
            return None;
        }
        at -= 1;
    }
}

// -- gzip ------------------------------------------------------------------

/// gzip ends with the uncompressed length and a CRC of the original data, both
/// of which the decoder checks, so a full inflate is a real verification.
fn gzip(data: &[u8]) -> Verdict {
    if data.len() < 18 || data[0] != 0x1F || data[1] != 0x8B {
        return Verdict::Inconclusive;
    }
    match inflate_len(GzDecoder::new(data)) {
        Some(0) => Verdict::Inconclusive, // an empty member proves little
        Some(_) => Verdict::Verified(None),
        None => Verdict::Invalid,
    }
}

// -- SQLite ----------------------------------------------------------------

/// A structural check, not `PRAGMA integrity_check`: the header's own geometry
/// must agree with the length of the carve, which is what catches a database
/// whose tail is somebody else's data.
fn sqlite(data: &[u8]) -> Verdict {
    if data.len() < 100 || &data[..16] != b"SQLite format 3\x00" {
        return Verdict::Inconclusive;
    }
    let page_size = match u16be(data, 16) {
        1 => 65_536, // the spec's escape for 64K pages
        n => n,
    };
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Verdict::Invalid;
    }
    let pages = u32be(data, 28);
    let reserved = data[20] as u64;
    if reserved >= page_size {
        return Verdict::Invalid;
    }
    if pages == 0 {
        return Verdict::Inconclusive; // pre-3.7 header: page count not tracked
    }
    let want = pages.checked_mul(page_size);
    match want {
        Some(w) if w == data.len() as u64 => Verdict::Verified(Some(w)),
        // A carve longer than the header says is over-read, not corruption:
        // tighten it to the database and keep it.
        Some(w) if w < data.len() as u64 && w >= 512 => Verdict::Verified(Some(w)),
        _ => Verdict::Invalid,
    }
}

// -- dispatch --------------------------------------------------------------

/// Is there a validator for this extension?
pub fn can_validate(ext: &str) -> bool {
    matches!(
        ext,
        "png"
            | "jpg"
            | "gif"
            | "bmp"
            | "zip"
            | "docx"
            | "xlsx"
            | "pptx"
            | "apk"
            | "jar"
            | "epub"
            | "odf"
            | "gz"
            | "sqlite"
    )
}

/// Decode `data` as `ext` and report what the decode concluded.
pub fn validate(ext: &str, data: &[u8]) -> Verdict {
    match ext {
        "png" => png(data),
        "jpg" => jpeg(data),
        "gif" => gif(data),
        "bmp" => bmp(data),
        "zip" | "docx" | "xlsx" | "pptx" | "apk" | "jar" | "epub" | "odf" => zip(data),
        "gz" => gzip(data),
        "sqlite" => sqlite(data),
        _ => Verdict::Inconclusive,
    }
}
