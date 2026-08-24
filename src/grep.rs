//! Keyword search across the raw source.
//!
//! Each pattern is searched in both Latin-1 and UTF-16LE form, since Windows
//! artefacts store text either way, and every hit is reported with its byte
//! offset and surrounding context. Literal patterns only -- the Python
//! implementation also takes regexes, which would mean a regex engine here.

use crate::reader::Source;
use aho_corasick::AhoCorasick;

pub struct Hit {
    pub offset: u64,
    pub pattern: String,
    pub encoding: &'static str,
    pub context: String,
}

/// Build the byte patterns for one search term: Latin-1 and UTF-16LE.
fn encodings(pattern: &str, ignore_case: bool) -> Vec<(Vec<u8>, &'static str)> {
    let ascii: Vec<u8> = pattern.chars().map(|c| c as u8).collect();
    let utf16: Vec<u8> = pattern
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let mut out = vec![(ascii, "ascii"), (utf16, "utf-16le")];
    if ignore_case {
        // The matcher handles case folding; nothing extra to add here.
        out.dedup_by(|a, b| a.0 == b.0);
    }
    out
}

fn context(buf: &[u8], start: usize, end: usize, width: usize, utf16: bool) -> String {
    let lo = start.saturating_sub(width);
    let hi = (end + width).min(buf.len());
    let snippet = &buf[lo..hi];
    let text: String = if utf16 {
        snippet
            .chunks(2)
            .filter(|c| c.len() == 2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .map(|u| char::from_u32(u as u32).unwrap_or('.'))
            .collect()
    } else {
        snippet.iter().map(|&b| b as char).collect()
    };
    text.chars()
        .map(|c| if (' '..'\x7f').contains(&c) { c } else { '.' })
        .collect()
}

/// Scan [start, start+length) for the patterns, calling `on_hit` for each.
pub fn search(
    src: &Source,
    patterns: &[String],
    start: u64,
    length: u64,
    ignore_case: bool,
    max_hits: usize,
    mut on_hit: impl FnMut(&Hit),
) -> usize {
    let end = if length > 0 {
        (start + length).min(src.size())
    } else {
        src.size()
    };
    let mut needles: Vec<Vec<u8>> = Vec::new();
    let mut meta: Vec<(String, &'static str)> = Vec::new();
    for p in patterns {
        for (bytes, enc) in encodings(p, ignore_case) {
            if bytes.is_empty() {
                continue;
            }
            needles.push(bytes);
            meta.push((p.clone(), enc));
        }
    }
    if needles.is_empty() {
        return 0;
    }
    let matcher = match AhoCorasick::builder()
        .ascii_case_insensitive(ignore_case)
        .build(&needles)
    {
        Ok(m) => m,
        Err(_) => return 0,
    };

    let chunk: usize = 8 << 20;
    let overlap: u64 = 256;
    let mut hits = 0usize;
    let mut pos = start;
    while pos < end {
        let want = ((end - pos + overlap) as usize).min(chunk + overlap as usize);
        let buf = src.pread(pos, want);
        if buf.is_empty() {
            break;
        }
        let limit = buf.len().min(chunk);
        for m in matcher.find_iter(&buf) {
            if m.start() >= limit {
                break;
            }
            let (pattern, enc) = &meta[m.pattern().as_usize()];
            let hit = Hit {
                offset: pos + m.start() as u64,
                pattern: pattern.clone(),
                encoding: enc,
                context: context(&buf, m.start(), m.end(), 32, *enc == "utf-16le"),
            };
            on_hit(&hit);
            hits += 1;
            if max_hits > 0 && hits >= max_hits {
                return hits;
            }
        }
        pos += limit as u64;
    }
    hits
}
