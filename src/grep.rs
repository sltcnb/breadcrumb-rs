//! Keyword and regex search across the raw source.
//!
//! A literal pattern is searched in both Latin-1 and UTF-16LE form, since
//! Windows artefacts store text either way. A regex is matched against the
//! bytes as they are: a pattern that has to describe UTF-16 text would have to
//! spell out the interleaved zero bytes, so the two-encoding trick does not
//! carry over. Every hit is reported with its byte offset and its context.

use crate::reader::Source;
use aho_corasick::AhoCorasick;

/// What to search for, and how far to go.
pub struct Query {
    pub patterns: Vec<String>,
    /// Case-insensitive matching (ASCII case folding).
    pub ignore_case: bool,
    /// Treat the patterns as regular expressions rather than literals.
    pub regex: bool,
    /// Stop after this many hits (0 = every hit).
    pub max_hits: usize,
}

impl Query {
    pub fn literal(patterns: Vec<String>) -> Self {
        Query {
            patterns,
            ignore_case: false,
            regex: false,
            max_hits: 0,
        }
    }
}

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

/// Scan [start, start+length) for the query, calling `on_hit` for each hit.
///
/// Returns the number of hits, or an error if a regex will not compile -- which
/// is worth failing on rather than silently finding nothing.
pub fn search(
    src: &Source,
    q: &Query,
    start: u64,
    length: u64,
    on_hit: impl FnMut(&Hit),
) -> Result<usize, String> {
    if q.regex {
        return search_regex(src, q, start, length, on_hit);
    }
    Ok(search_literal(src, q, start, length, on_hit))
}

fn search_literal(
    src: &Source,
    q: &Query,
    start: u64,
    length: u64,
    mut on_hit: impl FnMut(&Hit),
) -> usize {
    let (patterns, ignore_case, max_hits) = (&q.patterns, q.ignore_case, q.max_hits);
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

/// The regex path: one compiled pattern per term, matched over the same
/// overlapping chunks so a hit spanning a chunk boundary is still found.
fn search_regex(
    src: &Source,
    q: &Query,
    start: u64,
    length: u64,
    mut on_hit: impl FnMut(&Hit),
) -> Result<usize, String> {
    let mut res: Vec<(String, regex::bytes::Regex)> = Vec::new();
    for p in &q.patterns {
        // Byte semantics first: on a raw disk, `.` should match any byte and a
        // class should not need valid UTF-8 around it. A pattern that spells out
        // a non-ASCII character needs the Unicode engine, so fall back to it.
        let built = regex::bytes::RegexBuilder::new(p)
            .case_insensitive(q.ignore_case)
            .unicode(false)
            .build()
            .or_else(|_| {
                regex::bytes::RegexBuilder::new(p)
                    .case_insensitive(q.ignore_case)
                    .build()
            });
        match built {
            Ok(re) => res.push((p.clone(), re)),
            Err(e) => return Err(format!("--grep {p:?}: {e}")),
        }
    }
    if res.is_empty() {
        return Ok(0);
    }
    let end = if length > 0 {
        (start + length).min(src.size())
    } else {
        src.size()
    };
    let chunk: usize = 8 << 20;
    // Wider than the literal overlap: a regex match can be much longer than a
    // keyword, and one straddling a chunk edge would otherwise be missed.
    let overlap: u64 = 64 << 10;
    let mut hits = 0usize;
    let mut pos = start;
    while pos < end {
        let want = ((end - pos + overlap) as usize).min(chunk + overlap as usize);
        let buf = src.pread(pos, want);
        if buf.is_empty() {
            break;
        }
        let limit = buf.len().min(chunk);
        // Collect this chunk's hits in offset order, so output stays ordered
        // even with several patterns.
        let mut found: Vec<(usize, usize, &str)> = Vec::new();
        for (name, re) in &res {
            for m in re.find_iter(&buf) {
                if m.start() >= limit {
                    break;
                }
                found.push((m.start(), m.end(), name));
            }
        }
        found.sort_unstable();
        for (s, e, name) in found {
            let hit = Hit {
                offset: pos + s as u64,
                pattern: name.to_string(),
                encoding: "bytes",
                context: context(&buf, s, e, 32, false),
            };
            on_hit(&hit);
            hits += 1;
            if q.max_hits > 0 && hits >= q.max_hits {
                return Ok(hits);
            }
        }
        pos += limit as u64;
    }
    Ok(hits)
}
