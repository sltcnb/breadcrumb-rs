//! Scan engine: stream the source, match signatures, carve hits to disk.
//!
//! The scan is a chunked sweep with an overlap equal to the longest magic, so
//! a header straddling a chunk boundary is still found. Candidate offsets come
//! from one Aho-Corasick pass (SIMD prefilter) over each chunk.

use crate::handlers::Carve;
use crate::reader::Reader;
use crate::signatures::Signature;
use crate::window::Window;
use aho_corasick::{AhoCorasick, MatchKind};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Record {
    pub kind: &'static str,
    pub ext: &'static str,
    pub offset: u64,
    pub size: u64,
    pub sha256: String,
    pub validated: bool,
    pub path: String,
    pub duplicate_of: Option<u64>,
}

impl Record {
    pub fn confidence(&self) -> &'static str {
        if self.validated {
            "high"
        } else {
            "low"
        }
    }
}

#[derive(Clone)]
pub struct Options {
    pub out_dir: String,
    pub chunk_size: u64,
    pub align: u64,
    pub skip_carved: bool,
    pub min_size: u64,
    pub max_size: u64,
    pub start: u64,
    pub length: u64,
    pub window_end: u64,
    pub dry_run: bool,
    pub quiet: bool,
    pub dedup: bool,
    pub skip_blank: bool,
    pub jobs: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            out_dir: "carved".into(),
            chunk_size: 32 << 20,
            align: 1,
            skip_carved: true,
            min_size: 0,
            max_size: 0,
            start: 0,
            length: 0,
            window_end: 0,
            dry_run: false,
            quiet: false,
            dedup: true,
            skip_blank: true,
            jobs: 1,
        }
    }
}

pub struct Carver<'a> {
    reader: &'a Reader,
    opts: &'a Options,
    matcher: AhoCorasick,
    /// pattern index -> signatures owning that magic
    by_pattern: Vec<Vec<&'static Signature>>,
    pattern_len: Vec<usize>,
    pub rejected: u64,
    pub skipped_blank: u64,
    window_end: u64,
}

impl<'a> Carver<'a> {
    pub fn new(reader: &'a Reader, sigs: Vec<&'static Signature>, opts: &'a Options) -> Self {
        // One pattern per distinct magic; longest match wins so the most
        // specific magic is preferred, matching the Python alternation order.
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut by_pattern: Vec<Vec<&'static Signature>> = Vec::new();
        for sig in &sigs {
            for magic in sig.magics {
                let m = magic.to_vec();
                match patterns.iter().position(|p| *p == m) {
                    Some(i) => by_pattern[i].push(sig),
                    None => {
                        patterns.push(m);
                        by_pattern.push(vec![sig]);
                    }
                }
            }
        }
        let pattern_len = patterns.iter().map(|p| p.len()).collect();
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("signature magics build an automaton");
        Carver {
            reader,
            opts,
            matcher,
            by_pattern,
            pattern_len,
            rejected: 0,
            skipped_blank: 0,
            window_end: 0,
        }
    }

    pub fn run(&mut self) -> Vec<Record> {
        let o = self.opts;
        let mut records: Vec<Record> = Vec::new();
        let scan_end = if o.length > 0 {
            (o.start + o.length).min(self.reader.size)
        } else {
            self.reader.size
        };
        self.window_end = if o.window_end > 0 {
            o.window_end
        } else {
            scan_end
        };
        let overlap = self.pattern_len.iter().copied().max().unwrap_or(1) as u64 - 1 + 4;
        let mut pos = o.start;
        let mut next_allowed = o.start;

        while pos < scan_end {
            let want = (o.chunk_size + overlap).min(scan_end - pos + overlap);
            let buf = self.reader.pread(pos, want as usize);
            if buf.is_empty() {
                break;
            }
            let limit = (buf.len() as u64).min(o.chunk_size);
            // Blank-block skip: an all-zero chunk (TRIM'd/sparse) holds no headers.
            if o.skip_blank && buf[..limit as usize].iter().all(|&b| b == 0) {
                self.skipped_blank += limit;
                pos += limit;
                continue;
            }
            // Collect the chunk's candidate offsets before carving: carving
            // needs &mut self, and the match iterator borrows the automaton.
            let hits: Vec<(u64, usize)> = self
                .matcher
                .find_iter(&buf)
                .map(|m| (m.start() as u64, m.pattern().as_usize()))
                .filter(|&(i, _)| i < limit)
                .collect();
            for (i, pat) in hits {
                let abs_magic = pos + i;
                for sig in self.by_pattern[pat].clone() {
                    if abs_magic < sig.header_offset {
                        continue;
                    }
                    let start = abs_magic - sig.header_offset;
                    if start < o.start || abs_magic >= scan_end {
                        continue;
                    }
                    if start < next_allowed && o.skip_carved {
                        continue;
                    }
                    if o.align > 1 && start % o.align != 0 {
                        continue;
                    }
                    if let Some(pre) = sig.precheck {
                        if !pre(&buf, i as usize) {
                            continue;
                        }
                    }
                    if let Some(rec) = self.try_carve(sig, start) {
                        let validated = rec.validated;
                        let end = rec.offset + rec.size;
                        records.push(rec);
                        if o.skip_carved && validated {
                            next_allowed = end;
                        }
                        break;
                    }
                }
            }
            pos += limit;
        }
        if o.dedup {
            dedupe(&mut records, o.dry_run);
        }
        records
    }

    fn try_carve(&mut self, sig: &'static Signature, start: u64) -> Option<Record> {
        let o = self.opts;
        let mut cap = sig.max_size;
        if o.max_size > 0 {
            cap = cap.min(o.max_size);
        }
        cap = cap.min(self.window_end.saturating_sub(start));
        if cap == 0 {
            return None;
        }
        let carve: Carve = {
            let mut w = Window::new(self.reader, start, cap);
            match (sig.handler)(&mut w) {
                Some(c) => c,
                None => {
                    self.rejected += 1;
                    return None;
                }
            }
        };
        if carve.size < o.min_size.max(1) {
            self.rejected += 1;
            return None;
        }

        // Hash while streaming; write as we go unless this is a dry run.
        let mut hasher = Sha256::new();
        let mut path = String::new();
        let mut file = if o.dry_run {
            None
        } else {
            let dir = PathBuf::from(&o.out_dir).join(carve.ext);
            if fs::create_dir_all(&dir).is_err() {
                return None;
            }
            let p = dir.join(format!("f_{:012x}.{}", start, carve.ext));
            path = p.to_string_lossy().to_string();
            match fs::File::create(&p) {
                Ok(f) => Some(std::io::BufWriter::new(f)),
                Err(_) => return None,
            }
        };
        let mut done: u64 = 0;
        while done < carve.size {
            let want = ((carve.size - done) as usize).min(8 << 20);
            let blk = self.reader.pread(start + done, want);
            if blk.is_empty() {
                break;
            }
            hasher.update(&blk);
            if let Some(f) = file.as_mut() {
                if f.write_all(&blk).is_err() {
                    return None;
                }
            }
            done += blk.len() as u64;
        }
        if let Some(mut f) = file {
            let _ = f.flush();
        }

        Some(Record {
            kind: sig.name,
            ext: carve.ext,
            offset: start,
            size: done,
            sha256: format!("{:x}", hasher.finalize()),
            validated: carve.validated,
            path,
            duplicate_of: None,
        })
    }
}

/// Mark byte-identical carves as duplicates of the first one seen, dropping
/// the redundant copies from disk.
pub fn dedupe(records: &mut [Record], dry_run: bool) {
    let mut first: HashMap<String, u64> = HashMap::new();
    for rec in records.iter_mut() {
        match first.get(&rec.sha256) {
            None => {
                first.insert(rec.sha256.clone(), rec.offset);
            }
            Some(&origin) => {
                rec.duplicate_of = Some(origin);
                if !dry_run && !rec.path.is_empty() {
                    let _ = fs::remove_file(&rec.path);
                    rec.path = String::new();
                }
            }
        }
    }
}

/// Split [start, end) into `jobs` ranges and scan them on separate threads.
///
/// Carve windows may run past a range's end (`window_end`), so a file whose
/// header sits near a boundary is still carved whole by the worker that owns
/// the header -- the same contract as the Python `run_parallel`.
pub fn run_parallel(reader: &Reader, sigs: &[&'static Signature], opts: &Options) -> Vec<Record> {
    let scan_end = if opts.length > 0 {
        (opts.start + opts.length).min(reader.size)
    } else {
        reader.size
    };
    let total = scan_end.saturating_sub(opts.start);
    let jobs = opts.jobs.max(1);
    if jobs == 1 || total == 0 {
        let mut c = Carver::new(reader, sigs.to_vec(), opts);
        return c.run();
    }
    let span = total / jobs as u64 + 1;
    let mut out: Vec<Record> = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for j in 0..jobs {
            let range_start = opts.start + span * j as u64;
            if range_start >= scan_end {
                break;
            }
            let range_len = span.min(scan_end - range_start);
            let mut sub = opts.clone();
            sub.start = range_start;
            sub.length = range_len;
            sub.window_end = scan_end; // carve past the range end when needed
            sub.quiet = true;
            sub.dedup = false; // one dedup pass over the merged result instead
            sub.jobs = 1;
            let sigs = sigs.to_vec();
            handles.push(scope.spawn(move || {
                let mut c = Carver::new(reader, sigs, &sub);
                c.run()
            }));
        }
        for h in handles {
            out.extend(h.join().expect("scan worker panicked"));
        }
    });
    out.sort_by_key(|r| (r.offset, r.size));
    if opts.dedup {
        dedupe(&mut out, opts.dry_run);
    }
    out
}
