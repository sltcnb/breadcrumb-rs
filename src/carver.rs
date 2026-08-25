//! Scan engine: stream the source, match signatures, carve hits to disk.
//!
//! The scan is a chunked sweep with an overlap equal to the longest magic, so
//! a header straddling a chunk boundary is still found. Candidate offsets come
//! from one Aho-Corasick pass (SIMD prefilter) over each chunk.

use crate::handlers::Carve;
use crate::reader::Source;
use crate::signatures::Signature;
use crate::window::Window;
use aho_corasick::{AhoCorasick, MatchKind};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

/// Shared limit on what a scan may write.
///
/// A carve of a large disk can produce more than the volume it is written to
/// can hold -- on a 238 GB image an unfiltered run reached 51 GB inside the
/// first percent and filled the filesystem, which takes the machine down with
/// it. Workers charge every byte here and stop cleanly when the budget or the
/// free-space floor is reached, so the manifest still lands.
#[derive(Default)]
pub struct OutputBudget {
    written: AtomicU64,
    limit: u64,
    stop: AtomicBool,
}

impl OutputBudget {
    pub fn new(limit: u64) -> Self {
        OutputBudget {
            written: AtomicU64::new(0),
            limit,
            stop: AtomicBool::new(false),
        }
    }

    pub fn charge(&self, bytes: u64) {
        self.written.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    /// Has the scan hit its limit? Sticky, so every worker sees it.
    pub fn exhausted(&self) -> bool {
        if self.stop.load(Ordering::Relaxed) {
            return true;
        }
        if self.limit > 0 && self.written() >= self.limit {
            self.stop.store(true, Ordering::Relaxed);
            return true;
        }
        false
    }

    pub fn halt(&self) {
        self.stop.store(true, Ordering::Relaxed);
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
    /// Stop writing after this many bytes of carved output (0 = no limit).
    pub max_output: u64,
    /// Stop when the output filesystem has less than this much free (0 = off).
    pub min_free: u64,
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
            max_output: 0,
            min_free: 0,
        }
    }
}

pub struct Carver<'a> {
    reader: &'a Source,
    opts: &'a Options,
    /// Budget shared with the other workers of a parallel scan.
    budget: Option<&'a OutputBudget>,
    /// Budget for a carver used on its own, so the limit holds however the
    /// scan engine is entered.
    owned_budget: Option<OutputBudget>,
    matcher: AhoCorasick,
    /// pattern index -> signatures owning that magic
    by_pattern: Vec<Vec<&'static Signature>>,
    pattern_len: Vec<usize>,
    pub rejected: u64,
    pub skipped_blank: u64,
    window_end: u64,
}

impl<'a> Carver<'a> {
    pub fn new(reader: &'a Source, sigs: Vec<&'static Signature>, opts: &'a Options) -> Self {
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
            budget: None,
            owned_budget: (opts.max_output > 0).then(|| OutputBudget::new(opts.max_output)),
            matcher,
            by_pattern,
            pattern_len,
            rejected: 0,
            skipped_blank: 0,
            window_end: 0,
        }
    }

    /// Share an output budget with the other workers of this scan.
    pub fn with_budget(mut self, budget: &'a OutputBudget) -> Self {
        self.budget = Some(budget);
        self
    }

    /// True once the scan should stop writing.
    pub fn stopped(&self) -> bool {
        if let Some(b) = self.budget {
            return b.exhausted();
        }
        self.owned_budget
            .as_ref()
            .map(|b| b.exhausted())
            .unwrap_or(false)
    }

    pub fn run(&mut self) -> Vec<Record> {
        let o = self.opts;
        let mut records: Vec<Record> = Vec::new();
        let scan_end = if o.length > 0 {
            (o.start + o.length).min(self.reader.size())
        } else {
            self.reader.size()
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
            if self.stopped() {
                break;
            }
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
                // Per candidate, not per chunk: a single 32 MiB chunk can hold
                // thousands of files, so a chunk-level check overshoots wildly.
                if self.stopped() {
                    break;
                }
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
        // A handler must not report more than its window holds -- the bytes
        // past the end are not the file. Enforced here as well as in each
        // handler, so one arithmetic slip in one of 28 parsers cannot write
        // unrelated disk into evidence.
        if carve.size > cap {
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
        if !o.dry_run {
            if let Some(budget) = self.budget {
                budget.charge(done);
            } else if let Some(budget) = &self.owned_budget {
                budget.charge(done);
            }
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

/// Drop carves that fall entirely inside an earlier validated carve.
///
/// A serial scan skips ahead past a validated carve, so it never looks inside
/// one; parallel ranges cannot see each other's skip-ahead state, and a worker
/// starting mid-archive would otherwise report an inner member (a file stored
/// in a docx, say) as a separate carve. Without this, `-j` and a serial run
/// disagree on the same image.
pub fn containment_filter(records: Vec<Record>) -> Vec<Record> {
    let mut sorted = records;
    sorted.sort_by_key(|r| (r.offset, std::cmp::Reverse(r.size)));
    let mut out: Vec<Record> = Vec::with_capacity(sorted.len());
    let mut covered_end: u64 = 0;
    for rec in sorted {
        if covered_end > 0 && rec.offset + rec.size <= covered_end {
            if !rec.path.is_empty() {
                let _ = fs::remove_file(&rec.path);
            }
            continue;
        }
        if rec.validated {
            covered_end = covered_end.max(rec.offset + rec.size);
        }
        out.push(rec);
    }
    out
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
/// Scan the ranges given, checkpointing each as it completes.
///
/// Used by --resume: the caller works out which parts are still outstanding and
/// hands them over, so a run that died leaves the rest of the work intact.
pub fn run_ranges(
    reader: &Source,
    sigs: &[&'static Signature],
    opts: &Options,
    ranges: &[(u64, u64)],
    scan_end: u64,
    mut on_range_done: impl FnMut(u64, u64),
) -> Vec<Record> {
    let budget = OutputBudget::new(opts.max_output);
    let mut out: Vec<Record> = Vec::new();
    let jobs = opts.jobs.max(1);
    for chunk in ranges.chunks(jobs.max(1)) {
        if budget.exhausted() {
            break;
        }
        let mut produced: Vec<(u64, u64, Vec<Record>)> = Vec::new();
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for &(start, end) in chunk {
                let mut sub = opts.clone();
                sub.start = start;
                sub.length = end - start;
                sub.window_end = scan_end; // carve past a range end when needed
                sub.quiet = true;
                sub.dedup = false; // one dedup pass over the merged result
                sub.jobs = 1;
                let sigs = sigs.to_vec();
                let budget = &budget;
                handles.push(scope.spawn(move || {
                    let mut c = Carver::new(reader, sigs, &sub).with_budget(budget);
                    (start, end, c.run())
                }));
            }
            for h in handles {
                produced.push(h.join().expect("scan worker panicked"));
            }
        });
        for (start, end, recs) in produced {
            out.extend(recs);
            if !budget.exhausted() {
                on_range_done(start, end);
            }
        }
    }
    let mut out = containment_filter(out);
    if opts.dedup {
        dedupe(&mut out, opts.dry_run);
    }
    out
}

pub fn run_parallel(reader: &Source, sigs: &[&'static Signature], opts: &Options) -> Vec<Record> {
    let scan_end = if opts.length > 0 {
        (opts.start + opts.length).min(reader.size())
    } else {
        reader.size()
    };
    let total = scan_end.saturating_sub(opts.start);
    let jobs = opts.jobs.max(1);
    let budget = OutputBudget::new(opts.max_output);
    if jobs == 1 || total == 0 {
        let mut c = Carver::new(reader, sigs.to_vec(), opts).with_budget(&budget);
        let out = c.run();
        let mut out = containment_filter(out);
        if opts.dedup {
            dedupe(&mut out, opts.dry_run);
        }
        return out;
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
            let budget = &budget;
            handles.push(scope.spawn(move || {
                let mut c = Carver::new(reader, sigs, &sub).with_budget(budget);
                c.run()
            }));
        }
        for h in handles {
            out.extend(h.join().expect("scan worker panicked"));
        }
    });
    let mut out = containment_filter(out);
    if opts.dedup {
        dedupe(&mut out, opts.dry_run);
    }
    out
}
