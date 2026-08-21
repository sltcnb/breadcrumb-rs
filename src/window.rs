//! Bounded, cached view of the source starting at a candidate header.
//!
//! Handlers parse structure through this instead of slurping a whole
//! `max_size` window into memory: reads go through 64 KiB cache blocks, so
//! walking a box/chunk/segment list costs one read per block touched.

use crate::reader::Source;
use std::collections::HashMap;

pub struct Window<'a> {
    reader: &'a Source,
    pub base: u64,
    pub limit: u64,
    cache: HashMap<u64, Vec<u8>>,
    order: Vec<u64>,
}

const BLOCK: u64 = 1 << 16;
const MAX_BLOCKS: usize = 64;

impl<'a> Window<'a> {
    pub fn new(reader: &'a Source, base: u64, limit: u64) -> Self {
        let limit = limit.min(reader.size().saturating_sub(base));
        Window {
            reader,
            base,
            limit,
            cache: HashMap::new(),
            order: Vec::new(),
        }
    }

    fn block(&mut self, idx: u64) -> &[u8] {
        if !self.cache.contains_key(&idx) {
            if self.order.len() >= MAX_BLOCKS {
                let evict = self.order.remove(0);
                self.cache.remove(&evict);
            }
            let data = self.reader.pread(self.base + idx * BLOCK, BLOCK as usize);
            self.cache.insert(idx, data);
            self.order.push(idx);
        }
        &self.cache[&idx]
    }

    /// Read up to `n` bytes at `pos`; a short result means the limit was hit.
    pub fn read(&mut self, pos: u64, n: usize) -> Vec<u8> {
        if n == 0 || pos >= self.limit {
            return Vec::new();
        }
        let mut n = n.min((self.limit - pos) as usize);
        let mut pos = pos;
        let mut out = Vec::with_capacity(n);
        while n > 0 {
            let idx = pos / BLOCK;
            let rel = (pos % BLOCK) as usize;
            let blk = self.block(idx);
            if rel >= blk.len() {
                break;
            }
            let take = n.min(blk.len() - rel);
            out.extend_from_slice(&blk[rel..rel + take]);
            pos += take as u64;
            n -= take;
        }
        out
    }

    /// Exactly `n` bytes at `pos`, or None if the window is too short.
    pub fn exact(&mut self, pos: u64, n: usize) -> Option<Vec<u8>> {
        let b = self.read(pos, n);
        if b.len() == n {
            Some(b)
        } else {
            None
        }
    }

    /// First occurrence of `needle` lying wholly inside [start, end).
    pub fn find(&mut self, needle: &[u8], start: u64, end: Option<u64>) -> Option<u64> {
        let end = end.unwrap_or(self.limit).min(self.limit);
        let nl = needle.len() as u64;
        let step: usize = 1 << 20;
        let mut pos = start;
        while pos < end {
            let want = ((end - pos) as usize).min(step) + needle.len() - 1;
            let buf = self.read(pos, want);
            if (buf.len() as u64) < nl {
                return None;
            }
            if let Some(i) = find_sub(&buf, needle) {
                let abs = pos + i as u64;
                if abs + nl <= end {
                    return Some(abs);
                }
            }
            pos += step as u64;
        }
        None
    }

    /// Last occurrence of `needle` lying wholly inside [start, end).
    pub fn find_last(&mut self, needle: &[u8], start: u64, end: Option<u64>) -> Option<u64> {
        let end = end.unwrap_or(self.limit).min(self.limit);
        let nl = needle.len() as u64;
        let step: usize = 1 << 20;
        let mut pos = start;
        let mut last = None;
        while pos < end {
            let want = ((end - pos) as usize).min(step) + needle.len() - 1;
            let buf = self.read(pos, want);
            if (buf.len() as u64) < nl {
                break;
            }
            let mut from = 0usize;
            while let Some(i) = find_sub(&buf[from..], needle) {
                let abs = pos + (from + i) as u64;
                if abs + nl <= end {
                    last = Some(abs);
                }
                from += i + 1;
                if from >= buf.len() {
                    break;
                }
            }
            pos += step as u64;
        }
        last
    }
}

pub fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        let off = hay[i..hay.len() - needle.len() + 1]
            .iter()
            .position(|&b| b == first)?;
        let at = i + off;
        if &hay[at..at + needle.len()] == needle {
            return Some(at);
        }
        i = at + 1;
    }
    None
}
