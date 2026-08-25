//! EWF / E01 reader: section walk, chunk table, on-demand decompression.
//!
//! Ported from BreadCrumb's `images.py`, including the two things that
//! implementation learned the hard way:
//!
//! * the volume section's fields sit after a media-type byte and three unknown
//!   bytes, so `sectors_per_chunk` is at offset 8 and `bytes_per_sector` at 12;
//! * segment names run `E01`..`E99` and then roll into letters -- `EAA`..`EZZ`,
//!   `FAA`.. -- so a set of more than 99 segments must not stop at `E99`.
//!
//! A set whose chunk table falls short of the count the volume section declares
//! is refused rather than read as a smaller image.

use flate2::{Decompress, FlushDecompress};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;

const EVF_SIGNATURE: &[u8] = b"EVF\x09\x0d\x0a\xff\x00";
const SECTION_DESC: usize = 76;

struct Chunk {
    segment: usize,
    offset: u64,
    compressed: bool,
}

/// Hashes the acquisition recorded inside the image.
#[derive(Default, Clone)]
pub struct StoredHashes {
    pub md5: Option<[u8; 16]>,
    pub sha1: Option<[u8; 20]>,
}

pub struct EwfReader {
    segments: Vec<PathBuf>,
    files: Vec<File>,
    lengths: Vec<u64>,
    chunks: Vec<Chunk>,
    chunk_size: u64,
    pub size: u64,
    pub path: String,
    /// MD5/SHA-1 written by the acquisition tool, for --verify.
    pub stored_hashes: StoredHashes,
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

fn err(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Segment file names in libewf's order: `E01`..`E99`, then `EAA`..`EZZ`,
/// `FAA`.., through `ZZZ`, keeping the case of the first segment.
pub fn segment_names(stem: &str, kind: char) -> impl Iterator<Item = String> + '_ {
    let base = if kind.is_uppercase() { b'A' } else { b'a' };
    let first_letter = (kind.to_ascii_uppercase() as u8 - b'A') as usize;
    let letter = move |n: usize| (base + n as u8) as char;
    (0usize..).map_while(move |i| {
        if i < 99 {
            return Some(format!("{stem}.{kind}{:02}", i + 1));
        }
        let n = i - 99;
        let first = first_letter + n / (26 * 26);
        if first > 25 {
            return None; // past ZZZ
        }
        Some(format!(
            "{stem}.{}{}{}",
            letter(first),
            letter((n / 26) % 26),
            letter(n % 26)
        ))
    })
}

/// Every segment of the set the given path belongs to, in order.
pub fn glob_segments(path: &str) -> Vec<PathBuf> {
    let p = Path::new(path);
    let name = match p.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return vec![PathBuf::from(path)],
    };
    let (base, ext) = match name.rsplit_once('.') {
        Some((b, e)) if e.len() == 3 => (b, e),
        _ => return vec![PathBuf::from(path)],
    };
    let mut chars = ext.chars();
    let kind = match chars.next() {
        Some(c) if matches!(c.to_ascii_lowercase(), 'e' | 's' | 'l') => c,
        _ => return vec![PathBuf::from(path)],
    };
    let rest: String = chars.collect();
    let dir = p.parent().unwrap_or(Path::new("."));
    let stem = dir.join(base).to_string_lossy().to_string();

    if rest.eq_ignore_ascii_case("x01") {
        // EWF2 (.Ex01) keeps a numeric scheme of its own.
        let mut segs = Vec::new();
        for n in 1..=99u32 {
            let cand = PathBuf::from(format!("{stem}.{kind}x{n:02}"));
            if !cand.exists() {
                break;
            }
            segs.push(cand);
        }
        return if segs.is_empty() {
            vec![PathBuf::from(path)]
        } else {
            segs
        };
    }
    if rest != "01" {
        // Not the first segment: read it alone rather than guessing a set.
        return vec![PathBuf::from(path)];
    }

    let mut segs = Vec::new();
    for cand in segment_names(&stem, kind) {
        let cand = PathBuf::from(cand);
        if !cand.exists() {
            break;
        }
        segs.push(cand);
    }
    if segs.is_empty() {
        vec![PathBuf::from(path)]
    } else {
        segs
    }
}

impl EwfReader {
    pub fn open(path: &str) -> io::Result<Self> {
        let segments = glob_segments(path);
        let mut files = Vec::with_capacity(segments.len());
        let mut lengths = Vec::with_capacity(segments.len());
        for seg in &segments {
            let f = File::open(seg)?;
            lengths.push(f.metadata()?.len());
            files.push(f);
        }
        let mut r = EwfReader {
            segments,
            files,
            lengths,
            chunks: Vec::new(),
            chunk_size: 0,
            size: 0,
            path: path.to_string(),
            stored_hashes: StoredHashes::default(),
        };
        r.parse()?;
        Ok(r)
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    fn read_at(&self, seg: usize, offset: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let mut done = 0usize;
        while done < len {
            match self.read_exact_at(seg, &mut buf[done..], offset + done as u64) {
                Ok(0) | Err(_) => break,
                Ok(n) => done += n,
            }
        }
        buf.truncate(done);
        buf
    }

    #[cfg(unix)]
    fn read_exact_at(&self, seg: usize, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        self.files[seg].read_at(buf, offset)
    }

    #[cfg(windows)]
    fn read_exact_at(&self, seg: usize, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        use std::os::windows::fs::FileExt;
        self.files[seg].seek_read(buf, offset)
    }

    fn parse(&mut self) -> io::Result<()> {
        let mut bytes_per_sector: u64 = 512;
        let mut sector_counts: (u64, u64) = (0, 0);
        let mut declared_chunks: u64 = 0;

        for sidx in 0..self.segments.len() {
            let sig = self.read_at(sidx, 0, 13);
            if sig.len() < 13 || &sig[..8] != EVF_SIGNATURE {
                return Err(err(format!(
                    "{}: not an EWF/E01 image",
                    self.segments[sidx].display()
                )));
            }
            let mut offset: u64 = 13;
            loop {
                let desc = self.read_at(sidx, offset, SECTION_DESC);
                if desc.len() < SECTION_DESC {
                    break;
                }
                let stype: Vec<u8> = desc[..16].iter().copied().take_while(|&b| b != 0).collect();
                let next_off = u64le(&desc, 16);
                let data_off = offset + SECTION_DESC as u64;
                match stype.as_slice() {
                    b"volume" | b"disk" => {
                        let vol = self.read_at(sidx, data_off, 1052);
                        // ewf_volume: media_type(1) unknown(3) chunk_count(4)
                        // sectors_per_chunk(4) bytes_per_sector(4)
                        // sector_count(8, or 4 in the SMART/EWF-S01 layout)
                        let spc = u32le(&vol, 8);
                        let bps = u32le(&vol, 12);
                        bytes_per_sector = if bps == 0 { 512 } else { bps };
                        self.chunk_size = spc * bytes_per_sector;
                        if declared_chunks == 0 {
                            // Segment 1's volume section counts the whole media.
                            declared_chunks = u32le(&vol, 4);
                            sector_counts = (u64le(&vol, 16), u32le(&vol, 16));
                        }
                    }
                    b"table" => self.parse_table(sidx, data_off),
                    // "hash" carries MD5; "digest" carries MD5 then SHA-1.
                    b"hash" => {
                        let body = self.read_at(sidx, data_off, 16);
                        if body.len() == 16 && self.stored_hashes.md5.is_none() {
                            self.stored_hashes.md5 = Some(body.try_into().unwrap());
                        }
                    }
                    b"digest" => {
                        let body = self.read_at(sidx, data_off, 36);
                        if body.len() == 36 {
                            self.stored_hashes.md5 = Some(body[..16].try_into().unwrap());
                            self.stored_hashes.sha1 = Some(body[16..36].try_into().unwrap());
                        }
                    }
                    _ => {}
                }
                if next_off == 0 || next_off == offset {
                    break;
                }
                offset = next_off;
            }
        }

        if self.chunk_size == 0 || self.chunks.is_empty() {
            return Err(err(format!("{}: no EWF chunk table found", self.path)));
        }
        // A set missing its tail parses fine and simply ends early, which would
        // silently carve a fraction of the evidence. Refuse.
        let have = self.chunks.len() as u64;
        if declared_chunks > 0 && have < declared_chunks {
            let last = self
                .segments
                .last()
                .unwrap()
                .file_name()
                .unwrap_or_default();
            return Err(err(format!(
                "incomplete EWF set: {} segment(s) hold {have} of {declared_chunks} \
                 chunks ({:.1}% of the media). Last segment read: {} - the following \
                 segments are missing or misnamed.",
                self.segments.len(),
                100.0 * have as f64 / declared_chunks as f64,
                last.to_string_lossy(),
            )));
        }

        // The chunk table gives a chunk-aligned upper bound; the volume's sector
        // count gives the exact size when it lands inside that bound.
        let bound = have * self.chunk_size;
        self.size = bound;
        for sectors in [sector_counts.0, sector_counts.1] {
            let exact = sectors.saturating_mul(bytes_per_sector);
            if exact <= bound && bound - self.chunk_size < exact {
                self.size = exact;
                break;
            }
        }
        Ok(())
    }

    fn parse_table(&mut self, sidx: usize, data_off: u64) {
        let hdr = self.read_at(sidx, data_off, 24);
        let count = u32le(&hdr, 0);
        if count == 0 || count > (1 << 24) {
            return;
        }
        let base_off = u64le(&hdr, 8);
        let entries = self.read_at(sidx, data_off + 24, (count * 4) as usize);
        for i in 0..count as usize {
            if (i + 1) * 4 > entries.len() {
                break;
            }
            let v = u32le(&entries, i * 4);
            self.chunks.push(Chunk {
                segment: sidx,
                offset: (v & 0x7FFF_FFFF) + base_off,
                compressed: v & 0x8000_0000 != 0,
            });
        }
    }

    /// Upper bound on a compressed chunk's stored length: the next chunk in the
    /// same segment, else the end of that segment file.
    fn stored_len(&self, idx: usize) -> usize {
        let c = &self.chunks[idx];
        let end = self
            .chunks
            .get(idx + 1)
            .filter(|n| n.segment == c.segment && n.offset > c.offset)
            .map(|n| n.offset)
            .unwrap_or(self.lengths[c.segment]);
        // Deflate can expand slightly; keep a margin for an oversized final chunk.
        ((end - c.offset) as usize).min(self.chunk_size as usize * 2 + 1024)
    }

    fn chunk_bytes(&self, idx: usize) -> Vec<u8> {
        let c = &self.chunks[idx];
        if !c.compressed {
            return self.read_at(c.segment, c.offset, self.chunk_size as usize);
        }
        let raw = self.read_at(c.segment, c.offset, self.stored_len(idx));
        let mut out = vec![0u8; self.chunk_size as usize];
        let mut dec = Decompress::new(true); // zlib-wrapped deflate
        match dec.decompress(&raw, &mut out, FlushDecompress::Finish) {
            Ok(_) => {
                out.truncate(dec.total_out() as usize);
                out
            }
            Err(_) => Vec::new(),
        }
    }

    /// Read up to `len` bytes of decoded media at `offset`.
    pub fn pread(&self, offset: u64, len: usize) -> Vec<u8> {
        if offset >= self.size || len == 0 {
            return Vec::new();
        }
        let len = len.min((self.size - offset) as usize);
        let mut out = Vec::with_capacity(len);
        let mut pos = offset;
        while out.len() < len {
            let idx = (pos / self.chunk_size) as usize;
            if idx >= self.chunks.len() {
                break;
            }
            let within = (pos % self.chunk_size) as usize;
            let chunk = self.chunk_bytes(idx);
            if within >= chunk.len() {
                break;
            }
            let take = (len - out.len()).min(chunk.len() - within);
            out.extend_from_slice(&chunk[within..within + take]);
            pos += take as u64;
        }
        out
    }
}
