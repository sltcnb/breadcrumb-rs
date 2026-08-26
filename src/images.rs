//! Virtual and split image readers: split raw, QCOW2, VMDK, and stdin spooling.
//!
//! Each exposes the same `size`/`pread` surface as the raw reader, so the scan
//! engine never learns what it is reading. Ported from BreadCrumb's images.py.

use flate2::{Decompress, FlushDecompress};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt;

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

fn read_at(file: &File, offset: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut done = 0usize;
    while done < len {
        let n = {
            #[cfg(unix)]
            {
                file.read_at(&mut buf[done..], offset + done as u64)
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::FileExt;
                file.seek_read(&mut buf[done..], offset + done as u64)
            }
        };
        match n {
            Ok(0) | Err(_) => break,
            Ok(n) => done += n,
        }
    }
    buf.truncate(done);
    buf
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

// ------------------------------------------------------------- split raw

/// Numbered raw segments (image.001, image.002, ...) read as one image.
pub struct SplitRawReader {
    /// (file, start offset in the joined image, length)
    segments: Vec<(File, u64, u64)>,
    pub size: u64,
    pub path: String,
    pub count: usize,
}

/// Split a path into (stem, digits) when it ends in `.NN`/`.NNN`.
pub fn split_segment_name(path: &str) -> Option<(String, String)> {
    let (stem, ext) = path.rsplit_once('.')?;
    if (2..=3).contains(&ext.len()) && ext.bytes().all(|b| b.is_ascii_digit()) {
        return Some((stem.to_string(), ext.to_string()));
    }
    None
}

impl SplitRawReader {
    pub fn open(first: &str) -> io::Result<Self> {
        let (stem, digits) =
            split_segment_name(first).ok_or_else(|| err("not a split-raw segment name"))?;
        let width = digits.len();
        let mut segments = Vec::new();
        let mut total = 0u64;
        let mut i: u64 = digits.parse().unwrap_or(1);
        loop {
            let name = format!("{stem}.{i:0width$}", width = width);
            if !Path::new(&name).exists() {
                break;
            }
            let f = File::open(&name)?;
            let len = f.metadata()?.len();
            segments.push((f, total, len));
            total += len;
            i += 1;
        }
        if segments.is_empty() {
            return Err(err("no split-raw segments found"));
        }
        Ok(SplitRawReader {
            count: segments.len(),
            segments,
            size: total,
            path: first.to_string(),
        })
    }

    pub fn pread(&self, offset: u64, len: usize) -> Vec<u8> {
        if offset >= self.size || len == 0 {
            return Vec::new();
        }
        let len = len.min((self.size - offset) as usize);
        let mut out = Vec::with_capacity(len);
        let mut pos = offset;
        for (file, base, seg_len) in &self.segments {
            if out.len() >= len {
                break;
            }
            if pos >= base + seg_len {
                continue;
            }
            let local = pos.saturating_sub(*base);
            let want = ((seg_len - local) as usize).min(len - out.len());
            let chunk = read_at(file, local, want);
            if chunk.is_empty() {
                break;
            }
            pos += chunk.len() as u64;
            out.extend_from_slice(&chunk);
        }
        out
    }
}

// ----------------------------------------------------------------- QCOW2

pub struct Qcow2Reader {
    file: File,
    cluster_bits: u32,
    cluster_size: u64,
    l1: Vec<u64>,
    l2_entries: u64,
    pub size: u64,
    pub path: String,
}

const L2_OFFSET_MASK: u64 = 0x00FF_FFFF_FFFF_FE00;
const QCOW_COMPRESSED: u64 = 1 << 62;

impl Qcow2Reader {
    pub fn open(path: &str) -> io::Result<Self> {
        let file = File::open(path)?;
        let hdr = read_at(&file, 0, 104);
        if hdr.len() < 104 || &hdr[..4] != b"QFI\xfb" {
            return Err(err("not a QCOW2 image"));
        }
        let cluster_bits = u32be(&hdr, 20) as u32;
        if !(9..=21).contains(&cluster_bits) {
            return Err(err("implausible QCOW2 cluster size"));
        }
        let cluster_size = 1u64 << cluster_bits;
        let size = u64be(&hdr, 24);
        let l1_size = u32be(&hdr, 36);
        let l1_offset = u64be(&hdr, 40);
        // The L1 table size is a header field: bound it before allocating.
        if l1_size > 1 << 26 {
            return Err(err("implausible QCOW2 L1 table size"));
        }
        // The declared virtual size is a header field too, and a sparse image
        // legitimately declares far more than its file holds -- but not more
        // than its own L1 table can address. A header claiming 16 exabytes for
        // a 149-byte file had the carver searching a 1.6e19-byte window, which
        // is a hang with no output: cargo-fuzz found exactly that.
        let addressable = (l1_size as u64)
            .checked_mul(cluster_size / 8)
            .and_then(|clusters| clusters.checked_mul(cluster_size))
            .ok_or_else(|| err("implausible QCOW2 geometry"))?;
        if size == 0 || size > addressable {
            return Err(err(format!(
                "QCOW2 header declares {size} bytes, but its L1 table can address \
                 only {addressable} -- refusing rather than reading a window that \
                 is not there"
            )));
        }
        let raw = read_at(&file, l1_offset, (l1_size * 8) as usize);
        let l1 = (0..l1_size as usize).map(|i| u64be(&raw, i * 8)).collect();
        Ok(Qcow2Reader {
            file,
            cluster_bits,
            cluster_size,
            l1,
            l2_entries: cluster_size / 8,
            size,
            path: path.to_string(),
        })
    }

    fn cluster(&self, vaddr: u64) -> Vec<u8> {
        let zeros = vec![0u8; self.cluster_size as usize];
        let cluster_idx = vaddr >> self.cluster_bits;
        let l1_idx = (cluster_idx / self.l2_entries) as usize;
        let l2_idx = (cluster_idx % self.l2_entries) as usize;
        if l1_idx >= self.l1.len() {
            return zeros;
        }
        let l2_off = self.l1[l1_idx] & L2_OFFSET_MASK;
        if l2_off == 0 {
            return zeros;
        }
        let l2 = read_at(&self.file, l2_off, self.cluster_size as usize);
        let entry = u64be(&l2, l2_idx * 8);
        if entry & QCOW_COMPRESSED != 0 {
            return self.compressed_cluster(entry).unwrap_or(zeros);
        }
        let host = entry & L2_OFFSET_MASK;
        if host == 0 {
            return zeros;
        }
        let mut data = read_at(&self.file, host, self.cluster_size as usize);
        data.resize(self.cluster_size as usize, 0);
        data
    }

    fn compressed_cluster(&self, entry: u64) -> Option<Vec<u8>> {
        // The descriptor packs an offset in the low (62 - (cluster_bits - 8))
        // bits and a sector count above it.
        let x = 62 - (self.cluster_bits - 8);
        let offset = entry & ((1u64 << x) - 1);
        let nsectors = (entry >> x) & ((1u64 << (62 - x)) - 1);
        let nbytes = ((nsectors + 1) * 512).saturating_sub(offset & 511);
        let comp = read_at(&self.file, offset, nbytes as usize);
        let mut out = vec![0u8; self.cluster_size as usize];
        let mut dec = Decompress::new(false); // raw deflate
        match dec.decompress(&comp, &mut out, FlushDecompress::Finish) {
            Ok(_) => Some(out),
            Err(_) => None,
        }
    }

    pub fn pread(&self, offset: u64, len: usize) -> Vec<u8> {
        if offset >= self.size || len == 0 {
            return Vec::new();
        }
        let len = len.min((self.size - offset) as usize);
        let mut out = Vec::with_capacity(len);
        let mut pos = offset;
        while out.len() < len {
            let base = pos & !(self.cluster_size - 1);
            let cluster = self.cluster(base);
            let start = (pos - base) as usize;
            if start >= cluster.len() {
                break;
            }
            let take = (cluster.len() - start).min(len - out.len());
            out.extend_from_slice(&cluster[start..start + take]);
            pos += take as u64;
        }
        out
    }
}

// ------------------------------------------------------------------ VMDK

/// Monolithic sparse VMDK. Flat/descriptor-only extents are raw images and are
/// read as such; stream-optimized (compressed grain markers) is not modelled.
pub struct VmdkReader {
    file: File,
    grain_bytes: u64,
    gtes_per_gt: u64,
    gd: Vec<u64>,
    pub size: u64,
    pub path: String,
}

impl VmdkReader {
    pub fn open(path: &str) -> io::Result<Self> {
        let file = File::open(path)?;
        let h = read_at(&file, 0, 512);
        if h.len() < 512 || &h[..4] != b"KDMV" {
            return Err(err("not a sparse VMDK"));
        }
        let cap_sectors = u64le(&h, 12);
        let grain_size = u64le(&h, 20); // in sectors
        let gtes_per_gt = u32le(&h, 44);
        let gd_offset = u64le(&h, 56);
        // Every geometry field here comes off the disk, so each is bounded and
        // every product checked: a corrupt or hostile header must be an error,
        // not a wraparound that becomes a huge allocation or a panic. A real
        // grain is 8..128 sectors and a grain table holds 512 entries, so these
        // bounds are far past anything a writer emits.
        if !(1..=1u64 << 20).contains(&grain_size)
            || !(1..=1u64 << 20).contains(&gtes_per_gt)
            || cap_sectors > 1u64 << 44
        {
            return Err(err("implausible VMDK grain geometry"));
        }
        let per_gt = grain_size
            .checked_mul(gtes_per_gt)
            .ok_or_else(|| err("VMDK grain geometry overflows"))?;
        let gd_entries = cap_sectors.div_ceil(per_gt);
        let gd_bytes = gd_entries
            .checked_mul(4)
            .filter(|n| *n <= 1 << 28)
            .ok_or_else(|| err("VMDK grain directory is implausibly large"))?;
        let gd_raw = read_at(&file, gd_offset.saturating_mul(512), gd_bytes as usize);
        let gd = (0..gd_entries as usize)
            .map(|i| u32le(&gd_raw, i * 4))
            .collect();
        Ok(VmdkReader {
            file,
            grain_bytes: grain_size * 512, // bounded above, cannot overflow
            gtes_per_gt,
            gd,
            size: cap_sectors * 512,
            path: path.to_string(),
        })
    }

    fn grain_sector(&self, grain_idx: u64) -> u64 {
        let gt_idx = (grain_idx / self.gtes_per_gt) as usize;
        let gte_idx = (grain_idx % self.gtes_per_gt) as usize;
        if gt_idx >= self.gd.len() || self.gd[gt_idx] == 0 {
            return 0;
        }
        let gt = read_at(
            &self.file,
            self.gd[gt_idx] * 512,
            (self.gtes_per_gt * 4) as usize,
        );
        u32le(&gt, gte_idx * 4)
    }

    pub fn pread(&self, offset: u64, len: usize) -> Vec<u8> {
        if offset >= self.size || len == 0 {
            return Vec::new();
        }
        let len = len.min((self.size - offset) as usize);
        let mut out = Vec::with_capacity(len);
        let mut pos = offset;
        while out.len() < len {
            let grain_idx = pos / self.grain_bytes;
            let within = pos % self.grain_bytes;
            let take = ((self.grain_bytes - within) as usize).min(len - out.len());
            let sector = self.grain_sector(grain_idx);
            if sector == 0 {
                out.resize(out.len() + take, 0); // unallocated grain reads as zeros
            } else {
                let mut chunk = read_at(&self.file, sector * 512 + within, take);
                chunk.resize(take, 0);
                out.extend_from_slice(&chunk);
            }
            pos += take as u64;
        }
        out
    }
}

// ----------------------------------------------------------------- stdin

/// Spool a non-seekable stream to a temp file, then read it with random access.
///
/// Handlers seek, so a pipe has to be materialised; this is what makes
/// `dd if=/dev/sdb | bcrumb-rs -` work, bounded by temp-disk space.
pub struct StdinReader {
    file: File,
    tmp: PathBuf,
    pub size: u64,
    pub path: String,
}

impl StdinReader {
    pub fn spool(mut stream: impl Read) -> io::Result<Self> {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!("breadcrumb_stdin_{}", std::process::id()));
        let mut out = File::create(&tmp)?;
        let mut buf = vec![0u8; 8 << 20];
        let mut size = 0u64;
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    out.write_all(&buf[..n])?;
                    size += n as u64;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
            }
        }
        out.flush()?;
        drop(out);
        if size == 0 {
            let _ = std::fs::remove_file(&tmp);
            return Err(err("nothing on stdin"));
        }
        let file = File::open(&tmp)?;
        Ok(StdinReader {
            file,
            tmp,
            size,
            path: "-".to_string(),
        })
    }

    pub fn pread(&self, offset: u64, len: usize) -> Vec<u8> {
        if offset >= self.size || len == 0 {
            return Vec::new();
        }
        read_at(&self.file, offset, len.min((self.size - offset) as usize))
    }
}

impl Drop for StdinReader {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.tmp);
    }
}
