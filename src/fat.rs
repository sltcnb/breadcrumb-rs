//! FAT12/16/32 and exFAT undelete.
//!
//! FAT is the friendliest filesystem to recover from and the least reliable to
//! trust. A deleted entry keeps its metadata -- size, start cluster, times --
//! and only the first byte of the name is overwritten with 0xE5. What is lost
//! is the allocation chain: the FAT entries are freed, so there is no record of
//! which clusters after the first one belonged to the file. Reading forward
//! from the start cluster recovers a contiguous file exactly and a fragmented
//! one wrongly, and nothing in the filesystem says which case this is. Every
//! recovered file is therefore reported with that caveat attached: a length
//! that fits inside the volume is `validated`, and anything short is not.
//!
//! exFAT is better off: deleting clears the in-use bit (0x85 -> 0x05) but the
//! stream extension entry keeps first cluster and data length, and its
//! "no FAT chain" flag says outright that the file was contiguous.

use crate::reader::Source;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

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

/// Days from 1970-01-01 to the start of `y`-`m`-`d`, then seconds.
fn civil_to_unix(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> u64 {
    if !(1970..=9999).contains(&y) {
        return 0;
    }
    let (y_adj, m_adj) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = y_adj.div_euclid(400);
    let yoe = y_adj - era * 400;
    let doy = (153 * m_adj + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    if days < 0 {
        return 0;
    }
    (days * 86_400 + h * 3600 + mi * 60 + s) as u64
}

/// A FAT date/time pair (local time, recorded with no zone; treated as UTC).
fn dos_time(date: u64, time: u64) -> u64 {
    if date == 0 {
        return 0;
    }
    let y = ((date >> 9) & 0x7F) as i64 + 1980;
    let mo = ((date >> 5) & 0x0F).max(1) as i64;
    let d = (date & 0x1F).max(1) as i64;
    let h = ((time >> 11) & 0x1F) as i64;
    let mi = ((time >> 5) & 0x3F) as i64;
    let s = ((time & 0x1F) * 2) as i64;
    civil_to_unix(y, mo, d, h, mi, s)
}

/// The exFAT timestamp: the same fields packed into one 32-bit word.
fn exfat_time(v: u64) -> u64 {
    if v == 0 {
        return 0;
    }
    let s = ((v & 0x1F) * 2) as i64;
    let mi = ((v >> 5) & 0x3F) as i64;
    let h = ((v >> 11) & 0x1F) as i64;
    let d = ((v >> 16) & 0x1F).max(1) as i64;
    let mo = ((v >> 21) & 0x0F).max(1) as i64;
    let y = ((v >> 25) & 0x7F) as i64 + 1980;
    civil_to_unix(y, mo, d, h, mi, s)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Timestamps {
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    /// `fat` or `exfat`.
    pub kind: &'static str,
    pub name: String,
    pub ext: String,
    /// Byte offset of the directory entry this came from.
    pub offset: u64,
    pub size: u64,
    pub sha256: String,
    /// The declared length was readable inside the volume. It does not mean the
    /// file was contiguous -- FAT cannot say.
    pub validated: bool,
    pub deleted: bool,
    pub path: String,
    pub timestamps: Timestamps,
}

impl FileRecord {
    pub fn confidence(&self) -> &'static str {
        if self.validated {
            "high"
        } else {
            "low"
        }
    }
}

pub struct Options {
    pub out_dir: String,
    pub dry_run: bool,
    pub include_live: bool,
    pub min_size: u64,
}

/// Where a directory's bytes came from, so an entry's offset on the volume can
/// be reported: an analyst reads the raw entry at that offset.
enum Where {
    Flat(u64),
    Clusters(Vec<u64>),
}

/// One directory entry worth recovering.
struct Entry {
    name: String,
    deleted: bool,
    start: u64,
    size: u64,
    offset: u64,
    timestamps: Timestamps,
}

enum Kind {
    Fat { fat_type: u8 },
    Exfat,
}

pub struct Volume<'a> {
    src: &'a Source,
    base: u64,
    kind: Kind,
    bps: u64,
    spc: u64,
    pub cluster_size: u64,
    pub volume_size: u64,
    cluster_count: u64,
    // FAT12/16/32
    reserved: u64,
    num_fats: u64,
    fat_size: u64,
    root_entries: u64,
    first_data_sector: u64,
    root_cluster: u64,
    // exFAT
    fat_offset: u64,
    heap_offset: u64,
}

impl<'a> Volume<'a> {
    pub fn open(src: &'a Source, base: u64) -> Result<Self, String> {
        let bs = src.pread(base, 512);
        if bs.len() < 512 || &bs[510..512] != b"\x55\xaa" {
            return Err("no FAT/exFAT boot sector here (missing 0x55AA)".into());
        }
        if &bs[3..11] == b"EXFAT   " {
            Self::open_exfat(src, base, &bs)
        } else {
            Self::open_fat(src, base, &bs)
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            Kind::Fat { .. } => "fat",
            Kind::Exfat => "exfat",
        }
    }

    fn open_fat(src: &'a Source, base: u64, bs: &[u8]) -> Result<Self, String> {
        let bps = u16le(bs, 11);
        let spc = bs[13] as u64;
        if !matches!(bps, 512 | 1024 | 2048 | 4096) || spc == 0 || spc > 128 {
            return Err("implausible FAT geometry".into());
        }
        let reserved = u16le(bs, 14);
        let num_fats = bs[16] as u64;
        let root_entries = u16le(bs, 17);
        let total = match u16le(bs, 19) {
            0 => u32le(bs, 32),
            n => n,
        };
        let fat_size = match u16le(bs, 22) {
            0 => u32le(bs, 36),
            n => n,
        };
        if reserved == 0 || num_fats == 0 || total == 0 || fat_size == 0 {
            return Err("implausible FAT geometry".into());
        }
        let root_dir_sectors = (root_entries * 32).div_ceil(bps);
        let first_data_sector = reserved
            .checked_add(num_fats.checked_mul(fat_size).ok_or("FAT size overflow")?)
            .and_then(|v| v.checked_add(root_dir_sectors))
            .ok_or("implausible FAT layout")?;
        if total <= first_data_sector {
            return Err("implausible FAT data region".into());
        }
        let cluster_count = (total - first_data_sector) / spc;
        let fat_type = if cluster_count < 4085 {
            12
        } else if cluster_count < 65_525 {
            16
        } else {
            32
        };
        Ok(Volume {
            src,
            base,
            kind: Kind::Fat { fat_type },
            bps,
            spc,
            cluster_size: bps * spc,
            volume_size: total.saturating_mul(bps),
            cluster_count,
            reserved,
            num_fats,
            fat_size,
            root_entries,
            first_data_sector,
            root_cluster: if fat_type == 32 { u32le(bs, 44) } else { 0 },
            fat_offset: 0,
            heap_offset: 0,
        })
    }

    fn open_exfat(src: &'a Source, base: u64, bs: &[u8]) -> Result<Self, String> {
        let bps_shift = bs[108] as u32;
        let spc_shift = bs[109] as u32;
        if bps_shift > 12 || spc_shift > 25 {
            return Err("implausible exFAT geometry".into());
        }
        let bps = 1u64 << bps_shift;
        let spc = 1u64 << spc_shift;
        if bps < 512 || bps * spc > (1 << 25) {
            return Err("implausible exFAT geometry".into());
        }
        let cluster_count = u32le(bs, 92);
        let heap_offset = u32le(bs, 88);
        let volume_sectors = u32le(bs, 72);
        let volume_size = if volume_sectors > 0 {
            volume_sectors.saturating_mul(bps)
        } else {
            heap_offset
                .saturating_add(cluster_count.saturating_mul(spc))
                .saturating_mul(bps)
        };
        Ok(Volume {
            src,
            base,
            kind: Kind::Exfat,
            bps,
            spc,
            cluster_size: bps * spc,
            volume_size,
            cluster_count,
            reserved: 0,
            num_fats: bs[110] as u64,
            fat_size: u32le(bs, 84),
            root_entries: 0,
            first_data_sector: 0,
            root_cluster: u32le(bs, 96),
            fat_offset: u32le(bs, 80),
            heap_offset,
        })
    }

    fn cluster_offset(&self, cluster: u64) -> u64 {
        let sector = match self.kind {
            Kind::Fat { .. } => self
                .first_data_sector
                .saturating_add(cluster.saturating_sub(2).saturating_mul(self.spc)),
            Kind::Exfat => self
                .heap_offset
                .saturating_add(cluster.saturating_sub(2).saturating_mul(self.spc)),
        };
        self.base.saturating_add(sector.saturating_mul(self.bps))
    }

    fn root_dir_offset(&self) -> u64 {
        let sector = self.reserved + self.num_fats * self.fat_size;
        self.base + sector * self.bps
    }

    /// The next cluster in a live chain, or None at the end.
    fn fat_next(&self, cluster: u64) -> Option<u64> {
        let fat_base = match self.kind {
            Kind::Fat { .. } => self.base + self.reserved * self.bps,
            Kind::Exfat => self.base + self.fat_offset * self.bps,
        };
        match self.kind {
            Kind::Exfat => {
                let v = u32le(&self.src.pread(fat_base + cluster * 4, 4), 0);
                if (2..0xFFFF_FFF7).contains(&v) {
                    Some(v)
                } else {
                    None
                }
            }
            Kind::Fat { fat_type: 16 } => {
                let v = u16le(&self.src.pread(fat_base + cluster * 2, 2), 0);
                if v >= 0xFFF8 {
                    None
                } else {
                    Some(v)
                }
            }
            Kind::Fat { fat_type: 32 } => {
                let v = u32le(&self.src.pread(fat_base + cluster * 4, 4), 0) & 0x0FFF_FFFF;
                if v >= 0x0FFF_FFF8 {
                    None
                } else {
                    Some(v)
                }
            }
            // FAT12: an entry is 12 bits, so two of them share a byte.
            Kind::Fat { .. } => {
                let idx = cluster + (cluster >> 1);
                let raw = u16le(&self.src.pread(fat_base + idx, 2), 0);
                let v = if cluster & 1 == 1 {
                    raw >> 4
                } else {
                    raw & 0x0FFF
                };
                if v >= 0xFF8 {
                    None
                } else {
                    Some(v)
                }
            }
        }
    }

    /// Read a directory by following its live chain, so the deleted entries
    /// inside it can be reached.
    fn read_dir_chain(&self, start: u64) -> (Vec<u8>, Vec<u64>) {
        let mut out = Vec::new();
        let mut clusters = Vec::new();
        let mut cluster = start;
        let mut seen = HashSet::new();
        // A directory of more than this is not a directory any more.
        for _ in 0..4096 {
            if cluster < 2 || cluster >= self.cluster_count + 2 || !seen.insert(cluster) {
                break;
            }
            let at = self.cluster_offset(cluster);
            if at.saturating_add(self.cluster_size) > self.base + self.volume_size {
                break;
            }
            let blk = self.src.pread(at, self.cluster_size as usize);
            if blk.is_empty() {
                break;
            }
            out.extend_from_slice(&blk);
            clusters.push(cluster);
            match self.fat_next(cluster) {
                Some(next) => cluster = next,
                None => break,
            }
        }
        (out, clusters)
    }

    /// Where byte `i` of a directory read through `clusters` actually sits.
    fn entry_offset(&self, clusters: &[u64], i: u64) -> u64 {
        if self.cluster_size == 0 || clusters.is_empty() {
            return i;
        }
        let idx = (i / self.cluster_size) as usize;
        let within = i % self.cluster_size;
        match clusters.get(idx) {
            Some(&c) => self.cluster_offset(c) + within,
            None => i,
        }
    }

    /// Read `size` bytes from `first_cluster` forward, contiguously.
    ///
    /// The freed chain cannot be followed, so this is the only thing available
    /// -- and the reason a fragmented file comes back wrong rather than not at
    /// all. The caller reports the uncertainty.
    fn read_contiguous(&self, first_cluster: u64, size: u64) -> Option<(Vec<u8>, bool)> {
        if first_cluster < 2 || size == 0 {
            return None;
        }
        let at = self.cluster_offset(first_cluster);
        let volume_end = self.base.saturating_add(self.volume_size);
        if at >= volume_end {
            return None;
        }
        // A declared length reaching past the volume is not this file's.
        let want = size.min(volume_end - at);
        let mut data = Vec::with_capacity(want.min(8 << 20) as usize);
        let mut done = 0u64;
        while done < want {
            let blk = self
                .src
                .pread(at + done, ((want - done).min(8 << 20)) as usize);
            if blk.is_empty() {
                break;
            }
            done += blk.len() as u64;
            data.extend_from_slice(&blk);
        }
        if data.is_empty() {
            return None;
        }
        let complete = data.len() as u64 == size;
        Some((data, complete))
    }
}

// -- FAT directory walk ----------------------------------------------------

fn short_name(e: &[u8], deleted: bool) -> String {
    let mut raw = e[..11].to_vec();
    if deleted {
        raw[0] = b'_'; // the first character is what 0xE5 replaced
    }
    let base: String = String::from_utf8_lossy(&raw[..8]).trim_end().to_string();
    let ext: String = String::from_utf8_lossy(&raw[8..11]).trim_end().to_string();
    let name = if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    };
    name.trim().to_string()
}

/// Reassemble a long name from its component entries.
///
/// They are stored in reverse order, highest sequence number first. Deletion
/// overwrites the sequence byte with 0xE5, so it cannot be trusted -- physical
/// order is all there is to go on.
fn long_name(parts: &[Vec<u8>]) -> String {
    let mut pieces: Vec<String> = Vec::new();
    for le in parts {
        if le.len() < 32 {
            continue;
        }
        let mut chars: Vec<u8> = Vec::with_capacity(26);
        chars.extend_from_slice(&le[1..11]);
        chars.extend_from_slice(&le[14..26]);
        chars.extend_from_slice(&le[28..32]);
        let units: Vec<u16> = chars
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0 && u != 0xFFFF)
            .collect();
        pieces.push(String::from_utf16_lossy(&units));
    }
    pieces.reverse();
    pieces.concat()
}

fn walk_fat(vol: &Volume, entries: &mut Vec<Entry>) {
    let mut seen_dirs: HashSet<u64> = HashSet::new();
    // (directory bytes, where those bytes live: a flat offset for the FAT16
    // root directory, or the cluster list of a chain, and the recursion depth)
    let mut queue: Vec<(Vec<u8>, Where, u32)> = Vec::new();
    match vol.kind {
        Kind::Fat { fat_type: 32 } => {
            seen_dirs.insert(vol.root_cluster);
            let (data, clusters) = vol.read_dir_chain(vol.root_cluster);
            queue.push((data, Where::Clusters(clusters), 0));
        }
        _ => {
            // FAT12/16 keep the root directory in its own fixed area, outside
            // the cluster heap and without a chain.
            let at = vol.root_dir_offset();
            let len = (vol.root_entries * 32) as usize;
            queue.push((vol.src.pread(at, len), Where::Flat(at), 0));
        }
    }

    while let Some((data, whence, depth)) = queue.pop() {
        let mut lfn: Vec<Vec<u8>> = Vec::new();
        let mut i = 0usize;
        while i + 32 <= data.len() {
            let e = &data[i..i + 32];
            let first = e[0];
            let attr = e[11];
            if first == 0x00 {
                lfn.clear();
                i += 32;
                continue;
            }
            if attr == 0x0F {
                lfn.push(e.to_vec());
                i += 32;
                continue;
            }
            if attr & 0x08 != 0 {
                // volume label
                lfn.clear();
                i += 32;
                continue;
            }
            let deleted = first == 0xE5;
            let name = {
                let from_lfn = long_name(&lfn);
                if from_lfn.is_empty() {
                    short_name(e, deleted)
                } else {
                    from_lfn
                }
            };
            lfn.clear();
            let start = u16le(e, 26) | (u16le(e, 20) << 16);
            let size = u32le(e, 28);
            let is_dir = attr & 0x10 != 0;
            let offset = match &whence {
                Where::Flat(at) => at + i as u64,
                Where::Clusters(cl) => vol.entry_offset(cl, i as u64),
            };
            if is_dir {
                // A live directory is descended into so its deleted entries can
                // be read; a deleted one has no chain left to follow.
                if !deleted && start >= 2 && depth < 32 && seen_dirs.insert(start) {
                    let (sub, clusters) = vol.read_dir_chain(start);
                    if !sub.is_empty() {
                        queue.push((sub, Where::Clusters(clusters), depth + 1));
                    }
                }
                i += 32;
                continue;
            }
            entries.push(Entry {
                name,
                deleted,
                start,
                size,
                offset,
                timestamps: Timestamps {
                    created: dos_time(u16le(e, 16), u16le(e, 14)),
                    modified: dos_time(u16le(e, 24), u16le(e, 22)),
                    accessed: dos_time(u16le(e, 18), 0),
                },
            });
            i += 32;
        }
    }
}

fn walk_exfat(vol: &Volume, entries: &mut Vec<Entry>) {
    let mut seen: HashSet<u64> = HashSet::new();
    let mut queue: Vec<(u64, u32)> = vec![(vol.root_cluster, 0)];
    while let Some((cluster, depth)) = queue.pop() {
        if depth > 32 || cluster < 2 || !seen.insert(cluster) {
            continue;
        }
        let (data, clusters) = vol.read_dir_chain(cluster);
        let mut i = 0usize;
        while i + 32 <= data.len() {
            let etype = data[i];
            if etype == 0x00 {
                break; // end of the directory
            }
            let in_use = etype & 0x80 != 0;
            if etype & 0x7F != 0x05 {
                i += 32;
                continue;
            }
            // File entry: a stream extension and the name entries follow.
            let secondary = data[i + 1] as usize;
            let attr = u16le(&data, i + 4);
            let created = exfat_time(u32le(&data, i + 8));
            let modified = exfat_time(u32le(&data, i + 12));
            if i + 64 > data.len() || data[i + 32] & 0x7F != 0x40 {
                i += 32;
                continue;
            }
            let stream = &data[i + 32..i + 64];
            let name_len = stream[3] as usize;
            let first_cluster = u32le(stream, 20);
            let size = u32le(stream, 24) | (u32le(stream, 28) << 32);
            let mut chars: Vec<u8> = Vec::new();
            let mut j = i + 64;
            for _ in 0..secondary.saturating_sub(1) {
                if j + 32 > data.len() || data[j] & 0x7F != 0x41 {
                    break;
                }
                chars.extend_from_slice(&data[j + 2..j + 32]);
                j += 32;
            }
            let units: Vec<u16> = chars
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take(name_len)
                .collect();
            let name = String::from_utf16_lossy(&units);
            let is_dir = attr & 0x10 != 0;
            if is_dir {
                if in_use && first_cluster >= 2 {
                    queue.push((first_cluster, depth + 1));
                }
            } else {
                entries.push(Entry {
                    name: if name.is_empty() {
                        format!("exfat_{first_cluster}")
                    } else {
                        name
                    },
                    deleted: !in_use,
                    start: first_cluster,
                    size,
                    offset: vol.entry_offset(&clusters, i as u64),
                    timestamps: Timestamps {
                        created,
                        modified,
                        accessed: 0,
                    },
                });
            }
            i = j.max(i + 32);
        }
    }
}

fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim().trim_matches('.').to_string();
    if trimmed.is_empty() {
        "unnamed".into()
    } else {
        trimmed
    }
}

/// Find the volume: the offset given, the whole image, or the first FAT
/// partition in the table.
pub fn locate(src: &Source, offset: u64) -> Result<Volume<'_>, String> {
    if offset > 0 {
        return Volume::open(src, offset);
    }
    if let Ok(v) = Volume::open(src, 0) {
        return Ok(v);
    }
    for p in crate::partition::parse(src) {
        if matches!(p.fstype, "fat" | "exfat") {
            if let Ok(v) = Volume::open(src, p.start) {
                return Ok(v);
            }
        }
    }
    Err(
        "no FAT or exFAT volume found; pass --offset to point at one \
         (--list-partitions shows what is here)"
            .into(),
    )
}

/// Recover deleted (and optionally live) files from a FAT or exFAT volume.
pub fn recover(
    src: &Source,
    offset: u64,
    opts: &Options,
    mut on_file: impl FnMut(&FileRecord),
) -> Result<(Vec<FileRecord>, &'static str, u64), String> {
    let vol = locate(src, offset)?;
    let mut entries: Vec<Entry> = Vec::new();
    match vol.kind {
        Kind::Exfat => walk_exfat(&vol, &mut entries),
        Kind::Fat { .. } => walk_fat(&vol, &mut entries),
    }
    let kind = vol.kind_name();
    let mut out = Vec::new();
    let mut used: HashSet<String> = HashSet::new();
    for ent in &entries {
        if !ent.deleted && !opts.include_live {
            continue;
        }
        if ent.size < opts.min_size.max(1) {
            continue;
        }
        let Some((data, complete)) = vol.read_contiguous(ent.start, ent.size) else {
            continue;
        };
        let name = if ent.name.is_empty() {
            format!("file_{}", ent.start)
        } else {
            ent.name.clone()
        };
        let ext = std::path::Path::new(&name)
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_else(|| "bin".into());
        let mut path = String::new();
        if !opts.dry_run {
            let dir = std::path::PathBuf::from(&opts.out_dir).join(kind);
            if std::fs::create_dir_all(&dir).is_err() {
                continue;
            }
            let mut p = dir.join(sanitize(&name));
            // Two entries can carry the same name -- a file deleted twice over,
            // or a short name colliding with a long one. Keep both.
            let key = p.to_string_lossy().to_string();
            if p.exists() || !used.insert(key) {
                let stem = p
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "file".into());
                let suffix = p
                    .extension()
                    .map(|e| format!(".{}", e.to_string_lossy()))
                    .unwrap_or_default();
                p = p.with_file_name(format!("{stem}_{:x}{suffix}", ent.offset));
            }
            if std::fs::write(&p, &data).is_err() {
                continue;
            }
            path = p.to_string_lossy().to_string();
        }
        let rec = FileRecord {
            kind,
            name,
            ext,
            offset: ent.offset,
            size: data.len() as u64,
            sha256: format!("{:x}", Sha256::digest(&data)),
            validated: complete,
            deleted: ent.deleted,
            path,
            timestamps: ent.timestamps,
        };
        on_file(&rec);
        out.push(rec);
    }
    let cluster = vol.cluster_size;
    Ok((out, kind, cluster))
}

/// Where the free clusters are, from the FAT itself.
///
/// A FAT entry of zero means the cluster is free, so the allocation map and the
/// chain map are the same structure. The table is read in blocks rather than an
/// entry at a time: a 2 TB volume has hundreds of millions of entries, and one
/// read each would cost more than the scan it is meant to save.
pub fn free_ranges(
    src: &Source,
    offset: u64,
    merge_gap: u64,
) -> Result<crate::ntfs::FreeSpace, String> {
    let vol = locate(src, offset)?;
    if vol.cluster_count == 0 {
        return Err("FAT volume reports no clusters".into());
    }
    let bits: u32 = match vol.kind {
        Kind::Exfat => 32,
        Kind::Fat { fat_type } => fat_type as u32,
    };
    let fat_base = match vol.kind {
        Kind::Exfat => vol.base + vol.fat_offset * vol.bps,
        Kind::Fat { .. } => vol.base + vol.reserved * vol.bps,
    };
    // Clusters are numbered from 2; entries 0 and 1 are reserved.
    let last = vol.cluster_count + 1;
    let mut runs: Vec<(u64, u64)> = Vec::new();
    let mut run_start: Option<u64> = None;
    let block: u64 = 8 << 20;
    let mut cluster = 2u64;
    while cluster <= last {
        // Where this cluster's entry sits, and how many entries the next block
        // covers. FAT12 packs two entries into three bytes, so a block is read
        // with a byte of overlap and the count is derived from the entry index.
        let (at, span) = match bits {
            16 => (fat_base + cluster * 2, block / 2),
            32 => (fat_base + cluster * 4, block / 4),
            _ => (fat_base + cluster + (cluster >> 1), block * 2 / 3),
        };
        let want = (block + 4) as usize;
        let buf = vol.src.pread(at, want);
        if buf.len() < 2 {
            break;
        }
        let upto = (cluster + span).min(last);
        for c in cluster..=upto {
            let rel = match bits {
                16 => ((c - cluster) * 2) as usize,
                32 => ((c - cluster) * 4) as usize,
                _ => ((c + (c >> 1)) - (cluster + (cluster >> 1))) as usize,
            };
            let free = match bits {
                16 => u16le(&buf, rel) == 0,
                32 => u32le(&buf, rel) & 0x0FFF_FFFF == 0,
                _ => {
                    let raw = u16le(&buf, rel);
                    let v = if c & 1 == 1 { raw >> 4 } else { raw & 0x0FFF };
                    v == 0
                }
            };
            if rel + 2 > buf.len() {
                break;
            }
            match (free, run_start) {
                (true, None) => run_start = Some(c),
                (false, Some(s)) => {
                    runs.push((s - 2, c - s));
                    run_start = None;
                }
                _ => {}
            }
        }
        cluster = upto + 1;
    }
    if let Some(s) = run_start {
        runs.push((s - 2, last + 1 - s));
    }
    // Cluster 2 starts the data region, so a run's byte offset is measured from
    // there rather than from the start of the volume.
    let data_start = vol.cluster_offset(2);
    let volume_end = vol.base.saturating_add(vol.volume_size);
    let (ranges, free_bytes) = crate::ntfs::ranges_from_free_clusters(
        runs.into_iter(),
        data_start,
        vol.cluster_size,
        volume_end,
        merge_gap,
    );
    Ok(crate::ntfs::FreeSpace {
        ranges,
        free_bytes,
        volume_bytes: vol.volume_size,
    })
}
