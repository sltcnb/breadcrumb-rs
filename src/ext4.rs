//! ext2/3/4 undelete: names from directory blocks, content from inodes.
//!
//! Two sources have to be put together, because neither is enough on its own.
//! A directory block holds `inode -> name`, and an unlinked entry's name often
//! survives in the record's slack, so names are recoverable. The inode holds
//! the block map, the size and the timestamps.
//!
//! The hard limit is what ext4 does on delete: it clears the extent tree of a
//! freed inode in many cases, and where that has happened the content is simply
//! not there any more -- the journal is the only remaining copy, and replaying
//! it is not done here. An inode whose map is gone is reported as such rather
//! than as an empty file, and one whose map has holes is reported at low
//! confidence with the holes zero-filled.
//!
//! Not handled: inline data (the content lives in the inode itself), encrypted
//! inodes, and the journal replay above.

use crate::reader::Source;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const EXT_MAGIC: u64 = 0xEF53;
const ROOT_INO: u64 = 2;

// s_feature_incompat
const INCOMPAT_EXTENTS: u64 = 0x0040;
const INCOMPAT_64BIT: u64 = 0x0080;

// inode i_flags
const EXTENTS_FL: u64 = 0x8_0000;
const INLINE_DATA_FL: u64 = 0x1000_0000;

const S_IFMT: u64 = 0xF000;
const S_IFREG: u64 = 0x8000;
const S_IFDIR: u64 = 0x4000;

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

#[derive(Debug, Clone, Copy, Default)]
pub struct Timestamps {
    pub accessed: u64,
    pub changed: u64,
    pub modified: u64,
    /// When the inode was freed -- ext keeps this, unlike NTFS.
    pub deleted: u64,
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub inode: u64,
    /// Path inside the volume, or `#inode_N` when no name was found.
    pub name: String,
    pub ext: String,
    pub size: u64,
    pub sha256: String,
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

struct Inode {
    mode: u64,
    size: u64,
    links: u64,
    flags: u64,
    times: Timestamps,
}

impl Inode {
    fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
    fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
}

pub struct Volume<'a> {
    src: &'a Source,
    base: u64,
    pub block_size: u64,
    pub inodes_count: u64,
    pub blocks_count: u64,
    inodes_per_group: u64,
    inode_size: u64,
    first_ino: u64,
    has_extents: bool,
    /// Inode table block, per group.
    tables: Vec<u64>,
    /// Block bitmap block, per group.
    bitmaps: Vec<u64>,
    blocks_per_group: u64,
    first_data_block: u64,
}

impl<'a> Volume<'a> {
    pub fn open(src: &'a Source, base: u64) -> Result<Self, String> {
        let sb = src.pread(base + 1024, 1024);
        if sb.len() < 1024 || u16le(&sb, 56) != EXT_MAGIC {
            return Err("no ext2/3/4 superblock here".into());
        }
        let log_block_size = u32le(&sb, 24);
        if log_block_size > 10 {
            return Err("implausible ext block size".into());
        }
        let block_size = 1024u64 << log_block_size;
        let inodes_count = u32le(&sb, 0);
        let blocks_count = u32le(&sb, 4) | (u32le(&sb, 0x150) << 32);
        let blocks_per_group = u32le(&sb, 32);
        let inodes_per_group = u32le(&sb, 40);
        let inode_size = match u16le(&sb, 88) {
            0 => 128,
            n => n,
        };
        let feature_incompat = u32le(&sb, 96);
        let is_64bit = feature_incompat & INCOMPAT_64BIT != 0;
        let desc_size = if is_64bit {
            u16le(&sb, 0xFE).max(32)
        } else {
            32
        };
        let first_data_block = u32le(&sb, 20);
        if inodes_count == 0
            || blocks_count == 0
            || blocks_per_group == 0
            || inodes_per_group == 0
            || !(128..=4096).contains(&inode_size)
        {
            return Err("implausible ext geometry".into());
        }
        let groups = blocks_count.div_ceil(blocks_per_group);
        if groups == 0 || groups > 1 << 22 {
            return Err("implausible ext group count".into());
        }
        // Group descriptors follow the superblock.
        let gdt_at = base + (first_data_block + 1) * block_size;
        let raw = src.pread(
            gdt_at,
            (groups.saturating_mul(desc_size)).min(64 << 20) as usize,
        );
        let mut tables = Vec::with_capacity(groups as usize);
        let mut bitmaps = Vec::with_capacity(groups as usize);
        for g in 0..groups {
            let at = (g * desc_size) as usize;
            if at + 32 > raw.len() {
                break;
            }
            let d = &raw[at..];
            let lo = u32le(d, 8);
            let hi = if desc_size >= 0x2C { u32le(d, 0x28) } else { 0 };
            tables.push(lo | (hi << 32));
            // bg_block_bitmap is the first field of the descriptor.
            let blo = u32le(d, 0);
            let bhi = if desc_size >= 0x24 { u32le(d, 0x20) } else { 0 };
            bitmaps.push(blo | (bhi << 32));
        }
        if tables.is_empty() {
            return Err("ext group descriptors unreadable".into());
        }
        Ok(Volume {
            src,
            base,
            block_size,
            inodes_count,
            blocks_count,
            inodes_per_group,
            inode_size,
            first_ino: match u32le(&sb, 84) {
                0 => 11,
                n => n,
            },
            has_extents: feature_incompat & INCOMPAT_EXTENTS != 0,
            tables,
            bitmaps,
            blocks_per_group,
            first_data_block,
        })
    }

    fn block(&self, n: u64) -> Vec<u8> {
        if n == 0 || n >= self.blocks_count {
            return Vec::new();
        }
        self.src.pread(
            self.base.saturating_add(n.saturating_mul(self.block_size)),
            self.block_size as usize,
        )
    }

    fn inode_raw(&self, ino: u64) -> Option<Vec<u8>> {
        if ino < 1 || ino > self.inodes_count {
            return None;
        }
        let g = (ino - 1) / self.inodes_per_group;
        let idx = (ino - 1) % self.inodes_per_group;
        let table = *self.tables.get(g as usize)?;
        let at = self
            .base
            .checked_add(table.checked_mul(self.block_size)?)?
            .checked_add(idx.checked_mul(self.inode_size)?)?;
        let raw = self.src.pread(at, self.inode_size as usize);
        if raw.len() < 128 {
            None
        } else {
            Some(raw)
        }
    }

    fn parse_inode(raw: &[u8]) -> Inode {
        Inode {
            mode: u16le(raw, 0),
            size: u32le(raw, 4) | (u32le(raw, 108) << 32),
            links: u16le(raw, 26),
            flags: u32le(raw, 32),
            times: Timestamps {
                accessed: u32le(raw, 8),
                changed: u32le(raw, 12),
                modified: u32le(raw, 16),
                deleted: u32le(raw, 20),
            },
        }
    }

    /// The file's blocks in order, and whether the map was complete.
    ///
    /// `None` means there is no usable map at all -- the inode was freed and
    /// its extent tree cleared, which is the ordinary ext4 case.
    fn block_map(&self, raw: &[u8], inode: &Inode) -> Option<(Vec<(u64, u64)>, bool)> {
        if inode.flags & INLINE_DATA_FL != 0 {
            return None; // the content lives in the inode; not handled
        }
        if self.has_extents && inode.flags & EXTENTS_FL != 0 {
            let body = raw.get(40..100)?;
            let (ranges, ok) = self.walk_extents(body, 0)?;
            if ranges.is_empty() {
                return None;
            }
            return Some((ranges, ok));
        }
        self.classic_map(raw, inode)
    }

    fn walk_extents(&self, node: &[u8], depth: u32) -> Option<(Vec<(u64, u64)>, bool)> {
        if depth > 5 || node.len() < 12 || u16le(node, 0) != 0xF30A {
            return None;
        }
        let entries = u16le(node, 2) as usize;
        // A node cannot hold more entries than it has room for.
        if entries > (node.len() - 12) / 12 {
            return None;
        }
        let leaf = u16le(node, 6) == 0;
        let mut ranges = Vec::new();
        let mut ok = true;
        for i in 0..entries {
            let e = &node[12 + i * 12..24 + i * 12];
            if leaf {
                let mut length = u16le(e, 4);
                let phys = u32le(e, 8) | (u16le(e, 6) << 32);
                if length > 32768 {
                    length -= 32768; // an uninitialised extent
                }
                if length == 0 {
                    continue;
                }
                ranges.push((phys, length));
            } else {
                let child = u32le(e, 4) | (u16le(e, 8) << 32);
                match self.walk_extents(&self.block(child), depth + 1) {
                    Some((sub, sok)) => {
                        ranges.extend(sub);
                        ok = ok && sok;
                    }
                    None => ok = false,
                }
            }
        }
        Some((ranges, ok))
    }

    /// ext2/3: twelve direct pointers, then one, two and three levels of
    /// indirection.
    fn classic_map(&self, raw: &[u8], inode: &Inode) -> Option<(Vec<(u64, u64)>, bool)> {
        let want = inode.size.div_ceil(self.block_size) as usize;
        if want == 0 {
            return None;
        }
        let ptr = |i: usize| u32le(raw, 40 + i * 4);
        let mut out: Vec<(u64, u64)> = Vec::new();
        for i in 0..12 {
            if out.len() >= want {
                break;
            }
            out.push((ptr(i), 1));
        }
        let per_block = (self.block_size / 4) as usize;
        // Indirection, iteratively: (block, level) pairs still to expand.
        let mut pending: Vec<(u64, u32)> = Vec::new();
        for (i, level) in [(12usize, 1u32), (13, 2), (14, 3)] {
            let b = ptr(i);
            if b != 0 {
                pending.push((b, level));
            }
        }
        let mut guard = 0usize;
        while let Some((blockno, level)) = pending.pop() {
            guard += 1;
            if out.len() >= want || guard > 1 << 16 {
                break;
            }
            let data = self.block(blockno);
            if data.is_empty() {
                continue;
            }
            let mut children = Vec::new();
            for i in 0..per_block {
                let child = u32le(&data, i * 4);
                if level == 1 {
                    if out.len() >= want {
                        break;
                    }
                    out.push((child, 1));
                } else if child != 0 {
                    children.push((child, level - 1));
                }
            }
            // Keep file order: the first child must be expanded first.
            children.reverse();
            pending.extend(children);
        }
        out.truncate(want);
        if out.is_empty() {
            return None;
        }
        let complete = out.iter().all(|&(b, _)| b != 0);
        Some((out, complete))
    }

    /// The file's content, and whether every byte of it came from the disk.
    fn read_file(&self, raw: &[u8], inode: &Inode) -> Option<(Vec<u8>, bool)> {
        let (ranges, mut ok) = self.block_map(raw, inode)?;
        let mut data: Vec<u8> = Vec::with_capacity(inode.size.min(8 << 20) as usize);
        for (phys, count) in ranges {
            let need = inode.size.saturating_sub(data.len() as u64);
            if need == 0 {
                break;
            }
            let want = count.saturating_mul(self.block_size).min(need);
            if phys == 0 {
                // A sparse hole, or a pointer the delete cleared: the file is
                // not all here, and a zero-filled gap must be flagged.
                data.resize(data.len() + want as usize, 0);
                ok = false;
                continue;
            }
            let at = self
                .base
                .saturating_add(phys.saturating_mul(self.block_size));
            let chunk = self.src.pread(at, want as usize);
            if chunk.is_empty() {
                ok = false;
                break;
            }
            data.extend_from_slice(&chunk);
        }
        data.truncate(inode.size as usize);
        if (data.len() as u64) < inode.size {
            data.resize(inode.size as usize, 0);
            ok = false;
        }
        Some((data, ok))
    }

    /// `inode -> (name, parent)` from every directory on the volume.
    ///
    /// Both live entries and the stale ones left in a record's slack: when a
    /// file is unlinked its neighbour's `rec_len` is extended over its record,
    /// but the name is usually still sitting there.
    fn directory_names(&self) -> HashMap<u64, (String, u64)> {
        let mut names: HashMap<u64, (String, u64)> = HashMap::new();
        for ino in ROOT_INO..=self.inodes_count {
            let Some(raw) = self.inode_raw(ino) else {
                continue;
            };
            let inode = Self::parse_inode(&raw);
            if !inode.is_dir() || inode.size == 0 || inode.size > 64 * self.block_size {
                continue;
            }
            if let Some((data, _)) = self.read_file(&raw, &inode) {
                self.parse_dirents(&data, ino, &mut names);
            }
        }
        names
    }

    fn parse_dirents(&self, data: &[u8], parent: u64, names: &mut HashMap<u64, (String, u64)>) {
        let n = data.len();
        let mut pos = 0usize;
        while pos + 8 <= n {
            let Some((rec_len, real)) = self.read_dirent(data, pos, parent, names) else {
                pos += 4; // not a record here; step on and try again
                continue;
            };
            // Whatever lies between the end of this entry and the end of its
            // record is slack, and that is where unlinked names survive.
            let mut sp = pos + ((real + 3) & !3);
            while sp + 8 <= pos + rec_len && sp + 8 <= n {
                match self.read_dirent(data, sp, parent, names) {
                    Some((_, sreal)) => sp += ((sreal + 3) & !3).max(4),
                    None => sp += 4,
                }
            }
            pos += rec_len.max(4);
        }
    }

    /// Read one directory entry, recording its name. Returns its record length
    /// and the length actually used by the entry.
    fn read_dirent(
        &self,
        data: &[u8],
        pos: usize,
        parent: u64,
        names: &mut HashMap<u64, (String, u64)>,
    ) -> Option<(usize, usize)> {
        if pos + 8 > data.len() {
            return None;
        }
        let inode = u32le(data, pos);
        let rec_len = u16le(data, pos + 4) as usize;
        let name_len = data[pos + 6] as usize;
        if rec_len < 8 || rec_len % 4 != 0 || pos + 8 + name_len > data.len() {
            return None;
        }
        if name_len > 0 && inode > 0 && inode <= self.inodes_count {
            let raw = &data[pos + 8..pos + 8 + name_len];
            // A name is printable and has no separators in it; anything else is
            // not a name and this is not an entry.
            if raw
                .iter()
                .all(|&c| (0x20..0x7F).contains(&c) && c != b'/' || c >= 0x80)
            {
                let name = String::from_utf8_lossy(raw).to_string();
                if name != "." && name != ".." {
                    names.entry(inode).or_insert((name, parent));
                }
            }
        }
        Some((rec_len, 8 + name_len))
    }
}

fn sanitize(name: &str) -> String {
    let out: String = name
        .chars()
        .map(|c| match c {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    let trimmed = out.trim().trim_matches('.').to_string();
    if trimmed.is_empty() {
        "unnamed".into()
    } else {
        trimmed
    }
}

fn build_paths(names: &HashMap<u64, (String, u64)>) -> HashMap<u64, String> {
    fn walk(
        ino: u64,
        depth: u32,
        names: &HashMap<u64, (String, u64)>,
        cache: &mut HashMap<u64, String>,
    ) -> String {
        if let Some(p) = cache.get(&ino) {
            return p.clone();
        }
        if depth > 64 {
            return "_deep_".into();
        }
        let path = match names.get(&ino) {
            Some((name, parent)) => {
                let prefix = walk(*parent, depth + 1, names, cache);
                let name = sanitize(name);
                if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                }
            }
            None => "_orphan_".into(),
        };
        cache.insert(ino, path.clone());
        path
    }
    let mut cache: HashMap<u64, String> = HashMap::new();
    cache.insert(ROOT_INO, String::new());
    let mut out = HashMap::new();
    for &ino in names.keys() {
        let p = walk(ino, 0, names, &mut cache);
        out.insert(ino, p);
    }
    out
}

/// Find the volume: the offset given, the whole image, or the first ext
/// partition in the table.
pub fn locate(src: &Source, offset: u64) -> Result<Volume<'_>, String> {
    if offset > 0 {
        return Volume::open(src, offset);
    }
    if let Ok(v) = Volume::open(src, 0) {
        return Ok(v);
    }
    for p in crate::partition::parse(src) {
        if let Ok(v) = Volume::open(src, p.start) {
            return Ok(v);
        }
    }
    Err("no ext2/3/4 volume found; pass --offset to point at one \
         (--list-partitions shows what is here)"
        .into())
}

/// What a volume scan turned up, alongside the records.
#[derive(Debug, Clone, Copy)]
pub struct Summary {
    pub block_size: u64,
    pub inodes: u64,
    pub volume_size: u64,
    /// Inodes marked deleted whose block map was already cleared -- the files
    /// exist in the directory listing and nowhere else.
    pub map_gone: u64,
}

/// Recover deleted (and optionally live) files from an ext2/3/4 volume.
pub fn recover(
    src: &Source,
    offset: u64,
    opts: &Options,
    mut on_file: impl FnMut(&FileRecord),
) -> Result<(Vec<FileRecord>, Summary), String> {
    let vol = locate(src, offset)?;
    let names = vol.directory_names();
    let paths = build_paths(&names);
    let mut out = Vec::new();
    let mut map_gone = 0u64;

    for ino in vol.first_ino..=vol.inodes_count {
        let Some(raw) = vol.inode_raw(ino) else {
            continue;
        };
        let inode = Volume::parse_inode(&raw);
        if !inode.is_regular() {
            continue;
        }
        let deleted = inode.times.deleted != 0 || inode.links == 0;
        if !deleted && !opts.include_live {
            continue;
        }
        if inode.size == 0 || inode.size < opts.min_size.max(1) {
            continue;
        }
        let Some((data, complete)) = vol.read_file(&raw, &inode) else {
            // ext4 clears the extent tree when it frees an inode; the file is
            // named in its directory and its content is gone.
            map_gone += 1;
            continue;
        };
        let vpath = paths.get(&ino).cloned().unwrap_or_default();
        let name = if vpath.is_empty() || vpath == "_orphan_" {
            format!("#inode_{ino}")
        } else {
            vpath.clone()
        };
        let ext = std::path::Path::new(&name)
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_else(|| "bin".into());
        let mut path = String::new();
        if !opts.dry_run {
            let rel = if vpath.is_empty() || vpath == "_orphan_" {
                std::path::PathBuf::from("_orphans").join(format!("inode_{ino}.{ext}"))
            } else {
                std::path::PathBuf::from(vpath.trim_start_matches('/'))
            };
            let mut p = std::path::PathBuf::from(&opts.out_dir)
                .join("ext4")
                .join(rel);
            if let Some(parent) = p.parent() {
                if std::fs::create_dir_all(parent).is_err() {
                    continue;
                }
            }
            if p.exists() {
                // A name can be reused; the inode number keeps them apart.
                let stem = p
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "file".into());
                let suffix = p
                    .extension()
                    .map(|e| format!(".{}", e.to_string_lossy()))
                    .unwrap_or_default();
                p = p.with_file_name(format!("{stem}_ino{ino}{suffix}"));
            }
            if std::fs::write(&p, &data).is_err() {
                continue;
            }
            path = p.to_string_lossy().to_string();
        }
        let rec = FileRecord {
            inode: ino,
            name,
            ext,
            size: inode.size,
            sha256: format!("{:x}", Sha256::digest(&data)),
            // A file is only fully accounted for when every block was read and
            // its name was found.
            validated: complete && !vpath.is_empty() && vpath != "_orphan_",
            deleted,
            path,
            timestamps: inode.times,
        };
        on_file(&rec);
        out.push(rec);
    }
    let summary = Summary {
        block_size: vol.block_size,
        inodes: vol.inodes_count,
        volume_size: vol.blocks_count.saturating_mul(vol.block_size),
        map_gone,
    };
    Ok((out, summary))
}

/// Where the free blocks are, from the per-group block bitmaps.
///
/// Each group descriptor points at a bitmap of one bit per block in that group,
/// set when the block is in use. Carving only the clear ones skips every
/// allocated file.
pub fn free_ranges(
    src: &Source,
    offset: u64,
    merge_gap: u64,
) -> Result<crate::ntfs::FreeSpace, String> {
    let vol = locate(src, offset)?;
    if vol.bitmaps.is_empty() || vol.blocks_per_group == 0 {
        return Err("ext volume has no block bitmaps".into());
    }
    let mut runs: Vec<(u64, u64)> = Vec::new();
    let mut run_start: Option<u64> = None;
    for (g, &bitmap_block) in vol.bitmaps.iter().enumerate() {
        let first_block = vol.first_data_block + g as u64 * vol.blocks_per_group;
        let in_group = vol
            .blocks_per_group
            .min(vol.blocks_count.saturating_sub(first_block));
        if in_group == 0 {
            break;
        }
        let bitmap = vol.block(bitmap_block);
        if bitmap.is_empty() {
            // An unreadable bitmap must not be read as "all free": treat the
            // whole group as allocated and say nothing about it.
            if let Some(s) = run_start.take() {
                runs.push((s, first_block - s));
            }
            continue;
        }
        for b in 0..in_group.min(bitmap.len() as u64 * 8) {
            let block_no = first_block + b;
            let in_use = bitmap[(b / 8) as usize] & (1 << (b % 8)) != 0;
            match (in_use, run_start) {
                (false, None) => run_start = Some(block_no),
                (true, Some(s)) => {
                    runs.push((s, block_no - s));
                    run_start = None;
                }
                _ => {}
            }
        }
    }
    if let Some(s) = run_start {
        runs.push((s, vol.blocks_count.saturating_sub(s)));
    }
    let volume_bytes = vol.blocks_count.saturating_mul(vol.block_size);
    let (ranges, free_bytes) = crate::ntfs::ranges_from_free_clusters(
        runs.into_iter(),
        vol.base,
        vol.block_size,
        vol.base.saturating_add(volume_bytes),
        merge_gap,
    );
    Ok(crate::ntfs::FreeSpace {
        ranges,
        free_bytes,
        volume_bytes,
    })
}
