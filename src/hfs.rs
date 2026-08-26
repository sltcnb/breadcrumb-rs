//! HFS+ / HFSX undelete through the catalog B-tree.
//!
//! The volume header points at the catalog file, a B-tree whose leaf records
//! hold a name, a parent id and the fork extents of every file. Deleting a file
//! unlinks its record from the tree but usually leaves the bytes where they
//! were: in the slack of a leaf node, in nodes the tree has since dropped, or
//! in a journal copy of a node. So this reads records structurally rather than
//! through the record-offset array, which is exactly what a deleted record no
//! longer appears in.
//!
//! Only the eight extents held in the catalog record are followed. A file
//! fragmented beyond that continues in the extents-overflow file, which is not
//! walked here, so such a file comes back truncated and is reported at low
//! confidence rather than as complete.

use crate::reader::Source;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// 1904-01-01 to 1970-01-01, in seconds: the HFS epoch.
const HFS_EPOCH: u64 = 2_082_844_800;
const ROOT_CNID: u64 = 2;

fn u16be(b: &[u8], o: usize) -> u64 {
    if o + 2 > b.len() {
        return 0;
    }
    u16::from_be_bytes([b[o], b[o + 1]]) as u64
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
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_be_bytes(v)
}

fn hfs_time(t: u64) -> u64 {
    if t == 0 {
        0
    } else {
        t.saturating_sub(HFS_EPOCH)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Timestamps {
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    /// Catalog node id, the file's identity on an HFS+ volume.
    pub cnid: u64,
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
    /// Sweep the whole volume for catalog nodes that are no longer part of the
    /// tree. This is where deleted files come from; without it only the live
    /// catalog is read.
    pub scan_volume: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            out_dir: "carved".into(),
            dry_run: false,
            include_live: false,
            min_size: 0,
            scan_volume: true,
        }
    }
}

#[derive(Clone)]
struct Entry {
    cnid: u64,
    name: String,
    size: u64,
    extents: Vec<(u64, u64)>,
    timestamps: Timestamps,
    /// Was this record still listed in its node's record-offset array? Deleting
    /// a file takes its offset out of that array and leaves the record itself
    /// in place, so a record found only by scanning is a deleted file.
    in_tree: bool,
}

pub struct Volume<'a> {
    src: &'a Source,
    base: u64,
    pub block_size: u64,
    pub volume_size: u64,
    catalog_extents: Vec<(u64, u64)>,
    catalog_size: u64,
}

impl<'a> Volume<'a> {
    pub fn open(src: &'a Source, base: u64) -> Result<Self, String> {
        // The volume header sits 1024 bytes into the volume.
        let vh = src.pread(base + 1024, 512);
        if vh.len() < 512 || !(vh.starts_with(b"H+") || vh.starts_with(b"HX")) {
            return Err("no HFS+/HFSX volume header here".into());
        }
        let block_size = u32be(&vh, 40);
        let total_blocks = u32be(&vh, 44);
        if !(512..=(1 << 20)).contains(&block_size) || total_blocks == 0 {
            return Err("implausible HFS+ geometry".into());
        }
        // HFSPlusForkData for the catalog file starts at 272: logicalSize(8),
        // clumpSize(4), totalBlocks(4), then eight (startBlock, blockCount).
        let catalog_size = u64be(&vh, 272);
        let mut catalog_extents = Vec::new();
        for i in 0..8 {
            let at = 272 + 16 + i * 8;
            let start = u32be(&vh, at);
            let count = u32be(&vh, at + 4);
            if count > 0 {
                catalog_extents.push((start, count));
            }
        }
        if catalog_extents.is_empty() {
            return Err("HFS+ catalog file has no extents".into());
        }
        Ok(Volume {
            src,
            base,
            block_size,
            volume_size: total_blocks.saturating_mul(block_size),
            catalog_extents,
            catalog_size,
        })
    }

    /// Read a fork from its extents. The bool says whether every byte came off
    /// the disk rather than being padded.
    fn read_fork(&self, extents: &[(u64, u64)], size: u64) -> (Vec<u8>, bool) {
        let mut data: Vec<u8> = Vec::with_capacity(size.min(8 << 20) as usize);
        let mut ok = true;
        for &(start, count) in extents {
            let need = size.saturating_sub(data.len() as u64);
            if need == 0 {
                break;
            }
            let want = count.saturating_mul(self.block_size).min(need);
            let at = self
                .base
                .saturating_add(start.saturating_mul(self.block_size));
            if at.saturating_add(want) > self.base.saturating_add(self.volume_size) {
                ok = false;
                break;
            }
            let chunk = self.src.pread(at, want as usize);
            if chunk.is_empty() {
                ok = false;
                break;
            }
            data.extend_from_slice(&chunk);
        }
        data.truncate(size as usize);
        if (data.len() as u64) < size {
            // Beyond the eight catalog extents, or a short read: the file is
            // not all here.
            data.resize(size as usize, 0);
            ok = false;
        }
        (data, ok)
    }

    fn catalog_bytes(&self) -> Vec<u8> {
        let declared = if self.catalog_size > 0 {
            self.catalog_size
        } else {
            self.catalog_extents
                .iter()
                .map(|&(_, c)| c)
                .sum::<u64>()
                .saturating_mul(self.block_size)
        };
        // A catalog is large but bounded; refuse to hold an absurd claim.
        let size = declared.min(1 << 30);
        self.read_fork(&self.catalog_extents, size).0
    }

    /// The offsets the node's own record array points at: the live records.
    ///
    /// The array sits at the end of the node, one 2-byte offset per record,
    /// stored in reverse. Deleting a record removes its offset from this array
    /// without touching the record.
    fn live_offsets(node: &[u8]) -> HashSet<usize> {
        let mut out = HashSet::new();
        let num = u16be(node, 10) as usize;
        // A node holds at most one record per eight bytes; more than that means
        // this is not a node.
        if num == 0 || num > node.len() / 8 {
            return out;
        }
        for i in 0..num {
            let at = node.len().saturating_sub(2 * (i + 1));
            if at < 14 {
                break;
            }
            let off = u16be(node, at) as usize;
            if (14..node.len()).contains(&off) {
                out.insert(off);
            }
        }
        out
    }

    /// Parse catalog records out of one node.
    ///
    /// The record-offset array at the end of a node is the ordinary way in, and
    /// it is precisely what a deleted record has been removed from. So records
    /// are found by their own shape instead: keyLength(2), parentCNID(4),
    /// nameLength(2), name in UTF-16BE, then the record type.
    fn scan_node(
        &self,
        node: &[u8],
        names: &mut HashMap<u64, (String, u64)>,
        files: &mut Vec<Entry>,
    ) {
        let live = Self::live_offsets(node);
        let end = node.len();
        let mut pos = 14usize; // past the node descriptor
        while pos + 8 < end {
            let key_len = u16be(node, pos) as usize;
            if !(6..=516).contains(&key_len) || pos + 2 + key_len + 2 > end {
                pos += 2;
                continue;
            }
            let parent = u32be(node, pos + 2);
            let name_len = u16be(node, pos + 6) as usize;
            if name_len > 255 || pos + 8 + name_len * 2 > end {
                pos += 2;
                continue;
            }
            let mut rec_off = pos + 2 + key_len;
            rec_off += rec_off & 1; // records are two-byte aligned
            if rec_off + 2 > end {
                pos += 2;
                continue;
            }
            let rtype = u16be(node, rec_off);
            // 1 folder, 2 file, 3 and 4 are thread records.
            if rtype != 1 && rtype != 2 {
                pos += 2;
                continue;
            }
            let units: Vec<u16> = node[pos + 8..pos + 8 + name_len * 2]
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            if units.is_empty() || units.contains(&0) {
                pos += 2;
                continue;
            }
            let name = String::from_utf16_lossy(&units);
            if rtype == 1 {
                let cnid = u32be(node, rec_off + 8);
                names.entry(cnid).or_insert((name, parent));
                pos = rec_off + 2;
                continue;
            }
            if let Some(mut entry) = self.parse_file_record(node, rec_off, &name) {
                entry.in_tree = live.contains(&pos);
                names.entry(entry.cnid).or_insert((name.clone(), parent));
                files.push(entry);
            }
            pos = rec_off + 2;
        }
    }

    /// HFSPlusCatalogFile: recordType(2) flags(2) reserved(4) fileID(4)
    /// createDate(4) contentModDate(4) attributeModDate(4) accessDate(4)
    /// backupDate(4) bsdInfo(16) userInfo(16) finderInfo(16) textEncoding(4)
    /// reserved(4) then the data fork at +88.
    fn parse_file_record(&self, node: &[u8], off: usize, name: &str) -> Option<Entry> {
        if off + 248 > node.len() {
            return None;
        }
        let cnid = u32be(node, off + 8);
        let created = hfs_time(u32be(node, off + 12));
        let modified = hfs_time(u32be(node, off + 16));
        let accessed = hfs_time(u32be(node, off + 24));
        let fork = off + 88;
        let logical = u64be(node, fork);
        let mut extents = Vec::new();
        for i in 0..8 {
            let at = fork + 16 + i * 8;
            let start = u32be(node, at);
            let count = u32be(node, at + 4);
            if count > 0 {
                extents.push((start, count));
            }
        }
        if logical == 0 || logical > self.volume_size || extents.is_empty() {
            return None;
        }
        Some(Entry {
            cnid,
            name: name.to_string(),
            size: logical,
            extents,
            timestamps: Timestamps {
                created,
                modified,
                accessed,
            },
            // Filled in by the caller, which knows the node's record array.
            in_tree: false,
        })
    }

    /// Sweep the volume for catalog leaf nodes that are not part of the live
    /// tree: journal copies, and nodes the tree compacted away.
    fn scan_volume(
        &self,
        node_size: usize,
        live: &HashSet<u64>,
        names: &mut HashMap<u64, (String, u64)>,
        found: &mut Vec<Entry>,
    ) {
        let mut seen: HashSet<(u64, u64)> = HashSet::new();
        let step: usize = 8 << 20;
        let mut pos = 0u64;
        while pos < self.volume_size {
            let buf = self.src.pread(self.base + pos, step + node_size);
            if buf.len() < 14 {
                break;
            }
            let limit = buf.len().min(step);
            let mut off = 0usize;
            // A journal copy is not aligned to the catalog file's node grid, so
            // every sector boundary is a candidate.
            while off + 14 < buf.len() && off < limit {
                // Node kind -1 (0xFF) marks a leaf node.
                if buf[off + 8] == 0xFF {
                    let node = &buf[off..(off + node_size).min(buf.len())];
                    let mut tmp = Vec::new();
                    self.scan_node(node, names, &mut tmp);
                    for entry in tmp {
                        if live.contains(&entry.cnid) || !seen.insert((entry.cnid, entry.size)) {
                            continue;
                        }
                        found.push(entry);
                    }
                }
                off += 512;
            }
            pos += limit as u64;
        }
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
        cnid: u64,
        depth: u32,
        names: &HashMap<u64, (String, u64)>,
        cache: &mut HashMap<u64, String>,
    ) -> String {
        if let Some(p) = cache.get(&cnid) {
            return p.clone();
        }
        if depth > 64 {
            return String::new();
        }
        let path = match names.get(&cnid) {
            Some((name, parent)) => {
                let prefix = walk(*parent, depth + 1, names, cache);
                let name = sanitize(name);
                if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                }
            }
            None => String::new(),
        };
        cache.insert(cnid, path.clone());
        path
    }
    let mut cache: HashMap<u64, String> = HashMap::new();
    cache.insert(ROOT_CNID, String::new());
    let mut out = HashMap::new();
    for &cnid in names.keys() {
        let p = walk(cnid, 0, names, &mut cache);
        out.insert(cnid, p);
    }
    out
}

/// Find the volume: the offset given, the whole image, or an HFS+ partition.
pub fn locate(src: &Source, offset: u64) -> Result<Volume<'_>, String> {
    if offset > 0 {
        return Volume::open(src, offset);
    }
    if let Ok(v) = Volume::open(src, 0) {
        return Ok(v);
    }
    // Largest first, so a small system partition never wins over the volume
    // that was meant.
    let parts = crate::partition::parse(src);
    let mut candidates: Vec<&crate::partition::Partition> = parts.iter().collect();
    candidates.sort_by_key(|p| std::cmp::Reverse(p.size));
    for p in candidates {
        if let Ok(v) = Volume::open(src, p.start) {
            return Ok(v);
        }
    }
    Err("no HFS+/HFSX volume found; pass --offset to point at one \
         (--list-partitions shows what is here)"
        .into())
}

#[derive(Debug, Clone, Copy)]
pub struct Summary {
    pub block_size: u64,
    pub volume_size: u64,
    pub node_size: u64,
    /// Files recovered from records no longer in the live tree.
    pub from_slack: u64,
}

/// Recover files from an HFS+/HFSX catalog.
pub fn recover(
    src: &Source,
    offset: u64,
    opts: &Options,
    mut on_file: impl FnMut(&FileRecord),
) -> Result<(Vec<FileRecord>, Summary), String> {
    let vol = locate(src, offset)?;
    let catalog = vol.catalog_bytes();
    if catalog.len() < 64 {
        return Err("HFS+ catalog file is unreadable".into());
    }
    // Node 0 is the header node: the descriptor is 14 bytes, and nodeSize sits
    // 18 bytes into the header record that follows it.
    let mut node_size = u16be(&catalog, 32) as usize;
    if node_size < 512 || !node_size.is_power_of_two() {
        node_size = 4096;
    }

    let mut names: HashMap<u64, (String, u64)> = HashMap::new();
    let mut found: Vec<Entry> = Vec::new();
    for n in 0..catalog.len() / node_size {
        let node = &catalog[n * node_size..(n + 1) * node_size];
        vol.scan_node(node, &mut names, &mut found);
    }
    // A record the tree still lists is a live file. One sitting in a node's
    // slack is a file whose entry was unlinked -- the same node, the same
    // bytes, just no longer pointed at.
    let live_cnids: HashSet<u64> = found.iter().filter(|e| e.in_tree).map(|e| e.cnid).collect();
    if opts.scan_volume {
        let mut elsewhere: Vec<Entry> = Vec::new();
        vol.scan_volume(node_size, &live_cnids, &mut names, &mut elsewhere);
        found.extend(elsewhere);
    }
    let paths = build_paths(&names);

    let mut out = Vec::new();
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    // Deleted records first: when the same file turns up twice, the copy that
    // says where it came from should be the one reported.
    found.sort_by_key(|e| e.in_tree);
    for entry in found {
        let is_deleted = !entry.in_tree && !live_cnids.contains(&entry.cnid);
        if !is_deleted && !opts.include_live {
            continue;
        }
        if entry.size < opts.min_size.max(1) {
            continue;
        }
        if !seen.insert((entry.cnid, entry.size)) {
            continue;
        }
        let (data, complete) = vol.read_fork(&entry.extents, entry.size);
        if data.is_empty() {
            continue;
        }
        let vpath = paths.get(&entry.cnid).cloned().unwrap_or_default();
        let label = if vpath.is_empty() {
            entry.name.clone()
        } else {
            vpath.clone()
        };
        let ext = std::path::Path::new(&entry.name)
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_else(|| "bin".into());
        let mut path = String::new();
        if !opts.dry_run {
            let rel = if vpath.is_empty() {
                std::path::PathBuf::from("_orphans").join(format!("cnid_{}.{ext}", entry.cnid))
            } else {
                std::path::PathBuf::from(vpath.trim_start_matches('/'))
            };
            let mut p = std::path::PathBuf::from(&opts.out_dir)
                .join("hfs")
                .join(rel);
            if let Some(parent) = p.parent() {
                if std::fs::create_dir_all(parent).is_err() {
                    continue;
                }
            }
            if p.exists() {
                let stem = p
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "file".into());
                let suffix = p
                    .extension()
                    .map(|e| format!(".{}", e.to_string_lossy()))
                    .unwrap_or_default();
                p = p.with_file_name(format!("{stem}_cnid{}{suffix}", entry.cnid));
            }
            if std::fs::write(&p, &data).is_err() {
                continue;
            }
            path = p.to_string_lossy().to_string();
        }
        let rec = FileRecord {
            cnid: entry.cnid,
            name: label,
            ext,
            size: entry.size,
            sha256: format!("{:x}", Sha256::digest(&data)),
            validated: complete,
            deleted: is_deleted,
            path,
            timestamps: entry.timestamps,
        };
        on_file(&rec);
        out.push(rec);
    }
    let summary = Summary {
        block_size: vol.block_size,
        volume_size: vol.volume_size,
        node_size: node_size as u64,
        // Counted from what was reported, not from what was seen: the same
        // record turns up more than once (a node is read as part of the catalog
        // and again by the volume sweep), and each file should count once.
        from_slack: out.iter().filter(|r| r.deleted).count() as u64,
    };
    Ok((out, summary))
}
