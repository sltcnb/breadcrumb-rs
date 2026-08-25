//! APFS recovery by scanning for superseded copy-on-write objects.
//!
//! APFS never overwrites metadata in place. Every change writes new B-tree
//! nodes and leaves the old ones where they were until the space is reused, so
//! the filesystem-tree leaf that described a now-deleted file is usually still
//! on the disk as a superseded copy. That is what this reads: every block is
//! checked for an FS-tree leaf node, confirmed by its Fletcher-64 checksum, and
//! the records inside are joined across all the versions found:
//!
//! - `DIR_REC`: parent id + name -> file id
//! - `INODE`: file id -> logical size and timestamps
//! - `FILE_EXTENT`: file id + logical offset -> physical block and length
//!
//! Because the objects come from any point in the volume's history, everything
//! here is a deleted-or-superseded record; there is no live/deleted distinction
//! to make. Not decoded: compressed and encrypted streams, and inline data held
//! in an extended attribute rather than in extents.

use crate::reader::Source;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

const NX_MAGIC: &[u8; 4] = b"NXSB";

const OBJ_TYPE_BTREE: u64 = 0x0002; // a B-tree root, which a single-node tree is
const OBJ_TYPE_BTREE_NODE: u64 = 0x0003;
const OBJ_TYPE_MASK: u64 = 0x0000_FFFF;
const SUBTYPE_FSTREE: u64 = 0x0000_000E;
/// ROOT nodes carry a btree_info trailer that is not part of the value area.
const BTREE_INFO_SIZE: usize = 40;

// j-object types, in the top four bits of obj_id_and_type
const J_INODE: u64 = 3;
const J_FILE_EXTENT: u64 = 8;
const J_DIR_REC: u64 = 9;

const INO_EXT_TYPE_DSTREAM: u8 = 8;

const BTNODE_ROOT: u64 = 0x0001;
const BTNODE_LEAF: u64 = 0x0002;
const BTNODE_FIXED_KV: u64 = 0x0004;

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

fn u64le(b: &[u8], o: usize) -> u64 {
    if o + 8 > b.len() {
        return 0;
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

/// The APFS object checksum: Fletcher-64 over the block after the checksum
/// field itself. This is what makes a blind block scan trustworthy -- a random
/// block that looks like a node will not have a matching checksum.
pub fn fletcher64(block: &[u8]) -> [u8; 8] {
    let body = &block[8.min(block.len())..];
    let mut lo: u64 = 0;
    let mut hi: u64 = 0;
    for w in body.chunks_exact(4) {
        let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as u64;
        lo = (lo + v) % 0xFFFF_FFFF;
        hi = (hi + lo) % 0xFFFF_FFFF;
    }
    let c1 = 0xFFFF_FFFFu64 - ((lo + hi) % 0xFFFF_FFFF);
    let c2 = 0xFFFF_FFFFu64 - ((lo + c1) % 0xFFFF_FFFF);
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&(c1 as u32).to_le_bytes());
    out[4..].copy_from_slice(&(c2 as u32).to_le_bytes());
    out
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Timestamps {
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    /// The inode's object id, which is a file's identity on APFS.
    pub file_id: u64,
    pub name: String,
    pub ext: String,
    pub size: u64,
    pub sha256: String,
    pub validated: bool,
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
    pub min_size: u64,
}

#[derive(Default)]
struct Meta {
    size: Option<u64>,
    timestamps: Timestamps,
}

pub struct Container<'a> {
    src: &'a Source,
    base: u64,
    pub block_size: u64,
    pub block_count: u64,
}

impl<'a> Container<'a> {
    pub fn open(src: &'a Source, base: u64) -> Result<Self, String> {
        let sb = src.pread(base, 4096);
        if sb.len() < 4096 || &sb[32..36] != NX_MAGIC {
            return Err("no APFS container superblock (NXSB) here".into());
        }
        let block_size = u32le(&sb, 36);
        if !(512..=(1 << 20)).contains(&block_size) || !block_size.is_power_of_two() {
            return Err("implausible APFS block size".into());
        }
        let block_count = u64le(&sb, 40);
        if block_count == 0 {
            return Err("APFS container claims no blocks".into());
        }
        Ok(Container {
            src,
            base,
            block_size,
            block_count,
        })
    }

    pub fn volume_size(&self) -> u64 {
        self.block_count.saturating_mul(self.block_size)
    }

    /// Is this block an FS-tree leaf node, and does its checksum agree?
    fn is_fstree_leaf(&self, blk: &[u8]) -> bool {
        let otype = u32le(blk, 24) & OBJ_TYPE_MASK;
        if otype != OBJ_TYPE_BTREE && otype != OBJ_TYPE_BTREE_NODE {
            return false;
        }
        if u32le(blk, 28) != SUBTYPE_FSTREE {
            return false;
        }
        if u16le(blk, 32) & BTNODE_LEAF == 0 {
            return false;
        }
        blk.len() >= 8 && blk[..8] == fletcher64(blk)
    }

    /// Read the records out of one leaf node.
    fn parse_leaf(
        &self,
        blk: &[u8],
        inodes: &mut HashMap<u64, Meta>,
        names: &mut HashMap<u64, (String, u64)>,
        extents: &mut HashMap<u64, BTreeMap<u64, (u64, u64)>>,
    ) {
        // btree_node_phys: obj(32), btn_flags(2), btn_level(2), btn_nkeys(4),
        // btn_table_space {off(2), len(2)} at 40.
        let flags = u16le(blk, 32);
        let nkeys = u32le(blk, 36);
        let toc_off = u16le(blk, 40) as usize;
        let toc_len = u16le(blk, 42) as usize;
        let fixed = flags & BTNODE_FIXED_KV != 0;
        let key_area = 56 + toc_off + toc_len;
        // Value offsets count back from the end of the data area.
        let val_base = blk.len().saturating_sub(if flags & BTNODE_ROOT != 0 {
            BTREE_INFO_SIZE
        } else {
            0
        });
        let toc_base = 56 + toc_off;
        if nkeys > 4096 {
            return;
        }
        for i in 0..nkeys as usize {
            let (k_off, v_off, k_len, v_len) = if fixed {
                let e = toc_base + i * 4;
                if e + 4 > blk.len() {
                    break;
                }
                (
                    u16le(blk, e) as usize,
                    u16le(blk, e + 2) as usize,
                    None,
                    None,
                )
            } else {
                let e = toc_base + i * 8;
                if e + 8 > blk.len() {
                    break;
                }
                (
                    u16le(blk, e) as usize,
                    u16le(blk, e + 4) as usize,
                    Some(u16le(blk, e + 2) as usize),
                    Some(u16le(blk, e + 6) as usize),
                )
            };
            let kpos = key_area + k_off;
            if kpos + 8 > blk.len() || v_off > val_base {
                continue;
            }
            let vpos = val_base - v_off;
            self.decode_record(blk, kpos, vpos, k_len, v_len, inodes, names, extents);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_record(
        &self,
        blk: &[u8],
        kpos: usize,
        vpos: usize,
        _k_len: Option<usize>,
        v_len: Option<usize>,
        inodes: &mut HashMap<u64, Meta>,
        names: &mut HashMap<u64, (String, u64)>,
        extents: &mut HashMap<u64, BTreeMap<u64, (u64, u64)>>,
    ) {
        let oid_type = u64le(blk, kpos);
        let obj_id = oid_type & 0x0FFF_FFFF_FFFF_FFFF;
        let jtype = (oid_type >> 60) & 0x0F;

        match jtype {
            J_FILE_EXTENT => {
                if kpos + 16 > blk.len() || v_len.is_none() || vpos + 16 > blk.len() {
                    return;
                }
                let logical = u64le(blk, kpos + 8);
                let length = u64le(blk, vpos) & 0x00FF_FFFF_FFFF_FFFF;
                let phys = u64le(blk, vpos + 8);
                if length == 0 || length > self.volume_size() {
                    return;
                }
                extents
                    .entry(obj_id)
                    .or_default()
                    .insert(logical, (phys, length));
            }
            J_INODE => {
                if v_len.is_none() || vpos + 40 > blk.len() {
                    return;
                }
                let created = ns_to_secs(u64le(blk, vpos + 16));
                let modified = ns_to_secs(u64le(blk, vpos + 24));
                let accessed = if vpos + 48 <= blk.len() {
                    ns_to_secs(u64le(blk, vpos + 40))
                } else {
                    0
                };
                let size = self.inode_dstream_size(blk, vpos);
                // Several versions of one inode can be on the disk; the one
                // that knows its size is the useful one.
                let slot = inodes.entry(obj_id).or_default();
                if slot.size.is_none() {
                    slot.size = size;
                }
                if slot.timestamps.modified == 0 {
                    slot.timestamps = Timestamps {
                        created,
                        modified,
                        accessed,
                    };
                }
            }
            J_DIR_REC => {
                // key: oid_type(8), name length and hash(4), then the name
                if kpos + 12 > blk.len() {
                    return;
                }
                let nlh = u32le(blk, kpos + 8) as usize;
                let name_len = nlh & 0x3FF; // low ten bits, including the NUL
                if name_len == 0 || kpos + 12 + name_len > blk.len() {
                    return;
                }
                let raw = &blk[kpos + 12..kpos + 12 + name_len];
                let raw = raw.split(|&b| b == 0).next().unwrap_or(raw);
                if v_len.is_none() || vpos + 8 > blk.len() {
                    return;
                }
                let file_id = u64le(blk, vpos); // j_drec_val.file_id
                let Ok(name) = std::str::from_utf8(raw) else {
                    return;
                };
                if !name.is_empty() && name != "." && name != ".." {
                    names.entry(file_id).or_insert((name.to_string(), obj_id));
                }
            }
            _ => {}
        }
    }

    /// The logical size, from the inode's DSTREAM extended field.
    ///
    /// j_inode_val is 92 bytes, then an xfield blob: count(2), used(2), then
    /// one 4-byte header per field, then the data, each field 8-byte aligned.
    fn inode_dstream_size(&self, blk: &[u8], vpos: usize) -> Option<u64> {
        let base = vpos + 92;
        if base + 4 > blk.len() {
            return None;
        }
        let num = u16le(blk, base) as usize;
        if num > 64 {
            return None;
        }
        let hdr = base + 4;
        let mut off = hdr + num * 4;
        if off > blk.len() {
            return None;
        }
        for i in 0..num {
            let xtype = *blk.get(hdr + i * 4)?;
            let xlen = u16le(blk, hdr + i * 4 + 2) as usize;
            if xtype == INO_EXT_TYPE_DSTREAM && off + 8 <= blk.len() {
                return Some(u64le(blk, off)); // j_dstream.size comes first
            }
            off += (xlen + 7) & !7;
            if off > blk.len() {
                return None;
            }
        }
        None
    }

    /// Reassemble a file from the extents found for it.
    fn read_extents(&self, exts: &BTreeMap<u64, (u64, u64)>, size: u64) -> (Vec<u8>, bool) {
        let mut data: Vec<u8> = Vec::with_capacity(size.min(8 << 20) as usize);
        let mut ok = true;
        for (&logical, &(phys, length)) in exts {
            if logical != data.len() as u64 {
                // A gap, or extents out of order: some version of this file's
                // map is missing, so what comes out is not the whole file.
                ok = false;
            }
            let want = length.min(size.saturating_sub(data.len() as u64).max(1));
            if phys == 0 {
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
            if data.len() as u64 >= size {
                break;
            }
        }
        data.truncate(size as usize);
        if (data.len() as u64) < size {
            data.resize(size as usize, 0);
            ok = false;
        }
        (data, ok)
    }
}

fn ns_to_secs(t: u64) -> u64 {
    // APFS timestamps are nanoseconds since the Unix epoch.
    t / 1_000_000_000
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

/// Rebuild full paths from the directory records.
///
/// A DIR_REC gives a name and the id of the directory holding it, and the root
/// directory is object id 2, so the chain can be followed up. Where a parent's
/// record did not survive, the name stands on its own.
fn build_paths(names: &HashMap<u64, (String, u64)>) -> HashMap<u64, String> {
    const ROOT_DIR_ID: u64 = 2;
    fn walk(
        id: u64,
        depth: u32,
        names: &HashMap<u64, (String, u64)>,
        cache: &mut HashMap<u64, String>,
    ) -> String {
        if let Some(p) = cache.get(&id) {
            return p.clone();
        }
        if depth > 64 {
            return String::new();
        }
        let path = match names.get(&id) {
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
        cache.insert(id, path.clone());
        path
    }
    let mut cache: HashMap<u64, String> = HashMap::new();
    cache.insert(ROOT_DIR_ID, String::new());
    let mut out = HashMap::new();
    for &id in names.keys() {
        let p = walk(id, 0, names, &mut cache);
        out.insert(id, p);
    }
    out
}

/// Find the container: the offset given, the whole image, or a partition.
pub fn locate(src: &Source, offset: u64) -> Result<Container<'_>, String> {
    if offset > 0 {
        return Container::open(src, offset);
    }
    if let Ok(c) = Container::open(src, 0) {
        return Ok(c);
    }
    for p in crate::partition::parse(src) {
        if let Ok(c) = Container::open(src, p.start) {
            return Ok(c);
        }
    }
    Err("no APFS container found; pass --offset to point at one \
         (--list-partitions shows what is here)"
        .into())
}

#[derive(Debug, Clone, Copy)]
pub struct Summary {
    pub block_size: u64,
    pub volume_size: u64,
    /// FS-tree leaf nodes whose checksum verified.
    pub nodes_found: u64,
    /// Files with extents but no name anywhere on the disk.
    pub unnamed: u64,
}

/// Recover files from the superseded objects on an APFS container.
pub fn recover(
    src: &Source,
    offset: u64,
    opts: &Options,
    mut on_file: impl FnMut(&FileRecord),
) -> Result<(Vec<FileRecord>, Summary), String> {
    let cont = locate(src, offset)?;
    let mut inodes: HashMap<u64, Meta> = HashMap::new();
    let mut names: HashMap<u64, (String, u64)> = HashMap::new();
    let mut extents: HashMap<u64, BTreeMap<u64, (u64, u64)>> = HashMap::new();
    let mut nodes_found = 0u64;

    // Read in large runs rather than a block at a time: the scan covers the
    // whole container.
    let bs = cont.block_size as usize;
    let per_read = (8 << 20) / bs * bs;
    let mut block = 0u64;
    while block < cont.block_count {
        let at = cont.base.saturating_add(block * cont.block_size);
        let buf = cont.src.pread(at, per_read);
        if buf.len() < bs {
            break;
        }
        for chunk in buf.chunks_exact(bs) {
            if cont.is_fstree_leaf(chunk) {
                nodes_found += 1;
                cont.parse_leaf(chunk, &mut inodes, &mut names, &mut extents);
            }
        }
        block += (buf.len() / bs) as u64;
    }

    let paths = build_paths(&names);
    let mut out = Vec::new();
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut unnamed = 0u64;
    let mut ids: Vec<u64> = extents.keys().copied().collect();
    ids.sort_unstable();
    for file_id in ids {
        let exts = &extents[&file_id];
        // Prefer the full path; fall back to the bare name when the parent
        // chain did not survive.
        let named = paths
            .get(&file_id)
            .filter(|p| !p.is_empty())
            .cloned()
            .or_else(|| names.get(&file_id).map(|(n, _)| n.clone()));
        if named.is_none() {
            unnamed += 1;
        }
        let meta = inodes.get(&file_id);
        let size = match meta.and_then(|m| m.size) {
            Some(s) => s,
            // No inode for this file id: fall back to what the extents cover,
            // which is block-aligned and so may carry slack.
            None => exts
                .iter()
                .map(|(&lo, &(_, len))| lo + len)
                .max()
                .unwrap_or(0),
        };
        if size == 0 || size < opts.min_size.max(1) || size > cont.volume_size() {
            continue;
        }
        if !seen.insert((file_id, size)) {
            continue;
        }
        let (data, complete) = cont.read_extents(exts, size);
        if data.is_empty() {
            continue;
        }
        let label = named.clone().unwrap_or_else(|| format!("inode_{file_id}"));
        let ext = std::path::Path::new(&label)
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_else(|| "bin".into());
        let mut path = String::new();
        if !opts.dry_run {
            let dir = std::path::PathBuf::from(&opts.out_dir).join("apfs");
            let rel = if named.is_some() {
                dir.join(label.trim_start_matches('/'))
            } else {
                dir.join("_unnamed").join(format!("inode_{file_id}.{ext}"))
            };
            let mut p = rel;
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
                p = p.with_file_name(format!("{stem}_{file_id}{suffix}"));
            }
            if std::fs::write(&p, &data).is_err() {
                continue;
            }
            path = p.to_string_lossy().to_string();
        }
        let rec = FileRecord {
            file_id,
            name: label,
            ext,
            size,
            sha256: format!("{:x}", Sha256::digest(&data)),
            // Only a file whose map was complete and whose name was found is
            // fully accounted for.
            validated: complete && named.is_some(),
            path,
            timestamps: meta.map(|m| m.timestamps).unwrap_or_default(),
        };
        on_file(&rec);
        out.push(rec);
    }
    let summary = Summary {
        block_size: cont.block_size,
        volume_size: cont.volume_size(),
        nodes_found,
        unnamed,
    };
    Ok((out, summary))
}
