//! NTFS undelete: walk the MFT and recover deleted files.
//!
//! Carving finds file *content* by its bytes. This finds files by their
//! metadata, which is what recovers the things carving cannot: original names,
//! directory paths, and the created/modified/accessed/MFT-changed timestamps.
//! It also recovers fragmented files intact, because the runlist says where the
//! pieces are.
//!
//! What it will not do: compressed or encrypted streams are skipped rather than
//! written out as garbage, and a file whose clusters have been reused comes back
//! with whatever is there now — flagged low confidence, never silently.

use crate::artifacts;
use crate::reader::Source;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Write;

/// 1601-01-01 to 1970-01-01, in 100 ns units.
const FILETIME_EPOCH: u64 = 116_444_736_000_000_000;

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

fn filetime_to_unix(ft: u64) -> u64 {
    if ft <= FILETIME_EPOCH {
        return 0;
    }
    (ft - FILETIME_EPOCH) / 10_000_000
}

#[derive(Default, Clone, Copy)]
pub struct Timestamps {
    pub created: u64,
    pub modified: u64,
    pub changed: u64,
    pub accessed: u64,
}

pub struct FileRecord {
    /// MFT record number: the file's identity in this volume.
    pub mft: u64,
    /// Reconstructed path inside the volume, plus `~stream` for a named stream.
    pub name: String,
    pub ext: String,
    pub size: u64,
    pub sha256: String,
    /// Every run read inside the volume and nothing was reused or padded.
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

/// One extent of a stream. `None` is a sparse run, which reads as zeros.
type Run = (Option<u64>, u64);

#[derive(Clone)]
struct Attribute {
    atype: u64,
    name: String,
    resident: bool,
    flags: u64,
    content: Vec<u8>,
    real_size: u64,
    runs: Option<Vec<Run>>,
}

pub struct Volume<'a> {
    src: &'a Source,
    pub base: u64,
    pub cluster: u64,
    bps: u64,
    pub volume_size: u64,
    pub record_size: u64,
    pub record_count: u64,
    mft_runs: Vec<Run>,
}

impl<'a> Volume<'a> {
    pub fn open(src: &'a Source, base: u64) -> Result<Self, String> {
        let boot = src.pread(base, 512);
        if boot.len() < 512 || &boot[3..11] != b"NTFS    " {
            return Err("no NTFS boot sector at this offset".into());
        }
        let bps = u16le(&boot, 11);
        let spc = boot[13] as u64;
        if !matches!(bps, 512 | 1024 | 2048 | 4096) || spc == 0 {
            return Err("implausible NTFS geometry".into());
        }
        let cluster = bps * spc;
        let total_sectors = u64le(&boot, 40);
        let volume_size = total_sectors.saturating_mul(bps);
        let mft_lcn = u64le(&boot, 48);
        // Clusters per MFT record, or -log2(bytes) when negative.
        let cpr = boot[64];
        let record_size = if cpr > 127 {
            1u64 << (256 - cpr as u64)
        } else {
            (cpr as u64).saturating_mul(cluster)
        };
        if !(256..=65536).contains(&record_size) {
            return Err("implausible MFT record size".into());
        }

        let mut vol = Volume {
            src,
            base,
            cluster,
            bps,
            volume_size,
            record_size,
            record_count: 0,
            mft_runs: Vec::new(),
        };
        // The MFT can be fragmented, so its own record 0 has to be read first
        // to find the rest of it.
        let first = src.pread(
            base.saturating_add(mft_lcn.saturating_mul(cluster)),
            record_size as usize,
        );
        let rec0 = vol
            .fixup(&first)
            .ok_or("cannot read $MFT record 0 (not an NTFS volume, or damaged)")?;
        let mut mft_size = 0u64;
        for attr in vol.attributes(&rec0) {
            if attr.atype == 0x80 && attr.name.is_empty() {
                if let Some(runs) = attr.runs {
                    vol.mft_runs = runs;
                    mft_size = attr.real_size;
                }
            }
        }
        if vol.mft_runs.is_empty() {
            return Err("cannot map the $MFT data runs".into());
        }
        vol.record_count = mft_size / record_size;
        Ok(vol)
    }

    /// Concatenate runs into `length` bytes; sparse runs read as zeros.
    /// Allocated bytes of a stream, up to `cap`, with sparse holes skipped
    /// rather than materialised as zeros.
    ///
    /// The change journal is a sparse file whose hole is most of its declared
    /// length, so reading it the ordinary way would mean gigabytes of nothing.
    fn read_allocated(&self, runs: &[Run], cap: usize) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for &(lcn, count) in runs {
            if out.len() >= cap {
                break;
            }
            let Some(lcn) = lcn else { continue };
            let bytes = count.saturating_mul(self.cluster);
            if lcn.saturating_add(count).saturating_mul(self.cluster) > self.volume_size {
                continue; // run points outside the volume: not this file's any more
            }
            let want = (bytes as usize).min(cap - out.len());
            let at = self.base.saturating_add(lcn.saturating_mul(self.cluster));
            let mut done = 0usize;
            while done < want {
                let chunk = self.src.pread(at + done as u64, (want - done).min(8 << 20));
                if chunk.is_empty() {
                    break;
                }
                done += chunk.len();
                out.extend_from_slice(&chunk);
            }
        }
        out
    }

    fn read_runs(&self, runs: &[Run], length: u64) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(length.min(1 << 24) as usize);
        for &(lcn, count) in runs {
            if out.len() as u64 >= length {
                break;
            }
            let want = (count.saturating_mul(self.cluster)).min(length - out.len() as u64);
            match lcn {
                None => out.resize(out.len() + want as usize, 0),
                Some(lcn) => {
                    let at = self.base.saturating_add(lcn.saturating_mul(self.cluster));
                    let chunk = self.src.pread(at, want as usize);
                    if chunk.is_empty() {
                        break;
                    }
                    out.extend_from_slice(&chunk);
                }
            }
        }
        out
    }

    /// Check the FILE signature and apply the update sequence fixups.
    ///
    /// The last two bytes of every sector in a record are replaced by a
    /// sequence number when it is written; the originals live in the fixup
    /// array. A record whose sequence numbers disagree was torn mid-write and
    /// is rejected rather than parsed as if it were whole.
    fn fixup(&self, rec: &[u8]) -> Option<Vec<u8>> {
        if rec.len() < 48 || &rec[..4] != b"FILE" {
            return None;
        }
        let usa_off = u16le(rec, 4) as usize;
        let usa_count = u16le(rec, 6) as usize;
        if usa_count < 1 || usa_off + usa_count * 2 > rec.len() {
            return None;
        }
        let mut out = rec.to_vec();
        let usn = [out[usa_off], out[usa_off + 1]];
        for i in 1..usa_count {
            let sec_end = i * self.bps as usize;
            if sec_end < 2 || sec_end > out.len() {
                break;
            }
            let at = sec_end - 2;
            if out[at..at + 2] != usn {
                return None; // torn write
            }
            let src = usa_off + i * 2;
            out[at] = rec[src];
            out[at + 1] = rec[src + 1];
        }
        Some(out)
    }

    /// Read MFT record `num` through the MFT's own runlist.
    /// Walk every MFT record, reading the table in large blocks.
    ///
    /// One `pread` per record means millions of tiny reads, each of them going
    /// through BitLocker decryption and an EWF chunk decode: listing a 1.4
    /// million record MFT that way took hours, on an image that carves at
    /// 90 MiB/s. The table is contiguous within each run, so it is read a few
    /// megabytes at a time and the records are sliced out of the buffer.
    pub fn for_each_record(&self, mut f: impl FnMut(u64, &[u8])) {
        const BLOCK: u64 = 8 << 20;
        let mut num = 0u64;
        for &(lcn, count) in &self.mft_runs {
            let run_bytes = count.saturating_mul(self.cluster);
            let Some(lcn) = lcn else {
                // A sparse run holds no records, but it still advances the
                // numbering.
                num += run_bytes / self.record_size;
                continue;
            };
            let run_start = self.base.saturating_add(lcn.saturating_mul(self.cluster));
            let mut done = 0u64;
            while done < run_bytes && num < self.record_count {
                let want = BLOCK.min(run_bytes - done);
                let buf = self.src.pread(run_start + done, want as usize);
                if buf.is_empty() {
                    return;
                }
                let got = buf.len() as u64;
                let mut at = 0u64;
                while at + self.record_size <= got && num < self.record_count {
                    let raw = &buf[at as usize..(at + self.record_size) as usize];
                    if let Some(rec) = self.fixup(raw) {
                        f(num, &rec);
                    }
                    at += self.record_size;
                    num += 1;
                }
                // A short read leaves a partial record; pick it up next time.
                done += at;
                if at == 0 {
                    break;
                }
            }
        }
    }

    pub fn record(&self, num: u64) -> Option<Vec<u8>> {
        let mut remaining = num.saturating_mul(self.record_size);
        for &(lcn, count) in &self.mft_runs {
            let run_bytes = count.saturating_mul(self.cluster);
            if remaining < run_bytes {
                let lcn = lcn?; // a sparse MFT run holds no records
                let at = self
                    .base
                    .saturating_add(lcn.saturating_mul(self.cluster))
                    .saturating_add(remaining);
                return self.fixup(&self.src.pread(at, self.record_size as usize));
            }
            remaining -= run_bytes;
        }
        None
    }

    /// Decode a runlist into extents. `None` in the tuple means sparse.
    fn decode_runs(data: &[u8]) -> Option<Vec<Run>> {
        let mut runs = Vec::new();
        let mut pos = 0usize;
        let mut lcn: i64 = 0;
        while pos < data.len() {
            let header = data[pos];
            pos += 1;
            if header == 0 {
                break;
            }
            let len_sz = (header & 0x0F) as usize;
            let off_sz = (header >> 4) as usize;
            if len_sz == 0 || pos + len_sz + off_sz > data.len() {
                return None;
            }
            let mut count = 0u64;
            for i in 0..len_sz {
                count |= (data[pos + i] as u64) << (8 * i);
            }
            pos += len_sz;
            if off_sz == 0 {
                runs.push((None, count)); // sparse
                continue;
            }
            // The offset is a signed delta from the previous run's start.
            let mut delta: i64 = 0;
            for i in 0..off_sz {
                delta |= (data[pos + i] as i64) << (8 * i);
            }
            let sign_bit = 1i64 << (off_sz * 8 - 1);
            if delta & sign_bit != 0 {
                delta -= sign_bit << 1;
            }
            pos += off_sz;
            lcn += delta;
            if lcn < 0 || count == 0 {
                return None;
            }
            runs.push((Some(lcn as u64), count));
        }
        Some(runs)
    }

    fn attributes(&self, rec: &[u8]) -> Vec<Attribute> {
        let mut out = Vec::new();
        let mut pos = u16le(rec, 20) as usize;
        let used = (u32le(rec, 24) as usize).min(rec.len());
        while pos + 8 <= used {
            let atype = u32le(rec, pos);
            if atype == 0xFFFF_FFFF {
                break;
            }
            let alen = u32le(rec, pos + 4) as usize;
            if alen < 16 || pos + alen > used {
                break;
            }
            let resident = rec[pos + 8] == 0;
            let namelen = rec[pos + 9] as usize;
            let nameoff = u16le(rec, pos + 10) as usize;
            let name = if namelen > 0 && pos + nameoff + namelen * 2 <= rec.len() {
                rec[pos + nameoff..pos + nameoff + namelen * 2]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .filter_map(|u| char::from_u32(u as u32))
                    .collect()
            } else {
                String::new()
            };
            let flags = u16le(rec, pos + 12);
            let mut attr = Attribute {
                atype,
                name,
                resident,
                flags,
                content: Vec::new(),
                real_size: 0,
                runs: None,
            };
            if resident {
                let csize = u32le(rec, pos + 16) as usize;
                let coff = u16le(rec, pos + 20) as usize;
                if pos + coff + csize <= rec.len() {
                    attr.content = rec[pos + coff..pos + coff + csize].to_vec();
                }
            } else {
                let runoff = u16le(rec, pos + 32) as usize;
                attr.real_size = u64le(rec, pos + 48);
                if pos + runoff <= pos + alen && pos + alen <= rec.len() {
                    attr.runs = Self::decode_runs(&rec[pos + runoff..pos + alen]);
                }
            }
            out.push(attr);
            pos += alen;
        }
        out
    }
}

struct Info {
    num: u64,
    in_use: bool,
    is_dir: bool,
    base_record: u64,
    name: String,
    parent: Option<u64>,
    namespace: i32,
    timestamps: Timestamps,
    data: Vec<Stream>,
}

/// One $DATA attribute of a file: the unnamed stream, or a named one.
struct Stream {
    name: String,
    /// Content of a resident stream; empty when the data is in runs.
    content: Vec<u8>,
    runs: Option<Vec<Run>>,
    real_size: u64,
    flags: u64,
    resident: bool,
}

fn parse_record(vol: &Volume, num: u64) -> Option<Info> {
    let rec = vol.record(num)?;
    parse_record_bytes(vol, num, &rec)
}

/// Every attribute belonging to a record, following its attribute list.
///
/// A record holds about a kilobyte. When a file's attributes do not fit -- a
/// heavily fragmented file whose runlist is long, which on a Windows volume
/// means `$UsnJrnl:$J` and every large file that has been rewritten often --
/// NTFS moves them into extension records and leaves an $ATTRIBUTE_LIST behind
/// pointing at them. Reading only the base record finds no $DATA at all and the
/// file looks empty, which is why the change journal came back missing from
/// three real volumes.
fn attributes_with_list(vol: &Volume, rec: &[u8], num: u64) -> Vec<Attribute> {
    let mut out = vol.attributes(rec);
    let list: Vec<Attribute> = out.iter().filter(|a| a.atype == 0x20).cloned().collect();
    if list.is_empty() {
        return out;
    }
    // The list itself can be resident or not.
    let mut entries: Vec<u8> = Vec::new();
    for attr in list {
        if attr.resident {
            entries.extend_from_slice(&attr.content);
        } else if let Some(runs) = attr.runs.as_deref() {
            entries.extend_from_slice(&vol.read_runs(runs, attr.real_size.min(1 << 20)));
        }
    }

    // Entry: type(4) length(2) name length(1) name offset(1) starting VCN(8)
    // base record reference(8) attribute id(2), then the name.
    let mut seen: HashSet<u64> = HashSet::new();
    seen.insert(num);
    let mut pos = 0usize;
    while pos + 26 <= entries.len() {
        let len = u16le(&entries, pos + 4) as usize;
        if len < 26 || pos + len > entries.len() {
            break;
        }
        let reference = u64le(&entries, pos + 16) & 0xFFFF_FFFF_FFFF;
        pos += len;
        // Attributes in the base record are already here; only the extension
        // records need reading, and each of them only once.
        if !seen.insert(reference) {
            continue;
        }
        if let Some(ext) = vol.record(reference) {
            for attr in vol.attributes(&ext) {
                if attr.atype != 0x20 {
                    out.push(attr);
                }
            }
        }
        // A record with thousands of extents still has a bounded list; this
        // stops a damaged one from being walked for ever.
        if seen.len() > 4096 {
            break;
        }
    }
    out
}

fn parse_record_bytes(vol: &Volume, num: u64, rec: &[u8]) -> Option<Info> {
    let flags = u16le(rec, 22);
    let mut info = Info {
        num,
        in_use: flags & 1 != 0,
        is_dir: flags & 2 != 0,
        base_record: u64le(rec, 32) & 0xFFFF_FFFF_FFFF,
        name: String::new(),
        parent: None,
        namespace: -1,
        timestamps: Timestamps::default(),
        data: Vec::new(),
    };
    for attr in attributes_with_list(vol, rec, num) {
        match attr.atype {
            0x10 if attr.resident && attr.content.len() >= 32 => {
                let c = &attr.content;
                info.timestamps = Timestamps {
                    created: filetime_to_unix(u64le(c, 0)),
                    modified: filetime_to_unix(u64le(c, 8)),
                    changed: filetime_to_unix(u64le(c, 16)),
                    accessed: filetime_to_unix(u64le(c, 24)),
                };
            }
            0x30 if attr.resident && attr.content.len() >= 66 => {
                let c = &attr.content;
                let namelen = c[64] as usize;
                let namespace = c[65] as i32;
                if c.len() < 66 + namelen * 2 {
                    continue;
                }
                // Prefer a Win32/POSIX name over the DOS 8.3 alias.
                let better = info.namespace < 0 || (info.namespace == 2 && namespace != 2);
                if better {
                    info.name = c[66..66 + namelen * 2]
                        .chunks(2)
                        .map(|p| u16::from_le_bytes([p[0], p[1]]))
                        .filter_map(|u| char::from_u32(u as u32))
                        .collect();
                    info.parent = Some(u64le(c, 0) & 0xFFFF_FFFF_FFFF);
                    info.namespace = namespace;
                }
            }
            0x80 => {
                // One stream can arrive as several attributes, each carrying a
                // slice of the runlist, when they came from extension records.
                // They are already in starting-VCN order.
                match info.data.iter_mut().find(|s| s.name == attr.name) {
                    Some(existing) => {
                        if let Some(more) = attr.runs.clone() {
                            existing.runs.get_or_insert_with(Vec::new).extend(more);
                            existing.resident = false;
                        }
                        // Only the first fragment carries the real size.
                        if existing.real_size == 0 {
                            existing.real_size = attr.real_size;
                        }
                    }
                    None => info.data.push(Stream {
                        name: attr.name.clone(),
                        content: attr.content.clone(),
                        runs: attr.runs.clone(),
                        real_size: attr.real_size,
                        flags: attr.flags,
                        resident: attr.resident,
                    }),
                }
            }
            _ => {}
        }
    }
    Some(info)
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect()
}

/// Reconstruct each record's path by walking parent references to the root.
/// What rebuilding a path needs, and nothing else.
///
/// The MFT of a working Windows volume holds well over a million records. Held
/// as full `Info` values -- names, timestamps, and a `Vec<Stream>` per file --
/// that is gigabytes, and three volumes walked at once exhausted a 36 GB
/// machine. This is about eighty bytes a record instead, so the table stays in
/// the low hundreds of megabytes and each record's streams are dropped as soon
/// as the file is written.
struct PathInfo {
    name: String,
    parent: Option<u64>,
    parent_seq: u64,
    seq: u64,
}

/// First pass: read only what paths are made of.
fn parse_path_info(vol: &Volume, rec: &[u8]) -> Option<PathInfo> {
    // Extension records describe another record's attributes.
    if u64le(rec, 32) & 0xFFFF_FFFF_FFFF != 0 {
        return None;
    }
    let mut best: Option<(i32, String, u64, u64)> = None;
    for attr in vol.attributes(rec) {
        if attr.atype != 0x30 || !attr.resident || attr.content.len() < 66 {
            continue;
        }
        let c = &attr.content;
        let namelen = c[64] as usize;
        let namespace = c[65] as i32;
        if c.len() < 66 + namelen * 2 {
            continue;
        }
        // Prefer a Win32/POSIX name over the DOS 8.3 alias.
        let better = match &best {
            None => true,
            Some((ns, _, _, _)) => *ns == 2 && namespace != 2,
        };
        if better {
            let name: String = c[66..66 + namelen * 2]
                .chunks(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .filter_map(|u| char::from_u32(u as u32))
                .collect();
            let reference = u64le(c, 0);
            best = Some((
                namespace,
                name,
                reference & 0xFFFF_FFFF_FFFF,
                reference >> 48,
            ));
        }
    }
    let (_, name, parent, parent_seq) = best?;
    Some(PathInfo {
        name,
        parent: Some(parent),
        parent_seq,
        seq: u16le(rec, 16),
    })
}

fn build_paths(infos: &HashMap<u64, PathInfo>) -> HashMap<u64, String> {
    let mut cache: HashMap<u64, String> = HashMap::new();
    cache.insert(5, String::new()); // record 5 is the root directory
    fn walk(
        num: u64,
        depth: u32,
        infos: &HashMap<u64, PathInfo>,
        cache: &mut HashMap<u64, String>,
    ) -> String {
        if let Some(p) = cache.get(&num) {
            return p.clone();
        }
        if depth > 64 {
            return "_deep_".into(); // a parent cycle in a damaged MFT
        }
        let path = match infos.get(&num) {
            Some(info) if !info.name.is_empty() && info.parent.is_some() => {
                let parent_num = info.parent.unwrap();
                // A deleted file names its parent by record number *and*
                // sequence. NTFS bumps the sequence every time it reuses a
                // record, so a mismatch means that record now holds a different
                // file -- and the path built through it would be fiction. Seen
                // on real evidence: an 84 MB DLL reported inside a Chrome .pak.
                let reused = infos
                    .get(&parent_num)
                    .is_some_and(|p| info.parent_seq != 0 && p.seq != info.parent_seq);
                if reused {
                    // The ancestry is fiction, but the file's own name is not:
                    // it is written in this record. Losing it would throw away
                    // the one thing an investigator is looking for, so keep the
                    // name and say only that the folder above it is unknown.
                    let unknown = format!("_parent_reused_/{}", sanitize(&info.name));
                    cache.insert(num, unknown.clone());
                    return unknown;
                }
                let parent = walk(parent_num, depth + 1, infos, cache);
                let name = sanitize(&info.name);
                if parent.is_empty() {
                    name
                } else {
                    format!("{parent}/{name}")
                }
            }
            // No name, or a parent that is gone: the file is real but its place
            // in the tree is not recoverable.
            _ => "_orphan_".into(),
        };
        cache.insert(num, path.clone());
        path
    }
    let mut out = HashMap::new();
    for &num in infos.keys() {
        let p = walk(num, 0, infos, &mut cache);
        out.insert(num, p);
    }
    out
}

pub struct Options {
    pub out_dir: String,
    pub dry_run: bool,
    pub include_live: bool,
    pub min_size: u64,
}

/// Walk the MFT and recover deleted files.
pub fn recover(
    src: &Source,
    base: u64,
    opts: &Options,
    on_file: impl FnMut(&FileRecord),
) -> Result<Vec<FileRecord>, String> {
    recover_reporting(src, base, opts, on_file, |_, _| {})
}

/// As `recover`, reporting how far through the MFT it is.
///
/// A walk of a million-record MFT takes minutes and used to say nothing at all
/// until it finished, which makes a slow pass indistinguishable from a hung one.
/// `on_progress` is called with (records walked, records total).
pub fn recover_reporting(
    src: &Source,
    base: u64,
    opts: &Options,
    mut on_file: impl FnMut(&FileRecord),
    mut on_progress: impl FnMut(u64, u64),
) -> Result<Vec<FileRecord>, String> {
    let vol = Volume::open(src, base)?;
    // Pass one: the path table, which is small. Pass two re-reads each record
    // and lets it go again, so a million-record volume no longer has to fit in
    // memory all at once.
    let mut infos: HashMap<u64, PathInfo> = HashMap::new();
    let total = vol.record_count;
    vol.for_each_record(|num, rec| {
        if let Some(info) = parse_path_info(&vol, rec) {
            infos.insert(num, info);
        }
        // First of two passes over the table.
        on_progress(num / 2, total);
    });
    let paths = build_paths(&infos);
    drop(infos);
    let mut out = Vec::new();

    // Collect the parsed records in one block-read sweep rather than
    // fetching each by number: a per-record read costs a BitLocker
    // decrypt and an EWF chunk decode, and there are over a million.
    // Each record is handled as it is read and then dropped. Collecting them
    // first costs a gigabyte per few hundred thousand files -- the mistake this
    // pass was rewritten to avoid.
    vol.for_each_record(|num, rec| {
        on_progress(total / 2 + num / 2, total);
        let Some(info) = parse_record_bytes(&vol, num, rec) else {
            return;
        };
        if info.base_record != 0 || info.is_dir || info.data.is_empty() || info.name.is_empty() {
            return;
        }
        if info.in_use && !opts.include_live {
            return;
        }
        let vpath = paths.get(&num).cloned().unwrap_or_default();
        for stream in &info.data {
            if let Some(rec) = recover_stream(&vol, &info, &vpath, stream, opts) {
                on_file(&rec);
                out.push(rec);
            }
        }
    });
    Ok(out)
}

fn recover_stream(
    vol: &Volume,
    info: &Info,
    vpath: &str,
    stream: &Stream,
    opts: &Options,
) -> Option<FileRecord> {
    let flags = stream.flags;
    let mut validated = true;

    // Resident data lives in the record itself and is at most a kilobyte or so.
    // Everything else is written a block at a time: reading a stream into
    // memory first meant $BadClus:$Bad -- a sparse stream as large as the whole
    // volume -- asking for 236 GB of allocation, which killed the process with
    // no message on a real examination.
    let size = if stream.resident {
        stream.content.len() as u64
    } else {
        stream.real_size
    };
    if size < opts.min_size.max(1) {
        return None;
    }
    let runs: &[Run] = if stream.resident {
        &[]
    } else {
        let runs = stream.runs.as_deref()?;
        // Compressed (0x0001) or encrypted (0x4000) streams: the raw clusters
        // are not the file, so writing them out would be worse than nothing.
        if flags & 0x4001 != 0 {
            return None;
        }
        // Entirely sparse: there is nothing on the disk to recover, only a
        // declared length. $BadClus is exactly this on a healthy volume.
        if runs.iter().all(|&(lcn, _)| lcn.is_none()) {
            return None;
        }
        // A run pointing outside the volume means the runlist is not this
        // file's any more.
        if !runs.iter().all(|&(lcn, cnt)| match lcn {
            None => true,
            Some(l) => l.saturating_add(cnt).saturating_mul(vol.cluster) <= vol.volume_size,
        }) {
            return None;
        }
        runs
    };

    let label = if stream.name.is_empty() {
        vpath.to_string()
    } else {
        format!("{vpath}~{}", stream.name)
    };

    // A dry run is an inventory: names, sizes and timestamps. Hashing would
    // mean reading every file on the volume -- on a 237 GB disk that is the
    // whole disk, to answer a question about metadata.
    if opts.dry_run {
        let ext = std::path::Path::new(&info.name)
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_else(|| "bin".into());
        return Some(FileRecord {
            mft: info.num,
            name: label,
            ext,
            size,
            sha256: String::new(),
            validated: !info.in_use,
            deleted: !info.in_use,
            path: String::new(),
            timestamps: info.timestamps,
        });
    }

    let mut hasher = Sha256::new();
    let mut out_path = String::new();
    let mut file = None;
    if !opts.dry_run {
        let rel = label.trim_start_matches('/');
        let mut p = std::path::PathBuf::from(&opts.out_dir)
            .join("ntfs")
            .join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok()?;
        }
        if p.exists() {
            // Two records can claim the same path; keep both, named by record.
            let stem = p.file_stem().map(|s| s.to_string_lossy().to_string())?;
            let ext = p.extension().map(|e| format!(".{}", e.to_string_lossy()));
            let fname = format!("{stem}_mft{}{}", info.num, ext.unwrap_or_default());
            p = p.with_file_name(fname);
        }
        file = Some(std::io::BufWriter::new(std::fs::File::create(&p).ok()?));
        out_path = p.to_string_lossy().to_string();
    }

    let mut written = 0u64;
    let mut emit = |chunk: &[u8]| -> bool {
        hasher.update(chunk);
        match file.as_mut() {
            Some(f) => f.write_all(chunk).is_ok(),
            None => true,
        }
    };
    if stream.resident {
        if !emit(&stream.content) {
            return None;
        }
    } else {
        const BLOCK: u64 = 8 << 20;
        let zeros = vec![0u8; BLOCK as usize];
        'runs: for &(lcn, count) in runs {
            let mut left = count.saturating_mul(vol.cluster).min(size - written);
            let mut at = lcn.map(|l| vol.base + l * vol.cluster);
            while left > 0 {
                let want = left.min(BLOCK);
                let ok = match at {
                    // A sparse run inside a real file is a hole: zeros belong
                    // there, and they cost nothing to write.
                    None => emit(&zeros[..want as usize]),
                    Some(pos) => {
                        let blk = vol.src.pread(pos, want as usize);
                        if blk.is_empty() {
                            validated = false;
                            break 'runs;
                        }
                        at = Some(pos + blk.len() as u64);
                        let n = blk.len() as u64;
                        let ok = emit(&blk);
                        left -= n.min(left);
                        written += n;
                        if !ok {
                            return None;
                        }
                        continue;
                    }
                };
                if !ok {
                    return None;
                }
                left -= want;
                written += want;
            }
        }
        if written < size {
            // Volume edge, or a short read: pad and say the file is not whole.
            validated = false;
            let mut left = size - written;
            while left > 0 {
                let want = left.min(BLOCK);
                if !emit(&vec![0u8; want as usize]) {
                    return None;
                }
                left -= want;
            }
        }
    }
    if let Some(mut f) = file {
        f.flush().ok()?;
    }

    let ext = std::path::Path::new(&info.name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_else(|| "bin".into());

    Some(FileRecord {
        mft: info.num,
        name: label,
        ext,
        size,
        sha256: format!("{:x}", hasher.finalize()),
        validated: validated && !info.in_use,
        deleted: !info.in_use,
        path: out_path,
        timestamps: info.timestamps,
    })
}

/// A file read out of the MFT and handed to another parser instead of being
/// written to disk.
pub struct Extracted {
    /// Full virtual path, with `~stream` appended for a named stream.
    pub path: String,
    pub name: String,
    pub mft: u64,
    pub deleted: bool,
    pub data: Vec<u8>,
}

/// Read the files whose path and stream name `want` accepts, live or deleted.
///
/// This is how the deletion artefacts are collected: `$Recycle.Bin/$I*` and
/// `$Extend/$UsnJrnl:$J` are ordinary files, so the MFT walk already knows
/// where they are. `cap` bounds each stream.
pub fn extract(
    src: &Source,
    base: u64,
    want: impl Fn(&str, &str) -> bool,
    cap: usize,
) -> Result<Vec<Extracted>, String> {
    let vol = Volume::open(src, base)?;
    // Same two passes as `recover`: a compact path table, then one record at a
    // time. Holding every record's attributes cost gigabytes on a real volume.
    let mut infos: HashMap<u64, PathInfo> = HashMap::new();
    vol.for_each_record(|num, rec| {
        if let Some(info) = parse_path_info(&vol, rec) {
            infos.insert(num, info);
        }
    });
    let paths = build_paths(&infos);
    drop(infos);
    let mut out = Vec::new();
    // Collect the parsed records in one block-read sweep rather than
    // fetching each by number: a per-record read costs a BitLocker
    // decrypt and an EWF chunk decode, and there are over a million.
    vol.for_each_record(|num, rec| {
        let Some(info) = parse_record_bytes(&vol, num, rec) else {
            return;
        };
        if info.base_record != 0 || info.is_dir || info.name.is_empty() {
            return;
        }
        let info = &info;
        let vpath = paths.get(&num).cloned().unwrap_or_default();
        for stream in &info.data {
            if !want(&vpath.to_lowercase(), &stream.name) {
                continue;
            }
            let data = if stream.resident {
                stream.content.clone()
            } else {
                match stream.runs.as_deref() {
                    // Compressed or encrypted: the raw clusters are not the file.
                    Some(runs) if stream.flags & 0x4001 == 0 => vol.read_allocated(runs, cap),
                    _ => continue,
                }
            };
            if data.is_empty() {
                continue;
            }
            let label = if stream.name.is_empty() {
                vpath.clone()
            } else {
                format!("{vpath}~{}", stream.name)
            };
            out.push(Extracted {
                path: label,
                name: info.name.clone(),
                mft: num,
                deleted: !info.in_use,
                data,
            });
        }
    });
    Ok(out)
}

/// What a volume's deletion artefacts yielded: the events, and how many came
/// from each artefact so a report can name its sources.
pub struct Deletions {
    pub events: Vec<artifacts::DeletionEvent>,
    pub sources: Vec<(String, usize)>,
}

/// Collect deletion events from a volume's `$Recycle.Bin` and change journal.
pub fn deletion_events(
    src: &Source,
    base: u64,
    deletions_only: bool,
    cap: usize,
) -> Result<Deletions, String> {
    let found = extract(
        src,
        base,
        |path, stream| {
            let file = path.rsplit('/').next().unwrap_or(path);
            // $I records live in the recycle bin; the journal is the $J stream
            // of $Extend/$UsnJrnl.
            (file.starts_with("$i") && file.len() > 2 && path.contains("recycle"))
                || (file.contains("usnjrnl") && (stream == "$J" || stream.is_empty()))
        },
        cap,
    )?;
    let mut events = Vec::new();
    let mut tally = Vec::new();
    for item in found {
        let before = events.len();
        if item.name.to_lowercase().contains("usnjrnl") {
            events.extend(artifacts::events_from_usn(&item.data, deletions_only));
        } else {
            events.extend(artifacts::events_from_recycle(&item.data, &item.name));
        }
        tally.push((item.path, events.len() - before));
    }
    Ok(Deletions {
        events,
        sources: tally,
    })
}

/// The unallocated regions of a volume, as absolute byte ranges.
pub struct FreeSpace {
    pub ranges: Vec<(u64, u64)>,
    pub free_bytes: u64,
    pub volume_bytes: u64,
}

impl FreeSpace {
    pub fn fraction(&self) -> f64 {
        if self.volume_bytes == 0 {
            0.0
        } else {
            self.free_bytes as f64 / self.volume_bytes as f64
        }
    }
}

/// Turn a run of free cluster numbers into coalesced byte ranges.
///
/// Runs separated by less than `merge_gap` are joined: reading a little
/// allocated data costs less than the seek and the per-range overhead of
/// avoiding it, and it keeps the range count sane on a fragmented volume.
pub(crate) fn ranges_from_free_clusters(
    free: impl Iterator<Item = (u64, u64)>,
    base: u64,
    cluster: u64,
    volume_end: u64,
    merge_gap: u64,
) -> (Vec<(u64, u64)>, u64) {
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut free_bytes = 0u64;
    for (first, count) in free {
        let start = base.saturating_add(first.saturating_mul(cluster));
        let end = start
            .saturating_add(count.saturating_mul(cluster))
            .min(volume_end);
        if end <= start {
            continue;
        }
        free_bytes += end - start;
        match ranges.last_mut() {
            Some(last) if start.saturating_sub(last.1) <= merge_gap => last.1 = end,
            _ => ranges.push((start, end)),
        }
    }
    (ranges, free_bytes)
}

/// Where the free clusters are, from `$Bitmap`.
///
/// `$Bitmap` is MFT record 6 and holds one bit per cluster, least significant
/// bit first, set when the cluster is in use. Carving only the clear ones skips
/// every allocated file -- which is both the bulk of a full disk and the source
/// of most spurious carves, since a stray header inside an allocated archive or
/// installer is what produces them.
pub fn free_ranges(src: &Source, base: u64, merge_gap: u64) -> Result<FreeSpace, String> {
    let vol = Volume::open(src, base)?;
    let info = parse_record(&vol, 6).ok_or("NTFS $Bitmap (record 6) is unreadable")?;
    let stream = info
        .data
        .iter()
        .find(|s| s.name.is_empty())
        .ok_or("NTFS $Bitmap has no unnamed $DATA")?;
    let bitmap = if stream.resident {
        stream.content.clone()
    } else {
        let runs = stream
            .runs
            .as_deref()
            .ok_or("NTFS $Bitmap is non-resident with no runlist")?;
        vol.read_runs(runs, stream.real_size)
    };
    if bitmap.is_empty() {
        return Err("NTFS $Bitmap is empty".into());
    }
    let clusters = vol.volume_size.checked_div(vol.cluster).unwrap_or(0);
    if clusters == 0 {
        return Err("NTFS volume has no clusters".into());
    }
    // Bits past the end of the volume are not clusters, whatever they say.
    let counted = clusters.min(bitmap.len() as u64 * 8);
    let mut runs: Vec<(u64, u64)> = Vec::new();
    let mut run_start: Option<u64> = None;
    for c in 0..counted {
        let byte = bitmap[(c / 8) as usize];
        let in_use = byte & (1 << (c % 8)) != 0;
        match (in_use, run_start) {
            (false, None) => run_start = Some(c),
            (true, Some(s)) => {
                runs.push((s, c - s));
                run_start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = run_start {
        runs.push((s, counted - s));
    }
    let volume_end = base.saturating_add(vol.volume_size);
    let (ranges, free_bytes) =
        ranges_from_free_clusters(runs.into_iter(), base, vol.cluster, volume_end, merge_gap);
    Ok(FreeSpace {
        ranges,
        free_bytes,
        volume_bytes: vol.volume_size,
    })
}
