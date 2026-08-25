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
use std::collections::HashMap;

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
    let flags = u16le(&rec, 22);
    let mut info = Info {
        num,
        in_use: flags & 1 != 0,
        is_dir: flags & 2 != 0,
        base_record: u64le(&rec, 32) & 0xFFFF_FFFF_FFFF,
        name: String::new(),
        parent: None,
        namespace: -1,
        timestamps: Timestamps::default(),
        data: Vec::new(),
    };
    for attr in vol.attributes(&rec) {
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
            0x80 => info.data.push(Stream {
                name: attr.name.clone(),
                content: attr.content.clone(),
                runs: attr.runs.clone(),
                real_size: attr.real_size,
                flags: attr.flags,
                resident: attr.resident,
            }),
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
fn build_paths(infos: &HashMap<u64, Info>) -> HashMap<u64, String> {
    let mut cache: HashMap<u64, String> = HashMap::new();
    cache.insert(5, String::new()); // record 5 is the root directory
    fn walk(
        num: u64,
        depth: u32,
        infos: &HashMap<u64, Info>,
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
                let parent = walk(info.parent.unwrap(), depth + 1, infos, cache);
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
    mut on_file: impl FnMut(&FileRecord),
) -> Result<Vec<FileRecord>, String> {
    let vol = Volume::open(src, base)?;
    let mut infos: HashMap<u64, Info> = HashMap::new();
    for num in 0..vol.record_count {
        if let Some(info) = parse_record(&vol, num) {
            // Extension records describe attributes of another record; the base
            // record is the one that owns the file.
            if info.base_record == 0 {
                infos.insert(num, info);
            }
        }
    }
    let paths = build_paths(&infos);
    let mut out = Vec::new();
    let mut nums: Vec<u64> = infos.keys().copied().collect();
    nums.sort_unstable();

    for num in nums {
        let info = &infos[&num];
        if info.is_dir || info.data.is_empty() || info.name.is_empty() {
            continue;
        }
        if info.in_use && !opts.include_live {
            continue;
        }
        let vpath = paths.get(&num).cloned().unwrap_or_default();
        for stream in &info.data {
            if let Some(rec) = recover_stream(&vol, info, &vpath, stream, opts) {
                on_file(&rec);
                out.push(rec);
            }
        }
    }
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
    let data: Vec<u8>;
    let size: u64;

    if stream.resident {
        data = stream.content.clone();
        size = data.len() as u64;
    } else {
        let runs = stream.runs.as_deref()?;
        // Compressed (0x0001) or encrypted (0x4000) streams: the raw clusters
        // are not the file, so writing them out would be worse than nothing.
        if flags & 0x4001 != 0 {
            return None;
        }
        size = stream.real_size;
        // A run pointing outside the volume means the runlist is not this
        // file's any more.
        if !runs.iter().all(|&(lcn, cnt)| match lcn {
            None => true,
            Some(l) => l.saturating_add(cnt).saturating_mul(vol.cluster) <= vol.volume_size,
        }) {
            return None;
        }
        let mut got = vol.read_runs(runs, size);
        if (got.len() as u64) < size {
            got.resize(size as usize, 0); // volume edge: pad and flag it
            validated = false;
        }
        data = got;
    }
    if size < opts.min_size.max(1) {
        return None;
    }

    let label = if stream.name.is_empty() {
        vpath.to_string()
    } else {
        format!("{vpath}~{}", stream.name)
    };
    let sha256 = format!("{:x}", Sha256::digest(&data));
    let mut out_path = String::new();
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
        std::fs::write(&p, &data).ok()?;
        out_path = p.to_string_lossy().to_string();
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
        sha256,
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
    let mut infos: HashMap<u64, Info> = HashMap::new();
    for num in 0..vol.record_count {
        if let Some(info) = parse_record(&vol, num) {
            if info.base_record == 0 {
                infos.insert(num, info);
            }
        }
    }
    let paths = build_paths(&infos);
    let mut nums: Vec<u64> = infos.keys().copied().collect();
    nums.sort_unstable();
    let mut out = Vec::new();
    for num in nums {
        let info = &infos[&num];
        if info.is_dir || info.name.is_empty() {
            continue;
        }
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
    }
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
