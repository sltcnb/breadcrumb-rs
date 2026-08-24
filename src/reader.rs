//! Read-only random access over an image file or block device.
//!
//! The source is opened read-only and never written to, the same guarantee the
//! Python implementation makes: `File::open` requests read access only, and no
//! code path here holds a writable handle to the source.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::FileExt;

/// Container formats this port still cannot read. Carving their bytes as if
/// they were raw yields a manifest full of nonsense -- fragments of compressed
/// chunk data -- with no sign that anything went wrong, so refuse instead.
/// The Python implementation reads all of these.
const CONTAINERS: &[(&[u8], &str)] = &[
    (b"EVF2\x0d\x0a\x81\x00", "EWF2/Ex01"),
    (b"LVF\x09\x0d\x0a\xff\x00", "EWF logical (L01)"),
    (b"conectix", "VHD"),
    (b"vhdxfile", "VHDX"),
];

/// Extensions that name a container even when the magic is unreadable, so a
/// misnamed or truncated first segment is still caught.
const CONTAINER_EXTS: &[(&str, &str)] = &[
    (".ex01", "EWF2/Ex01"),
    (".l01", "EWF logical (L01)"),
    (".vhd", "VHD"),
    (".vhdx", "VHDX"),
    (".aff", "AFF"),
];

/// EWF (`.E01`/`.s01`) is read natively; see `ewf.rs`.
const EWF_MAGIC: &[u8] = b"EVF\x09\x0d\x0a\xff\x00";
const EWF_EXTS: &[&str] = &[".e01", ".s01"];

fn container_kind(path: &str, head: &[u8]) -> Option<&'static str> {
    for (magic, name) in CONTAINERS {
        if head.starts_with(magic) {
            return Some(name);
        }
    }
    let lower = path.to_ascii_lowercase();
    CONTAINER_EXTS
        .iter()
        .find(|(ext, _)| lower.ends_with(ext))
        .map(|(_, name)| *name)
}

fn looks_like_ewf(path: &str, head: &[u8]) -> bool {
    let lower = path.to_ascii_lowercase();
    head.starts_with(EWF_MAGIC) || EWF_EXTS.iter().any(|e| lower.ends_with(e))
}

/// The image behind a scan.
pub enum Source {
    Raw(Reader),
    Ewf(crate::ewf::EwfReader),
    Split(crate::images::SplitRawReader),
    Qcow2(crate::images::Qcow2Reader),
    Vmdk(crate::images::VmdkReader),
    Stdin(crate::images::StdinReader),
}

impl Source {
    pub fn open(path: &str) -> io::Result<Self> {
        if path == "-" || path == "/dev/stdin" {
            return Ok(Source::Stdin(crate::images::StdinReader::spool(
                io::stdin(),
            )?));
        }
        // A numbered segment with a sibling behind it is a split raw image.
        if let Some((stem, digits)) = crate::images::split_segment_name(path) {
            let width = digits.len();
            let n: u64 = digits.parse().unwrap_or(0);
            let next = format!("{stem}.{:0width$}", n + 1, width = width);
            if Path::new(&next).exists() || n <= 1 {
                if let Ok(r) = crate::images::SplitRawReader::open(path) {
                    return Ok(Source::Split(r));
                }
            }
        }
        let mut file = File::open(Path::new(path))?;
        let mut head = [0u8; 16];
        let n = file.read(&mut head).unwrap_or(0);
        drop(file);
        let head = &head[..n];
        if head.starts_with(b"QFI\xfb") {
            return Ok(Source::Qcow2(crate::images::Qcow2Reader::open(path)?));
        }
        if head.starts_with(b"KDMV") {
            return Ok(Source::Vmdk(crate::images::VmdkReader::open(path)?));
        }
        if let Some(kind) = container_kind(path, head) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "this is a {kind} image, which this port cannot read -- \
                     carving it as raw would report the container's own bytes \
                     as recovered files. Use the Python implementation \
                     (https://github.com/sltcnb/BreadCrumb), which reads it \
                     directly, or convert to raw first."
                ),
            ));
        }
        if looks_like_ewf(path, head) {
            return Ok(Source::Ewf(crate::ewf::EwfReader::open(path)?));
        }
        Ok(Source::Raw(Reader::open(path)?))
    }

    pub fn size(&self) -> u64 {
        match self {
            Source::Raw(r) => r.size,
            Source::Ewf(e) => e.size,
            Source::Split(s) => s.size,
            Source::Qcow2(q) => q.size,
            Source::Vmdk(v) => v.size,
            Source::Stdin(s) => s.size,
        }
    }

    pub fn pread(&self, offset: u64, len: usize) -> Vec<u8> {
        match self {
            Source::Raw(r) => r.pread(offset, len),
            Source::Ewf(e) => e.pread(offset, len),
            Source::Split(s) => s.pread(offset, len),
            Source::Qcow2(q) => q.pread(offset, len),
            Source::Vmdk(v) => v.pread(offset, len),
            Source::Stdin(s) => s.pread(offset, len),
        }
    }

    pub fn path(&self) -> &str {
        match self {
            Source::Raw(r) => &r.path,
            Source::Ewf(e) => &e.path,
            Source::Split(s) => &s.path,
            Source::Qcow2(q) => &q.path,
            Source::Vmdk(v) => &v.path,
            Source::Stdin(s) => &s.path,
        }
    }

    /// Short description of what was opened, for the scan banner.
    pub fn describe(&self) -> String {
        match self {
            Source::Raw(r) if r.is_device => " (device)".into(),
            Source::Raw(_) => String::new(),
            Source::Ewf(e) => format!(" (EWF, {} segment(s))", e.segment_count()),
            Source::Split(s) => format!(" (split raw, {} segment(s))", s.count),
            Source::Qcow2(_) => " (QCOW2)".into(),
            Source::Vmdk(_) => " (VMDK sparse)".into(),
            Source::Stdin(_) => " (spooled from stdin)".into(),
        }
    }
}

pub struct Reader {
    file: File,
    pub size: u64,
    pub path: String,
    pub is_device: bool,
}

impl Reader {
    pub fn open(path: &str) -> io::Result<Self> {
        let mut file = File::open(Path::new(path))?;
        let mut head = [0u8; 16];
        let n = file.read(&mut head).unwrap_or(0);
        file.seek(SeekFrom::Start(0))?;
        if let Some(kind) = container_kind(path, &head[..n]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "this is a {kind} image, which this port cannot read -- \
                     carving it as raw would report the container's own bytes \
                     as recovered files. Use the Python implementation \
                     (https://github.com/sltcnb/BreadCrumb), which reads it \
                     directly, or convert to raw first."
                ),
            ));
        }
        let meta = file.metadata()?;
        let (size, is_device) = if meta.is_file() {
            (meta.len(), false)
        } else {
            // Block/character device: length comes from seeking to the end.
            let mut f = &file;
            let end = f.seek(SeekFrom::End(0))?;
            (end, true)
        };
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cannot determine size of {path:?}"),
            ));
        }
        Ok(Reader {
            file,
            size,
            path: path.to_string(),
            is_device,
        })
    }

    /// Read up to `len` bytes at `offset`. A short result means EOF.
    pub fn pread(&self, offset: u64, len: usize) -> Vec<u8> {
        if offset >= self.size || len == 0 {
            return Vec::new();
        }
        let len = len.min((self.size - offset) as usize);
        let mut buf = vec![0u8; len];
        let mut done = 0usize;
        while done < len {
            match self.read_at(&mut buf[done..], offset + done as u64) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        buf.truncate(done);
        buf
    }

    #[cfg(unix)]
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        self.file.read_at(buf, offset)
    }

    #[cfg(windows)]
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        use std::os::windows::fs::FileExt;
        self.file.seek_read(buf, offset)
    }
}
