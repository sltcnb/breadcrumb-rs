//! Read-only random access over an image file or block device.
//!
//! The source is opened read-only and never written to, the same guarantee the
//! Python implementation makes: `File::open` requests read access only, and no
//! code path here holds a writable handle to the source.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// Container formats this port cannot read. Carving their bytes as if they
/// were raw yields a manifest full of nonsense -- fragments of compressed
/// chunk data -- with no sign that anything went wrong, so refuse instead.
/// The Python implementation reads all of these.
const CONTAINERS: &[(&[u8], &str)] = &[
    (b"EVF\x09\x0d\x0a\xff\x00", "EWF/E01"),
    (b"EVF2\x0d\x0a\x81\x00", "EWF2/Ex01"),
    (b"LVF\x09\x0d\x0a\xff\x00", "EWF logical (L01)"),
    (b"QFI\xfb", "QCOW2"),
    (b"KDMV", "VMDK"),
    (b"conectix", "VHD"),
    (b"vhdxfile", "VHDX"),
];

/// Extensions that name a container even when the magic is unreadable, so a
/// misnamed or truncated first segment is still caught.
const CONTAINER_EXTS: &[(&str, &str)] = &[
    (".e01", "EWF/E01"),
    (".ex01", "EWF2/Ex01"),
    (".s01", "EWF SMART (s01)"),
    (".l01", "EWF logical (L01)"),
    (".qcow2", "QCOW2"),
    (".vmdk", "VMDK"),
    (".vhd", "VHD"),
    (".vhdx", "VHDX"),
    (".aff", "AFF"),
];

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

#[cfg(unix)]
use std::os::unix::fs::FileExt;

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
