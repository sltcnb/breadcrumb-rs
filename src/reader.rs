//! Read-only random access over an image file or block device.
//!
//! The source is opened read-only and never written to, the same guarantee the
//! Python implementation makes: `File::open` requests read access only, and no
//! code path here holds a writable handle to the source.

use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::path::Path;

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
        let file = File::open(Path::new(path))?;
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
