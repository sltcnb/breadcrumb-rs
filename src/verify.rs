//! Check an image against the hashes its acquisition recorded.
//!
//! A carve is worth no more than the image under it. EWF stores the MD5 (and
//! usually SHA-1) computed while the disk was read; recomputing them over the
//! decoded data is what says the image is intact and complete — the first thing
//! anyone reviewing the work will ask, and the check that catches a missing
//! segment or a truncated acquisition before any conclusions rest on it.

use crate::reader::Source;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub struct Outcome {
    pub bytes: u64,
    pub md5: [u8; 16],
    pub sha1: [u8; 20],
    pub sha256: [u8; 32],
    pub stored_md5: Option<[u8; 16]>,
    pub stored_sha1: Option<[u8; 20]>,
}

impl Outcome {
    /// None when the image records nothing to compare against.
    pub fn matches(&self) -> Option<bool> {
        let mut checked = false;
        let mut ok = true;
        if let Some(want) = self.stored_md5 {
            checked = true;
            ok &= want == self.md5;
        }
        if let Some(want) = self.stored_sha1 {
            checked = true;
            ok &= want == self.sha1;
        }
        checked.then_some(ok)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hash every byte of the source, reporting progress through `on_progress`.
pub fn verify(src: &Source, mut on_progress: impl FnMut(u64, u64)) -> Result<Outcome, String> {
    let stored = src.stored_hashes();
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let total = src.size();
    let mut pos = 0u64;
    while pos < total {
        let block = src.pread(pos, 8 << 20);
        if block.is_empty() {
            return Err(format!(
                "read failed at {pos:#x} after {pos} of {total} bytes: the image \
                 is truncated, or a segment is missing"
            ));
        }
        md5.update(&block);
        sha1.update(&block);
        sha256.update(&block);
        pos += block.len() as u64;
        on_progress(pos, total);
    }
    Ok(Outcome {
        bytes: total,
        md5: md5.finalize().into(),
        sha1: sha1.finalize().into(),
        sha256: sha256.finalize().into(),
        stored_md5: stored.md5,
        stored_sha1: stored.sha1,
    })
}
