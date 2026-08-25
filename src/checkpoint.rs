//! Scan checkpoints, so a run that dies can pick up where it stopped.
//!
//! A 238 GB image takes long enough that a power cut, a full disk or a killed
//! process should not mean starting over. The scan records which byte ranges it
//! has finished into a small state file beside the output; on `--resume` those
//! ranges are skipped and the records already in the manifest are carried
//! forward.
//!
//! The file is deliberately dull: a source fingerprint, then one line per
//! completed range. It is appended to as ranges complete, so a run killed
//! mid-write loses at most the last line.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const STATE_FILE: &str = ".bcrumb-state";

/// What a checkpoint is for: resuming the same scan of the same image, not a
/// different one. Recorded so a mismatched resume is refused.
#[derive(Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub source: String,
    pub size: u64,
    pub types: String,
}

impl Fingerprint {
    fn encode(&self) -> String {
        format!(
            "source={}\nsize={}\ntypes={}\n",
            self.source, self.size, self.types
        )
    }
}

pub struct Checkpoint {
    path: PathBuf,
    pub fingerprint: Fingerprint,
    /// Completed [start, end) ranges, merged and sorted.
    pub done: Vec<(u64, u64)>,
    file: Option<File>,
}

impl Checkpoint {
    pub fn path_for(out_dir: &str) -> PathBuf {
        Path::new(out_dir).join(STATE_FILE)
    }

    /// Start a checkpoint, or load an existing one for the same scan.
    ///
    /// A state file describing a different source, size or type set is refused
    /// rather than silently skipping ranges of the wrong image.
    pub fn open(out_dir: &str, fingerprint: Fingerprint, resume: bool) -> Result<Self, String> {
        let path = Self::path_for(out_dir);
        let mut done = Vec::new();
        if resume && path.exists() {
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let mut seen = Fingerprint {
                source: String::new(),
                size: 0,
                types: String::new(),
            };
            for line in BufReader::new(text.as_bytes())
                .lines()
                .map_while(Result::ok)
            {
                if let Some(v) = line.strip_prefix("source=") {
                    seen.source = v.to_string();
                } else if let Some(v) = line.strip_prefix("size=") {
                    seen.size = v.parse().unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("types=") {
                    seen.types = v.to_string();
                } else if let Some(v) = line.strip_prefix("done=") {
                    if let Some((a, b)) = v.split_once('-') {
                        if let (Ok(a), Ok(b)) = (a.parse(), b.parse()) {
                            done.push((a, b));
                        }
                    }
                }
            }
            if seen != fingerprint {
                return Err(format!(
                    "{} describes a different scan (source {:?}, {} bytes, types {:?}); \
                     remove it or point --output elsewhere",
                    path.display(),
                    seen.source,
                    seen.size,
                    seen.types
                ));
            }
        }
        std::fs::create_dir_all(out_dir).map_err(|e| format!("{out_dir}: {e}"))?;
        let fresh = done.is_empty();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if fresh {
            file.write_all(fingerprint.encode().as_bytes())
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        merge(&mut done);
        Ok(Checkpoint {
            path,
            fingerprint,
            done,
            file: Some(file),
        })
    }

    /// Record a finished range. Flushed immediately: a checkpoint that is still
    /// in a buffer when the process dies is worth nothing.
    pub fn complete(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        self.done.push((start, end));
        merge(&mut self.done);
        if let Some(f) = self.file.as_mut() {
            let mut line = String::new();
            let _ = writeln!(line, "done={start}-{end}");
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }

    /// The parts of [start, end) still to scan.
    pub fn remaining(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut pos = start;
        for &(a, b) in &self.done {
            if b <= pos || a >= end {
                continue;
            }
            if a > pos {
                out.push((pos, a.min(end)));
            }
            pos = pos.max(b);
            if pos >= end {
                break;
            }
        }
        if pos < end {
            out.push((pos, end));
        }
        out
    }

    pub fn bytes_done(&self) -> u64 {
        self.done.iter().map(|(a, b)| b - a).sum()
    }

    /// Remove the state file: the scan finished, so there is nothing to resume.
    pub fn finish(self) {
        drop(self.file);
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Sort and coalesce touching or overlapping ranges.
fn merge(ranges: &mut Vec<(u64, u64)>) {
    if ranges.is_empty() {
        return;
    }
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for &(a, b) in ranges.iter() {
        match out.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    *ranges = out;
}
