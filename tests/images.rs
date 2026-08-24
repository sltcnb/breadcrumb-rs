//! Image-format reader tests. Split raw and stdin need no tools; QCOW2 and
//! VMDK are checked against qemu-img output where qemu-img is installed.

mod builders;

use breadcrumb_rs::images::{SplitRawReader, StdinReader};
use breadcrumb_rs::reader::Source;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("breadcrumb-rs-img-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn join(&self, n: &str) -> PathBuf {
        self.0.join(n)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn qemu_img() -> Option<String> {
    for cand in [
        "qemu-img",
        "/opt/homebrew/bin/qemu-img",
        "/usr/bin/qemu-img",
    ] {
        if Command::new(cand).arg("--version").output().is_ok() {
            return Some(cand.to_string());
        }
    }
    None
}

/// Raw image with carvable files in it; returns (bytes, sha256).
fn raw_image() -> (Vec<u8>, String) {
    let mut data = vec![0u8; 4096];
    for b in [
        builders::make_png(),
        builders::make_jpeg(),
        builders::make_gif(),
    ] {
        data.extend_from_slice(&[0x11; 2048]);
        data.extend_from_slice(&b);
    }
    data.extend_from_slice(&builders::Rng::new(31).bytes(4096));
    let sha = format!("{:x}", Sha256::digest(&data));
    (data, sha)
}

#[test]
fn split_raw_segments_read_as_one_image() {
    let dir = Tmp::new("split");
    let (data, sha) = raw_image();
    let seg = 5000usize;
    for (i, chunk) in data.chunks(seg).enumerate() {
        std::fs::write(dir.join(&format!("img.{:03}", i + 1)), chunk).unwrap();
    }
    let first = dir.join("img.001");
    let r = SplitRawReader::open(first.to_str().unwrap()).unwrap();
    assert_eq!(r.count, data.len().div_ceil(seg));
    assert_eq!(r.size, data.len() as u64);
    assert_eq!(
        format!("{:x}", Sha256::digest(r.pread(0, r.size as usize))),
        sha
    );
    // a read spanning a segment boundary
    assert_eq!(r.pread(4900, 300), data[4900..5200]);

    // and Source routes a numbered segment to it
    let src = Source::open(first.to_str().unwrap()).unwrap();
    assert!(matches!(src, Source::Split(_)));
    assert!(src.describe().contains("split raw"));
}

#[test]
fn stdin_is_spooled_then_read_randomly() {
    let (data, sha) = raw_image();
    let r = StdinReader::spool(std::io::Cursor::new(data.clone())).unwrap();
    assert_eq!(r.size, data.len() as u64);
    assert_eq!(
        format!("{:x}", Sha256::digest(r.pread(0, r.size as usize))),
        sha
    );
    assert_eq!(r.pread(1000, 256), data[1000..1256]);
    assert_eq!(r.path, "-");
    // the spool file is removed when the reader goes away
    drop(r);
}

#[test]
fn qcow2_and_vmdk_match_the_raw_source() {
    let Some(qemu) = qemu_img() else {
        eprintln!("skipping: qemu-img not installed");
        return;
    };
    let dir = Tmp::new("virt");
    let (data, sha) = raw_image();
    let raw = dir.join("raw.img");
    std::fs::write(&raw, &data).unwrap();

    for (fmt, compress) in [("qcow2", true), ("qcow2", false), ("vmdk", false)] {
        let out = dir.join(&format!("img.{fmt}{}", if compress { "c" } else { "" }));
        let mut cmd = Command::new(&qemu);
        cmd.args(["convert", "-f", "raw", "-O", fmt]);
        if compress {
            cmd.arg("-c");
        }
        cmd.arg(&raw).arg(&out);
        assert!(
            cmd.output().unwrap().status.success(),
            "{fmt}: convert failed"
        );

        let src = Source::open(out.to_str().unwrap()).unwrap();
        match fmt {
            "qcow2" => assert!(matches!(src, Source::Qcow2(_))),
            _ => assert!(matches!(src, Source::Vmdk(_))),
        }
        assert!(src.size() >= data.len() as u64);
        let got = src.pread(0, data.len());
        assert_eq!(
            format!("{:x}", Sha256::digest(&got)),
            sha,
            "{fmt} compressed={compress}: contents differ from the raw source"
        );
    }
}

#[test]
fn unreadable_containers_are_still_refused() {
    let dir = Tmp::new("refuse");
    for (name, magic) in [
        ("img.vhdx", b"vhdxfile\x00\x00\x00\x00".to_vec()),
        ("img.Ex01", b"EVF2\x0d\x0a\x81\x00\x01\x00".to_vec()),
    ] {
        let mut blob = magic;
        blob.extend_from_slice(&[0u8; 4096]);
        let p = dir.join(name);
        std::fs::write(&p, &blob).unwrap();
        let err = Source::open(p.to_str().unwrap()).err().expect("accepted");
        assert!(err.to_string().contains("cannot read"), "{name}: {err}");
    }
}
