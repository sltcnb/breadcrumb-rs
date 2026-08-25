//! One disk, several filesystems, one pass.
//!
//! The image is assembled from the volumes the other tests use -- the FAT16 one
//! from `newfs_msdos`, the ext4 one from `mke2fs`, the HFS+ one from
//! `newfs_hfs` -- laid out behind an MBR at 1 MiB alignment, the way a real
//! disk is partitioned. Each volume is still exactly what the OS tool wrote.

use breadcrumb_rs::partition;
use breadcrumb_rs::reader::Source;
use flate2::read::GzDecoder;
use std::io::Read;

const SECTOR: u64 = 512;
const ALIGN: usize = 1 << 20;

struct Tmp(std::path::PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn unpack(rel: &str) -> Vec<u8> {
    let gz = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel);
    let mut data = Vec::new();
    GzDecoder::new(std::fs::File::open(&gz).unwrap_or_else(|e| panic!("{}: {e}", gz.display())))
        .read_to_end(&mut data)
        .expect("fixture did not decompress");
    data
}

/// Build the multi-filesystem disk. Returns its path and the partition offsets.
fn multi_disk(tag: &str) -> (Tmp, String, Vec<u64>) {
    let mut dir = std::env::temp_dir();
    dir.push(format!("bcrumb-auto-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let volumes: [(&str, u8); 3] = [
        ("fat/fat16.dd.gz", 0x06),
        ("ext/ext4.img.gz", 0x83),
        ("hfs/hfsplus.dd.gz", 0xAF),
    ];
    let mut img = vec![0u8; ALIGN];
    let mut entries = Vec::new();
    for (rel, ptype) in volumes {
        let body = unpack(rel);
        let start = img.len();
        img.extend_from_slice(&body);
        let pad = (ALIGN - img.len() % ALIGN) % ALIGN;
        img.extend(std::iter::repeat(0u8).take(pad));
        entries.push((ptype, start as u64 / SECTOR, body.len() as u64 / SECTOR));
    }
    for (i, (ptype, lba, count)) in entries.iter().enumerate() {
        let e = 446 + i * 16;
        img[e + 4] = *ptype;
        img[e + 8..e + 12].copy_from_slice(&(*lba as u32).to_le_bytes());
        img[e + 12..e + 16].copy_from_slice(&(*count as u32).to_le_bytes());
    }
    img[510..512].copy_from_slice(&[0x55, 0xAA]);

    let path = dir.join("multi.dd");
    std::fs::write(&path, &img).unwrap();
    let offsets = entries.iter().map(|(_, lba, _)| lba * SECTOR).collect();
    (Tmp(dir), path.to_string_lossy().to_string(), offsets)
}

#[test]
fn every_partitions_filesystem_is_identified() {
    let (_dir, img, offsets) = multi_disk("detect");
    let src = Source::open(&img).unwrap();
    let parts = partition::parse(&src);
    assert_eq!(parts.len(), 3, "{parts:?}");
    let kinds: Vec<&str> = parts.iter().map(|p| p.fstype).collect();
    // HFS+ keeps its volume header 1024 bytes in, past the first sector: this
    // is the case that used to come back unidentified.
    assert_eq!(kinds, vec!["fat", "ext", "hfs+"]);
    for (p, want) in parts.iter().zip(&offsets) {
        assert_eq!(p.start, *want);
        assert_eq!(partition::detect_fs(&src, p.start), p.fstype);
    }
}

#[test]
fn auto_recovers_from_all_three_volumes_in_one_run() {
    let (dir, img, _offsets) = multi_disk("run");
    let out = dir.0.join("out");
    let csv = dir.0.join("files.csv");
    let exe = env!("CARGO_BIN_EXE_bcrumb-rs");
    let run = std::process::Command::new(exe)
        .arg(&img)
        .arg("--auto")
        .arg("-o")
        .arg(&out)
        .arg("--csv")
        .arg(&csv)
        .arg("-q")
        .output()
        .expect("failed to run");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let text = std::fs::read_to_string(&csv).unwrap();
    let rows: Vec<&str> = text.lines().skip(1).collect();
    assert!(rows.len() >= 6, "too few recoveries:\n{text}");

    // Each filesystem contributed, and each wrote under its own volume
    // directory so identical paths on two volumes cannot collide.
    for (vol, fs, name) in [
        (0, "fat", "ELETED.TXT"),
        (1, "ext4", "deleted.txt"),
        (2, "hfs+", "target.txt"),
    ] {
        let hit = rows
            .iter()
            .find(|r| r.starts_with(&format!("{vol},{fs},")) && r.contains(name))
            .unwrap_or_else(|| panic!("volume {vol} ({fs}) missing {name}:\n{text}"));
        let path = std::path::PathBuf::from(hit.rsplit(',').next().unwrap());
        // Compare path components, not text: Windows separates them with `\`.
        assert!(
            path.components()
                .any(|c| c.as_os_str() == format!("volume{vol}").as_str()),
            "{fs} wrote outside its own volume's directory: {}",
            path.display()
        );
        assert!(
            std::fs::metadata(&path).is_ok(),
            "reported file is not on disk: {}",
            path.display()
        );
    }

    // The manifest lists the volumes it swept, whether or not each yielded
    // anything -- that is the record of what was covered.
    let manifest = std::fs::read_to_string(out.join("manifest.json")).unwrap();
    for fs in ["fat", "ext", "hfs+"] {
        assert!(
            manifest.contains(&format!("\"fs\": \"{fs}\"")),
            "{fs} missing"
        );
    }
}

#[test]
fn an_image_with_no_filesystem_says_so() {
    let mut p = std::env::temp_dir();
    p.push(format!("bcrumb-auto-empty-{}.dd", std::process::id()));
    std::fs::write(&p, vec![0u8; 1 << 20]).unwrap();
    let exe = env!("CARGO_BIN_EXE_bcrumb-rs");
    let run = std::process::Command::new(exe)
        .arg(&p)
        .arg("--auto")
        .arg("--dry-run")
        .output()
        .unwrap();
    assert!(!run.status.success());
    let err = String::from_utf8_lossy(&run.stderr);
    assert!(err.contains("no filesystem"), "{err}");
    let _ = std::fs::remove_file(&p);
}
