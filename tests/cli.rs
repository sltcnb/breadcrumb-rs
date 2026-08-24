//! Search, partition, and report outputs.

mod builders;

use breadcrumb_rs::carver::{Options, Record};
use breadcrumb_rs::reader::Source;
use breadcrumb_rs::{grep, partition, report};
use std::path::PathBuf;

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("breadcrumb-rs-cli-{tag}-{}", std::process::id()));
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

fn write(dir: &Tmp, name: &str, data: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    p
}

#[test]
fn grep_finds_both_ascii_and_utf16_forms() {
    let dir = Tmp::new("grep");
    let needle = "SECRET-TOKEN-42";
    let mut blob = builders::Rng::new(41).bytes(40_000);
    blob[5000..5000 + needle.len()].copy_from_slice(needle.as_bytes());
    let utf16: Vec<u8> = needle
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    blob[20_000..20_000 + utf16.len()].copy_from_slice(&utf16);
    let path = write(&dir, "img.bin", &blob);
    let src = Source::open(path.to_str().unwrap()).unwrap();

    let mut hits: Vec<(u64, &'static str)> = Vec::new();
    let n = grep::search(&src, &[needle.to_string()], 0, 0, false, 0, |h| {
        hits.push((h.offset, h.encoding));
        assert!(
            h.context.contains(needle),
            "context lost the match: {}",
            h.context
        );
    });
    assert_eq!(n, 2);
    hits.sort();
    assert_eq!(hits, vec![(5000, "ascii"), (20_000, "utf-16le")]);

    // case-insensitive matching, and the hit cap
    let n = grep::search(&src, &["secret-token-42".into()], 0, 0, true, 1, |_| {});
    assert_eq!(n, 1, "--max-hits should stop the scan");
    let n = grep::search(&src, &["secret-token-42".into()], 0, 0, false, 0, |_| {});
    assert_eq!(n, 0, "case-sensitive search must not match");
}

#[test]
fn mbr_partitions_and_filesystem_detection() {
    let dir = Tmp::new("parts");
    let mut img = vec![0u8; 40 << 20];
    let entry = |ptype: u8, lba: u32, count: u32| -> Vec<u8> {
        let mut e = vec![0u8; 16];
        e[4] = ptype;
        e[8..12].copy_from_slice(&lba.to_le_bytes());
        e[12..16].copy_from_slice(&count.to_le_bytes());
        e
    };
    img[446..462].copy_from_slice(&entry(0x07, 2048, 20480));
    img[462..478].copy_from_slice(&entry(0x0B, 22528, 20480));
    img[510..512].copy_from_slice(b"\x55\xaa");
    // an NTFS boot sector and a FAT32 one at those offsets
    let ntfs_at = 2048usize * 512;
    img[ntfs_at + 3..ntfs_at + 11].copy_from_slice(b"NTFS    ");
    img[ntfs_at + 510..ntfs_at + 512].copy_from_slice(b"\x55\xaa");
    let fat_at = 22528usize * 512;
    img[fat_at + 82..fat_at + 90].copy_from_slice(b"FAT32   ");
    img[fat_at + 11..fat_at + 13].copy_from_slice(&512u16.to_le_bytes());
    img[fat_at + 13] = 8;
    img[fat_at + 14..fat_at + 16].copy_from_slice(&32u16.to_le_bytes());
    img[fat_at + 510..fat_at + 512].copy_from_slice(b"\x55\xaa");

    let path = write(&dir, "disk.dd", &img);
    let src = Source::open(path.to_str().unwrap()).unwrap();
    let parts = partition::parse(&src);
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].start, ntfs_at as u64);
    assert_eq!(parts[0].fstype, "ntfs");
    assert_eq!(partition::fs_to_mode(parts[0].fstype), Some("ntfs"));
    assert_eq!(parts[1].fstype, "fat");
    assert!(partition::format_table(&parts).contains("FAT32"));
    assert!(partition::format_table(&[]).contains("no partitions"));
}

fn sample_records() -> Vec<Record> {
    vec![
        Record {
            kind: "png",
            ext: "png",
            offset: 0x1a00,
            size: 92,
            sha256: "a".repeat(64),
            validated: true,
            path: "out/png/f_000000001a00.png".into(),
            duplicate_of: None,
        },
        Record {
            kind: "zip",
            ext: "docx",
            offset: 0x2c00,
            size: 4096,
            sha256: "b".repeat(64),
            validated: false,
            path: String::new(),
            duplicate_of: Some(0x1a00),
        },
    ]
}

#[test]
fn derived_reports_carry_every_record() {
    let recs = sample_records();

    let csv = report::csv(&recs);
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(
        lines[0],
        "type,ext,offset,size,sha256,validated,confidence,duplicate_of,path"
    );
    assert_eq!(lines.len(), 3);
    assert!(lines[1].contains(",True,high,,"), "{}", lines[1]);
    assert!(lines[2].contains(",False,low,6656,"), "{}", lines[2]);

    // bodyfile: md5-slot|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
    let body = report::bodyfile(&recs);
    for line in body.lines() {
        assert_eq!(line.split('|').count(), 11);
    }
    assert!(
        body.contains("carved_0x2c00.docx"),
        "unpathed carve needs a name"
    );

    let tl = report::timeline(&recs);
    assert!(tl.starts_with("offset,ext,size,sha256,confidence,path\n"));
    assert_eq!(tl.lines().count(), 3);

    let html = report::html("/ev/disk.E01", 1 << 30, &recs, 1.25);
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("/ev/disk.E01"));
    assert!(html.contains("docx"));
    assert!(html.contains("1.25s"));
}

#[test]
fn html_escapes_values_from_the_image() {
    // Extensions and paths are ours, but a source path comes from the command
    // line and must not be able to inject markup into the report.
    let recs = sample_records();
    let html = report::html("<script>alert(1)</script>", 100, &recs, 0.1);
    assert!(!html.contains("<script>alert"));
    assert!(html.contains("&lt;script&gt;"));
}

#[test]
fn dry_run_default_options_are_unchanged() {
    // Guards the defaults the CLI relies on.
    let o = Options::default();
    assert_eq!(o.chunk_size, 32 << 20);
    assert!(o.skip_carved && o.dedup && o.skip_blank);
    assert_eq!(o.align, 1);
    assert_eq!(o.jobs, 1);
}
