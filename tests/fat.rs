//! FAT and exFAT undelete.
//!
//! The fixtures are volumes made by the operating system, not by this code:
//! `newfs_msdos -F 16` and `newfs_exfat` formatted them, macOS wrote the files
//! and macOS deleted three of them. That matters more here than anywhere else
//! in this tool -- the whole mode depends on what a real implementation leaves
//! behind when it deletes an entry, and a hand-built fixture would only show
//! what this parser expects. They are stored gzipped because most of a
//! filesystem image is zeros.
//!
//! On both volumes: `/deleted.txt` (880 bytes) and `/sub/inner.bin`
//! (5120 bytes) were deleted, `/kept.dat` was left in place, and macOS added
//! its own `._` sidecar files, which are ordinary files too.

use breadcrumb_rs::fat;
use breadcrumb_rs::reader::Source;
use flate2::read::GzDecoder;
use std::io::Read;

struct Tmp(std::path::PathBuf);

/// Tests run concurrently in one process, so each unpacked image needs its own
/// directory -- otherwise one test's cleanup removes another's evidence.
static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl Tmp {
    /// Unpack a fixture image into a temporary directory.
    fn image(name: &str) -> (Self, String) {
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        dir.push(format!("bcrumb-fat-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let gz = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/fat")
            .join(format!("{name}.dd.gz"));
        let mut data = Vec::new();
        GzDecoder::new(
            std::fs::File::open(&gz).unwrap_or_else(|e| panic!("{}: {e}", gz.display())),
        )
        .read_to_end(&mut data)
        .expect("fixture did not decompress");
        let img = dir.join("disk.dd");
        std::fs::write(&img, &data).unwrap();
        let path = img.to_string_lossy().to_string();
        (Tmp(dir), path)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn recover(name: &str, include_live: bool) -> (Vec<fat::FileRecord>, &'static str, Tmp, String) {
    let (dir, img) = Tmp::image(name);
    let src = Source::open(&img).unwrap();
    let opts = fat::Options {
        out_dir: dir.0.join("out").to_string_lossy().to_string(),
        dry_run: false,
        include_live,
        min_size: 0,
    };
    let (records, kind, _cluster) = fat::recover(&src, 0, &opts, |_| {}).expect("recover failed");
    (records, kind, dir, img)
}

fn find<'a>(records: &'a [fat::FileRecord], want: &str) -> &'a fat::FileRecord {
    records
        .iter()
        .find(|r| r.name.to_lowercase().contains(want))
        .unwrap_or_else(|| {
            panic!(
                "{want} not recovered; got {:?}",
                records.iter().map(|r| &r.name).collect::<Vec<_>>()
            )
        })
}

#[test]
fn fat16_recovers_deleted_files_including_one_in_a_subdirectory() {
    let (records, kind, _dir, img) = recover("fat16", false);
    assert_eq!(kind, "fat");
    assert!(records.iter().all(|r| r.deleted));

    // A short name loses its first character to the 0xE5 that marks the entry
    // free; that is the format, not a bug, so it is replaced visibly.
    let txt = find(&records, "eleted.txt");
    assert!(
        txt.name.starts_with('_'),
        "the lost first character should be visible: {}",
        txt.name
    );
    assert_eq!(txt.size, 880);
    assert_eq!(txt.ext, "txt");
    assert!(txt.timestamps.modified > 1_600_000_000, "no modified time");
    assert!(txt.validated);
    assert_eq!(
        std::fs::read(&txt.path).unwrap(),
        b"deleted evidence text\n".repeat(40),
        "recovered content is not the file that was written"
    );

    // The file in the live subdirectory: reaching it means the directory's own
    // chain was followed.
    let inner = find(&records, "nner.bin");
    assert_eq!(inner.size, 5120);
    let want: Vec<u8> = (0..=255u8).cycle().take(5120).collect();
    assert_eq!(std::fs::read(&inner.path).unwrap(), want);

    // The entry offset must point at the directory entry itself: byte 0xE5,
    // which is what an analyst goes to look at.
    let raw = std::fs::read(&img).unwrap();
    assert_eq!(
        raw[txt.offset as usize], 0xE5,
        "offset {} is not a deleted directory entry",
        txt.offset
    );
}

#[test]
fn exfat_recovers_the_full_long_names() {
    let (records, kind, _dir, _img) = recover("exfat", false);
    assert_eq!(kind, "exfat");
    // exFAT clears an in-use bit rather than overwriting a character, so the
    // name survives intact.
    let txt = find(&records, "deleted.txt");
    assert_eq!(txt.name, "deleted.txt");
    assert_eq!(txt.size, 880);
    assert!(txt.deleted);
    assert_eq!(
        std::fs::read(&txt.path).unwrap(),
        b"deleted evidence text\n".repeat(40)
    );
    let inner = find(&records, "inner.bin");
    assert_eq!(inner.name, "inner.bin");
    assert_eq!(inner.size, 5120);
}

#[test]
fn live_files_are_left_out_unless_asked_for() {
    for name in ["fat16", "exfat"] {
        let (deleted_only, _k, _d, _i) = recover(name, false);
        let (with_live, _k2, _d2, _i2) = recover(name, true);
        assert!(
            with_live.len() > deleted_only.len(),
            "{name}: --include-live found nothing extra"
        );
        assert!(
            with_live
                .iter()
                .any(|r| r.name.to_lowercase().contains("kept")),
            "{name}: the file that was never deleted is missing"
        );
        assert!(
            !deleted_only
                .iter()
                .any(|r| r.name.to_lowercase().contains("kept")),
            "{name}: a live file was reported as deleted"
        );
    }
}

#[test]
fn a_volume_that_is_not_fat_is_refused() {
    let mut p = std::env::temp_dir();
    p.push(format!("bcrumb-fat-none-{}.img", std::process::id()));
    std::fs::write(&p, [0x41u8; 65536]).unwrap();
    let src = Source::open(p.to_str().unwrap()).unwrap();
    let opts = fat::Options {
        out_dir: "/dev/null".into(),
        dry_run: true,
        include_live: false,
        min_size: 0,
    };
    let err = fat::recover(&src, 0, &opts, |_| {}).expect_err("accepted");
    assert!(err.contains("FAT"), "{err}");
    let _ = std::fs::remove_file(&p);
}
