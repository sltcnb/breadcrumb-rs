//! ext2/3/4 undelete.
//!
//! The fixtures were built by e2fsprogs, not by this code: `mke2fs` made the
//! volumes, `debugfs` wrote the files and unlinked two of them. `ext4_cleared`
//! goes one step further and zeroes the freed inode's extent tree, which is
//! what the kernel usually does on delete -- the case where the name is
//! recoverable and the content is not.
//!
//! On each volume: `/deleted.txt` (924 bytes) and `/sub/inner.bin` (7680 bytes)
//! were deleted, `/kept.dat` was left alone.

use breadcrumb_rs::ext4;
use breadcrumb_rs::reader::Source;
use flate2::read::GzDecoder;
use std::io::Read;

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct Tmp(std::path::PathBuf);

impl Tmp {
    fn image(name: &str) -> (Self, String) {
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        dir.push(format!("bcrumb-ext-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let gz = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ext")
            .join(format!("{name}.img.gz"));
        let mut data = Vec::new();
        GzDecoder::new(
            std::fs::File::open(&gz).unwrap_or_else(|e| panic!("{}: {e}", gz.display())),
        )
        .read_to_end(&mut data)
        .expect("fixture did not decompress");
        let img = dir.join("disk.img");
        std::fs::write(&img, &data).unwrap();
        let p = img.to_string_lossy().to_string();
        (Tmp(dir), p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn recover(name: &str, include_live: bool) -> (Vec<ext4::FileRecord>, ext4::Summary, Tmp) {
    let (dir, img) = Tmp::image(name);
    let src = Source::open(&img).unwrap();
    let opts = ext4::Options {
        out_dir: dir.0.join("out").to_string_lossy().to_string(),
        dry_run: false,
        include_live,
        min_size: 0,
    };
    let (records, summary) = ext4::recover(&src, 0, &opts, |_| {}).expect("recover failed");
    (records, summary, dir)
}

fn find<'a>(records: &'a [ext4::FileRecord], want: &str) -> &'a ext4::FileRecord {
    records
        .iter()
        .find(|r| r.name.contains(want))
        .unwrap_or_else(|| {
            panic!(
                "{want} not recovered; got {:?}",
                records.iter().map(|r| &r.name).collect::<Vec<_>>()
            )
        })
}

fn deleted_txt() -> Vec<u8> {
    b"deleted ext evidence\n".repeat(44)
}

fn inner_bin() -> Vec<u8> {
    (0..=255u8).cycle().take(7680).collect()
}

#[test]
fn ext2_recovers_names_paths_and_content() {
    let (records, summary, _dir) = recover("ext2", false);
    assert!(summary.block_size >= 1024);
    assert_eq!(records.len(), 2, "{records:#?}");
    assert!(records.iter().all(|r| r.deleted));

    let txt = find(&records, "deleted.txt");
    assert_eq!(txt.name, "deleted.txt", "the original name should survive");
    assert_eq!(txt.size, 924);
    assert!(txt.validated);
    assert!(txt.timestamps.modified > 1_600_000_000);
    // ext records when the inode was freed, which NTFS does not.
    assert!(txt.timestamps.deleted > 0, "no deletion time");
    assert_eq!(std::fs::read(&txt.path).unwrap(), deleted_txt());

    // A file in a subdirectory keeps its path: the directory blocks give
    // inode -> name, and the parent chain gives the rest.
    let inner = find(&records, "inner.bin");
    assert_eq!(inner.name, "sub/inner.bin");
    assert_eq!(inner.size, 7680);
    assert_eq!(std::fs::read(&inner.path).unwrap(), inner_bin());
}

#[test]
fn ext4_extents_are_walked_not_just_block_pointers() {
    // Same volume layout, but the map is an extent tree rather than the
    // ext2-style pointer list.
    let (records, _summary, _dir) = recover("ext4", false);
    assert_eq!(records.len(), 2, "{records:#?}");
    let txt = find(&records, "deleted.txt");
    assert_eq!(std::fs::read(&txt.path).unwrap(), deleted_txt());
    let inner = find(&records, "inner.bin");
    assert_eq!(inner.name, "sub/inner.bin");
    assert_eq!(std::fs::read(&inner.path).unwrap(), inner_bin());
}

#[test]
fn an_inode_whose_map_was_cleared_is_counted_not_invented() {
    // What the kernel usually leaves behind: the directory entry names the
    // file, the extent tree is gone. Reporting an empty file here would be
    // worse than reporting nothing.
    let (records, summary, _dir) = recover("ext4_cleared", false);
    assert_eq!(summary.map_gone, 1, "the cleared inode was not counted");
    assert!(
        !records.iter().any(|r| r.name.contains("deleted.txt")),
        "a file with no block map was reported anyway: {records:#?}"
    );
    // The other deleted file still comes back whole.
    let inner = find(&records, "inner.bin");
    assert_eq!(std::fs::read(&inner.path).unwrap(), inner_bin());
}

#[test]
fn live_files_come_only_when_asked_for() {
    let (deleted_only, _s, _d) = recover("ext4", false);
    let (with_live, _s2, _d2) = recover("ext4", true);
    assert!(with_live.len() > deleted_only.len());
    assert!(with_live.iter().any(|r| r.name.contains("kept.dat")));
    assert!(!deleted_only.iter().any(|r| r.name.contains("kept.dat")));
    assert!(with_live.iter().any(|r| !r.deleted));
}

#[test]
fn a_volume_that_is_not_ext_is_refused() {
    let mut p = std::env::temp_dir();
    p.push(format!("bcrumb-ext-none-{}.img", std::process::id()));
    std::fs::write(&p, [0x41u8; 65536]).unwrap();
    let src = Source::open(p.to_str().unwrap()).unwrap();
    let opts = ext4::Options {
        out_dir: "/dev/null".into(),
        dry_run: true,
        include_live: false,
        min_size: 0,
    };
    let err = ext4::recover(&src, 0, &opts, |_| {}).expect_err("accepted");
    assert!(err.contains("ext"), "{err}");
    let _ = std::fs::remove_file(&p);
}
