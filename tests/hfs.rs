//! HFS+ undelete through the catalog B-tree.
//!
//! The fixture is a volume `newfs_hfs -J` created and macOS wrote three files
//! to. One record was then unlinked on disk the way a delete leaves it: its
//! offset taken out of its node's record array and the record count lowered,
//! with the record bytes and the file data untouched. macOS itself no longer
//! lists that file on the volume, which is the proof that it is deleted; this
//! mode's job is to find it anyway.
//!
//! Worth knowing, and measured on macOS before writing this: deleting a file
//! through the OS on a journaled HFS+ volume usually leaves *no* catalog record
//! at all -- of 100 files deleted that way, 0 names were still on the volume.
//! When that is what happened, this mode has nothing to work with and carving
//! is the only route left. What it recovers is records that survive: nodes with
//! stale entries, journal copies, and nodes dropped from the tree.

use breadcrumb_rs::hfs;
use breadcrumb_rs::reader::Source;
use flate2::read::GzDecoder;
use std::io::Read;

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct Tmp(std::path::PathBuf);

impl Tmp {
    fn image() -> (Self, String) {
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        dir.push(format!("bcrumb-hfs-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let gz = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/hfs/hfsplus.dd.gz");
        let mut data = Vec::new();
        GzDecoder::new(
            std::fs::File::open(&gz).unwrap_or_else(|e| panic!("{}: {e}", gz.display())),
        )
        .read_to_end(&mut data)
        .expect("fixture did not decompress");
        let img = dir.join("disk.dd");
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

fn recover(include_live: bool) -> (Vec<hfs::FileRecord>, hfs::Summary, Tmp) {
    let (dir, img) = Tmp::image();
    let src = Source::open(&img).unwrap();
    let opts = hfs::Options {
        out_dir: dir.0.join("out").to_string_lossy().to_string(),
        dry_run: false,
        include_live,
        min_size: 0,
        scan_volume: true,
    };
    let (records, summary) = hfs::recover(&src, 0, &opts, |_| {}).expect("recover failed");
    (records, summary, dir)
}

fn find<'a>(records: &'a [hfs::FileRecord], want: &str) -> &'a hfs::FileRecord {
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

#[test]
fn an_unlinked_catalog_record_is_recovered_with_its_name_and_content() {
    let (records, summary, _dir) = recover(false);
    assert!(summary.node_size >= 512);
    assert_eq!(records.len(), 1, "{records:#?}");
    let rec = find(&records, "target.txt");
    assert!(rec.deleted);
    assert_eq!(rec.size, 924);
    assert_eq!(rec.ext, "txt");
    assert!(rec.validated);
    assert!(rec.cnid > 0);
    assert!(rec.timestamps.created > 1_600_000_000, "no created time");
    assert!(rec.timestamps.modified > 1_600_000_000, "no modified time");
    assert_eq!(
        std::fs::read(&rec.path).unwrap(),
        b"the record for this file will be unlinked\n".repeat(22),
        "recovered content is not the file that was written"
    );
    assert_eq!(summary.from_slack, 1, "the record was not counted as stale");
}

#[test]
fn live_files_keep_their_paths_and_are_not_called_deleted() {
    let (records, _summary, _dir) = recover(true);
    // The file in a subdirectory shows the parent chain was rebuilt.
    let inner = find(&records, "inner.bin");
    assert!(!inner.deleted, "a live file was reported as deleted");
    assert_eq!(inner.name, "sub/inner.bin");
    let want: Vec<u8> = (0..=255u8).cycle().take(6400).collect();
    assert_eq!(std::fs::read(&inner.path).unwrap(), want);

    let kept = find(&records, "kept.dat");
    assert!(!kept.deleted);
    // ...and the deleted one is still there and still marked deleted.
    assert!(find(&records, "target.txt").deleted);
}

#[test]
fn a_volume_that_is_not_hfs_is_refused() {
    let mut p = std::env::temp_dir();
    p.push(format!("bcrumb-hfs-none-{}.img", std::process::id()));
    std::fs::write(&p, [0x41u8; 65536]).unwrap();
    let src = Source::open(p.to_str().unwrap()).unwrap();
    let opts = hfs::Options {
        out_dir: "/dev/null".into(),
        dry_run: true,
        ..Default::default()
    };
    let err = hfs::recover(&src, 0, &opts, |_| {}).expect_err("accepted");
    assert!(err.contains("HFS"), "{err}");
    let _ = std::fs::remove_file(&p);
}
