//! APFS recovery from superseded copy-on-write objects.
//!
//! The fixture is a container macOS made and wrote to: `diskutil partitionDisk
//! ... APFS`, three files written, two of them deleted through the OS, then
//! unmounted. No editing afterwards -- unlike HFS+, APFS leaves the old
//! filesystem-tree nodes on the disk, which is exactly why this works: the
//! deleted files' records are still there in earlier versions of the tree.
//!
//! `/deleted.txt` (1012 bytes) and `/sub/inner.bin` (6656 bytes) were deleted;
//! `/kept.dat` was left in place. macOS's own `fseventsd` files are on the
//! volume too, and are real files.

use breadcrumb_rs::apfs;
use breadcrumb_rs::reader::Source;
use flate2::read::GzDecoder;
use std::io::Read;

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct Tmp(std::path::PathBuf);

impl Tmp {
    fn image() -> (Self, String) {
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        dir.push(format!("bcrumb-apfs-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let gz = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/apfs/apfs.dd.gz");
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

fn recover() -> (Vec<apfs::FileRecord>, apfs::Summary, Tmp) {
    let (dir, img) = Tmp::image();
    let src = Source::open(&img).unwrap();
    let opts = apfs::Options {
        out_dir: dir.0.join("out").to_string_lossy().to_string(),
        dry_run: false,
        min_size: 0,
    };
    let (records, summary) = apfs::recover(&src, 0, &opts, |_| {}).expect("recover failed");
    (records, summary, dir)
}

fn find<'a>(records: &'a [apfs::FileRecord], want: &str) -> &'a apfs::FileRecord {
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
fn fletcher64_verifies_a_real_node_and_rejects_a_changed_one() {
    // The checksum is what makes a blind block scan trustworthy, so it has to
    // be right. These are the container's own nodes.
    let (_dir, img) = Tmp::image();
    let data = std::fs::read(&img).unwrap();
    let src = Source::open(&img).unwrap();
    let cont = apfs::locate(&src, 0).expect("container not found");
    let bs = cont.block_size as usize;
    let mut checked = 0;
    for block in data.chunks_exact(bs) {
        // An object block starts with its checksum; a zero block does not.
        if block[..8] == [0u8; 8] {
            continue;
        }
        if apfs::fletcher64(block) == block[..8] {
            checked += 1;
            // Change one byte and the checksum must stop matching.
            let mut tampered = block.to_vec();
            tampered[bs / 2] ^= 0x40;
            assert_ne!(
                apfs::fletcher64(&tampered),
                tampered[..8],
                "a changed block still verified"
            );
        }
    }
    assert!(checked > 4, "only {checked} blocks verified; expected many");
}

#[test]
fn deleted_files_are_recovered_from_superseded_nodes() {
    let (records, summary, _dir) = recover();
    assert!(summary.nodes_found > 0, "no FS-tree nodes found");

    let txt = find(&records, "deleted.txt");
    assert_eq!(txt.size, 1012);
    assert_eq!(txt.ext, "txt");
    assert!(txt.validated);
    assert!(txt.timestamps.modified > 1_600_000_000, "no modified time");
    assert_eq!(
        std::fs::read(&txt.path).unwrap(),
        b"apfs deleted evidence\n".repeat(46)
    );

    // The path is rebuilt from the directory records, so a file in a
    // subdirectory comes back where it was.
    let inner = find(&records, "inner.bin");
    assert_eq!(inner.name, "sub/inner.bin");
    assert_eq!(inner.size, 6656);
    let want: Vec<u8> = (0..=255u8).cycle().take(6656).collect();
    assert_eq!(std::fs::read(&inner.path).unwrap(), want);
}

#[test]
fn the_file_that_was_never_deleted_is_recovered_too() {
    // Every object found is some past state of the container, so there is no
    // live/deleted split to make -- and the mode should not pretend otherwise.
    let (records, _summary, _dir) = recover();
    let kept = find(&records, "kept.dat");
    assert_eq!(
        std::fs::read(&kept.path).unwrap(),
        b"still here\n".repeat(80)
    );
}

#[test]
fn a_container_that_is_not_apfs_is_refused() {
    let mut p = std::env::temp_dir();
    p.push(format!("bcrumb-apfs-none-{}.img", std::process::id()));
    std::fs::write(&p, [0x41u8; 65536]).unwrap();
    let src = Source::open(p.to_str().unwrap()).unwrap();
    let opts = apfs::Options {
        out_dir: "/dev/null".into(),
        dry_run: true,
        min_size: 0,
    };
    let err = apfs::recover(&src, 0, &opts, |_| {}).expect_err("accepted");
    assert!(err.contains("APFS"), "{err}");
    let _ = std::fs::remove_file(&p);
}
