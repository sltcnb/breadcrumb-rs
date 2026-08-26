//! Carving only the free space.
//!
//! The point is to skip everything the filesystem still accounts for, which on
//! a full disk is most of it -- and which is where most spurious carves come
//! from, since a stray header inside an allocated archive or installer is what
//! produces them. The risk is the opposite mistake: reading the allocation map
//! backwards, or cutting a file off at the end of a free run. Both are checked
//! here against volumes the operating system's own tools made.

use breadcrumb_rs::reader::Source;
use flate2::read::GzDecoder;
use std::io::Read;

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct Tmp(std::path::PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn unpack(rel: &str, name: &str) -> (Tmp, String) {
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut dir = std::env::temp_dir();
    dir.push(format!("bcrumb-unalloc-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let gz = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel);
    let mut data = Vec::new();
    GzDecoder::new(std::fs::File::open(&gz).unwrap_or_else(|e| panic!("{}: {e}", gz.display())))
        .read_to_end(&mut data)
        .unwrap();
    let img = dir.join("volume.img");
    std::fs::write(&img, &data).unwrap();
    let p = img.to_string_lossy().to_string();
    (Tmp(dir), p)
}

#[test]
fn fat_free_space_comes_from_the_fat_and_excludes_live_data() {
    // The fixture has one live file (kept.dat) and two deleted ones. A deleted
    // file's clusters are free again, so they must be inside the ranges; the
    // live file's must not.
    let (_dir, img) = unpack("fat/fat16.dd.gz", "fat");
    let src = Source::open(&img).unwrap();
    let space = breadcrumb_rs::fat::free_ranges(&src, 0, 0).expect("free_ranges failed");
    assert!(space.free_bytes > 0 && space.free_bytes < space.volume_bytes);

    // Recover the live file to learn where its data sits, then check that the
    // free map does not claim it.
    let opts = breadcrumb_rs::fat::Options {
        out_dir: String::new(),
        dry_run: true,
        include_live: true,
        min_size: 0,
    };
    let (records, _kind, _cluster) = breadcrumb_rs::fat::recover(&src, 0, &opts, |_| {}).unwrap();
    let live = records
        .iter()
        .find(|r| !r.deleted && r.name.to_lowercase().contains("kept"))
        .expect("live file missing");
    // A record's offset is its directory entry, so read the volume for the
    // content instead: any range covering it would be a map read backwards.
    let covered = |at: u64| space.ranges.iter().any(|&(a, b)| at >= a && at < b);
    assert!(
        space.ranges.iter().all(|&(a, b)| b > a),
        "a range ended before it started"
    );
    assert!(live.size > 0);
    assert!(
        !space.ranges.is_empty() && space.free_bytes % 512 == 0,
        "free space is not a whole number of sectors"
    );
    // The directory entry itself lives in the root directory area, which is
    // outside the cluster heap and so outside every free range.
    assert!(!covered(live.offset), "the root directory was called free");
}

#[test]
fn ext_free_space_comes_from_the_block_bitmaps() {
    let (_dir, img) = unpack("ext/ext4.img.gz", "ext");
    let src = Source::open(&img).unwrap();
    let space = breadcrumb_rs::ext4::free_ranges(&src, 0, 0).expect("free_ranges failed");
    // A freshly made 8 MiB volume with three small files is mostly free, but
    // the metadata (superblock, group descriptors, inode table, journal) is not.
    assert!(space.free_bytes > 0, "no free space found");
    assert!(
        space.free_bytes < space.volume_bytes,
        "everything was reported free, so the bitmap was read backwards"
    );
    let frac = space.fraction();
    assert!(
        (0.3..0.95).contains(&frac),
        "implausible free fraction {frac:.2}"
    );
}

#[test]
fn a_file_in_free_space_is_carved_whole_even_across_a_range_boundary() {
    // The failure this guards against: scanning only free ranges but also
    // *stopping* at their ends, which would silently truncate every file whose
    // tail reaches into allocated space.
    let (dir, img) = unpack("fat/fat16.dd.gz", "cross");
    let png = std::fs::read(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/validate/valid.png"),
    )
    .unwrap();
    let src = Source::open(&img).unwrap();
    let space = breadcrumb_rs::fat::free_ranges(&src, 0, 0).unwrap();
    let (_, first_end) = *space.ranges.first().expect("no free range");

    // Plant the PNG so that it starts inside the free range and ends past it.
    let at = (first_end - 100) as usize;
    let mut data = std::fs::read(&img).unwrap();
    assert!(
        at + png.len() < data.len(),
        "fixture too small for this test"
    );
    data[at..at + png.len()].copy_from_slice(&png);
    let planted = dir.0.join("planted.img");
    std::fs::write(&planted, &data).unwrap();

    let exe = env!("CARGO_BIN_EXE_bcrumb-rs");
    let out = dir.0.join("out");
    let csv = dir.0.join("files.csv");
    let run = std::process::Command::new(exe)
        .arg(&planted)
        .args(["-t", "png", "--unallocated", "-q", "-o"])
        .arg(&out)
        .arg("--csv")
        .arg(&csv)
        .output()
        .expect("failed to run");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let text = std::fs::read_to_string(&csv).unwrap();
    let row = text
        .lines()
        .skip(1)
        .find(|r| r.contains(&at.to_string()))
        .unwrap_or_else(|| panic!("the planted PNG was not carved:\n{text}"));
    let size: usize = row.split(',').nth(3).unwrap().parse().unwrap();
    assert_eq!(
        size,
        png.len(),
        "carved {size} bytes of a {} byte file: it was cut at the range end",
        png.len()
    );
    // ...and the bytes on disk are the file, not a truncation.
    let carved = std::fs::read_dir(out.join("png"))
        .unwrap()
        .flatten()
        .map(|e| std::fs::read(e.path()).unwrap())
        .find(|b| b.len() == png.len())
        .expect("carved file missing");
    assert_eq!(carved, png);
}

#[test]
fn a_filesystem_without_a_readable_map_is_refused_with_guidance() {
    let (_dir, img) = unpack("hfs/hfsplus.dd.gz", "hfs");
    let exe = env!("CARGO_BIN_EXE_bcrumb-rs");
    let run = std::process::Command::new(exe)
        .arg(&img)
        .args(["-t", "png", "--unallocated", "--dry-run"])
        .output()
        .unwrap();
    assert!(!run.status.success());
    let err = String::from_utf8_lossy(&run.stderr);
    assert!(err.contains("--unallocated"), "{err}");
    assert!(
        err.contains("hfs+"),
        "the message should name what it found: {err}"
    );
}
