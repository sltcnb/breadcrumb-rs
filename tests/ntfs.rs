//! NTFS undelete.
//!
//! The fixture is a volume built by BreadCrumb's own NTFS test builder: a boot
//! sector, an MFT, a deleted resident file, and a deleted file whose data spans
//! two non-adjacent clusters. That last one is the point of this mode — carving
//! would recover its first fragment plus whatever follows, while the runlist
//! says exactly where both pieces are.

use breadcrumb_rs::ntfs;
use breadcrumb_rs::reader::Source;
use std::path::PathBuf;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join("ntfs_deleted.img")
}

fn out_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("breadcrumb-rs-ntfs-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn recover(tag: &str, include_live: bool) -> (Vec<ntfs::FileRecord>, PathBuf) {
    let src = Source::open(fixture().to_str().unwrap()).unwrap();
    let out = out_dir(tag);
    let opts = ntfs::Options {
        out_dir: out.to_string_lossy().to_string(),
        dry_run: false,
        include_live,
        min_size: 0,
        only_path: None,
    };
    let recs = ntfs::recover(&src, 0, &opts, |_| {}).expect("recover failed");
    (recs, out)
}

#[test]
fn deleted_files_come_back_with_names_and_timestamps() {
    let (recs, out) = recover("named", false);
    let mut names: Vec<&str> = recs.iter().map(|r| r.name.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["deleted-frag.bin", "deleted-resident.txt"]);

    for rec in &recs {
        assert!(rec.deleted, "{} was reported as live", rec.name);
        assert!(rec.validated, "{} came back low confidence", rec.name);
        // Carving cannot produce any of these three.
        assert!(rec.timestamps.created > 0, "{}: no created time", rec.name);
        assert!(
            rec.timestamps.modified > 0,
            "{}: no modified time",
            rec.name
        );
        assert!(rec.mft > 0, "{}: no MFT number", rec.name);
        // What landed on disk is what the record describes.
        let on_disk = std::fs::read(&rec.path).expect("recovered file missing");
        assert_eq!(on_disk.len() as u64, rec.size);
        assert_eq!(format!("{:x}", sha2::Sha256::digest(&on_disk)), rec.sha256);
    }
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn a_fragmented_file_is_reassembled_from_its_runlist() {
    // Two non-adjacent clusters: the reason to read the MFT rather than carve.
    let (recs, out) = recover("frag", false);
    let frag = recs
        .iter()
        .find(|r| r.name == "deleted-frag.bin")
        .expect("fragmented file missing");
    assert_eq!(frag.size, 5096);
    assert!(frag.size > 4096, "should span more than one cluster");
    let data = std::fs::read(&frag.path).unwrap();
    assert_eq!(data.len(), 5096);
    // The second fragment is real content, not the zeros a short read leaves.
    assert!(
        data[4096..].iter().any(|&b| b != 0),
        "second fragment is empty"
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn live_files_are_skipped_unless_asked_for() {
    let (deleted_only, out1) = recover("deleted", false);
    let (with_live, out2) = recover("live", true);
    assert!(
        with_live.len() > deleted_only.len(),
        "--include-live found nothing extra ({} vs {})",
        with_live.len(),
        deleted_only.len()
    );
    assert!(
        with_live.iter().any(|r| !r.deleted),
        "no live file reported"
    );
    assert!(deleted_only.iter().all(|r| r.deleted));
    let _ = std::fs::remove_dir_all(&out1);
    let _ = std::fs::remove_dir_all(&out2);
}

#[test]
fn a_volume_without_ntfs_is_refused() {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "breadcrumb-rs-ntfs-none-{}.img",
        std::process::id()
    ));
    std::fs::write(&p, [0x41u8; 8192]).unwrap();
    let src = Source::open(p.to_str().unwrap()).unwrap();
    let opts = ntfs::Options {
        out_dir: "/dev/null".into(),
        dry_run: true,
        include_live: false,
        min_size: 0,
        only_path: None,
    };
    let err = ntfs::recover(&src, 0, &opts, |_| {})
        .err()
        .expect("accepted");
    assert!(err.contains("NTFS"), "{err}");
    let _ = std::fs::remove_file(&p);
}

use sha2::Digest;

/// The clusters the fixture's builder actually used, recorded by the builder
/// itself when it laid the volume out -- not by anything that reads it.
fn layout() -> (u64, u64, Vec<u64>) {
    let text = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ntfs_deleted.layout.json"),
    )
    .expect("layout record missing");
    let doc = breadcrumb_rs::jsonin::parse(&text).expect("layout is not JSON");
    let num = |k: &str| doc.get(k).and_then(|v| v.as_f64()).unwrap() as u64;
    let used = doc
        .get("used_clusters")
        .and_then(|v| v.as_array())
        .unwrap()
        .iter()
        .map(|v| v.as_f64().unwrap() as u64)
        .collect();
    (num("cluster_size"), num("total_clusters"), used)
}

#[test]
fn free_space_is_exactly_the_complement_of_what_is_allocated() {
    // $Bitmap is one bit per cluster, set when in use. Getting the bit order or
    // the sense backwards would still produce plausible-looking ranges, so this
    // compares against the set of clusters the builder allocated -- which it
    // knew before writing the bitmap, and which nothing in this crate computed.
    let (cluster_size, total, used) = layout();
    let src = Source::open(fixture().to_str().unwrap()).unwrap();
    // merge_gap 0: no coalescing, so the ranges map one-to-one onto free runs.
    let space = ntfs::free_ranges(&src, 0, 0).expect("free_ranges failed");

    let mut want: Vec<u64> = (0..total).filter(|c| !used.contains(c)).collect();
    want.sort_unstable();
    assert_eq!(
        space.free_bytes,
        want.len() as u64 * cluster_size,
        "free byte count disagrees with the layout"
    );

    // Every free cluster must fall inside a reported range, and no allocated
    // one may.
    let covered = |c: u64| {
        let at = c * cluster_size;
        space.ranges.iter().any(|&(a, b)| at >= a && at < b)
    };
    for c in &want {
        assert!(covered(*c), "free cluster {c} is not in any range");
    }
    for c in &used {
        assert!(!covered(*c), "allocated cluster {c} was reported as free");
    }
    assert_eq!(space.volume_bytes, total * cluster_size);
}

#[test]
fn a_path_through_a_reused_parent_record_is_not_invented() {
    // A deleted file names its parent by record number and sequence. NTFS bumps
    // that sequence each time it reuses a record, so when they disagree the
    // record now holds some other file and any path built through it is
    // fiction. On live evidence this reported an 84 MB DLL as living inside a
    // Chrome .pak file.
    let mut data = std::fs::read(fixture()).expect("fixture missing");

    // Point the deleted file's parent at record 5 (the root) but claim a
    // sequence the root does not have.
    let boot = &data[..512];
    let cluster = u16::from_le_bytes([boot[11], boot[12]]) as usize * boot[13] as usize;
    let mft = u64::from_le_bytes(data[48..56].try_into().unwrap()) as usize * cluster;
    let rec_size = 1usize << (256 - boot[64] as usize);
    let target = mft + 65 * rec_size; // deleted-resident.txt

    // Find its $FILE_NAME attribute and rewrite the parent reference's sequence.
    let attr_off = u16::from_le_bytes([data[target + 20], data[target + 21]]) as usize;
    let mut pos = target + attr_off;
    let mut patched = false;
    while pos + 8 < target + rec_size {
        let atype = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let alen = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if atype == 0xFFFF_FFFF || alen == 0 {
            break;
        }
        if atype == 0x30 {
            let coff = u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
            let refr = pos + coff;
            // sequence lives in the top 16 bits of the 8-byte reference
            data[refr + 6..refr + 8].copy_from_slice(&0x4242u16.to_le_bytes());
            patched = true;
            break;
        }
        pos += alen;
    }
    assert!(patched, "no $FILE_NAME attribute found to patch");

    let mut dir = std::env::temp_dir();
    dir.push(format!("bcrumb-reused-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let patched_img = dir.join("disk.img");
    std::fs::write(&patched_img, &data).unwrap();

    let src = Source::open(patched_img.to_str().unwrap()).unwrap();
    let opts = ntfs::Options {
        out_dir: dir.join("out").to_string_lossy().to_string(),
        dry_run: true,
        include_live: false,
        min_size: 0,
        only_path: None,
    };
    let recs = ntfs::recover(&src, 0, &opts, |_| {}).expect("recover failed");
    let rec = recs
        .iter()
        .find(|r| r.mft == 65)
        .expect("the deleted file should still be recovered");
    assert!(
        rec.name.contains("_parent_reused_"),
        "path claimed through a reused parent: {}",
        rec.name
    );
    // The parent is unknowable; the file's own name is not, and it is what an
    // investigator is looking for.
    assert!(
        rec.name.ends_with("deleted-resident.txt"),
        "the file's own name was thrown away with its parent: {}",
        rec.name
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_inventory_writes_a_csv_and_leaves_stdout_alone() {
    // A dry run over a real volume lists a million files. The manifest for
    // that is hundreds of megabytes, and printing it to a terminal is how a
    // one-minute inventory turns into a log nobody can read. The CSV is the
    // artifact; stdout stays quiet unless the caller asked for JSON.
    let out = out_dir("cli-inventory");
    std::fs::create_dir_all(&out).unwrap();
    let csv = out.join("inventaire.csv");
    let run = std::process::Command::new(env!("CARGO_BIN_EXE_bcrumb-rs"))
        .arg(fixture())
        .args(["--ntfs", "--dry-run", "-q", "-o"])
        .arg(&out)
        .arg("--csv")
        .arg(&csv)
        .output()
        .expect("inventory failed to run");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );

    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        !stdout.contains("\"files\""),
        "manifest went to stdout: {stdout}"
    );

    let text = std::fs::read_to_string(&csv).expect("no CSV");
    let mut lines = text.lines();
    assert!(lines
        .next()
        .unwrap()
        .starts_with("mft,name,ext,size,sha256,deleted"));
    assert!(lines.next().is_some(), "inventory is empty");

    // Nothing was extracted: an inventory reads metadata, not file content.
    assert!(!out.join("manifest.json").exists());
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn only_one_corner_of_the_volume_can_be_asked_for() {
    // A volume holds a million files and an examination usually wants one
    // corner of it -- a recycle bin, one user's profile. Extracting everything
    // to get at a few hundred files costs hours and a disk to put them on.
    let src = Source::open(fixture().to_str().unwrap()).unwrap();
    let out = out_dir("only-path");
    let all = ntfs::recover(
        &src,
        0,
        &ntfs::Options {
            out_dir: out.to_string_lossy().to_string(),
            dry_run: true,
            include_live: true,
            min_size: 0,
            only_path: None,
        },
        |_| {},
    )
    .expect("recover failed");
    let wanted = all
        .iter()
        .find(|r| r.name.contains("deleted-resident"))
        .expect("fixture changed");
    let needle = "deleted-resident".to_string();

    let some = ntfs::recover(
        &src,
        0,
        &ntfs::Options {
            out_dir: out.to_string_lossy().to_string(),
            dry_run: true,
            include_live: true,
            min_size: 0,
            only_path: Some(needle.clone()),
        },
        |_| {},
    )
    .expect("recover failed");
    assert!(some.len() < all.len(), "the filter kept everything");
    assert!(!some.is_empty(), "the filter kept nothing");
    assert!(some.iter().all(|r| r.name.to_lowercase().contains(&needle)));
    assert!(some.iter().any(|r| r.mft == wanted.mft));
    let _ = std::fs::remove_dir_all(&out);
}
