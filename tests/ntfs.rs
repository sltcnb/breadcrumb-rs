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
    };
    let err = ntfs::recover(&src, 0, &opts, |_| {})
        .err()
        .expect("accepted");
    assert!(err.contains("NTFS"), "{err}");
    let _ = std::fs::remove_file(&p);
}

use sha2::Digest;
