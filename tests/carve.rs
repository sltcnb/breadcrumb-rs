//! Carve engine tests: every supported type is planted in a synthetic image
//! and must come back byte-exact, plus the behaviour switches (align, min
//! size, dedup, parallel) and the regression cases the Python implementation
//! learned the hard way.

mod builders;

use breadcrumb_rs::carver::{run_parallel, Carver, Options, Record};
use breadcrumb_rs::handlers;
use breadcrumb_rs::reader::Source;
use breadcrumb_rs::signatures::{resolve_types, SIGNATURES};
use breadcrumb_rs::window::Window;
use builders::Rng;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        // Test-local, collision-free without a tempfile dependency.
        p.push(format!("breadcrumb-rs-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sha(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

struct Planted {
    path: PathBuf,
    /// (type name, offset, size, sha256)
    expected: Vec<(&'static str, u64, u64, String)>,
}

/// Image with every builder's file at a sector-aligned offset, separated by
/// seeded filler.
fn planted_image(dir: &Tmp) -> Planted {
    let mut rng = Rng::new(7);
    let mut img: Vec<u8> = vec![0u8; 4096];
    let mut expected = Vec::new();
    for (name, data) in builders::all() {
        let gap = rng.range(1000, 5000);
        img.extend_from_slice(&rng.bytes(gap));
        let pad = (512 - img.len() % 512) % 512;
        img.extend_from_slice(&vec![0u8; pad]);
        let offset = img.len() as u64;
        img.extend_from_slice(&data);
        expected.push((name, offset, data.len() as u64, sha(&data)));
    }
    img.extend_from_slice(&rng.bytes(3000));
    let path = dir.join("test.img");
    std::fs::write(&path, &img).unwrap();
    Planted { path, expected }
}

fn carve_all(source: &Path, out: PathBuf, tune: impl FnOnce(&mut Options)) -> Vec<Record> {
    let mut opts = Options {
        out_dir: out.to_string_lossy().to_string(),
        quiet: true,
        ..Options::default()
    };
    tune(&mut opts);
    let reader = Source::open(source.to_str().unwrap()).unwrap();
    let sigs: Vec<_> = SIGNATURES.iter().collect();
    let mut c = Carver::new(&reader, sigs, &opts);
    c.run()
}

fn window_over(reader: &Source) -> Window<'_> {
    Window::new(reader, 0, reader.size())
}

fn write_tmp(dir: &Tmp, name: &str, data: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    p
}

#[test]
fn every_type_is_recovered_byte_exact() {
    let dir = Tmp::new("exact");
    let img = planted_image(&dir);
    let records = carve_all(&img.path, dir.join("out"), |_| {});

    for (name, offset, size, digest) in &img.expected {
        let rec = records
            .iter()
            .find(|r| r.offset == *offset)
            .unwrap_or_else(|| panic!("{name}: nothing carved at {offset:#x}"));
        assert_eq!(rec.size, *size, "{name}: carved size");
        assert_eq!(&rec.sha256, digest, "{name}: content hash");
        assert_eq!(
            std::fs::metadata(&rec.path).unwrap().len(),
            *size,
            "{name}: file on disk"
        );
    }
    assert_eq!(records.len(), img.expected.len(), "extra or missing carves");
}

#[test]
fn dry_run_writes_nothing_but_still_hashes() {
    let dir = Tmp::new("dry");
    let img = planted_image(&dir);
    let out = dir.join("out");
    let records = carve_all(&img.path, out.clone(), |o| o.dry_run = true);
    assert_eq!(records.len(), img.expected.len());
    assert!(!out.exists(), "dry run created {out:?}");
    for (_, _, _, digest) in &img.expected {
        assert!(records.iter().any(|r| &r.sha256 == digest));
    }
}

#[test]
fn align_filter_keeps_only_aligned_headers() {
    let dir = Tmp::new("align");
    let img = planted_image(&dir);
    let records = carve_all(&img.path, dir.join("out"), |o| o.align = 512);
    assert_eq!(
        records.len(),
        img.expected.len(),
        "all planted sector-aligned"
    );
    assert!(records.iter().all(|r| r.offset % 512 == 0));
}

#[test]
fn min_size_drops_small_carves() {
    let dir = Tmp::new("minsize");
    let img = planted_image(&dir);
    let records = carve_all(&img.path, dir.join("out"), |o| o.min_size = 1000);
    assert!(!records.is_empty());
    assert!(records.iter().all(|r| r.size >= 1000));
}

#[test]
fn offset_and_length_restrict_the_scan() {
    let dir = Tmp::new("range");
    let img = planted_image(&dir);
    let mut offsets: Vec<u64> = img.expected.iter().map(|e| e.1).collect();
    offsets.sort();
    let third = offsets[2];
    let records = carve_all(&img.path, dir.join("out"), |o| o.start = third);
    let got: Vec<u64> = records.iter().map(|r| r.offset).collect();
    assert_eq!(got, offsets[2..].to_vec());
}

#[test]
fn duplicates_are_marked_and_stored_once() {
    let dir = Tmp::new("dedup");
    let png = builders::make_png();
    let mut blob = vec![0u8; 512];
    blob.extend_from_slice(&png);
    blob.extend_from_slice(&vec![0u8; 512 - png.len() % 512]);
    blob.extend_from_slice(&png);
    blob.extend_from_slice(&[0u8; 64]);
    let path = write_tmp(&dir, "dup.img", &blob);

    let records = carve_all(&path, dir.join("out"), |o| o.dedup = true);
    let dups: Vec<_> = records
        .iter()
        .filter(|r| r.duplicate_of.is_some())
        .collect();
    let originals: Vec<_> = records
        .iter()
        .filter(|r| r.duplicate_of.is_none())
        .collect();
    assert_eq!(dups.len(), 1);
    assert_eq!(originals.len(), 1);
    assert!(dups[0].path.is_empty(), "duplicate should not keep a file");
    assert!(PathBuf::from(&originals[0].path).exists());
    assert_eq!(dups[0].duplicate_of, Some(originals[0].offset));
}

#[test]
fn parallel_scan_matches_serial() {
    let dir = Tmp::new("parallel");
    let img = planted_image(&dir);
    let reader = Source::open(img.path.to_str().unwrap()).unwrap();
    let sigs: Vec<_> = SIGNATURES.iter().collect();

    let serial = {
        let opts = Options {
            out_dir: dir.join("s").to_string_lossy().into(),
            quiet: true,
            ..Options::default()
        };
        let mut c = Carver::new(&reader, sigs.clone(), &opts);
        c.run()
    };
    let parallel = {
        let opts = Options {
            out_dir: dir.join("p").to_string_lossy().into(),
            quiet: true,
            jobs: 4,
            chunk_size: 1 << 16,
            ..Options::default()
        };
        run_parallel(&reader, &sigs, &opts)
    };
    let key = |rs: &[Record]| {
        let mut v: Vec<(u64, u64, String)> = rs
            .iter()
            .map(|r| (r.offset, r.size, r.sha256.clone()))
            .collect();
        v.sort();
        v
    };
    assert_eq!(key(&serial), key(&parallel));
}

#[test]
fn random_noise_yields_no_validated_carves() {
    let dir = Tmp::new("noise");
    let noise = Rng::new(1234).bytes(8 << 20);
    let path = write_tmp(&dir, "noise.img", &noise);
    let records = carve_all(&path, dir.join("out"), |o| o.dry_run = true);
    assert!(
        records.iter().all(|r| !r.validated),
        "false positive validated carve"
    );
}

#[test]
fn embedded_file_needs_no_skip() {
    // A PNG stored uncompressed inside a zip is only reachable with
    // skip_carved disabled -- by default the carver does not rescan the
    // interior of a validated carve.
    let dir = Tmp::new("skip");
    let zip = builders::zip_with(b"img.png", &builders::make_png());
    let mut blob = vec![0u8; 512];
    blob.extend_from_slice(&zip);
    blob.extend_from_slice(&[0u8; 512]);
    let path = write_tmp(&dir, "img.bin", &blob);

    let with_skip = carve_all(&path, dir.join("a"), |o| o.skip_carved = true);
    let exts: Vec<&str> = with_skip.iter().map(|r| r.ext).collect();
    assert_eq!(exts, vec!["zip"], "default scan should stop at the zip");

    let without = carve_all(&path, dir.join("b"), |o| o.skip_carved = false);
    let mut exts: Vec<&str> = without.iter().map(|r| r.ext).collect();
    exts.sort();
    assert_eq!(
        exts,
        vec!["png", "zip"],
        "no-skip should also find the inner png"
    );
}

// ------------------------------------------------- handler regression cases

#[test]
fn pdf_takes_one_line_terminator_not_every_eol_byte() {
    // A PDF ending "%%EOF\n" followed by data whose first byte is CR or LF
    // must not absorb that byte (BreadCrumb PR #6).
    let dir = Tmp::new("pdfeol");
    let pdf = builders::make_pdf();
    for tail in [b"\n".to_vec(), b"\r".to_vec(), vec![0x41]] {
        let mut blob = pdf.clone();
        blob.extend_from_slice(&tail);
        blob.extend_from_slice(&[0u8; 64]);
        let path = write_tmp(&dir, "pdf.bin", &blob);
        let reader = Source::open(path.to_str().unwrap()).unwrap();
        let mut w = window_over(&reader);
        let carve = handlers::carve_pdf(&mut w).expect("pdf rejected");
        assert_eq!(
            carve.size,
            pdf.len() as u64,
            "tail {tail:?} changed the size"
        );
    }
}

#[test]
fn mp3_frame_walk_is_profile_locked() {
    // Trailing data that syncs but declares another version/layer/rate is not
    // a frame of this stream (BreadCrumb PR #7).
    let dir = Tmp::new("mp3lock");
    let mp3 = builders::make_mp3(); // MPEG1 Layer III, 44100 Hz
    let mut other = Vec::new();
    for _ in 0..4 {
        other.extend_from_slice(&[0xFF, 0xF3, 0x80, 0x00]); // MPEG2 L3, 22050 Hz
        other.extend_from_slice(&vec![0u8; 208 - 4]);
    }
    let mut blob = mp3.clone();
    blob.extend_from_slice(&other);
    let path = write_tmp(&dir, "mp3.bin", &blob);
    let reader = Source::open(path.to_str().unwrap()).unwrap();
    let mut w = window_over(&reader);
    let carve = handlers::carve_mp3(&mut w).expect("mp3 rejected");
    assert_eq!(carve.size, mp3.len() as u64);
}

#[test]
fn truncated_input_never_overruns() {
    let dir = Tmp::new("trunc");
    for (name, data) in builders::all() {
        for cut in [data.len() / 2, 20, 10] {
            if cut >= data.len() {
                continue;
            }
            let path = write_tmp(&dir, "cut.bin", &data[..cut]);
            let records = carve_all(&path, dir.join("out"), |o| o.dry_run = true);
            for r in records {
                assert!(r.size <= cut as u64, "{name}: carved {} of {cut}", r.size);
            }
        }
    }
}

#[test]
fn unsupported_containers_are_refused_not_carved_as_raw() {
    // Carving a container as raw reports fragments of its own compressed chunk
    // data as recovered files, with nothing to signal the mistake. EWF is read
    // properly (see tests/ewf.rs); everything else here must be refused.
    let dir = Tmp::new("container");
    let cases: &[(&str, &[u8])] = &[
        ("img.Ex01", b"EVF2\x0d\x0a\x81\x00\x01\x00\x00\x00"),
        ("img.qcow2", b"QFI\xfb\x00\x00\x00\x03\x00"),
        ("img.vmdk", b"KDMV\x01\x00\x00\x00\x00"),
        ("img.vhdx", b"vhdxfile\x00\x00\x00\x00"),
    ];
    for (name, magic) in cases {
        let mut blob = magic.to_vec();
        blob.extend_from_slice(&vec![0u8; 4096]);
        let path = write_tmp(&dir, name, &blob);
        let err = Source::open(path.to_str().unwrap())
            .err()
            .unwrap_or_else(|| panic!("{name} was accepted"));
        assert!(err.to_string().contains("cannot read"), "{name}: {err}");
    }

    // A file named .e01 that is not an EWF image is an error too, not a raw
    // carve of whatever it happens to contain.
    let path = write_tmp(&dir, "unreadable.e01", b"not really an ewf header");
    let err = Source::open(path.to_str().unwrap())
        .err()
        .expect("accepted");
    assert!(err.to_string().contains("EWF"), "{err}");

    // ...and a plain raw image still opens.
    let path = write_tmp(&dir, "plain.dd", &[0x41; 4096]);
    assert!(Source::open(path.to_str().unwrap()).is_ok());
}

#[test]
fn type_filter_and_aliases_resolve() {
    let sigs = resolve_types("jpeg,png,webp").unwrap();
    let names: Vec<&str> = sigs.iter().map(|s| s.name).collect();
    assert_eq!(names, vec!["jpg", "png", "riff"]);
    assert!(resolve_types("jpg,nosuchtype").is_err());
}
