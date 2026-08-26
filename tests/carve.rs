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
    // data as recovered files, with nothing to signal the mistake. EWF, QCOW2,
    // VMDK and split raw are read properly; what is left must be refused.
    let dir = Tmp::new("container");
    let cases: &[(&str, &[u8])] = &[
        ("img.Ex01", b"EVF2\x0d\x0a\x81\x00\x01\x00\x00\x00"),
        ("img.vhd", b"conectix\x00\x00\x00\x00"),
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
fn ole_extension_comes_from_the_stream_name() {
    // An OLE2 container is only a container; which Office application wrote it
    // is decided by the stream names in its directory.
    let dir = Tmp::new("ole");
    for (stream, ext) in [
        ("WordDocument", "doc"),
        ("Workbook", "xls"),
        ("Book", "xls"),
        ("PowerPoint Document", "ppt"),
        ("__substg1.0_0037001F", "msg"),
        ("VisioDocument", "vsd"),
        ("SomethingElse", "ole"),
    ] {
        let data = builders::make_ole(stream);
        let mut blob = data.clone();
        blob.extend_from_slice(&builders::Rng::new(2).bytes(2048));
        let path = write_tmp(&dir, "ole.bin", &blob);
        let reader = Source::open(path.to_str().unwrap()).unwrap();
        let mut w = window_over(&reader);
        let carve = handlers::carve_ole(&mut w).unwrap_or_else(|| panic!("{stream} rejected"));
        assert_eq!(carve.ext, ext, "{stream}");
        assert_eq!(carve.size, data.len() as u64, "{stream}");
    }
}

#[test]
fn rtf_survives_escapes_and_binary_blobs() {
    // Naive brace counting breaks on \{ escapes and on \binN payloads holding
    // unbalanced braces; both appear in real documents.
    let dir = Tmp::new("rtf");
    let rtf = builders::make_rtf();
    let mut blob = rtf.clone();
    blob.extend_from_slice(&b"TRAILING JUNK".repeat(8));
    let path = write_tmp(&dir, "doc.rtf", &blob);
    let reader = Source::open(path.to_str().unwrap()).unwrap();
    let mut w = window_over(&reader);
    let carve = handlers::carve_rtf(&mut w).expect("rtf rejected");
    assert_eq!(carve.size, rtf.len() as u64);
    assert!(carve.validated);

    // no closing brace: reject rather than guess a length
    let path = write_tmp(&dir, "cut.rtf", &rtf[..rtf.len() - 1]);
    let reader = Source::open(path.to_str().unwrap()).unwrap();
    let mut w = window_over(&reader);
    assert!(handlers::carve_rtf(&mut w).is_none());
}

#[test]
fn ole_root_clsid_names_the_application() {
    // The CLSID is authoritative and outranks stream names: each container
    // below carries a misleading WordDocument stream on purpose.
    let dir = Tmp::new("clsid");
    let ppt: [u8; 16] = [
        0x10, 0x8D, 0x81, 0x64, 0x9B, 0x4F, 0xCF, 0x11, 0x86, 0xEA, 0x00, 0xAA, 0x00, 0xB9, 0x29,
        0xE8,
    ];
    let office = |d1: u32| -> [u8; 16] {
        let b = d1.to_le_bytes();
        [
            b[0], b[1], b[2], b[3], 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
        ]
    };
    for (clsid, ext) in [
        (office(0x0002_0820), "xls"),
        (office(0x0002_0906), "doc"),
        (office(0x000C_1084), "msi"),
        (office(0x0002_123D), "pub"),
        (office(0x0002_1A13), "vsd"),
        (ppt, "ppt"),
    ] {
        let data = builders::make_ole_clsid(clsid, "WordDocument");
        let path = write_tmp(&dir, "c.bin", &data);
        let reader = Source::open(path.to_str().unwrap()).unwrap();
        let mut w = window_over(&reader);
        let carve = handlers::carve_ole(&mut w).expect("rejected");
        assert_eq!(carve.ext, ext);
        assert_eq!(carve.size, data.len() as u64);
    }
}

#[test]
fn pst_size_comes_from_the_header() {
    let dir = Tmp::new("pst");
    for unicode_store in [true, false] {
        let data = builders::make_pst(unicode_store, 0x20000);
        let mut blob = data.clone();
        blob.extend_from_slice(&builders::Rng::new(6).bytes(4096));
        let path = write_tmp(&dir, "store.pst", &blob);
        let reader = Source::open(path.to_str().unwrap()).unwrap();
        let mut w = window_over(&reader);
        let carve = handlers::carve_pst(&mut w).expect("pst rejected");
        assert_eq!(carve.size, data.len() as u64, "unicode={unicode_store}");
        assert!(carve.validated);
    }

    // An implausible recorded size must not be trusted.
    let mut data = builders::make_pst(true, 0x20000);
    data[0xB8..0xC0].copy_from_slice(&(1u64 << 60).to_le_bytes());
    let path = write_tmp(&dir, "bogus.pst", &data);
    let reader = Source::open(path.to_str().unwrap()).unwrap();
    let mut w = window_over(&reader);
    let carve = handlers::carve_pst(&mut w).expect("rejected");
    assert!(!carve.validated);
    assert!(carve.size <= data.len() as u64);
}

#[test]
fn a_zip_fragment_without_a_central_directory_is_not_carved() {
    // What made this the default: a scan of a 238 GB Windows disk wrote 3192
    // files of exactly 16 MiB -- the unresolved cap, hit dead on -- for 49.9 GB,
    // 74% of everything it produced, and most were "not a zip file" when
    // tested. A window opening part-way inside a real archive walks genuine
    // member headers and never reaches that archive's directory. Without a
    // directory these bytes are a fragment of an archive, not an archive.
    let dir = Tmp::new("zipfrag");
    let whole = builders::zip_with(b"word/document.xml", &b"content ".repeat(200));
    let mut blob = whole[..whole.len() / 2].to_vec(); // first fragment only
    blob.extend_from_slice(&builders::Rng::new(8).bytes(60_000)); // unrelated data
    let tail_start = blob.len();
    blob.extend_from_slice(&whole); // an intact archive further along
    let path = write_tmp(&dir, "frag.img", &blob);

    let records = carve_all(&path, dir.join("out"), |o| o.skip_carved = false);
    assert!(
        !records.iter().any(|r| r.offset == 0),
        "a directory-less fragment was carved: {:?}",
        records
            .iter()
            .map(|r| (r.offset, r.size))
            .collect::<Vec<_>>()
    );
    // The intact archive further along is unaffected.
    let intact = records
        .iter()
        .find(|r| r.offset == tail_start as u64)
        .expect("intact archive missed");
    assert_eq!(intact.size, whole.len() as u64);
    assert!(intact.validated);
}

#[test]
fn zip_partial_brings_fragments_back_without_over_carving() {
    // An examination that wants the fragments can have them, and the protection
    // that matters still holds: a fragment must never be extended to a
    // *different* archive's end-of-central-directory, swallowing everything in
    // between, which is what hunting for a trailing EOCD used to do.
    let dir = Tmp::new("zippartial");
    let whole = builders::zip_with(b"word/document.xml", &b"content ".repeat(200));
    let mut blob = whole[..whole.len() / 2].to_vec();
    blob.extend_from_slice(&builders::Rng::new(8).bytes(60_000));
    let tail_start = blob.len();
    blob.extend_from_slice(&whole);
    let path = write_tmp(&dir, "frag.img", &blob);

    handlers::set_zip_partial(true);
    let records = carve_all(&path, dir.join("out"), |o| o.skip_carved = false);
    handlers::set_zip_partial(false);

    let first = records
        .iter()
        .find(|r| r.offset == 0)
        .expect("--zip-partial did not bring the fragment back");
    assert!(
        first.size <= whole.len() as u64,
        "fragment over-carved to {} bytes, past one archive's worth",
        first.size
    );
    assert!(
        (first.size as usize) < tail_start,
        "fragment reached the next archive"
    );
    assert!(
        !first.validated,
        "a fragment must not be reported as validated"
    );
}

#[test]
fn parallel_ranges_do_not_report_files_inside_a_validated_carve() {
    // A worker starting mid-archive would otherwise carve an inner member as a
    // separate file, so -j output would disagree with a serial run.
    let dir = Tmp::new("containment");
    let inner = builders::make_png();
    let archive = builders::zip_with(b"word/media/image1.png", &inner);
    let mut blob = vec![0u8; 512];
    blob.extend_from_slice(&archive);
    blob.extend_from_slice(&builders::Rng::new(12).bytes(70_000));
    let path = write_tmp(&dir, "img.bin", &blob);

    let reader = Source::open(path.to_str().unwrap()).unwrap();
    let sigs: Vec<_> = SIGNATURES.iter().collect();
    let key = |rs: &[Record]| {
        let mut v: Vec<(u64, u64)> = rs.iter().map(|r| (r.offset, r.size)).collect();
        v.sort();
        v
    };
    let serial = {
        let opts = Options {
            out_dir: dir.join("s").to_string_lossy().into(),
            quiet: true,
            ..Options::default()
        };
        run_parallel(&reader, &sigs, &opts)
    };
    let parallel = {
        let opts = Options {
            out_dir: dir.join("p").to_string_lossy().into(),
            quiet: true,
            jobs: 4,
            chunk_size: 1 << 12,
            ..Options::default()
        };
        run_parallel(&reader, &sigs, &opts)
    };
    assert_eq!(
        key(&serial),
        key(&parallel),
        "-j disagreed with a serial scan"
    );
    assert!(
        parallel.iter().all(|r| r.offset != 512 + 30 + 21),
        "inner png reported as its own carve"
    );
}

#[test]
fn pe_end_covers_sections_and_the_certificate_table() {
    // The Authenticode certificate table sits past the last section and is
    // addressed by file offset, so it decides the end of a signed binary.
    let dir = Tmp::new("pe");
    for dll in [false, true] {
        let data = builders::make_pe(dll);
        let mut blob = data.clone();
        blob.extend_from_slice(&builders::Rng::new(17).bytes(4096));
        let path = write_tmp(&dir, "bin.exe", &blob);
        let reader = Source::open(path.to_str().unwrap()).unwrap();
        let mut w = window_over(&reader);
        let carve = handlers::carve_pe(&mut w).expect("pe rejected");
        assert_eq!(carve.size, data.len() as u64);
        assert_eq!(carve.ext, if dll { "dll" } else { "exe" });
        assert!(carve.validated);
    }
}

#[test]
fn macho_thin_and_universal_binaries_carve_exactly() {
    let dir = Tmp::new("macho");
    let thin = builders::make_macho();
    let mut blob = thin.clone();
    blob.extend_from_slice(&builders::Rng::new(18).bytes(2048));
    let path = write_tmp(&dir, "thin.macho", &blob);
    let reader = Source::open(path.to_str().unwrap()).unwrap();
    let mut w = window_over(&reader);
    let carve = handlers::carve_macho(&mut w).expect("thin rejected");
    assert_eq!(carve.size, thin.len() as u64);
    assert!(carve.validated);

    // A universal binary wrapping two copies of the same slice.
    let align = 0x1000usize;
    let mut fat: Vec<u8> = 0xCAFEBABEu32.to_be_bytes().to_vec();
    fat.extend_from_slice(&2u32.to_be_bytes());
    for i in 0..2u32 {
        fat.extend_from_slice(&0x0100000Cu32.to_be_bytes()); // cputype
        fat.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        fat.extend_from_slice(&((align * (i as usize + 1)) as u32).to_be_bytes());
        fat.extend_from_slice(&(thin.len() as u32).to_be_bytes());
        fat.extend_from_slice(&12u32.to_be_bytes()); // align
    }
    for i in 0..2usize {
        fat.resize(align * (i + 1), 0);
        fat.extend_from_slice(&thin);
    }
    let fat_len = fat.len();
    fat.extend_from_slice(&builders::Rng::new(19).bytes(1024));
    let path = write_tmp(&dir, "fat.macho", &fat);
    let reader = Source::open(path.to_str().unwrap()).unwrap();
    let mut w = window_over(&reader);
    let carve = handlers::carve_macho(&mut w).expect("universal rejected");
    assert_eq!(carve.size, fat_len as u64);
    assert!(carve.validated);
}

#[test]
fn best_effort_handlers_return_plausible_carves() {
    // flac and psd have no end marker: they must not crash, must not reject a
    // valid file, and must run no further than the next file or EOF.
    let dir = Tmp::new("besteffort");
    for (name, data) in [
        ("flac", builders::make_flac()),
        ("psd", builders::make_psd()),
    ] {
        let mut blob = data.clone();
        blob.extend_from_slice(&builders::Rng::new(20).bytes(4096));
        blob.extend_from_slice(&data); // a second stream further along
        let path = write_tmp(&dir, "a.bin", &blob);
        let reader = Source::open(path.to_str().unwrap()).unwrap();
        let mut w = window_over(&reader);
        let sig = SIGNATURES.iter().find(|s| s.name == name).unwrap();
        let carve = sig
            .carve(&mut w)
            .unwrap_or_else(|| panic!("{name} rejected"));
        assert!(carve.size >= data.len() as u64, "{name}: truncated");
        assert!(carve.size <= blob.len() as u64, "{name}: past the window");
    }
    // rar has no structure to walk at all: capped window, never validated.
    let path = write_tmp(&dir, "a.rar", &b"Rar!\x1a\x07\x00payload".repeat(8));
    let reader = Source::open(path.to_str().unwrap()).unwrap();
    let mut w = window_over(&reader);
    let carve = handlers::carve_rar(&mut w).expect("rar rejected");
    assert!(!carve.validated);
}

#[test]
fn an_unresolvable_zip_carve_is_bounded() {
    // A stray PK\x03\x04 in unrelated data declares whatever the next bytes
    // say. On a real image that walked hundreds of megabytes and shipped a
    // 400 MB "docx" that was not a zip at all.
    let dir = Tmp::new("zipbound");
    let mut blob: Vec<u8> = b"PK\x03\x04".to_vec();
    blob.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // ver..date
    blob.extend_from_slice(&0u32.to_le_bytes()); // crc
    blob.extend_from_slice(&(900u32 << 20).to_le_bytes()); // compressed size: absurd
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&4u16.to_le_bytes()); // name length
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(b"junk");
    blob.extend_from_slice(&builders::Rng::new(77).bytes(40 << 20));
    let path = write_tmp(&dir, "stray.bin", &blob);

    // By default there is no carve at all: no central directory, no archive.
    let records = carve_all(&path, dir.join("out"), |o| o.dry_run = true);
    assert!(
        !records.iter().any(|r| r.offset == 0),
        "a stray PK header produced a carve"
    );

    // With --zip-partial the cap is what stops it, and it must hold.
    handlers::set_zip_partial(true);
    let records = carve_all(&path, dir.join("out"), |o| o.dry_run = true);
    handlers::set_zip_partial(false);
    for r in records.iter().filter(|r| r.offset == 0) {
        assert!(r.size <= 16 << 20, "unresolved zip carved {} bytes", r.size);
        assert!(!r.validated);
    }
}

#[test]
fn an_output_budget_stops_the_scan_and_keeps_the_manifest() {
    // A carve can outgrow the volume it writes to. On a real 238 GB image an
    // unfiltered run reached 51 GB inside the first percent and filled the
    // filesystem, which takes the machine with it.
    let dir = Tmp::new("budget");
    let mut img = Vec::new();
    for i in 0..40u32 {
        img.extend_from_slice(&builders::Rng::new(90 + i as u64).bytes(64 << 10));
        img.extend_from_slice(&builders::make_png());
        img.extend_from_slice(&builders::make_jpeg());
    }
    let path = write_tmp(&dir, "big.img", &img);

    let unlimited = carve_all(&path, dir.join("all"), |_| {});
    let capped = carve_all(&path, dir.join("capped"), |o| o.max_output = 1024);
    assert!(
        capped.len() < unlimited.len(),
        "the budget did not stop anything: {} vs {}",
        capped.len(),
        unlimited.len()
    );
    assert!(!capped.is_empty(), "the budget stopped everything");
    // What it did write is on disk and accounted for, not half a file.
    for r in capped.iter().filter(|r| !r.path.is_empty()) {
        let on_disk = std::fs::metadata(&r.path).map(|m| m.len()).unwrap_or(0);
        assert_eq!(on_disk, r.size, "{} truncated", r.path);
    }
}

#[test]
fn the_budget_is_shared_across_workers() {
    let dir = Tmp::new("budgetpar");
    let mut img = Vec::new();
    for i in 0..40u32 {
        img.extend_from_slice(&builders::Rng::new(30 + i as u64).bytes(64 << 10));
        img.extend_from_slice(&builders::make_png());
    }
    let path = write_tmp(&dir, "big.img", &img);
    let reader = Source::open(path.to_str().unwrap()).unwrap();
    let sigs: Vec<_> = SIGNATURES.iter().collect();
    let opts = Options {
        out_dir: dir.join("out").to_string_lossy().into(),
        quiet: true,
        jobs: 4,
        chunk_size: 1 << 16,
        max_output: 512,
        ..Options::default()
    };
    let records = run_parallel(&reader, &sigs, &opts);
    let written: u64 = records
        .iter()
        .filter(|r| !r.path.is_empty())
        .map(|r| r.size)
        .sum();
    // Four workers can each be mid-file when the limit trips, so allow a
    // margin -- but nothing like an unbounded run.
    assert!(
        written < 64 << 10,
        "workers ignored the shared budget: {written}"
    );
}

#[test]
fn office_group_resolves_to_every_document_container() {
    let names: Vec<&str> = resolve_types("office")
        .unwrap()
        .iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(names, vec!["ole", "zip", "pdf", "rtf", "pst"]);
    let names: Vec<&str> = resolve_types("doc,xls,docx,pdf")
        .unwrap()
        .iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(names, vec!["ole", "zip", "pdf"]);
}

#[test]
fn type_filter_and_aliases_resolve() {
    let sigs = resolve_types("jpeg,png,webp").unwrap();
    let names: Vec<&str> = sigs.iter().map(|s| s.name).collect();
    assert_eq!(names, vec!["jpg", "png", "riff"]);
    assert!(resolve_types("jpg,nosuchtype").is_err());
}

#[test]
fn a_stray_zip_header_does_not_search_the_whole_window() {
    // A ZIP's window is 512 MB. Searching all of it for an end-of-central-
    // directory record, once per stray PK header, is what made a live scan
    // crawl: on an encrypted image inside a compressed container every byte
    // looked at has to be decrypted and inflated first. The search is bounded
    // by what the member walk accounted for.
    let dir = Tmp::new("zipsearch");
    let mut rng = builders::Rng::new(31);
    let mut blob = rng.bytes(64 << 20);
    for i in 0..16 {
        let at = (i + 1) * (3 << 20);
        blob[at..at + 4].copy_from_slice(b"PK\x03\x04");
    }
    let path = write_tmp(&dir, "stray.bin", &blob);

    let started = std::time::Instant::now();
    let records = carve_all(&path, dir.join("out"), |o| {
        o.dry_run = true;
        o.jobs = 1;
    });
    let elapsed = started.elapsed();
    assert!(
        records.is_empty(),
        "stray headers produced carves: {:?}",
        records
            .iter()
            .map(|r| (r.offset, r.size))
            .collect::<Vec<_>>()
    );
    // Generous enough not to be flaky on a loaded machine, tight enough that a
    // full-window search per header (which was ~20x this) fails it.
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "16 stray headers over 64 MB took {elapsed:?}"
    );
}
