//! Inputs that once crashed a fuzz target, kept as a regression corpus.
//!
//! Each file is a raw fuzz input: the first byte picks the handler, the rest is
//! the file, exactly as `fuzz/fuzz_targets/handlers.rs` reads it. Long
//! campaigns run in the fuzz job; these run on every commit, so a fixed crash
//! stays fixed even if the corpus that found it is gone.

use breadcrumb_rs::reader::Source;
use breadcrumb_rs::signatures::SIGNATURES;
use breadcrumb_rs::window::Window;

#[test]
fn known_crashing_inputs_are_still_handled() {
    let dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fuzz_crashes");
    let mut count = 0;
    for entry in std::fs::read_dir(&dir)
        .expect("corpus directory missing")
        .flatten()
    {
        // fuzz_crashes/ewf/ holds whole images, covered by the test below.
        if entry.path().is_dir() {
            continue;
        }
        let data = std::fs::read(entry.path()).unwrap();
        if data.len() < 2 {
            continue;
        }
        let sig = &SIGNATURES[data[0] as usize % SIGNATURES.len()];
        let mut tmp = std::env::temp_dir();
        tmp.push(format!(
            "bcrumb-regress-{}-{}",
            std::process::id(),
            entry.file_name().to_string_lossy()
        ));
        std::fs::write(&tmp, &data[1..]).unwrap();
        let started = std::time::Instant::now();
        let Ok(src) = Source::open(tmp.to_str().unwrap()) else {
            // Refusing the file outright is a perfectly good outcome: one of
            // these inputs is a QCOW2 header claiming sixteen exabytes.
            let _ = std::fs::remove_file(&tmp);
            count += 1;
            continue;
        };
        let limit = src.size();
        let mut w = Window::new(&src, 0, limit);
        if let Some(carve) = sig.carve(&mut w) {
            assert!(
                carve.size <= limit,
                "{}: {} carved {} bytes from a {} byte window",
                entry.file_name().to_string_lossy(),
                sig.name,
                carve.size,
                limit
            );
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{}: took {:?}",
            entry.file_name().to_string_lossy(),
            started.elapsed()
        );
        let _ = std::fs::remove_file(&tmp);
        count += 1;
    }
    assert!(count > 0, "no regression inputs found");
}

#[test]
fn a_hostile_ewf_section_chain_does_not_walk_forever() {
    // Sections point forward at each other, and nothing in the format stops an
    // image pointing backwards or in a cycle. cargo-fuzz found a 185-byte file
    // that kept the parser busy for half an hour; it must be refused promptly
    // now, as must everything else in this corpus.
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/fuzz_crashes/ewf");
    let mut count = 0;
    for entry in std::fs::read_dir(&dir)
        .expect("EWF corpus missing")
        .flatten()
    {
        let started = std::time::Instant::now();
        let path = entry.path();
        if let Ok(r) = breadcrumb_rs::ewf::EwfReader::open(path.to_str().unwrap()) {
            // If it opens at all, a read must stay inside what it claims.
            let got = r.pread(0, 4096);
            assert!(got.len() as u64 <= r.size.min(4096));
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{}: took {:?} to resolve",
            path.display(),
            started.elapsed()
        );
        count += 1;
    }
    assert!(count > 0, "no EWF regression inputs found");
}

#[test]
fn a_boot_sector_asking_for_an_impossible_record_size_is_refused() {
    // Byte 64 of an NTFS boot sector is clusters-per-record, or -log2(bytes)
    // when read as a signed byte. 0x80 is -128, so it asks for a record of
    // 1 << 128 bytes -- and a shift that wide is not a big number, it is a
    // panic. Found by the fuzzer on the filesystems target.
    let mut boot = vec![0u8; 8192];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512u16.to_le_bytes());
    boot[13] = 8;
    boot[40..48].copy_from_slice(&16u64.to_le_bytes());
    boot[48..56].copy_from_slice(&1u64.to_le_bytes());
    boot[510..512].copy_from_slice(&[0x55, 0xaa]);

    let mut dir = std::env::temp_dir();
    dir.push(format!("bcrumb-shift-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let img = dir.join("disk.img");

    // Every byte that reads as negative must be refused or accepted, never
    // panic -- and only the shifts that land in range can be accepted.
    for cpr in 128u16..=255 {
        boot[64] = cpr as u8;
        std::fs::write(&img, &boot).unwrap();
        let src = breadcrumb_rs::reader::Source::open(img.to_str().unwrap()).unwrap();
        let opts = breadcrumb_rs::ntfs::Options {
            out_dir: dir.join("out").to_string_lossy().to_string(),
            dry_run: true,
            include_live: false,
            min_size: 0,
            only_path: None,
        };
        let got = breadcrumb_rs::ntfs::recover(&src, 0, &opts, |_| {});
        if !(240..=248).contains(&cpr) {
            assert!(
                got.is_err(),
                "cpr {cpr:#x} produced a record size out of range"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
