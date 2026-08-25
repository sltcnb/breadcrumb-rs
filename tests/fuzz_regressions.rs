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
        let src = Source::open(tmp.to_str().unwrap()).unwrap();
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
