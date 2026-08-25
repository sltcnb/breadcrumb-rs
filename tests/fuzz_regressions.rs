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
