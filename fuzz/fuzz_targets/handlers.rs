//! Every carving handler over arbitrary bytes.
//!
//! Handlers parse structures that come straight off a disk of unknown
//! provenance: sizes, offsets and counts are all attacker-controlled in
//! practice. A handler may reject anything it likes, but it must not panic,
//! must not run forever, and must never return a carve reaching past its
//! window -- the caller writes that many bytes.
#![no_main]

use breadcrumb_rs::reader::Source;
use breadcrumb_rs::signatures::SIGNATURES;
use breadcrumb_rs::window::Window;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    // First byte picks the handler, the rest is the file.
    let sig = &SIGNATURES[data[0] as usize % SIGNATURES.len()];
    let body = &data[1..];

    let mut path = std::env::temp_dir();
    path.push(format!("bcrumb-fuzz-{}", std::process::id()));
    if std::fs::write(&path, body).is_err() {
        return;
    }
    if let Ok(src) = Source::open(path.to_str().unwrap()) {
        let limit = src.size();
        let mut w = Window::new(&src, 0, limit);
        if let Some(carve) = sig.carve(&mut w) {
            assert!(
                carve.size <= limit,
                "{}: carve of {} bytes past a {} byte window",
                sig.name,
                carve.size,
                limit
            );
        }
    }
    let _ = std::fs::remove_file(&path);
});
