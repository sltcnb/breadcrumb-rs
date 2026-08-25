//! The EWF container parser over arbitrary bytes.
//!
//! Section lists, chunk tables and volume geometry are all read from the file,
//! and a malformed or hostile image must be an error rather than a panic, an
//! endless walk, or a read that claims to have data it does not.
#![no_main]

use breadcrumb_rs::ewf::EwfReader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut path = std::env::temp_dir();
    path.push(format!("bcrumb-fuzz-ewf-{}.E01", std::process::id()));
    if std::fs::write(&path, data).is_err() {
        return;
    }
    if let Ok(reader) = EwfReader::open(path.to_str().unwrap()) {
        let size = reader.size;
        // Reads must stay inside what the reader claims, at any offset.
        for off in [0u64, 1, size / 2, size.saturating_sub(1), size, size + 1] {
            let got = reader.pread(off, 4096);
            assert!(
                got.len() as u64 <= size.saturating_sub(off).min(4096),
                "read at {off} returned {} bytes of a {size} byte image",
                got.len()
            );
        }
    }
    let _ = std::fs::remove_file(&path);
});
