//! BitLocker metadata parsing over arbitrary bytes.
//!
//! The FVE metadata carries lengths and nested entry lists that decide how far
//! the parser walks and how key material is read. It is reached before any
//! credential is verified, so it has to survive whatever is on the disk.
#![no_main]

use breadcrumb_rs::bitlocker::{parse_metadata, Credentials};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Give the fuzzer a head start on the signature so it spends its time on
    // the structure rather than guessing eight magic bytes.
    let mut block = b"-FVE-FS-".to_vec();
    block.extend_from_slice(data);
    if let Ok(meta) = parse_metadata(&block) {
        let _ = meta.protectors();
        let creds = Credentials {
            recovery: Some("011000-022000-033000-044000-055000-066000-077000-088000".into()),
            ..Default::default()
        };
        // Recovery must fail cleanly on nonsense, not panic or hang.
        let _ = breadcrumb_rs::bitlocker::recover_fvek_candidates(&meta, &creds);
        let _ = breadcrumb_rs::bitlocker::describe_metadata(&meta, &creds);
    }
});
