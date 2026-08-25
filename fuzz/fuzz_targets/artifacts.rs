//! Recycle-bin and change-journal records over arbitrary bytes.
//!
//! Both come off the disk with attacker-controlled lengths: a $I record
//! declares its path length, a USN record its own size and name bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The Rust port does not parse these yet; the target is kept so it lands
    // with the parser rather than after it. Exercise what is here today.
    let _ = breadcrumb_rs::signatures::resolve_types(&String::from_utf8_lossy(data));
});
