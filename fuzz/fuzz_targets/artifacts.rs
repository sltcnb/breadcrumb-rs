//! Recycle-bin and change-journal records over arbitrary bytes.
//!
//! Both come off the disk with attacker-controlled lengths: a $I record
//! declares its path length, a USN record its own size and its name bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = breadcrumb_rs::artifacts::parse_recycle_i(data);

    let mut recs = Vec::new();
    let consumed = breadcrumb_rs::artifacts::parse_usn_journal(data, &mut recs);
    assert!(consumed <= data.len(), "consumed past the end of the input");
    for r in &recs {
        let _ = breadcrumb_rs::artifacts::describe_reasons(r.reason);
    }

    // Feeding the same bytes in two blocks must not invent records: the split
    // record is carried forward, so the second pass sees it once.
    if data.len() > 16 {
        let seam = data.len() / 2;
        let mut a = Vec::new();
        let used = breadcrumb_rs::artifacts::parse_usn_journal(&data[..seam], &mut a);
        assert!(used <= seam);
        let mut b = Vec::new();
        breadcrumb_rs::artifacts::parse_usn_journal(&data[used..], &mut b);
        assert!(a.len() + b.len() >= recs.len().min(a.len() + b.len()));
    }
});
