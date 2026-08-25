//! The filesystem parsers over arbitrary bytes.
//!
//! Every geometry field, every runlist, every extent and every directory entry
//! these read comes off a disk of unknown provenance. A parser may refuse
//! anything it likes, but it must not panic, must not run forever, and must not
//! be talked into an enormous allocation by a declared length.
#![no_main]

use breadcrumb_rs::reader::Source;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }
    let mut path = std::env::temp_dir();
    path.push(format!("bcrumb-fuzz-fs-{}", std::process::id()));
    if std::fs::write(&path, data).is_err() {
        return;
    }
    let Ok(src) = Source::open(path.to_str().unwrap()) else {
        let _ = std::fs::remove_file(&path);
        return;
    };

    let mut out = std::env::temp_dir();
    out.push(format!("bcrumb-fuzz-fs-out-{}", std::process::id()));

    // dry_run everywhere: the parsers are what is being exercised, and a fuzz
    // run should not be writing recovered files to the disk.
    let _ = breadcrumb_rs::ntfs::recover(
        &src,
        0,
        &breadcrumb_rs::ntfs::Options {
            out_dir: out.to_string_lossy().to_string(),
            dry_run: true,
            include_live: true,
            min_size: 0,
        },
        |_| {},
    );
    let _ = breadcrumb_rs::fat::recover(
        &src,
        0,
        &breadcrumb_rs::fat::Options {
            out_dir: out.to_string_lossy().to_string(),
            dry_run: true,
            include_live: true,
            min_size: 0,
        },
        |_| {},
    );
    let _ = breadcrumb_rs::ext4::recover(
        &src,
        0,
        &breadcrumb_rs::ext4::Options {
            out_dir: out.to_string_lossy().to_string(),
            dry_run: true,
            include_live: true,
            min_size: 0,
        },
        |_| {},
    );
    let _ = breadcrumb_rs::hfs::recover(
        &src,
        0,
        &breadcrumb_rs::hfs::Options {
            out_dir: out.to_string_lossy().to_string(),
            dry_run: true,
            include_live: true,
            min_size: 0,
            scan_volume: true,
        },
        |_| {},
    );
    let _ = breadcrumb_rs::apfs::recover(
        &src,
        0,
        &breadcrumb_rs::apfs::Options {
            out_dir: out.to_string_lossy().to_string(),
            dry_run: true,
            min_size: 0,
        },
        |_| {},
    );
    let _ = breadcrumb_rs::partition::parse(&src);
    let _ = std::fs::remove_file(&path);
});
