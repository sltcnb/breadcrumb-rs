//! Mutation fuzzing that runs on stable, in ordinary CI.
//!
//! `fuzz/` holds cargo-fuzz targets for long campaigns; this is the part that
//! runs on every commit. Valid files are mutated -- bytes flipped, lengths
//! corrupted, tails truncated, sizes made absurd -- and every handler is run
//! over the result. A handler may reject anything, but it must not panic, must
//! not walk forever, and must never report a carve reaching past its window,
//! because the caller writes exactly that many bytes.

mod builders;

use breadcrumb_rs::bitlocker;
use breadcrumb_rs::ewf::EwfReader;
use breadcrumb_rs::reader::Source;
use breadcrumb_rs::signatures::SIGNATURES;
use breadcrumb_rs::window::Window;
use builders::Rng;
use std::path::PathBuf;
use std::time::{Duration, Instant};

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("breadcrumb-rs-fuzz-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One mutation of `data`, chosen by the generator.
fn mutate(rng: &mut Rng, data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    if out.is_empty() {
        return out;
    }
    match rng.next_u64() % 6 {
        0 => {
            // flip a byte
            let at = (rng.next_u64() as usize) % out.len();
            out[at] ^= 1 << (rng.next_u64() % 8);
        }
        1 => {
            // truncate: the file continues elsewhere on disk
            let keep = (rng.next_u64() as usize) % out.len();
            out.truncate(keep);
        }
        2 => {
            // overwrite a 4-byte field with something absurd, the way a stray
            // header in unrelated data declares its own size
            let at = (rng.next_u64() as usize) % out.len();
            let end = (at + 4).min(out.len());
            let bogus = [0xFF, 0xFF, 0xFF, 0x7F];
            out[at..end].copy_from_slice(&bogus[..end - at]);
        }
        3 => {
            // zero a run: sparse or wiped region
            let at = (rng.next_u64() as usize) % out.len();
            let len = ((rng.next_u64() as usize) % 64).min(out.len() - at);
            out[at..at + len].fill(0);
        }
        4 => out.extend_from_slice(&rng.bytes(64)), // junk after the file
        _ => {
            // splice the file onto itself: two headers, one buffer
            let half = out.len() / 2;
            let tail = out[half..].to_vec();
            out.extend_from_slice(&tail);
        }
    }
    out
}

fn seeds() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = builders::all().into_iter().map(|(_, d)| d).collect();
    out.push(builders::make_macho());
    out.push(builders::make_pe(false));
    out.push(builders::make_flac());
    out.push(builders::make_psd());
    out
}

#[test]
fn handlers_survive_mutated_input() {
    let dir = Tmp::new("handlers");
    let path = dir.0.join("case.bin");
    let mut rng = Rng::new(0xC0FFEE);
    let seeds = seeds();
    let deadline = Instant::now() + Duration::from_secs(50);
    let mut cases = 0u32;

    while cases < 20000 && Instant::now() < deadline {
        let seed = &seeds[(rng.next_u64() as usize) % seeds.len()];
        let mut body = mutate(&mut rng, seed);
        // occasionally mutate twice: single-field damage is the easy case
        // Up to four mutations: single-field damage is the easy case, and
        // overflow bugs tend to need several fields wrong at once.
        for _ in 0..(rng.next_u64() % 4) {
            body = mutate(&mut rng, &body);
        }
        std::fs::write(&path, &body).unwrap();
        let Ok(src) = Source::open(path.to_str().unwrap()) else {
            continue;
        };
        let limit = src.size();
        for sig in SIGNATURES {
            let started = Instant::now();
            let mut w = Window::new(&src, 0, limit);
            if let Some(carve) = sig.carve(&mut w) {
                assert!(
                    carve.size <= limit,
                    "{} carved {} bytes from a {} byte window\ninput: {:02x?}",
                    sig.name,
                    carve.size,
                    limit,
                    &body[..body.len().min(48)]
                );
            }
            // A handler that takes seconds on a few KB would take days on a
            // disk full of near-miss headers.
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "{} took {:?} on {} bytes",
                sig.name,
                started.elapsed(),
                body.len()
            );
        }
        cases += 1;
    }
    assert!(cases > 200, "only managed {cases} cases");
}

#[test]
fn the_ewf_parser_survives_mutated_images() {
    let dir = Tmp::new("ewf");
    let path = dir.0.join("img.E01");
    let mut rng = Rng::new(0xBEEF);
    // A structurally valid E01 to mutate, built the way tests/ewf.rs does.
    let mut base = b"EVF\x09\x0d\x0a\xff\x00".to_vec();
    base.push(1);
    base.extend_from_slice(&1u16.to_le_bytes());
    base.extend_from_slice(&0u16.to_le_bytes());
    base.extend_from_slice(&rng.bytes(4096));

    for _ in 0..600 {
        let body = mutate(&mut rng, &base);
        std::fs::write(&path, &body).unwrap();
        if let Ok(r) = EwfReader::open(path.to_str().unwrap()) {
            let size = r.size;
            let got = r.pread(0, 8192);
            assert!(
                got.len() as u64 <= size.min(8192),
                "read {} bytes from a {} byte image",
                got.len(),
                size
            );
            // reads past the end must be empty, not wrapped or panicking
            assert!(r.pread(size, 512).is_empty());
        }
    }
}

#[test]
fn fve_metadata_parsing_survives_mutated_blocks() {
    let mut rng = Rng::new(0xFEED);
    let creds = bitlocker::Credentials {
        recovery: Some("011000-022000-033000-044000-055000-066000-077000-088000".into()),
        ..Default::default()
    };
    let mut base = b"-FVE-FS-".to_vec();
    base.extend_from_slice(&rng.bytes(0x400));

    for _ in 0..800 {
        let block = mutate(&mut rng, &base);
        if let Ok(meta) = bitlocker::parse_metadata(&block) {
            let _ = meta.protectors();
            // Nonsense metadata must fail, not panic or spin.
            let started = Instant::now();
            let _ = bitlocker::describe_metadata(&meta, &creds);
            assert!(started.elapsed() < Duration::from_secs(2), "describe hung");
        }
    }
}

#[test]
fn deletion_artefact_parsing_survives_mutated_records() {
    // Both records declare their own lengths on disk: a $I record its path
    // length, a USN record its size and its name bounds.
    let mut rng = Rng::new(0xDE1E7E);
    let mut recycle = 2u64.to_le_bytes().to_vec();
    recycle.extend_from_slice(&44_213u64.to_le_bytes());
    recycle.extend_from_slice(&133_400_000_000_000_000u64.to_le_bytes());
    recycle.extend_from_slice(&12u32.to_le_bytes());
    recycle.extend_from_slice(
        &"C:\\a\\b.txt\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>(),
    );

    let mut journal = vec![0u8; 64];
    journal.extend_from_slice(&96u32.to_le_bytes());
    journal.extend_from_slice(&2u16.to_le_bytes());
    journal.extend_from_slice(&0u16.to_le_bytes());
    journal.resize(64 + 24, 0);
    journal.extend_from_slice(&1u64.to_le_bytes()); // usn
    journal.extend_from_slice(&133_400_000_000_000_000u64.to_le_bytes());
    journal.extend_from_slice(&0x200u32.to_le_bytes()); // file-delete
    journal.resize(64 + 24 + 32, 0);
    journal.extend_from_slice(&20u16.to_le_bytes()); // name length
    journal.extend_from_slice(&60u16.to_le_bytes()); // name offset
    journal.resize(64 + 96, 0x41);

    for _ in 0..2000 {
        let started = Instant::now();
        let r = mutate(&mut rng, &recycle);
        if let Some(entry) = breadcrumb_rs::artifacts::parse_recycle_i(&r) {
            // A path is only ever read from inside the record.
            assert!(entry.path.len() <= r.len() * 2);
        }
        let j = mutate(&mut rng, &journal);
        let mut recs = Vec::new();
        let consumed = breadcrumb_rs::artifacts::parse_usn_journal(&j, &mut recs);
        assert!(consumed <= j.len(), "consumed past the end of the stream");
        for rec in &recs {
            let _ = breadcrumb_rs::artifacts::describe_reasons(rec.reason);
            assert!(rec.name.len() <= j.len() * 2);
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "journal walk hung"
        );
    }
}

#[test]
fn filesystem_parsers_survive_mutated_volumes() {
    // The undelete modes read geometry, runlists, extents and directory entries
    // straight off the disk. A mutated volume must be refused or partly read,
    // never panic and never hang -- and never write anything, since these run
    // with dry_run set.
    let mut rng = Rng::new(0xF11E5);
    let dir = Tmp::new("fsparsers");
    let fixtures = [
        "tests/fixtures/ntfs_deleted.img",
        "tests/fixtures/ntfs_artifacts.img",
    ];
    let mut bases: Vec<Vec<u8>> = Vec::new();
    for rel in fixtures {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
        if let Ok(data) = std::fs::read(&p) {
            bases.push(data);
        }
    }
    assert!(!bases.is_empty(), "no volume fixtures to mutate");

    let out = dir.0.join("out").to_string_lossy().to_string();
    for round in 0..40 {
        let base = &bases[round % bases.len()];
        let mutated = mutate(&mut rng, base);
        let img = dir.0.join("volume.img");
        if std::fs::write(&img, &mutated).is_err() {
            continue;
        }
        let Ok(src) = Source::open(img.to_str().unwrap()) else {
            continue;
        };
        let started = Instant::now();
        let _ = breadcrumb_rs::ntfs::recover(
            &src,
            0,
            &breadcrumb_rs::ntfs::Options {
                out_dir: out.clone(),
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
                out_dir: out.clone(),
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
                out_dir: out.clone(),
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
                out_dir: out.clone(),
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
                out_dir: out.clone(),
                dry_run: true,
                min_size: 0,
            },
            |_| {},
        );
        let _ = breadcrumb_rs::partition::parse(&src);
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "a filesystem parser hung on round {round}"
        );
        // dry_run must mean exactly that.
        assert!(
            !std::path::Path::new(&out).exists(),
            "a dry run wrote to {out}"
        );
    }
}
