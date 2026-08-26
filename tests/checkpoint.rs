//! Checkpointing and resume.

mod builders;

use breadcrumb_rs::carver::{run_parallel, run_ranges, Options};
use breadcrumb_rs::checkpoint::{Checkpoint, Fingerprint};
use breadcrumb_rs::reader::Source;
use breadcrumb_rs::signatures::SIGNATURES;
use std::path::PathBuf;

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("breadcrumb-rs-ckpt-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn join(&self, n: &str) -> PathBuf {
        self.0.join(n)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fingerprint(source: &str, size: u64) -> Fingerprint {
    Fingerprint {
        source: source.into(),
        size,
        types: "png,jpg".into(),
    }
}

#[test]
fn remaining_reports_the_gaps_between_finished_ranges() {
    let dir = Tmp::new("gaps");
    let out = dir.join("out").to_string_lossy().to_string();
    let mut cp = Checkpoint::open(&out, fingerprint("img", 1000), false).unwrap();
    cp.complete(100, 200);
    cp.complete(300, 400);
    assert_eq!(
        cp.remaining(0, 1000),
        vec![(0, 100), (200, 300), (400, 1000)]
    );
    assert_eq!(cp.remaining(150, 350), vec![(200, 300)]);
    assert_eq!(cp.bytes_done(), 200);
    // touching and overlapping ranges coalesce rather than piling up
    cp.complete(200, 300);
    assert_eq!(cp.remaining(0, 1000), vec![(0, 100), (400, 1000)]);
    cp.complete(0, 1000);
    assert!(cp.remaining(0, 1000).is_empty());
}

#[test]
fn progress_survives_reopening_and_is_removed_when_complete() {
    let dir = Tmp::new("persist");
    let out = dir.join("out").to_string_lossy().to_string();
    {
        let mut cp = Checkpoint::open(&out, fingerprint("img", 500), false).unwrap();
        cp.complete(0, 250);
    }
    // A new process resumes where the last one stopped.
    let cp = Checkpoint::open(&out, fingerprint("img", 500), true).unwrap();
    assert_eq!(cp.bytes_done(), 250);
    assert_eq!(cp.remaining(0, 500), vec![(250, 500)]);
    assert!(Checkpoint::path_for(&out).exists());
    cp.finish();
    assert!(
        !Checkpoint::path_for(&out).exists(),
        "a finished scan left state behind, so the next run would skip work"
    );
}

#[test]
fn resuming_a_different_scan_is_refused() {
    let dir = Tmp::new("mismatch");
    let out = dir.join("out").to_string_lossy().to_string();
    {
        let mut cp = Checkpoint::open(&out, fingerprint("first.dd", 500), false).unwrap();
        cp.complete(0, 100);
    }
    // Same output directory, different image: skipping "already done" ranges
    // of the wrong disk would quietly lose evidence.
    let err = Checkpoint::open(&out, fingerprint("second.dd", 900), true)
        .err()
        .expect("mismatched resume was accepted");
    assert!(err.contains("different scan"), "{err}");
    // A different type set counts as a different scan too.
    let other_types = Fingerprint {
        source: "first.dd".into(),
        size: 500,
        types: "pdf".into(),
    };
    assert!(Checkpoint::open(&out, other_types, true).is_err());
}

#[test]
fn a_resumed_scan_finds_what_one_pass_finds() {
    let dir = Tmp::new("equivalent");
    let mut img = Vec::new();
    for i in 0..24u32 {
        img.extend_from_slice(&builders::Rng::new(120 + i as u64).bytes(32 << 10));
        img.extend_from_slice(&builders::make_png());
        img.extend_from_slice(&builders::make_pdf());
    }
    let path = dir.join("img.bin");
    std::fs::write(&path, &img).unwrap();
    let reader = Source::open(path.to_str().unwrap()).unwrap();
    let sigs: Vec<_> = SIGNATURES.iter().collect();
    let key = |rs: &[breadcrumb_rs::carver::Record]| {
        let mut v: Vec<(u64, u64, String)> = rs
            .iter()
            .map(|r| (r.offset, r.size, r.sha256.clone()))
            .collect();
        v.sort();
        v
    };

    let one_pass = {
        let opts = Options {
            out_dir: dir.join("one").to_string_lossy().into(),
            quiet: true,
            dry_run: true,
            ..Options::default()
        };
        run_parallel(&reader, &sigs, &opts)
    };

    // Scan in two halves, as an interrupted run and its resume would.
    let opts = Options {
        out_dir: dir.join("two").to_string_lossy().into(),
        quiet: true,
        dry_run: true,
        ..Options::default()
    };
    let end = img.len() as u64;
    let mid = end / 2;
    let mut done: Vec<(u64, u64)> = Vec::new();
    let mut first = run_ranges(&reader, &sigs, &opts, &[(0, mid)], end, None, |a, b, _| {
        done.push((a, b))
    });
    let second = run_ranges(
        &reader,
        &sigs,
        &opts,
        &[(mid, end)],
        end,
        None,
        |a, b, _| done.push((a, b)),
    );
    first.extend(second);
    assert_eq!(done, vec![(0, mid), (mid, end)]);
    assert_eq!(
        key(&one_pass),
        key(&first),
        "a resumed scan disagreed with a single pass"
    );
}

#[test]
fn a_killed_scan_still_leaves_a_record_of_what_it_found() {
    // The manifest is written when a scan ends. Two killed runs on a real
    // examination left 165 GB of carved files and no record of any of them, so
    // records are streamed to carved.jsonl as each range completes.
    let dir = Tmp::new("stream");
    let png = builders::make_png();
    let mut blob = vec![0u8; 4096];
    for _ in 0..6 {
        blob.extend_from_slice(&png);
        blob.extend_from_slice(&builders::Rng::new(4).bytes(20_000));
    }
    let img = dir.join("disk.dd");
    std::fs::write(&img, &blob).unwrap();
    let out = dir.0.join("out");

    let exe = env!("CARGO_BIN_EXE_bcrumb-rs");
    let run = std::process::Command::new(exe)
        .arg(&img)
        .args(["-t", "png", "--no-dedup", "-q", "-o"])
        .arg(&out)
        .output()
        .expect("failed to run");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );

    let stream = std::fs::read_to_string(out.join("carved.jsonl")).expect("no carved.jsonl");
    let lines: Vec<&str> = stream.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "nothing was streamed");
    // Every line stands on its own, so a file truncated mid-write still parses
    // up to the last complete record.
    for line in &lines {
        let v = breadcrumb_rs::jsonin::parse(line).expect("a streamed line is not JSON");
        assert!(v
            .get("sha256")
            .and_then(|s| s.as_str())
            .is_some_and(|s| s.len() == 64));
        assert!(v.get("offset").and_then(|o| o.as_f64()).is_some());
    }
    // ...and it agrees with the manifest the finished run wrote.
    let manifest = std::fs::read_to_string(out.join("manifest.json")).unwrap();
    let doc = breadcrumb_rs::jsonin::parse(&manifest).unwrap();
    let files = doc.get("files").and_then(|f| f.as_array()).unwrap();
    assert_eq!(
        files.len(),
        lines.len(),
        "the stream and the manifest disagree on how many files were carved"
    );
}
