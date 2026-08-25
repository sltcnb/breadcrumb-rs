//! bcrumb-rs: signature-based file carver for disk images and block devices.

use breadcrumb_rs::carver::{run_parallel, run_ranges, Options, Record};
use breadcrumb_rs::checkpoint;
use breadcrumb_rs::json;
use breadcrumb_rs::reader::Source;
use breadcrumb_rs::report;
use breadcrumb_rs::signatures::{resolve_types, Signature, SIGNATURES};
use std::process::ExitCode;
use std::time::Instant;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
usage: bcrumb-rs [options] <source>

  <source>                disk image file or block device

options:
  -o, --output DIR        output directory (default: ./carved)
  -t, --types LIST        comma-separated types to carve (default: all)
      --list-types        list supported types and exit
  -j, --jobs N            parallel scan threads (0 = all cores, default 1)
      --offset N          start scanning at byte N
      --length N          scan only N bytes
      --align N           only carve headers on N-byte boundaries
      --min-size N        drop carves smaller than N bytes
      --max-size N        cap every carve window at N bytes
      --chunk N           scan chunk size (default 32 MiB)
      --no-skip           also carve files embedded inside other files
      --no-dedup          keep byte-identical duplicates
      --dry-run           inventory only, write nothing
      --max-output SIZE   stop after writing this much carved data, keeping the
                          manifest (default: none)
      --min-free SIZE     stop when the output filesystem has less than this
                          free (default 2G; 0 disables the check)
      --grep PATTERN      search the source for a string instead of carving
                          (repeatable; both ASCII and UTF-16LE are matched)
  -i, --ignore-case       case-insensitive --grep
      --max-hits N        stop after N --grep hits
      --ntfs              NTFS undelete: walk the MFT for deleted files,
                          recovering names, paths and timestamps
      --include-live      with --ntfs, also recover files still in use
      --deleted-times     when files were deleted, from $Recycle.Bin/$I records
                          and the $UsnJrnl change journal (writes deletions.csv)
      --usn-all           with --deleted-times, report every journal reason,
                          not only deletions
      --events FILE       write the deletion events to this CSV instead
                          (the source may also be a folder of already-extracted
                          $I / $UsnJrnl files rather than an image)
      --list-partitions   print the partition table and detected filesystems
      --csv FILE          write a CSV of the carve results
      --bodyfile FILE     write a Sleuth Kit bodyfile
      --timeline FILE     write a timeline CSV
      --html FILE         write an HTML report
      --hash-source       hash the whole source for the manifest (custody)
      --verify            recompute the image hashes and compare them with the
                          ones the acquisition recorded, then exit
      --resume            continue a scan that stopped, skipping the ranges
                          already finished (state lives in <out>/.bcrumb-state)
      --bitlocker-recovery-key KEY
                          unlock BitLocker volume(s) with a 48-digit key
      --bitlocker-password PASS
                          unlock BitLocker with the user passphrase
      --bitlocker-bek FILE
                          unlock BitLocker with a startup-key .BEK file
      --bitlocker-fvek HEX
                          supply the raw FVEK, skipping key recovery
      --bitlocker-scan-metadata
                          search the volume for FVE metadata when the offsets
                          in the boot sector do not resolve (reads it all)
      --machine           JSON-lines events on stdout (for wrapping)
      --hexdump OFF[:LEN] print LEN bytes at OFF (decoded, after any unlock)
                          and exit; for inspecting a structure by hand
      --dump-fve          describe the BitLocker metadata (entry types, sizes,
                          protectors, payload shapes) and exit; no key material
  -q, --quiet             no progress output
  -V, --version           print version and exit
  -h, --help              this help

Sizes accept K/M/G/T suffixes (e.g. --chunk 64M, --max-output 20G).

by scenario
  documents off a disk image
    bcrumb-rs disk.dd -t office -o out
  ...that is BitLocker-encrypted (E01 sets: pass the FIRST segment only)
    bcrumb-rs disk.E01 -t office -o out --bitlocker-recovery-key 650441-...-609257
  filenames, paths and timestamps instead of bytes (NTFS)
    bcrumb-rs disk.E01 --ntfs -o out --csv files.csv
  when files were deleted (recycle bin + change journal)
    bcrumb-rs disk.E01 --deleted-times -o out
  ...from artefacts already pulled off a machine
    bcrumb-rs ./artefacts --deleted-times --events deletions.csv
  what is on the disk before committing to a long scan
    bcrumb-rs disk.E01 --list-partitions
  inventory first: how much would a full carve write?
    bcrumb-rs disk.E01 --dry-run -t office
  a big disk, all cores, output somewhere with room
    bcrumb-rs disk.E01 -j 0 -o /mnt/scratch/out
  find a keyword, in ASCII and UTF-16LE
    bcrumb-rs disk.E01 --grep secret-project --max-hits 50
  a case file: CSV, timeline, HTML report and a custody hash
    bcrumb-rs disk.dd -o out --csv files.csv --timeline t.csv --html r.html --hash-source
  read from a pipe (spooled to a temp file, since handlers seek)
    dd if=/dev/sdb | bcrumb-rs - -o out
  inspect a structure by hand, decrypted
    bcrumb-rs disk.E01 --hexdump 0xe500000:512 --bitlocker-recovery-key ...
  a BitLocker volume that will not open
    bcrumb-rs disk.E01 --dump-fve --bitlocker-recovery-key ...
    bcrumb-rs disk.E01 --bitlocker-scan-metadata --bitlocker-recovery-key ...

Carving gives bytes; --ntfs gives names, paths and timestamps. Deletion times
(recycle bin, change journal) are not ported yet.
";

/// Split the outstanding work into ranges, aligned to the scan chunk size so a
/// resumed run reads the same boundaries as the original.
fn plan_ranges(
    state: &checkpoint::Checkpoint,
    start: u64,
    end: u64,
    chunk: u64,
    jobs: usize,
) -> Vec<(u64, u64)> {
    // Aim for a few ranges per worker: small enough that a kill loses little,
    // large enough that the per-range overhead stays invisible.
    let total = end.saturating_sub(start);
    let target = (total / (jobs.max(1) as u64 * 4)).max(chunk);
    let mut out = Vec::new();
    for (a, b) in state.remaining(start, end) {
        let mut pos = a;
        while pos < b {
            let stop = (pos + target).min(b);
            out.push((pos, stop));
            pos = stop;
        }
    }
    out
}

/// Fold records from a previous attempt's manifest into this run's, so a
/// resumed scan reports the whole image rather than only the part it did.
fn merge_with_existing(out_dir: &str, mut records: Vec<Record>) -> Vec<Record> {
    let path = std::path::Path::new(out_dir).join("manifest.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return records;
    };
    // The manifest is ours and its shape is fixed, so the fields are pulled out
    // directly rather than pulling in a JSON parser for one use.
    let mut recovered = 0usize;
    for line in text.lines() {
        let get = |key: &str| -> Option<&str> {
            let at = line.find(&format!("\"{key}\": "))? + key.len() + 4;
            let rest = &line[at..];
            let end = rest.find(',').unwrap_or(rest.len());
            Some(rest[..end].trim().trim_matches('"'))
        };
        let (Some(off), Some(size), Some(sha)) = (get("offset"), get("size"), get("sha256")) else {
            continue;
        };
        let (Ok(offset), Ok(size)) = (off.parse::<u64>(), size.parse::<u64>()) else {
            continue;
        };
        if records.iter().any(|r| r.offset == offset && r.size == size) {
            continue;
        }
        records.push(Record {
            kind: "carved",
            ext: get("ext").unwrap_or("bin").to_string().leak(),
            offset,
            size,
            sha256: sha.to_string(),
            validated: get("validated") == Some("true"),
            path: get("path").unwrap_or("").to_string(),
            duplicate_of: None,
        });
        recovered += 1;
    }
    if recovered > 0 {
        eprintln!("resumed: carried {recovered} record(s) forward from the earlier manifest");
    }
    records.sort_by_key(|r| (r.offset, r.size));
    records
}

/// Bytes free on the filesystem holding `path` (or its nearest existing parent).
fn free_space(path: &str) -> Option<u64> {
    let mut probe = std::path::PathBuf::from(path);
    loop {
        if probe.exists() {
            break;
        }
        match probe.parent() {
            Some(p) if !p.as_os_str().is_empty() => probe = p.to_path_buf(),
            _ => return None,
        }
    }
    let out = std::process::Command::new("df")
        .arg("-Pk")
        .arg(&probe)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().nth(1)?;
    let avail_kb: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    Some(avail_kb * 1024)
}

fn human(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("TiB", 1 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
    ];
    for (name, scale) in UNITS {
        if bytes >= scale {
            return format!("{:.1} {name}", bytes as f64 / scale as f64);
        }
    }
    format!("{bytes} B")
}

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('k') | Some('K') => (&s[..s.len() - 1], 1u64 << 10),
        Some('m') | Some('M') => (&s[..s.len() - 1], 1u64 << 20),
        Some('g') | Some('G') => (&s[..s.len() - 1], 1u64 << 30),
        Some('t') | Some('T') => (&s[..s.len() - 1], 1u64 << 40),
        _ => (s, 1),
    };
    num.parse::<u64>()
        .map(|n| n * mult)
        .map_err(|_| format!("not a size: {s:?}"))
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("bcrumb-rs: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut opts = Options::default();
    let mut source: Option<String> = None;
    let mut types: Option<String> = None;
    let mut grep_patterns: Vec<String> = Vec::new();
    let mut ignore_case = false;
    let mut max_hits: usize = 0;
    let mut list_partitions = false;
    let mut csv_path: Option<String> = None;
    let mut bodyfile_path: Option<String> = None;
    let mut timeline_path: Option<String> = None;
    let mut html_path: Option<String> = None;
    let mut hash_source = false;
    let mut machine = false;
    let mut creds = breadcrumb_rs::bitlocker::Credentials::default();
    let mut scan_metadata = false;
    let mut hexdump: Option<(u64, usize)> = None;
    let mut dump_fve = false;
    let mut verify = false;
    let mut resume = false;
    let mut ntfs_mode = false;
    let mut include_live = false;
    let mut deleted_times = false;
    let mut usn_all = false;
    let mut events_path: Option<String> = None;
    let mut i = 0;

    while i < argv.len() {
        let arg = argv[i].as_str();
        let next = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            argv.get(*i)
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            "-V" | "--version" => {
                println!("bcrumb-rs {VERSION}");
                return Ok(ExitCode::SUCCESS);
            }
            "--list-types" => {
                println!("{:<8} DESCRIPTION", "TYPE");
                for s in SIGNATURES {
                    println!("{:<8} {}", s.name, s.description);
                }
                println!("\ngroups (usable in -t):");
                for (name, members) in breadcrumb_rs::signatures::GROUPS {
                    println!("  {:<9} {}", name, members.join(", "));
                }
                return Ok(ExitCode::SUCCESS);
            }
            "-o" | "--output" => opts.out_dir = next(&mut i)?,
            "-t" | "--types" => types = Some(next(&mut i)?),
            "-j" | "--jobs" => {
                let v = next(&mut i)?;
                let n: usize = v.parse().map_err(|_| format!("not a number: {v:?}"))?;
                opts.jobs = if n == 0 {
                    std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(1)
                } else {
                    n
                };
            }
            "--offset" => opts.start = parse_size(&next(&mut i)?)?,
            "--length" => opts.length = parse_size(&next(&mut i)?)?,
            "--align" => opts.align = parse_size(&next(&mut i)?)?.max(1),
            "--min-size" => opts.min_size = parse_size(&next(&mut i)?)?,
            "--max-size" => opts.max_size = parse_size(&next(&mut i)?)?,
            "--chunk" => opts.chunk_size = parse_size(&next(&mut i)?)?.max(1 << 16),
            "--no-skip" => opts.skip_carved = false,
            "--no-dedup" => opts.dedup = false,
            "--dry-run" => opts.dry_run = true,
            "--max-output" => opts.max_output = parse_size(&next(&mut i)?)?,
            "--min-free" => opts.min_free = parse_size(&next(&mut i)?)?,
            "--grep" => grep_patterns.push(next(&mut i)?),
            "-i" | "--ignore-case" => ignore_case = true,
            "--max-hits" => {
                let v = next(&mut i)?;
                max_hits = v.parse().map_err(|_| format!("not a number: {v:?}"))?;
            }
            "--ntfs" => ntfs_mode = true,
            "--include-live" => include_live = true,
            "--deleted-times" => deleted_times = true,
            "--usn-all" => usn_all = true,
            "--events" => events_path = Some(next(&mut i)?),
            "--list-partitions" | "--list-parts" => list_partitions = true,
            "--csv" => csv_path = Some(next(&mut i)?),
            "--bodyfile" => bodyfile_path = Some(next(&mut i)?),
            "--timeline" => timeline_path = Some(next(&mut i)?),
            "--html" => html_path = Some(next(&mut i)?),
            "--hash-source" => hash_source = true,
            "--verify" => verify = true,
            "--resume" => resume = true,
            "--bitlocker-recovery-key" => {
                let key = next(&mut i)?;
                // Fail on a malformed key here rather than after a long scan.
                breadcrumb_rs::bitlocker::parse_recovery_password(&key)
                    .map_err(|e| format!("--bitlocker-recovery-key: {e}"))?;
                creds.recovery = Some(key);
            }
            "--bitlocker-password" => creds.password = Some(next(&mut i)?),
            "--bitlocker-scan-metadata" => scan_metadata = true,
            "--dump-fve" => dump_fve = true,
            "--hexdump" => {
                let v = next(&mut i)?;
                let (off, len) = match v.split_once(':') {
                    Some((o, l)) => (o.to_string(), parse_size(l)? as usize),
                    None => (v, 256),
                };
                let off = if let Some(hex) = off.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).map_err(|_| format!("not an offset: {off:?}"))?
                } else {
                    parse_size(&off)?
                };
                hexdump = Some((off, len));
            }
            "--bitlocker-bek" => {
                let path = next(&mut i)?;
                creds.bek = Some(
                    std::fs::read(&path).map_err(|e| format!("--bitlocker-bek: {path}: {e}"))?,
                );
            }
            "--bitlocker-fvek" => {
                let hex = next(&mut i)?.replace([':', ' '], "");
                if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("--bitlocker-fvek must be hex".into());
                }
                creds.fvek = Some(
                    (0..hex.len() / 2)
                        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
                        .collect(),
                );
            }
            "--machine" => {
                machine = true;
                opts.quiet = true;
            }
            "-q" | "--quiet" => opts.quiet = true,
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unknown option {other:?} (--help)"));
            }
            other => {
                if source.replace(other.to_string()).is_some() {
                    return Err("more than one source given".into());
                }
            }
        }
        i += 1;
    }

    let source = match source {
        Some(s) => s,
        None => {
            print!("{USAGE}");
            return Ok(ExitCode::from(2));
        }
    };

    let sigs: Vec<&'static Signature> = match &types {
        Some(spec) => resolve_types(spec)?,
        None => SIGNATURES.iter().collect(),
    };
    if sigs.is_empty() {
        return Err("no signatures selected".into());
    }

    if deleted_times && std::path::Path::new(&source).is_dir() {
        let events = breadcrumb_rs::artifacts::scan_tree(&source, !usn_all);
        return report_deletions(events, &opts, events_path.as_deref(), machine, &[]);
    }

    let reader = Source::open(&source).map_err(|e| format!("{source}: {e}"))?;

    if dump_fve {
        use breadcrumb_rs::bitlocker as bl;
        let mut bases = vec![0u64];
        for p in breadcrumb_rs::partition::parse(&reader) {
            if p.start > 0 {
                bases.push(p.start);
            }
        }
        let mut found = false;
        for base in bases {
            if !bl::is_bitlocker(&reader, base) {
                continue;
            }
            found = true;
            println!("BitLocker volume at {base:#x}");
            let boot = reader.pread(base, 512);
            if let Some(id) = bl::volume_identifier(&boot) {
                println!("  volume identifier {id}");
            }
            let mut meta = None;
            for off in bl::metadata_offsets_pub(&boot) {
                let block = reader.pread(base + off, 0x10000);
                if block.len() >= 8 && block.starts_with(bl::FVE_SIGNATURE) {
                    if let Ok(m) = bl::parse_metadata(&block) {
                        println!("  metadata at {off:#x} (volume-relative)");
                        meta = Some(m);
                        break;
                    }
                }
            }
            if meta.is_none() && scan_metadata {
                meta = bl::scan_for_metadata(&reader, base, reader.size() - base, |m| {
                    println!("  {m}")
                });
            }
            match meta {
                Some(m) => {
                    for line in bl::describe_metadata(&m, &creds) {
                        println!("  {line}");
                    }
                }
                None => println!("  no metadata block found"),
            }
        }
        if !found {
            println!("no BitLocker volume found");
        }
        return Ok(ExitCode::SUCCESS);
    }

    let quiet = opts.quiet;
    let reader = reader.unlock_bitlocker(&creds, scan_metadata, |msg| {
        if !quiet {
            eprintln!("{msg}");
        }
    })?;

    if let Some((off, len)) = hexdump {
        let data = reader.pread(off, len);
        println!(
            "{} bytes at {off:#x} (source is {} bytes)",
            data.len(),
            reader.size()
        );
        for (row, chunk) in data.chunks(16).enumerate() {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            let text: String = chunk
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            println!(
                "{:08x}  {:47}  {}",
                off as usize + row * 16,
                hex.join(" "),
                text
            );
        }
        return Ok(ExitCode::SUCCESS);
    }

    if verify {
        return verify_image(&reader, opts.quiet);
    }

    if deleted_times {
        return run_deleted_times(&reader, &opts, usn_all, events_path.as_deref(), machine);
    }

    if ntfs_mode {
        return run_ntfs(&reader, &opts, include_live, machine, csv_path.as_deref());
    }

    if list_partitions {
        let parts = breadcrumb_rs::partition::parse(&reader);
        println!("{}", breadcrumb_rs::partition::format_table(&parts));
        return Ok(ExitCode::SUCCESS);
    }

    if !grep_patterns.is_empty() {
        let mut count = 0usize;
        breadcrumb_rs::grep::search(
            &reader,
            &grep_patterns,
            opts.start,
            opts.length,
            ignore_case,
            max_hits,
            |h| {
                count += 1;
                if machine {
                    println!(
                        "{}",
                        json::object(vec![
                            ("event", json::string("hit")),
                            ("offset", json::number(h.offset)),
                            ("pattern", json::string(&h.pattern)),
                            ("encoding", json::string(h.encoding)),
                            ("context", json::string(&h.context)),
                        ])
                    );
                } else {
                    println!(
                        "{:#014x}  {:<9} {:?}: {}",
                        h.offset, h.encoding, h.pattern, h.context
                    );
                }
            },
        );
        if !opts.quiet && !machine {
            eprintln!("\n{count} hit(s)");
        }
        return Ok(ExitCode::SUCCESS);
    }
    if !opts.quiet {
        eprintln!(
            "scanning {}{} ({:.1} MiB) for {} type(s), {} thread(s)",
            reader.path(),
            reader.describe(),
            reader.size() as f64 / (1 << 20) as f64,
            sigs.len(),
            opts.jobs
        );
    }

    // Pre-flight: a carve can outgrow the volume it is written to, and filling
    // the filesystem takes the machine with it. Warn before starting, and let
    // the scan stop itself if it gets close.
    if !opts.dry_run {
        if opts.min_free == 0 {
            opts.min_free = 2 << 30; // 2 GiB, unless the operator said otherwise
        }
        if let Some(free) = free_space(&opts.out_dir) {
            if !opts.quiet {
                eprintln!(
                    "output: {} free on the target volume, stopping at {} free{}",
                    human(free),
                    human(opts.min_free),
                    match opts.max_output {
                        0 => String::new(),
                        n => format!(" or {} written", human(n)),
                    }
                );
            }
            if free <= opts.min_free {
                return Err(format!(
                    "only {} free on {} (below the {} floor); write elsewhere, \
                     narrow --types, or lower --min-free",
                    human(free),
                    opts.out_dir,
                    human(opts.min_free)
                ));
            }
        }
    }

    let t0 = Instant::now();
    // A scan of a large image is long enough that dying part-way through should
    // not mean starting over: completed ranges are checkpointed, and --resume
    // picks up the rest.
    let scan_end = if opts.length > 0 {
        (opts.start + opts.length).min(reader.size())
    } else {
        reader.size()
    };
    let records = if opts.dry_run {
        run_parallel(&reader, &sigs, &opts)
    } else {
        let fingerprint = checkpoint::Fingerprint {
            source: reader.path().to_string(),
            size: reader.size(),
            types: sigs.iter().map(|s| s.name).collect::<Vec<_>>().join(","),
        };
        let mut state = checkpoint::Checkpoint::open(&opts.out_dir, fingerprint, resume)?;
        let ranges = plan_ranges(&state, opts.start, scan_end, opts.chunk_size, opts.jobs);
        if resume && state.bytes_done() > 0 && !opts.quiet {
            eprintln!(
                "resuming: {} of {} already scanned, {} range(s) left",
                human(state.bytes_done()),
                human(scan_end - opts.start),
                ranges.len()
            );
        }
        let recs = run_ranges(&reader, &sigs, &opts, &ranges, scan_end, |a, b| {
            state.complete(a, b)
        });
        let complete = state.remaining(opts.start, scan_end).is_empty();
        let mut merged = recs;
        if resume {
            merged = merge_with_existing(&opts.out_dir, merged);
        }
        if complete {
            state.finish();
        } else if !opts.quiet {
            eprintln!(
                "scan incomplete: {} of {} done. Re-run with --resume to continue",
                human(state.bytes_done()),
                human(scan_end - opts.start)
            );
        }
        merged
    };
    let elapsed = t0.elapsed().as_secs_f64();

    if machine {
        for r in &records {
            println!(
                "{}",
                json::object(vec![
                    ("event", json::string("carve")),
                    ("type", json::string(r.kind)),
                    ("ext", json::string(r.ext)),
                    ("offset", json::number(r.offset)),
                    ("size", json::number(r.size)),
                    ("sha256", json::string(&r.sha256)),
                    ("validated", json::boolean(r.validated)),
                    ("path", json::string(&r.path)),
                ])
            );
        }
    }

    let source_hash = if hash_source {
        Some(hash_whole_source(&reader))
    } else {
        None
    };
    for (path, body) in [
        (csv_path, report::csv(&records)),
        (bodyfile_path, report::bodyfile(&records)),
        (timeline_path, report::timeline(&records)),
        (
            html_path,
            report::html(reader.path(), reader.size(), &records, elapsed),
        ),
    ] {
        if let Some(path) = path {
            if let Some(parent) = std::path::Path::new(&path).parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            std::fs::write(&path, body).map_err(|e| format!("{path}: {e}"))?;
            if !opts.quiet {
                eprintln!("wrote {path}");
            }
        }
    }

    let manifest_path = write_manifest(
        &source,
        &reader,
        &records,
        &opts,
        elapsed,
        source_hash.as_deref(),
    )?;
    if machine {
        println!(
            "{}",
            json::object(vec![
                ("event", json::string("summary")),
                ("carved", json::number(records.len() as u64)),
                ("source_size", json::number(reader.size())),
                ("elapsed_s", json::float(elapsed)),
                ("manifest", json::string(&manifest_path)),
            ])
        );
    }
    if !opts.quiet {
        let written: u64 = records
            .iter()
            .filter(|r| !r.path.is_empty())
            .map(|r| r.size)
            .sum();
        if opts.max_output > 0 && written >= opts.max_output {
            eprintln!(
                "stopped at the {} output limit: the scan did not finish, and \
                 the manifest covers only what was written",
                human(opts.max_output)
            );
        }
        let mibs = reader.size() as f64 / (1 << 20) as f64 / elapsed.max(1e-9);
        let dups = records.iter().filter(|r| r.duplicate_of.is_some()).count();
        eprintln!(
            "carved {} file(s){} in {:.2}s ({:.0} MiB/s) -> {}",
            records.len() - dups,
            if dups > 0 {
                format!(", {dups} duplicate(s)")
            } else {
                String::new()
            },
            elapsed,
            mibs,
            manifest_path
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// NTFS undelete: recover deleted files with their names and timestamps.
///
/// Carving finds content; this finds files. Where the MFT still describes a
/// deleted file, its name, directory path and four timestamps come back with
/// it, and a fragmented file is reassembled from its runlist instead of being
/// carved as its first fragment plus junk.
/// Deletion times, which carving and the MFT alone cannot give.
///
/// `$STANDARD_INFORMATION` has no deleted field, so this reads the two places
/// Windows does record one: a `$I` file per Explorer-deleted item, and the
/// `FILE_DELETE` records in the change journal.
fn run_deleted_times(
    reader: &Source,
    opts: &Options,
    usn_all: bool,
    events_path: Option<&str>,
    machine: bool,
) -> Result<ExitCode, String> {
    let base = ntfs_base(reader, opts)?;
    // 256 MiB per artefact: a journal is normally far smaller, and the cap
    // keeps a corrupt one from being read as gigabytes.
    let found = breadcrumb_rs::ntfs::deletion_events(reader, base, !usn_all, 256 << 20)?;
    report_deletions(found.events, opts, events_path, machine, &found.sources)
}

fn report_deletions(
    mut events: Vec<breadcrumb_rs::artifacts::DeletionEvent>,
    opts: &Options,
    events_path: Option<&str>,
    machine: bool,
    sources: &[(String, usize)],
) -> Result<ExitCode, String> {
    use breadcrumb_rs::artifacts;

    if !opts.quiet {
        for (path, count) in sources {
            eprintln!("artefact: {path} ({count} event(s))");
        }
    }
    if events.is_empty() {
        if !opts.quiet {
            eprintln!(
                "no deletion artefacts found; the recycle bin may be empty and \
                 the change journal disabled or wiped"
            );
        }
        return Ok(ExitCode::SUCCESS);
    }
    events.sort_by(|a, b| a.when.cmp(&b.when).then_with(|| a.name.cmp(&b.name)));
    if machine {
        for e in &events {
            println!(
                "{}",
                json::object(vec![
                    ("event", json::string("deletion")),
                    ("when", json::number(e.when)),
                    ("source", json::string(e.source)),
                    ("name", json::string(&e.name)),
                    ("size", json::number(e.size)),
                    ("detail", json::string(&e.detail)),
                ])
            );
        }
    } else if !opts.quiet {
        for e in events.iter().take(20) {
            eprintln!("  {} {} {}", e.when, e.source, e.name);
        }
        if events.len() > 20 {
            eprintln!("  ... {} more", events.len() - 20);
        }
    }
    let csv = match events_path {
        Some(p) => Some(p.to_string()),
        None if !opts.dry_run => Some(
            std::path::Path::new(&opts.out_dir)
                .join("deletions.csv")
                .to_string_lossy()
                .to_string(),
        ),
        None => None,
    };
    if let Some(path) = csv {
        if let Some(parent) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let n = artifacts::write_events_csv(&events, &path).map_err(|e| format!("{path}: {e}"))?;
        if !opts.quiet {
            eprintln!("wrote {n} deletion event(s) to {path}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The NTFS volume to work on: the whole image, a partition of it, or the
/// offset the analyst gave.
fn ntfs_base(reader: &Source, opts: &Options) -> Result<u64, String> {
    if opts.start != 0 || breadcrumb_rs::partition::detect_fs(reader, 0) == "ntfs" {
        return Ok(opts.start);
    }
    let parts = breadcrumb_rs::partition::parse(reader);
    match parts.iter().find(|p| p.fstype == "ntfs") {
        Some(p) => {
            if !opts.quiet {
                eprintln!("ntfs: volume at {:#x} ({})", p.start, p.name);
            }
            Ok(p.start)
        }
        None => Err("no NTFS volume found; pass --offset to point at one \
                     (--list-partitions shows what is here)"
            .into()),
    }
}

fn run_ntfs(
    reader: &Source,
    opts: &Options,
    include_live: bool,
    machine: bool,
    csv_path: Option<&str>,
) -> Result<ExitCode, String> {
    use breadcrumb_rs::ntfs;

    // The volume may be the whole image, or a partition of it.
    let base = ntfs_base(reader, opts)?;

    let nopts = ntfs::Options {
        out_dir: opts.out_dir.clone(),
        dry_run: opts.dry_run,
        include_live,
        min_size: opts.min_size,
    };
    let started = Instant::now();
    let quiet = opts.quiet;
    let records = ntfs::recover(reader, base, &nopts, |rec| {
        if machine {
            println!(
                "{}",
                json::object(vec![
                    ("event", json::string("file")),
                    ("name", json::string(&rec.name)),
                    ("mft", json::number(rec.mft)),
                    ("size", json::number(rec.size)),
                    ("sha256", json::string(&rec.sha256)),
                    ("deleted", json::boolean(rec.deleted)),
                    ("created", json::number(rec.timestamps.created)),
                    ("modified", json::number(rec.timestamps.modified)),
                    ("changed", json::number(rec.timestamps.changed)),
                    ("accessed", json::number(rec.timestamps.accessed)),
                    ("path", json::string(&rec.path)),
                ])
            );
        } else if !quiet {
            eprintln!(
                "[+] {}  {} B{}",
                rec.name,
                rec.size,
                if rec.validated {
                    ""
                } else {
                    "  (low confidence)"
                }
            );
        }
    })?;
    let elapsed = started.elapsed().as_secs_f64();

    // Manifest and CSV carry the timestamps, which is the point of this mode.
    let files: Vec<String> = records
        .iter()
        .map(|r| {
            json::object(vec![
                ("type", json::string("ntfs")),
                ("ext", json::string(&r.ext)),
                ("mft", json::number(r.mft)),
                ("name", json::string(&r.name)),
                ("size", json::number(r.size)),
                ("sha256", json::string(&r.sha256)),
                ("deleted", json::boolean(r.deleted)),
                ("validated", json::boolean(r.validated)),
                ("confidence", json::string(r.confidence())),
                ("created", json::number(r.timestamps.created)),
                ("modified", json::number(r.timestamps.modified)),
                ("changed", json::number(r.timestamps.changed)),
                ("accessed", json::number(r.timestamps.accessed)),
                ("path", json::string(&r.path)),
            ])
        })
        .collect();
    let manifest = json::object(vec![
        ("tool", json::string(&format!("breadcrumb-rs {VERSION}"))),
        ("mode", json::string("ntfs")),
        ("source", json::string(reader.path())),
        ("source_size", json::number(reader.size())),
        ("volume_offset", json::number(base)),
        ("elapsed_s", json::float(elapsed)),
        ("files", json::array(files)),
    ]);
    if !opts.dry_run {
        std::fs::create_dir_all(&opts.out_dir).map_err(|e| format!("{}: {e}", opts.out_dir))?;
        let path = std::path::Path::new(&opts.out_dir).join("manifest.json");
        std::fs::write(&path, manifest).map_err(|e| format!("{}: {e}", path.display()))?;
        if let Some(csv) = csv_path {
            let mut out = String::from(
                "mft,name,ext,size,sha256,deleted,confidence,created,modified,changed,accessed,path\n",
            );
            for r in &records {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    r.mft,
                    r.name.replace(',', ";"),
                    r.ext,
                    r.size,
                    r.sha256,
                    r.deleted,
                    r.confidence(),
                    r.timestamps.created,
                    r.timestamps.modified,
                    r.timestamps.changed,
                    r.timestamps.accessed,
                    r.path.replace(',', ";")
                ));
            }
            std::fs::write(csv, out).map_err(|e| format!("{csv}: {e}"))?;
        }
    } else {
        println!("{manifest}");
    }
    if !opts.quiet {
        let deleted = records.iter().filter(|r| r.deleted).count();
        eprintln!(
            "recovered {} file(s) ({deleted} deleted) in {elapsed:.2}s",
            records.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Print a verification report and choose the exit code from it.
fn verify_image(reader: &Source, quiet: bool) -> Result<ExitCode, String> {
    use breadcrumb_rs::verify::{self, hex};

    let mut last_pct = u64::MAX;
    let outcome = verify::verify(reader, |done, total| {
        if !quiet {
            let pct = done * 100 / total.max(1);
            if pct != last_pct {
                eprint!("\rverifying {pct}%");
                last_pct = pct;
            }
        }
    })?;
    if !quiet {
        eprintln!("\rverifying done");
    }
    if let Some(want) = outcome.stored_md5 {
        let good = want == outcome.md5;
        println!(
            "md5    {}  {}  (stored {})",
            hex(&outcome.md5),
            if good { "MATCH" } else { "MISMATCH" },
            hex(&want)
        );
    }
    if let Some(want) = outcome.stored_sha1 {
        let good = want == outcome.sha1;
        println!(
            "sha1   {}  {}  (stored {})",
            hex(&outcome.sha1),
            if good { "MATCH" } else { "MISMATCH" },
            hex(&want)
        );
    }
    println!(
        "sha256 {}  (recomputed; nothing stored to compare)",
        hex(&outcome.sha256)
    );
    println!("{} bytes verified", outcome.bytes);
    match outcome.matches() {
        Some(true) => Ok(ExitCode::SUCCESS),
        Some(false) => Err("the image does not match the hashes recorded when it \
                            was acquired. If the source was not a whole number of \
                            sectors, some acquisition tools hash bytes they do not \
                            store, which shows up here as a mismatch"
            .into()),
        None => Err(
            "this image carries no acquisition hashes to verify against \
                     (EWF stores them; raw images do not)"
                .into(),
        ),
    }
}

/// SHA-256 over every byte of the source, for chain-of-custody records.
fn hash_whole_source(reader: &Source) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut pos = 0u64;
    while pos < reader.size() {
        let block = reader.pread(pos, 8 << 20);
        if block.is_empty() {
            break;
        }
        hasher.update(&block);
        pos += block.len() as u64;
    }
    format!("{:x}", hasher.finalize())
}

fn write_manifest(
    source: &str,
    reader: &Source,
    records: &[Record],
    opts: &Options,
    elapsed: f64,
    source_sha256: Option<&str>,
) -> Result<String, String> {
    let abs = std::fs::canonicalize(source)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| source.to_string());
    let mut files = Vec::new();
    for r in records {
        files.push(json::object(vec![
            ("type", json::string(r.kind)),
            ("ext", json::string(r.ext)),
            ("offset", json::number(r.offset)),
            ("size", json::number(r.size)),
            ("sha256", json::string(&r.sha256)),
            ("validated", json::boolean(r.validated)),
            ("confidence", json::string(r.confidence())),
            (
                "duplicate_of",
                match r.duplicate_of {
                    Some(o) => json::number(o),
                    None => "null".to_string(),
                },
            ),
            ("path", json::string(&r.path)),
        ]));
    }
    let mut fields = vec![
        ("tool", json::string(&format!("breadcrumb-rs {VERSION}"))),
        ("source", json::string(&abs)),
        ("source_size", json::number(reader.size())),
        ("elapsed_s", json::float(elapsed)),
    ];
    if let Some(sha) = source_sha256 {
        fields.push(("source_sha256", json::string(sha)));
    }
    fields.push(("files", json::array(files)));
    let manifest = json::object(fields);

    let dir = std::path::Path::new(&opts.out_dir);
    if records.is_empty() && opts.dry_run {
        println!("{manifest}");
        return Ok("(stdout)".into());
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", opts.out_dir))?;
    let path = dir.join("manifest.json");
    std::fs::write(&path, manifest).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path.to_string_lossy().to_string())
}
