//! bcrumb-rs: signature-based file carver for disk images and block devices.

use breadcrumb_rs::carver::{run_parallel, Options, Record};
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
      --grep PATTERN      search the source for a string instead of carving
                          (repeatable; both ASCII and UTF-16LE are matched)
  -i, --ignore-case       case-insensitive --grep
      --max-hits N        stop after N --grep hits
      --list-partitions   print the partition table and detected filesystems
      --csv FILE          write a CSV of the carve results
      --bodyfile FILE     write a Sleuth Kit bodyfile
      --timeline FILE     write a timeline CSV
      --html FILE         write an HTML report
      --hash-source       hash the whole source for the manifest (custody)
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

Sizes accept K/M/G suffixes (e.g. --chunk 64M).

by scenario
  documents off a disk image
    bcrumb-rs disk.dd -t office -o out
  ...that is BitLocker-encrypted (E01 sets: pass the FIRST segment only)
    bcrumb-rs disk.E01 -t office -o out --bitlocker-recovery-key 650441-...-609257
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

Filenames, timestamps and deletion dates need the filesystem, not carving:
use the Python implementation (--ntfs, --deleted-times).
";

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('k') | Some('K') => (&s[..s.len() - 1], 1u64 << 10),
        Some('m') | Some('M') => (&s[..s.len() - 1], 1u64 << 20),
        Some('g') | Some('G') => (&s[..s.len() - 1], 1u64 << 30),
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
            "--grep" => grep_patterns.push(next(&mut i)?),
            "-i" | "--ignore-case" => ignore_case = true,
            "--max-hits" => {
                let v = next(&mut i)?;
                max_hits = v.parse().map_err(|_| format!("not a number: {v:?}"))?;
            }
            "--list-partitions" | "--list-parts" => list_partitions = true,
            "--csv" => csv_path = Some(next(&mut i)?),
            "--bodyfile" => bodyfile_path = Some(next(&mut i)?),
            "--timeline" => timeline_path = Some(next(&mut i)?),
            "--html" => html_path = Some(next(&mut i)?),
            "--hash-source" => hash_source = true,
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

    let t0 = Instant::now();
    let records = run_parallel(&reader, &sigs, &opts);
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
