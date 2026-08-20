//! bcrumb-rs: signature-based file carver for disk images and block devices.

use breadcrumb_rs::carver::{run_parallel, Options, Record};
use breadcrumb_rs::json;
use breadcrumb_rs::reader::Reader;
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
  -q, --quiet             no progress output
  -V, --version           print version and exit
  -h, --help              this help

Sizes accept K/M/G suffixes (e.g. --chunk 64M).
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

    let reader = Reader::open(&source).map_err(|e| format!("{source}: {e}"))?;
    if !opts.quiet {
        eprintln!(
            "scanning {}{} ({:.1} MiB) for {} type(s), {} thread(s)",
            reader.path,
            if reader.is_device { " (device)" } else { "" },
            reader.size as f64 / (1 << 20) as f64,
            sigs.len(),
            opts.jobs
        );
    }

    let t0 = Instant::now();
    let records = run_parallel(&reader, &sigs, &opts);
    let elapsed = t0.elapsed().as_secs_f64();

    let manifest_path = write_manifest(&source, &reader, &records, &opts, elapsed)?;
    if !opts.quiet {
        let mibs = reader.size as f64 / (1 << 20) as f64 / elapsed.max(1e-9);
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

fn write_manifest(
    source: &str,
    reader: &Reader,
    records: &[Record],
    opts: &Options,
    elapsed: f64,
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
    let manifest = json::object(vec![
        ("tool", json::string(&format!("breadcrumb-rs {VERSION}"))),
        ("source", json::string(&abs)),
        ("source_size", json::number(reader.size)),
        ("elapsed_s", json::float(elapsed)),
        ("files", json::array(files)),
    ]);

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
