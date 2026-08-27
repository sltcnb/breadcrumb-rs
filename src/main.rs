//! bcrumb-rs: signature-based file carver for disk images and block devices.

use breadcrumb_rs::carver::{run_parallel, run_ranges, Options, Progress, Record};
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
  -E, --regex             treat --grep patterns as regular expressions (matched
                          against the bytes; literals also match UTF-16LE)
      --max-hits N        stop after N --grep hits
      --zip-partial       also keep ZIP-family fragments that have no central
                          directory of their own. Off by default: on a 238 GB
                          disk they were 74% of everything written and mostly
                          were not archives
      --validate          decode each carved file to confirm it is intact, not
                          only well formed (PNG/ZIP+OOXML/gzip CRCs, JPEG and
                          SQLite structure); reported as verified/failed
      --drop-failed       with --validate, do not keep a file that failed to
                          decode
      --ntfs              NTFS undelete: walk the MFT for deleted files,
                          recovering names, paths and timestamps
      --fat               FAT12/16/32 or exFAT undelete: recover deleted
                          directory entries (names, sizes, timestamps)
      --ext4              ext2/3/4 undelete: names from directory blocks,
                          content from inodes whose map survived
      --hfs               HFS+/HFSX undelete: catalog B-tree walk, including
                          records left outside the live tree
      --apfs              APFS recovery: scan for superseded copy-on-write
                          objects, which is where deleted files survive
      --auto              find every partition and run the undelete mode its
                          filesystem calls for, one volume at a time
      --list-free         print the free-space map (how much, in how many runs)
                          and exit, without scanning anything
      --unallocated       carve only the free space, read from the filesystem's
                          own allocation map (NTFS $Bitmap, the FAT, ext block
                          bitmaps). Skips every allocated file, which is both
                          the bulk of a full disk and where most spurious
                          carves come from
      --include-live      with an undelete mode, also recover files in use
      --deleted-times     when files were deleted, from $Recycle.Bin/$I records
                          and the $UsnJrnl change journal (writes deletions.csv)
      --usn-all           with --deleted-times, report every journal reason,
                          not only deletions
      --events FILE       write the deletion events to this CSV instead
                          (the source may also be a folder of already-extracted
                          $I / $UsnJrnl files rather than an image)
      --list-partitions   print the partition table and detected filesystems
      --sig-file FILE     add signatures defined in a JSON file (see README)
      --only-custom       carve only the --sig-file signatures
      --from-manifest FILE
                          write the reports below from an existing manifest,
                          without rescanning the image
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
  a camera card or USB stick (FAT / exFAT)
    bcrumb-rs card.dd --fat -o out --csv files.csv
  a Linux volume (ext2/3/4)
    bcrumb-rs disk.dd --ext4 -o out --csv files.csv
  an older Mac volume (HFS+)
    bcrumb-rs disk.dd --hfs -o out --csv files.csv
  a Mac volume (APFS): superseded objects hold the deleted files
    bcrumb-rs disk.dd --apfs -o out --csv files.csv
  when files were deleted (recycle bin + change journal)
    bcrumb-rs disk.E01 --deleted-times -o out
  ...from artefacts already pulled off a machine
    bcrumb-rs ./artefacts --deleted-times --events deletions.csv
  a whole disk, each partition with the right undelete mode
    bcrumb-rs disk.E01 --auto -o out --csv files.csv
  what is on the disk before committing to a long scan
    bcrumb-rs disk.E01 --list-partitions
  inventory first: how much would a full carve write?
    bcrumb-rs disk.E01 --dry-run -t office
  how much of the disk is even worth scanning?
    bcrumb-rs disk.E01 --list-free
  skip everything still allocated: usually the biggest win there is
    bcrumb-rs disk.E01 -t office -o out --unallocated
  a big disk, all cores, output somewhere with room
    bcrumb-rs disk.E01 -j 0 -o /mnt/scratch/out
  find a keyword, in ASCII and UTF-16LE
    bcrumb-rs disk.E01 --grep secret-project --max-hits 50
  ...or a pattern: card numbers, IBANs, anything with a shape
    bcrumb-rs disk.E01 --regex --grep \"[0-9]{4}([ -]?[0-9]{4}){3}\"
  only files that actually decode (fragmented carves fail here)
    bcrumb-rs disk.dd -t office,jpg -o out --validate --drop-failed
  reports from a scan that already ran
    bcrumb-rs --from-manifest out/manifest.json --html report.html
  a format the tool does not know, by magic and footer
    bcrumb-rs disk.dd --sig-file mysigs.json --only-custom -o out
  a case file: CSV, timeline, HTML report and a custody hash
    bcrumb-rs disk.dd -o out --csv files.csv --timeline t.csv --html r.html --hash-source
  read from a pipe (spooled to a temp file, since handlers seek)
    dd if=/dev/sdb | bcrumb-rs - -o out
  inspect a structure by hand, decrypted
    bcrumb-rs disk.E01 --hexdump 0xe500000:512 --bitlocker-recovery-key ...
  a BitLocker volume that will not open
    bcrumb-rs disk.E01 --dump-fve --bitlocker-recovery-key ...
    bcrumb-rs disk.E01 --bitlocker-scan-metadata --bitlocker-recovery-key ...

Carving gives bytes. The undelete modes give names, paths and timestamps, and
--deleted-times gives the deletion times themselves.
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

/// Read the records out of a manifest written by an earlier run.
fn records_from_manifest(path: &std::path::Path) -> Result<Vec<Record>, String> {
    use breadcrumb_rs::jsonin::{self, Value};

    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let doc = jsonin::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let files = match doc.get("files").and_then(Value::as_array) {
        Some(f) => f,
        None => return Err(format!("{}: no \"files\" list", path.display())),
    };
    let mut out = Vec::new();
    for f in files {
        let num = |k: &str| f.get(k).and_then(Value::as_f64).map(|n| n as u64);
        let text = |k: &str| f.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let (Some(offset), Some(size)) = (num("offset"), num("size")) else {
            continue;
        };
        out.push(Record {
            // The registry owns the built-in names; a manifest's are read at
            // run time, so they are leaked to match the &'static in Record.
            kind: Box::leak(text("type").into_boxed_str()),
            ext: Box::leak(
                match f.get("ext").and_then(Value::as_str) {
                    Some(e) if !e.is_empty() => e.to_string(),
                    _ => "bin".to_string(),
                }
                .into_boxed_str(),
            ),
            offset,
            size,
            sha256: text("sha256"),
            validated: f.get("validated").and_then(Value::as_bool).unwrap_or(false),
            path: text("path"),
            duplicate_of: num("duplicate_of"),
            decoded: f.get("decoded").and_then(Value::as_bool),
        });
    }
    Ok(out)
}

/// Fold records from a previous attempt's manifest into this run's, so a
/// resumed scan reports the whole image rather than only the part it did.
fn merge_with_existing(out_dir: &str, mut records: Vec<Record>) -> Vec<Record> {
    let path = std::path::Path::new(out_dir).join("manifest.json");
    let Ok(earlier) = records_from_manifest(&path) else {
        return records;
    };
    let mut recovered = 0usize;
    for rec in earlier {
        if records
            .iter()
            .any(|r| r.offset == rec.offset && r.size == rec.size)
        {
            continue;
        }
        records.push(rec);
        recovered += 1;
    }
    if recovered > 0 {
        eprintln!("resumed: carried {recovered} record(s) forward from the earlier manifest");
    }
    records.sort_by_key(|r| r.offset);
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
    let mut fat_mode = false;
    let mut ext_mode = false;
    let mut hfs_mode = false;
    let mut apfs_mode = false;
    let mut auto_mode = false;
    let mut unallocated = false;
    let mut list_free = false;
    let mut include_live = false;
    let mut grep_regex = false;
    let mut sig_file: Option<String> = None;
    let mut only_custom = false;
    let mut from_manifest: Option<String> = None;
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
            "--regex" | "-E" => grep_regex = true,
            "--max-hits" => {
                let v = next(&mut i)?;
                max_hits = v.parse().map_err(|_| format!("not a number: {v:?}"))?;
            }
            "--sig-file" => sig_file = Some(next(&mut i)?),
            "--only-custom" => only_custom = true,
            "--from-manifest" => from_manifest = Some(next(&mut i)?),
            "--zip-partial" => breadcrumb_rs::handlers::set_zip_partial(true),
            "--validate" => opts.validate = true,
            "--drop-failed" => {
                opts.validate = true;
                opts.drop_failed = true;
            }
            "--ntfs" => ntfs_mode = true,
            "--fat" | "--exfat" => fat_mode = true,
            "--ext4" | "--ext" => ext_mode = true,
            "--hfs" | "--hfsplus" => hfs_mode = true,
            "--apfs" => apfs_mode = true,
            "--auto" => auto_mode = true,
            "--unallocated" | "--free-space" => unallocated = true,
            "--list-free" => {
                list_free = true;
                unallocated = true;
            }
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

    // Writing reports from a manifest needs no image, and must work when the
    // evidence is not attached any more.
    if let Some(manifest) = &from_manifest {
        return run_from_manifest(
            manifest,
            &opts,
            csv_path.as_deref(),
            bodyfile_path.as_deref(),
            timeline_path.as_deref(),
            html_path.as_deref(),
        );
    }

    let source = match source {
        Some(s) => s,
        None => {
            print!("{USAGE}");
            return Ok(ExitCode::from(2));
        }
    };

    let mut sigs: Vec<&'static Signature> = match &types {
        Some(spec) => resolve_types(spec)?,
        None => SIGNATURES.iter().collect(),
    };
    if let Some(path) = &sig_file {
        let custom = breadcrumb_rs::customsig::load(path)?;
        if !opts.quiet {
            eprintln!("loaded {} custom signature(s) from {path}", custom.len());
        }
        if only_custom {
            sigs = custom;
        } else {
            sigs.extend(custom);
        }
    } else if only_custom {
        return Err("--only-custom needs --sig-file".into());
    }
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

    if fat_mode {
        return run_fat(&reader, &opts, include_live, machine, csv_path.as_deref());
    }

    if ext_mode {
        return run_ext4(&reader, &opts, include_live, machine, csv_path.as_deref());
    }

    if hfs_mode {
        return run_hfs(&reader, &opts, include_live, machine, csv_path.as_deref());
    }

    if apfs_mode {
        return run_apfs(&reader, &opts, machine, csv_path.as_deref());
    }

    if auto_mode {
        return run_auto(&reader, &opts, include_live, machine, csv_path.as_deref());
    }

    if list_partitions {
        let parts = breadcrumb_rs::partition::parse(&reader);
        println!("{}", breadcrumb_rs::partition::format_table(&parts));
        return Ok(ExitCode::SUCCESS);
    }

    if !grep_patterns.is_empty() {
        let mut count = 0usize;
        let query = breadcrumb_rs::grep::Query {
            patterns: grep_patterns.clone(),
            ignore_case,
            regex: grep_regex,
            max_hits,
        };
        breadcrumb_rs::grep::search(&reader, &query, opts.start, opts.length, |h| {
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
        })?;
        if !opts.quiet && !machine {
            eprintln!("\n{count} hit(s)");
        }
        return Ok(ExitCode::SUCCESS);
    }
    let free = if unallocated {
        let ranges = plan_unallocated(&reader, &opts)?;
        if list_free {
            let total: u64 = ranges.iter().map(|&(a, b)| b - a).sum();
            let largest = ranges.iter().map(|&(a, b)| b - a).max().unwrap_or(0);
            if machine {
                println!(
                    "{}",
                    json::object(vec![
                        ("event", json::string("free_space")),
                        ("ranges", json::number(ranges.len() as u64)),
                        ("free_bytes", json::number(total)),
                        ("largest_run", json::number(largest)),
                    ])
                );
                for (a, b) in &ranges {
                    println!(
                        "{}",
                        json::object(vec![
                            ("event", json::string("free_range")),
                            ("start", json::number(*a)),
                            ("end", json::number(*b)),
                        ])
                    );
                }
            } else {
                println!(
                    "{} to scan in {} run(s); largest {}",
                    human(total),
                    ranges.len(),
                    human(largest)
                );
                println!("{:>16}  {:>16}  {:>12}", "start", "end", "size");
                for (a, b) in ranges.iter().take(40) {
                    println!("{a:>16}  {b:>16}  {:>12}", human(b - a));
                }
                if ranges.len() > 40 {
                    println!("... {} more run(s)", ranges.len() - 40);
                }
            }
            return Ok(ExitCode::SUCCESS);
        }
        Some(ranges)
    } else {
        None
    };

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
    // Only the free space, if asked: the filesystem's allocation map says where
    // that is, and the range scanner below already carves a file that starts in
    // a range and continues past its end.

    // What the scan intends to read, for the progress line.
    let planned: u64 = match &free {
        Some(ranges) => ranges.iter().map(|&(a, b)| b - a).sum(),
        None => scan_end.saturating_sub(opts.start),
    };
    let progress = Progress::new(planned);
    let stop_reporting = std::sync::atomic::AtomicBool::new(false);
    let show_progress = !opts.quiet || machine;

    let records = if opts.dry_run {
        match &free {
            Some(ranges) => run_ranges(
                &reader,
                &sigs,
                &opts,
                ranges,
                scan_end,
                Some(&progress),
                |_, _, _| {},
            ),
            None => run_parallel(&reader, &sigs, &opts),
        }
    } else {
        let fingerprint = checkpoint::Fingerprint {
            source: reader.path().to_string(),
            size: reader.size(),
            types: sigs.iter().map(|s| s.name).collect::<Vec<_>>().join(","),
        };
        let mut state = checkpoint::Checkpoint::open(&opts.out_dir, fingerprint, resume)?;
        // Records are appended here as ranges finish. A manifest is only
        // written when a scan ends, and two killed runs on a real examination
        // left 165 GB of carved files with no record of what they were.
        let mut stream = open_record_stream(&opts.out_dir, resume);
        let ranges = match &free {
            // Free-space ranges are already the work list; the checkpoint still
            // records which of them finished, so --resume works with it.
            Some(free) => free
                .iter()
                .flat_map(|&(a, b)| state.remaining(a, b))
                .collect::<Vec<_>>(),
            None => plan_ranges(&state, opts.start, scan_end, opts.chunk_size, opts.jobs),
        };
        if resume && state.bytes_done() > 0 && !opts.quiet {
            eprintln!(
                "resuming: {} of {} already scanned, {} range(s) left",
                human(state.bytes_done()),
                human(scan_end - opts.start),
                ranges.len()
            );
        }
        let recs = std::thread::scope(|scope| {
            if show_progress {
                spawn_reporter(&progress, &stop_reporting, machine, scope);
            }
            let recs = run_ranges(
                &reader,
                &sigs,
                &opts,
                &ranges,
                scan_end,
                Some(&progress),
                |a, b, recs| {
                    stream_records(&mut stream, recs);
                    state.complete(a, b);
                },
            );
            stop_reporting.store(true, std::sync::atomic::Ordering::Relaxed);
            recs
        });
        // With --unallocated the allocated ranges are never going to be
        // scanned, so completeness is measured against what was planned rather
        // than against the whole volume -- otherwise every run ends by telling
        // the analyst to resume something that is already finished.
        let complete = match &free {
            Some(free) => free.iter().all(|&(a, b)| state.remaining(a, b).is_empty()),
            None => state.remaining(opts.start, scan_end).is_empty(),
        };
        let mut merged = recs;
        if resume {
            merged = merge_with_existing(&opts.out_dir, merged);
        }
        if complete {
            state.finish();
        } else if !opts.quiet {
            let target = match &free {
                Some(free) => free.iter().map(|&(a, b)| b - a).sum(),
                None => scan_end - opts.start,
            };
            eprintln!(
                "scan incomplete: {} of {} done. Re-run with --resume to continue",
                human(state.bytes_done()),
                human(target)
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
                    (
                        "decoded",
                        match r.decoded {
                            Some(v) => json::boolean(v),
                            None => "null".to_string(),
                        },
                    ),
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
/// Derived reports from a manifest an earlier scan wrote.
///
/// The carved files and the image may be long gone; the manifest is the record,
/// and a case often needs a report in a different shape later.
fn run_from_manifest(
    manifest: &str,
    opts: &Options,
    csv_path: Option<&str>,
    bodyfile_path: Option<&str>,
    timeline_path: Option<&str>,
    html_path: Option<&str>,
) -> Result<ExitCode, String> {
    let path = std::path::Path::new(manifest);
    let records = records_from_manifest(path)?;
    if records.is_empty() {
        return Err(format!("{manifest}: no carve records in it"));
    }
    if csv_path.is_none()
        && bodyfile_path.is_none()
        && timeline_path.is_none()
        && html_path.is_none()
    {
        return Err(
            "--from-manifest needs a report to write: --csv, --bodyfile, --timeline or --html"
                .into(),
        );
    }
    let source = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| {
            breadcrumb_rs::jsonin::parse(&t)
                .ok()
                .and_then(|d| d.get("source").and_then(|v| v.as_str()).map(str::to_string))
        })
        .unwrap_or_else(|| manifest.to_string());
    let total: u64 = records.iter().map(|r| r.size).sum();
    for (out, body) in [
        (csv_path, report::csv(&records)),
        (bodyfile_path, report::bodyfile(&records)),
        (timeline_path, report::timeline(&records)),
        (html_path, report::html(&source, total, &records, 0.0)),
    ] {
        if let Some(out) = out {
            if let Some(parent) = std::path::Path::new(out).parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            std::fs::write(out, body).map_err(|e| format!("{out}: {e}"))?;
            if !opts.quiet {
                eprintln!("wrote {out}");
            }
        }
    }
    if !opts.quiet {
        eprintln!("{} record(s) from {manifest}", records.len());
    }
    Ok(ExitCode::SUCCESS)
}

/// FAT and exFAT undelete.
///
/// A deleted FAT entry keeps its size, start cluster and timestamps; what it
/// loses is the allocation chain, so a file that was fragmented cannot be
/// reassembled and comes back as whatever follows its first cluster. That is
/// stated in the output rather than hidden: see the note printed at the end.
fn run_fat(
    reader: &Source,
    opts: &Options,
    include_live: bool,
    machine: bool,
    csv_path: Option<&str>,
) -> Result<ExitCode, String> {
    use breadcrumb_rs::fat;

    let started = Instant::now();
    let quiet = opts.quiet;
    let fopts = fat::Options {
        out_dir: opts.out_dir.clone(),
        dry_run: opts.dry_run,
        include_live,
        min_size: opts.min_size,
    };
    let (records, kind, cluster_size) = fat::recover(reader, opts.start, &fopts, |rec| {
        if machine {
            println!(
                "{}",
                json::object(vec![
                    ("event", json::string("file")),
                    ("name", json::string(&rec.name)),
                    ("offset", json::number(rec.offset)),
                    ("size", json::number(rec.size)),
                    ("sha256", json::string(&rec.sha256)),
                    ("deleted", json::boolean(rec.deleted)),
                    ("validated", json::boolean(rec.validated)),
                    ("created", json::number(rec.timestamps.created)),
                    ("modified", json::number(rec.timestamps.modified)),
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
                    "  (short read: the file ran past the volume)"
                }
            );
        }
    })?;
    let elapsed = started.elapsed().as_secs_f64();

    let files: Vec<String> = records
        .iter()
        .map(|r| {
            json::object(vec![
                ("type", json::string(r.kind)),
                ("ext", json::string(&r.ext)),
                ("name", json::string(&r.name)),
                ("offset", json::number(r.offset)),
                ("size", json::number(r.size)),
                ("sha256", json::string(&r.sha256)),
                ("deleted", json::boolean(r.deleted)),
                ("validated", json::boolean(r.validated)),
                ("confidence", json::string(r.confidence())),
                ("created", json::number(r.timestamps.created)),
                ("modified", json::number(r.timestamps.modified)),
                ("accessed", json::number(r.timestamps.accessed)),
                ("path", json::string(&r.path)),
            ])
        })
        .collect();
    let manifest = json::object(vec![
        ("tool", json::string(&format!("breadcrumb-rs {VERSION}"))),
        ("mode", json::string(kind)),
        ("source", json::string(reader.path())),
        ("source_size", json::number(reader.size())),
        ("cluster_size", json::number(cluster_size)),
        ("elapsed_s", json::float(elapsed)),
        (
            "note",
            json::string(
                "FAT frees the allocation chain on delete, so a file that was \
                 fragmented is recovered as the bytes following its first \
                 cluster. Contiguous files are exact.",
            ),
        ),
        ("files", json::array(files)),
    ]);
    if !opts.dry_run {
        std::fs::create_dir_all(&opts.out_dir).map_err(|e| format!("{}: {e}", opts.out_dir))?;
        let path = std::path::Path::new(&opts.out_dir).join("manifest.json");
        std::fs::write(&path, manifest).map_err(|e| format!("{}: {e}", path.display()))?;
    } else {
        println!("{manifest}");
    }

    // An inventory is not recovered data: a dry run writes the CSV so a
    // volume can be listed without extracting it.
    if let Some(csv) = csv_path {
        let mut out = String::from(
            "name,ext,offset,size,sha256,deleted,confidence,created,modified,accessed,path\n",
        );
        for r in &records {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{}\n",
                r.name.replace(',', ";"),
                r.ext,
                r.offset,
                r.size,
                r.sha256,
                r.deleted,
                r.confidence(),
                r.timestamps.created,
                r.timestamps.modified,
                r.timestamps.accessed,
                r.path.replace(',', ";")
            ));
        }
        std::fs::write(csv, out).map_err(|e| format!("{csv}: {e}"))?;
    }
    if !opts.quiet {
        let deleted = records.iter().filter(|r| r.deleted).count();
        eprintln!(
            "recovered {} file(s) ({deleted} deleted) from {} in {elapsed:.2}s",
            records.len(),
            kind.to_uppercase()
        );
        if deleted > 0 {
            eprintln!(
                "note: {} frees the allocation chain on delete, so a file that was \
                 fragmented comes back as the bytes after its first cluster",
                kind.to_uppercase()
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// ext2/3/4 undelete.
fn run_ext4(
    reader: &Source,
    opts: &Options,
    include_live: bool,
    machine: bool,
    csv_path: Option<&str>,
) -> Result<ExitCode, String> {
    use breadcrumb_rs::ext4;

    let started = Instant::now();
    let quiet = opts.quiet;
    let eopts = ext4::Options {
        out_dir: opts.out_dir.clone(),
        dry_run: opts.dry_run,
        include_live,
        min_size: opts.min_size,
    };
    let (records, summary) = ext4::recover(reader, opts.start, &eopts, |rec| {
        if machine {
            println!(
                "{}",
                json::object(vec![
                    ("event", json::string("file")),
                    ("name", json::string(&rec.name)),
                    ("inode", json::number(rec.inode)),
                    ("size", json::number(rec.size)),
                    ("sha256", json::string(&rec.sha256)),
                    ("deleted", json::boolean(rec.deleted)),
                    ("validated", json::boolean(rec.validated)),
                    ("modified", json::number(rec.timestamps.modified)),
                    ("deleted_at", json::number(rec.timestamps.deleted)),
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
                    "  (low confidence: incomplete map or no name)"
                }
            );
        }
    })?;
    let elapsed = started.elapsed().as_secs_f64();

    let files: Vec<String> = records
        .iter()
        .map(|r| {
            json::object(vec![
                ("type", json::string("ext4")),
                ("ext", json::string(&r.ext)),
                ("inode", json::number(r.inode)),
                ("name", json::string(&r.name)),
                ("size", json::number(r.size)),
                ("sha256", json::string(&r.sha256)),
                ("deleted", json::boolean(r.deleted)),
                ("validated", json::boolean(r.validated)),
                ("confidence", json::string(r.confidence())),
                ("modified", json::number(r.timestamps.modified)),
                ("changed", json::number(r.timestamps.changed)),
                ("accessed", json::number(r.timestamps.accessed)),
                ("deleted_at", json::number(r.timestamps.deleted)),
                ("path", json::string(&r.path)),
            ])
        })
        .collect();
    let manifest = json::object(vec![
        ("tool", json::string(&format!("breadcrumb-rs {VERSION}"))),
        ("mode", json::string("ext4")),
        ("source", json::string(reader.path())),
        ("source_size", json::number(reader.size())),
        ("volume_size", json::number(summary.volume_size)),
        ("block_size", json::number(summary.block_size)),
        ("inodes", json::number(summary.inodes)),
        ("map_cleared", json::number(summary.map_gone)),
        ("elapsed_s", json::float(elapsed)),
        ("files", json::array(files)),
    ]);
    if !opts.dry_run {
        std::fs::create_dir_all(&opts.out_dir).map_err(|e| format!("{}: {e}", opts.out_dir))?;
        let path = std::path::Path::new(&opts.out_dir).join("manifest.json");
        std::fs::write(&path, manifest).map_err(|e| format!("{}: {e}", path.display()))?;
    } else {
        println!("{manifest}");
    }

    // An inventory is not recovered data: a dry run writes the CSV so a
    // volume can be listed without extracting it.
    if let Some(csv) = csv_path {
        let mut out = String::from(
            "inode,name,ext,size,sha256,deleted,confidence,modified,changed,accessed,deleted_at,path\n",
        );
        for r in &records {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                r.inode,
                r.name.replace(',', ";"),
                r.ext,
                r.size,
                r.sha256,
                r.deleted,
                r.confidence(),
                r.timestamps.modified,
                r.timestamps.changed,
                r.timestamps.accessed,
                r.timestamps.deleted,
                r.path.replace(',', ";")
            ));
        }
        std::fs::write(csv, out).map_err(|e| format!("{csv}: {e}"))?;
    }
    if !opts.quiet {
        let deleted = records.iter().filter(|r| r.deleted).count();
        eprintln!(
            "recovered {} file(s) ({deleted} deleted) from ext in {elapsed:.2}s",
            records.len()
        );
        if summary.map_gone > 0 {
            eprintln!(
                "note: {} deleted inode(s) had their block map already cleared -- ext4 \
                 does that when it frees an inode, and the content is not on the volume \
                 any more (the journal may still hold a copy)",
                summary.map_gone
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// HFS+/HFSX undelete.
fn run_hfs(
    reader: &Source,
    opts: &Options,
    include_live: bool,
    machine: bool,
    csv_path: Option<&str>,
) -> Result<ExitCode, String> {
    use breadcrumb_rs::hfs;

    let started = Instant::now();
    let quiet = opts.quiet;
    let hopts = hfs::Options {
        out_dir: opts.out_dir.clone(),
        dry_run: opts.dry_run,
        include_live,
        min_size: opts.min_size,
        scan_volume: true,
    };
    let (records, summary) = hfs::recover(reader, opts.start, &hopts, |rec| {
        if machine {
            println!(
                "{}",
                json::object(vec![
                    ("event", json::string("file")),
                    ("name", json::string(&rec.name)),
                    ("cnid", json::number(rec.cnid)),
                    ("size", json::number(rec.size)),
                    ("sha256", json::string(&rec.sha256)),
                    ("deleted", json::boolean(rec.deleted)),
                    ("validated", json::boolean(rec.validated)),
                    ("created", json::number(rec.timestamps.created)),
                    ("modified", json::number(rec.timestamps.modified)),
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
                    "  (low confidence: beyond the catalog's eight extents)"
                }
            );
        }
    })?;
    let elapsed = started.elapsed().as_secs_f64();

    let files: Vec<String> = records
        .iter()
        .map(|r| {
            json::object(vec![
                ("type", json::string("hfs+")),
                ("ext", json::string(&r.ext)),
                ("cnid", json::number(r.cnid)),
                ("name", json::string(&r.name)),
                ("size", json::number(r.size)),
                ("sha256", json::string(&r.sha256)),
                ("deleted", json::boolean(r.deleted)),
                ("validated", json::boolean(r.validated)),
                ("confidence", json::string(r.confidence())),
                ("created", json::number(r.timestamps.created)),
                ("modified", json::number(r.timestamps.modified)),
                ("accessed", json::number(r.timestamps.accessed)),
                ("path", json::string(&r.path)),
            ])
        })
        .collect();
    let manifest = json::object(vec![
        ("tool", json::string(&format!("breadcrumb-rs {VERSION}"))),
        ("mode", json::string("hfs+")),
        ("source", json::string(reader.path())),
        ("source_size", json::number(reader.size())),
        ("volume_size", json::number(summary.volume_size)),
        ("block_size", json::number(summary.block_size)),
        ("node_size", json::number(summary.node_size)),
        ("records_outside_the_tree", json::number(summary.from_slack)),
        ("elapsed_s", json::float(elapsed)),
        ("files", json::array(files)),
    ]);
    if !opts.dry_run {
        std::fs::create_dir_all(&opts.out_dir).map_err(|e| format!("{}: {e}", opts.out_dir))?;
        let path = std::path::Path::new(&opts.out_dir).join("manifest.json");
        std::fs::write(&path, manifest).map_err(|e| format!("{}: {e}", path.display()))?;
    } else {
        println!("{manifest}");
    }

    // An inventory is not recovered data: a dry run writes the CSV so a
    // volume can be listed without extracting it.
    if let Some(csv) = csv_path {
        let mut out = String::from(
            "cnid,name,ext,size,sha256,deleted,confidence,created,modified,accessed,path\n",
        );
        for r in &records {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{}\n",
                r.cnid,
                r.name.replace(',', ";"),
                r.ext,
                r.size,
                r.sha256,
                r.deleted,
                r.confidence(),
                r.timestamps.created,
                r.timestamps.modified,
                r.timestamps.accessed,
                r.path.replace(',', ";")
            ));
        }
        std::fs::write(csv, out).map_err(|e| format!("{csv}: {e}"))?;
    }
    if !opts.quiet {
        let deleted = records.iter().filter(|r| r.deleted).count();
        eprintln!(
            "recovered {} file(s) ({deleted} deleted) from HFS+ in {elapsed:.2}s",
            records.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// APFS recovery from superseded copy-on-write objects.
///
/// There is no live/deleted split here: the objects come from every version the
/// container still holds, so everything found is a record of some past state.
fn run_apfs(
    reader: &Source,
    opts: &Options,
    machine: bool,
    csv_path: Option<&str>,
) -> Result<ExitCode, String> {
    use breadcrumb_rs::apfs;

    let started = Instant::now();
    let quiet = opts.quiet;
    let aopts = apfs::Options {
        out_dir: opts.out_dir.clone(),
        dry_run: opts.dry_run,
        min_size: opts.min_size,
    };
    let (records, summary) = apfs::recover(reader, opts.start, &aopts, |rec| {
        if machine {
            println!(
                "{}",
                json::object(vec![
                    ("event", json::string("file")),
                    ("name", json::string(&rec.name)),
                    ("file_id", json::number(rec.file_id)),
                    ("size", json::number(rec.size)),
                    ("sha256", json::string(&rec.sha256)),
                    ("validated", json::boolean(rec.validated)),
                    ("created", json::number(rec.timestamps.created)),
                    ("modified", json::number(rec.timestamps.modified)),
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
                    "  (low confidence: partial extent map or no name)"
                }
            );
        }
    })?;
    let elapsed = started.elapsed().as_secs_f64();

    let files: Vec<String> = records
        .iter()
        .map(|r| {
            json::object(vec![
                ("type", json::string("apfs")),
                ("ext", json::string(&r.ext)),
                ("file_id", json::number(r.file_id)),
                ("name", json::string(&r.name)),
                ("size", json::number(r.size)),
                ("sha256", json::string(&r.sha256)),
                ("validated", json::boolean(r.validated)),
                ("confidence", json::string(r.confidence())),
                ("created", json::number(r.timestamps.created)),
                ("modified", json::number(r.timestamps.modified)),
                ("accessed", json::number(r.timestamps.accessed)),
                ("path", json::string(&r.path)),
            ])
        })
        .collect();
    let manifest = json::object(vec![
        ("tool", json::string(&format!("breadcrumb-rs {VERSION}"))),
        ("mode", json::string("apfs")),
        ("source", json::string(reader.path())),
        ("source_size", json::number(reader.size())),
        ("volume_size", json::number(summary.volume_size)),
        ("block_size", json::number(summary.block_size)),
        ("fstree_nodes", json::number(summary.nodes_found)),
        ("unnamed", json::number(summary.unnamed)),
        ("elapsed_s", json::float(elapsed)),
        ("files", json::array(files)),
    ]);
    if !opts.dry_run {
        std::fs::create_dir_all(&opts.out_dir).map_err(|e| format!("{}: {e}", opts.out_dir))?;
        let path = std::path::Path::new(&opts.out_dir).join("manifest.json");
        std::fs::write(&path, manifest).map_err(|e| format!("{}: {e}", path.display()))?;
    } else {
        println!("{manifest}");
    }

    // An inventory is not recovered data: a dry run writes the CSV so a
    // volume can be listed without extracting it.
    if let Some(csv) = csv_path {
        let mut out = String::from(
            "file_id,name,ext,size,sha256,confidence,created,modified,accessed,path\n",
        );
        for r in &records {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                r.file_id,
                r.name.replace(',', ";"),
                r.ext,
                r.size,
                r.sha256,
                r.confidence(),
                r.timestamps.created,
                r.timestamps.modified,
                r.timestamps.accessed,
                r.path.replace(',', ";")
            ));
        }
        std::fs::write(csv, out).map_err(|e| format!("{csv}: {e}"))?;
    }
    if !opts.quiet {
        eprintln!(
            "recovered {} file(s) from {} FS-tree node(s) in {elapsed:.2}s",
            records.len(),
            summary.nodes_found
        );
        if summary.unnamed > 0 {
            eprintln!(
                "note: {} file(s) had extents but no name anywhere on the container",
                summary.unnamed
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// One recovered file, from whichever filesystem produced it.
///
/// The per-filesystem records carry different identities (an MFT number, an
/// inode, a CNID, a directory-entry offset) and different timestamps; this is
/// what they have in common, for one report across a whole disk.
struct AutoRecord {
    volume: usize,
    fs: &'static str,
    offset: u64,
    id_kind: &'static str,
    name: String,
    ext: String,
    size: u64,
    sha256: String,
    deleted: bool,
    confidence: &'static str,
    path: String,
    created: u64,
    modified: u64,
    accessed: u64,
    deleted_at: u64,
}

/// Every partition, each with the undelete mode its filesystem calls for.
///
/// This is the "point it at the disk" mode: an examination usually starts
/// without knowing what is on the thing, and running four tools by hand over
/// four offsets is how a volume gets missed.
fn run_auto(
    reader: &Source,
    opts: &Options,
    include_live: bool,
    machine: bool,
    csv_path: Option<&str>,
) -> Result<ExitCode, String> {
    use breadcrumb_rs::partition;

    // Volumes to try: the whole image if it is one, otherwise the table.
    let mut volumes: Vec<(usize, u64, &'static str, String)> = Vec::new();
    let whole = partition::detect_fs(reader, 0);
    if !whole.is_empty() {
        volumes.push((0, 0, whole, "whole image".to_string()));
    }
    for p in partition::parse(reader) {
        let fs = if p.fstype.is_empty() {
            partition::detect_fs(reader, p.start)
        } else {
            p.fstype
        };
        // Detection can come up empty on a volume whose header is damaged; the
        // partition type still says what it was meant to hold, and trying is
        // better than passing over it in silence.
        let fs = if fs.is_empty() {
            match p.name.as_str() {
                "apple-hfs" => "hfs+",
                "apple-apfs" => "apfs",
                "linux" | "linux-fs" | "linux-home" => "ext",
                "NTFS/exFAT" | "basic-data" => "ntfs",
                n if n.starts_with("FAT") => "fat",
                _ => "",
            }
        } else {
            fs
        };
        if fs.is_empty() {
            continue;
        }
        let label = if p.name.is_empty() {
            format!("{} #{}", p.scheme, p.index)
        } else {
            format!("{} #{} {}", p.scheme, p.index, p.name)
        };
        volumes.push((volumes.len(), p.start, fs, label));
    }
    if volumes.is_empty() {
        return Err("no filesystem found to recover from; --list-partitions \
                    shows what is on this image"
            .into());
    }

    let started = Instant::now();
    let mut all: Vec<AutoRecord> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for (index, base, fs, label) in &volumes {
        let (index, base, fs) = (*index, *base, *fs);
        if !opts.quiet {
            eprintln!("volume {index} at {base:#x}: {fs} ({label})");
        }
        // Each volume writes under its own directory, so two volumes holding
        // the same paths cannot overwrite each other. The filesystem's own name
        // is the directory below that, which each mode adds itself -- naming it
        // here as well would only risk disagreeing with what the mode found.
        let vol_out = std::path::Path::new(&opts.out_dir)
            .join(format!("volume{index}"))
            .to_string_lossy()
            .to_string();
        let before = all.len();
        let result = recover_one(
            reader,
            base,
            fs,
            &vol_out,
            opts,
            include_live,
            index,
            &mut all,
        );
        match result {
            Ok(()) => {
                if !opts.quiet {
                    eprintln!("  {} file(s)", all.len() - before);
                }
            }
            Err(e) => {
                // One unreadable volume must not end the sweep: the others may
                // be the ones that matter.
                if !opts.quiet {
                    eprintln!("  skipped: {e}");
                }
                skipped.push(format!("volume {index} ({fs}): {e}"));
            }
        }
    }
    let elapsed = started.elapsed().as_secs_f64();

    if machine {
        for r in &all {
            println!(
                "{}",
                json::object(vec![
                    ("event", json::string("file")),
                    ("volume", json::number(r.volume as u64)),
                    ("fs", json::string(r.fs)),
                    ("name", json::string(&r.name)),
                    ("size", json::number(r.size)),
                    ("sha256", json::string(&r.sha256)),
                    ("deleted", json::boolean(r.deleted)),
                    ("path", json::string(&r.path)),
                ])
            );
        }
    }

    let files: Vec<String> = all
        .iter()
        .map(|r| {
            json::object(vec![
                ("volume", json::number(r.volume as u64)),
                ("fs", json::string(r.fs)),
                (r.id_kind, json::number(r.offset)),
                ("name", json::string(&r.name)),
                ("ext", json::string(&r.ext)),
                ("size", json::number(r.size)),
                ("sha256", json::string(&r.sha256)),
                ("deleted", json::boolean(r.deleted)),
                ("confidence", json::string(r.confidence)),
                ("created", json::number(r.created)),
                ("modified", json::number(r.modified)),
                ("accessed", json::number(r.accessed)),
                ("deleted_at", json::number(r.deleted_at)),
                ("path", json::string(&r.path)),
            ])
        })
        .collect();
    let vols: Vec<String> = volumes
        .iter()
        .map(|(i, base, fs, label)| {
            json::object(vec![
                ("index", json::number(*i as u64)),
                ("offset", json::number(*base)),
                ("fs", json::string(fs)),
                ("label", json::string(label)),
            ])
        })
        .collect();
    let manifest = json::object(vec![
        ("tool", json::string(&format!("breadcrumb-rs {VERSION}"))),
        ("mode", json::string("auto")),
        ("source", json::string(reader.path())),
        ("source_size", json::number(reader.size())),
        ("volumes", json::array(vols)),
        (
            "skipped",
            json::array(skipped.iter().map(|s| json::string(s)).collect()),
        ),
        ("elapsed_s", json::float(elapsed)),
        ("files", json::array(files)),
    ]);
    if !opts.dry_run {
        std::fs::create_dir_all(&opts.out_dir).map_err(|e| format!("{}: {e}", opts.out_dir))?;
        let path = std::path::Path::new(&opts.out_dir).join("manifest.json");
        std::fs::write(&path, manifest).map_err(|e| format!("{}: {e}", path.display()))?;
    } else {
        println!("{manifest}");
    }

    // An inventory is not recovered data: a dry run writes the CSV so a
    // volume can be listed without extracting it.
    if let Some(csv) = csv_path {
        let mut out = String::from(
            "volume,fs,id,name,ext,size,sha256,deleted,confidence,created,modified,accessed,deleted_at,path\n",
        );
        for r in &all {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                r.volume,
                r.fs,
                r.offset,
                r.name.replace(',', ";"),
                r.ext,
                r.size,
                r.sha256,
                r.deleted,
                r.confidence,
                r.created,
                r.modified,
                r.accessed,
                r.deleted_at,
                r.path.replace(',', ";")
            ));
        }
        std::fs::write(csv, out).map_err(|e| format!("{csv}: {e}"))?;
    }
    if !opts.quiet {
        let deleted = all.iter().filter(|r| r.deleted).count();
        eprintln!(
            "recovered {} file(s) ({deleted} deleted) from {} volume(s) in {elapsed:.2}s",
            all.len(),
            volumes.len() - skipped.len()
        );
        for note in &skipped {
            eprintln!("skipped {note}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Run one volume through the mode its filesystem calls for.
#[allow(clippy::too_many_arguments)]
fn recover_one(
    reader: &Source,
    base: u64,
    fs: &'static str,
    out_dir: &str,
    opts: &Options,
    include_live: bool,
    index: usize,
    all: &mut Vec<AutoRecord>,
) -> Result<(), String> {
    use breadcrumb_rs::{apfs, ext4, fat, hfs, ntfs};

    match fs {
        "ntfs" => {
            let o = ntfs::Options {
                out_dir: out_dir.to_string(),
                dry_run: opts.dry_run,
                include_live,
                min_size: opts.min_size,
            };
            for r in ntfs::recover(reader, base, &o, |_| {})? {
                let confidence = r.confidence();
                all.push(AutoRecord {
                    volume: index,
                    fs,
                    offset: r.mft,
                    id_kind: "mft",
                    ext: r.ext,
                    name: r.name,
                    size: r.size,
                    sha256: r.sha256,
                    deleted: r.deleted,
                    confidence,
                    path: r.path,
                    created: r.timestamps.created,
                    modified: r.timestamps.modified,
                    accessed: r.timestamps.accessed,
                    deleted_at: 0,
                });
            }
        }
        "fat" | "exfat" => {
            let o = fat::Options {
                out_dir: out_dir.to_string(),
                dry_run: opts.dry_run,
                include_live,
                min_size: opts.min_size,
            };
            let (records, kind, _cluster) = fat::recover(reader, base, &o, |_| {})?;
            for r in records {
                let confidence = r.confidence();
                all.push(AutoRecord {
                    volume: index,
                    fs: kind,
                    offset: r.offset,
                    id_kind: "entry_offset",
                    ext: r.ext,
                    name: r.name,
                    size: r.size,
                    sha256: r.sha256,
                    deleted: r.deleted,
                    confidence,
                    path: r.path,
                    created: r.timestamps.created,
                    modified: r.timestamps.modified,
                    accessed: r.timestamps.accessed,
                    deleted_at: 0,
                });
            }
        }
        "ext" => {
            let o = ext4::Options {
                out_dir: out_dir.to_string(),
                dry_run: opts.dry_run,
                include_live,
                min_size: opts.min_size,
            };
            let (records, _summary) = ext4::recover(reader, base, &o, |_| {})?;
            for r in records {
                let confidence = r.confidence();
                all.push(AutoRecord {
                    volume: index,
                    fs: "ext4",
                    offset: r.inode,
                    id_kind: "inode",
                    ext: r.ext,
                    name: r.name,
                    size: r.size,
                    sha256: r.sha256,
                    deleted: r.deleted,
                    confidence,
                    path: r.path,
                    created: 0,
                    modified: r.timestamps.modified,
                    accessed: r.timestamps.accessed,
                    deleted_at: r.timestamps.deleted,
                });
            }
        }
        "hfs+" => {
            let o = hfs::Options {
                out_dir: out_dir.to_string(),
                dry_run: opts.dry_run,
                include_live,
                min_size: opts.min_size,
                scan_volume: true,
            };
            let (records, _summary) = hfs::recover(reader, base, &o, |_| {})?;
            for r in records {
                let confidence = r.confidence();
                all.push(AutoRecord {
                    volume: index,
                    fs,
                    offset: r.cnid,
                    id_kind: "cnid",
                    ext: r.ext,
                    name: r.name,
                    size: r.size,
                    sha256: r.sha256,
                    deleted: r.deleted,
                    confidence,
                    path: r.path,
                    created: r.timestamps.created,
                    modified: r.timestamps.modified,
                    accessed: r.timestamps.accessed,
                    deleted_at: 0,
                });
            }
        }
        "apfs" => {
            let o = apfs::Options {
                out_dir: out_dir.to_string(),
                dry_run: opts.dry_run,
                min_size: opts.min_size,
            };
            let (records, _summary) = apfs::recover(reader, base, &o, |_| {})?;
            for r in records {
                let confidence = r.confidence();
                all.push(AutoRecord {
                    volume: index,
                    fs,
                    offset: r.file_id,
                    id_kind: "file_id",
                    ext: r.ext,
                    name: r.name,
                    size: r.size,
                    sha256: r.sha256,
                    // Every APFS object is a past state; there is no live set
                    // to compare against.
                    deleted: true,
                    confidence,
                    path: r.path,
                    created: r.timestamps.created,
                    modified: r.timestamps.modified,
                    accessed: r.timestamps.accessed,
                    deleted_at: 0,
                });
            }
        }
        "bitlocker" => {
            return Err("BitLocker volume: pass a key (--bitlocker-recovery-key, \
                        --bitlocker-password, --bitlocker-bek or --bitlocker-fvek) \
                        and the volume will be unlocked before this runs"
                .into())
        }
        other => return Err(format!("no undelete mode for {other}")),
    }
    Ok(())
}

/// The volume's unallocated ranges, from its own allocation map.
///
/// This is the cheapest large win available on a full disk: the map costs one
/// small read (a 238 GB NTFS volume's $Bitmap is about 7 MiB) and everything
/// still allocated is then skipped. It also removes the main source of spurious
/// carves, since a stray header inside an allocated archive or installer is what
/// produces most of them.
fn plan_unallocated(reader: &Source, opts: &Options) -> Result<Vec<(u64, u64)>, String> {
    use breadcrumb_rs::partition;

    // Adjacent free runs closer than this are merged: reading a little
    // allocated data costs less than the seek and the per-range overhead of
    // avoiding it. Small enough not to swallow whole allocated files, large
    // enough that a fragmented volume does not become one range per cluster.
    const MERGE_GAP: u64 = 64 << 10;

    let base = opts.start;
    let fs = match partition::detect_fs(reader, base) {
        "" if base == 0 => {
            // No filesystem at the start of the image: try the partitions.
            let parts = partition::parse(reader);
            match partition::largest_matching(&parts, |fs| {
                matches!(fs, "ntfs" | "fat" | "exfat" | "ext")
            }) {
                Some((p, count)) => {
                    if !opts.quiet {
                        eprintln!(
                            "unallocated: using the largest candidate, {} at {:#x} ({})",
                            p.fstype,
                            p.start,
                            human(p.size)
                        );
                        if count > 1 {
                            eprintln!(
                                "unallocated: {} other volume(s) could have been meant -- \
                                 pass --offset to choose",
                                count - 1
                            );
                        }
                    }
                    return free_ranges_for(reader, p.fstype, p.start, MERGE_GAP, opts);
                }
                None => return Err(unallocated_unsupported("no filesystem found")),
            }
        }
        other => other,
    };
    free_ranges_for(reader, fs, base, MERGE_GAP, opts)
}

fn free_ranges_for(
    reader: &Source,
    fs: &str,
    base: u64,
    merge_gap: u64,
    opts: &Options,
) -> Result<Vec<(u64, u64)>, String> {
    let space = match fs {
        "ntfs" => breadcrumb_rs::ntfs::free_ranges(reader, base, merge_gap),
        "fat" | "exfat" => breadcrumb_rs::fat::free_ranges(reader, base, merge_gap),
        "ext" => breadcrumb_rs::ext4::free_ranges(reader, base, merge_gap),
        other => return Err(unallocated_unsupported(other)),
    }?;
    if space.ranges.is_empty() {
        return Err(
            "the allocation map reports no free space at all -- refusing \
                    rather than scanning nothing"
                .into(),
        );
    }
    if !opts.quiet {
        let to_scan: u64 = space.ranges.iter().map(|&(a, b)| b - a).sum();
        eprintln!(
            "unallocated: {} free of {} ({:.0}%); scanning {} in {} run(s) after \
             coalescing, skipping {}",
            human(space.free_bytes),
            human(space.volume_bytes),
            space.fraction() * 100.0,
            human(to_scan),
            space.ranges.len(),
            human(space.volume_bytes.saturating_sub(to_scan))
        );
    }
    Ok(space.ranges)
}

fn unallocated_unsupported(fs: &str) -> String {
    format!(
        "--unallocated needs an allocation map, and {fs} is not one this reads \
         (NTFS, FAT/exFAT and ext are). Scan the whole volume instead, or point \
         --offset at a volume that is."
    )
}

/// Report how far a running scan has got, until it is told to stop.
///
/// A carve of a real disk runs for hours. Without this the only output was the
/// summary at the end, so an analyst could not tell a slow scan from a stuck one
/// -- on a live 237 GB image there was nothing to distinguish sixteen hours of
/// progress from sixteen hours of a hang.
fn spawn_reporter<'a>(
    progress: &'a Progress,
    stop: &'a std::sync::atomic::AtomicBool,
    machine: bool,
    scope: &'a std::thread::Scope<'a, '_>,
) {
    use std::io::IsTerminal;
    use std::sync::atomic::Ordering;

    scope.spawn(move || {
        // Overwrite one line on a terminal; on a log, print a new line each
        // time so the history is kept.
        let tty = std::io::stderr().is_terminal();
        let started = Instant::now();
        // Quiet for the first few seconds, so a short scan says nothing, then
        // every five.
        let mut next = std::time::Duration::from_secs(3);
        let mut printed = false;
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(250));
            let elapsed = started.elapsed();
            if elapsed < next {
                continue;
            }
            next = elapsed + std::time::Duration::from_secs(5);
            let done = progress.scanned();
            if done == 0 {
                continue;
            }
            let secs = elapsed.as_secs_f64();
            let rate = done as f64 / secs;
            if machine {
                println!(
                    "{}",
                    json::object(vec![
                        ("event", json::string("progress")),
                        ("scanned", json::number(done)),
                        ("total", json::number(progress.total)),
                        ("files", json::number(progress.files())),
                        ("bytes_out", json::number(progress.bytes_out())),
                        ("elapsed_s", json::float(secs)),
                        ("rate_bytes_s", json::number(rate as u64)),
                    ])
                );
                continue;
            }
            let pct = if progress.total > 0 {
                100.0 * done as f64 / progress.total as f64
            } else {
                0.0
            };
            let eta = if rate > 0.0 && progress.total > done {
                format_duration(((progress.total - done) as f64 / rate) as u64)
            } else {
                "--".to_string()
            };
            let line = format!(
                "  {} of {} ({pct:.1}%) · {}/s · {} file(s), {} · ETA {eta}",
                human(done),
                human(progress.total),
                human(rate as u64),
                progress.files(),
                human(progress.bytes_out()),
            );
            printed = true;
            if tty {
                eprint!("\r{line}\x1b[K");
            } else {
                eprintln!("{line}");
            }
        }
        if tty && printed {
            eprintln!();
        }
    });
}

/// Seconds as something an analyst can read at a glance.
fn format_duration(secs: u64) -> String {
    match secs {
        s if s < 90 => format!("{s}s"),
        s if s < 5400 => format!("{}m", s / 60),
        s if s < 86_400 * 2 => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d{}h", s / 86_400, (s % 86_400) / 3600),
    }
}

/// Append-only record of what a scan has carved so far.
///
/// The manifest is written when a scan finishes, which is no help when one is
/// killed: two interrupted runs on a real examination left 165 GB of carved
/// files and no record of what any of them were. Each record is written here as
/// its range completes, flushed, so the answer survives a kill -9.
fn open_record_stream(out_dir: &str, resume: bool) -> Option<std::fs::File> {
    use std::fs::OpenOptions;
    let path = std::path::Path::new(out_dir).join("carved.jsonl");
    std::fs::create_dir_all(out_dir).ok()?;
    OpenOptions::new()
        .create(true)
        .append(resume)
        .write(true)
        .truncate(!resume)
        .open(&path)
        .ok()
}

fn stream_records(stream: &mut Option<std::fs::File>, records: &[Record]) {
    use std::io::Write;
    let Some(file) = stream.as_mut() else {
        return;
    };
    let mut buf = String::new();
    for r in records {
        buf.push_str(&json::object(vec![
            ("type", json::string(r.kind)),
            ("ext", json::string(r.ext)),
            ("offset", json::number(r.offset)),
            ("size", json::number(r.size)),
            ("sha256", json::string(&r.sha256)),
            ("validated", json::boolean(r.validated)),
            ("confidence", json::string(r.confidence())),
            ("path", json::string(&r.path)),
        ]));
        buf.push('\n');
    }
    if !buf.is_empty() {
        let _ = file.write_all(buf.as_bytes());
        let _ = file.flush();
    }
}

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
    match breadcrumb_rs::partition::largest_matching(&parts, |fs| fs == "ntfs") {
        Some((p, count)) => {
            if !opts.quiet {
                eprintln!(
                    "ntfs: volume at {:#x} ({}, {})",
                    p.start,
                    p.name,
                    human(p.size)
                );
                if count > 1 {
                    eprintln!(
                        "ntfs: {} other NTFS volume(s) here -- pass --offset to choose",
                        count - 1
                    );
                }
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
    // The walk says where it is: a million-record MFT takes minutes, and
    // silence for minutes is indistinguishable from a hang.
    let mut last = Instant::now();
    let records = ntfs::recover_reporting(
        reader,
        base,
        &nopts,
        |rec| {
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
        },
        |done, total| {
            if quiet || machine || last.elapsed() < std::time::Duration::from_secs(5) {
                return;
            }
            last = Instant::now();
            let pct = if total > 0 {
                100.0 * done as f64 / total as f64
            } else {
                0.0
            };
            eprintln!("  MFT {done}/{total} ({pct:.0}%)");
        },
    )?;
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
    } else {
        println!("{manifest}");
    }

    // An inventory is not recovered data: a dry run writes the CSV so a
    // volume can be listed without extracting it.
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
            (
                "decoded",
                match r.decoded {
                    Some(v) => json::boolean(v),
                    None => "null".to_string(),
                },
            ),
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
