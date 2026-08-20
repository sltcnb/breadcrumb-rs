# breadcrumb-rs

Signature-based file carver for disk images and block devices — recovers deleted
files by scanning raw bytes, with no filesystem metadata involved.

A Rust port of the carving core of [BreadCrumb](https://github.com/sltcnb/BreadCrumb)
(Python). Same signatures, same structure-walking handlers, same output layout —
**byte-identical carves**, roughly **7x the throughput**.

```sh
cargo build --release
./target/release/bcrumb-rs disk.dd -o carved -j 0
```

## Why a port

BreadCrumb's scan is bounded almost entirely by one thing: finding candidate
headers. Profiling the Python implementation over a 513 MiB image put **84% of
wall-clock inside CPython's `re` engine** — the rest (reads, handlers, hashing)
barely registered. That is the part a native multi-pattern matcher with a SIMD
prefilter changes, and `aho-corasick` is exactly that.

## Benchmarks

513 MiB image, 20 signature types, warm page cache, Apple M-series (12 logical
cores, 6 performance). Best of 3 runs. `--dry-run` isolates the scan; the full
carve also hashes and writes 511 files.

| Workload | Python (`bcrumb`) | Rust (`bcrumb-rs`) | Speedup |
| --- | --- | --- | --- |
| scan, 1 thread | 4.35 s — 118 MiB/s | 0.60 s — 855 MiB/s | **7.2x** |
| scan, 8 workers | 0.90 s — 570 MiB/s | 0.15 s — 3420 MiB/s | **6.0x** |
| full carve + write, 1 thread | 4.58 s | 1.06 s | **4.3x** |

For reference on the same box and the same 34 magics, `ripgrep` scans that image
at ~2050 MiB/s single-threaded — so the matcher here is in the right league, and
what remains is handler and I/O work.

Parallelism differs in kind, not just degree: Python forks worker *processes*
(`-j` in BreadCrumb), while this uses threads over one read-only file handle,
so there is no per-worker interpreter or re-open cost.

## Parity with the reference implementation

Both tools were run over the same images and their manifests compared on
`(offset, size, sha256, ext, validated, duplicate_of)` for every record:

| Image | Records | Identical |
| --- | --- | --- |
| 513 MiB, ~500 planted files in random filler | 511 | yes |
| BreadCrumb's own `tests/make_test_image.py` output | 12 | yes |

That is the acceptance test for this port: if a handler here disagreed with the
Python one by a single byte, the hashes would diverge.

`cargo test` additionally carves a synthetic image containing one file of every
supported type and checks each recovery byte-for-byte, plus the behaviour
switches (align, min-size, dedup, offset/length, no-skip, serial vs parallel),
truncation safety, and two regression cases ported from upstream fixes: PDF
trailing-EOL over-carve, and the profile-locked MP3 frame walk.

## What is carved

20 types, each with a structure-walking handler that finds the file's true end:

`jpg` `png` `gif` `bmp` `tif` `pdf` `zip` (+`docx`/`xlsx`/`pptx`/`jar`/`apk`/`epub`/`odf`)
`gz` `7z` `sqlite` `mp4` (+`mov`/`heic`/`avif`/`3gp`/`m4a`/`m4v`) `riff` (`wav`/`avi`/`webp`)
`mp3` `elf` `ico` `ogg` `mkv`/`webm` `evtx` `hive` `plist`

`--list-types` prints them at runtime.

## Not ported

This is the carving core only. For any of the following, use the Python
implementation — it remains the reference and the more complete tool:

- **Filesystem undelete modes** — NTFS / ext4 / FAT / HFS+ / APFS metadata
  recovery (`--ntfs`, `--auto`, …), which recover names and timestamps
- **BitLocker** transparent decryption
- **Container image readers** — EWF/E01, QCOW2, VMDK, split raw, stdin spooling.
  Only raw images and block devices are read here
- **Deep validation** (`--validate`) and bifragment reassembly
- **`--grep`, `--list-partitions`, custom `--sig-file` signatures**
- **HTML/CSV/bodyfile/timeline reports** — the JSON manifest is written, the
  derived reports are not
- Handlers for `exe`/PE, `macho`, `ole`, `rar`, `flac`, `psd`

## Usage

```
usage: bcrumb-rs [options] <source>

  -o, --output DIR     output directory (default: ./carved)
  -t, --types LIST     comma-separated types (default: all; aliases accepted)
      --list-types     list supported types and exit
  -j, --jobs N         parallel scan threads (0 = all cores)
      --offset N        start scanning at byte N
      --length N        scan only N bytes
      --align N         only carve headers on N-byte boundaries
      --min-size N      drop carves smaller than N bytes
      --max-size N      cap every carve window
      --chunk N         scan chunk size (default 32 MiB)
      --no-skip         also carve files embedded inside other files
      --no-dedup        keep byte-identical duplicates
      --dry-run         inventory only, write nothing
  -q, --quiet          no progress output
```

Sizes accept `K`/`M`/`G` suffixes. Each carve lands in
`<out>/<ext>/f_<offset:012x>.<ext>`, with `<out>/manifest.json` recording type,
offset, size, SHA-256, `validated`, `confidence`, and `duplicate_of` per file.

## The source is opened read-only

`File::open` requests read access only, and no code path holds a writable handle
to the source: every write goes to the output directory. Standard forensic
practice still applies — work from an image or behind a write blocker, not the
original media.

## Dependencies

Three, all pure Rust: `aho-corasick` (the reason this port exists), `sha2`,
and `flate2` with the `rust_backend` feature (gzip member sizing). Parallelism
uses `std::thread::scope`; the JSON manifest is written directly. No C toolchain
required.

MSRV 1.74. CI covers fmt, clippy (`-D warnings`), and tests on Linux, macOS,
and Windows.

## License

MIT, same as the upstream project.
