# breadcrumb-rs

Signature-based file carver for disk images and block devices — recovers deleted
files by scanning raw bytes, with no filesystem metadata involved.

A Rust port of the carving core of [BreadCrumb](https://github.com/sltcnb/BreadCrumb)
(Python). Same signatures, same structure-walking handlers, same output layout —
**byte-identical carves**, roughly **7x the throughput**.

```sh
cargo build --release
./target/release/bcrumb-rs disk.dd  -o carved -j 0
./target/release/bcrumb-rs disk.E01 -o carved -j 0   # EWF sets read natively
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
| scan through 8-segment E01, 1 thread | 5.46 s — 94 MiB/s | 0.76 s — 674 MiB/s | **7.2x** |
| scan through 8-segment E01, 8 workers | 1.32 s — 388 MiB/s | 0.20 s — 2602 MiB/s | **6.7x** |

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
| 513 MiB raw, ~500 planted files in random filler | 511 | yes |
| BreadCrumb's own `tests/make_test_image.py` output | 12 | yes |
| the same 513 MiB as an 8-segment compressed E01 | 510 | yes |
| 120 MiB as a 124-segment E01 set (`E01`…`EAY`) | 7268 | yes |
| 4 MiB as a 4-segment compressed E01 | 356 | yes |

That is the acceptance test for this port: if a handler here disagreed with the
Python one by a single byte, the hashes would diverge.

`cargo test` additionally carves a synthetic image containing one file of every
supported type and checks each recovery byte-for-byte, plus the behaviour
switches (align, min-size, dedup, offset/length, no-skip, serial vs parallel),
truncation safety, and two regression cases ported from upstream fixes: PDF
trailing-EOL over-carve, and the profile-locked MP3 frame walk.

## What is carved

All 28 types the Python implementation carves, each with a structure-walking
handler that finds the file's true end:

`jpg` `png` `gif` `bmp` `tif` `pdf` `rtf` `ole` (`doc`/`xls`/`ppt`/`msg`/`vsd`/`pub`/`msi`)
`pst` (`.pst`/`.ost`) `zip` (+`docx`/`xlsx`/`pptx`/`vsdx`/`jar`/`apk`/`epub`/`odf`) `gz` `7z` `sqlite`
`mp4` (+`mov`/`heic`/`avif`/`3gp`/`m4a`/`m4v`) `riff` (`wav`/`avi`/`webp`) `mp3`
`exe`/`dll` (PE) `elf` `macho` (thin + universal) `rar` `flac` `psd`
`ico` `ogg` `mkv`/`webm` `evtx` `hive` `plist`

`--list-types` prints them at runtime, with the groups below.

### Documents

Office documents span three unrelated containers, so `-t office` takes all of
them at once (`ole,zip,pdf,rtf`); `docs`, `images`, `media` and `archives` are
grouped the same way.

```
$ bcrumb-rs disk.E01 -t office -o out
  doc    at  0x1800   2048 B  high
  rtf    at  0x2800    127 B  high
  pdf    at  0x3200    106 B  high
  docx   at  0x3c00    267 B  high
  zip    at  0x4600   1249 B  high
```

Legacy Office files are OLE2/CFB containers, and the extension comes from the
root entry's CLSID — the application's own statement of what it wrote — with
the directory stream names as fallback — `WordDocument` → `doc`, `Workbook`/`Book` →
`xls`, `PowerPoint Document` → `ppt`, `__substg1.0_*` → `msg` (Outlook),
`VisioDocument` → `vsd` — so the carve is triageable without opening anything.
The modern formats are ZIP containers, named from their internal paths
(`word/` → `docx`, `xl/` → `xlsx`, `ppt/` → `pptx`, `visio/` → `vsdx`).

A zip's end is found by walking its local file headers, then the central
directory, then the EOCD — never by searching forward for a trailing
`PK\x05\x06`, which on a real disk finds the *next* archive's directory and
carves everything in between. An archive that cannot be resolved is bounded by
the members actually accounted for and reported unvalidated.

## Not ported

This is the carving core only. For any of the following, use the Python
implementation — it remains the reference and the more complete tool:

- **Filesystem undelete modes** — NTFS / ext4 / FAT / HFS+ / APFS metadata
  recovery (`--ntfs`, `--auto`, …), which recover names and timestamps
- **VHD/VHDX, Ex01/EWF2, L01, AFF.** Raw images, block devices, EWF
  (`.E01`/`.s01`) sets, QCOW2, sparse VMDK, split raw and stdin are all read
  here; what is left is refused outright, by magic and by extension, because
  carving a container as raw reports fragments of its own compressed chunk data
  as recovered files with nothing to signal the mistake

  ```
  $ bcrumb-rs disk.vhdx -o out
  bcrumb-rs: disk.vhdx: this is a VHDX image, which this port cannot read --
  carving it as raw would report the container's own bytes as recovered files.
  Use the Python implementation (https://github.com/sltcnb/BreadCrumb), which
  reads it directly, or convert to raw first.
  ```
- **Deep validation** (`--validate`) and bifragment reassembly
- **Regex `--grep`** (literal patterns are supported here), custom `--sig-file`
  signatures, and `--from-manifest`

## Image formats

Detected by magic, falling back to the extension, so the image goes straight in
with no conversion step:

| Format | Notes |
| --- | --- |
| raw / dd | also block devices; `-` spools stdin to a temp file |
| split raw | `.001/.002…` globbed from the first segment |
| EWF / E01 | see below |
| QCOW2 v2/v3 | raw + zlib clusters |
| VMDK | monolithic sparse (grain tables) |

## EWF / E01

`.E01` and `.s01` sets are read natively — no conversion step, no libewf:

```sh
bcrumb-rs RM.E01 -o out -j 0        # pass the FIRST segment only
```

The section list and chunk table are parsed directly, stored and
deflate-compressed chunks are decoded on demand, and the rest of the set is
found by name through libewf's full sequence: `E01`…`E99`, then `EAA`…`EZZ`,
`FAA`…, through `ZZZ`. Media size comes from the volume section's sector count,
so carve offsets match the original disk.

If segments are missing, the read is refused rather than silently carving part
of the evidence:

```
bcrumb-rs: RM.E01: incomplete EWF set: 29 segment(s) hold 899 of 3840 chunks
(23.4% of the media). Last segment read: RM.E29 - the following segments are
missing or misnamed.
```

Not covered: **Ex01/EWF2**, bzip2-compressed chunks, and encrypted EWF — use the
Python implementation with `libewf-python` for those.

## BitLocker

A locked volume reads back as plaintext at the same offsets, so carving and
`--grep` work through it unchanged:

```sh
bcrumb-rs disk.E01 -t office -o out \
    --bitlocker-recovery-key 471806-...-635835
```

Credentials: `--bitlocker-recovery-key` (48 digits), `--bitlocker-password`,
`--bitlocker-bek` (startup key file), or `--bitlocker-fvek` (raw key, skipping
recovery). Suspended volumes still need one of these to be passed before the
clear-key protector is used, matching the Python implementation.

Ciphers: **AES-XTS-128/256** (the Windows 8+/10/11 default), AES-CBC-128/256,
and AES-CBC + **Elephant diffuser** (Vista/7). Only the AES block cipher comes
from a crate; XTS, CBC, CCM and the diffuser are implemented in `src/crypto.rs`
so the whole decryption path reads as one file.

If the three FVE metadata offsets in the boot sector do not resolve, the error
names each offset and the bytes actually found there, and
`--bitlocker-scan-metadata` walks the volume for the metadata block instead —
for a header that is partly overwritten, or a layout this code does not expect.

A credential that unlocks nothing is an error, not an empty result — carving
ciphertext and reporting "0 files" is indistinguishable from an empty disk.

TPM-only protectors cannot be unlocked from an image by any tool: the key is
sealed in hardware. Use the recovery key, a `.BEK`, or the FVEK.

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
and `flate2` with the `rust_backend` feature (gzip member sizing and EWF chunk
decompression — no libewf needed). Parallelism
uses `std::thread::scope`; the JSON manifest is written directly. No C toolchain
required.

MSRV 1.74. CI covers fmt, clippy (`-D warnings`), and tests on Linux, macOS,
and Windows.

## License

MIT, same as the upstream project.
