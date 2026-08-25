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

## NTFS undelete

Carving finds file *content* by its bytes, which is why every carved file is
named `f_<offset>.<ext>`. `--ntfs` finds files by their *metadata* instead, and
recovers what carving cannot:

```sh
bcrumb-rs disk.E01 --ntfs -o out --csv files.csv \
    --bitlocker-recovery-key 650441-...-609257
```

- **original names and directory paths**, rebuilt by walking parent references
- **timestamps**: created, modified, MFT-changed, accessed
- **fragmented files intact** — the runlist says where every piece is, where a
  carve would return the first fragment plus whatever follows it
- named data streams, as `path~stream`

The volume is found automatically (whole-image NTFS, or the first NTFS partition
in the table); `--offset` points at one directly. `--include-live` recovers files
still in use as well as deleted ones.

Two things it will not do, both deliberate: a compressed or encrypted stream is
skipped rather than written out as garbage, and a file whose clusters have been
reused since deletion comes back with whatever is there now, flagged low
confidence — never silently.

## When files were deleted

NTFS records four timestamps per file and none of them is "deleted": the MFT
change time is only a proxy. Two Windows artefacts record it outright, and
`--deleted-times` reads both:

```sh
bcrumb-rs disk.E01 --deleted-times -o out          # writes out/deletions.csv
bcrumb-rs ./artefacts --deleted-times --events d.csv   # already-extracted files
```

- `$Recycle.Bin/$I*` — one record per item deleted through Explorer: the
  deletion time, the original size, and the full original path (both the
  Vista-era fixed-length layout and the Windows 10 length-prefixed one)
- `$Extend/$UsnJrnl:$J` — the change journal, read straight off the volume,
  live or deleted, V2 and V3 records; `--usn-all` reports every reason rather
  than only `file-delete`

The journal is sparse, so only its allocated clusters are read — its declared
length is mostly hole. A carved copy that starts inside a record still parses:
the walk hunts for the next plausible record instead of trusting the offset it
started on.

An empty result is reported as one, not as an absence of evidence: the recycle
bin may simply be empty, and the journal can be disabled or wiped.

## Not ported

This is the carving core only. For any of the following, use the Python
implementation — it remains the reference and the more complete tool:

- **ext4 / FAT / HFS+ / APFS undelete** — NTFS is done (above); the others and
  the `--auto` whole-disk sweep are not ported yet
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

## Fuzzing

Every handler parses structures that come off a disk of unknown provenance:
sizes, offsets and counts are all attacker-controlled in practice. Two layers
cover that:

- `tests/fuzz_smoke.rs` runs on stable in ordinary CI. Valid files are mutated —
  bytes flipped, length fields made absurd, tails truncated, files spliced onto
  themselves — and every handler runs over the result. A handler may reject
  anything, but it must not panic, must not take seconds on a few KB, and must
  never report a carve reaching past its window.
- `fuzz/` holds cargo-fuzz targets (`handlers`, `ewf`, `fve`, `artifacts`) for
  longer campaigns, built in CI and run for a minute each.

The invariant is also enforced centrally in the scan engine: a carve larger than
its window is rejected, so one arithmetic slip in one of 28 parsers cannot write
unrelated disk into evidence. The first run of the mutation fuzz found exactly
that — a corrupted PNG chunk length yielding 16 KB from an 80-byte window.

## Verifying the image first

EWF stores the MD5, and usually the SHA-1, computed while the disk was read.
`--verify` recomputes them over the decoded data and compares:

```
$ bcrumb-rs disk.E01 --verify
md5    5bd967b8f1e50e694f72d358579c3323  MATCH  (stored 5bd967b8f1e50e694f72d358579c3323)
sha1   671f433e9eb9a13aba58c13881ab5bc88f9aa00c  MATCH  (stored 671f...)
sha256 4044e4245130a7304af475e0c4c62945534ef461f57263006da0639ba6fcaa3f
2405376 bytes verified
```

Exit status is 0 only on a match, so it drops straight into a script. A missing
segment or truncated acquisition fails with the offset where the read stopped,
rather than being discovered halfway through a carve.

One caveat worth knowing: if the source was not a whole number of sectors, some
acquisition tools hash bytes they then do not store, which shows up here as a
mismatch. Real disks are always sector multiples.

## Resuming an interrupted scan

A scan of a few hundred gigabytes runs long enough that a power cut, a full
disk or a stray `pkill` should not mean starting over. Finished byte ranges are
checkpointed to `<out>/.bcrumb-state` as they complete, and `--resume` picks up
the rest:

```
$ bcrumb-rs disk.E01 -o out -t office          # dies at 45 of 60 GiB
scan incomplete: 45.0 GiB of 60.0 GiB done. Re-run with --resume to continue

$ bcrumb-rs disk.E01 -o out -t office --resume
resuming: 45.0 GiB of 60.0 GiB already scanned, 1 range(s) left
resumed: carried 135 record(s) forward from the earlier manifest
```

Records from the earlier attempt are folded into the new manifest, so the result
describes the whole image and not just the part this run did — a resumed scan
produces the same records as a single pass, which the tests check directly. The
state file names the source, its size and the type set, and a resume against a
different scan is refused rather than skipping ranges of the wrong disk. It is
deleted once the scan completes, so a later run does not skip work.

## Not filling the disk

A carve can write more than the volume it is written to can hold: on a 238 GB
image an unfiltered run reached 51 GB inside the first percent. So before
writing anything the free space is checked, and the scan stops itself rather
than filling the filesystem:

```
$ bcrumb-rs disk.E01 -o out -t office
output: 55.0 GiB free on the target volume, stopping at 2.0 GiB free
```

- `--min-free SIZE` — floor on free space, default **2 GiB**; the run refuses to
  start below it and stops when it gets there. `--min-free 0` disables the check.
- `--max-output SIZE` — hard ceiling on carved bytes. The scan stops cleanly and
  the manifest still describes everything written, with a line saying the run
  did not finish.

`--dry-run` writes nothing at all and still produces the manifest, which is the
cheap way to size a job before committing to it.

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
