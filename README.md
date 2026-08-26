# breadcrumb-rs

Signature-based file carver for disk images and block devices — recovers deleted
files by scanning raw bytes, with no filesystem metadata involved.

Carving plus filesystem undelete for NTFS, FAT/exFAT, ext2/3/4, HFS+ and APFS;
EWF/E01 and BitLocker read natively; deep validation of what it recovers.

It began as a Rust port of the carving core of
[BreadCrumb](https://github.com/sltcnb/BreadCrumb) (Python) and is now the
implementation that is developed — byte-identical carves at roughly **7x the
throughput**, and since then everything above.

```sh
cargo build --release
./target/release/bcrumb-rs disk.dd  -o carved -j 0
./target/release/bcrumb-rs disk.E01 -o carved -j 0   # EWF sets read natively
```

## Which mode

| What you have | What to run | What you get back |
| --- | --- | --- |
| a disk and no idea what is on it | [`--auto`](#a-whole-disk-in-one-pass) | every partition, each with the right undelete mode |
| a Windows volume | [`--ntfs`](#ntfs-undelete) | original names, paths, four timestamps, fragmented files intact |
| a card or USB stick | [`--fat`](#fat-and-exfat-undelete) | names, sizes, timestamps; contiguous files exactly |
| a Linux volume | [`--ext4`](#ext234-undelete) | names, paths, and *when the file was deleted* |
| a Mac volume | [`--apfs`](#apfs-recovery) / [`--hfs`](#hfs-undelete) | files from superseded objects / from the catalog |
| a question of *when* | [`--deleted-times`](#when-files-were-deleted) | deletion times from the recycle bin and change journal |
| no filesystem left at all | the default carve | files by their bytes, `-t` to pick types |
| carved files you do not trust | [`--validate`](#is-the-carved-file-intact) | each one decoded, `verified` or `failed` |
| a keyword or a pattern | [`--grep`](#searching-custom-formats-later-reports) | hits with offsets and context, ASCII and UTF-16LE |
| an image to check first | [`--verify`](#verifying-the-image-first) | its hashes against the ones acquisition recorded |

Nothing is guessed at: where a filesystem cannot say something — whether a FAT
file was fragmented, whether an ext4 inode still has its map — the tool says so
instead of implying it knows.

## Why Rust

A carve is bounded almost entirely by one thing: finding candidate headers.
Profiling the Python implementation over a 513 MiB image put **84% of wall-clock
inside CPython's `re` engine** — the rest (reads, handlers, hashing) barely
registered. That is the part a native multi-pattern matcher with a SIMD prefilter
changes, and `aho-corasick` is exactly that.

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

## Parity with the Python implementation

The carving core was accepted by byte parity: both tools were run over the same
images and their manifests compared on
`(offset, size, sha256, ext, validated, duplicate_of)` for every record:

| Image | Records | Identical |
| --- | --- | --- |
| 513 MiB raw, ~500 planted files in random filler | 511 | yes |
| BreadCrumb's own `tests/make_test_image.py` output | 12 | yes |
| the same 513 MiB as an 8-segment compressed E01 | 510 | yes |
| 120 MiB as a 124-segment E01 set (`E01`…`EAY`) | 7268 | yes |
| 4 MiB as a 4-segment compressed E01 | 356 | yes |

That was the acceptance test for the port: if a handler here disagreed with the
Python one by a single byte, the hashes would diverge. Everything added since --
the undelete modes, validation, the artefact parsers -- is tested against
volumes and files made by other implementations instead (`newfs_msdos`,
`newfs_exfat`, `mke2fs`, `newfs_hfs`, `diskutil ... APFS`, `ewfacquire`,
Python's `zipfile`/`gzip`/`sqlite3`), which is the same idea applied where there
is no second implementation of the same tool to diff against.

`cargo test` additionally carves a synthetic image containing one file of every
supported type and checks each recovery byte-for-byte, plus the behaviour
switches (align, min-size, dedup, offset/length, no-skip, serial vs parallel),
truncation safety, and two regression cases ported from upstream fixes: PDF
trailing-EOL over-carve, and the profile-locked MP3 frame walk.

## What is carved

28 types, each with a structure-walking
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

## A whole disk in one pass

An examination usually starts without knowing what is on the thing, and running
four modes by hand over four offsets is how a volume gets missed.

```sh
bcrumb-rs disk.E01 --auto -o out --csv files.csv
```

`--auto` reads the partition table, identifies each volume's filesystem, and
runs the mode that filesystem calls for — NTFS, FAT/exFAT, ext, HFS+ or APFS —
writing each volume's recoveries under `out/volume<N>/`. One CSV and one
manifest cover the disk, with a `volume` and `fs` column on every row.

A volume that cannot be read does not end the sweep: it is reported as skipped,
by name and reason, in the manifest and on the way out. Volumes are listed in
the manifest whether or not they yielded anything, so the record says what was
covered rather than only what was found. A BitLocker volume is unlocked first if
a key was given, and named as skipped if not.

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

## FAT and exFAT undelete

A camera card, a USB stick, most removable media:

```sh
bcrumb-rs card.dd --fat -o out --csv files.csv
```

A deleted FAT entry keeps everything except its allocation chain: the size, the
start cluster and the timestamps are all still there, and only the first
character of the short name is overwritten with `0xE5` (shown as `_`). Long
names usually survive in the entries preceding it.

What is gone is the list of clusters after the first, so a file that was
contiguous is recovered exactly and one that was fragmented is recovered as the
bytes that follow its first cluster. Nothing in the filesystem distinguishes the
two, so the tool says so — in the manifest and on the way out — rather than
implying more than it knows.

exFAT is in better shape: deletion clears an in-use bit, so the full name and
the data length survive, and the format records outright whether a file was
contiguous.

Deleted files inside live directories are found too: the directory's own chain
is intact, so it can be walked to reach the entries in it.

## ext2/3/4 undelete

```sh
bcrumb-rs disk.dd --ext4 -o out --csv files.csv
```

Two sources have to be combined, because neither is enough alone. Directory
blocks map inode numbers to names — including names left in the slack of a
record whose file was unlinked — so files come back with their original paths.
The inode holds the size, the block map and the timestamps, and unlike NTFS it
records *when the file was deleted*.

Both map styles are handled: the ext2/3 pointer list with its three levels of
indirection, and the ext4 extent tree.

The real limit is what ext4 does on delete: freeing an inode usually clears its
extent tree, and then the content is no longer on the volume at all. Those files
are counted and named in the summary rather than written out as zeros —

```
note: 12 deleted inode(s) had their block map already cleared -- ext4 does that
when it frees an inode, and the content is not on the volume any more (the
journal may still hold a copy)
```

A file whose map has holes is written with the holes zero-filled and reported at
low confidence. Inline-data inodes (content stored inside the inode) and
encrypted inodes are skipped rather than guessed at.

## HFS+ undelete

```sh
bcrumb-rs disk.dd --hfs -o out --csv files.csv
```

The catalog B-tree holds a name, a parent and the fork extents for every file.
Deleting one takes its offset out of its node's record array; the record itself
often stays where it was. So records are read by their own shape rather than
through that array — which is exactly what a deleted record is no longer in —
and whether a record is still listed there is how live and deleted are told
apart. The whole volume is then swept for catalog nodes that are no longer part
of the tree: journal copies, and nodes the tree compacted away.

Only the eight extents in the catalog record are followed. A file fragmented
beyond that continues in the extents-overflow file, which is not walked, so it
comes back truncated and marked low confidence rather than passed off as whole.

**What to expect**: deleting a file through macOS on a journaled HFS+ volume
often leaves no catalog record at all. Measured while building this: of 100
files deleted that way, 0 names were still anywhere on the volume. When that is
what happened, this mode has nothing to work with and carving is the only route
left — the file's *content* usually is still there.

## APFS recovery

```sh
bcrumb-rs disk.dd --apfs -o out --csv files.csv
```

APFS never overwrites metadata in place. Every change writes new B-tree nodes
and leaves the old ones until the space is reused, so the filesystem-tree leaf
that described a deleted file is usually still on the disk as a superseded copy.
This scans every block for FS-tree leaf nodes, confirms each by its Fletcher-64
checksum, and joins the records across all the versions it finds:

| record | gives |
| --- | --- |
| `DIR_REC` | parent id + name → file id, so paths can be rebuilt |
| `INODE` | logical size and timestamps |
| `FILE_EXTENT` | logical offset → physical block and length |

There is no live/deleted distinction here, and the tool does not invent one:
every object found is a record of some past state of the container, so a file
that was never deleted comes back alongside one that was.

Not decoded: compressed and encrypted streams, and inline data held in an
extended attribute instead of extents. A file whose extent map is incomplete is
written with the gaps zero-filled and reported at low confidence.

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

## Carve only the free space

```sh
bcrumb-rs disk.E01 --list-free                        # how much is worth scanning?
bcrumb-rs disk.E01 -t office -o out --unallocated     # scan only that
```

The filesystem already knows which clusters nothing owns, so `--unallocated`
asks it: NTFS `$Bitmap`, the FAT itself, ext's per-group block bitmaps. Reading
the map is one small read — a 238 GB NTFS volume's bitmap is about 7 MiB — and
everything still allocated is then skipped.

Two things follow, and the second is easy to miss:

- **Time.** The saving is whatever fraction of the volume is in use. On a disk
  that is 70% full, that is 70% of the scan.
- **Noise.** Most spurious carves come from *allocated* data — a stray header
  inside an installer payload or a nested archive. Skipping allocated space
  removes them at the source, and the files that were still allocated are
  recoverable by reading the filesystem anyway (`--ntfs`, `--fat`, `--ext4`).

A file that starts in free space and runs past the end of a free run is still
carved whole: the run bounds where headers are *looked for*, not how far a carve
may read. Free runs closer together than 64 KiB are coalesced, so a fragmented
volume does not turn into one range per cluster; the reported numbers say both
what is free and what will actually be read.

HFS+ and APFS are not covered — their maps are not read yet — and the tool says
so rather than silently scanning everything.

## ZIP fragments are not archives

A carved ZIP-family file (`zip`, `docx`, `xlsx`, `pptx`, `jar`, …) must have a
central directory of its own. Without one it is not written.

That default came from a measurement, not a preference. A scan of a 238 GB
Windows disk for `-t office` produced 67.6 GB, of which **3192 files were exactly
16 MiB — 49.9 GB, 74% of everything written**. That size is the tool's own cap
for an archive whose end it cannot resolve, hit dead on. Sampling them found
`not a zip file` far more often than not; the genuine finds were the other
quarter (2.1 GB of PDF, ~1 GB xlsx, 727 MB pptx, 704 MB docx, and real archives
including one holding a `.doc`).

The cause is ordinary on a Windows disk: a window that opens part-way inside a
real archive — an installer payload, a nested zip — walks genuine member headers,
never reaches that archive's directory, and gets clamped at the cap. The bytes
are a fragment of an archive rather than an archive.

```sh
bcrumb-rs disk.E01 -t office -o out                  # fragments are skipped
bcrumb-rs disk.E01 -t office -o out --zip-partial    # ...and kept, unvalidated
```

An archive that lost only its final record still comes back: a parsed central
directory is enough, and it is reported unvalidated. On a synthetic image of the
failing shape, the default writes nothing where the old behaviour wrote 36 MB
from a 3.8 MB image.

## Is the carved file intact?

A handler agrees the structure is well formed. That is not the same as the file
being whole: a fragmented file carved as consecutive bytes can keep its header
and its trailer and still hold somebody else's data in the middle. Only a decode
catches it.

```sh
bcrumb-rs disk.dd -t office,jpg -o out --validate       # report it
bcrumb-rs disk.dd -t office,jpg -o out --drop-failed    # and keep only what decodes
```

`--validate` decodes each carved file of a type it can check and reports
`verified` or `failed` in the CSV, the manifest and the HTML report — a column
of its own, so "not checked" stays distinguishable from "checked and failed".
`--drop-failed` implies `--validate` and does not write the failures at all.

| type | what is actually checked |
| --- | --- |
| PNG | CRC of every chunk, IDAT inflated, tightened to the end of IEND |
| ZIP, docx, xlsx, pptx, jar, apk, epub, odf | every member decompressed and CRC-checked against the central directory |
| gzip | full inflate; the format's own length and CRC are verified by the decoder |
| SQLite | header geometry against the length of the carve |
| JPEG | marker walk and terminator — JPEG carries no checksum, so a pass here is not proof the image renders |
| GIF, BMP | trailer and declared size |

Validation also tightens a carve that over-read: a PNG followed by unrelated
bytes comes back cut at IEND, and a SQLite database at its last page.

## Searching, custom formats, later reports

**Search** takes a keyword or a pattern:

```sh
bcrumb-rs disk.E01 --grep secret-project --max-hits 50      # ASCII + UTF-16LE
bcrumb-rs disk.E01 --regex --grep "[0-9]{4}([ -]?[0-9]{4}){3}"
```

A literal is searched in both Latin-1 and UTF-16LE, because Windows artefacts
store text either way. A regex is matched against the bytes as they are. A
pattern that will not compile is an error, not zero hits — silently finding
nothing looks like an absence of evidence.

**A format the tool does not know** needs a magic and, ideally, an end marker:

```json
[
  {"name": "widget", "ext": "wdg", "magic": "57494447",
   "footer": "454e4457", "max_size": "1M"},
  {"name": "blob", "magic": ["0xCAFEBABE", "DEADBEEF"], "max_size": 4096}
]
```

```sh
bcrumb-rs disk.dd --sig-file mysigs.json -o out          # alongside the built-ins
bcrumb-rs disk.dd --sig-file mysigs.json --only-custom   # instead of them
```

With a footer the carve ends after the first match and counts as validated;
without one it runs to `max_size` and is reported unvalidated, because nothing
in the data says where the file ends. `"footer_optional": true` allows the
fallback when the marker is missing.

**Reports later, without the image**: the manifest is the record, so a case can
be reported in a different shape long after the evidence is detached.

```sh
bcrumb-rs --from-manifest out/manifest.json --html report.html --csv files.csv
```

## Not implemented

Named so an examination is not planned around something that is not here:

- **ext4 journal replay** — where a freed inode's extent tree has been cleared,
  the journal may still hold the pre-delete inode. `--ext4` reports how many
  files are in that state; it does not replay the journal to get them back
- **VHD/VHDX, Ex01/EWF2, L01, AFF.** Raw images, block devices, EWF
  (`.E01`/`.s01`) sets, QCOW2, sparse VMDK, split raw and stdin are all read
  here; what is left is refused outright, by magic and by extension, because
  carving a container as raw reports fragments of its own compressed chunk data
  as recovered files with nothing to signal the mistake

  ```
  $ bcrumb-rs disk.vhdx -o out
  bcrumb-rs: disk.vhdx: this is a VHDX image, which this tool cannot read --
  carving it as raw would report the container's own bytes as recovered files.
  Convert it to raw first, for example with: qemu-img convert -O raw <in> <out.dd>
  ```
- **Bifragment reassembly** — the gap-carving search for a file split into
  two pieces with unrelated data between them

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

Every parser here reads structures off a disk of unknown provenance -- carving
handlers, the filesystem readers, the EWF and BitLocker code, the deletion
artefacts. Sizes, offsets and counts are all attacker-controlled in practice.
Two layers cover that:

- `tests/fuzz_smoke.rs` runs on stable in ordinary CI. Valid files are mutated —
  bytes flipped, length fields made absurd, tails truncated, files spliced onto
  themselves — and every handler runs over the result. Mutated *volumes* go
  through the undelete modes the same way, with a further check that a dry run
  writes nothing at all. A parser may reject anything, but it must not panic,
  must not take seconds on a few KB, and must never report a carve reaching past
  its window.
- `fuzz/` holds cargo-fuzz targets (`handlers`, `ewf`, `fve`, `artifacts`,
  `filesystems`) for longer campaigns, built in CI and run for a minute each.
- `tests/fixtures/fuzz_crashes/` keeps the inputs that crashed a target once, so
  a fixed crash stays fixed even when a short campaign would not rediscover it.

The invariant is also enforced centrally in the scan engine: a carve larger than
its window is rejected, so one arithmetic slip in one of 28 parsers cannot write
unrelated disk into evidence. The first run of the mutation fuzz found exactly
that — a corrupted PNG chunk length yielding 16 KB from an 80-byte window.

Fuzzing has paid for itself four times so far: that PNG over-read, an overflow
in the VMDK grain-table geometry, a 185-byte EWF file whose section chain pointed
in a cycle, and a 149-byte QCOW2 header declaring sixteen exabytes of virtual
size — which had a handler searching a 1.6×10¹⁹-byte window. The last two were
hangs rather than crashes: a tool that stops responding on a corrupt image, with
no output and no explanation. All four inputs are in the regression corpus, which
now also bounds how long each one may take.

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

## Knowing what a scan is doing

A carve of a real disk runs for hours, so it says where it is:

```
  42.1 GiB of 100.5 GiB (41.9%) · 12.3 MiB/s · 1,204 file(s), 5.7 GiB · ETA 1h22m
```

Every few seconds, rewriting one line on a terminal and appending a line when
piped to a log. `--machine` emits the same as JSON `progress` events, `-q`
silences it, and a scan shorter than three seconds says nothing.

Two things make that record durable rather than just decorative:

- **`carved.jsonl`** beside the output gets one line per file as each range
  completes, flushed. A manifest is only written when a scan *ends*; two killed
  runs on a real examination left 165 GB of carved files with no record of what
  any of them were.
- **Ranges are checkpointed as each finishes**, not when the slowest of a batch
  does. The same two runs had recorded nothing resumable after sixteen hours.

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
