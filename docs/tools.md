# apfs-excavate — Tools

Helper scripts in the `tools/` directory for diagnosing tricky images,
post-processing recovered files, and comparing outputs across runs.

Python scripts are standalone with no dependencies beyond the standard library.
No pip installs required.

---

## Contents

- [find_superblock.py](#find_superblocky) — find the right `--block` value
- [find_min_xid.py](#find_min_xidpy) — find the right `--min-xid` value
- [identify_orphans.py](#identify_orphanspy) — identify and rename orphan files
- [decompress_orphans.py](#decompress_orphanspy) — decompress APFS-compressed orphan blobs
- [inspect_checkpoint.py](#inspect_checkpointpy) — inspect scan and extraction checkpoint files
- [dir_stats.py](#dir_statspy) — snapshot per-file stats for a directory tree
- [snapshot_recovery.sh](#snapshot_recoverysh) — snapshot all `recovered_*` dirs and generate a SHA256 manifest

---

## find_superblock.py

**Use this to find the correct value for `--block`.**

apfs-excavate auto-detects the container superblock in most cases. You only need `--block` if:
- The image contains **multiple APFS containers** (e.g. Fusion Drive, dual-boot setup)
- Auto-detection picked a **stale checkpoint copy** instead of the current superblock
- The tool reports a wrong partition size or block count

This script scans the image for every NXSB (container superblock) magic occurrence, parses each one, and tells you exactly which `--block` value to use.

### Usage

```bash
python3 tools/find_superblock.py <image>
python3 tools/find_superblock.py <image> --verbose   # adds UUID and object IDs
```

### Example output

```
Image            : /Volumes/Media/SSD_dump.raw
Image size       : 931.32 GB (1,000,204,886,016 bytes)

Found 2 APFS container superblock(s):

  Candidate 1:  ← largest container (most likely the right one)
    --block value  : 409640
    Byte offset    : 209,735,680 (0xC800000)
    Block size     : 4096 bytes
    Container size : 930.51 GB (230,584,320 blocks)

  Candidate 2:  ← checkpoint/backup copy
    --block value  : 435
    Byte offset    : 222,720 (0x36600)
    Block size     : 4096 bytes
    Container size : 930.51 GB (230,584,320 blocks)

Multiple superblocks found — apfs-excavate may pick the wrong one.
  Recommended:  --block 409640
```

Then use:
```bash
./apfs-excavate image.raw out/ --block 409640
```

---

## find_min_xid.py

**Use this to find a sensible value for `--min-xid`.**

Every APFS B-tree node is stamped with a **Transaction ID (XID)** — a number that increases every time the filesystem makes a change. Higher XID = more recent write.

On a healthy image, all B-tree nodes have similar XIDs. On a damaged or fragmented image, old nodes from earlier filesystem states survive on disk with much lower XIDs — and apfs-excavate can pick them up, producing phantom files or duplicate entries from an older state of the drive.

`--min-xid` tells apfs-excavate to ignore any B-tree node whose XID is below your cut-off, keeping only the more recent state.

This script scans the image, collects XIDs from every B-tree node, and gives you a distribution histogram plus a concrete recommendation.

### Usage

```bash
# Full scan (may take a few minutes on large images)
python3 tools/find_min_xid.py <image>

# Quick sample — scan only the first 200,000 blocks
python3 tools/find_min_xid.py <image> --max-blocks 200000

# If you already know the block size
python3 tools/find_min_xid.py <image> --block-size 4096
```

### Example output

```
Image      : /Volumes/Media/SSD_dump.raw
Image size : 931.32 GB
Block size : 4096 bytes (auto-detected)
Blocks     : 227,124,736 total, scanning 227,124,736

Scanning... 100,000... 200,000... done.

B-tree nodes found : 1,842,301  (1,104,582 leaf, 12,847 root)
XID range          : 1,203  →  5,847,291

XID distribution (leaf node XIDs):
  XID range                         count  histogram
  ---------------------------------  -----  ----------------------------------------
      1,203 –     293,868           3,241  ████
    293,869 –     586,533           1,829  ██
    ...
  4,680,941 –   4,974,606         182,041  ████████████████████████████████████████
  4,974,607 –   5,268,272         401,832  ████████████████████████████████████████
  5,268,273 –   5,847,291         288,441  ████████████████████████████████████████

Percentiles (leaf XIDs):
  50th percentile (median) :        4,823,017
  75th percentile          :        5,201,884
  ...
  Maximum (most recent)    :        5,847,291

Recommendation:

  A significant XID gap was detected:
    Gap of 4,386,208 between XID 294,733 and 4,680,941
    1,102,314 nodes (99.8%) are above the gap

  To keep only the more recent state:
    --min-xid 4,680,941
```

Then use:
```bash
./apfs-excavate damaged.dmg out/ --min-xid 4680941
```

> **Note:** Start without `--min-xid` first. Only add it if a normal run produces clearly stale or duplicate files.

---

## identify_orphans.py

**Post-process `recovered_orphans/` to identify and rename files by type.**

> **You usually don't need this manually** — apfs-excavate runs this automatically as a post-processing step after extraction. Use this tool if you want to re-run identification on your own, or if you have orphans from a previous run.

Files in `recovered_orphans/` are often APFS-compressed blobs written without decompression (because no inode metadata was available at extraction time). This script:

1. Detects and decompresses LZVN/LZFSE/ZLIB APFS compression headers
2. Classifies the content by magic bytes, text patterns, and heuristics
3. Renames each `.dat` file with the correct extension (`.jpg`, `.pdf`, `.mp4`, …)

### Usage

```bash
# Dry run — show what would be renamed, but don't rename anything
python3 tools/identify_orphans.py <orphan_dir>

# Actually rename the files
python3 tools/identify_orphans.py <orphan_dir> --rename
```

### Supported formats

JPEG, PNG, GIF, PDF, ZIP (+ docx/xlsx/pptx sub-types), RAR, GZ, BZ2, XZ, 7z, DOC, SQLite, PLIST, Mach-O, ELF, WAV, AVI, WEBP, OGG, FLAC, MP3, MKV, MP4, MOV, HEIC, M4A, TTF, OTF, WOFF, TIFF, BMP, ICO, PSD, DMG, RTF, HTML, XML, JSON, Python, Shell, C#, Java, Swift, Objective-C, SQL, CSS, PEM, and more.

---

## decompress_orphans.py

**Decompress APFS-compressed orphan blobs without renaming them.**

A companion to `identify_orphans.py` — useful when you want to decompress the raw content but inspect it yourself before committing to a rename.

### Usage

```bash
# Decompress all .dat files in place
python3 tools/decompress_orphans.py <orphan_dir>

# Output decompressed files to a separate directory
python3 tools/decompress_orphans.py <orphan_dir> --output <output_dir>
```

---

## inspect_checkpoint.py

**Inspect and dump the contents of checkpoint files.**

apfs-excavate writes two binary checkpoint files to `output_dir/logs/`:

| File | Magic | Contains |
|------|-------|----------|
| `scan_results.bin` | `APFSCKPT` | Scan geometry, inode table, directory records, resolved paths, deleted fragments |
| `extracted_ids.bin` | `APFSDONE` | Cumulative extraction stats (files found/recovered/skipped/zero-byte) + set of already-processed inode IDs |

The script auto-detects the file type from the magic header — no type flag needed.

### Usage

```bash
# Summary view (default) — fast, safe for any file size
python3 tools/inspect_checkpoint.py out/logs/scan_results.bin
python3 tools/inspect_checkpoint.py out/logs/extracted_ids.bin

# Full dump to JSON (can be large for scan checkpoints — warns before writing)
python3 tools/inspect_checkpoint.py out/logs/scan_results.bin --dump scan_dump.json
python3 tools/inspect_checkpoint.py out/logs/extracted_ids.bin --dump ids_dump.json

# Dump just the inode ID list to a text file, one ID per line (extracted_ids.bin only)
python3 tools/inspect_checkpoint.py out/logs/extracted_ids.bin --dump-ids ids.txt
```

`--dump` and `--dump-ids` can be combined on `extracted_ids.bin`.

### Example output — scan_results.bin

```
Type     : Scan checkpoint  (APFSCKPT)
Version  : 5
Status   : Complete
File     : out/logs/scan_results.bin  (2.34 GB  (2,512,345,088 bytes))

Geometry:
  Partition offset : 0x0000000000000000  (0 bytes)
  Block size       : 4096 bytes
  Container offset : 0x0000000000000000  (0 bytes)
  Encryption       : No
  Case-sensitive   : No

Counts:
  Directory records : 1,234,567
  Inodes            : 987,654
  Resolved paths    : 901,234
  Deleted fragments : 0
```

### Example output — extracted_ids.bin

```
Type     : Extraction checkpoint  (APFSDONE)
Version  : 5
File     : out/logs/extracted_ids.bin  (390.62 KB  (400,000 bytes))

Extraction Stats  (cumulative across all runs):
  Files found       : 48,655
  Files recovered   : 48,500
  Files skipped     : 20  (size filter)
  Zero-byte files   : 135  (all extents out of range)
  Recovery rate     : 99.7%

Checkpoint:
  IDs in checkpoint : 48,655
  Status            : All files accounted for
```

### JSON dump schema

**scan_results.bin** → `{ magic, version, complete, geometry, counts, drecs[], inodes[], paths[], deleted[] }`

Each inode record includes all metadata fields (timestamps in ISO-8601/UTC, mode in octal, uid/gid, bsd_flags) plus its extents array and decmpfs data as hex.

**extracted_ids.bin** → `{ magic, version, stats{}, checkpoint_count, inode_ids[] }`

### --dump-ids text format

One decimal inode ID per line — useful for scripting:
```bash
# Compare two runs
comm -23 <(sort run1_ids.txt) <(sort run2_ids.txt)
```

---

## dir_stats.py

**Snapshot per-file statistics for a directory tree.**

Outputs one tab-separated record per entry, sorted by relative path.
Designed to be diffed between runs to identify added, removed, or changed files.

### Output columns

| Column | Description |
|--------|-------------|
| `SHA256` | Hex digest for regular files; `-` for dirs/symlinks (or with `--no-checksum`) |
| `TYPE` | `F`=file  `D`=directory  `L`=symlink  `O`=other |
| `PERM` | Octal permission bits, e.g. `755` |
| `OWNER` | Username (or UID if lookup fails) |
| `GROUP` | Group name (or GID if lookup fails) |
| `SIZE` | Bytes for regular files; `-` for dirs and symlinks |
| `MTIME` | Modification time (ISO-8601 UTC) — restored from APFS metadata, stable across runs |
| `PATH` | Relative path from the root; symlinks shown as `path -> target` |

SHA256 is the first column so the file can double as a checksum manifest:

```bash
awk '$1!="-"{print $1"  "$NF}' stats.txt | sha256sum -c
```

### Usage

```bash
python3 tools/dir_stats.py <directory>
python3 tools/dir_stats.py <directory> --label "recovered_files"
python3 tools/dir_stats.py <directory> --output run1_stats.txt
python3 tools/dir_stats.py <directory> --no-checksum        # skip SHA256, metadata only
python3 tools/dir_stats.py <directory> --workers 8          # parallel SHA256 (default: 2×CPU, max 16)
```

### Example output

```
# label:     recovered_files
# root:      /Volumes/SSD1TB/apfs-excavate_recovered7/recovered_files
# generated: 2026-04-29T14:22:10Z
# checksum:  sha256
# entries:   12,450  (files: 11,832, total size: 47,291,043,812 bytes)
# SHA256	TYPE	PERM	OWNER	GROUP	SIZE	MTIME	PATH
-	D	755	user	staff	-	2024-03-15T08:12:04	Documents
3f4a...	F	644	user	staff	102400	2024-01-10T16:33:21	Documents/report.pdf
-	L	777	user	staff	-	2024-03-15T09:01:00	Documents/shortcut -> ../Desktop/report.pdf
```

### Diffing two runs

```bash
diff run1/recovered_files_stats.txt run2/recovered_files_stats.txt
```

Lines with `+` are new or changed; lines with `-` are missing or changed.

---

## snapshot_recovery.sh

**Snapshot all `recovered_*` directories and generate a SHA256 manifest.**

Wrapper around `dir_stats.py` that handles an entire apfs-excavate output directory
in one shot. Does three things in order:

1. **Cleans macOS metadata noise** from every `recovered_*` directory (`.DS_Store` files
   and `._*` AppleDouble sidecars via `dot_clean`).
2. **Captures stats** for every `recovered_*` subdirectory via `dir_stats.py`, writing
   all sections into a single `recovered_files_stats.txt`.
3. **Generates a SHA256 manifest** (`recovered_files_manifest.sha256`) suitable for
   direct use with `sha256sum -c` or `shasum -a 256 -c`. Skipped with `--no-checksum`.

### Usage

```bash
tools/snapshot_recovery.sh <output_dir>
tools/snapshot_recovery.sh <output_dir> --no-checksum     # metadata only, much faster
tools/snapshot_recovery.sh <output_dir> --workers 8       # parallel SHA256 workers for dir_stats.py
```

### Output files

Both files are written into `<output_dir>`:

| File | Description |
|------|-------------|
| `recovered_files_stats.txt` | Full per-file stats for all `recovered_*` dirs, with section headers |
| `recovered_files_manifest.sha256` | `sha256sum`-compatible manifest (regular files only) |

### Validating a future run

After snapshotting run N, use the manifest to verify run N+1 produced identical content:

```bash
# macOS
cd /path/to/run_N+1_output
shasum -a 256 -c /path/to/run_N_output/recovered_files_manifest.sha256

# Linux
cd /path/to/run_N+1_output
sha256sum -c /path/to/run_N_output/recovered_files_manifest.sha256
```

Paths in the manifest are relative to the output directory (e.g. `recovered_files/Documents/report.pdf`),
so `sha256sum -c` must be run from the output directory of the run being validated.

### Example output

```
Found 4 recovered_* directories.

Cleaning macOS metadata files...
  recovered_files
  recovered_orphans
  recovered_unknown_format
  recovered_deleted

Snapshotting stats → /Volumes/SSD1TB/run7/recovered_files_stats.txt
Done: /Volumes/SSD1TB/run7/recovered_files_stats.txt

Generating SHA256 manifest → /Volumes/SSD1TB/run7/recovered_files_manifest.sha256
Done: /Volumes/SSD1TB/run7/recovered_files_manifest.sha256 (11832 files)
```
