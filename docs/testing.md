# apfs-excavate — Test Plan

This document describes how to set up a controlled test image and run a complete
validation suite against it.  A small USB pendrive (8–32 GB) formatted as APFS is
the easiest way to create a known-good image with full control over its contents.

---

## 1. Preparing the test image

### 1.1 Format and populate a pendrive

Use a small USB pendrive that you can dedicate to testing.  On macOS:

```bash
# Erase and reformat (choose one)
diskutil eraseDisk APFS            "TestAPFS"     /dev/diskN   # unencrypted
diskutil eraseDisk APFS            "TestAPFS"     /dev/diskN   # case-sensitive: use "APFS (Case-sensitive)"
diskutil eraseDisk "APFS Encrypted" "TestAPFS"    /dev/diskN   # encrypted (sets FileVault password)
```

Mount point will appear at `/Volumes/TestAPFS`.  Write the content tree described
in §1.2, then image the disk **before** ejecting or writing anything else.

### 1.2 Content tree to create

Create each of the following so the tool's major code paths are exercised.

| Directory / path | What to put there | Feature exercised |
|---|---|---|
| `photos/` | 4–6 JPEG files, 2–3 PNG files | Basic named-file extraction, image formats |
| `documents/` | PDF, TXT, CSV, Markdown, Python `.py`, C `.c` | Multi-format; small text files may be APFS-LZVN compressed transparently |
| `media/` | 2–3 MP3, 1 MP4 | Audio/video extraction |
| `archives/` | 1–2 ZIP, 1 EPUB | Container formats (ZIP magic check) |
| `deep_nesting/a/b/c/d/e/f/` | One small file at depth 6, one at depth 3 | Path reconstruction at depth |
| `Special Names/` | File with spaces, a unicode filename (e.g. `café_résumé.txt`), a filename with emoji | `sanitize_path()`, unicode handling |
| `hardlinks/` | Create one file, then `ln original.txt hardlink_a.txt hardlink_b.txt` | Hard-link dedup — 3 drec names → 1 extracted file |
| `symlinks/` | `ln -s ../photos/some.jpg link_to_photo.jpg`; `ln -s ../documents/readme.txt cross_dir.txt` | Symlink restoration (modern `com.apple.fs.symlink` xattr path) |
| `empty_files/` | `touch empty.txt empty.jpg empty.xlsx empty.mp3` | Named 0-byte file extraction with metadata restored |
| `old_timestamps/` | Copy files then set old mtimes: `touch -t 200501150000 ancient.txt` | Metadata restoration — timestamps on files and directories |
| `wrong_extensions/` | Rename a JPEG to `.txt`, a PNG to `.pdf`, a PNG to no extension, a ZIP to `.docx`, 2 genuinely unknown binary blobs | Magic-byte extension correction |
| `.Trash/` | Copy 2 files into `~/.Trash` while mounted | Trash folder recovery |
| *(delete some files)* | After writing all the above, delete 3–5 files from various directories | `--deleted` fragment recovery (SSD TRIM may already have reclaimed blocks) |

> **Tip:** After writing all content, run `du -sh /Volumes/TestAPFS` to confirm the
> total size is what you expect, then **immediately** image the disk before Spotlight,
> Time Machine, or other daemons can modify anything.

### 1.3 Image the disk

```bash
# Find the disk node (look for your pendrive by size)
diskutil list

# Unmount the volume but keep the disk node accessible
diskutil unmount /Volumes/TestAPFS

# Image the raw disk (adjust diskN to match your pendrive)
sudo dd if=/dev/rdiskN of=~/Desktop/test_apfs.raw bs=4m status=progress

# Sanity check — confirm GPT is present
python3 -c "
d = open('$(echo ~/Desktop/test_apfs.raw)', 'rb').read(1024*1024)
print('GPT found' if b'EFI PART' in d else 'WARNING: no GPT signature')
"
```

Keep the raw image as a stable artefact for repeatable test runs.

---

## 2. Test cases

In all commands below, replace `<image>` with the path to your raw image and
`<out>` with a fresh output directory.  For encrypted images also supply
`--password <password>`.

---

### Test 1 — Full run (all features)

```bash
./apfs-excavate <image> <out> [--password PWD] --workers 4 --deleted
```

**Pre-flight checks:**
- Encrypted: `✓ Volume key acquired` and `Case-sensitive: Yes/No` printed.
- Unencrypted: `✓ Pre-flight passed` with no crypto errors in `execution.log`.

**Verify each scenario after the run:**

```bash
OUT=<out>

# Hard-link dedup: multiple drec names → exactly 1 extracted file
grep -i "hardlink\|dedup" $OUT/logs/execution.log

# Symlinks restored as symlinks (not regular files)
ls -la $OUT/recovered_files/symlinks/
# Both entries must show 'l' in permissions

# Old timestamps preserved on files and directories
ls -la $OUT/recovered_files/old_timestamps/

# Magic-byte extension correction
ls $OUT/recovered_files/wrong_extensions/
# JPEG renamed to .jpg, PNG renamed to .png

# Empty files exist (0-byte, with original metadata)
ls -la $OUT/recovered_files/empty_files/

# Trash files recovered under .Trash/
ls $OUT/recovered_files/.Trash/ 2>/dev/null

# Deep path reconstructed
ls "$OUT/recovered_files/deep_nesting/a/b/c/d/e/f/"

# Unicode / space names intact
ls "$OUT/recovered_files/Special Names/"

# Deleted fragments (if TRIM hasn't wiped them)
ls $OUT/recovered_deleted/ 2>/dev/null && echo "deleted recovered" || echo "none (TRIM likely ran)"

# Summary counts: files_found = files_recovered + files_skipped + files_zero_byte
cat $OUT/recovery_summary.md

# Checkpoint: Remaining should be 0
python3 tools/inspect_checkpoint.py $OUT/logs/extracted_ids.bin
```

---

### Test 2 — Interrupt + resume (checkpoint)

```bash
# Start a run and interrupt it (Ctrl-C) roughly halfway through scanning
./apfs-excavate <image> <out2> [--password PWD] --workers 4
# ^C

# Resume — scan is skipped, extraction continues from last checkpoint
./apfs-excavate <image> <out2> [--password PWD] --workers 4
```

**Check:**
- "Resuming: N files already processed" message printed.
- Final counts in summary match Test 1.
- `inspect_checkpoint.py` shows Remaining: 0.

---

### Test 3 — `--scan-only` then resume

```bash
# Phase 1: scan only — writes scan_results.bin + file_list.md, then exits
./apfs-excavate <image> <out3> [--password PWD] --scan-only

ls <out3>/logs/scan_results.bin   # must exist
head -30 <out3>/file_list.md

# Phase 2: resume — scan skipped, extraction runs
./apfs-excavate <image> <out3> [--password PWD]
```

**Check:** Second run prints `✓ resumed from checkpoint`, no "Scanning blocks" step.

---

### Test 4 — `--filter-ext` selective extraction

```bash
./apfs-excavate <image> <out4> [--password PWD] --filter-ext jpg,png,mp3
```

**Check:** only matching extensions in `recovered_files/` — no PDF, TXT, MP4, etc.

```bash
find <out4>/recovered_files -type f | grep -v -iE "\.(jpg|jpeg|png|mp3)$"
# Should be empty
```

---

### Test 5 — `--re-extract` (force fresh extraction pass)

```bash
# Run on a completed output directory from Test 1
./apfs-excavate <image> <out> [--password PWD] --re-extract
```

**Check:** Prior output is archived (`previous_extraction.<timestamp>/`), fresh extraction runs, final counts match Test 1.

---

### Test 6 — `--pilot` (path-targeted extraction)

```bash
./apfs-excavate <image> <out5> [--password PWD] --pilot "documents"
```

**Check:** Only files under paths containing "documents" are extracted; other directories absent.

---

### Test 7 — `--min-size` / `--max-size` filters

```bash
./apfs-excavate <image> <out6> [--password PWD] --min-size 1KB --max-size 100MB
```

**Check:** `skipped_files.md` lists files outside the range; none appear in `recovered_files/`.

---

### Test 8 — `--skip-metadata`

```bash
./apfs-excavate <image> <out7> [--password PWD] --skip-metadata
```

**Check:** Recovered files have current extraction time as mtime (not original timestamps).  Permissions are default umask rather than APFS originals.

---

### Test 9 — `inspect_checkpoint.py` modes

```bash
OUT=<out>   # from Test 1

# Scan checkpoint summary
python3 tools/inspect_checkpoint.py $OUT/logs/scan_results.bin

# Extraction checkpoint summary
python3 tools/inspect_checkpoint.py $OUT/logs/extracted_ids.bin

# Dump all extracted inode IDs
python3 tools/inspect_checkpoint.py $OUT/logs/extracted_ids.bin --dump-ids /tmp/ids.txt
wc -l /tmp/ids.txt   # must match "IDs in checkpoint" from summary
```

---

### Test 10 — `--no-resume` (discard existing checkpoint)

```bash
# Run on an output dir with an existing checkpoint
./apfs-excavate <image> <out> [--password PWD] --no-resume
```

**Check:** Prior output moved to `previous_run.<timestamp>/`; full scan restarts from block 0.

---

### Test 11 — Orphan post-processing

Run against a **damaged** image (or any image with orphaned inodes whose paths can't
be resolved).  Orphan files land in `recovered_orphans/` as `.dat` blobs before
post-processing.

```bash
./apfs-excavate <damaged_image> <out8>
```

**Check after run:**
- `recovered_orphans/` contains renamed files with correct extensions (`.jpg`, `.pdf`, etc.).
- `recovered_unknown_format/` contains files that could not be identified.
- `recovery_summary.md` shows orphan counts.
- Python tool agrees with C classifier:
  ```bash
  python3 tools/identify_orphans.py <out8>/recovered_orphans/ --dry-run
  # Should report few or no further renames needed
  ```

---

### Test 12 — Possibly-truncated files and path collisions

Run against a damaged image where DSTREAM sizes may be corrupt (large image recommended).

```bash
./apfs-excavate <damaged_image> <out9>
```

**Check:**
- Any `_EXPANDED` copies in `recovered_files/` are noted in `recovery_summary.md` under "Possibly Truncated Files".
- Any `_COLLISION` renames appear in the "Path Collisions" table.
- On `--re-extract`, both tables consolidate across runs (loaded from `logs/pt_collisions.bin`).

---

### Test 13 — Deleted fragment recovery (`--deleted`)

```bash
./apfs-excavate <image> <out10> --deleted
```

**Check:**
- `recovered_deleted/` contains raw `.raw` blocks for deleted fragments.
- Post-processing renames those with recognisable magic bytes (`*.jpg`, `*.pdf`, etc.).
- Encrypted images: fragments remain `.raw` (no usable magic — expected).
- On resume: Phase 5 is skipped (flag file `logs/deleted_done.flag` exists).

---

### Test 14 — Multi-run summary consolidation

```bash
# Run 1: interrupted mid-extraction
./apfs-excavate <image> <out11> [--password PWD]
# ^C

# Run 2: resume to completion
./apfs-excavate <image> <out11> [--password PWD]
```

**Check:** `recovery_summary.md` "Path Collisions" and "Possibly Truncated Files" tables
include entries from *both* runs, not just the final one.

---

## 3. Unit tests

```bash
make check
```

Expected: **121/121** tests pass (12 LZVN + 16 AES-XTS + 67 orphan type + 26 checkpoint).

All tests are self-contained (no external files or network required) and run in < 5 seconds.

---

## 4. Expected count relationships

On a clean run with no I/O errors:

```
files_found = files_recovered + files_skipped + files_zero_byte
```

- **Scan box "Files found"** — all named drec files (deduped, excl. dirs) + orphan inodes with extents.  No size filter applied here.
- **Summary box "Files found"** — persisted in `extracted_ids.bin`; set once on first run, read from checkpoint on re-runs.
- Hard links count as **one** file (one inode, multiple drec names — deduped before extraction).
- Filtered-out files (by `--min-size`, `--max-size`, `--filter-ext`, `--pilot`) appear in **files_skipped** and in `logs/skipped_files.md`.

---

## 5. Known non-issues

| Observation | Explanation |
|---|---|
| `.DS_Store` checksum mismatch | macOS Finder modifies `.DS_Store` when you browse recovered dirs. Not a tool bug. |
| Hard links: only one copy extracted | Expected — one inode maps to one file; other names share the same content. |
| Deleted fragments from encrypted volume stay `.raw` | Encrypted blocks have no recognisable magic bytes. |
| Files with 1970s timestamps | Damaged inodes with near-zero POSIX timestamps. ExFAT output drives clamp these to 1980; APFS/HFS+ output drives show the real value. |
| LZFSE files skipped on Linux | `libcompression` is macOS-only; LZFSE-compressed files log a warning and are skipped. |
