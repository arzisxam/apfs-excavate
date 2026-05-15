# apfs-excavate — User Guide

This guide covers every option, the output structure, and advanced usage scenarios.
For a quick start, see the [README](../README.md).

---

## Contents

- [Usage](#usage)
- [Options reference](#options-reference)
- [Output structure](#output-structure)
- [Examples](#examples)
- [Resuming an interrupted run](#resuming-an-interrupted-run)
- [Re-running extraction without re-scanning](#re-running-extraction-without-re-scanning)
- [Building from source](#building-from-source)
- [Running on Linux](#running-on-linux)
- [Related documentation](#related-documentation)

---

## Usage

```
apfs-excavate <image.dmg|.img|.raw> [output_dir] [options]
```

The `./apfs-excavate` wrapper script at the project root builds the binary automatically and passes all arguments through — you never need to compile manually.

If `output_dir` is omitted, a folder named `<image>_recovered` is created next to the image.

---

## Options reference

### Main options

| Option | Description |
|--------|-------------|
| `--password PWD` | Password for an encrypted APFS volume (FileVault / APFS encryption). The password is used to derive the Volume Encryption Key via PBKDF2 from the keybag stored in the container. **Note:** The password is kept in memory only and is never saved or logged anywhere. |
| `--workers N` | Number of parallel scan threads (1–64, default 1). **SSD only** — on HDDs, multiple workers cause random seek overhead that makes the scan significantly slower. |
| `--no-resume` | Ignore any existing scan checkpoint and start completely fresh. |
| `--scan-only` | Scan and resolve paths, save a checkpoint, then exit without extracting any files. Useful for pre-scanning on one machine, then moving the checkpoint to another for extraction. |
| `--re-extract` | Re-run extraction from the existing scan checkpoint without re-scanning the image (saves hours on large images). Archives previous output first. Cannot be used with `--no-resume` or `--scan-only`. |
| `--deleted` | Also scan for deleted file fragments using a heuristic inode search. Slower and produces lower-confidence results; off by default. Recovered fragments go to `recovered_deleted/`. |
| `--debug` | Write verbose diagnostic output to `logs/debug_<timestamp>.log`. Does not print to the terminal. |

### File filters

| Option | Description |
|--------|-------------|
| `--filter-ext EXTS` | Only recover files whose extension matches the comma-separated list. Case-insensitive; leading dot optional. Example: `jpg,pdf,mov`. Orphaned files (no resolved path) are skipped when this filter is active. |
| `--pilot FILTER` | Only extract files whose resolved path contains FILTER. Useful for targeting one directory (e.g. `--pilot Documents`). Orphaned files are skipped in pilot mode. |
| `--max-size N` | Skip files larger than N. Accepts human-readable suffixes: `500MB`, `1.5GB`, `2TB`. **Default: 50 GB.** The default cap prevents runaway extraction of "ghost" files created by corrupted extent metadata. Raise this only if you have legitimate files larger than 50 GB. |
| `--min-size N` | Skip files smaller than N. Useful for filtering zero-byte stubs and tiny lock/temp files. Accepts the same suffixes as `--max-size`. |

### Advanced options

These are rarely needed. Only use them if a normal run produces wrong results.

| Option | Description |
|--------|-------------|
| `-b`, `--block LBA` | Force the container superblock location to LBA (512-byte sectors). Use when the image has multiple APFS containers and auto-detection picks the wrong one. See [tools/find_superblock.py](tools.md#find_superblocky) to discover the right value. |
| `--min-xid XID` | Ignore B-tree nodes whose transaction ID (XID) is lower than XID. Higher XID = more recent. Use this to filter out stale nodes from old filesystem states when a normal run produces phantom or duplicate files. See [tools/find_min_xid.py](tools.md#find_min_xidpy) to find a good value. |
| `--case-sensitive` | Override case-sensitivity detection. Normally auto-detected from the volume superblock. Use only if the superblock is too damaged to read and you know the volume was formatted as case-sensitive. |
| `--skip-metadata` | Skip all metadata restoration (timestamps, permissions, ownership, BSD flags). Use when restored metadata causes issues — for example, Finder showing greyed-out folders, files appearing read-only, or recovering to a partially POSIX-compatible volume such as ExFAT. |
| `--no-compression` | Extract compressed files as raw compressed data instead of decompressing. Output will be unreadable. For debugging decompression failures only. |

---

## Output structure

```
output_dir/
├── recovered_files/          Your files — original folder structure preserved
│   ├── Users/
│   │   └── alice/
│   │       ├── Documents/
│   │       └── Pictures/
│   └── ...
├── recovered_orphans/        Files found without a path (renamed by type after post-processing)
├── recovered_unknown_format/ Orphans that could not be identified or decoded
├── recovered_deleted/        Raw deleted fragments (--deleted only)
├── file_list.md              Every recoverable file with size and path
├── recovery_summary.md       Run statistics: counts, rate, timing; possibly-truncated + collision tables
├── unrecovered_files.md      Files found in metadata but not extracted
└── logs/
    ├── execution.log         Full timestamped run log
    ├── error.log             Errors and warnings
    ├── scan_results.bin      Scan checkpoint — inode table, directory records, paths
    ├── extracted_ids.bin     Extraction checkpoint — cumulative stats + set of processed IDs
    ├── pt_collisions.bin     Possibly-truncated and path-collision history (across re-runs)
    ├── deleted_done.flag     Marks deleted-recovery phase complete (skipped on resume)
    ├── skipped_files.md      Files excluded by --max-size / --min-size (when any)
    ├── execution_<ts>.log    Prior run logs (automatically archived)
    ├── error_<ts>.log        Prior error logs (automatically archived)
    └── debug_<ts>.log        Verbose diagnostics (only when --debug)
```

**recovered_files/** — full directory tree is reconstructed from B-tree directory records. Files land in their original paths exactly as they existed on the volume. Original file and directory metadata (creation time, modification time, permissions, and owner) are fully restored. Symbolic links are also recreated as actual shortcuts.

**recovered_orphans/** — files whose inode was found but whose path could not be resolved (common after corruption). After extraction, these `.dat` blobs are inspected: APFS compression headers are detected and decompressed; content is classified by magic bytes (JPEG, PNG, PDF, MP4, HEIC, ZIP, and 40+ other formats) and renamed with the correct extension. Files that cannot be identified land in `recovered_unknown_format/`. *Note: Many files here may be macOS system files (like Spotlight search indexes, cache files, or background daemon logs) rather than your personal data.*

**Log rotation** — at the start of each run, the previous `execution.log`, `error.log`, `recovery_summary.md`, and `unrecovered_files.md` are archived to timestamped copies in `logs/`, so no historical data is overwritten.

---

## Examples

```bash
# Basic recovery — output goes to out/
./apfs-excavate damaged.dmg out/

# Encrypted volume
./apfs-excavate encrypted.dmg out/ --password "my passphrase"

# See what's recoverable before extracting (no files written)
./apfs-excavate damaged.dmg out/ --scan-only

# Re-run extraction after a failed run without re-scanning (saves hours)
./apfs-excavate damaged.dmg out/ --re-extract

# Recover only photos and documents
./apfs-excavate damaged.dmg out/ --filter-ext jpg,jpeg,png,heic,pdf,docx,xlsx

# Skip files under 1 KB and over 10 GB (focus on real user data)
./apfs-excavate damaged.dmg out/ --min-size 1KB --max-size 10GB

# Target a specific directory (fast when you know where the data was)
./apfs-excavate damaged.dmg out/ --pilot "Documents/Projects"

# Recover videos and images, 4 threads (SSD only)
./apfs-excavate damaged.dmg out/ --filter-ext mp4,mov,jpg,png --workers 4

# Also scan for deleted file fragments
./apfs-excavate damaged.dmg out/ --deleted

# Force a known superblock location (multiple containers / wrong auto-detect)
./apfs-excavate damaged.dmg out/ --block 409640

# Filter out stale B-tree nodes from old filesystem states
./apfs-excavate damaged.dmg out/ --min-xid 4800000

# Debug a failed or incomplete run
./apfs-excavate damaged.dmg out/ --no-resume --debug
cat out/logs/debug_*.log
```

---

## Resuming an interrupted run

If a run is interrupted (Ctrl-C, power loss, disk full), the scan checkpoint is automatically saved. Just run the same command again — the scan phase is skipped and extraction resumes from where it stopped:

```bash
# First run — interrupted
./apfs-excavate damaged.dmg out/

# Resume — scan is skipped, extraction continues
./apfs-excavate damaged.dmg out/
```

To start completely fresh instead:
```bash
./apfs-excavate damaged.dmg out/ --no-resume
```

---

## Re-running extraction without re-scanning

If extraction completed but you want to run it again (e.g. you freed up disk space, or want to try different filters), use `--re-extract`. This skips the multi-hour scan phase and re-does only extraction:

```bash
./apfs-excavate damaged.dmg out/ --re-extract

# With different filters this time
./apfs-excavate damaged.dmg out/ --re-extract --filter-ext jpg,pdf
```

The previous output folders are automatically archived to `previous_extraction.<timestamp>/` before re-extraction begins.

---

## Building from source

The `./apfs-excavate` wrapper script handles this automatically. Manual build commands are listed here for reference (e.g. when modifying the source):

```bash
# Release build (optimised, -O3)
make

# Debug build (AddressSanitizer + UndefinedBehaviorSanitizer)
make debug

# Install to /usr/local/bin
make install

# Install to a custom prefix
make install PREFIX=$HOME/.local

# Run unit tests
make check

# Remove build artefacts
make clean
```

The binary is placed at `build/apfs-excavate`.

### Dependencies

| Dependency | macOS | Linux |
|------------|-------|-------|
| C11 compiler | Xcode CLT (`xcode-select --install`) | `gcc` or `clang` |
| OpenSSL (libcrypto) | `brew install openssl` | `apt install libssl-dev` |
| zlib | included with Xcode CLT | `apt install zlib1g-dev` |
| libcompression | included with macOS SDK | stubbed (LZFSE files skipped) |

---

## Running on Linux

All functionality is identical except LZFSE-compressed files — the macOS `libcompression` framework is not available on Linux, so those files will log a warning and be skipped. ZLIB and LZVN compressed files work normally.

```bash
apt install libssl-dev zlib1g-dev build-essential
make
./build/apfs-excavate damaged.img out/
```

---

## Related documentation

| Document | What's in it |
|---|---|
| [README](../README.md) | Quick start and common examples |
| [Tools](tools.md) | Helper scripts: `find_superblock.py`, `find_min_xid.py`, and orphan tools |
| [Terminal Output Reference](terminal-output-reference.md) | Sample output for every run scenario (full run, resume, Ctrl-C at each phase, scan-only) |
| [Execution Flow](execution-flow.md) | Detailed phase-by-phase walkthrough of what the tool does internally |
| [Architecture](architecture.md) | Module dependency graph, threading model, checkpoint format |
| [Encryption Pipeline](encryption.md) | AES-XTS key derivation, per-extent crypto states, known limitations |
| [Test Plan](testing.md) | How to prepare a test image and run the full validation suite |
