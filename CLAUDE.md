# apfs-excavate — Claude Code context

## What this project is

A deep-recovery CLI tool for extracting files from damaged, corrupted, or
encrypted APFS disk images. Written in C11, targeting macOS (primary) and
Linux (LZFSE stubbed out on Linux).

Binary: `build/apfs-excavate`
Wrapper: `./apfs-excavate` (shell script — auto-builds if needed)

---

## Build commands

```bash
make              # release build → build/apfs-excavate  (-O3, -Wall -Wextra -Wpedantic)
make debug        # ASan + UBSan debug build → build/debug/apfs-excavate
make check        # run 112 unit tests (12 LZVN + 16 AES-XTS + 67 orphan-type + 17 checkpoint)
make clean        # remove build/
```

The build is clean with zero warnings (except pre-existing OpenSSL 3.x
deprecation warnings in `crypto.c` which are upstream issues).

---

## Module layout

```
include/            All headers (.h)
  compat.h          get_u16/32/64() — UB-free unaligned reads via memcpy
  version.h         TOOL_VERSION — single definition used by main.c and report.c
  apfs_types.h      Core structs: inode_t, drec_t, extent_t, result_t, ...
  apfs_globals.h    extern declarations for all g_* globals
  apfs_parse.h      APFS struct offset constants (APFS_BTNODE_*, APFS_INO_*)

src/
  globals.c         Definitions of all g_* globals
  term.c            Terminal detection: isatty, TIOCGWINSZ, NO_COLOR, g_term_color/width
  log.c             2-mode logger: stdout (no timestamp) + execution.log (timestamped)
  errors.c          Thread-safe error/warning collection
  util.c            Timing, size formatting, yellow progress bars, inode hash table
  crypto.c          AES-XTS, PBKDF2, RFC3394 key unwrap, keybag, VEK pipeline
  block_io.c        Raw + decrypted block reads
  compress.c        ZLIB, LZVN, LZFSE decompression
  checkpoint.c      Binary scan/extraction checkpoint save/load (CP_VERSION 5)
  apfs_parse.c      B-tree node parsing (drec, inode, extent, xattr, crypto state)
  scan.c            Multi-threaded block scanner + deleted inode heuristic
  recovery.c        Path resolution, file extraction, orphan handling
  report.c          Markdown report generation
  main.c            CLI parsing, partition detection, main pipeline, terminal UI

tests/
  test_lzvn.c       12 LZVN unit tests (hand-crafted opcodes)
  test_aes_xts.c    16 AES-XTS unit tests (cross-checked against OpenSSL EVP)
  test_orphan_type.c 67 orphan file-type classification tests (magic + text patterns)
  test_checkpoint.c  13 checkpoint round-trip and rejection tests

tools/
  identify_orphans.py   Standalone orphan identifier (dry-run + --rename)
  decompress_orphans.py Standalone orphan decompressor using libcompression

docs/
  architecture.md              Scan strategies, partition detection, extraction pipeline
  encryption.md                AES-XTS pipeline, keybag, PBKDF2, per-extent crypto states
  execution-flow.md            Phase-wise execution flow with inputs/outputs per phase
  terminal-output-reference.md All terminal flow scenarios
  user-guide.md                End-user guide
  tools.md                     Reference for tools/ scripts
```

---

## CLI

```
apfs-excavate <image> [output_dir] [options]

Options:
  --password PWD      Password for encrypted volumes
  --workers N         Scan threads (1–64, SSD only)
  --no-resume         Ignore existing checkpoints (archives prior run, restarts from scan)
  --deleted           Scan for deleted file fragments (off by default)
  --scan-only         Scan + build paths + save checkpoint + write file_list.md, then exit
  --re-extract        Clear extraction checkpoint + archive output folders, re-run extraction
  --max-size N        Skip files larger than N bytes (e.g. 500MB, 1.5GB). Default: 50GB cap
  --min-size N        Skip files smaller than N bytes
  --filter-ext EXTS   Only recover matching extensions (e.g. jpg,pdf,mov)
  --pilot FILTER      Only extract paths containing FILTER
  --skip-metadata     Skip all metadata restoration (timestamps, permissions,
                      ownership, BSD flags)
  --debug             Write diagnostics to debug_<timestamp>.log

Advanced:
  -b, --block LBA     Force superblock at LBA
  --min-xid XID       Skip B-tree nodes older than XID
  --case-sensitive    Override case-sensitivity (auto-detected from APSB)
  --no-compression    Extract raw compressed data (debugging only)
```

---

## Output directory layout

```
output_dir/
  recovery_summary.md
  unrecovered_files.md
  file_list.md
  recovered_unknown_format/
  logs/
    execution.log
    error.log
    scan_results.bin       ← CP_VERSION 5 checkpoint
    extracted_ids.bin
    pt_collisions.bin      ← possibly-truncated + collision history (persisted across re-runs)
    deleted_done.flag      ← marks deleted-recovery phase complete (skip on resume)
    skipped_files.md
    debug_<timestamp>.log  ← only when --debug
  recovered_files/         ← named files (full path tree)
  recovered_orphans/       ← files with no resolved path
  recovered_deleted/       ← --deleted only
```

---

## Key design decisions

- **Unaligned reads**: always use `get_u16/32/64(ptr)` from `include/compat.h` — never cast a pointer to `uint32_t *` etc. Violating this is undefined behaviour on all targets.
- **`g_block_size` not hardcoded**: use `g_block_size` everywhere; never write `4096` as a block-size literal. Sector factor is `g_block_size / 512` at runtime.
- **Thread safety**: all inode table mutations require `g_inode_mutex`. Acquire the lock before `get_or_create_inode_nolock()` and hold it across all field writes. Block reads and `malloc` happen before the lock.
- **Bool returns**: `bio_read_block`, `bio_read_decrypt`, `crypto_aes_xts_decrypt`, and `crypto_aes_xts_decrypt_with_sector_offset` return `bool`. Best-effort callers cast to `(void)`; callers that care check the return value.
- **Key material**: scrub with `OPENSSL_cleanse()` at every exit path. Never log VEK or salt even at DEBUG level.
- **`localtime_r`**: always use `localtime_r()` with a local `struct tm` — `localtime()` is not thread-safe.
- **`f_frsize` not `f_bsize`**: on APFS, `f_bsize` is 1 MB (I/O preference); `f_frsize` is 4 KB. Use `f_frsize` for free-space calculations.
- **Decimal units on macOS**: `util_format_size()` uses 1000-based SI units (KB/MB/GB/TB) on macOS to match Finder/Disk Utility. Linux uses IEC (KiB/MiB/GiB/TiB).
- **Checkpoint format**: `CP_SCAN_MAGIC` = "APFSCKPT", `CP_DONE_MAGIC` = "APFSDONE", `CP_VERSION` = 5. VEK is never stored in the checkpoint. V4 checkpoints still load (symlink_len treated as 0).
- **`TOOL_VERSION`**: defined once in `include/version.h`. Do not duplicate it.
- **No shell interpolation**: use `posix_spawn` (not `popen`/`system`) for any subprocess that takes user-derived input.
- **Orphan files in `recovered_unknown_format/`**: intentionally have no extension — prevents accidental opening by media players.
- **macOS-only code**: guard with `#ifdef __APPLE__`. LZFSE is stubbed on Linux.

---

## What not to re-implement

These are already present — do not add them again:

- Signal handler (Ctrl-C saves scan checkpoint)
- `--scan-only` / `--re-extract` / `--no-resume` modes
- HDD detection warning when `--workers > 1`
- APSB-based case-sensitivity auto-detection
- Free space check before extraction (inside `recovery_extract_files`)
- Log rotation (each run backs up previous logs with timestamps)
- Resume from checkpoint (scan/path-resolution skipped when `scan_results.bin` exists)
- ExFAT/non-POSIX output drive detection (`g_output_nonposix`)
- Orphan post-processing: decompress, identify 40+ file types, rename
- Always-on Markdown reports (`recovery_summary.md`, `unrecovered_files.md`, `file_list.md`)

---

## Adding a new unit test

Place a `tests/test_<name>.c` file and add it to `TEST_SRCS` in the `Makefile`.
The test binary is linked against all objects except `main.o` — all globals and
functions are available. Use the `check(cond, name)` pattern from the existing
tests. Run `make check` to verify.
