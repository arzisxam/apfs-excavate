# Architecture

## Overview

apfs-excavate is a single-pass recovery pipeline:

```
Image file (mmap)
      │
      ▼
Partition detection ──► sets g_partition_offset, g_block_size
      │
      ▼
Encryption setup ──────► derives VEK from password + keybag
      │
      ▼
Scan phase ─────────────► populates g_drecs[], g_inodes[], g_deleted[]
      │
      ▼
Path resolution ────────► populates g_paths[]
      │
      ▼
Extraction phase ───────► writes recovered_files/, recovered_orphans/
      │
      ▼
Deleted recovery ───────► writes recovered_deleted/  (--deleted only)
      │
      ▼
Reports ────────────────► recovery_summary.md, unrecovered_files.md, error.log
```

Each phase saves state that the next phase reads. The scan checkpoint makes the entire pipeline resumable — if interrupted after scanning, re-running picks up at the extraction phase without re-scanning.

---

## Module dependency graph

```
main.c
  ├── apfs_parse.h   (partition detection: apfs_is_valid_btree_node)
  ├── crypto.h       (keybag + VEK pipeline)
  ├── scan.h         (scan_image)
  ├── recovery.h     (build_paths, extract_files, extract_deleted)
  ├── checkpoint.h   (cp_load_scan, cp_save_scan)
  ├── report.h       (report_write_*)
  ├── util.h         (timing, formatting, progress)
  └── log.h          (LOG_NORMAL, LOG_DEBUG, LOG_ERROR)

scan.c
  ├── apfs_parse.h   (apfs_parse_btree_node, validity checks)
  └── block_io.h     (bio_read_block, bio_read_decrypt)

recovery.c
  ├── compress.h     (cmp_decompress_file)
  ├── crypto.h       (per-extent AES-XTS)
  ├── block_io.h     (bio_read_block, bio_read_decrypt)
  └── checkpoint.h   (cp_save_extracted, cp_load_extracted)

apfs_parse.c
  └── block_io.h     (bio_read_block — for keybag reads only)

crypto.c
  └── block_io.h     (bio_read_block — direct, avoids circular dep with bio_read_decrypt)
```

---

## Partition detection

`find_partition()` in `main.c` tries five strategies in order:

1. **Manual override** (`--block LBA`) — trusts the user; verifies NXSB magic at the given address.

2. **GPT** — reads the GUID Partition Table at LBA 1, scans entries for the APFS GUID (`EF577347-...`). Extracts `first_lba` and checks for NXSB magic. If the primary superblock is damaged, scans the first 20 blocks of the partition for a checkpoint copy.

3. **NXSB magic search** — `memmem` scan for the literal `"NXSB"` string. Up to 16 hits are collected. Three sub-strategies:
   - **A**: first hit is at the partition start (offset matches block boundary)
   - **B**: spacing analysis — back-calculates the partition start from two adjacent hits
   - **C**: try each hit as a potential partition start

4. **Checkpoint spacing inference** — when the NXSB primary is zeroed, attempts to locate it by back-calculating from a known checkpoint offset using common APFS checkpoint descriptor distances (435, 871, 1307, 1743 blocks).

5. **B-tree node scan** — scans the first 1,000 blocks for a valid B-tree node. If found, assumes common partition offsets (0, 20480, 40960 bytes). Last resort.

---

## Scan phase

### Threading model

`scan_image()` divides the image into `g_workers` equal block ranges and launches one `pthread` per range. Thread 0 owns the progress bar. All threads write to shared global arrays (`g_drecs`, `g_inodes`, `g_deleted`, `g_crypto_states`) protected by per-array mutexes.

### Parse strategies (per block)

For **encrypted** volumes, three strategies are tried in order (stopping at the first hit):

| Strategy | Read method | Validator |
|----------|------------|-----------|
| 1 | `bio_read_block` (plaintext) | `apfs_is_valid_btree_node` (strict checksum) |
| 2 | `bio_read_decrypt` (AES-XTS) | `apfs_is_valid_btree_node` (strict) |
| 3 | `bio_read_block` (plaintext) | `apfs_is_partial_btree_node` (lenient) |

Strategy 2 is only attempted when strategy 1 fails — decrypting a plaintext block produces garbage that can pass the lenient validator, so ordering matters.

For **unencrypted** volumes: strategy 1 (strict), then strategy 3 (lenient). No decryption attempt.

### Zero-block fast skip

Contiguous zeroed blocks are common in images from drives with head crash damage. The worker allocates a zero-reference block and uses `memcmp` to skip them in O(1).

### XID filtering

If `--min-xid` is set, leaf nodes whose transaction ID is below the threshold are skipped. This targets a specific filesystem state when multiple generations of B-tree fragments coexist in the image.

---

## Path resolution

`recovery_build_paths()` in `recovery.c`:

1. **Deduplication** — sorts `g_drecs[]` by `file_inode` and collapses duplicates, preferring entries whose parent inode has a known directory over those that don't.

2. **Reverse tree walk** — for each file drec, calls `resolve_path()` which recursively looks up the parent inode's directory record, building the path from root to leaf. A generation counter (incremented on each `resolve_path` call) replaces the visited[] array that would otherwise require O(n) clearing per call.

3. Resolved paths are stored in `g_paths[inode_array_index]` as malloc'd strings.

---

## Extraction phase

`recovery_extract_files()` in `recovery.c`:

1. **Work list construction** — one entry per file: named files from `g_drecs[]`, then orphans (inodes with extents but no path). Each entry records the first physical block address.

2. **Physical sort** — the work list is sorted by `first_phys` before extraction. This converts the access pattern from random inode-ordered I/O to approximately sequential physical I/O — critical for performance on both SSDs and HDDs.

3. **Head crash zone detection** — counts contiguous zeroed blocks from the partition start. Files whose extents fall entirely within the crash zone are skipped rather than extracted as zero-filled garbage.

4. **Per-file extraction**:
   - If compressed (`is_compressed` flag set): call `cmp_decompress_file()` which reads the decmpfs xattr and dispatches to ZLIB/LZVN/LZFSE
   - Otherwise: iterate extents, read each block via `bio_read_decrypt` (which applies per-extent AES-XTS if encryption is enabled), write to output file

5. **Magic-byte correction** — after writing, sniffs the first 4 bytes of the output to detect JPEG/PNG/PDF magic and corrects the file extension if the drec extension doesn't match.

6. **Incremental checkpoint** — calls `cp_save_extracted()` every 100 files, enabling extraction to resume from the last saved point.

---

## Checkpoint format

The binary scan checkpoint (`scan_results.bin`) stores:

```
[header: magic "APFSCKPT", version, counts]
[cp_inode_hdr_t × inode_count]        fixed-size per inode
[extent_t × extent_count]             variable per inode
[decmpfs_data bytes × decmpfs_len]    variable per inode
[drec_t × drec_count]
[deleted_file_t × deleted_count]
[crypto_state_t × crypto_state_count]
```

No pointers are stored — all variable-length data is laid out sequentially after its header. On load, `extents` and `decmpfs_data` pointers are re-allocated and populated from the flat layout.

The extraction checkpoint (`extracted_ids.bin`) stores a `cp_extract_stats_t` header (cumulative counts: files found, recovered, skipped, zero-byte) followed by a flat array of inode IDs for every file already written. The ID array is checked during work-list construction to skip already-extracted files; the stats are used to populate the summary box and reports on re-runs.
