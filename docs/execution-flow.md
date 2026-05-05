# apfs-excavate — Phase-wise Execution Flow

Phase numbers are fixed and always the same regardless of whether the volume is
encrypted or not. Phases that do not apply to a given run are simply skipped and
noted as such.

---

## Startup — before Phase 0

**What happens:**
- Signal handlers installed (SIGINT / SIGTERM → set `g_interrupted`, save checkpoint, exit cleanly)
- CLI arguments parsed; globals (`g_workers`, `g_password`, `g_filter_exts`, etc.) set
- Global buffers allocated (`g_inodes`, `g_drecs`, `g_inode_hash`, `g_errors`, …)
- Output directory created (`mkdir output_dir`)
- On `--no-resume`: prior contents of `output_dir` archived to `previous_run.TIMESTAMP/` via O(1) `rename(2)` calls
- `output_dir/logs/` created
- Prior run's logs and `.md` reports renamed to timestamped copies so nothing is silently overwritten:
  - `execution.log` → `execution_TIMESTAMP.log`
  - `error.log` → `error_TIMESTAMP.log`
  - `recovery_summary.md` / `unrecovered_files.md` → moved into `logs/` with timestamp suffix
- `log_init()` opens fresh `execution.log` and (if `--debug`) `debug_TIMESTAMP.log`

**Inputs:** nothing (first run), or existing logs/checkpoints from a prior run  
**Outputs:** `output_dir/logs/execution.log` (created/opened), archived prior-run files

---

## Phase 0 — Pre-flight checks

**What happens:**

| Step | Detail |
|------|--------|
| Open image | `open(O_RDONLY)` + `fstat` to get file size |
| Memory-map image | `mmap(MAP_PRIVATE)` + `madvise(MADV_SEQUENTIAL)` for sequential read |
| APFS signature check | Search first 64 MB for `NXSB` (container superblock) and `APSB` (volume superblock) magic bytes. Warn if neither found — tool continues anyway. |
| Volume features | Scan for an APSB and read `apfs_incompatible_features` bit 0x8 to auto-detect case-sensitivity. CLI `--case-sensitive` overrides this. |
| Locate container | `find_partition()` — walks partition table (GPT/MBR/raw) to find the APFS container superblock. Reads `block_size`, `g_partition_offset`, `g_container_offset`. Advanced: `--block LBA` forces a specific superblock location. |
| Encryption check | `crypto_find_and_decrypt_keybag()` — scan image for a keybag blob. Sets `is_encrypted`. No key is derived yet; this is detection only. |

**Inputs:** raw image file  
**Outputs:** `execution.log` — step confirmations, signature status, case-sensitivity, encryption status

**Exit conditions:**
- Image cannot be opened or is empty → fatal error, exit
- Encrypted volume but no `--password` provided → fatal error, exit
- No APFS signature → warning logged, continues

---

## Phase 1 — Key derivation *(encrypted volumes only; skipped otherwise)*

**What happens:**
1. `crypto_find_volume_uuid()` — locates the volume UUID from the APSB superblock
2. `crypto_find_and_decrypt_keybag()` — re-reads the keybag blob
3. `crypto_parse_keybag()` — parses the RFC 3394 wrapped-key structure
4. `crypto_derive_vek_from_password()` — PBKDF2 key stretch → AES-XTS key unwrap → Volume Encryption Key (VEK) stored in `g_vek`

**Inputs:** image (mmap'd), `--password` CLI argument  
**Outputs:**
- `g_vek[32]` in memory (used for all subsequent block decryption)
- `execution.log` — "VEK derived successfully" (password is never logged)

**Exit conditions:** Wrong password or keybag parse failure → fatal error, exit

---

## Phase 2 — B-tree scan

**Resume check (scan-phase shortcut):**
- `cp_load_scan(output_dir)` reads `logs/scan_results.bin`
- If valid: restores `g_inodes`, `g_drecs`, `g_inode_hash`, `g_paths` — **Phase 2 and Phase 3 are both skipped**

**Inputs (resume):** `output_dir/logs/scan_results.bin`  
**Outputs (resume):** restored in-memory state; nothing new written to disk

**Scan (skipped if resumed):**

`scan_image(true)` — multi-threaded worker pool (controlled by `--workers`):
- Each worker reads 4 KB blocks from the image
- For each block: checks for valid APFS B-tree node magic, validates object type
- Extracts from valid nodes:
  - **Directory records** (`drec_t`) — filename + parent inode + child inode
  - **Inodes** (`inode_t`) — inode ID, file size, extent list, compression info (decmpfs xattr), is_dir flag
  - **Extents** — physical block ranges for file data
  - **Crypto states** — per-volume AES-XTS parameters (encrypted volumes)
  - **Deleted inodes** — heuristic-detected deleted file fragments (only if `--deleted`)
- `--min-xid` skips nodes older than the given transaction ID
- Ctrl-C during scan → `g_interrupted = 1` → scan stops, checkpoint saved, tool exits cleanly

**Inputs:** mmap'd image, optional `--min-xid`, optional `--deleted`  
**Outputs:**
- `g_inodes[]`, `g_drecs[]`, `g_deleted[]` arrays in memory
- `execution.log` — node/drec/inode/deleted counts, scan time

---

## Phase 3 — Path building *(skipped if scan checkpoint loaded)*

`recovery_build_paths(true)`:
1. `deduplicate_drecs()` — when the same inode appears in multiple B-tree leaves (common after corruption), prefer entries whose parent is a known directory
2. Walks `g_drecs` recursively up through parent-inode links to build full path strings
3. Result: `g_paths[inode_array_index]` = malloc'd absolute path string, or NULL (orphan)

After path building, the scan checkpoint is saved:
- `cp_save_scan(output_dir)` — serialises `g_inodes`, `g_drecs`, `g_paths` to binary

**Inputs:** `g_inodes[]`, `g_drecs[]`  
**Outputs:**
- `g_paths[]` array in memory
- `output_dir/logs/scan_results.bin`
- `output_dir/file_list.md` — full list of every recoverable file (named + orphans) with sizes. Written here so `--scan-only` users get it too.
- `execution.log` — resolved path count, build time

---

## `--scan-only` exit *(optional)*

If `--scan-only` was passed, the tool prints a brief summary (named file count, orphan
count, estimated total size, checkpoint path) and exits here without extracting anything.
`file_list.md` has already been written at the end of Phase 3.

**Inputs:** in-memory scan state  
**Outputs:** `output_dir/logs/scan_results.bin`, `output_dir/file_list.md` (both written in Phase 3), console summary

---

## Phase 4 — File extraction

`recovery_extract_files(files_dir, orphan_dir, output_dir, true, &comp_count)`:

**Setup:**
- Output subdirectories created: `recovered_files/`, `recovered_orphans/`
- If `--deleted`: `recovered_deleted/` created
- Disk space check: sum all inode sizes vs `statvfs(f_bavail * f_frsize)`; warn if insufficient (does not abort)
- `madvise(MADV_RANDOM)` — switches read pattern now that scan is done

**Resume logic:**
- `cp_load_extracted(output_dir)` reads `logs/extracted_ids.bin` → loads `extracted_ids[]` (set of already-extracted inode IDs) and restores `g_cp_extract_stats` (cumulative counts)
- Each inode is skipped if its ID is in `extracted_ids`; counter `g_previously_extracted_count` is incremented

**Nothing-left-to-extract shortcut:**
- If `work_count == 0` and `g_cp_extract_stats.files_found > 0` (all inodes already in checkpoint): prints "**Nothing left to extract**", skips extraction + orphan post-processing, applies directory metadata, then jumps directly to reports.  The summary box still shows full cumulative stats from the checkpoint.

**Per-file extraction loop:**
1. For each inode with extents: look up `g_paths[inode_idx]`
2. **Named file** (path exists): reconstruct directory tree under `recovered_files/`, open output file
3. **Orphan** (no path): write to `recovered_orphans/file_<inode>.dat`
4. **EISDIR collision** (directory exists at target path): redirect to `recovered_orphans/conflict_<inode>_<name>`
5. **Empty path**: redirect to `recovered_orphans/file_<inode>.dat`
6. **Trailing slash**: stripped before open
7. Read extents sequentially; decrypt each block if encrypted (`crypto_aes_xts_decrypt`)
8. Decompress if inode has decmpfs xattr (ZLIB / LZVN / LZFSE), unless `--no-compression`
9. 0-byte inodes (no extents or untrusted size): create empty file, checkpoint immediately, continue
10. Progress bar printed every 100 iterations; 10% milestones logged to `execution.log`
11. After each file: `extracted_ids[n++] = inode_array_index`; every 100 files → `cp_save_extracted()`

**Inputs:** `g_inodes[]`, `g_drecs[]`, `g_paths[]`, `logs/extracted_ids.bin` (if resuming)  
**Outputs:**
- `output_dir/recovered_files/` — full directory tree of named files
- `output_dir/recovered_orphans/` — files with no resolved path (raw blobs, `.dat` extension)
- `output_dir/logs/extracted_ids.bin` — updated every 100 files
- `execution.log` — per-file errors, 10% progress snapshots
- `output_dir/logs/error.log` — per-file write failures

---

## Phase 5 — Deleted file recovery *(optional; only with `--deleted`)*

Only runs if `--deleted` was passed and `g_deleted_count > 0`.

`recovery_extract_deleted(deleted_dir)`:
- Iterates `g_deleted[]` (heuristic-detected deleted inode fragments from scan)
- Attempts to read the raw extent data and write fragments to `recovered_deleted/`

**Inputs:** `g_deleted[]`, mmap'd image  
**Outputs:** `output_dir/recovered_deleted/` — raw file fragments

---

## Phase 6 — Orphan post-processing

`orphan_post_process(orphan_dir, output_dir, &result)`:

Processes every `.dat` file in `recovered_orphans/` in sequence:

1. **Read up to 256 KB** of the blob
2. **Decompress** (try in order):
   - `fpmc` header → standard APFS decmpfs xattr → detect type (3=ZLIB, 7/8=LZVN, 11/12=LZFSE) → decompress with `compression_decode_buffer` (macOS) or `inflate` (ZLIB)
   - Simplified blob header: `byte[0] ≤ 96` = stream offset → LZVN decode from that offset
   - Late-decompression fallback: if sliding-window classifies content but `decomp_buf` is NULL, attempt LZVN on the raw blob
   - If all fail: classify the raw blob bytes directly
3. **Identify file type** from the decompressed (or raw) bytes:
   - Binary magic bytes (40+ rules: JPEG, PNG, PDF, ZIP, MP4/MOV ftyp, RIFF/WAV, DOCX, …)
   - `ftyp` box sub-type refinement for MPEG-4 variants
   - UTF-16 LE detection for Windows-origin files
   - Case-insensitive text-pattern table (`<?xml`, `<!DOCTYPE`, `#!/`, `{`, …)
   - Plain-ASCII printability heuristic (>85% printable → `.txt`)
   - Sliding-window scan (for streams that start with a back-reference opcode)
4. **Rename** the `.dat` file to its identified extension in-place
5. **Unrecoverable**: if type cannot be determined → move to `output_dir/recovered_unknown_format/` (`.dat` extension stripped, no extension at all)

**Inputs:** `output_dir/recovered_orphans/*.dat`  
**Outputs:**
- `recovered_orphans/` files renamed with correct extensions
- `output_dir/recovered_unknown_format/` — blobs that could not be identified (no extension)
- `result.orphans_identified`, `result.orphans_unrecoverable` — counters used in summary

---

## Reports *(after Phase 6)*

| Report | Writer | Path |
|--------|--------|------|
| Recovery summary | `report_write_summary()` | `output_dir/recovery_summary.md` |
| Unrecovered files | `report_write_unrecovered()` | `output_dir/unrecovered_files.md` |
| Error log | `report_write_error_log()` | `output_dir/logs/error.log` |

Note: `file_list.md` is written at the end of Phase 3 (not here), so it is available
in both `--scan-only` and normal runs.

**Inputs:** `g_errors[]`, `g_unrecovered[]`, `result_t` struct  
**Outputs:** three Markdown/text files listed above

---

## File and checkpoint summary

```
output_dir/
  file_list.md                    ← every recoverable file — written after Phase 3
  recovery_summary.md             ← run statistics
  unrecovered_files.md            ← files that failed extraction
  recovered_unknown_format/      ← orphan blobs with no identifiable type
  logs/
    execution.log                 ← full timestamped run log
    error.log                     ← errors and warnings only
    debug_TIMESTAMP.log           ← --debug only
    scan_results.bin           ← scan + path state (resume Phases 2+3)
    extracted_ids.bin      ← cumulative stats + extracted inode IDs (resume Phase 4)
    execution_TIMESTAMP.log       ← prior run's log (rotated on re-run)
    recovery_summary_TIMESTAMP.md ← prior run's summary (rotated on re-run)
  recovered_files/                   ← named files with full directory tree
  recovered_orphans/              ← files without resolved paths (renamed by Phase 6)
  recovered_deleted/              ← --deleted only (Phase 5)
  previous_run.TIMESTAMP/         ← --no-resume: entire prior run archived here
```
