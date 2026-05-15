# Terminal Output Reference

Sample terminal output for every major run scenario.

Bar width varies with terminal width (shown here for a ~120-column terminal).  
Piped output (`| cat`) or `NO_COLOR=1`: all text is identical but with zero ANSI codes.

---

## 1. Full end-to-end run

Fresh run on an unencrypted 931 GB image. No prior checkpoint.

```
Command: apfs-excavate /Volumes/Backup/SSD_Dump.raw /Users/username/Desktop/recovered
```

```
apfs-excavate 1.0.0  —  Excavating your lost files
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Disk Image:    /Volumes/Backup/SSD_Dump.raw
Output Folder: /Users/username/Desktop/recovered


▶ Pre-flight checks
  ✓ Pre-flight passed


▶ Scanning disk image for files
  Scanning |████████████████████████████████████████████████████████████| 100.0%  931.5 GB  23,847/s  ETA 0s    
  ✓ Scanning completed in 2h 51m


▶ Resolving directory paths of the files
  ✓ Directory paths resolved in 0s

╔═════════════════════════════════╗
║  SCANNING COMPLETE — SUCCESS    ║
║                                 ║
║  Files found     :    620,823   ║
║  Est. size       :     ~723 GB  ║
╚═════════════════════════════════╝

List of files saved in /Users/username/Desktop/recovered/file_list.md


▶ Preparing for file extraction
  ✓ Preparation completed


▶ Extracting files
  Extracting |████████████████████████████| 100.0%  [610,102/610,102]  119/s  ETA 0s  
  ✓ Extraction completed in 1h 25m


▶ Restoring folder metadata
  ✓ Folder metadata restored for 48,302 folders


▶ Post-processing files
  Post-processing |████████████████████████████| 100.0%  [9,721/9,721]  249/s  ETA 0s  
  ✓ Post-processing completed in 39s


  Excavation completed in 4h 17m

╔═════════════════════════════════╗
║  RECOVERY COMPLETE — SUCCESS    ║
║                                 ║
║  Files found     :    620,302   ║
║  Files recovered :    610,099   ║
║  Files skipped   :          3   ║
║  Files failed    :         12   ║
╚═════════════════════════════════╝

Recovered files:
  → recovered_files/
  → recovered_orphans/
  → recovered_unknown_format/

Reports:
  → file_list.md
  → recovery_summary.md
  → unrecovered_files.md
```

**Count definitions:**
- Files found (scan box) = `count_scan_files()` — B-tree named files (deduped, excl. dirs) + orphan inodes with extents
- Files found (recovery box) = `g_cp_extract_stats.files_found` — set once on first run, read from checkpoint on subsequent runs
- Files recovered = total files successfully written to disk (named + orphan)
- Files skipped = files excluded by `--max-size` / `--min-size` / `--filter-ext` / `--pilot`
- Files failed = extraction attempts that errored (not counting skipped)
- Zero-byte files row shown when > 0 (named files with no recoverable data)
- `recovered_unknown_format/` line only shown when unidentifiable orphans exist

---

## 2. Extract-only run (scan already done)

Scan checkpoint exists from a prior run or `--scan-only`. Scanning and path resolution are
skipped entirely. Extraction starts immediately after pre-flight.

```
Command: apfs-excavate /Volumes/Backup/SSD_Dump.raw /Users/username/Desktop/recovered
```

```
apfs-excavate 1.0.0  —  Excavating your lost files
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Disk Image:    /Volumes/Backup/SSD_Dump.raw
Output Folder: /Users/username/Desktop/recovered


▶ Pre-flight checks
  ✓ Pre-flight passed (resumed from checkpoint)
  · Volume is not encrypted


▶ Preparing for file extraction
  ✓ Preparation completed


▶ Extracting files
  Extracting |████████████████████████████| 100.0%  [610,102/610,102]  119/s  ETA 0s  
  ✓ Extraction completed in 1h 25m


▶ Restoring folder metadata
  ✓ Folder metadata restored for 48,302 folders


▶ Post-processing files
  Post-processing |████████████████████████████| 100.0%  [9,721/9,721]  249/s  ETA 0s  
  ✓ Post-processing completed in 39s


  Excavation completed in 1h 26m

╔═════════════════════════════════╗
║  RECOVERY COMPLETE — SUCCESS    ║
║                                 ║
║  Files found     :    620,302   ║
║  Files recovered :    610,099   ║
║  Files skipped   :          3   ║
║  Files failed    :         12   ║
╚═════════════════════════════════╝

Recovered files:
  → recovered_files/
  → recovered_orphans/
  → recovered_unknown_format/

Reports:
  → file_list.md
  → recovery_summary.md
  → unrecovered_files.md
```

**Notes:**
- Phases 2 (Scanning) and 3 (Resolving paths) are entirely absent from terminal output
- No scan summary box shown on a resumed run (scan already completed in a prior session)
- The encryption check, partition detection, and volume feature detection are all skipped
- If some files were extracted in a previous partial run, the bar starts at the partial count
  and `extracted_ids.bin` ensures already-extracted files are not overwritten

---

## 3. --re-extract run

Archives prior output, then re-runs extraction from the existing scan checkpoint without re-scanning.

```
Command: apfs-excavate /Volumes/Backup/SSD_Dump.raw /Users/username/Desktop/recovered --re-extract
```

```
apfs-excavate 1.0.0  —  Excavating your lost files
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Disk Image:    /Volumes/Backup/SSD_Dump.raw
Output Folder: /Users/username/Desktop/recovered


▶ Pre-flight checks
  ✓ Pre-flight passed (resumed from checkpoint)
  · Volume is not encrypted


▶ Preparing for file extraction
  ✓ Preparation completed


▶ Extracting files
  Extracting |████████████████████████████| 100.0%  [610,102/610,102]  119/s  ETA 0s  
  ✓ Extraction completed in 1h 25m


▶ Restoring folder metadata
  ✓ Folder metadata restored for 48,302 folders


▶ Post-processing files
  Post-processing |████████████████████████████| 100.0%  [9,721/9,721]  249/s  ETA 0s  
  ✓ Post-processing completed in 39s


  Excavation completed in 1h 26m

╔═════════════════════════════════╗
║  RECOVERY COMPLETE — SUCCESS    ║
║                                 ║
║  Files found     :    620,302   ║
║  Files recovered :    610,099   ║
║  Files skipped   :          3   ║
║  Files failed    :         12   ║
╚═════════════════════════════════╝

Recovered files:
  → recovered_files/
  → recovered_orphans/
  → recovered_unknown_format/

Reports:
  → file_list.md
  → recovery_summary.md
  → unrecovered_files.md
```

**Notes:**
- Prior `recovered_files/`, `recovered_orphans/`, `recovered_unknown_format/`, `recovered_deleted/` are
  renamed to `previous_extraction.<timestamp>/` before extraction starts
- `extracted_ids.bin`, `deleted_done.flag`, and `pt_collisions.bin` are deleted (fresh history)
- Scan phases are skipped — `scan_results.bin` is reused
- If interrupted, the resume hint changes to: "Run the same command (without --re-extract) to resume"

---

## 4. Scan-only run

Scans and builds paths, writes `file_list.md`, then exits without extracting.

```
Command: apfs-excavate /Volumes/Backup/SSD_Dump.raw /Users/username/Desktop/recovered --scan-only
```

```
apfs-excavate 1.0.0  —  Excavating your lost files
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Disk Image:    /Volumes/Backup/SSD_Dump.raw
Output Folder: /Users/username/Desktop/recovered


▶ Pre-flight checks
  ✓ Pre-flight passed


▶ Scanning disk image for files
  Scanning |████████████████████████████████████████████████████████████| 100.0%  931.5 GB  23,847/s  ETA 0s    
  ✓ Scanning completed in 2h 51m


▶ Resolving directory paths of the files
  ✓ Directory paths resolved in 0s

╔═════════════════════════════════╗
║  SCANNING COMPLETE — SUCCESS    ║
║                                 ║
║  Files found     :    620,823   ║
║  Est. size       :     ~723 GB  ║
╚═════════════════════════════════╝

List of files saved in /Users/username/Desktop/recovered/file_list.md

To extract all the files, run the same command without --scan-only
```

**Notes:**
- No extraction, no post-processing, no reports written (beyond `file_list.md`)
- "Files found" = all named drec files + all orphan inodes (before post-processing)
- The scan checkpoint (`scan_results.bin`) is saved; next run starts directly at extraction

---

## 5. Run with --deleted (deleted fragment recovery)

Run on the same image as scenario 1, additionally scanning for deleted file fragments.

```
Command: apfs-excavate /Volumes/Backup/SSD_Dump.raw /Users/username/Desktop/recovered --deleted
```

The scan, path resolution, extraction, and folder-metadata phases are identical to scenario 1.
After extraction, two additional phases appear:

```
  ✓ Extraction completed in 1h 32m


▶ Restoring folder metadata
  ✓ Folder metadata restored for 48,302 folders


▶ Recovering deleted files
  ✓ Deleted files recovery completed in 4m 12s (2,847 fragments)


▶ Post-processing files
  Post-processing |████████████████████████████| 100.0%  [9,721/9,721]  249/s  ETA 0s  
  ✓ Post-processing completed in 39s


  Excavation completed in 4h 23m

╔══════════════════════════════════════╗
║  RECOVERY COMPLETE — SUCCESS         ║
║                                      ║
║  Files found     :      620,302      ║
║  Files recovered :      610,099      ║
║  Files skipped   :            3      ║
║  Files failed    :           12      ║
║  Deleted found   :        4,201      ║
║  Deleted recov.  :        2,847      ║
╚══════════════════════════════════════╝

Recovered files:
  → recovered_files/
  → recovered_orphans/
  → recovered_unknown_format/
  → recovered_deleted/

Reports:
  → file_list.md
  → recovery_summary.md
  → unrecovered_files.md
```

**Notes:**
- "Deleted found" = total heuristic inode candidates found during scan (`g_deleted_count`)
- "Deleted recov." = fragments actually written (may be lower if blocks were TRIM'd or overlap live files)
- `recovered_deleted/` only appears in the post-box when non-empty
- Post-processing renames `.raw` fragments to the correct extension where magic bytes are recognisable; encrypted-volume fragments have no magic → remain `.raw`
- The deleted phase is checkpointed (`deleted_done.flag`); resume runs skip it automatically

---

## 6. ExFAT / non-POSIX output drive warning

When the output directory is on an ExFAT, FAT32, or NTFS volume, a warning is printed
immediately after pre-flight (before scanning begins).

```
▶ Pre-flight checks
  ✓ Pre-flight passed
  ⚠  Output drive is exfat — file ownership, permissions, and
     timestamps cannot be restored on this filesystem.
```

**Notes:**
- Metadata restoration (`chmod`/`chown`/timestamps/BSD flags) is silently skipped for the whole run
- The warning appears in magenta in colour-capable terminals
- `--skip-metadata` suppresses metadata restoration on any filesystem (no warning printed — logged to `execution.log` only)

---

## 7. Possibly-truncated files warning

When one or more files have extent coverage significantly larger than their DSTREAM size
(and the extra data is not all-zero), a warning is printed after the summary box.

```
  Excavation completed in 4h 17m

╔═════════════════════════════════╗
║  RECOVERY COMPLETE — SUCCESS    ║
║ ...                             ║
╚═════════════════════════════════╝

Recovered files:
  → recovered_files/
  ...

  ⚠  3 file(s) may be truncated. Expanded versions saved as _EXPANDED.
     See recovery_summary.md → "Possibly Truncated Files".
```

**Notes:**
- The primary file is extracted at the DSTREAM size; the `_EXPANDED` copy adds the extra extent data
- If the extra data is entirely zero bytes, the `_EXPANDED` copy is discarded and does not trigger the warning
- The warning is magenta in colour-capable terminals
- The "Possibly Truncated Files" table in `recovery_summary.md` lists inode, DSTREAM size, extent coverage, status, and path for each candidate
- `pt_collisions.bin` persists these records so `recovery_summary.md` consolidates across re-runs

---

## 8. Ctrl-C during Scanning (Phase 2)

User presses Ctrl-C while the scan bar is at ~42%.

```
apfs-excavate 1.0.0  —  Excavating your lost files
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Disk Image:    /Volumes/Backup/SSD_Dump.raw
Output Folder: /Users/username/Desktop/recovered


▶ Pre-flight checks
  ✓ Pre-flight passed


▶ Scanning disk image for files
  Scanning |█████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░|  42.3%  394.0 GB  23,912/s  ETA 1h 53m    
  Scanning interrupted after 1h 3m
  Run again to continue. Run with --no-resume to restart the scan.
```

**What happens:**
- Worker threads detect `g_interrupted` and stop within the current block iteration
- A geometry-only checkpoint is saved silently (no terminal message)
- No summary box shown — the scan is incomplete
- Next run detects the incomplete checkpoint and rescans from block 0 automatically
- The scan cannot be resumed mid-way; a full rescan is always required after interruption
- `--no-resume` restarts from scratch, discarding the partial checkpoint

---

## 9. Ctrl-C during Resolving paths (Phase 3)

User presses Ctrl-C while path resolution is running. Path resolution is a tight in-memory
loop that finishes in under a second regardless — the interruption is detected only
*after* the phase completes. A complete checkpoint is saved. Extraction does not start.

```
apfs-excavate 1.0.0  —  Excavating your lost files
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Disk Image:    /Volumes/Backup/SSD_Dump.raw
Output Folder: /Users/username/Desktop/recovered


▶ Pre-flight checks
  ✓ Pre-flight passed


▶ Scanning disk image for files
  Scanning |████████████████████████████████████████████████████████████| 100.0%  931.5 GB  23,847/s  ETA 0s    
  ✓ Scanning completed in 2h 51m


▶ Resolving directory paths of the files
  ✓ Directory paths resolved in 0s

╔═════════════════════════════════╗
║  SCANNING COMPLETE — SUCCESS    ║
║                                 ║
║  Files found     :    620,823   ║
║  Est. size       :     ~723 GB  ║
╚═════════════════════════════════╝

List of files saved in /Users/username/Desktop/recovered/file_list.md

  Excavation interrupted after 2h 51m
  Run the same command again to resume Extraction.
```

**What happens:**
- Path resolution completes normally (it is too fast to interrupt mid-run)
- `g_interrupted` is checked immediately after the phase finishes
- A **complete** scan checkpoint is saved (`scan_results.bin` with `scan_complete=true`)
- Extraction never starts
- Next run sees the complete checkpoint and skips directly to extraction (Phase 4)

---

## 10. Ctrl-C during Extracting (Phase 4)

User presses Ctrl-C while extraction is at ~47% (287,000 files extracted).

```
apfs-excavate 1.0.0  —  Excavating your lost files
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Disk Image:    /Volumes/Backup/SSD_Dump.raw
Output Folder: /Users/username/Desktop/recovered


▶ Pre-flight checks
  ✓ Pre-flight passed (resumed from checkpoint)


▶ Preparing for file extraction
  ✓ Preparation completed


▶ Extracting files
  Extracting |█████████████░░░░░░░░░░░░░░░|  47.1%  [287,410/610,102]  118/s  ETA 2h 49m  
  Extraction interrupted after 40m

╔══════════════════════════════════════╗
║  RECOVERY INTERRUPTED — PARTIAL      ║
║                                      ║
║  Files found     :    620,302        ║
║  Files recovered :    287,410        ║
╚══════════════════════════════════════╝

Recovered files:
  → recovered_files/
  → recovered_orphans/

Reports:
  → file_list.md

  Excavation interrupted after 40m
  Run the same command again to resume Extraction.
```

**What happens:**
- The extraction loop breaks at the next work-item boundary (typically within a fraction of a second)
- `extracted_ids.bin` is saved with the IDs of all files written so far
- Orphan post-processing is **skipped entirely** — no Phase 6
- The interrupted box shows only Files found + Files recovered (skipped/failed/zero-byte omitted)
- Next run resumes from `extracted_ids.bin` and extracts only the remaining files

---

## 11. Ctrl-C during Post-processing (Phase 6)

User presses Ctrl-C while Phase 6 is at ~33% (3,214 of 9,721 orphans processed).
The already-processed orphans have already been renamed (`.dat` → `.jpg` / `.pdf` / etc.)
and any unidentifiable ones moved to `recovered_unknown_format/`.

```
apfs-excavate 1.0.0  —  Excavating your lost files
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Disk Image:    /Volumes/Backup/SSD_Dump.raw
Output Folder: /Users/username/Desktop/recovered


▶ Pre-flight checks
  ✓ Pre-flight passed (resumed from checkpoint)


▶ Preparing for file extraction
  ✓ Preparation completed


▶ Extracting files
  Extracting |████████████████████████████| 100.0%  [610,102/610,102]  119/s  ETA 0s  
  ✓ Extraction completed in 1h 25m


▶ Restoring folder metadata
  ✓ Folder metadata restored for 48,302 folders


▶ Post-processing files
  Post-processing |█████████░░░░░░░░░░░░░░░░░░░|  33.1%  [3,214/9,721]  249/s  ETA 26m  
  Post-processing interrupted after 13m

╔══════════════════════════════════════╗
║  RECOVERY INTERRUPTED — PARTIAL      ║
║                                      ║
║  Files found     :    620,302        ║
║  Files recovered :    610,099        ║
╚══════════════════════════════════════╝

Recovered files:
  → recovered_files/
  → recovered_orphans/
  → recovered_unknown_format/

Reports:
  → file_list.md

  Excavation interrupted after 1h 38m
  Run the same command again to resume Post-processing.
```

**What happens:**
- The post-processing loop checks `g_interrupted` at the start of each file and breaks
- The 3,214 already-processed orphans keep their new names — the rename is permanent
- The remaining 6,507 unprocessed orphans stay as `.dat` files in `recovered_orphans/`
- `recovered_unknown_format/` is shown because some unidentifiable files were already moved there
- **Resume is automatic** on next run: `orphan_post_process()` scans for `.dat` files only, so already-renamed files are skipped and only the remaining 6,507 are processed
- `extracted_ids.bin` still covers all 610,102 extracted files, so extraction is not repeated

---

## 12. All files already extracted (nothing to extract)

Every inode ID is already in `extracted_ids.bin` from a completed prior run.

```
Command: apfs-excavate /Volumes/Backup/SSD_Dump.raw /Users/username/Desktop/recovered
```

```
apfs-excavate 1.0.0  —  Excavating your lost files
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Disk Image:    /Volumes/Backup/SSD_Dump.raw
Output Folder: /Users/username/Desktop/recovered


▶ Pre-flight checks
  ✓ Pre-flight passed (resumed from checkpoint)
  · Volume is not encrypted


▶ Preparing for file extraction
  ✓ Preparation completed


  Nothing left to extract

▶ Restoring folder metadata
  ✓ Folder metadata restored for 48,302 folders

  Excavation completed in 3s

╔═════════════════════════════════╗
║  RECOVERY COMPLETE — SUCCESS    ║
║                                 ║
║  Files found     :     48,655   ║
║  Files recovered :     48,500   ║
║  Files skipped   :         20   ║
║  Files failed    :          0   ║
╚═════════════════════════════════╝

Recovered files:
  → recovered_files/
  → recovered_orphans/

Reports:
  → file_list.md
  → recovery_summary.md
  → unrecovered_files.md
```

**What happens:**
- Scan and path phases are skipped (scan checkpoint loaded)
- `extracted_ids.bin` covers all inodes — work count is zero
- "Nothing left to extract" is printed; extraction + orphan post-processing are skipped entirely
- Directory metadata (timestamps, permissions) is still restored
- Summary box shows full cumulative stats read from `extracted_ids.bin`
- Use `--re-extract` to force a fresh extraction pass

---

## Summary: Ctrl-C behavior by phase

| Phase | Detection | Bar shown | Checkpoint | What comes next |
|---|---|---|---|---|
| **Scanning** | Worker threads stop | Partial bar stays on screen | Geometry-only (incomplete) | No box — exits with duration message. Next run rescans from block 0. |
| **Resolving paths** | After phase completes | No bar (phase is too fast) | Complete scan checkpoint | Green scan box. Duration + resume message below box. Next run extracts directly. |
| **Extracting** | At next work-item boundary | Partial bar stays | `extracted_ids.bin` saved | Interrupted message + red partial box + paths. Resume message at end. Next run extracts remaining files. |
| **Post-processing** | At next file boundary | Partial bar stays | No new checkpoint needed | Interrupted message + red partial box + paths. Resume message at end. Next run resumes automatically (`.dat` files only). |
