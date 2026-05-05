# ROADMAP

Planned and proposed enhancements for apfs-excavate, organised by theme and rough priority.
Items are not commitments — they reflect known gaps and community-requested features.

---

## Contents

- [Tier 1 — High value, straightforward](#tier-1--high-value-straightforward)
  - 1.6: Possible-truncation detection and `--expand-extents` flag *(new, Session 36)*
- [Tier 2 — High value, moderate effort](#tier-2--high-value-moderate-effort)
- [Tier 3 — Significant effort, power-user value](#tier-3--significant-effort-power-user-value)
- [Tier 4 — Research / exploratory](#tier-4--research--exploratory)

---

## Tier 1 — High value, straightforward

### ~~1.1 Restore file metadata on extraction~~ [DONE]

*(Implemented in v1.0)*
Currently all extracted files are written with the extraction timestamp and the running user's permissions. The original metadata is present in the inode record but not applied.

**What to restore:**

| Attribute | APFS source | Restore API |
|---|---|---|
| Modification time | `mod_time` (ns since epoch) | `utimensat()` — macOS + Linux |
| Access time | `access_time` | `utimensat()` |
| Creation (birth) time | `create_time` | `setattrlist(ATTR_CMN_CRTIME)` — macOS only |
| inode change time | `change_time` | read-only on most FSes; log only |
| Permissions | `mode` (already stored in `inode_t`) | `chmod()` |
| Hidden / immutable flags | `bsd_flags` | `chflags()` — macOS; `ioctl FS_IOC_SETFLAGS` — Linux |

**Implementation notes:**
- Add `create_time`, `mod_time`, `access_time`, `uid`, `gid`, `bsd_flags` to `inode_t`
- Parse them from the inode xfields during B-tree scan
- Apply after writing each file with a `restore_metadata()` helper
- Add `--no-metadata` flag to skip this for speed (the current behaviour)
- UID/GID restoration requires root; fall back gracefully if `EPERM`

---

### ~~1.2 Restore symlinks~~ [DONE]

*(Implemented in v1.0)*
Symbolic links are stored as regular inodes with their target path in the data stream. Currently they are extracted as regular files containing the raw target bytes.

**Fix:** detect `S_ISLNK(inode->mode)` during extraction and call `symlink(target, dest_path)` instead of writing a file.

---

### 1.3 Restore hard links correctly

APFS hard links are tracked via `J_SIBLING_VAL_T` records in the B-tree. When the same inode appears under multiple paths (multiple drecs with the same `file_inode`), the tool currently extracts the file content once per drec — creating duplicate copies.

**Fix:** after extracting the primary copy, call `link()` for each additional path. Falls back to independent copies if the destination filesystem does not support hard links.

---

### 1.4 Mid-scan checkpoint (resume interrupted scan)

A Ctrl-C during the scan phase currently saves only a geometry checkpoint — the next run has to re-scan from block 0. For a 1 TB image at 2.5+ hours per scan, this is costly.

**Fix:** save a partial scan checkpoint every N blocks (e.g., every 5 million blocks, roughly every 10 minutes). On next run, detect the partial checkpoint and resume from the last saved block.

**Complexity note:** the global arrays (`g_drecs`, `g_inodes`, etc.) would need to support append-on-load. The checkpoint format version would need a bump.

---

### 1.5 SHA-256 manifest of extracted files

After extraction, write a `checksums.sha256` file (one line per extracted file in standard `sha256sum` format). This provides:
- Integrity verification: re-run `sha256sum -c checksums.sha256` at any time
- Chain-of-custody documentation for forensic use
- Deduplication reference: identical files across the image are immediately visible

**Controlled by:** `--no-checksums` to skip for speed on very large recoveries.

---

### 1.6 Possible-truncation detection and `--expand-extents` flag

When a file's DSTREAM size is readable (`size_trusted = true`) but the total extent
coverage is significantly larger, the tool currently trusts DSTREAM — producing a correct
but potentially truncated file.  This happens on images with corrupt DSTREAM fields
(e.g. a 33 GB file whose DSTREAM reads as 736 MB due to damage).

**Phase 1 — Detection and dual-extract ✅ IMPLEMENTED (Session 38)**

During extraction, when `size_trusted && extents_dense && extent_coverage > expected_size * 2`
and the gap is ≥ 10 blocks, the tool:
1. Extracts the primary file at DSTREAM size (always safe).
2. Extracts an `_EXPANDED` copy alongside it up to `extent_coverage`.
3. Checks whether the extra bytes (beyond DSTREAM) are all zeros — if so, removes
   the `_EXPANDED` file and marks it "discarded (zeros)" in the report.
4. Logs all detections in `recovery_summary.md` → "Possibly Truncated Files" table
   (inode, DSTREAM size, extent coverage, status, path).
5. Shows a terminal warning (`⚠  N file(s) may be truncated…`) if any expansions
   were kept (non-zero extra bytes).
6. Path collisions are now logged in `recovery_summary.md` → "Path Collisions" table
   with `_COLLISION` suffix replacing the old `_<inode_id>` suffix.

**Phase 2 — `--expand-extents` flag (remaining future work):**
When `--expand-extents` is supplied, re-enable the density-based DSTREAM override:
if `extents_dense && extent_coverage > expected_size` then use `extent_coverage` instead.
This is the pre-P24 behaviour — correct for corrupt-DSTREAM files, but risks phantom-extent
inflation for files with stray extent records.  Users should run a targeted re-extraction
(`--re-extract --pilot <path>`) on only the affected files.

**Background:** P24 (Session 36) removed unconditional density expansion because adjacent
phantom extent records were inflating common files (JPGs, XLSes) by 100–1900×.
Trusting DSTREAM is correct for ≈99.9% of files; Phase 2 provides an escape hatch for
the rare corrupt-DSTREAM case.

---

### 1.8 Multiple volumes in one container

APFS containers can hold multiple volumes (e.g., the standard macOS install has `Macintosh HD`, `Macintosh HD - Data`, `Preboot`, `Recovery`, `VM`). Currently the tool targets whichever volume's metadata it encounters first.

**Fix:**
- Parse `nx_max_file_systems` from the NXSB and enumerate all volume superblocks (`APSB`)
- Print a volume list with names and UUIDs; let the user pick with `--volume N` or `--volume-uuid UUID`
- Default: recover from the largest data volume (heuristic)

---

### ~~1.7 Restore directory metadata~~ [DONE]

*(Implemented in v1.0)*
Currently directories are `mkdir`'d with default permissions and no timestamp. The same metadata fields available for files exist for directory inodes too.

**Fix:** apply the same `restore_metadata()` path used for files (see 1.1) to directories after their subtree has been written (timestamps must be applied last, since creating children updates the directory mtime).

---

## Tier 2 — High value, moderate effort

### 2.1 APFS snapshot recovery (Time Machine)

APFS snapshots are point-in-time consistent views of a volume, stored as separate B-tree root references in the snapshot metadata B-tree. Time Machine uses these extensively.

**What this enables:**
- Enumerate all snapshots with their timestamps: `--list-snapshots`
- Target a specific snapshot for recovery: `--snapshot 2024-03-15-120000`
- Recover a file as it existed on a given date — even if overwritten on the live volume

**Implementation notes:**
- Parse `J_SNAP_METADATA_VAL_T` records from the snapshot metadata B-tree
- Each snapshot has its own `extentref_tree_oid` — a root OID for a parallel extent tree
- The object map (`omap`) maps OID+XID pairs to physical blocks; targeting a snapshot means filtering the omap to the snapshot's XID

---

### 2.2 Raw block carving (content-based recovery)

For images so badly damaged that no B-tree fragments survive at all, a last-resort scan that ignores filesystem structure entirely: walk every block looking for known file format magic bytes (JPEG `\xff\xd8\xff`, PDF `%PDF`, MP4 `ftyp`, ZIP `PK\x03\x04`, etc.) and carve out contiguous runs.

**Similar to:** PhotoRec, Foremost, Scalpel.

**This is a complement to, not replacement for, the B-tree approach:**
- B-tree scan runs first; carving activates only on blocks that weren't claimed by any inode
- Carved files go to `recovered_carved/` with a generated name and zero path information
- File boundaries are estimated from format-specific end-of-file markers or fixed sizes

---

### 2.3 FileVault personal recovery key

Currently only password-based VEK derivation is supported. macOS also issues a 24-character personal recovery key (PRK) in the format `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` which derives the VEK via a different PBKDF2 path.

**Fix:** detect whether the `--password` argument matches the PRK format and follow the alternate derivation path.

---

### 2.4 LZFSE support on Linux

`libcompression` (used for LZFSE/LZVN decoding) is a macOS SDK framework and is not available on Linux. Currently LZFSE-compressed files log a warning and are skipped.

**Options:**
- Bundle `lzfse` reference implementation (BSD-licensed, from Apple's open-source release)
- Use the `lzfse` Homebrew/apt package as an optional dependency with autodetection

---

### 2.5 Sparse file support

Files with "holes" (large zero-filled regions) are stored in APFS with sparse extents — only the non-zero regions have physical blocks. Currently these holes are written as literal zeros, producing large dense output files.

**Fix:** detect gaps between extents and use `lseek(SEEK_END)` / `fallocate(FALLOC_FL_PUNCH_HOLE)` (Linux) or `fcntl(F_PUNCHHOLE)` (macOS) to recreate sparseness in the output.

---

### 2.6 xattr passthrough

Extended attributes (other than `com.apple.decmpfs` which is already used for decompression) are currently ignored. This includes Finder colour labels, Spotlight metadata, quarantine flags, and app-specific data.

**Fix:**
- During B-tree scan, collect `J_XATTR_VAL_T` records for each inode
- After extraction, replay them with `setxattr()`
- Embedded xattrs (stored inline in the B-tree record) are straightforward; stream xattrs (pointing to a dstream) require reading the extent data too

---

### ~~2.7 Better path collision handling~~ [DONE]

*(Implemented in v1.0)*
When two inodes resolve to the same output path (common on damaged images with stale duplicate drecs), the second file is currently redirected to `recovered_orphans/conflict_<inode>_<name>`. 

**Better approach:** append `_<inode>` to the filename before the extension (e.g., `report_1048776.pdf`) and place it in the correct directory — giving more context than a flat orphans folder with a generic name.

---

## Tier 3 — Significant effort, power-user value

### 3.1 Journal replay for recent deletions

The current `--deleted` mode uses a heuristic inode scan. APFS also maintains a transaction journal (via checkpoint descriptors and the space manager) that records very recent operations. Replaying the journal could identify files deleted in the most recent few transactions with much higher confidence than the heuristic.

---

### 3.2 APFS Fusion Drive support

Fusion Drives combine a small SSD and a large HDD into a single logical APFS volume using CoreStorage (or APFS directly on newer macOS). File data can span both physical devices.

**Recovery requirement:** both physical device images would need to be provided. The tool would need to understand the CoreStorage mapping layer to reconstruct the logical address space before block parsing begins.

---

### 3.3 Forensic output formats

For professional forensic use, support writing output in standard forensic container formats:

- **E01 (EnCase):** widely accepted in legal proceedings; includes case metadata, MD5/SHA1 hash, acquisition notes
- **AFF4:** modern open forensic format with streaming compression
- **DFXML:** Digital Forensics XML — structured metadata about every extracted file (path, hashes, timestamps, inode ID, source offset)

---

### 3.4 Web / GUI interface

A local web interface (served on `localhost`) would make the tool accessible to non-technical users:

- File picker for image and output directory
- Real-time progress bars (WebSocket or SSE)
- Interactive `file_list.md` viewer (sortable, filterable)
- One-click download of `recovery_summary.md`

Tech stack candidates: single-binary Go/Python HTTP server bundled alongside the C binary.

---

### 3.5 Live block device support

Currently requires a disk image file. Direct recovery from a live (but dying) block device (e.g., `/dev/disk2` on macOS, `/dev/sdb` on Linux) without creating an intermediate image first:

- Reduces total time and eliminates the need for an intermediate copy destination
- Requires careful handling of read errors (retry with smaller read units, log bad sectors)
- **Risk:** reading from a failing drive without imaging first is generally not recommended forensically — document the tradeoff clearly

---

## Tier 4 — Research / exploratory

### 4.1 T2 / Apple Silicon hardware-bound encryption

Macs with a T2 chip or Apple Silicon (M1/M2/M3/M4) use hardware-bound Volume Encryption Keys stored in the Secure Enclave. The VEK is not derivable from the user password alone — the Secure Enclave wraps it with a hardware UID that never leaves the chip.

**Current state:** recovery from these images without the original hardware is not possible with any known technique. This is a research item to track developments in the field, not a near-term implementation goal.

**Partial mitigation:** if the original Mac is functional (even with a corrupted APFS volume), the OS can sometimes be booted into Recovery Mode to dump the decrypted data. Document this workflow.

---

### 4.2 Snapshot delta recovery

When a snapshot exists but its B-tree is partially overwritten, it may be possible to reconstruct the snapshot state by combining:
- The surviving snapshot's extent records
- The live volume's current B-tree (as a fallback for missing nodes)
- XID ordering to determine which version of a node is authoritative

This is complex APFS internals work requiring deep study of the object map and checkpoint area layout.

---

### 4.3 APFS container replication / cloning awareness

macOS uses APFS clones extensively (copy-on-write file copies). A cloned file shares extents with its source. On a damaged image, two inodes may point to the same physical extents via the `phys_ext_tree`.

Currently both are extracted independently (reading the same blocks twice). Proper clone detection would let the tool recreate the clone relationship with `clonefile()` on macOS, saving disk space.

---

## Contributing

If you'd like to work on any of these, please open an issue on GitHub first to discuss the approach before starting implementation. See [CONTRIBUTING.md](CONTRIBUTING.md).
