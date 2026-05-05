#pragma once
/*
 * checkpoint.h — binary checkpoint save/load for scan and extraction phases.
 *
 * Scan checkpoint  (_scan_results.bin): saved after scan+build_paths.
 *   On restart the entire scan is skipped and results restored from disk.
 *
 * Extracted checkpoint (_extracted_ids.bin): updated every 100 files
 *   during extraction; on restart already-extracted inodes are skipped.
 *   CP_VERSION 4+: also stores cumulative extraction stats (cp_extract_stats_t).
 *
 * Both writes are atomic: data is written to a .tmp file then renamed.
 */

#include <stdint.h>
#include <stdbool.h>
#include "apfs_types.h"

/*
 * Save scan results to the checkpoint directory (g_logs_dir).
 * complete=true  after a successful full scan + path build.
 * complete=false after a Ctrl-C interrupt (geometry only; forces rescan on next run).
 */
void cp_save_scan(bool complete);

/* Restore scan results from checkpoint.  Returns true on success. */
bool cp_load_scan(void);

/*
 * cp_save_extracted() — persist the set of inode IDs already extracted and
 * the cumulative stats.  stats may be NULL (written as all-zero).
 * Called every 100 files during extraction and on clean completion.
 */
void cp_save_extracted(uint64_t *ids, uint32_t count, const cp_extract_stats_t *stats);

/*
 * cp_load_extracted() — mark previously extracted inodes in done_set[].
 * done_set must be calloc'd with g_max_inodes entries.
 * ids (optional) receives the raw inode ID array; caller supplies the buffer.
 * max_ids is the capacity of ids[] (typically g_max_inodes).
 * stats_out (optional) receives the persisted extraction stats.
 * Returns the number of IDs loaded.
 */
uint32_t cp_load_extracted(bool *done_set, uint64_t *ids, uint32_t max_ids,
                           cp_extract_stats_t *stats_out);

/*
 * cp_save_pt_collisions() — persist g_possibly_truncated[] and g_collisions[]
 * to logs/pt_collisions.bin after a successful run.
 *
 * cp_load_pt_collisions() — prepend persisted data into the global arrays
 * before extraction starts, so the final recovery_summary.md covers all runs.
 * Call only on resumed runs where --re-extract and --no-resume are not set.
 */
void cp_save_pt_collisions(void);
void cp_load_pt_collisions(void);
