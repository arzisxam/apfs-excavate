#pragma once
/*
 * recovery.h — path resolution and file extraction.
 *
 * recovery_build_paths()
 *   Deduplicates directory records, then resolves each inode's full path
 *   from the B-tree parent chain.  Populates g_paths[].
 *   Returns the number of successfully resolved paths.
 *
 * recovery_extract_files()
 *   Builds a work list of named files + orphans, sorts it by physical block
 *   address for sequential I/O, then extracts each file to files_dir.
 *   Orphaned files (no resolved path) go to orphan_dir.
 *   Compressed files are decompressed via cmp_decompress_file().
 *   Returns the number of files written.
 *
 * recovery_extract_deleted()
 *   Dumps the raw blocks identified by scan_for_deleted_inodes() into
 *   deleted_dir.  Returns the number of blocks written.
 */

#include <stdint.h>
#include <stdbool.h>

/*
 * Resolve full paths for all discovered inodes into g_paths[].
 * Returns the count of paths successfully resolved.
 */
int recovery_build_paths(bool show_progress);

/*
 * Extract named files to files_dir; orphans (no resolved path) go to orphan_dir.
 * compressed_count_out receives the number of files decompressed on-the-fly.
 * Returns the total number of files written.
 */
int recovery_extract_files(const char *files_dir, const char *orphan_dir,
                           const char *checkpoint_dir,
                           bool show_progress, int *compressed_count_out);

/*
 * Dump raw deleted inode blocks into deleted_dir (created if absent).
 * Returns the number of block-files written.
 */
int recovery_extract_deleted(const char *deleted_dir);

/*
 * Restore timestamps, ownership, and permissions for all discovered
 * directories to files_dir.  Must be called after all files have been
 * extracted (creating child files updates parent directory mtime).
 * Skipped automatically when g_output_nonposix is set.
 */
void recovery_restore_dir_metadata(const char *files_dir);
