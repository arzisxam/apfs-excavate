#pragma once
/*
 * util.h — timing, number formatting, progress bars, inode hash table.
 */

#include <stdint.h>
#include <stdbool.h>
#include "apfs_types.h"

/* ---- Timing ---------------------------------------------------------------- */

/* Returns current time in milliseconds (monotonic wall clock). */
double util_get_time_ms(void);

/* ---- Number / time formatting ---------------------------------------------- */

/* Format n with thousand separators into buf (at least 32 bytes). Returns buf. */
char *util_format_num(uint64_t n, char *buf);

/* Format seconds into human-readable string in buf (at least 32 bytes).
 * Examples: "45s", "3m 12s", "1h 5m". Returns buf. */
char *util_format_time(double seconds, char *buf);

/* Format bytes as human-readable size in buf (at least 32 bytes).
 * Examples: "1.23 TB", "456.78 MB", "12.34 KB". Returns buf. */
char *util_format_size(uint64_t bytes, char *buf);

/* ---- Progress bars --------------------------------------------------------- */

/* In-place scan progress bar written to stdout with \r. */
void util_print_scan_progress(uint64_t block_num, uint64_t total_blocks,
                              double start_time);

/* Generic in-place progress bar written to stdout with \r. */
void util_print_progress(const char *desc, uint64_t current, uint64_t total,
                         double start_time);

/* Flush the active progress bar line with a newline (if one is displayed). */
void util_progress_newline(void);

/* ---- Inode hash table ------------------------------------------------------ */

/*
 * find_inode() — thread-safe O(1) lookup by inode_id (acquires g_inode_mutex).
 * Falls back to linear scan before the hash table is allocated.
 * Returns NULL if not found.
 */
inode_t *find_inode(uint64_t inode_id);

/*
 * get_inode_idx() — returns the array index of an inode in g_inodes[],
 * or -1 if not found.
 */
int64_t get_inode_idx(uint64_t inode_id);

/*
 * get_or_create_inode_nolock() — find an existing inode or allocate a new
 * slot.  MUST be called with g_inode_mutex already held by the caller.
 * Returns NULL on allocation failure.
 */
inode_t *get_or_create_inode_nolock(uint64_t inode_id);

/*
 * get_or_create_inode() — find an existing inode or allocate a new slot.
 * Thread-safe (acquires g_inode_mutex internally for the lookup/create only).
 * Callers that need to modify the returned inode without a data race must
 * instead hold g_inode_mutex themselves and call get_or_create_inode_nolock().
 * Returns NULL on allocation failure.
 */
inode_t *get_or_create_inode(uint64_t inode_id);

/* ---- Path helpers ---------------------------------------------------------- */

/*
 * sanitize_path() — strip leading '/' and drop ".." components.
 * Writes safe path into dst[dst_size]. Returns dst.
 */
char *sanitize_path(const char *src, char *dst, size_t dst_size);

/*
 * create_directory() — recursively create all parent directories for path.
 * Handles file/directory path collisions by renaming the blocking file.
 */
void create_directory(const char *path);

/* ---- Extension filter ------------------------------------------------------ */

/*
 * util_matches_filter_ext() — returns true if filename's extension matches
 * one of the entries in g_filter_exts[], or if g_filter_ext_count == 0
 * (no filter active).  Comparison is case-insensitive.
 */
bool util_matches_filter_ext(const char *filename);
