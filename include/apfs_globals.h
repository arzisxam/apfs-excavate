#pragma once
/*
 * apfs_globals.h — extern declarations for all process-wide mutable state.
 *
 * Definitions live in src/globals.c.  Every other translation unit that
 * needs to read or write global state includes this header.
 */

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>

#include "apfs_types.h"

/* ============================================================================
 * Output directory paths
 * ============================================================================
 */
/* Path to the logs/ subdirectory; set in main() before log_init. */
extern char *g_logs_dir;

/* ============================================================================
 * Image / partition geometry
 * ============================================================================
 */
extern uint8_t  *g_data;
extern size_t    g_data_size;
extern uint32_t  g_block_size;
extern uint64_t  g_partition_offset;
extern uint64_t  g_container_offset;
extern uint64_t  g_override_sb_lba;
extern uint64_t  g_min_xid;
extern bool      g_case_sensitive;
extern char     *g_pilot_filter;
extern int       g_fd;

/* ============================================================================
 * Directory records
 * ============================================================================
 */
extern drec_t   *g_drecs;
extern int       g_drec_count;
extern uint32_t  g_drec_capacity;
extern uint32_t  g_max_drecs;

/* ============================================================================
 * Inodes
 * ============================================================================
 */
extern inode_t  *g_inodes;
extern int       g_inode_count;
extern uint32_t  g_max_inodes;

/* Inode hash table — O(1) inode_id → inode_t* lookup (open addressing). */
extern inode_t **g_inode_hash;
extern uint32_t  g_inode_hash_capacity;

/* Resolved paths: g_paths[inode_array_index] = malloc'd path string or NULL */
extern char    **g_paths;

/* ============================================================================
 * Deleted file tracking
 * ============================================================================
 */
extern deleted_file_t *g_deleted;
extern int             g_deleted_count;
extern uint32_t        g_deleted_capacity;
extern uint32_t        g_max_deleted_files;

/* ============================================================================
 * Encryption state
 * ============================================================================
 */
extern aes_xts_ctx_t g_aes_xts;
extern uint8_t       g_vek[32];
extern bool          g_encryption_enabled;
extern char         *g_password;
extern uint8_t       g_container_uuid[16];
extern uint8_t       g_volume_uuid[16];

extern crypto_state_t g_crypto_states[MAX_CRYPTO_STATES];
extern int            g_crypto_state_count;

/* ============================================================================
 * Feature flags / configuration
 * ============================================================================
 */
extern int   g_workers;
extern bool  g_enable_compression;
extern bool  g_enable_deleted_recovery;
extern bool  g_no_resume;
extern bool  g_skip_metadata; /* --skip-metadata: skip all POSIX metadata restoration */
extern bool  g_debug_mode;   /* --debug: write LOG_DEBUG to debug_*.log */
extern bool  g_scan_only;    /* --scan-only: scan + checkpoint, no extraction */

/* Extension filter (--filter-ext jpg,pdf,mov).  Empty = accept all. */
extern char **g_filter_exts;
extern int    g_filter_ext_count;

/* Set to 1 by SIGINT/SIGTERM handler; checked by scan workers and extract loop. */
extern volatile sig_atomic_t g_interrupted;

/* ============================================================================
 * Threading / synchronisation
 * ============================================================================
 */
extern pthread_mutex_t g_inode_mutex;
extern pthread_mutex_t g_drec_mutex;
extern pthread_mutex_t g_deleted_mutex;
extern pthread_mutex_t g_stats_mutex;
extern pthread_mutex_t g_cp_mutex;

/* ============================================================================
 * Progress bar state
 * ============================================================================
 */
extern bool g_progress_line_active;

/* ============================================================================
 * Error collection
 * ============================================================================
 */
extern error_record_t *g_errors;
extern int             g_error_count;
extern uint32_t        g_error_capacity;
extern uint32_t        g_max_errors;

/* ============================================================================
 * Unrecovered file tracking (for unrecovered_files.md)
 * ============================================================================
 */
extern unrecovered_t *g_unrecovered;
extern int            g_unrecovered_count;
extern uint32_t       g_unrecovered_capacity;

/* ============================================================================
 * Possibly-truncated file tracking (for recovery_summary.md)
 * ============================================================================
 */
extern possibly_truncated_t *g_possibly_truncated;
extern int                   g_possibly_truncated_count;
extern uint32_t              g_possibly_truncated_capacity;

/* ============================================================================
 * Path collision tracking (for recovery_summary.md)
 * ============================================================================
 */
extern path_collision_t *g_collisions;
extern int               g_collision_count;
extern uint32_t          g_collision_capacity;

/* ============================================================================
 * Feature flags — size filters and re-extraction
 * ============================================================================
 */
extern bool     g_re_extract;         /* --re-extract: clear extracted checkpoint, re-run extraction */
extern uint64_t g_min_file_size;      /* --min-size: 0 = no minimum */
extern uint64_t g_max_file_size;      /* --max-size: default 50 GB hard cap; overridable */

/* ============================================================================
 * Run-level counters
 * ============================================================================
 */
/* Files skipped during extraction due to size filter (default cap or --max/min-size) */
extern uint64_t g_skipped_size_count;
/* Orphan files removed because all extents were out of range (0-byte on disk) */
extern uint32_t g_zero_byte_removed_count;
/* Extraction work list size (= progress bar denominator) for this run */
extern uint32_t g_work_count;
/* Files already extracted in a previous run (loaded from checkpoint) */
extern uint32_t g_previously_extracted_count;
/* Final cumulative extracted count (checkpoint size at end of extraction run) */
extern uint32_t g_total_extracted_count;

/* Cumulative extraction stats persisted in extracted_ids.bin.
 * Loaded at the start of extraction; updated and saved throughout. */
extern cp_extract_stats_t g_cp_extract_stats;

/* True when the output drive is a non-POSIX filesystem (ExFAT/FAT/NTFS).
 * Metadata restoration (chmod, chown, timestamps, BSD flags) is skipped. */
extern bool g_output_nonposix;

