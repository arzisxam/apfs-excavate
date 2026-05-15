/*
 * globals.c — definitions for all process-wide mutable state.
 *
 * Every g_* variable declared extern in apfs_globals.h is defined here.
 * All other translation units access these through the header.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>

#include "apfs_types.h"
#include "apfs_globals.h"

/* ============================================================================
 * Output directory paths
 * ============================================================================
 */
char *g_logs_dir = NULL;

/* ============================================================================
 * Image / partition geometry
 * ============================================================================
 */
uint8_t  *g_data            = NULL;
size_t    g_data_size        = 0;
uint32_t  g_block_size       = 4096;
uint64_t  g_partition_offset = 0;
uint64_t  g_container_offset = 0;
uint64_t  g_override_sb_lba  = 0;
uint64_t  g_min_xid          = 0;
bool      g_case_sensitive   = false;
char     *g_pilot_filter     = NULL;
int       g_fd               = -1;

/* ============================================================================
 * Directory records
 * ============================================================================
 */
drec_t  *g_drecs        = NULL;
int      g_drec_count   = 0;
uint32_t g_drec_capacity = 0;
uint32_t g_max_drecs    = 100000;

/* ============================================================================
 * Inodes
 * ============================================================================
 */
inode_t  *g_inodes       = NULL;
int       g_inode_count  = 0;
uint32_t  g_max_inodes   = 1000000;

inode_t **g_inode_hash          = NULL;
uint32_t  g_inode_hash_capacity = 2097152U; /* 2^21 */

char    **g_paths = NULL;

/* ============================================================================
 * Deleted file tracking
 * ============================================================================
 */
deleted_file_t *g_deleted          = NULL;
int             g_deleted_count    = 0;
uint32_t        g_deleted_capacity = 0;
uint32_t        g_max_deleted_files = 10000;

/* ============================================================================
 * Encryption state
 * ============================================================================
 */
aes_xts_ctx_t g_aes_xts          = {0};
uint8_t       g_vek[32]          = {0};
bool          g_encryption_enabled = false;
char         *g_password          = NULL;
uint8_t       g_container_uuid[16] = {0};
uint8_t       g_volume_uuid[16]   = {0};

crypto_state_t g_crypto_states[MAX_CRYPTO_STATES] = {0};
int            g_crypto_state_count = 0;

/* ============================================================================
 * Feature flags
 * ============================================================================
 */
int   g_workers               = 1;
bool  g_enable_compression    = true;
bool  g_enable_deleted_recovery = false;
bool  g_no_resume             = false;
bool  g_skip_metadata         = false;
bool  g_debug_mode            = false;
bool  g_scan_only             = false;

char **g_filter_exts      = NULL;
int    g_filter_ext_count = 0;

bool     g_re_extract     = false;
uint64_t g_min_file_size  = 0;
uint64_t g_max_file_size  = 50ULL * 1024 * 1024 * 1024;  /* 50 GB default cap */

volatile sig_atomic_t g_interrupted = 0;

/* ============================================================================
 * Threading / synchronisation
 * ============================================================================
 */
pthread_mutex_t g_inode_mutex   = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_drec_mutex    = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_deleted_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_stats_mutex   = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_cp_mutex      = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================================
 * Progress bar state
 * ============================================================================
 */
bool g_progress_line_active = false;

/* ============================================================================
 * Error collection
 * ============================================================================
 */
error_record_t *g_errors        = NULL;
int             g_error_count   = 0;
uint32_t        g_error_capacity = 0;
uint32_t        g_max_errors    = 1000;

/* ============================================================================
 * Unrecovered file tracking
 * ============================================================================
 */
unrecovered_t *g_unrecovered          = NULL;
int            g_unrecovered_count    = 0;
uint32_t       g_unrecovered_capacity = 0;

/* ============================================================================
 * Possibly-truncated file tracking
 * ============================================================================
 */
possibly_truncated_t *g_possibly_truncated          = NULL;
int                   g_possibly_truncated_count    = 0;
uint32_t              g_possibly_truncated_capacity = 0;

/* ============================================================================
 * Path collision tracking
 * ============================================================================
 */
path_collision_t *g_collisions          = NULL;
int               g_collision_count     = 0;
uint32_t          g_collision_capacity  = 0;

/* ============================================================================
 * Run-level counters
 * ============================================================================
 */
uint64_t g_skipped_size_count         = 0;
uint32_t g_zero_byte_removed_count    = 0;
uint32_t g_work_count                 = 0;
uint32_t g_previously_extracted_count = 0;
uint32_t g_total_extracted_count      = 0;

bool g_output_nonposix = false;

cp_extract_stats_t g_cp_extract_stats = {0};

