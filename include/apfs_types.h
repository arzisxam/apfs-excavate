#pragma once
/*
 * apfs_types.h — shared data structures and compile-time constants
 *
 * All structs used across modules live here. No functions, no globals.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/* ============================================================================
 * Compile-time limits
 * ============================================================================
 */

#define MAX_PATH_LEN        4096
#define MAX_NAME_LEN        256
#define MAX_KEYBAG_ENTRIES  256
#define MAX_XATTR_SIZE      65536
#define MAX_CRYPTO_STATES   256

/* ============================================================================
 * APFS on-disk constants
 * ============================================================================
 */

/* J-Key object types */
#define JOBJ_TYPE_INODE        3
#define JOBJ_TYPE_XATTR        4
#define JOBJ_TYPE_SIBLING      5
#define JOBJ_TYPE_CRYPTO_STATE 7
#define JOBJ_TYPE_EXTENT       8
#define JOBJ_TYPE_DIR_REC      9

/* Directory entry types */
#define DT_DIR  4
#define DT_REG  8

/* B-tree node flags */
#define BTNODE_ROOT  0x0001
#define BTNODE_LEAF  0x0002
#define BTNODE_FIXED 0x0004

/* Keybag entry tags */
#define KB_TAG_VOLUME_UNLOCK_RECORDS 3

/* Compression algorithm identifiers (from com.apple.decmpfs) */
#define COMP_ZLIB_RSRC   3
#define COMP_ZLIB_ATTR   4
#define COMP_LZVN_RSRC   7
#define COMP_LZVN_ATTR   8
#define COMP_LZFSE_RSRC  11
#define COMP_LZFSE_ATTR  12

/* Inode internal flags */
#define INODE_IS_COMPRESSED 0x20

/* Checkpoint magic strings and per-file version constants.
 * Kept separate so each file can evolve independently. */
#define CP_SCAN_MAGIC     "APFSCKPT"
#define CP_DONE_MAGIC     "APFSDONE"
#define CP_SCAN_VERSION    5
#define CP_EXTRACT_VERSION 5

/* ============================================================================
 * Core APFS metadata structures
 * ============================================================================
 */

/* Directory record: maps a filename to an inode within a parent directory. */
typedef struct {
    uint64_t parent_inode;
    uint64_t file_inode;
    char     name[MAX_NAME_LEN];
    bool     is_dir;
} drec_t;

/* File extent: maps a logical byte range in a file to a physical block. */
typedef struct {
    uint64_t logical;    /* byte offset within file */
    uint64_t physical;   /* physical block number on disk */
    uint64_t length;     /* extent length in bytes */
    uint64_t crypto_id;  /* per-extent encryption key selector */
    uint8_t  flags;
} extent_t;

/* Inode: all metadata for a single file or directory. */
typedef struct {
    uint64_t  inode_id;
    uint64_t  parent_id;
    uint32_t  mode;
    uint64_t  size;
    bool      is_dir;
    bool      is_compressed;
    uint32_t  compression_type;
    uint64_t  uncompressed_size;
    
    /* Metadata */
    uint64_t  create_time;
    uint64_t  mod_time;
    uint64_t  change_time;
    uint64_t  access_time;
    uint32_t  uid;
    uint32_t  gid;
    uint32_t  bsd_flags;

    int       extent_count;
    int       extent_capacity;   /* allocated slots in extents[] */
    extent_t *extents;           /* dynamically grown */
    uint8_t  *decmpfs_data;      /* inline decmpfs xattr data */
    size_t    decmpfs_len;
    uint64_t  default_crypto_id; /* from dstream xfield; used when extent crypto_id == 0 */
    char     *symlink_target;    /* inline symlink target from xfield type 13; NULL if absent */
} inode_t;

/* Record of a potential deleted file (block + former inode id). */
typedef struct {
    uint64_t block_num;
    uint64_t inode_id;
} deleted_file_t;

/* Single entry in an APFS keybag (container or volume). */
typedef struct {
    uint8_t  uuid[16];
    uint16_t tag;
    uint16_t keylen;
    uint8_t *key_data;
} keybag_entry_t;

/* Parsed keybag (array of entries). */
typedef struct {
    int           count;
    keybag_entry_t entries[MAX_KEYBAG_ENTRIES];
} keybag_t;

/* Per-extent AES-XTS key material derived from the crypto state B-tree. */
typedef struct {
    uint64_t crypto_id;
    uint8_t  key[32];    /* 16-byte key1 + 16-byte key2 */
    uint16_t key_len;
    bool     initialized;
} crypto_state_t;

/* AES-XTS context holding the two 128-bit sub-keys. */
typedef struct {
    uint8_t key1[16];
    uint8_t key2[16];
    bool    initialized;
} aes_xts_ctx_t;

/* ============================================================================
 * Error collection
 * ============================================================================
 */

typedef enum {
    ERR_INFO    = 0,
    ERR_WARNING = 1,
    ERR_ERROR   = 2
} error_severity_t;

typedef struct {
    error_severity_t severity;
    char             message[256];
    uint64_t         block_num;
    uint64_t         inode_id;
    char             file_path[MAX_PATH_LEN];
    time_t           timestamp;
} error_record_t;

/* ============================================================================
 * Unrecovered file record (for unrecovered_files.md report)
 * ============================================================================
 */

typedef enum {
    UNRECOVERED_OTHER       = 0,
    UNRECOVERED_SIZE_FILTER = 1,  /* skipped by --max-size / --min-size */
    UNRECOVERED_EXT_FILTER  = 2,  /* skipped by --filter-ext */
} unrecovered_kind_t;

typedef struct {
    uint64_t            inode_id;
    char                path[MAX_PATH_LEN];
    uint64_t            size;
    char                reason[256];
    bool                is_orphan;  /* true = no path resolved, placed in orphan_recovered/ */
    unrecovered_kind_t  kind;
} unrecovered_t;

typedef struct {
    uint64_t inode_id;
    char     original_path[MAX_PATH_LEN]; /* primary file path (DSTREAM size) */
    char     expanded_path[MAX_PATH_LEN]; /* _EXPANDED file path, or "" if discarded */
    uint64_t dstream_size;                /* DSTREAM (primary) extraction size */
    uint64_t extent_size;                 /* extent_coverage (expanded) size */
    bool     discarded;                   /* true = expanded was all-zeros, removed */
} possibly_truncated_t;

typedef struct {
    uint64_t inode_id;
    char     original_path[MAX_PATH_LEN]; /* attempted path (already taken) */
    char     actual_path[MAX_PATH_LEN];   /* where the file was actually written */
} path_collision_t;

/* ============================================================================
 * Run statistics (accumulated during recovery)
 * ============================================================================
 */

typedef struct {
    int      directories_found;
    int      files_found;
    int      paths_resolved;
    int      files_extracted;
    int      compressed_files;
    int      deleted_files_found;
    int      deleted_files_recovered;
    uint64_t skipped_size_count;       /* files skipped due to size filter */
    uint32_t zero_byte_removed;        /* orphans removed — all extents out of range */
    int      scan_estimate_files;      /* count_scan_files() result — scan box source */
    uint32_t previously_extracted;     /* files extracted in prior resumed runs     */
    uint32_t total_extracted;          /* cumulative files in extraction checkpoint  */
    uint32_t orphans_decompressed;     /* orphan blobs successfully decompressed    */
    uint32_t orphans_identified;       /* orphans renamed with correct extension    */
    uint32_t orphans_unrecoverable;    /* orphans moved to unrecoverable/           */
    uint32_t orphans_zeroed;           /* orphans deleted — all-zero content        */
    int      orphan_fail_count;        /* orphans that failed post-processing entirely */
    double   scan_time;
    double   build_time;
    double   extract_time;
    double   orphan_time;
    double   total_time;
    uint64_t blocks_scanned;
    double   blocks_per_second;
    bool     keybag_found;
    bool     vek_derived;
    int      error_count;
    int      warning_count;
} result_t;

/* ============================================================================
 * Checkpoint on-disk format helpers
 * ============================================================================
 */

/*
 * Cumulative extraction statistics persisted in extracted_ids.bin (CP_VERSION 4+).
 * Loaded at the start of each run; updated and saved after each run.
 * files_found is set once (first run) and never overwritten.
 */
typedef struct {
    uint32_t files_found;     /* total work list size on first run */
    uint32_t files_recovered; /* cumulative files physically written to disk */
    uint32_t files_skipped;   /* cumulative size-filtered files */
    uint32_t files_zero_byte; /* cumulative zero-byte orphans removed */
    uint32_t files_failed;    /* reserved (0) */
    uint32_t files_deduped;   /* cumulative duplicate orphans removed (same content, different inode) */
    uint32_t _pad[2];
} cp_extract_stats_t;

/*
 * Per-inode header written to the scan checkpoint (no pointers).
 * Variable-length extents[] and decmpfs_data[] follow immediately.
 * CP_VERSION 4: added create_time, mod_time, access_time, change_time,
 *               uid, gid, bsd_flags so metadata is restored on resumed runs.
 * CP_VERSION 5: added symlink_len; symlink_target bytes follow decmpfs in the
 *               stream.  V4 checkpoints are still accepted on load (symlink_len
 *               treated as 0, symlinks re-created as 0-byte placeholders).
 *
 * Layout of per-inode data in the stream (V5):
 *   cp_inode_hdr_t (108 bytes)
 *   extent_t × extent_count
 *   uint8_t  × decmpfs_len
 *   char     × symlink_len   (null-terminated; 0 = no symlink target)
 */
typedef struct {
    uint64_t inode_id;
    uint64_t parent_id;
    uint64_t size;
    uint64_t uncompressed_size;
    uint64_t default_crypto_id;
    uint64_t create_time;
    uint64_t mod_time;
    uint64_t access_time;
    uint64_t change_time;
    uint32_t mode;
    uint32_t compression_type;
    uint32_t extent_count;
    uint32_t decmpfs_len;
    uint32_t uid;
    uint32_t gid;
    uint32_t bsd_flags;
    uint8_t  is_dir;
    uint8_t  is_compressed;
    uint8_t  _pad[2];
    uint32_t symlink_len;   /* V5+: strlen(symlink_target)+1, or 0 if none */
} cp_inode_hdr_t;

/* ============================================================================
 * Threading helpers
 * ============================================================================
 */

/* Argument block for one scan worker thread. */
typedef struct {
    uint64_t start_block;
    uint64_t end_block;
    uint64_t total_blocks;
    bool     show_progress;
    int      nodes_found;
    _Atomic uint64_t *shared_done; /* points to a per-scan counter owned by scan_image() */
} scan_task_t;

/* Work item for the extraction phase (ordered by physical block for I/O). */
typedef struct {
    int      drec_idx;    /* index into g_drecs, or -(inode_tbl_idx+1) for orphans */
    uint64_t first_phys;  /* first physical block of the inode's first extent */
} extract_work_t;
