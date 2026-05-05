/*
 * test_checkpoint.c — unit tests for cp_save_scan / cp_load_scan and
 *                     cp_save_extracted / cp_load_extracted.
 *
 * No disk image required.  The tests set up minimal global state, write
 * checkpoint files to a temporary directory, reload them, and verify that
 * all fields round-trip exactly.  Error-path tests confirm that a corrupt
 * magic, wrong version, or incomplete checkpoint is rejected cleanly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "checkpoint.h"
#include "apfs_globals.h"
#include "apfs_types.h"

static int s_run    = 0;
static int s_failed = 0;

static void check(int cond, const char *name) {
    s_run++;
    if (cond) {
        printf("  PASS  %s\n", name);
    } else {
        printf("  FAIL  %s\n", name);
        s_failed++;
    }
}

/* ============================================================================
 * Temporary directory helpers
 * ============================================================================
 */

static char s_tmpdir[256];

static int make_tmpdir(void) {
    snprintf(s_tmpdir, sizeof(s_tmpdir), "/tmp/apfsckpt_test_XXXXXX");
    return mkdtemp(s_tmpdir) ? 0 : -1;
}

static void rm_rf(const char *dir) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    (void)system(cmd);
}

/* ============================================================================
 * Global state helpers
 *
 * Use a small hash capacity and inode limit for tests.  The real values are
 * 2^21 (hash) and 10^6 (inodes) — too large to allocate in a unit test.
 * ============================================================================
 */

#define TEST_MAX_INODES   256
#define TEST_HASH_CAP     512
#define TEST_MAX_DRECS    64

static void globals_alloc(void) {
    g_max_inodes          = TEST_MAX_INODES;
    g_inode_hash_capacity = TEST_HASH_CAP;

    g_inodes     = calloc(g_max_inodes, sizeof(inode_t));
    g_inode_hash = calloc(g_inode_hash_capacity, sizeof(inode_t *));
    g_drecs      = calloc(TEST_MAX_DRECS, sizeof(drec_t));
    g_paths      = calloc(g_max_inodes, sizeof(char *));

    g_drec_capacity = TEST_MAX_DRECS;
    g_drec_count    = 0;
    g_inode_count   = 0;

    g_deleted          = NULL;
    g_deleted_count    = 0;
    g_deleted_capacity = 0;

    g_logs_dir = s_tmpdir;
}

static void globals_free(void) {
    free(g_inodes);    g_inodes    = NULL;
    free(g_inode_hash);g_inode_hash = NULL;
    free(g_drecs);     g_drecs     = NULL;
    if (g_paths) {
        for (uint32_t i = 0; i < g_max_inodes; i++) {
            free(g_paths[i]);
            g_paths[i] = NULL;
        }
        free(g_paths);
        g_paths = NULL;
    }
    free(g_deleted);   g_deleted   = NULL;
    g_inode_count   = 0;
    g_drec_count    = 0;
    g_deleted_count = 0;
    g_max_inodes    = 1000000;         /* restore defaults */
    g_inode_hash_capacity = 2097152U;
}

/* Zero the geometry globals so we can confirm cp_load_scan restores them. */
static void geometry_clear(void) {
    g_partition_offset   = 0;
    g_block_size         = 0;
    g_container_offset   = 0;
    g_encryption_enabled = false;
    g_case_sensitive     = false;
}

/* ============================================================================
 * Test: scan geometry round-trip (0 inodes, 0 drecs, 0 paths, 0 deleted)
 * ============================================================================
 */

static void test_scan_geometry_roundtrip(void) {
    printf("\n--- Scan checkpoint: geometry round-trip ---\n");

    globals_alloc();

    /* Set known geometry. */
    g_partition_offset   = 0x100000ULL;
    g_block_size         = 4096;
    g_container_offset   = 0x200000ULL;
    g_encryption_enabled = true;
    g_case_sensitive     = false;

    cp_save_scan(/*complete=*/true);

    /* Clear geometry so we can verify cp_load_scan restores it. */
    geometry_clear();

    bool ok = cp_load_scan();
    check(ok, "cp_load_scan returns true for complete checkpoint");
    check(g_partition_offset   == 0x100000ULL, "partition_offset restored");
    check(g_block_size         == 4096,         "block_size restored");
    check(g_container_offset   == 0x200000ULL, "container_offset restored");
    check(g_encryption_enabled == true,         "encryption_enabled restored");
    check(g_case_sensitive     == false,        "case_sensitive restored");

    globals_free();
}

/* ============================================================================
 * Test: incomplete checkpoint (Ctrl-C mid-scan) is rejected
 * ============================================================================
 */

static void test_scan_incomplete_rejected(void) {
    printf("\n--- Scan checkpoint: incomplete rejected ---\n");

    globals_alloc();

    g_partition_offset = 0xABCDEF00ULL;
    g_block_size       = 4096;
    g_container_offset = 0x0;

    cp_save_scan(/*complete=*/false);

    geometry_clear();

    bool ok = cp_load_scan();
    check(!ok, "cp_load_scan returns false for incomplete checkpoint");

    globals_free();
}

/* ============================================================================
 * Test: corrupt magic bytes rejected
 * ============================================================================
 */

static void test_scan_bad_magic(void) {
    printf("\n--- Scan checkpoint: bad magic rejected ---\n");

    /* Write a file with garbage in place of the magic. */
    char path[300];
    snprintf(path, sizeof(path), "%s/scan_results.bin", s_tmpdir);

    FILE *f = fopen(path, "wb");
    if (!f) { check(0, "could not create bad-magic file"); return; }
    fwrite("BADMAGIC", 8, 1, f);
    uint32_t ver = CP_VERSION;
    fwrite(&ver, 4, 1, f);
    fclose(f);

    globals_alloc();
    bool ok = cp_load_scan();
    check(!ok, "cp_load_scan rejects bad magic");
    globals_free();

    unlink(path);
}

/* ============================================================================
 * Test: wrong version rejected
 * ============================================================================
 */

static void test_scan_bad_version(void) {
    printf("\n--- Scan checkpoint: wrong version rejected ---\n");

    char path[300];
    snprintf(path, sizeof(path), "%s/scan_results.bin", s_tmpdir);

    FILE *f = fopen(path, "wb");
    if (!f) { check(0, "could not create bad-version file"); return; }
    fwrite(CP_SCAN_MAGIC, 8, 1, f);
    uint32_t ver = CP_VERSION + 99;  /* wrong version */
    fwrite(&ver, 4, 1, f);
    fclose(f);

    globals_alloc();
    bool ok = cp_load_scan();
    check(!ok, "cp_load_scan rejects wrong version");
    globals_free();

    unlink(path);
}

/* ============================================================================
 * Test: extracted IDs round-trip
 * ============================================================================
 */

static void test_extracted_ids_roundtrip(void) {
    printf("\n--- Extracted IDs checkpoint: round-trip ---\n");

    globals_alloc();

    /* The IDs we want to persist. */
    uint64_t save_ids[] = {1001, 2002, 3003, 5005, 99999};
    uint32_t save_count = (uint32_t)(sizeof(save_ids) / sizeof(save_ids[0]));

    cp_extract_stats_t save_stats = {
        .files_found     = 12345,
        .files_recovered = 10000,
        .files_skipped   = 20,
        .files_zero_byte = 135,
        .files_failed    = 0,
    };
    cp_save_extracted(save_ids, save_count, &save_stats);

    /* Reload.  done_set is per-slot; since the inodes are not in the hash the
     * done_set entries won't be set, but the raw IDs array, count, and stats
     * still round-trip correctly. */
    bool    done_set[TEST_MAX_INODES] = {false};
    uint64_t loaded_ids[TEST_MAX_INODES];
    cp_extract_stats_t loaded_stats = {0};
    uint32_t loaded = cp_load_extracted(done_set, loaded_ids, TEST_MAX_INODES,
                                        &loaded_stats);

    check(loaded == save_count, "loaded count matches saved count");

    bool ids_match = true;
    for (uint32_t i = 0; i < save_count && i < loaded; i++) {
        if (loaded_ids[i] != save_ids[i]) { ids_match = false; break; }
    }
    check(ids_match, "loaded IDs match saved IDs");

    check(loaded_stats.files_found     == 12345, "stats.files_found round-trips");
    check(loaded_stats.files_recovered == 10000, "stats.files_recovered round-trips");
    check(loaded_stats.files_skipped   == 20,    "stats.files_skipped round-trips");
    check(loaded_stats.files_zero_byte == 135,   "stats.files_zero_byte round-trips");

    globals_free();
}

/* ============================================================================
 * Test: extracted IDs — 0 IDs
 * ============================================================================
 */

static void test_extracted_ids_zero(void) {
    printf("\n--- Extracted IDs checkpoint: zero IDs ---\n");

    globals_alloc();

    cp_save_extracted(NULL, 0, NULL);

    bool     done_set[1] = {false};
    uint32_t loaded = cp_load_extracted(done_set, NULL, 0, NULL);
    check(loaded == 0, "zero-count checkpoint loads as 0");

    globals_free();
}

/* ============================================================================
 * Test: extracted IDs — bad magic rejected
 * ============================================================================
 */

static void test_extracted_bad_magic(void) {
    printf("\n--- Extracted IDs checkpoint: bad magic rejected ---\n");

    char path[300];
    snprintf(path, sizeof(path), "%s/extracted_ids.bin", s_tmpdir);

    FILE *f = fopen(path, "wb");
    if (!f) { check(0, "could not create bad-magic file"); return; }
    fwrite("BADMAGIC", 8, 1, f);
    uint32_t ver = CP_VERSION;
    uint32_t cnt = 0;
    fwrite(&ver, 4, 1, f);
    fwrite(&cnt, 4, 1, f);
    fclose(f);

    globals_alloc();
    bool     done_set[1] = {false};
    uint32_t loaded = cp_load_extracted(done_set, NULL, TEST_MAX_INODES, NULL);
    check(loaded == 0, "cp_load_extracted returns 0 for bad magic");
    globals_free();

    unlink(path);
}

/* ============================================================================
 * Test: symlink_target round-trip (CP_VERSION 5)
 * ============================================================================
 */

static void test_scan_symlink_roundtrip(void) {
    printf("\n--- Scan checkpoint: symlink_target round-trip (V5) ---\n");

    globals_alloc();

    g_partition_offset = 0x1000;
    g_block_size       = 4096;
    g_container_offset = 0x2000;

    /* Populate one symlink inode directly in the flat array. */
    g_inodes[0].inode_id       = 42;
    g_inodes[0].mode           = S_IFLNK | 0777;
    g_inodes[0].size           = 11;  /* length of "python3.12\0" */
    g_inodes[0].symlink_target = strdup("python3.12");
    g_inodes[0].mod_time       = 1234567890ULL;
    g_inode_count              = 1;

    cp_save_scan(/*complete=*/true);

    globals_free();
    globals_alloc();
    geometry_clear();

    bool ok = cp_load_scan();
    check(ok,                  "cp_load_scan returns true for V5 checkpoint");
    check(g_inode_count == 1,  "one inode loaded from V5 checkpoint");
    check(g_inodes[0].symlink_target != NULL, "symlink_target non-NULL after load");
    check(g_inodes[0].symlink_target &&
          strcmp(g_inodes[0].symlink_target, "python3.12") == 0,
          "symlink_target value correct after load");
    check((g_inodes[0].mode & S_IFMT) == S_IFLNK, "mode is S_IFLNK after load");

    globals_free();
}

/* ============================================================================
 * Test: V4 checkpoint loads successfully with symlink_target == NULL
 * ============================================================================
 */

static void test_scan_v4_compat(void) {
    printf("\n--- Scan checkpoint: V4 backward compat (no symlink field) ---\n");

    char path[300];
    snprintf(path, sizeof(path), "%s/scan_results.bin", s_tmpdir);

    FILE *f = fopen(path, "wb");
    if (!f) { check(0, "could not create V4 file"); return; }

    /* Write a well-formed V4 header. */
    fwrite(CP_SCAN_MAGIC, 8, 1, f);
    uint32_t ver = 4;   fwrite(&ver, 4, 1, f);
    uint64_t poff = 0x1000ULL; fwrite(&poff, 8, 1, f);
    uint32_t bs   = 4096;      fwrite(&bs,   4, 1, f);
    uint64_t coff = 0x2000ULL; fwrite(&coff, 8, 1, f);
    uint8_t enc = 0, cs = 0, done = 1, pad = 0;
    fwrite(&enc, 1, 1, f); fwrite(&cs, 1, 1, f);
    fwrite(&done,1, 1, f); fwrite(&pad,1, 1, f);
    uint32_t dc=0, ic=1, pc=0, del=0;
    fwrite(&dc,4,1,f); fwrite(&ic,4,1,f); fwrite(&pc,4,1,f); fwrite(&del,4,1,f);

    /* Write one inode in V4 format: no symlink_len field (104 bytes). */
    cp_inode_hdr_t v4hdr = {0};
    v4hdr.inode_id = 99;
    v4hdr.mode     = S_IFLNK | 0777;
    /* Write sizeof(hdr)-sizeof(uint32_t) bytes: omits the trailing symlink_len */
    fwrite(&v4hdr, sizeof(v4hdr) - sizeof(uint32_t), 1, f);

    fclose(f);

    globals_alloc();
    geometry_clear();

    bool ok = cp_load_scan();
    check(ok,                  "V4 checkpoint loads successfully");
    check(g_inode_count == 1,  "one inode loaded from V4 checkpoint");
    check(g_inodes[0].symlink_target == NULL,
          "symlink_target is NULL for V4 inode (expected — no symlink field)");
    check(g_inodes[0].inode_id == 99, "inode_id round-trips from V4");

    globals_free();
    unlink(path);
}

/* ============================================================================
 * main
 * ============================================================================
 */

int main(void) {
    printf("test_checkpoint\n");

    if (make_tmpdir() != 0) {
        fprintf(stderr, "FATAL: could not create temp dir: %s\n", strerror(errno));
        return 1;
    }

    g_logs_dir = s_tmpdir;

    test_scan_geometry_roundtrip();
    test_scan_incomplete_rejected();
    test_scan_bad_magic();
    test_scan_bad_version();
    test_scan_symlink_roundtrip();
    test_scan_v4_compat();
    test_extracted_ids_roundtrip();
    test_extracted_ids_zero();
    test_extracted_bad_magic();

    rm_rf(s_tmpdir);

    printf("\n%d/%d passed", s_run - s_failed, s_run);
    if (s_failed == 0)
        printf("  OK\n");
    else
        printf("  FAILED\n");

    return s_failed > 0 ? 1 : 0;
}
