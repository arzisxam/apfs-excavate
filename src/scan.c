/*
 * scan.c — multi-threaded APFS block scanner.
 */

#define _GNU_SOURCE
#include "scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

#ifdef __APPLE__
#include <sys/mman.h>
#endif

#include "apfs_globals.h"
#include "apfs_parse.h"
#include "block_io.h"
#include "compat.h"
#include "util.h"
#include "log.h"

/* ============================================================================
 * Deleted inode heuristic
 * ============================================================================
 */

/*
 * scan_for_deleted_inodes() — look for orphaned inode records in non-B-tree
 * blocks.  Uses a lightweight heuristic: check that the first two uint64_t
 * fields look like plausible APFS inode IDs and that the mode field at
 * offset 80 identifies a regular file or directory.
 */
static void scan_for_deleted_inodes(const uint8_t *block, uint64_t block_num) {
    if (!g_enable_deleted_recovery) return;
    if (g_block_size < 88) return;  /* need at least mode field */

    uint64_t parent_id  = get_u64(block);
    uint64_t private_id = get_u64(block + 8);

    if (parent_id  == 0 || parent_id  >= 0x100000) return;
    if (private_id == 0 || private_id >= 0x100000) return;

    uint16_t mode = get_u16(block + 80);
    if (mode == 0) return;
    if ((mode & 0170000) != 0100000 && (mode & 0170000) != 0040000) return;

    pthread_mutex_lock(&g_deleted_mutex);

    if (g_deleted_count >= (int)g_deleted_capacity) {
        uint32_t new_cap = (g_deleted_capacity == 0) ? 1024 : g_deleted_capacity * 2;
        deleted_file_t *nd = realloc(g_deleted, new_cap * sizeof(deleted_file_t));
        if (!nd) { pthread_mutex_unlock(&g_deleted_mutex); return; }
        g_deleted          = nd;
        g_deleted_capacity = new_cap;
    }

    g_deleted[g_deleted_count].block_num = block_num;
    g_deleted[g_deleted_count].inode_id  = private_id;
    g_deleted_count++;

    pthread_mutex_unlock(&g_deleted_mutex);
}

/* ============================================================================
 * Worker thread
 * ============================================================================
 */

static void *scan_worker_thread(void *arg) {
    scan_task_t *task        = (scan_task_t *)arg;
    uint64_t     total       = task->total_blocks;
    bool         show_prog   = task->show_progress;
    double       start_time  = util_get_time_ms();
    int          nodes_found = 0;
    uint64_t     local_done  = 0;   /* blocks counted locally; flushed to shared_done */

    uint8_t *block      = malloc(g_block_size);
    uint8_t *zero_block = calloc(1, g_block_size);
    if (!block || !zero_block) { free(block); free(zero_block); return NULL; }

    for (uint64_t bn = task->start_block; bn < task->end_block; bn++) {
        if (g_interrupted) break;

        local_done++;

        bool parsed = false;

        /* Fast-skip zeroed blocks (common in damaged images with large empty regions). */
        size_t off = g_partition_offset + bn * g_block_size;
        if (off + g_block_size > g_data_size) continue;  /* #20: skip out-of-bounds blocks */
        /* Fast path: check first 64 bytes before the full block compare. */
        if (memcmp(g_data + off, zero_block, 64) == 0 &&
            memcmp(g_data + off, zero_block, g_block_size) == 0) {
            if (show_prog && bn % 10000 == 0) {
                atomic_fetch_add_explicit(task->shared_done, local_done,
                                          memory_order_relaxed);
                local_done = 0;
                uint64_t done = atomic_load_explicit(task->shared_done,
                                                     memory_order_relaxed);
                util_print_scan_progress(done, total, start_time);
            } else if (!show_prog && bn % 100000 == 0) {
                atomic_fetch_add_explicit(task->shared_done, local_done,
                                          memory_order_relaxed);
                local_done = 0;
            }
            continue;
        }

        if (g_encryption_enabled) {
            /* Strategy 1: plaintext + strict — catches container-level metadata. */
            (void)bio_read_block(bn, block);
            if (apfs_is_valid_btree_node(block)) {
                uint64_t xid   = get_u64(block + 24);
                uint16_t flags = get_u16(block + APFS_BTNODE_FLAGS_OFF);
                if ((g_min_xid == 0 || xid >= g_min_xid) && (flags & BTNODE_LEAF)) {
                    apfs_parse_btree_node(block, bn);
                    nodes_found++;
                    parsed = true;
                }
            }

            /* Strategy 2: decrypted + strict — catches volume-level encrypted metadata.
             * We only try this when strategy 1 failed; decrypting a plaintext block
             * produces garbage that can pass the lenient validator. */
            if (!parsed) {
                (void)bio_read_decrypt(bn, block);
                if (apfs_is_valid_btree_node(block)) {
                    uint16_t flags = get_u16(block + APFS_BTNODE_FLAGS_OFF);
                    if (flags & BTNODE_LEAF) {
                        apfs_parse_btree_node(block, bn);
                        nodes_found++;
                        parsed = true;
                    }
                }
            }

            /* Strategy 3: plaintext + lenient — catches damaged but readable plaintext. */
            if (!parsed) {
                (void)bio_read_block(bn, block);
                if (apfs_is_partial_btree_node(block)) {
                    uint16_t flags = get_u16(block + APFS_BTNODE_FLAGS_OFF);
                    if (flags & BTNODE_LEAF) {
                        apfs_parse_btree_node(block, bn);
                        nodes_found++;
                        parsed = true;
                    }
                }
            }

        } else {
            /* Unencrypted: bio_read_decrypt is a no-op pass-through. */
            (void)bio_read_decrypt(bn, block);
            if (apfs_is_valid_btree_node(block)) {
                uint16_t flags = get_u16(block + APFS_BTNODE_FLAGS_OFF);
                if (flags & BTNODE_LEAF) {
                    apfs_parse_btree_node(block, bn);
                    nodes_found++;
                    parsed = true;
                }
            } else if (apfs_is_partial_btree_node(block)) {
                uint16_t flags = get_u16(block + APFS_BTNODE_FLAGS_OFF);
                if (flags & BTNODE_LEAF) {
                    apfs_parse_btree_node(block, bn);
                    nodes_found++;
                    parsed = true;
                }
            }
        }

        /* Deleted inode heuristic on non-B-tree blocks.
         * For encrypted volumes scan both plaintext (metadata blocks that were
         * never encrypted) and decrypted (file-data blocks). */
        if (!parsed) {
            if (g_encryption_enabled) {
                (void)bio_read_block(bn, block);
                scan_for_deleted_inodes(block, bn);
                (void)bio_read_decrypt(bn, block);
                scan_for_deleted_inodes(block, bn);
            } else {
                scan_for_deleted_inodes(block, bn);
            }
        }

        if (show_prog && (bn % 10000 == 0 || bn == task->end_block - 1)) {
            atomic_fetch_add_explicit(task->shared_done, local_done,
                                      memory_order_relaxed);
            local_done = 0;
            uint64_t done = atomic_load_explicit(task->shared_done,
                                                 memory_order_relaxed);
            util_print_scan_progress(done, total, start_time);
        } else if (!show_prog && bn % 100000 == 0) {
            atomic_fetch_add_explicit(task->shared_done, local_done,
                                      memory_order_relaxed);
            local_done = 0;
        }
    }

    /* Flush any locally-counted blocks not yet reflected in shared_done. */
    if (local_done > 0)
        atomic_fetch_add_explicit(task->shared_done, local_done, memory_order_relaxed);

    task->nodes_found = nodes_found;
    free(block);
    free(zero_block);
    return NULL;
}

/* ============================================================================
 * Public interface
 * ============================================================================
 */

int scan_image(bool show_progress) {
    uint64_t total_blocks = (g_data_size - g_partition_offset) / g_block_size;
    if (total_blocks == 0) total_blocks = g_data_size / g_block_size;

#ifdef __APPLE__
    madvise(g_data, g_data_size, MADV_SEQUENTIAL);
#endif

    pthread_t   *threads = malloc(g_workers * sizeof(pthread_t));
    scan_task_t *tasks   = malloc(g_workers * sizeof(scan_task_t));
    bool        *launched = calloc(g_workers, sizeof(bool));
    if (!threads || !tasks || !launched) {
        free(threads); free(tasks); free(launched);
        return 0;
    }

    double scan_start = util_get_time_ms();
    uint64_t blk_per_worker = total_blocks / (uint64_t)g_workers;

    /* Shared atomic counter: all workers contribute; worker 0 reads it for
     * the progress bar so the display reflects total throughput, not just
     * the 1/N slice covered by one thread. */
    _Atomic uint64_t blocks_done = 0;

    for (int i = 0; i < g_workers; i++) {
        tasks[i].start_block   = (uint64_t)i * blk_per_worker;
        tasks[i].end_block     = (i == g_workers - 1) ? total_blocks
                                                       : (uint64_t)(i + 1) * blk_per_worker;
        tasks[i].total_blocks  = total_blocks;
        tasks[i].show_progress = show_progress && (i == 0);
        tasks[i].nodes_found   = 0;
        tasks[i].shared_done   = &blocks_done;

        if (pthread_create(&threads[i], NULL, scan_worker_thread, &tasks[i]) != 0) {
            LOG_ERROR("Failed to create worker thread %d, running inline", i);
            scan_worker_thread(&tasks[i]);
        } else {
            launched[i] = true;
        }
    }

    int total_nodes = 0;
    for (int i = 0; i < g_workers; i++) {
        if (launched[i]) pthread_join(threads[i], NULL);
        total_nodes += tasks[i].nodes_found;
    }

    free(launched);
    free(threads);
    free(tasks);

    if (show_progress) {
        /* After all workers finish, force the progress bar to 100% so it
         * doesn't stay stuck at 1/N when more than one worker is used. */
        util_print_scan_progress(total_blocks, total_blocks, scan_start);
        util_progress_newline();
    }
    return total_nodes;
}
