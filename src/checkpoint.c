/*
 * checkpoint.c — binary checkpoint save/load.
 */

#define _GNU_SOURCE
#include "checkpoint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include "apfs_globals.h"
#include "util.h"
#include "log.h"

/* ============================================================================
 * Scan checkpoint
 * ============================================================================
 */

/* Return the directory to use for checkpoint files. */
static const char *cp_dir(void) {
    return (g_logs_dir && g_logs_dir[0]) ? g_logs_dir : ".";
}

void cp_save_scan(bool complete) {

    /* Count unique resolved paths (avoid writing duplicate inode paths) */
    uint32_t path_count = 0;
    bool *counted = calloc(g_max_inodes, sizeof(bool));
    if (!counted) return;
    for (int i = 0; i < g_drec_count; i++) {
        int64_t idx = get_inode_idx(g_drecs[i].file_inode);
        if (idx >= 0 && g_paths && g_paths[idx] && !counted[idx]) {
            counted[idx] = true;
            path_count++;
        }
    }

    const char *dir = cp_dir();
    char tmp_path[MAX_PATH_LEN], final_path[MAX_PATH_LEN];
    snprintf(final_path, sizeof(final_path),
             "%s/scan_results.bin", dir);
    snprintf(tmp_path,   sizeof(tmp_path),
             "%s/scan_results.bin.tmp", dir);

    FILE *f = fopen(tmp_path, "wb");
    if (!f) { free(counted); return; }

    /* Header */
    fwrite(CP_SCAN_MAGIC, 8, 1, f);
    uint32_t ver = CP_VERSION;
    fwrite(&ver, 4, 1, f);
    fwrite(&g_partition_offset,  8, 1, f);
    fwrite(&g_block_size,        4, 1, f);
    fwrite(&g_container_offset,  8, 1, f);
    uint8_t enc  = g_encryption_enabled ? 1 : 0;
    uint8_t cs   = g_case_sensitive     ? 1 : 0;
    uint8_t done = complete             ? 1 : 0;
    uint8_t pad  = 0;
    fwrite(&enc,  1, 1, f);
    fwrite(&cs,   1, 1, f);
    fwrite(&done, 1, 1, f);
    fwrite(&pad,  1, 1, f);
    uint32_t dc = (uint32_t)g_drec_count;
    uint32_t ic = (uint32_t)g_inode_count;
    uint32_t pc = path_count;
    uint32_t del = (uint32_t)g_deleted_count;
    fwrite(&dc, 4, 1, f);
    fwrite(&ic, 4, 1, f);
    fwrite(&pc, 4, 1, f);
    fwrite(&del, 4, 1, f);

    /* Drecs */
    fwrite(g_drecs, sizeof(drec_t), g_drec_count, f);

    /* Inodes (variable-length: extents + decmpfs follow each header) */
    for (int i = 0; i < g_inode_count; i++) {
        inode_t *ino = &g_inodes[i];
        uint32_t slink_len = (ino->symlink_target && ino->symlink_target[0])
                             ? (uint32_t)(strlen(ino->symlink_target) + 1) : 0;
        cp_inode_hdr_t hdr = {
            .inode_id          = ino->inode_id,
            .parent_id         = ino->parent_id,
            .size              = ino->size,
            .uncompressed_size = ino->uncompressed_size,
            .default_crypto_id = ino->default_crypto_id,
            .create_time       = ino->create_time,
            .mod_time          = ino->mod_time,
            .access_time       = ino->access_time,
            .change_time       = ino->change_time,
            .mode              = ino->mode,
            .compression_type  = ino->compression_type,
            .extent_count      = (uint32_t)ino->extent_count,
            .decmpfs_len       = (uint32_t)ino->decmpfs_len,
            .uid               = ino->uid,
            .gid               = ino->gid,
            .bsd_flags         = ino->bsd_flags,
            .is_dir            = ino->is_dir,
            .is_compressed     = ino->is_compressed,
            .symlink_len       = slink_len,
        };
        fwrite(&hdr, sizeof(hdr), 1, f);
        if (ino->extent_count > 0 && ino->extents)
            fwrite(ino->extents, sizeof(extent_t), ino->extent_count, f);
        if (ino->decmpfs_len > 0 && ino->decmpfs_data)
            fwrite(ino->decmpfs_data, 1, ino->decmpfs_len, f);
        if (slink_len > 0)
            fwrite(ino->symlink_target, 1, slink_len, f);
    }

    /* Paths: (inode_id, path_len, path bytes) */
    memset(counted, 0, g_max_inodes);
    for (int i = 0; i < g_drec_count; i++) {
        uint64_t inode_id = g_drecs[i].file_inode;
        int64_t  idx      = get_inode_idx(inode_id);
        if (idx >= 0 && g_paths && g_paths[idx] && !counted[idx]) {
            counted[idx] = true;
            uint32_t plen = (uint32_t)(strlen(g_paths[idx]) + 1);
            fwrite(&inode_id, 8, 1, f);
            fwrite(&plen,     4, 1, f);
            fwrite(g_paths[idx], 1, plen, f);
        }
    }

    /* Deleted files */
    if (g_deleted_count > 0)
        fwrite(g_deleted, sizeof(deleted_file_t), g_deleted_count, f);

    bool write_ok = !ferror(f);
    fclose(f);
    free(counted);

    if (!write_ok) {
        LOG_NORMAL("Warning: I/O error writing scan checkpoint, discarding");
        unlink(tmp_path);
        return;
    }
    if (rename(tmp_path, final_path) != 0) {
        LOG_NORMAL("Warning: could not rename checkpoint: %s", strerror(errno));
        unlink(tmp_path);
    } else {
        LOG_EXEC_ONLY("Checkpoint saved to %s", final_path);
    }
}

bool cp_load_scan(void) {
    const char *dir = cp_dir();
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/scan_results.bin", dir);

    FILE *f = fopen(path, "rb");
    if (!f) return false;

    char     magic[8];
    uint32_t ver;
    if (fread(magic, 8, 1, f) != 1 ||
        memcmp(magic, CP_SCAN_MAGIC, 8) != 0) { fclose(f); return false; }
    /* Accept CP_VERSION 4 (no symlink_len field) and CP_VERSION 5+ for
     * backward compatibility — a V4 checkpoint loaded with V5 code treats
     * symlink_target as NULL for all inodes, which is the same behaviour as
     * before CP_VERSION 5 was introduced. */
    if (fread(&ver, 4, 1, f) != 1 ||
        (ver != 4 && ver != CP_VERSION)) { fclose(f); return false; }

    uint32_t dc, ic, pc, del, bs;
    if (fread(&g_partition_offset,  8, 1, f) != 1) { fclose(f); return false; }
    if (fread(&bs, 4, 1, f) != 1)                  { fclose(f); return false; }
    g_block_size = bs;
    if (fread(&g_container_offset,  8, 1, f) != 1) { fclose(f); return false; }
    uint8_t enc, cs, done, pad;
    if (fread(&enc,  1, 1, f) != 1) { fclose(f); return false; }
    if (fread(&cs,   1, 1, f) != 1) { fclose(f); return false; }
    if (fread(&done, 1, 1, f) != 1) { fclose(f); return false; }
    if (fread(&pad,  1, 1, f) != 1) { fclose(f); return false; }
    g_encryption_enabled = (enc  != 0);
    g_case_sensitive     = (cs   != 0);

    /*
     * Incomplete checkpoint (Ctrl-C during scan): geometry globals are now
     * restored so Phase 0 can be skipped, but the scan data is garbage.
     * Return false so main() re-runs the full scan.
     */
    if (!done) { fclose(f); return false; }
    if (fread(&dc, 4, 1, f) != 1) { fclose(f); return false; }
    if (fread(&ic, 4, 1, f) != 1) { fclose(f); return false; }
    if (fread(&pc, 4, 1, f) != 1) { fclose(f); return false; }
    if (fread(&del, 4, 1, f) != 1) { fclose(f); return false; }

    if (dc > g_drec_capacity) {
        drec_t *new_drecs = realloc(g_drecs, dc * sizeof(drec_t));
        if (!new_drecs) { fclose(f); return false; }
        g_drecs        = new_drecs;
        g_drec_capacity = dc;
    }

    while (ic > g_max_inodes) {
        uint32_t new_max    = g_max_inodes * 2;
        inode_t *new_inodes = realloc(g_inodes, new_max * sizeof(inode_t));
        if (!new_inodes) { fclose(f); return false; }
        memset(new_inodes + g_max_inodes, 0,
               (new_max - g_max_inodes) * sizeof(inode_t));
        g_inodes     = new_inodes;
        g_max_inodes = new_max;
    }

    if (fread(g_drecs, sizeof(drec_t), dc, f) != dc) { fclose(f); return false; }
    if (dc > (uint32_t)INT_MAX) { fclose(f); return false; }  /* #17 */
    g_drec_count = (int)dc;

    /* Free any extents/decmpfs/symlink buffers held by previously loaded
     * inodes, clear the hash table, and reset the count before zeroing.
     * Without this, a double-load leaks memory and the main cleanup loop
     * (which walks g_inode_count entries) would over/under-free. */
    for (int i = 0; i < g_inode_count; i++) {
        free(g_inodes[i].extents);
        free(g_inodes[i].decmpfs_data);
        free(g_inodes[i].symlink_target);
    }
    g_inode_count = 0;
    if (g_inode_hash)
        memset(g_inode_hash, 0, g_inode_hash_capacity * sizeof(inode_t *));
    memset(g_inodes, 0, g_max_inodes * sizeof(inode_t));
    /* V4 checkpoints have a 4-byte-shorter inode header (no symlink_len).
     * Read only the bytes that exist on disk; the rest stay 0. */
    size_t inode_hdr_size = (ver >= 5) ? sizeof(cp_inode_hdr_t)
                                       : sizeof(cp_inode_hdr_t) - sizeof(uint32_t);
    for (uint32_t i = 0; i < ic; i++) {
        cp_inode_hdr_t hdr = {0};
        if (fread(&hdr, inode_hdr_size, 1, f) != 1) { fclose(f); return false; }

        inode_t *ino = get_or_create_inode(hdr.inode_id);
        if (!ino) { fclose(f); return false; }
        ino->parent_id         = hdr.parent_id;
        ino->size              = hdr.size;
        ino->uncompressed_size = hdr.uncompressed_size;
        ino->default_crypto_id = hdr.default_crypto_id;
        ino->create_time       = hdr.create_time;
        ino->mod_time          = hdr.mod_time;
        ino->access_time       = hdr.access_time;
        ino->change_time       = hdr.change_time;
        ino->mode              = hdr.mode;
        ino->compression_type  = hdr.compression_type;
        ino->uid               = hdr.uid;
        ino->gid               = hdr.gid;
        ino->bsd_flags         = hdr.bsd_flags;
        ino->is_dir            = hdr.is_dir;
        ino->is_compressed     = hdr.is_compressed;

        /* 65536: one full APFS B-tree node worth of extents — a safe upper bound */
        if (hdr.extent_count > 0 && hdr.extent_count <= 65536) {
            ino->extents = malloc(hdr.extent_count * sizeof(extent_t));
            if (!ino->extents) { fclose(f); return false; }
            if (fread(ino->extents, sizeof(extent_t), hdr.extent_count, f)
                    != hdr.extent_count) {
                free(ino->extents); ino->extents = NULL;
                fclose(f); return false;
            }
            ino->extent_count    = (int)hdr.extent_count;
            ino->extent_capacity = (int)hdr.extent_count;
        } else if (hdr.extent_count > 65536) {
            /* Pathological value: skip payload bytes so the next inode header
             * is read from the correct position.  Without this seek the stream
             * drifts and every subsequent inode is silently corrupted. */
            long skip = (long)(hdr.extent_count * sizeof(extent_t));
            if (fseek(f, skip, SEEK_CUR) != 0) { fclose(f); return false; }
        }

        if (hdr.decmpfs_len > 0 && hdr.decmpfs_len <= 65536) {  /* #16: cap */
            ino->decmpfs_data = malloc(hdr.decmpfs_len);
            if (!ino->decmpfs_data) { fclose(f); return false; }
            if (fread(ino->decmpfs_data, 1, hdr.decmpfs_len, f)
                    != hdr.decmpfs_len) {
                free(ino->decmpfs_data); ino->decmpfs_data = NULL;
                fclose(f); return false;
            }
            ino->decmpfs_len = hdr.decmpfs_len;
        } else if (hdr.decmpfs_len > 65536) {
            if (fseek(f, (long)hdr.decmpfs_len, SEEK_CUR) != 0) { fclose(f); return false; }
        }

        /* CP_VERSION 5: symlink_target bytes follow decmpfs data.
         * V4 checkpoints have symlink_len==0 (from zero-init of hdr). */
        if (hdr.symlink_len > 0 && hdr.symlink_len < MAX_PATH_LEN) {
            char *sbuf = malloc(hdr.symlink_len);
            if (!sbuf) { fclose(f); return false; }
            if (fread(sbuf, 1, hdr.symlink_len, f) != hdr.symlink_len) {
                free(sbuf); fclose(f); return false;
            }
            sbuf[hdr.symlink_len - 1] = '\0';
            ino->symlink_target = sbuf;
        } else if (hdr.symlink_len >= MAX_PATH_LEN) {
            if (fseek(f, (long)hdr.symlink_len, SEEK_CUR) != 0) { fclose(f); return false; }
        }
    }

    if (!g_paths) {
        g_paths = calloc(g_max_inodes, sizeof(char *));
        if (!g_paths) { fclose(f); return false; }
    }
    for (uint32_t i = 0; i < pc; i++) {
        uint64_t inode_id;
        uint32_t plen;
        if (fread(&inode_id, 8, 1, f) != 1) { fclose(f); return false; }
        if (fread(&plen, 4, 1, f) != 1 ||
            plen == 0 || plen > MAX_PATH_LEN) { fclose(f); return false; }
        char *p = malloc(plen);
        if (!p) { fclose(f); return false; }
        if (fread(p, 1, plen, f) != plen) { free(p); fclose(f); return false; }
        p[plen - 1] = '\0';
        /* #15: sanitize path before storing to prevent traversal attacks. */
        char safe[MAX_PATH_LEN];
        sanitize_path(p, safe, sizeof(safe));
        free(p);
        p = strdup(safe);
        if (!p) { fclose(f); return false; }
        int64_t idx = get_inode_idx(inode_id);
        if (idx >= 0) {
            free(g_paths[idx]);
            g_paths[idx] = p;
        } else {
            free(p);
        }
    }

    if (del > 0) {
        if (del > g_deleted_capacity) {
            deleted_file_t *new_del = realloc(g_deleted,
                                              del * sizeof(deleted_file_t));
            if (!new_del) { fclose(f); return false; }
            g_deleted          = new_del;
            g_deleted_capacity = del;
        }
        if (fread(g_deleted, sizeof(deleted_file_t), del, f) != del) {
            fclose(f); return false;
        }
    }
    g_deleted_count = (int)del;

    fclose(f);
    return true;
}

/* ============================================================================
 * Extracted checkpoint
 * ============================================================================
 */

void cp_save_extracted(uint64_t *ids, uint32_t count, const cp_extract_stats_t *stats) {
    const char *dir = cp_dir();
    char tmp_path[MAX_PATH_LEN], final_path[MAX_PATH_LEN];
    snprintf(final_path, sizeof(final_path),
             "%s/extracted_ids.bin", dir);
    snprintf(tmp_path,   sizeof(tmp_path),
             "%s/extracted_ids.bin.tmp", dir);

    FILE *f = fopen(tmp_path, "wb");
    if (!f) return;

    uint32_t ver = CP_VERSION;
    fwrite(CP_DONE_MAGIC, 8, 1, f);
    fwrite(&ver, 4, 1, f);

    cp_extract_stats_t zero = {0};
    fwrite(stats ? stats : &zero, sizeof(cp_extract_stats_t), 1, f);

    fwrite(&count, 4, 1, f);
    if (count > 0 && ids) fwrite(ids, 8, count, f);

    bool write_ok = !ferror(f);
    fclose(f);
    if (!write_ok) { unlink(tmp_path); return; }
    if (rename(tmp_path, final_path) != 0) unlink(tmp_path);
}

uint32_t cp_load_extracted(bool *done_set, uint64_t *ids, uint32_t max_ids,
                           cp_extract_stats_t *stats_out) {
    const char *dir = cp_dir();
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path),
             "%s/extracted_ids.bin", dir);

    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    char     magic[8];
    uint32_t ver, count;
    if (fread(magic, 8, 1, f) != 1 ||
        memcmp(magic, CP_DONE_MAGIC, 8) != 0) { fclose(f); return 0; }
    if (fread(&ver,   4, 1, f) != 1 || ver != CP_VERSION) { fclose(f); return 0; }

    cp_extract_stats_t stats_buf = {0};
    if (fread(&stats_buf, sizeof(cp_extract_stats_t), 1, f) != 1) {
        fclose(f); return 0;
    }
    if (stats_out) *stats_out = stats_buf;

    if (fread(&count, 4, 1, f) != 1) { fclose(f); return 0; }

    /* #6: cap against caller-supplied buffer size to prevent heap overflow. */
    if (count > max_ids) count = max_ids;

    uint32_t loaded = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t inode_id;
        if (fread(&inode_id, 8, 1, f) != 1) break;
        int64_t idx = get_inode_idx(inode_id);
        if (idx >= 0) done_set[idx] = true;
        if (ids) ids[loaded] = inode_id;
        loaded++;
    }
    fclose(f);
    return loaded;
}

/* ============================================================================
 * Possibly-truncated + path-collision persistence
 * ============================================================================
 *
 * Saved to logs/pt_collisions.bin after each successful run; loaded at the
 * start of a resumed extraction so the consolidated recovery_summary.md
 * reflects data from all runs in this output directory.
 *
 * On --re-extract the caller unlinks the file so history is cleared.
 * On --no-resume archive_previous_run() moves the entire logs/ directory so
 * the file is no longer present when the new run starts.
 */

#define PT_COLL_MAGIC   "APFSPTCL"
#define PT_COLL_VERSION ((uint32_t)1)

void cp_save_pt_collisions(void) {
    const char *dir = cp_dir();
    char tmp_path[MAX_PATH_LEN], final_path[MAX_PATH_LEN];
    snprintf(final_path, sizeof(final_path), "%s/pt_collisions.bin", dir);
    snprintf(tmp_path,   sizeof(tmp_path),   "%s/pt_collisions.bin.tmp", dir);

    FILE *f = fopen(tmp_path, "wb");
    if (!f) return;

    uint32_t ver   = PT_COLL_VERSION;
    uint32_t ptc   = (g_possibly_truncated_count > 0)
                   ? (uint32_t)g_possibly_truncated_count : 0;
    uint32_t collc = (g_collision_count > 0)
                   ? (uint32_t)g_collision_count : 0;

    fwrite(PT_COLL_MAGIC, 8, 1, f);
    fwrite(&ver,   sizeof(ver),   1, f);
    fwrite(&ptc,   sizeof(ptc),   1, f);
    fwrite(&collc, sizeof(collc), 1, f);

    if (ptc > 0)
        fwrite(g_possibly_truncated, sizeof(possibly_truncated_t), ptc, f);
    if (collc > 0)
        fwrite(g_collisions, sizeof(path_collision_t), collc, f);

    bool write_ok = !ferror(f);
    fclose(f);
    if (!write_ok) { unlink(tmp_path); return; }
    rename(tmp_path, final_path);
}

void cp_load_pt_collisions(void) {
    const char *dir = cp_dir();
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/pt_collisions.bin", dir);

    FILE *f = fopen(path, "rb");
    if (!f) return;

    char     magic[8];
    uint32_t ver, ptc, collc;
    if (fread(magic, 8, 1, f) != 1 ||
        memcmp(magic, PT_COLL_MAGIC, 8) != 0) { fclose(f); return; }
    if (fread(&ver,   sizeof(ver),   1, f) != 1 ||
        ver != PT_COLL_VERSION) { fclose(f); return; }
    if (fread(&ptc,   sizeof(ptc),   1, f) != 1) { fclose(f); return; }
    if (fread(&collc, sizeof(collc), 1, f) != 1) { fclose(f); return; }

    if (ptc > 100000) ptc = 0;
    if (collc > 100000) collc = 0;

    for (uint32_t i = 0; i < ptc; i++) {
        possibly_truncated_t entry;
        if (fread(&entry, sizeof(entry), 1, f) != 1) break;
        if (g_possibly_truncated_count >= (int)g_possibly_truncated_capacity) {
            uint32_t new_cap = g_possibly_truncated_capacity == 0
                             ? ptc + 32 : g_possibly_truncated_capacity * 2;
            possibly_truncated_t *np = realloc(g_possibly_truncated,
                                               new_cap * sizeof(possibly_truncated_t));
            if (!np) break;
            g_possibly_truncated          = np;
            g_possibly_truncated_capacity = new_cap;
        }
        g_possibly_truncated[g_possibly_truncated_count++] = entry;
    }

    for (uint32_t i = 0; i < collc; i++) {
        path_collision_t entry;
        if (fread(&entry, sizeof(entry), 1, f) != 1) break;
        if (g_collision_count >= (int)g_collision_capacity) {
            uint32_t new_cap = g_collision_capacity == 0
                             ? collc + 32 : g_collision_capacity * 2;
            path_collision_t *np = realloc(g_collisions,
                                           new_cap * sizeof(path_collision_t));
            if (!np) break;
            g_collisions         = np;
            g_collision_capacity = new_cap;
        }
        g_collisions[g_collision_count++] = entry;
    }

    fclose(f);
}
