/*
 * recovery.c — path resolution and file extraction.
 */

#define _GNU_SOURCE
#include "recovery.h"

/* Number of blocks from partition start checked for zeroed head-crash zone. */
#define HEAD_CRASH_CHECK_BLOCKS 20000
/* Bytes sampled from each orphan file for content-hash deduplication. */
#define ORPHAN_DEDUP_SAMPLE     65536

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>

#ifdef __APPLE__
#include <sys/mman.h>
#endif

#include "apfs_globals.h"
#include "util.h"
#include "log.h"
#include "errors.h"
#include "compress.h"
#include "crypto.h"
#include "block_io.h"
#include "checkpoint.h"
#include "term.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#ifdef __APPLE__
#include <sys/attr.h>
#endif

/* ============================================================================
 * Metadata Restoration
 * ============================================================================
 */
static void restore_metadata(const char *path, inode_t *ino) {
    if (!path || !ino) return;

    /* Skip all POSIX metadata calls on non-POSIX output filesystems
     * (ExFAT/FAT/NTFS): they either silently no-op or, worse, cause chmod
     * to mark the file as read-only via the ExFAT read-only attribute. */
    if (g_output_nonposix || g_skip_metadata) return;

#ifdef __APPLE__
    /* Clear blocking BSD flags FIRST so utimensat / chmod / lchown can succeed.
     * UF_IMMUTABLE / SF_IMMUTABLE / UF_APPEND / SF_APPEND all cause those calls
     * to fail with EPERM on APFS.  Always call lchflags (unconditional, not
     * guarded by bsd_flags != 0) so flags written by a prior run are cleared
     * even when the inode now records bsd_flags == 0. */
    {
        uint32_t flags = ino->bsd_flags;
        flags &= ~(uint32_t)(0x00000002 | 0x00020000   /* UF_IMMUTABLE | SF_IMMUTABLE */
                           | 0x00000004 | 0x00040000); /* UF_APPEND    | SF_APPEND    */
        lchflags(path, flags);
    }
#endif

    /* 1. Timestamps (mod_time and access_time)
     *
     * APFS stores timestamps as signed int64_t nanoseconds since the Unix epoch.
     * We store them as uint64_t.  Two classes of corrupted values must be skipped:
     *   a) High bit set: negative int64_t cast to huge uint64_t → far-future date.
     *   b) Zero: epoch (1970-01-01), meaning the field was never set.
     * We also skip any timestamp that would land more than 2 years in the future
     * relative to the current clock (covers bad system-clock artifacts while still
     * allowing intentional future-dated files within a plausible range). */
    time_t now        = time(NULL);
    time_t future_cap = now + (2 * 366 * 24 * 3600); /* 2 years from today */

    /* Interpret as signed to catch negative (corrupted) values. */
    int64_t mod_ns  = (int64_t)ino->mod_time;
    int64_t acc_ns  = (int64_t)ino->access_time;

    time_t mtime_sec = (mod_ns  > 0) ? (time_t)(ino->mod_time    / 1000000000ULL) : 0;
    time_t atime_sec = (acc_ns  > 0) ? (time_t)(ino->access_time / 1000000000ULL) : 0;

    bool mtime_ok = (mtime_sec > 0 && mtime_sec <= future_cap);
    bool atime_ok = (atime_sec > 0 && atime_sec <= future_cap);

    if (mtime_ok || atime_ok) {
        struct timespec times[2];
        /* Use the valid value; fall back to the other if one is invalid. */
        times[0].tv_sec  = atime_ok ? atime_sec : mtime_sec;
        times[0].tv_nsec = atime_ok ? (long)(ino->access_time % 1000000000ULL)
                                    : (long)(ino->mod_time    % 1000000000ULL);
        times[1].tv_sec  = mtime_ok ? mtime_sec : atime_sec;
        times[1].tv_nsec = mtime_ok ? (long)(ino->mod_time    % 1000000000ULL)
                                    : (long)(ino->access_time % 1000000000ULL);
        utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW);
    }

    /* 2. Ownership */
    if (ino->uid != 0 || ino->gid != 0) {
        lchown(path, ino->uid, ino->gid);
    }

    /* 3. Permissions — clamp to a minimum safe mode so the file remains
     * accessible.  Corrupted APFS metadata sometimes stores 0000 or mode bits
     * that would make the recovered file unreadable by the recovering user.
     *   • Regular files / symlinks: ensure at least 0600 (owner read+write).
     *   • Directories:              ensure at least 0700 (owner rwx). */
    if (ino->mode != 0) {
        mode_t m = ino->mode & 07777;
        m &= ~(mode_t)(S_ISUID | S_ISGID);  /* #23: strip setuid/setgid from corrupted metadata */
        if (ino->is_dir || (ino->mode & S_IFMT) == S_IFDIR)
            m |= 0700;   /* owner rwx */
        else
            m |= 0600;   /* owner rw  */
        chmod(path, m);
    }

    /* 4. macOS-specific features */
#ifdef __APPLE__
    {
        /* Lower bound: Jan 1, 1990.  Timestamps before this on a modern APFS
         * volume are almost certainly corrupted (e.g. "Jan 24 1984" sentinel).
         * A pre-1990 born-time via setattrlist causes Finder to display the
         * directory as greyed out.  We must ALWAYS write a valid creation time
         * (not just skip) so we overwrite any bad timestamp from a prior run.
         * Fall back to mtime when create_time is invalid. */
        static const time_t CRTIME_MIN = 631152000; /* 1990-01-01 00:00:00 UTC */

        int64_t ct_ns  = (int64_t)ino->create_time;
        time_t  ct_sec = (ct_ns > 0) ? (time_t)(ino->create_time / 1000000000ULL) : 0;

        time_t use_sec  = 0;
        long   use_nsec = 0;
        if (ct_sec >= CRTIME_MIN && ct_sec <= future_cap) {
            use_sec  = ct_sec;
            use_nsec = (long)(ino->create_time % 1000000000ULL);
        } else {
            /* Corrupted creation time — fall back to mtime. */
            int64_t mt_ns  = (int64_t)ino->mod_time;
            time_t  mt_sec = (mt_ns > 0) ? (time_t)(ino->mod_time / 1000000000ULL) : 0;
            if (mt_sec >= CRTIME_MIN && mt_sec <= future_cap) {
                use_sec  = mt_sec;
                use_nsec = (long)(ino->mod_time % 1000000000ULL);
            } else {
                /* Both create_time and mod_time are invalid — use current time
                 * as last resort so we always overwrite any bad prior value. */
                use_sec  = time(NULL);
                use_nsec = 0;
            }
        }

        if (use_sec != 0) {
            struct attrlist attrList;
            memset(&attrList, 0, sizeof(attrList));
            attrList.bitmapcount = ATTR_BIT_MAP_COUNT;
            attrList.commonattr  = ATTR_CMN_CRTIME;
            struct timespec crtime = { use_sec, use_nsec };
            if (setattrlist(path, &attrList, &crtime, sizeof(crtime), FSOPT_NOFOLLOW) != 0)
                LOG_DEBUG("setattrlist crtime failed for %s: %s", path, strerror(errno));
        }
    } /* end create_time block */
    /* bsd_flags already applied (with blocking flags stripped) at the top. */
#endif
}

/* ============================================================================
 * Unrecovered file tracking
 * ============================================================================
 */

static void add_unrecovered(uint64_t inode_id, const char *path,
                             uint64_t size, const char *reason, bool is_orphan) {
    if (g_unrecovered_count >= (int)g_unrecovered_capacity) {
        uint32_t new_cap = (g_unrecovered_capacity == 0) ? 256
                                                         : g_unrecovered_capacity * 2;
        unrecovered_t *nu = realloc(g_unrecovered, new_cap * sizeof(unrecovered_t));
        if (!nu) return;
        g_unrecovered          = nu;
        g_unrecovered_capacity = new_cap;
    }
    unrecovered_t *u = &g_unrecovered[g_unrecovered_count++];
    u->inode_id  = inode_id;
    u->size      = size;
    u->is_orphan = is_orphan;
    u->kind      = UNRECOVERED_OTHER;
    snprintf(u->path,   sizeof(u->path),   "%s", path   ? path   : "");
    snprintf(u->reason, sizeof(u->reason), "%s", reason ? reason : "");
    u->path[sizeof(u->path) - 1]   = '\0';  /* defence-in-depth NUL guard */
    u->reason[sizeof(u->reason) - 1] = '\0';
}

static void add_possibly_truncated(uint64_t inode_id,
                                   const char *original_path,
                                   const char *expanded_path,
                                   uint64_t dstream_size,
                                   uint64_t extent_size,
                                   bool discarded) {
    if (g_possibly_truncated_count >= (int)g_possibly_truncated_capacity) {
        uint32_t new_cap = (g_possibly_truncated_capacity == 0)
                         ? 32 : g_possibly_truncated_capacity * 2;
        possibly_truncated_t *np = realloc(g_possibly_truncated,
                                           new_cap * sizeof(possibly_truncated_t));
        if (!np) return;
        g_possibly_truncated          = np;
        g_possibly_truncated_capacity = new_cap;
    }
    possibly_truncated_t *pt = &g_possibly_truncated[g_possibly_truncated_count++];
    pt->inode_id     = inode_id;
    pt->dstream_size = dstream_size;
    pt->extent_size  = extent_size;
    pt->discarded    = discarded;
    snprintf(pt->original_path, sizeof(pt->original_path),
             "%s", original_path ? original_path : "");
    snprintf(pt->expanded_path, sizeof(pt->expanded_path),
             "%s", expanded_path ? expanded_path : "");
}

static void add_collision(uint64_t inode_id,
                          const char *original_path,
                          const char *actual_path) {
    if (g_collision_count >= (int)g_collision_capacity) {
        uint32_t new_cap = (g_collision_capacity == 0)
                         ? 64 : g_collision_capacity * 2;
        path_collision_t *nc = realloc(g_collisions, new_cap * sizeof(path_collision_t));
        if (!nc) return;
        g_collisions         = nc;
        g_collision_capacity = new_cap;
    }
    path_collision_t *c = &g_collisions[g_collision_count++];
    c->inode_id = inode_id;
    snprintf(c->original_path, sizeof(c->original_path),
             "%s", original_path ? original_path : "");
    snprintf(c->actual_path, sizeof(c->actual_path),
             "%s", actual_path ? actual_path : "");
}

/* ============================================================================
 * Deduplication of directory records
 * ============================================================================
 */

static int compare_drec_by_file_inode(const void *a, const void *b) {
    const drec_t *da = (const drec_t *)a;
    const drec_t *db = (const drec_t *)b;
    return (da->file_inode > db->file_inode) - (da->file_inode < db->file_inode);
}

/*
 * deduplicate_drecs() — when the same inode ID appears in multiple B-tree
 * leaves (common after corruption), keep the entry whose parent is a known
 * directory.  Result: g_drecs sorted by file_inode, g_drec_count reduced.
 */
static void deduplicate_drecs(void) {
    if (g_drec_count <= 1) return;

    /* Build a boolean map: which inode indices are known directories? */
    bool *is_known_dir = calloc(g_max_inodes, sizeof(bool));
    if (!is_known_dir) return;

    for (int i = 0; i < g_inode_count; i++) {
        if (g_inodes[i].is_dir) is_known_dir[i] = true;
    }
    for (int i = 0; i < g_drec_count; i++) {
        if (g_drecs[i].is_dir) {
            int64_t idx = get_inode_idx(g_drecs[i].file_inode);
            if (idx >= 0) is_known_dir[idx] = true;
        }
    }
    /* Root directory (inode 2) is always a directory. */
    {
        int64_t root = get_inode_idx(2);
        if (root >= 0) is_known_dir[root] = true;
    }

    qsort(g_drecs, g_drec_count, sizeof(drec_t), compare_drec_by_file_inode);

    int write_idx = 0, i = 0;
    while (i < g_drec_count) {
        if (g_drecs[i].file_inode == 0) { i++; continue; }

        int  best            = i;
        int64_t bp = get_inode_idx(g_drecs[i].parent_inode);
        bool best_dir_parent = (bp >= 0) ? is_known_dir[bp] : false;

        int j = i + 1;
        while (j < g_drec_count &&
               g_drecs[j].file_inode == g_drecs[i].file_inode) {
            int64_t jp = get_inode_idx(g_drecs[j].parent_inode);
            bool jdp   = (jp >= 0) ? is_known_dir[jp] : false;
            if (jdp && !best_dir_parent) {
                best = j;
                best_dir_parent = true;
            }
            j++;
        }

        if (j - i > 1)
            LOG_EXEC_ONLY("Inode %llu: %d hard link names — extracted as \"%s\" (parent %llu)",
                          (unsigned long long)g_drecs[i].file_inode,
                          j - i,
                          g_drecs[best].name,
                          (unsigned long long)g_drecs[best].parent_inode);

        if (write_idx != best) g_drecs[write_idx] = g_drecs[best];
        write_idx++;
        i = j;
    }
    g_drec_count = write_idx;
    free(is_known_dir);
}

/* ============================================================================
 * Path resolution
 * ============================================================================
 */

static int drec_search_cmp(const void *key, const void *elem) {
    uint64_t       id = *(const uint64_t *)key;
    const drec_t  *d  = (const drec_t *)elem;
    return (id > d->file_inode) - (id < d->file_inode);
}

/*
 * resolve_path() — recursively walk the parent chain to build the full path.
 * Uses a generation counter in visited[] to detect cycles without clearing
 * the whole array on each call (O(1) per call instead of O(n)).
 */
static char *resolve_path(uint64_t inode_id, uint32_t *visited,
                           uint32_t visit_gen, int depth) {
    if (depth > 100) return NULL;
    if (inode_id == 2) return strdup("");   /* root: empty prefix */

    int64_t idx = get_inode_idx(inode_id);
    if (idx >= 0) {
        if (visited[idx] == visit_gen) return NULL;  /* cycle */
        visited[idx] = visit_gen;
    }

    drec_t *d = bsearch(&inode_id, g_drecs, g_drec_count,
                        sizeof(drec_t), drec_search_cmp);
    if (!d) return NULL;

    char *parent = resolve_path(d->parent_inode, visited, visit_gen, depth + 1);
    if (!parent) return NULL;

    size_t need = strlen(parent) + strlen(d->name) + 2;
    char  *full = malloc(need);
    if (!full) { free(parent); return NULL; }

    if (strlen(parent) > 0)
        snprintf(full, need, "%s/%s", parent, d->name);
    else
        snprintf(full, need, "%s", d->name);

    free(parent);
    return full;
}

/* ============================================================================
 * Public: recovery_build_paths
 * ============================================================================
 */

int recovery_build_paths(bool show_progress) {
    deduplicate_drecs();

    if (!g_paths) {
        g_paths = calloc(g_max_inodes, sizeof(char *));
        if (!g_paths) return 0;
    }

    uint32_t *visited = calloc(g_max_inodes, sizeof(uint32_t));
    if (!visited) return 0;

    uint32_t visit_gen = 1;
    int      resolved  = 0;
    double   start     = util_get_time_ms();

    for (int i = 0; i < g_drec_count; i++) {
        uint64_t inode_id = g_drecs[i].file_inode;
        int64_t  idx      = get_inode_idx(inode_id);
        if (idx < 0) continue;

        if (!g_paths[idx]) {
            /* Wrap visit_gen: reset visited[] on overflow (happens after ~4 billion
             * unique drecs — safe in practice but handle it correctly). */
            if (visit_gen == UINT32_MAX) {
                memset(visited, 0, g_max_inodes * sizeof(uint32_t));
                visit_gen = 1;
            } else {
                visit_gen++;
            }
            char *p = resolve_path(inode_id, visited, visit_gen, 0);
            if (p) { g_paths[idx] = p; resolved++; }
        }

        if (show_progress && (i % 100 == 0))
            util_print_progress("Resolving paths", (uint64_t)i, (uint64_t)g_drec_count, start);
    }

    if (show_progress) {
        util_print_progress("Resolving paths", (uint64_t)g_drec_count, (uint64_t)g_drec_count, start);
        util_progress_newline();
    }
    free(visited);
    return resolved;
}

/* ============================================================================
 * Extraction helpers
 * ============================================================================
 */

static int extract_work_cmp(const void *a, const void *b) {
    const extract_work_t *wa = (const extract_work_t *)a;
    const extract_work_t *wb = (const extract_work_t *)b;
    return (wa->first_phys > wb->first_phys) - (wa->first_phys < wb->first_phys);
}

/* ============================================================================
 * Public: recovery_extract_files
 * ============================================================================
 */

int recovery_extract_files(const char *files_dir, const char *orphan_dir,
                            const char *checkpoint_dir,
                            bool show_progress, int *compressed_count_out) {
    int extracted         = 0;
    *compressed_count_out = 0;

    /* ---- Allocate per-inode state ---------------------------------------- */
    bool *is_dir_inode = calloc(g_max_inodes, sizeof(bool));
    bool *already_done = calloc(g_max_inodes, sizeof(bool));
    if (!is_dir_inode || !already_done) {
        free(is_dir_inode); free(already_done); return 0;
    }

    for (int i = 0; i < g_inode_count; i++) {
        if (g_inodes[i].is_dir) {
            int64_t ix = get_inode_idx(g_inodes[i].inode_id);
            if (ix >= 0) is_dir_inode[ix] = true;
        }
    }
    for (int i = 0; i < g_drec_count; i++) {
        if (g_drecs[i].is_dir) {
            int64_t ix = get_inode_idx(g_drecs[i].file_inode);
            if (ix >= 0) is_dir_inode[ix] = true;
        }
    }

    /* ---- Resume: load previously extracted inodes ------------------------ */
    uint64_t *extracted_ids       = calloc(g_max_inodes, sizeof(uint64_t));
    uint32_t  extracted_ids_count = 0;
    if (extracted_ids && !g_no_resume) {
        extracted_ids_count = cp_load_extracted(already_done,
                                                extracted_ids, g_max_inodes,
                                                &g_cp_extract_stats);
        if (extracted_ids_count > 0) {
            char nb[32];
            LOG_NORMAL("\n  %s%sResuming: %s files already processed from previous run%s",
                       g_term_color ? T_BOLD : "", g_term_color ? T_YELLOW : "",
                       util_format_num(extracted_ids_count, nb),
                       g_term_color ? T_RESET : "");
            g_previously_extracted_count = extracted_ids_count;
        }
    }

    /* ---- Phase 4 setup: count orphans and build work list ---------------- */

    int orphaned = 0;
    {
        for (int i = 0; i < g_inode_count; i++) {
            int64_t idx = get_inode_idx(g_inodes[i].inode_id);
            if (idx >= 0 && !is_dir_inode[idx] &&
                g_inodes[i].extent_count > 0 &&
                g_paths[idx] == NULL &&
                !already_done[idx])
                orphaned++;
        }
        if (orphaned > 0) {
            char nb[32];
            LOG_EXEC_ONLY("Identified %s orphaned files for recovery",
                          util_format_num((uint64_t)orphaned, nb));
        }
    }

    extract_work_t *work      = malloc(((size_t)g_drec_count + orphaned) *
                                       sizeof(extract_work_t));
    int             work_count = 0;

    if (work) {
        /* Dedup named files by inode: same inode can appear via multiple drec
         * entries (hard links or B-tree duplicates after corruption). Without
         * dedup the work list count exceeds the scan box count and the file is
         * extracted N times (once per drec), wasting I/O and disk space. */
        bool *in_worklist = calloc(g_max_inodes, sizeof(bool));

        /* Named files */
        for (int i = 0; i < g_drec_count; i++) {
            if (g_drecs[i].is_dir) continue;
            int64_t ix = get_inode_idx(g_drecs[i].file_inode);
            if (ix < 0 || is_dir_inode[ix] || already_done[ix]) continue;
            if (in_worklist && in_worklist[ix]) continue;  /* skip duplicate inode */
            if (in_worklist) in_worklist[ix] = true;

            if (g_pilot_filter && g_paths[ix] &&
                !strstr(g_paths[ix], g_pilot_filter))
                continue;

            inode_t *ino = find_inode(g_drecs[i].file_inode);
            if (!ino) continue;
            work[work_count++] = (extract_work_t){
                .drec_idx  = i,
                .first_phys = (ino->extent_count > 0) ? ino->extents[0].physical
                                                       : UINT64_MAX
            };
        }
        /* NOTE: in_worklist is kept alive into the orphan loop below so that
         * inodes already added via the named section (redirected to orphan_dir
         * because they had no resolved path) are not added a second time. */

        /* Orphans (skipped when pilot filter is active) */
        if (orphaned > 0 && !g_pilot_filter) {
            for (int i = 0; i < g_inode_count; i++) {
                inode_t *ino = &g_inodes[i];
                int64_t  idx = get_inode_idx(ino->inode_id);
                if (idx < 0 || is_dir_inode[idx] ||
                    ino->extent_count == 0 || g_paths[idx] != NULL ||
                    already_done[idx]) continue;
                /* Skip if already in the work list via a drec entry */
                if (in_worklist && in_worklist[idx]) continue;
                work[work_count++] = (extract_work_t){
                    .drec_idx  = -(i + 1),
                    .first_phys = (ino->extent_count > 0) ? ino->extents[0].physical
                                                           : UINT64_MAX
                };
            }
        } else if (orphaned > 0 && g_pilot_filter) {
            {
                char nb[32];
                LOG_NORMAL("  Pilot mode active: skipping %s orphans to focus on %s",
                           util_format_num((uint64_t)orphaned, nb), g_pilot_filter);
            }
        }
        free(in_worklist);   /* safe to release now that both loops are done */

        g_work_count = (uint32_t)work_count;   /* expose for progress bar / summary */

        /* Set files_found in stats on the first run (when checkpoint has no stats).
         * files_found = pending work + already done in prior runs. */
        if (g_cp_extract_stats.files_found == 0)
            g_cp_extract_stats.files_found = (uint32_t)work_count + extracted_ids_count;

        /* Nothing left to extract — all inodes already checkpointed. */
        if (work_count == 0 && g_cp_extract_stats.files_found > 0) {
            if (g_term_color)
                fprintf(stdout, "\n  %sNothing left to extract%s\n\n", T_BGREEN, T_RESET);
            else
                fprintf(stdout, "\n  Nothing left to extract\n\n");
            LOG_EXEC_ONLY("Nothing left to extract — all files already processed");
            fflush(stdout);
            g_total_extracted_count = extracted_ids_count;
            free(work);
            free(is_dir_inode);
            free(already_done);
            free(extracted_ids);
            return 0;
        }

        log_step_header("Preparing for file extraction");

        LOG_EXEC_ONLY("Sorting work list physically for optimal I/O");
        qsort(work, work_count, sizeof(extract_work_t), extract_work_cmp);

        /* Disk space check: sum sizes of PENDING work items only (already-extracted
         * files are not in the work list, so this is accurate on resumed runs). */
        {
            uint64_t needed = 0;
            for (int w = 0; w < work_count; w++) {
                int      d_idx = work[w].drec_idx;
                inode_t *ino2  = (d_idx < 0)
                    ? &g_inodes[-(d_idx + 1)]
                    : find_inode(g_drecs[d_idx].file_inode);
                if (ino2 && !ino2->is_dir && ino2->size > 0)
                    needed += ino2->size;
            }
            struct statvfs vfs;
            if (statvfs(checkpoint_dir, &vfs) == 0) {
                uint64_t avail = (uint64_t)vfs.f_bavail * (uint64_t)vfs.f_frsize;
                char ns[32], na[32];
                LOG_EXEC_ONLY("Disk space — needed: ~%s  available: %s",
                              util_format_size(needed, ns),
                              util_format_size(avail, na));
                if (avail < needed) {
                    LOG_WARN("Insufficient free space — extraction may be incomplete. "
                             "Free at least %s more on the destination.",
                             util_format_size(needed - avail, ns));
                }
            }
        }
    }

    LOG_OK("Preparation completed");

    /* ---- Phase 4: extract ------------------------------------------------ */
    {
        char nb[32];
        LOG_PHASE(4, "Extracting files");
        LOG_EXEC_ONLY("Extracting %s files to %s",
                      util_format_num((uint64_t)work_count, nb), files_dir);
    }

    uint8_t *block   = malloc(g_block_size);
    uint8_t *raw_buf = malloc(g_block_size); /* #5: pre-alloc crypto read buf */
    if (!block || !raw_buf) {
        free(block); free(raw_buf);
        free(work); free(is_dir_inode); free(already_done); free(extracted_ids);
        return 0;
    }

#ifdef __APPLE__
    madvise(g_data, g_data_size, MADV_RANDOM);
#endif

    /* Detect head crash zone: contiguous zeroed blocks at partition start. */
    uint64_t head_crash_zone = 0;
    {
        uint64_t check_blocks = HEAD_CRASH_CHECK_BLOCKS;
        if (g_data_size > 0) {
            uint64_t part_blks = (g_data_size - g_partition_offset) / g_block_size;
            if (check_blocks > part_blks / 10) check_blocks = part_blks / 10;
        }
        uint64_t zeroed = 0;
        for (uint64_t bn = 0; bn < check_blocks; bn++) {
            uint64_t off = g_partition_offset + bn * g_block_size;
            if (off + g_block_size > g_data_size) break;
            const uint8_t *b = g_data + off;
            bool all_zero = true;
            for (size_t k = 0; k < g_block_size; k++) {
                if (b[k] != 0) { all_zero = false; break; }
            }
            if (all_zero) zeroed++; else break;
        }
        if (zeroed > 1000) {
            head_crash_zone = zeroed;
            {
                char nb[32];
                LOG_WARN("Head crash detected: %s blocks destroyed from partition start",
                         util_format_num(head_crash_zone, nb));
            }
        }
    }

    double extract_start = util_get_time_ms();

    typedef struct { uint64_t file_size; uint8_t sha[32]; uint64_t inode_id; } orphan_sig_t;
    int           sig_capacity   = orphaned > 0 ? orphaned : 256;
    orphan_sig_t *orphan_sigs    = calloc((size_t)sig_capacity, sizeof(orphan_sig_t));
    int           orphan_sig_cnt = 0;
    int           orphan_dup_cnt = 0;
    EVP_MD_CTX   *sha_ctx        = EVP_MD_CTX_new(); /* reused per-orphan, NULL-safe */

    for (int w = 0; w < work_count; w++) {
        if (g_interrupted) {
            LOG_EXEC_ONLY("Interrupted — stopping extraction.");
            break;
        }

        int      d_idx     = work[w].drec_idx;
        inode_t *ino       = NULL;
        char     full_path[MAX_PATH_LEN] = {0};
        char     safe_path[MAX_PATH_LEN] = {0};
        const char *orig_path = NULL;
        int64_t  in_idx    = -1;
        uint64_t fi        = 0;
        bool     is_orphan = (d_idx < 0);

        if (!is_orphan) {
            fi     = g_drecs[d_idx].file_inode;
            in_idx = get_inode_idx(fi);
            ino    = find_inode(fi);
            if (ino && in_idx >= 0 && g_paths[in_idx]) {
                orig_path = g_paths[in_idx];
                sanitize_path(orig_path, safe_path, sizeof(safe_path));
                int n = snprintf(full_path, sizeof(full_path),
                                 "%s/%s", files_dir, safe_path);
                if (n < 0 || (size_t)n >= sizeof(full_path)) {
                    ERR_ADD_ERROR("path too long, skipping", fi, orig_path);
                    add_unrecovered(fi, orig_path, ino ? ino->size : 0,
                                    "path too long", false);
                    continue;
                }
                /* An empty safe_path means the drec name is empty/garbage
                 * (e.g. corrupted inode at the APFS root level).  Clear
                 * full_path so the "no resolved path" branch below redirects
                 * it to the orphan directory instead of colliding with
                 * files_dir itself and producing recovered_files_<inode> at
                 * the output-dir root.
                 * A filename component of ":" is the HFS+ display form of "/"
                 * — a corrupted drec entry; redirect to orphans regardless of
                 * depth in the tree (the root-level case has safe_path == ":",
                 * but nested entries have safe_path == "some/dir/:"). */
                {
                    const char *fn = strrchr(safe_path, '/');
                    fn = fn ? fn + 1 : safe_path;
                    if (safe_path[0] == '\0' || strcmp(fn, ":") == 0)
                        full_path[0] = '\0';
                }
            }
        } else {
            int in_tbl_idx = -(d_idx + 1);
            ino    = &g_inodes[in_tbl_idx];
            fi     = ino->inode_id;
            in_idx = get_inode_idx(fi);
            mkdir(orphan_dir, 0755);
            int n = snprintf(full_path, sizeof(full_path),
                             "%s/file_%llu.dat",
                             orphan_dir, (unsigned long long)fi);
            if (n < 0 || (size_t)n >= sizeof(full_path)) {
                ERR_ADD_ERROR("orphan path too long, skipping", fi, orphan_dir);
                continue;
            }
        }

        /* Named-file inode with no resolved path — redirect to orphans so the
         * data is not silently lost. */
        if (!is_orphan && full_path[0] == '\0') {
            mkdir(orphan_dir, 0755);
            int n = snprintf(full_path, sizeof(full_path), "%s/file_%llu.dat",
                             orphan_dir, (unsigned long long)fi);
            if (n < 0 || (size_t)n >= sizeof(full_path)) {
                ERR_ADD_ERROR("orphan path too long, skipping", fi, orphan_dir);
                continue;
            }
            is_orphan = true;
        }

        /* Strip any trailing slashes that can arise from double-slash paths in
         * the source metadata (sanitize_path passes them through). */
        {
            size_t plen = strlen(full_path);
            while (plen > 0 && full_path[plen - 1] == '/') full_path[--plen] = '\0';
        }

        if (!ino || in_idx < 0) continue;

        /* Extension filter: skip files whose name doesn't match --filter-ext.
         * Orphans have no meaningful filename so they're excluded when a filter
         * is active. */
        if (g_filter_ext_count > 0) {
            if (is_orphan || !util_matches_filter_ext(g_drecs[d_idx].name)) {
                /* Checkpoint as skipped so resume runs and inspect_checkpoint.py
                 * show accurate counts instead of reporting them as "remaining". */
                if (in_idx >= 0) {
                    if (!is_orphan) {
                        add_unrecovered(fi, full_path[0] ? full_path : "",
                                        ino ? ino->size : 0,
                                        "skipped by --filter-ext", false);
                        g_unrecovered[g_unrecovered_count - 1].kind = UNRECOVERED_EXT_FILTER;
                    }
                    g_cp_extract_stats.files_skipped++;
                    already_done[in_idx] = true;
                    if (extracted_ids && extracted_ids_count < (uint32_t)g_max_inodes)
                        extracted_ids[extracted_ids_count++] = fi;
                }
                continue;
            }
        }

        if (show_progress && w % 100 == 0)
            util_print_progress("Extracting", (uint64_t)w, (uint64_t)work_count, extract_start);

        if (!is_orphan && access(full_path, F_OK) == 0) {
            /* Path collision — rename with _COLLISION suffix and log for report. */
            char original_full_path[MAX_PATH_LEN];
            strncpy(original_full_path, full_path, sizeof(original_full_path) - 1);
            original_full_path[sizeof(original_full_path) - 1] = '\0';

            char *last_slash = strrchr(full_path, '/');
            char dir_part[MAX_PATH_LEN]  = {0};
            char base_part[MAX_PATH_LEN] = {0};

            if (last_slash) {
                strncpy(dir_part, full_path, (size_t)(last_slash - full_path + 1));
                dir_part[last_slash - full_path + 1] = '\0';
                strcpy(base_part, last_slash + 1);
            } else {
                strcpy(base_part, full_path);
            }

            char *ext = strrchr(base_part, '.');
            char new_base[MAX_PATH_LEN];
            if (ext && ext != base_part) {
                *ext = '\0';
                snprintf(new_base, sizeof(new_base), "%s_COLLISION.%s",
                         base_part, ext + 1);
            } else {
                snprintf(new_base, sizeof(new_base), "%s_COLLISION", base_part);
            }

            snprintf(full_path, sizeof(full_path), "%s%s", dir_part, new_base);
            add_collision(fi, original_full_path, full_path);
        }

        /* Symlinks with xfield type 13: handle before fopen so we don't create
         * a regular file placeholder when ino->size is set from a DSTREAM field.
         * When symlink_target is NULL (older APFS stores target as data extents),
         * fall through to normal extraction; the restoration block below reads
         * the extracted content and calls symlink() from it. */
        if (!is_orphan && (ino->mode & S_IFMT) == S_IFLNK && ino->symlink_target) {
            create_directory(full_path);
            if (symlink(ino->symlink_target, full_path) != 0)
                LOG_WARN("Symlink creation failed for inode %llu: %s",
                         (unsigned long long)fi, strerror(errno));
            else
                restore_metadata(full_path, ino);
            g_cp_extract_stats.files_recovered++;
            extracted++;
            already_done[in_idx] = true;
            if (extracted_ids && extracted_ids_count < (uint32_t)g_max_inodes)
                extracted_ids[extracted_ids_count++] = fi;
            continue;
        }

        create_directory(full_path);
        FILE *f = fopen(full_path, "wb");
        if (!f) {
            /* If it still fails with EISDIR, fall back to orphan directory as last resort */
            if (errno == EISDIR) {
                char alt_path[MAX_PATH_LEN];
                mkdir(orphan_dir, 0755);
                const char *bn = strrchr(full_path, '/');
                bn = bn ? bn + 1 : full_path;
                int n = snprintf(alt_path, sizeof(alt_path), "%s/conflict_%llu_%s",
                                 orphan_dir, (unsigned long long)fi, bn);
                if (n > 0 && (size_t)n < sizeof(alt_path)) {
                    f = fopen(alt_path, "wb");
                    if (f) {
                        memcpy(full_path, alt_path, (size_t)n + 1);
                        is_orphan = true;
                    }
                }
            }
            if (!f) {
                const char *reason = "fopen failed: check permissions/disk space";
                ERR_ADD_ERROR(reason, fi, full_path);
                add_unrecovered(fi, full_path, ino->size, reason, is_orphan);
                continue;
            }
        }

        bool     decomp             = false;
        uint64_t expected_size      = 0;
        uint64_t possible_full_size = 0;

        /* ---- Transparent decompression ---- */
        if (ino->is_compressed && g_enable_compression) {
            size_t   dlen = 0;
            uint8_t *dbuf = cmp_decompress_file(ino, &dlen);
            if (dbuf && dlen > 0) {
                size_t nw = fwrite(dbuf, 1, dlen, f);
                free(dbuf);
                if (nw != dlen) {
                    const char *reason = "fwrite failed writing decompressed data";
                    ERR_ADD_ERROR(reason, fi, full_path);
                    add_unrecovered(fi, full_path, ino->size, reason, is_orphan);
                    fclose(f); remove(full_path); continue;
                }
                decomp = true;
                (*compressed_count_out)++;
            } else {
                if (dbuf) free(dbuf);
            }
        }

        /* ---- Raw block extraction ---- */
        if (!decomp) {
            uint64_t part_sz = (g_data_size > g_partition_offset)
                             ? g_data_size - g_partition_offset : 0;

            /* Trust ino->size only if it fits within the partition.
             * Corrupt metadata can carry TB-range garbage sizes. */
            bool size_trusted = (ino->size > 0 &&
                                 (part_sz == 0 || ino->size <= part_sz));
            if (size_trusted) {
                expected_size = ino->size;
            }

            /* Extent coverage: the logical end of the furthest extent found.
             * Also track the sum of all extent lengths (extent_sum).
             *
             * On damaged images the DSTREAM may under-report the file size.
             * We use extent_coverage instead of DSTREAM when the extents are
             * "dense" — i.e. their total length fills ≥50% of the coverage
             * range. Dense extents mean the file genuinely occupies that space
             * (e.g. a large Audacity project with corrupt DSTREAM). Sparse
             * extents (tiny real data + one stray phantom extent far away)
             * would have a very low fill ratio and are left capped at DSTREAM
             * to avoid writing gigabytes of garbage from the phantom records.
             *
             * Two thresholds are used:
             *   extents_dense   (≥50%): used for the _EXPANDED detection path
             *                   where a false positive writes a large extra copy.
             *   extents_nonempty(≥10%): used for the !size_trusted path.  Real
             *                   large fragmented files typically fill ≥30% of
             *                   their range; phantom extents are <1% (e.g. 5 MB
             *                   of real data + one stray record at a 2 GB offset
             *                   = 0.25%).  10% safely separates the two cases. */
            uint64_t extent_coverage = 0;
            uint64_t extent_sum      = 0;
            for (int j = 0; j < ino->extent_count; j++) {
                uint64_t ec = ino->extents[j].logical + ino->extents[j].length;
                if (ec > extent_coverage) extent_coverage = ec;
                extent_sum += ino->extents[j].length;
            }
            bool extents_dense    = (extent_coverage > 0 &&
                                     extent_sum >= extent_coverage / 2);
            bool extents_nonempty = (extent_coverage > 0 &&
                                     extent_sum >= extent_coverage / 10);
            if (!size_trusted && extent_coverage > 0) {
                expected_size = extents_nonempty ? extent_coverage : extent_sum;
                size_trusted = true;
            }
            /* When size_trusted is true (DSTREAM was readable), we trust the
             * DSTREAM value and do not expand.  Expanding based on extents leads
             * to false inflation when phantom/stray extent records are adjacent to
             * the real data (giving near-100% density but multi-GB garbage). */

            /* Detect possibly-truncated files: DSTREAM size is trusted but extents
             * cover ≥2× more and the gap is at least 10 blocks.  Primary extraction
             * still uses DSTREAM; an _EXPANDED copy is written and zero-checked. */
            if (!is_orphan && size_trusted && extents_dense
                && extent_coverage > expected_size * 2
                && extent_coverage - expected_size >= 10 * g_block_size) {
                possible_full_size = extent_coverage;
            }

            /* Size filter: --max-size (default 50 GB cap) / --min-size.
             * The max cap catches "ghost" extractions from corrupted extent records.
             * --max-size overrides the default; --min-size adds a lower bound. */
            if (expected_size > g_max_file_size ||
                (g_min_file_size > 0 && expected_size < g_min_file_size)) {
                char sz_buf[32], lim_buf[32];
                util_format_size(expected_size, sz_buf);
                util_format_size(expected_size > g_max_file_size
                                 ? g_max_file_size : g_min_file_size, lim_buf);
                LOG_EXEC_ONLY("Skipping file outside size filter "
                              "(inode %llu, size %s, limit %s): %s",
                              (unsigned long long)fi, sz_buf, lim_buf, full_path);
                /* Track in g_unrecovered for skipped_files.md (not error.log) */
                add_unrecovered(fi, full_path, expected_size,
                                "skipped by size filter", is_orphan);
                g_unrecovered[g_unrecovered_count - 1].kind = UNRECOVERED_SIZE_FILTER;
                g_skipped_size_count++;
                g_cp_extract_stats.files_skipped++;
                fclose(f); remove(full_path);
                already_done[in_idx] = true;
                /* Checkpoint so resume runs skip this inode instead of
                 * re-evaluating the size filter on every subsequent run. */
                if (extracted_ids && extracted_ids_count < (uint32_t)g_max_inodes)
                    extracted_ids[extracted_ids_count++] = fi;
                continue;
            }

            if (!size_trusted && ino->extent_count == 0) {
                fclose(f);
                bool true_orphan = (d_idx < 0);
                if (true_orphan) {
                    remove(full_path);
                    /* Do NOT checkpoint true orphan 0-extent files — they were
                     * removed from disk and should be re-evaluated on resume. */
                } else {
                    /* Named 0-byte files, including those redirected to orphan_dir
                     * because path resolution failed.  Checkpoint them so they are
                     * not retried on every resume (they have no extractable content). */
                    if (is_orphan) {
                        remove(full_path);
                        g_cp_extract_stats.files_zero_byte++;
                        g_zero_byte_removed_count++;
                    } else {
                        /* Named zero-byte file — restore metadata but nothing to extract. */
                        restore_metadata(full_path, ino);
                        g_cp_extract_stats.files_recovered++;
                    }
                    extracted++;
                    already_done[in_idx] = true;
                    if (extracted_ids && extracted_ids_count < (uint32_t)g_max_inodes)
                        extracted_ids[extracted_ids_count++] = fi;
                }
                continue;
            }

            uint64_t total_disk_blocks = (g_data_size - g_partition_offset) /
                                          g_block_size;
            for (int j = 0; j < ino->extent_count; j++) {
                if (g_interrupted) break;
                uint64_t ext_logical = ino->extents[j].logical;
                uint64_t ext_length  = ino->extents[j].length;
                uint64_t ext_phys    = ino->extents[j].physical;

                /* Skip extents whose physical block is out of range. */
                if (ext_phys >= total_disk_blocks) continue;
                uint64_t max_len = (total_disk_blocks - ext_phys) * g_block_size;
                if (ext_length == 0 || ext_length > max_len) continue;
                if (part_sz > 0 && ext_logical > part_sz) continue;

                if (fseeko(f, (off_t)ext_logical, SEEK_SET) != 0) break;

                uint64_t ext_blocks = (ext_length + g_block_size - 1) / g_block_size;
                uint64_t phys       = ext_phys;

                /* Skip / trim extents that fall entirely within the head crash zone. */
                if (head_crash_zone > 0) {
                    uint64_t end = phys + ext_blocks;
                    if (end <= head_crash_zone) continue;
                    if (phys < head_crash_zone) {
                        uint64_t destroyed = head_crash_zone - phys;
                        phys       += destroyed;
                        ext_blocks -= destroyed;
                        if (fseeko(f, (off_t)(ext_logical + destroyed * g_block_size),
                               SEEK_SET) != 0) break;
                        if (ext_blocks == 0) continue;
                    }
                }

                for (uint64_t b = 0; b < ext_blocks; b++) {
                    if (g_interrupted) break;
                    uint64_t cur_logical = ext_logical + b * g_block_size;
                    if (expected_size > 0 && cur_logical >= expected_size) break;

                    uint64_t phys_blk = phys + b;
                    bool is_sparse = (ext_phys == 0);
                    if (!is_sparse && phys_blk * g_block_size >= g_data_size) break;

                    bool is_last = (expected_size > 0 &&
                                    cur_logical + g_block_size > expected_size);

                    if (is_sparse) {
                        memset(block, 0, g_block_size);
                    } else if (g_encryption_enabled) {
                        /* Per-extent crypto_id; fall back to inode's default. */
                        uint64_t cid = (ino->extents[j].crypto_id == 0 &&
                                        ino->default_crypto_id != 0)
                                     ? ino->default_crypto_id
                                     : ino->extents[j].crypto_id;

                        bool rd_ok = bio_read_block(phys_blk, raw_buf);
                        if (!rd_ok)
                            LOG_DEBUG("block %llu out of range during extraction",
                                      (unsigned long long)phys_blk);
                        if (rd_ok) {
                            crypto_state_t *cs = crypto_lookup_state(cid);
                            if (!cs && cid != 0)
                                LOG_DEBUG("inode %llu: crypto_id %llu not resolved, "
                                          "falling back to VEK",
                                          (unsigned long long)fi,
                                          (unsigned long long)cid);
                            if (cs && cs->initialized) {
                                aes_xts_ctx_t cs_ctx;
                                crypto_aes_xts_init(&cs_ctx, cs->key, cs->key + 16);
                                (void)crypto_aes_xts_decrypt_with_sector_offset(
                                    &cs_ctx, raw_buf, block, g_block_size,
                                    0, (int64_t)(phys_blk * (g_block_size / 512)));
                            } else {
                                (void)crypto_aes_xts_decrypt_with_sector_offset(
                                    &g_aes_xts, raw_buf, block, g_block_size,
                                    0, (int64_t)(phys_blk * (g_block_size / 512)));
                            }
                        } else {
                            memset(block, 0, g_block_size);
                        }
                    } else {
                        if (!bio_read_block(phys_blk, block))
                            LOG_DEBUG("block %llu out of range during extraction",
                                      (unsigned long long)phys_blk);
                    }

                    size_t to_write = is_last
                                    ? (size_t)(expected_size - cur_logical)
                                    : (size_t)g_block_size;
                    /* #11: break early on write failure; ferror() check below handles cleanup. */
                    if (fwrite(block, 1, to_write, f) != to_write) break;
                    if (is_last) break;
                }
            }

            if (ferror(f)) {
                const char *reason = "fwrite failed during block extraction";
                ERR_ADD_ERROR(reason, fi, full_path);
                add_unrecovered(fi, full_path, ino->size, reason, is_orphan);
                fclose(f); remove(full_path); continue;
            }

            /* Extend to the DSTREAM logical size only when extents don't
             * cover as far — preserves sparse end-of-file without truncating
             * data already written from extents that exceed the DSTREAM size. */
            if (ino->size > 0 && ino->size > extent_coverage) {
                uint64_t ps = (g_data_size > g_partition_offset)
                            ? g_data_size - g_partition_offset : 0;
                if (ps == 0 || ino->size <= ps) {
                    if (ftruncate(fileno(f), (off_t)ino->size) != 0)
                        LOG_DEBUG("ftruncate failed for inode %llu: %s",
                                  (unsigned long long)fi, strerror(errno));
                }
            }
        }
        fclose(f);

        /* ---- Expanded extraction for possibly-truncated files ---- */
        if (!is_orphan && possible_full_size > 0) {
            /* Build expanded_path: insert _EXPANDED before extension. */
            char expanded_path[MAX_PATH_LEN] = {0};
            {
                char *last_slash = strrchr(full_path, '/');
                char dir_part[MAX_PATH_LEN]  = {0};
                char base_part[MAX_PATH_LEN] = {0};
                if (last_slash) {
                    strncpy(dir_part, full_path, (size_t)(last_slash - full_path + 1));
                    dir_part[last_slash - full_path + 1] = '\0';
                    strcpy(base_part, last_slash + 1);
                } else {
                    strcpy(base_part, full_path);
                }
                char *ext = strrchr(base_part, '.');
                if (ext && ext != base_part) {
                    *ext = '\0';
                    snprintf(expanded_path, sizeof(expanded_path),
                             "%s%s_EXPANDED.%s", dir_part, base_part, ext + 1);
                } else {
                    snprintf(expanded_path, sizeof(expanded_path),
                             "%s%s_EXPANDED", dir_part, base_part);
                }
            }

            create_directory(expanded_path);
            FILE *fe = fopen(expanded_path, "wb");
            if (fe) {
                bool     extra_nonzero        = false;
                uint64_t total_disk_blocks_ex = (g_data_size - g_partition_offset) /
                                                 g_block_size;
                uint64_t part_sz_ex           = (g_data_size > g_partition_offset)
                                              ? g_data_size - g_partition_offset : 0;

                for (int j = 0; j < ino->extent_count && !g_interrupted; j++) {
                    uint64_t ext_logical = ino->extents[j].logical;
                    uint64_t ext_length  = ino->extents[j].length;
                    uint64_t ext_phys    = ino->extents[j].physical;

                    if (ext_phys >= total_disk_blocks_ex) continue;
                    uint64_t max_len = (total_disk_blocks_ex - ext_phys) * g_block_size;
                    if (ext_length == 0 || ext_length > max_len) continue;
                    if (part_sz_ex > 0 && ext_logical > part_sz_ex) continue;

                    if (fseeko(fe, (off_t)ext_logical, SEEK_SET) != 0) break;

                    uint64_t ext_blocks = (ext_length + g_block_size - 1) / g_block_size;
                    uint64_t phys = ext_phys;

                    if (head_crash_zone > 0) {
                        uint64_t end = phys + ext_blocks;
                        if (end <= head_crash_zone) continue;
                        if (phys < head_crash_zone) {
                            uint64_t destroyed = head_crash_zone - phys;
                            phys       += destroyed;
                            ext_blocks -= destroyed;
                            if (fseeko(fe,
                                       (off_t)(ext_logical + destroyed * g_block_size),
                                       SEEK_SET) != 0) break;
                            if (ext_blocks == 0) continue;
                        }
                    }

                    for (uint64_t b = 0; b < ext_blocks; b++) {
                        if (g_interrupted) break;
                        uint64_t cur_logical = ext_logical + b * g_block_size;
                        if (cur_logical >= possible_full_size) break;

                        uint64_t phys_blk = phys + b;
                        bool is_sparse = (ext_phys == 0);
                        if (!is_sparse && phys_blk * g_block_size >= g_data_size) break;

                        bool is_last = (cur_logical + g_block_size > possible_full_size);

                        if (is_sparse) {
                            memset(block, 0, g_block_size);
                        } else if (g_encryption_enabled) {
                            uint64_t cid = (ino->extents[j].crypto_id == 0 &&
                                            ino->default_crypto_id != 0)
                                         ? ino->default_crypto_id
                                         : ino->extents[j].crypto_id;
                            bool rd_ok = bio_read_block(phys_blk, raw_buf);
                            if (!rd_ok)
                                LOG_DEBUG("block %llu out of range (expanded)",
                                          (unsigned long long)phys_blk);
                            if (rd_ok) {
                                crypto_state_t *cs = crypto_lookup_state(cid);
                                if (cs && cs->initialized) {
                                    aes_xts_ctx_t cs_ctx;
                                    crypto_aes_xts_init(&cs_ctx, cs->key, cs->key + 16);
                                    (void)crypto_aes_xts_decrypt_with_sector_offset(
                                        &cs_ctx, raw_buf, block, g_block_size,
                                        0, (int64_t)(phys_blk * (g_block_size / 512)));
                                } else {
                                    (void)crypto_aes_xts_decrypt_with_sector_offset(
                                        &g_aes_xts, raw_buf, block, g_block_size,
                                        0, (int64_t)(phys_blk * (g_block_size / 512)));
                                }
                            } else {
                                memset(block, 0, g_block_size);
                            }
                        } else {
                            if (!bio_read_block(phys_blk, block))
                                LOG_DEBUG("block %llu out of range (expanded)",
                                          (unsigned long long)phys_blk);
                        }

                        size_t to_write = is_last
                                        ? (size_t)(possible_full_size - cur_logical)
                                        : (size_t)g_block_size;

                        /* Check for non-zero content in the region beyond DSTREAM. */
                        if (cur_logical >= expected_size && !extra_nonzero) {
                            for (size_t k = 0; k < to_write; k++) {
                                if (block[k] != 0) { extra_nonzero = true; break; }
                            }
                        }

                        if (fwrite(block, 1, to_write, fe) != to_write) break;
                        if (is_last) break;
                    }
                }

                bool write_ok = !ferror(fe);
                fclose(fe);

                if (!extra_nonzero || !write_ok) {
                    remove(expanded_path);
                    add_possibly_truncated(fi, full_path, "",
                                           expected_size, possible_full_size, true);
                } else {
                    add_possibly_truncated(fi, full_path, expanded_path,
                                           expected_size, possible_full_size, false);
                }
            }
        }

        /* Orphan files with no content written (all extents out-of-range, skipped,
         * or sparse-only) produce a 0-byte .dat that would land in
         * recovered_unknown_format/.  Delete them now and checkpoint so resume
         * runs skip them rather than re-creating and re-deleting each time. */
        if (is_orphan) {
            struct stat st;
            if (stat(full_path, &st) == 0 && st.st_size == 0) {
                remove(full_path);
                already_done[in_idx] = true;
                if (extracted_ids && extracted_ids_count < (uint32_t)g_max_inodes)
                    extracted_ids[extracted_ids_count++] = fi;
                g_zero_byte_removed_count++;
                g_cp_extract_stats.files_zero_byte++;
                continue;
            }
        }

        /* ---- Orphan content-hash deduplication --------------------------------
         * APFS hard links and COW clones assign different inode IDs to the same
         * physical data.  The worklist dedup (in_worklist[]) only catches the
         * same inode appearing twice; it cannot see content identity across
         * different inodes.  Hash the first 64 KB of each orphan file against an
         * in-memory table; delete and checkpoint any byte-identical duplicate so
         * recovered_unknown_format/ doesn't accumulate redundant copies. */
        if (is_orphan && orphan_sigs) {
            struct stat ost;
            if (stat(full_path, &ost) == 0 && ost.st_size > 0) {
                size_t   sample = (size_t)(ost.st_size < ORPHAN_DEDUP_SAMPLE
                                          ? ost.st_size : ORPHAN_DEDUP_SAMPLE);
                uint8_t *buf    = malloc(sample);
                if (buf) {
                    FILE *fh = fopen(full_path, "rb");
                    if (fh) {
                        size_t nr = fread(buf, 1, sample, fh);
                        fclose(fh);
                        if (nr == sample) {
                            uint8_t      sig[32] = {0};
                            uint64_t     fsz     = (uint64_t)ost.st_size;
                            unsigned int slen    = 32;
                            bool digest_ok = (sha_ctx &&
                                EVP_DigestInit_ex(sha_ctx, EVP_sha256(), NULL) == 1 &&
                                EVP_DigestUpdate(sha_ctx, &fsz, sizeof(fsz))   == 1 &&
                                EVP_DigestUpdate(sha_ctx, buf, nr)             == 1 &&
                                EVP_DigestFinal_ex(sha_ctx, sig, &slen)        == 1);

                            bool is_dup = false;
                            if (digest_ok) for (int k = 0; k < orphan_sig_cnt; k++) {
                                if (orphan_sigs[k].file_size == fsz &&
                                    memcmp(orphan_sigs[k].sha, sig, 32) == 0) {
                                    LOG_DEBUG("dedup orphan inode %llu = inode %llu, removing",
                                              (unsigned long long)fi,
                                              (unsigned long long)orphan_sigs[k].inode_id);
                                    is_dup = true;
                                    break;
                                }
                            }

                            if (!is_dup && digest_ok) {
                                if (orphan_sigs && orphan_sig_cnt >= sig_capacity) {
                                    int new_cap = sig_capacity * 2;
                                    orphan_sig_t *tmp = realloc(orphan_sigs,
                                                                (size_t)new_cap * sizeof(orphan_sig_t));
                                    if (tmp) { orphan_sigs = tmp; sig_capacity = new_cap; }
                                }
                                if (orphan_sigs && orphan_sig_cnt < sig_capacity) {
                                    orphan_sigs[orphan_sig_cnt].file_size = fsz;
                                    orphan_sigs[orphan_sig_cnt].inode_id  = fi;
                                    memcpy(orphan_sigs[orphan_sig_cnt].sha, sig, 32);
                                    orphan_sig_cnt++;
                                }
                            }

                            if (is_dup) {
                                free(buf);
                                remove(full_path);
                                already_done[in_idx] = true;
                                if (extracted_ids &&
                                    extracted_ids_count < (uint32_t)g_max_inodes)
                                    extracted_ids[extracted_ids_count++] = fi;
                                g_cp_extract_stats.files_deduped++;
                                orphan_dup_cnt++;
                                continue;
                            }
                        }
                    }
                    free(buf);
                }
            }
        }

        /* ---- Symlink restoration (Roadmap 1.2) ---- */
        /* #12/#24: check fread return; only create symlink on complete read;
         * check symlink() return so we log rather than silently lose the file. */
        if ((ino->mode & S_IFMT) == S_IFLNK && ino->size > 0 && ino->size < 4096) {
            FILE *fs = fopen(full_path, "rb");
            if (fs) {
                char target[4096] = {0};
                size_t nr = fread(target, 1, ino->size, fs);
                fclose(fs);
                if (nr == ino->size) {
                    remove(full_path);
                    if (symlink(target, full_path) != 0)
                        LOG_WARN("Symlink creation failed for inode %llu: %s",
                                 (unsigned long long)fi, strerror(errno));
                }
            }
        }

        /* ---- Broken symlink cleanup ---- */
        /* When symlink_target was NULL (xattr block unreadable on damaged image)
         * and no data extents held the target string, fopen() created a 0-byte
         * regular file.  Remove it and track as unrecovered so the recovered tree
         * has no misleading placeholders. */
        if (!is_orphan && (ino->mode & S_IFMT) == S_IFLNK) {
            struct stat lst;
            if (lstat(full_path, &lst) == 0 && !S_ISLNK(lst.st_mode)) {
                remove(full_path);
                add_unrecovered(fi, full_path, ino->size,
                                "broken symlink: target data unavailable on damaged image",
                                false);
                g_cp_extract_stats.files_zero_byte++;
                already_done[in_idx] = true;
                if (extracted_ids && extracted_ids_count < (uint32_t)g_max_inodes)
                    extracted_ids[extracted_ids_count++] = fi;
                continue;
            }
        }

        /* ---- File metadata restoration (Roadmap 1.1) ---- */
        restore_metadata(full_path, ino);

        /* ---- Magic-byte extension correction ---- */
        if (expected_size > 8) {
            FILE *fc = fopen(full_path, "rb");
            if (fc) {
                uint8_t magic[8];
                size_t  nr = fread(magic, 1, 8, fc);
                fclose(fc);
                if (nr >= 3) {
                    char *ext = strrchr(full_path, '.');
                    char new_path[MAX_PATH_LEN];
                    if (memcmp(magic, "\xFF\xD8\xFF", 3) == 0) {
                        if (!ext || (strcasecmp(ext, ".jpg") != 0 &&
                                     strcasecmp(ext, ".jpeg") != 0)) {
                            snprintf(new_path, sizeof(new_path), "%.*s.jpg",
                                     (int)(ext ? ext - full_path
                                               : (ptrdiff_t)strlen(full_path)),
                                     full_path);
                            rename(full_path, new_path);
                        }
                    } else if (nr >= 8 &&
                               memcmp(magic, "\x89PNG\r\n\x1a\n", 8) == 0) {
                        if (!ext || strcasecmp(ext, ".png") != 0) {
                            snprintf(new_path, sizeof(new_path), "%.*s.png",
                                     (int)(ext ? ext - full_path
                                               : (ptrdiff_t)strlen(full_path)),
                                     full_path);
                            rename(full_path, new_path);
                        }
                    }
                }
            }
        }

        already_done[in_idx] = true;
        if (extracted_ids && extracted_ids_count < (uint32_t)g_max_inodes)
            extracted_ids[extracted_ids_count++] = fi;
        extracted++;
        g_cp_extract_stats.files_recovered++;

        /* Periodic checkpoint every 100 files. */
        if (extracted % 100 == 0)
            cp_save_extracted(extracted_ids, extracted_ids_count, &g_cp_extract_stats);
    }

    if (show_progress) {
        if (!g_interrupted)
            util_print_progress("Extracting", (uint64_t)work_count, (uint64_t)work_count, extract_start);
        util_progress_newline();
    }

    /* Print skipped files summary if the size filter triggered */
    if (g_skipped_size_count > 0) {
        char sk[32];
        util_format_num(g_skipped_size_count, sk);
        LOG_WARN("Skipped %s file(s) outside size filter", sk);
    }

    /* Final checkpoint. */
    if (extracted_ids_count > 0)
        cp_save_extracted(extracted_ids, extracted_ids_count, &g_cp_extract_stats);

    /* Expose the final cumulative count for the summary box. */
    g_total_extracted_count = extracted_ids_count;

    if (orphan_dup_cnt > 0) {
        char nb[32];
        LOG_EXEC_ONLY("Duplicate orphans removed: %s (identical content, different inode ID)",
                      util_format_num((uint64_t)orphan_dup_cnt, nb));
    }
    EVP_MD_CTX_free(sha_ctx);
    free(orphan_sigs);
    free(work);
    free(block);
    free(raw_buf);
    free(is_dir_inode);
    free(already_done);
    free(extracted_ids);
    return extracted;
}

/* ============================================================================
 * Public: recovery_restore_dir_metadata
 * ============================================================================
 */

void recovery_restore_dir_metadata(const char *files_dir) {
    if (!files_dir || g_interrupted) return;

    /* Skipped on non-POSIX output filesystems — restore_metadata() will
     * return immediately, but skip the loop entirely for clarity. */
    if (g_output_nonposix || g_skip_metadata) return;

    log_step_header("Restoring folder metadata");

    int restored = 0;
    for (int i = 0; i < g_inode_count; i++) {
        inode_t *ino = &g_inodes[i];
        /* Skip root dir (inode 2) and non-dirs */
        if (!ino->is_dir || ino->inode_id == 2) continue;

        /* g_paths is indexed by hash table slot, not linear inode array index */
        int64_t idx = get_inode_idx(ino->inode_id);
        if (idx < 0 || !g_paths || !g_paths[idx]) continue;

        char full_path[MAX_PATH_LEN];
        /* path is relative (no leading slash); prepend files_dir + "/" */
        snprintf(full_path, sizeof(full_path), "%s/%s", files_dir, g_paths[idx]);
        /* Skip directories that were never created on disk (e.g. empty dirs
         * whose files were all filtered or skipped). */
        if (access(full_path, F_OK) != 0) continue;
        restore_metadata(full_path, ino);
        restored++;
    }

    {
        char nb[32];
        LOG_OK("Folder metadata restored for %s folder%s",
               util_format_num((uint64_t)restored, nb),
               restored == 1 ? "" : "s");
    }
}

/* ============================================================================
 * Public: recovery_extract_deleted
 * ============================================================================
 */

int recovery_extract_deleted(const char *deleted_dir) {
    if (!g_enable_deleted_recovery || g_deleted_count == 0) return 0;

    mkdir(deleted_dir, 0755);

    uint8_t *block = malloc(g_block_size);
    if (!block) return 0;

    int    recovered = 0;
    double start     = util_get_time_ms();

    for (int i = 0; i < g_deleted_count; i++) {
        util_print_progress("Recovering deleted",
                            (uint64_t)i, (uint64_t)g_deleted_count, start);

        (void)bio_read_block(g_deleted[i].block_num, block);

        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s/inode_%llu_block_%llu.raw",
                 deleted_dir,
                 (unsigned long long)g_deleted[i].inode_id,
                 (unsigned long long)g_deleted[i].block_num);

        if (access(path, F_OK) == 0) { recovered++; continue; }

        FILE *f = fopen(path, "wb");
        if (f) {
            size_t nw = fwrite(block, 1, g_block_size, f);
            fclose(f);
            if (nw == g_block_size) {
                recovered++;
            } else {
                LOG_WARN("Incomplete write to %s", path);
            }
        }
    }

    util_print_progress("Recovering deleted",
                        (uint64_t)g_deleted_count,
                        (uint64_t)g_deleted_count, start);
    util_progress_newline();

    free(block);
    return recovered;
}
