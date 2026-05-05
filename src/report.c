/*
 * report.c — always-on Markdown report generation.
 */

#define _GNU_SOURCE
#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "apfs_globals.h"
#include "log.h"
#include "util.h"

#include "version.h"

/* ============================================================================
 * recovery_summary.md
 * ============================================================================
 */

void report_write_summary(const char *output_dir, const result_t *result,
                          const char *image_path) {
    if (!output_dir) return;

    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/recovery_summary.md", output_dir);

    FILE *f = fopen(path, "w");
    if (!f) {
        LOG_ERROR("Could not write recovery_summary.md: %s", path);
        return;
    }

    /* Run date */
    time_t    now = time(NULL);
    struct tm tm_buf;
    char      date_str[64];
    strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S",
             localtime_r(&now, &tm_buf));

    fprintf(f, "# Recovery Summary\n\n");
    fprintf(f, "| Field | Value |\n");
    fprintf(f, "|:------|:------|\n");
    fprintf(f, "| Run date | %s |\n", date_str);
    fprintf(f, "| Tool version | apfs-excavate %s |\n", TOOL_VERSION);
    fprintf(f, "\n");

    /* Image info */
    fprintf(f, "## Image\n\n");
    fprintf(f, "| Field | Value |\n");
    fprintf(f, "|:------|:------|\n");
    fprintf(f, "| Path | `%s` |\n", image_path ? image_path : "—");
    {
        char buf[32];
        fprintf(f, "| Size | %s |\n",
                util_format_size((uint64_t)g_data_size, buf));
    }
    {
        char buf[32];
        fprintf(f, "| Block size | %s |\n",
                util_format_size(g_block_size, buf));
    }
    {
        char buf[32];
        fprintf(f, "| Partition offset | %s |\n",
                util_format_size(g_partition_offset, buf));
    }
    fprintf(f, "| Encrypted | %s |\n",
            g_encryption_enabled ? "Yes" : "No");
    fprintf(f, "| Case-sensitive | %s |\n",
            g_case_sensitive ? "Yes" : "No (default)");
    if (g_encryption_enabled) {
        fprintf(f, "| Keybag found | %s |\n",
                result->keybag_found ? "Yes" : "No");
        fprintf(f, "| VEK derived | %s |\n",
                result->vek_derived ? "Yes" : "No");
    }
    fprintf(f, "\n");

    /* Scan results */
    int fail_count = (int)g_unrecovered_count - (int)result->skipped_size_count;
    if (fail_count < 0) fail_count = 0;

    fprintf(f, "## Scan Results\n\n");
    fprintf(f, "| Metric | Count |\n");
    fprintf(f, "|:-------|------:|\n");
    {
        char b1[32], b2[32], b3[32], b4[32], b5[32];
        fprintf(f, "| Blocks scanned | %s |\n",
                util_format_num(result->blocks_scanned, b1));
        fprintf(f, "| Directories found | %s |\n",
                util_format_num((uint64_t)result->directories_found, b2));
        /* Use the pre-extraction scan estimate (same source as the scan summary
         * box) so this row stays consistent with what was shown before extraction.
         * Size-filtered files are excluded here; they appear in Recovery Results. */
        uint64_t scan_found = (result->scan_estimate_files > 0)
            ? (uint64_t)result->scan_estimate_files
            : (uint64_t)(result->files_found
                         + (int)result->orphans_identified
                         + (int)result->orphans_unrecoverable);
        fprintf(f, "| Files found | %s |\n",
                util_format_num(scan_found, b3));
        fprintf(f, "| Inodes | %s |\n",
                util_format_num((uint64_t)g_inode_count, b4));
        fprintf(f, "| Paths resolved | %s |\n",
                util_format_num((uint64_t)result->paths_resolved, b5));
    }
    if (result->blocks_per_second > 0) {
        char b[32];
        fprintf(f, "| Scan speed | %s blocks/s |\n",
                util_format_num((uint64_t)result->blocks_per_second, b));
    }
    fprintf(f, "\n");

    /* Recovery results — prefer checkpoint-based cumulative stats when available. */
    int total_found;
    uint32_t total_extracted;
    uint32_t rep_skipped;
    uint32_t rep_zero_byte;
    uint32_t rep_deduped;

    if (g_cp_extract_stats.files_found > 0) {
        total_found     = (int)g_cp_extract_stats.files_found;
        total_extracted = g_cp_extract_stats.files_recovered;
        rep_skipped     = g_cp_extract_stats.files_skipped;
        rep_zero_byte   = g_cp_extract_stats.files_zero_byte;
        rep_deduped     = g_cp_extract_stats.files_deduped;
    } else {
        total_found = (g_work_count > 0 || result->previously_extracted > 0)
            ? (int)g_work_count + (int)result->previously_extracted
            : result->files_found
              + (int)result->orphans_identified
              + (int)result->orphans_unrecoverable;
        if (result->total_extracted > 0) {
            int te = (int)result->total_extracted
                   - (int)result->skipped_size_count
                   - (int)result->zero_byte_removed;
            total_extracted = (te > 0) ? (uint32_t)te : 0;
        } else {
            total_extracted = (uint32_t)result->files_extracted + result->previously_extracted;
        }
        rep_skipped   = result->skipped_size_count;
        rep_zero_byte = result->zero_byte_removed;
        rep_deduped   = 0;
    }

    uint32_t rep_removed = rep_zero_byte + rep_deduped;

    double recovery_rate = (total_found > 0)
                         ? (100.0 * total_extracted / total_found)
                         : 0.0;
    if (recovery_rate > 100.0) recovery_rate = 100.0;

    fprintf(f, "## Recovery Results\n\n");
    fprintf(f, "| Metric | Count |\n");
    fprintf(f, "|:-------|------:|\n");
    {
        char b1[32], b2[32], b3[32], b4[32], b5[32], b6[32], b7[32], b8[32];
        if (result->previously_extracted > 0) {
            fprintf(f, "| Files extracted (this run) | %s |\n",
                    util_format_num((uint64_t)result->files_extracted, b1));
            fprintf(f, "| Files extracted (prior runs) | %s |\n",
                    util_format_num((uint64_t)result->previously_extracted, b2));
            fprintf(f, "| **Files extracted (total)** | **%s** |\n",
                    util_format_num((uint64_t)total_extracted, b3));
        } else {
            fprintf(f, "| Files extracted | %s |\n",
                    util_format_num((uint64_t)result->files_extracted, b1));
        }
        fprintf(f, "| Compressed files | %s |\n",
                util_format_num((uint64_t)result->compressed_files, b4));
        if (result->deleted_files_found > 0) {
            fprintf(f, "| Deleted files found | %s |\n",
                    util_format_num((uint64_t)result->deleted_files_found, b5));
            fprintf(f, "| Deleted files recovered | %s |\n",
                    util_format_num((uint64_t)result->deleted_files_recovered, b6));
        }
        if (rep_skipped > 0) {
            fprintf(f, "| Skipped (size filter) | %s |\n",
                    util_format_num(rep_skipped, b7));
        }
        if (rep_removed > 0) {
            char brm[32];
            fprintf(f, "| Files removed | %s |\n",
                    util_format_num((uint64_t)rep_removed, brm));
        }
        if (fail_count > 0) {
            fprintf(f, "| Failed extractions | %s |\n",
                    util_format_num((uint64_t)fail_count, b8));
        }
        fprintf(f, "| Recovery rate | %.1f%% |\n", recovery_rate);
    }
    fprintf(f, "\n");

    /* Orphan post-processing */
    if (result->orphans_identified > 0 || result->orphans_unrecoverable > 0
            || result->orphans_zeroed > 0) {
        uint32_t orphans_total = result->orphans_identified
                               + result->orphans_unrecoverable
                               + result->orphans_zeroed;
        fprintf(f, "## Orphan Post-Processing\n\n");
        fprintf(f, "| Metric | Count |\n");
        fprintf(f, "|:-------|------:|\n");
        {
            char b1[32], b2[32], b3[32], b4[32], b5[32];
            fprintf(f, "| Orphans found (.dat files) | %s |\n",
                    util_format_num((uint64_t)orphans_total, b1));
            fprintf(f, "| Orphans decompressed | %s |\n",
                    util_format_num((uint64_t)result->orphans_decompressed, b2));
            fprintf(f, "| Identified & renamed | %s |\n",
                    util_format_num((uint64_t)result->orphans_identified, b3));
            fprintf(f, "| Moved to recovered_unknown_format/ | %s |\n",
                    util_format_num((uint64_t)result->orphans_unrecoverable, b4));
            if (result->orphans_zeroed > 0)
                fprintf(f, "| Deleted (all-zero content) | %s |\n",
                        util_format_num((uint64_t)result->orphans_zeroed, b5));
        }
        fprintf(f, "\n");
    }

    /* Timing */
    fprintf(f, "## Timing\n\n");
    fprintf(f, "| Phase | Duration |\n");
    fprintf(f, "|:------|----------:|\n");
    {
        char t1[32], t2[32], t3[32], t5[32];
        fprintf(f, "| Scan | %s |\n",
                util_format_time(result->scan_time, t1));
        fprintf(f, "| Build paths | %s |\n",
                util_format_time(result->build_time, t2));
        fprintf(f, "| Extract | %s |\n",
                util_format_time(result->extract_time, t3));
        fprintf(f, "| **Total** | **%s** |\n",
                util_format_time(result->total_time, t5));
    }
    fprintf(f, "\n");

    /* Issues */
    fprintf(f, "## Issues\n\n");
    if (rep_skipped > 0) {
        char sk[32];
        fprintf(f, "> **%s file(s) skipped** — outside size filter range. "
                   "Full list in `logs/skipped_files.md`.\n\n",
                util_format_num(rep_skipped, sk));
    }
    if (rep_removed > 0) {
        char brm[32];
        fprintf(f, "> **%s file(s) removed** — found during scan but not retained on disk:\n",
                util_format_num((uint64_t)rep_removed, brm));
        if (rep_zero_byte > 0) {
            char b[32];
            fprintf(f, "> - Zero-byte (%s) — no data recovered from extents\n",
                    util_format_num((uint64_t)rep_zero_byte, b));
        }
        if (rep_deduped > 0) {
            char b[32];
            fprintf(f, "> - Duplicate content (%s) — identical data already saved via another inode (hard link / clone)\n",
                    util_format_num((uint64_t)rep_deduped, b));
        }
        fprintf(f, "\n");
    }
    if (result->error_count > 0 || result->warning_count > 0) {
        fprintf(f, "%d error(s), %d warning(s) — see `logs/error.log` for details.\n\n",
                result->error_count, result->warning_count);
    } else if (rep_skipped == 0 && rep_removed == 0) {
        fprintf(f, "No errors or warnings recorded.\n\n");
    }

    /* Possibly Truncated Files */
    if (g_possibly_truncated_count > 0) {
        int discarded_count = 0;
        for (int i = 0; i < g_possibly_truncated_count; i++)
            if (g_possibly_truncated[i].discarded) discarded_count++;

        char pc[32];
        fprintf(f, "## Possibly Truncated Files\n\n");
        fprintf(f, "%s file(s) had dense extent coverage significantly larger than their "
                   "DSTREAM size.\n"
                   "Expanded versions extracted alongside originals with `_EXPANDED` suffix.\n",
                util_format_num((uint64_t)g_possibly_truncated_count, pc));
        if (discarded_count > 0) {
            char dc[32];
            fprintf(f, "%s expanded file(s) were discarded (extra bytes were all zeros — "
                       "phantom extents).\n",
                    util_format_num((uint64_t)discarded_count, dc));
        }
        fprintf(f, "\n");
        fprintf(f, "| # | Inode | DSTREAM Size | Extent Coverage | Status | Path |\n");
        fprintf(f, "|---|-------|-------------|-----------------|--------|------|\n");
        for (int i = 0; i < g_possibly_truncated_count; i++) {
            possibly_truncated_t *pt = &g_possibly_truncated[i];
            char ds[32], es[32];
            fprintf(f, "| %d | %llu | %s | %s | %s | `%s` |\n",
                    i + 1,
                    (unsigned long long)pt->inode_id,
                    util_format_size(pt->dstream_size, ds),
                    util_format_size(pt->extent_size, es),
                    pt->discarded ? "discarded (zeros)" : "expanded saved",
                    pt->original_path[0] ? pt->original_path : "—");
        }
        fprintf(f, "\nTo attempt forced expansion of all dense-extent files, "
                   "use `--expand-extents` (see ROADMAP).\n\n");
    }

    /* Path Collisions */
    if (g_collision_count > 0) {
        char cc[32];
        fprintf(f, "## Path Collisions\n\n");
        fprintf(f, "%s file(s) were renamed with `_COLLISION` because another file already "
                   "occupied their path.\n"
                   "This is normal on damaged images with duplicate or stale drec entries.\n\n",
                util_format_num((uint64_t)g_collision_count, cc));
        fprintf(f, "| # | Inode | Attempted Path | Extracted As |\n");
        fprintf(f, "|---|-------|---------------|------|\n");
        for (int i = 0; i < g_collision_count; i++) {
            path_collision_t *c = &g_collisions[i];
            fprintf(f, "| %d | %llu | `%s` | `%s` |\n",
                    i + 1,
                    (unsigned long long)c->inode_id,
                    c->original_path[0] ? c->original_path : "—",
                    c->actual_path[0] ? c->actual_path : "—");
        }
        fprintf(f, "\n");
    }

    fclose(f);
    LOG_EXEC_ONLY("Report written: %s", path);
}

/* ============================================================================
 * unrecovered_files.md
 * ============================================================================
 */

void report_write_unrecovered(const char *output_dir) {
    if (!output_dir) return;

    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/unrecovered_files.md", output_dir);

    FILE *f = fopen(path, "w");
    if (!f) {
        LOG_ERROR("Could not write unrecovered_files.md: %s", path);
        return;
    }

    fprintf(f, "# Unrecovered Files\n\n");

    if (g_unrecovered_count == 0) {
        fprintf(f, "No unrecovered files — all discovered files were extracted "
                   "successfully.\n");
        fclose(f);
        LOG_EXEC_ONLY("Report written: %s", path);
        return;
    }

    /* Categorise entries.  Size/ext-filtered files are reported separately
     * in logs/skipped_files.md; exclude them from the failure tables here
     * to avoid double-listing them. */
    int named_count   = 0;
    int orphan_count  = 0;
    int massive_count = 0;
    for (int i = 0; i < g_unrecovered_count; i++) {
        unrecovered_t *u = &g_unrecovered[i];
        if (strstr(u->reason, "massive file")) massive_count++;
        else if (u->kind == UNRECOVERED_SIZE_FILTER ||
                 u->kind == UNRECOVERED_EXT_FILTER) continue;
        else if (u->is_orphan) orphan_count++;
        else named_count++;
    }

    /* Massive / corrupt files */
    if (massive_count > 0) {
        char mc[32];
        fprintf(f, "## Skipped — Implausible Size (Metadata Corruption)\n\n");
        fprintf(f, "%s file(s) had metadata-reported sizes >50 GB, which is a "
                   "strong indicator of B-tree corruption.  They were not extracted.\n\n",
                util_format_num((uint64_t)massive_count, mc));
        fprintf(f, "| Inode | Reported Size | Path |\n");
        fprintf(f, "|-------|---------------|------|\n");
        for (int i = 0; i < g_unrecovered_count; i++) {
            unrecovered_t *u = &g_unrecovered[i];
            if (!strstr(u->reason, "massive file")) continue;
            char sz[32];
            fprintf(f, "| %llu | %s | `%s` |\n",
                    (unsigned long long)u->inode_id,
                    util_format_size(u->size, sz),
                    u->path[0] ? u->path : "—");
        }
        fprintf(f, "\n");
    }

    /* Named extraction failures */
    if (named_count > 0) {
        fprintf(f, "## Failed Extractions\n\n");
        fprintf(f, "Files found in metadata but not successfully extracted.\n\n");
        fprintf(f, "| Inode | Path | Size | Reason |\n");
        fprintf(f, "|-------|------|------|--------|\n");
        for (int i = 0; i < g_unrecovered_count; i++) {
            unrecovered_t *u = &g_unrecovered[i];
            if (u->is_orphan || strstr(u->reason, "massive file") ||
                u->kind == UNRECOVERED_SIZE_FILTER ||
                u->kind == UNRECOVERED_EXT_FILTER) continue;
            char sz[32];
            fprintf(f, "| %llu | `%s` | %s | %s |\n",
                    (unsigned long long)u->inode_id,
                    u->path[0] ? u->path : "—",
                    util_format_size(u->size, sz),
                    u->reason[0] ? u->reason : "—");
        }
        fprintf(f, "\n");
    }

    /* Orphaned files */
    if (orphan_count > 0) {
        fprintf(f, "## Orphaned Files\n\n");
        fprintf(f, "Files with extents but no resolved path. These were placed "
                   "in `recovered_orphans/` with a generated filename.\n\n");
        fprintf(f, "| Inode | Size | Reason |\n");
        fprintf(f, "|-------|------|--------|\n");
        for (int i = 0; i < g_unrecovered_count; i++) {
            unrecovered_t *u = &g_unrecovered[i];
            if (!u->is_orphan || strstr(u->reason, "massive file")) continue;
            char sz[32];
            fprintf(f, "| %llu | %s | %s |\n",
                    (unsigned long long)u->inode_id,
                    util_format_size(u->size, sz),
                    u->reason[0] ? u->reason : "—");
        }
        fprintf(f, "\n");
    }

    fclose(f);
    LOG_EXEC_ONLY("Report written: %s", path);
}

/* ============================================================================
 * logs/skipped_files.md
 * ============================================================================
 */

void report_write_skipped_files(const char *output_dir) {
    if (!output_dir) return;
    /* Count entries matching either skip kind before deciding to write */
    int any_skipped = 0;
    for (int i = 0; i < g_unrecovered_count; i++)
        if (g_unrecovered[i].kind == UNRECOVERED_SIZE_FILTER ||
            g_unrecovered[i].kind == UNRECOVERED_EXT_FILTER)
            any_skipped++;
    if (any_skipped == 0) return;

    /* Write to logs/ subdirectory */
    const char *log_dir = (g_logs_dir && g_logs_dir[0]) ? g_logs_dir : output_dir;
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/skipped_files.md", log_dir);

    FILE *f = fopen(path, "w");
    if (!f) {
        LOG_ERROR("Could not write skipped_files.md: %s", path);
        return;
    }

    time_t    now = time(NULL);
    struct tm tm_buf;
    char      date_str[64];
    strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", localtime_r(&now, &tm_buf));

    fprintf(f, "# Skipped Files\n\n");
    fprintf(f, "Files skipped due to active filters "
               "(`--max-size`, `--min-size`, `--filter-ext`).\n");
    fprintf(f, "These files exist in the APFS metadata but were not extracted.\n\n");
    fprintf(f, "| Field | Value |\n");
    fprintf(f, "|:------|:------|\n");
    fprintf(f, "| Generated | %s |\n", date_str);
    {
        char sk[32];
        fprintf(f, "| Total skipped | %s |\n\n",
                util_format_num((uint64_t)any_skipped, sk));
    }

    /* Table of skipped files from g_unrecovered */
    fprintf(f, "| Inode | Path | Size | Reason |\n");
    fprintf(f, "|-------|------|------|--------|\n");
    int written = 0;
    for (int i = 0; i < g_unrecovered_count; i++) {
        unrecovered_t *u = &g_unrecovered[i];
        if (u->kind != UNRECOVERED_SIZE_FILTER && u->kind != UNRECOVERED_EXT_FILTER) continue;
        char sz[32];
        fprintf(f, "| %llu | `%s` | %s | %s |\n",
                (unsigned long long)u->inode_id,
                u->path[0] ? u->path : "—",
                util_format_size(u->size, sz),
                u->reason[0] ? u->reason : "—");
        written++;
    }
    if (written == 0)
        fprintf(f, "| — | — | — | (no detail recorded) |\n");
    fprintf(f, "\n");

    fclose(f);
    LOG_EXEC_ONLY("Report written: %s", path);
}

/* ============================================================================
 * error.log
 * ============================================================================
 */

void report_write_error_log(const char *output_dir) {
    if (!output_dir) return;

    /* error.log lives in logs/ when available */
    const char *log_dir = (g_logs_dir && g_logs_dir[0]) ? g_logs_dir : output_dir;
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/error.log", log_dir);

    FILE *f = fopen(path, "w");
    if (!f) {
        LOG_ERROR("Could not write error.log: %s", path);
        return;
    }

    if (g_error_count == 0) {
        fprintf(f, "No errors or warnings recorded.\n");
        fclose(f);
        LOG_EXEC_ONLY("Report written: %s", path);
        return;
    }

    for (int i = 0; i < g_error_count; i++) {
        error_record_t *e = &g_errors[i];

        char      ts[32] = "—";
        struct tm tm_buf2;
        if (e->timestamp != 0) {
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S",
                     localtime_r(&e->timestamp, &tm_buf2));
        }

        const char *sev = (e->severity == ERR_ERROR)   ? "ERROR"   :
                          (e->severity == ERR_WARNING)  ? "WARNING" : "INFO";

        fprintf(f, "[%s] [%-7s] %s", ts, sev, e->message);
        if (e->inode_id)     fprintf(f, " (inode %llu)",
                                     (unsigned long long)e->inode_id);
        if (e->file_path[0]) fprintf(f, " — %s", e->file_path);
        fprintf(f, "\n");
    }

    fclose(f);
    LOG_EXEC_ONLY("Report written: %s", path);
}
