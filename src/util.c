/*
 * util.c — timing, formatting, progress bars, inode hash table, path helpers.
 */

#define _GNU_SOURCE
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>

#include "apfs_globals.h"
#include "log.h"
#include "term.h"

/* ============================================================================
 * Timing
 * ============================================================================
 */

double util_get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

/* ============================================================================
 * Number / time formatting
 * ============================================================================
 */

char *util_format_num(uint64_t n, char *buf) {
    if (n < 100000) {
        snprintf(buf, 32, "%llu", (unsigned long long)n);
        return buf;
    }
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)n);
    int len    = (int)strlen(tmp);
    int commas = (len - 1) / 3;
    buf[len + commas] = '\0';
    int src = len - 1, dst = len + commas - 1, count = 0;
    while (src >= 0) {
        if (count > 0 && count % 3 == 0) buf[dst--] = ',';
        buf[dst--] = tmp[src--];
        count++;
    }
    return buf;
}

char *util_format_size(uint64_t bytes, char *buf) {
#ifdef __APPLE__
    /* macOS uses decimal (SI) units (1 GB = 10^9 bytes), matching Finder and
     * Disk Utility, so recovered file sizes correlate directly with what the
     * user sees in the Finder sidebar. */
    if (bytes >= 1000ULL * 1000 * 1000 * 1000)
        snprintf(buf, 32, "%.2f TB", bytes / (1000.0 * 1000 * 1000 * 1000));
    else if (bytes >= 1000ULL * 1000 * 1000)
        snprintf(buf, 32, "%.2f GB", bytes / (1000.0 * 1000 * 1000));
    else if (bytes >= 1000ULL * 1000)
        snprintf(buf, 32, "%.2f MB", bytes / (1000.0 * 1000));
    else if (bytes >= 1000)
        snprintf(buf, 32, "%.2f KB", bytes / 1000.0);
    else
        snprintf(buf, 32, "%llu B", (unsigned long long)bytes);
#else
    /* Linux uses binary (IEC) units (1 GiB = 2^30 bytes). */
    if (bytes >= 1024ULL * 1024 * 1024 * 1024)
        snprintf(buf, 32, "%.2f TiB", bytes / (1024.0 * 1024 * 1024 * 1024));
    else if (bytes >= 1024ULL * 1024 * 1024)
        snprintf(buf, 32, "%.2f GiB", bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024ULL * 1024)
        snprintf(buf, 32, "%.2f MiB", bytes / (1024.0 * 1024));
    else if (bytes >= 1024)
        snprintf(buf, 32, "%.2f KiB", bytes / 1024.0);
    else
        snprintf(buf, 32, "%llu B", (unsigned long long)bytes);
#endif
    return buf;
}

char *util_format_time(double seconds, char *buf) {
    if (seconds <= 0) { snprintf(buf, 32, "0s"); return buf; }
    uint64_t s = (uint64_t)seconds;
    uint32_t d = (uint32_t)(s / 86400); s %= 86400;
    uint32_t h = (uint32_t)(s / 3600);  s %= 3600;
    uint32_t m = (uint32_t)(s / 60);    s %= 60;
    if      (d > 0) snprintf(buf, 32, "%ud %uh", d, h);
    else if (h > 0) snprintf(buf, 32, "%uh %um", h, m);
    else if (m > 0) snprintf(buf, 32, "%um %02llus", m, (unsigned long long)s);
    else            snprintf(buf, 32, "%llus", (unsigned long long)s);
    return buf;
}

/* ============================================================================
 * Progress bars (write directly to stdout, bypassing the log system)
 * ============================================================================
 */

/*
 * bar_width_for_content() — compute the fill bar width given the total display
 * columns consumed by non-bar content (prefix + suffix).  The 4 extra cols are
 * for " |" before and "| " after the bar.  Result is clamped to [10, 60].
 */
static int bar_width_for_content(int content_cols) {
    int avail = g_term_width - content_cols - 4;
    if (avail < 10) avail = 10;
    if (avail > 60) avail = 60;
    return avail;
}

/*
 * print_bar() — emit filled and empty bar segments with optional color.
 *   filled_col  — ANSI code for filled blocks (or "" for plain)
 *   empty_col   — ANSI code for empty blocks  (or "" for plain)
 */
static void print_bar(int filled, int bar_width,
                      const char *filled_col, const char *empty_col) {
    if (!filled_col || !empty_col) return;
    if (filled_col[0]) fprintf(stdout, "%s", filled_col);
    for (int i = 0; i < filled; i++) fputs("\xe2\x96\x88", stdout);   /* █ */
    if (empty_col[0])  fprintf(stdout, "%s", empty_col);
    for (int i = filled; i < bar_width; i++) fputs("\xe2\x96\x91", stdout); /* ░ */
    if (empty_col[0])  fprintf(stdout, "%s", T_RESET);
}

void util_print_scan_progress(uint64_t block_num, uint64_t total_blocks,
                              double start_time) {
    double now     = util_get_time_ms();
    double elapsed = (now - start_time) / 1000.0;
    double pct     = total_blocks > 0 ? block_num * 100.0 / total_blocks : 0;
    double speed   = elapsed > 0 ? block_num / elapsed : 0;
    double eta     = (speed > 0 && block_num < total_blocks)
                   ? (total_blocks - block_num) / speed : 0;
    /* Position in image: decimal GB on macOS (matches Finder), binary GiB on Linux */
#ifdef __APPLE__
    double gb      = (double)(g_partition_offset + block_num * g_block_size)
                     / (1000.0 * 1000.0 * 1000.0);
#else
    double gb      = (double)(g_partition_offset + block_num * g_block_size)
                     / (1024.0 * 1024.0 * 1024.0);
#endif

    char time_eta[32];
    util_format_time(eta, time_eta);

    /*
     * Visible prefix: "▶ Scanning |" = 13 cols (▶ is 1 display col)
     * Visible suffix:  "| 63.4%  999.9 GB  99,999/s  ETA 99m 59s    "
     *   ≈ 2+5+2+8+2+8+6+7+4 = 44 cols (generous worst-case)
     * Total non-bar content ≈ 57 — used for bar width calculation.
     */
    int bar_width = bar_width_for_content(57);
    int filled    = total_blocks > 0 ? (int)(bar_width * block_num / total_blocks) : 0;
    if (block_num >= total_blocks && total_blocks > 0) filled = bar_width;

    /* Prefix */
    if (g_term_color)
        fprintf(stdout, "\r%s  Scanning |", T_BYELLOW);
    else
        fprintf(stdout, "\r  Scanning |");

    /* Bar */
    print_bar(filled, bar_width,
              g_term_color ? T_BYELLOW : "",
              g_term_color ? T_DIM     : "");

    /* Suffix */
    if (g_term_color)
        fprintf(stdout, "%s| %5.1f%%  %.1f GB  %.0f/s  ETA %s    %s",
                T_BYELLOW, pct, gb, speed, time_eta, T_RESET);
    else
        fprintf(stdout, "| %5.1f%%  %.1f GB  %.0f/s  ETA %s    ",
                pct, gb, speed, time_eta);
    fflush(stdout);
    g_progress_line_active = true;

    log_progress_snapshot("Scanning", block_num, total_blocks, start_time);
}

void util_print_progress(const char *desc, uint64_t current, uint64_t total,
                         double start_time) {
    double now     = util_get_time_ms();
    double elapsed = (now - start_time) / 1000.0;
    double pct     = total > 0 ? (double)current / total * 100.0 : 0;
    double speed   = elapsed > 0 ? current / elapsed : 0;
    double eta     = (speed > 0 && current < total) ? (total - current) / speed : 0;

    char num_cur[32], num_tot[32], time_eta[32];
    util_format_num(current, num_cur);
    util_format_num(total, num_tot);
    util_format_time(eta, time_eta);

    /*
     * Visible prefix: "▶ Extracting |" = 15 cols
     * Visible suffix:  "| 63.4%  [99,999,999/99,999,999]  99,999/s  ETA 99m 59s    "
     *   ≈ 2+5+2+22+2+8+6+7+4 = 58 cols
     * Total non-bar content ≈ 73.
     */
    int bar_width = bar_width_for_content(73);
    int filled    = total > 0 ? (int)(bar_width * current / total) : 0;
    if (current >= total && total > 0) filled = bar_width;

    /* Prefix */
    if (g_term_color)
        fprintf(stdout, "\r%s  %s |", T_BYELLOW, desc);
    else
        fprintf(stdout, "\r  %s |", desc);

    /* Bar */
    print_bar(filled, bar_width,
              g_term_color ? T_BYELLOW : "",
              g_term_color ? T_DIM     : "");

    /* Suffix */
    if (g_term_color) {
        fprintf(stdout, "%s| %5.1f%%  [%s/%s]  %.0f/s  ETA %s  ",
                T_BYELLOW, pct, num_cur, num_tot, speed, time_eta);
    } else {
        fprintf(stdout, "| %5.1f%%  [%s/%s]  %.0f/s  ETA %s  ",
                pct, num_cur, num_tot, speed, time_eta);
    }

    /* Show massive-file skip count during extraction */
    if (g_skipped_size_count > 0 && strcmp(desc, "Extracting") == 0) {
        char sk[32];
        util_format_num(g_skipped_size_count, sk);
        fprintf(stdout, "skipped: %s  ", sk);
    }
    if (g_term_color) fprintf(stdout, "%s", T_RESET);

    fflush(stdout);
    g_progress_line_active = true;

    log_progress_snapshot(desc, current, total, start_time);
}

void util_progress_newline(void) {
    if (g_progress_line_active) {
        fprintf(stdout, "\n");
        fflush(stdout);
        g_progress_line_active = false;
    }
}

/* ============================================================================
 * Inode hash table
 * ============================================================================
 */

static inline uint32_t inode_hash_index(uint64_t inode_id) {
    /* 64-bit finalizer mix, then power-of-two mask */
    uint64_t x = inode_id;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    return (uint32_t)x & (g_inode_hash_capacity - 1);
}

/* #3: Internal unlocked lookup — caller MUST hold g_inode_mutex. */
static inode_t *find_inode_nolock(uint64_t inode_id) {
    if (g_inode_hash) {
        uint32_t idx = inode_hash_index(inode_id);
        for (uint32_t probe = 0; probe < g_inode_hash_capacity; probe++) {
            inode_t *entry = g_inode_hash[idx];
            if (!entry) return NULL;
            if (entry->inode_id == inode_id) return entry;
            idx = (idx + 1) & (g_inode_hash_capacity - 1);
        }
        return NULL;
    }
    /* Fallback: linear scan before hash table is allocated */
    for (int i = 0; i < g_inode_count; i++) {
        if (g_inodes[i].inode_id == inode_id) return &g_inodes[i];
    }
    return NULL;
}

inode_t *find_inode(uint64_t inode_id) {
    pthread_mutex_lock(&g_inode_mutex);
    inode_t *r = find_inode_nolock(inode_id);
    pthread_mutex_unlock(&g_inode_mutex);
    return r;
}

int64_t get_inode_idx(uint64_t inode_id) {
    pthread_mutex_lock(&g_inode_mutex);
    inode_t *ino = find_inode_nolock(inode_id);
    int64_t  r   = ino ? (int64_t)(ino - g_inodes) : -1;
    pthread_mutex_unlock(&g_inode_mutex);
    return r;
}

/*
 * get_or_create_inode_nolock() — core implementation.
 * MUST be called with g_inode_mutex already held by the caller.
 * Finds an existing inode or allocates a new slot (growing the array
 * and rebuilding the hash table if needed).
 */
inode_t *get_or_create_inode_nolock(uint64_t inode_id) {
    inode_t *ino = find_inode_nolock(inode_id);
    if (ino) return ino;

    if (g_inode_count >= (int)g_max_inodes) {
        uint32_t new_max      = g_max_inodes * 2;
        LOG_EXEC_ONLY("Warning: inode table full at %u — growing to %u",
                      g_max_inodes, new_max);
        inode_t *new_inodes   = realloc(g_inodes, new_max * sizeof(inode_t));
        if (!new_inodes) {
            LOG_EXEC_ONLY("Error: inode table realloc failed at %u — inodes lost",
                          g_max_inodes);
            return NULL;
        }

        memset(new_inodes + g_max_inodes, 0,
               (new_max - g_max_inodes) * sizeof(inode_t));
        g_inodes    = new_inodes;
        g_max_inodes = new_max;

        /* Rebuild the hash table at double capacity */
        if (g_inode_hash) {
            uint32_t new_hash_cap = g_inode_hash_capacity * 2;
            free(g_inode_hash);
            g_inode_hash = calloc(new_hash_cap, sizeof(inode_t *));
            if (g_inode_hash) {
                g_inode_hash_capacity = new_hash_cap;
                for (int i = 0; i < g_inode_count; i++) {
                    uint32_t idx = inode_hash_index(g_inodes[i].inode_id);
                    for (uint32_t p = 0; p < g_inode_hash_capacity; p++) {
                        if (!g_inode_hash[idx]) {
                            g_inode_hash[idx] = &g_inodes[i];
                            break;
                        }
                        idx = (idx + 1) & (g_inode_hash_capacity - 1);
                    }
                }
            }
        }
    }

    ino = &g_inodes[g_inode_count++];
    memset(ino, 0, sizeof(inode_t));
    ino->inode_id = inode_id;

    if (g_inode_hash) {
        uint32_t idx = inode_hash_index(inode_id);
        for (uint32_t p = 0; p < g_inode_hash_capacity; p++) {
            if (!g_inode_hash[idx]) {
                g_inode_hash[idx] = ino;
                break;
            }
            idx = (idx + 1) & (g_inode_hash_capacity - 1);
        }
    }

    return ino;
}

inode_t *get_or_create_inode(uint64_t inode_id) {
    pthread_mutex_lock(&g_inode_mutex);
    inode_t *ino = get_or_create_inode_nolock(inode_id);
    pthread_mutex_unlock(&g_inode_mutex);
    return ino;
}

/* ============================================================================
 * Path helpers
 * ============================================================================
 */

char *sanitize_path(const char *src, char *dst, size_t dst_size) {
    if (dst_size == 0) return dst;
    while (*src == '/') src++;
    size_t out = 0;
    while (*src && out + 1 < dst_size) {
        const char *seg     = src;
        size_t      seg_len = 0;
        while (*src && *src != '/') { src++; seg_len++; }
        if (*src == '/') src++;
        /* Drop "." and ".." components */
        if ((seg_len == 1 && seg[0] == '.') ||
            (seg_len == 2 && seg[0] == '.' && seg[1] == '.')) continue;
        /* Count printable characters — drop segments that are pure control chars
         * (e.g. corrupted APFS drec names like ":\x17" appear as ":" in the
         * control-character-free result, which the colon guard then catches). */
        size_t printable = 0;
        for (size_t k = 0; k < seg_len; k++) {
            unsigned char c = (unsigned char)seg[k];
            if (c >= 0x20 && c != 0x7F) printable++;
        }
        if (printable == 0) continue;
        if (out > 0 && out + 1 < dst_size) dst[out++] = '/';
        for (size_t k = 0; k < seg_len && out + 1 < dst_size; k++) {
            unsigned char c = (unsigned char)seg[k];
            if (c >= 0x20 && c != 0x7F)
                dst[out++] = (char)c;
        }
    }
    dst[out] = '\0';
    return dst;
}

void create_directory(const char *path) {
    char *tmp = strdup(path);
    if (!tmp) return;
    char *p = tmp;
    while ((p = strchr(p + 1, '/'))) {
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno == EEXIST) {
            struct stat st;
            if (stat(tmp, &st) == 0 && !S_ISDIR(st.st_mode)) {
                /* A file is blocking the directory path — rename it. */
                char renamed[MAX_PATH_LEN];
                snprintf(renamed, sizeof(renamed), "%s.file_collision", tmp);
                if (rename(tmp, renamed) != 0 || mkdir(tmp, 0755) != 0)  /* #21 */
                    LOG_DEBUG("create_directory: collision resolve failed for %s", tmp);
            }
        }
        *p = '/';
    }
    free(tmp);
}

/* ============================================================================
 * Extension filter
 * ============================================================================
 */

bool util_matches_filter_ext(const char *filename) {
    if (g_filter_ext_count == 0) return true;
    if (!filename) return false;

    const char *dot = strrchr(filename, '.');
    if (!dot || dot[1] == '\0') return false;
    const char *ext = dot + 1;

    for (int i = 0; i < g_filter_ext_count; i++) {
        const char *f = g_filter_exts[i];
        /* Case-insensitive compare without requiring strcasecmp. */
        size_t j = 0;
        while (f[j] && tolower((unsigned char)ext[j]) == tolower((unsigned char)f[j]))  /* #13 */
            j++;
        if (f[j] == '\0' && ext[j] == '\0') return true;
    }
    return false;
}
