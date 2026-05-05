/*
 * log.c — two-mode logging implementation.
 *
 * Log destinations:
 *   s_exec_file  — always-on execution.log in logs_dir (LOG_NORMAL + LOG_ERROR)
 *   s_debug_file — debug_<ts>.log, opened only when --debug is passed
 *
 * Terminal behaviour:
 *   Progress bars use \r in-place refresh.  When a log message is printed, the
 *   active progress bar line is erased with \r\033[K before the message so bars
 *   do not leave trailing artefacts.
 *
 *   Messages that begin with \n (e.g. LOG_NORMAL("\nPhase 3: ...")) emit the
 *   blank line(s) first then print the actual text with a timestamp on its own
 *   line, so every user-visible line has a proper [HH:MM:SS] prefix.
 *
 * Progress snapshots:
 *   log_progress_snapshot() writes a brief progress line to the exec log at
 *   every 10% boundary so the log file contains a readable timeline.
 */

#define _GNU_SOURCE
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "apfs_globals.h"
#include "util.h"
#include "term.h"

/* Always-on execution log (mirrors LOG_NORMAL + LOG_ERROR) */
static FILE *s_exec_file  = NULL;

/* Optional debug log (--debug only) */
static FILE *s_debug_file = NULL;

/* #18: serialise concurrent log calls (timestamp + write must be atomic). */
static pthread_mutex_t s_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================================
 * Internal helpers
 * ============================================================================
 */

static void timestamp(char *buf, size_t bufsz) {
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm_info = localtime_r(&now, &tm_buf);  /* #19: thread-safe */
    strftime(buf, bufsz, "%Y-%m-%d %H:%M:%S", tm_info);
}

/*
 * Clear the progress bar line on the terminal with ANSI erase-to-EOL so the
 * subsequent log message prints cleanly without leaving bar artefacts.
 */
static void clear_progress_line(FILE *out) {
    if (g_progress_line_active) {
        fprintf(out, "\r\033[K");
        fflush(out);
        g_progress_line_active = false;
    }
}

/* ============================================================================
 * Public API
 * ============================================================================
 */

void log_init(const char *logs_dir, bool debug_mode) {
    if (!logs_dir) return;

    char ts[32];
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm_info = localtime_r(&now, &tm_buf);
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", tm_info);

    /* Always-on execution log — lives in logs/ dir */
    char exec_path[4096];
    snprintf(exec_path, sizeof(exec_path), "%s/execution.log", logs_dir);
    s_exec_file = fopen(exec_path, "w");
    if (s_exec_file) {
        char hdr[64];
        strftime(hdr, sizeof(hdr), "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(s_exec_file, "[%s] Execution log: %s\n", hdr, exec_path);
        fflush(s_exec_file);
    }

    /* Optional debug log */
    if (!debug_mode) return;

    char dbg_path[4096];
    snprintf(dbg_path, sizeof(dbg_path), "%s/debug_%s.log", logs_dir, ts);
    s_debug_file = fopen(dbg_path, "w");
    if (s_debug_file) {
        fprintf(stdout, "[%s] Debug log: %s\n", ts, dbg_path);
        fflush(stdout);
    }
}

void log_shutdown(void) {
    if (s_exec_file) {
        fflush(s_exec_file);
        fclose(s_exec_file);
        s_exec_file = NULL;
    }
    if (s_debug_file) {
        fflush(s_debug_file);
        fclose(s_debug_file);
        s_debug_file = NULL;
    }
}

void log_normal(const char *fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    pthread_mutex_lock(&s_log_mutex);    /* #18 */
    char ts[32];
    timestamp(ts, sizeof(ts));

    /* Strip trailing newline — we always add our own. */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[--len] = '\0';

    /*
     * Handle leading newlines: caller uses "\nPhase N: ..." to request a
     * blank separator line before the message.  We emit the blank lines
     * first, then the timestamped message on its own line, so every visible
     * line has a [HH:MM:SS] prefix.
     */
    char *msg = buf;
    int leading = 0;
    while (*msg == '\n') { msg++; leading++; }

    /* Clear any active progress bar before writing to the terminal. */
    clear_progress_line(stdout);

    /* Blank separator lines (no timestamp). */
    for (int i = 0; i < leading; i++) {
        fprintf(stdout, "\n");
        if (s_exec_file) fprintf(s_exec_file, "\n");
    }

    if (*msg == '\0') {
        fflush(stdout);
        pthread_mutex_unlock(&s_log_mutex);
        return;
    }

    /* Terminal: plain message, no timestamp prefix. */
    fprintf(stdout, "%s\n", msg);
    fflush(stdout);

    /* Log file: timestamp + [INFO] tag. */
    if (s_exec_file) {
        fprintf(s_exec_file, "[%s] [INFO] %s\n", ts, msg);
        fflush(s_exec_file);
    }
    pthread_mutex_unlock(&s_log_mutex);
}

void log_debug(const char *fmt, ...) {
    if (!s_debug_file) return;

    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[--len] = '\0';

    pthread_mutex_lock(&s_log_mutex);
    char ts[32];
    timestamp(ts, sizeof(ts));
    fprintf(s_debug_file, "[%s] [DEBUG] %s\n", ts, buf);
    fflush(s_debug_file);
    pthread_mutex_unlock(&s_log_mutex);
}

void log_error(const char *fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[--len] = '\0';

    pthread_mutex_lock(&s_log_mutex);
    char ts[32];
    timestamp(ts, sizeof(ts));
    clear_progress_line(stderr);
    if (g_term_color_err) {                              /* #26: stderr has its own flag */
        fprintf(stderr, "%s%s%s%s\n", T_BRED, ICON_ERR, buf, T_RESET);
    } else {
        fprintf(stderr, "[ERROR] %s\n", buf);
    }
    fflush(stderr);

    if (s_exec_file) {
        fprintf(s_exec_file, "[%s] [ERROR] %s\n", ts, buf);
        fflush(s_exec_file);
    }
    if (s_debug_file) {
        fprintf(s_debug_file, "[%s] [ERROR] %s\n", ts, buf);
        fflush(s_debug_file);
    }
    pthread_mutex_unlock(&s_log_mutex);
}

void log_exec_only(const char *fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[--len] = '\0';

    pthread_mutex_lock(&s_log_mutex);
    char ts[32];
    timestamp(ts, sizeof(ts));
    if (s_exec_file) {
        fprintf(s_exec_file, "[%s] [INFO] %s\n", ts, buf);
        fflush(s_exec_file);
    }
    if (s_debug_file) {
        fprintf(s_debug_file, "[%s] [INFO] %s\n", ts, buf);
        fflush(s_debug_file);
    }
    pthread_mutex_unlock(&s_log_mutex);
}

void log_progress_snapshot(const char *desc, uint64_t current, uint64_t total,
                            double start_ms) {
    if (!s_exec_file || total == 0) return;

    int pct = (int)(current * 100ULL / total);

    /*
     * Track the last logged 10%-boundary per description.
     * Key on the full desc string (SNAP_KEY_LEN chars) so phase names that
     * share a prefix are still treated as distinct slots.
     */
    #define SNAP_SLOTS   8
    #define SNAP_KEY_LEN 64
    static struct { char key[SNAP_KEY_LEN]; int last_pct; } slots[SNAP_SLOTS];
    static int slot_count = 0;

    /* Find or create a slot for this desc. */
    int si = -1;

    pthread_mutex_lock(&s_log_mutex);
    for (int i = 0; i < slot_count; i++) {
        if (strncmp(slots[i].key, desc, SNAP_KEY_LEN - 1) == 0) { si = i; break; }
    }
    if (si < 0) {
        if (slot_count < SNAP_SLOTS) {
            si = slot_count++;
            strncpy(slots[si].key, desc, SNAP_KEY_LEN - 1);
            slots[si].key[SNAP_KEY_LEN - 1] = '\0';
            slots[si].last_pct = -1;
        } else {
            pthread_mutex_unlock(&s_log_mutex);
            return;   /* table full — skip */
        }
    }

    int boundary = (pct / 10) * 10;
    if (boundary <= slots[si].last_pct) {
        pthread_mutex_unlock(&s_log_mutex);
        return;
    }
    slots[si].last_pct = boundary;

    char ts[32];
    timestamp(ts, sizeof(ts));

    double elapsed = (util_get_time_ms() - start_ms) / 1000.0;
    char te[32], nc[32], nt[32];
    util_format_time(elapsed, te);
    util_format_num(current, nc);
    util_format_num(total, nt);

    fprintf(s_exec_file, "[%s] [PROGRESS] %s: %d%% [%s / %s]  elapsed: %s\n",
            ts, desc, pct, nc, nt, te);
    fflush(s_exec_file);
    pthread_mutex_unlock(&s_log_mutex);
}

/* ============================================================================
 * Styled phase header and status lines
 * ============================================================================
 */

void log_phase_header(int num, const char *name) {
    char ts[32];
    timestamp(ts, sizeof(ts));

    /* Log file: timestamped plain text */
    if (s_exec_file) {
        fprintf(s_exec_file, "\n[%s] [INFO] Phase %d: %s\n", ts, num, name);
        fflush(s_exec_file);
    }

    /* Terminal: blank line + bold-cyan ▶ name (no phase number — avoids confusion
     * when phases are conditionally skipped; log file has the number for tracing) */
    clear_progress_line(stdout);
    if (g_term_color) {
        fprintf(stdout, "\n%s%s%s%s\n", T_BCYAN, PHASE_MARK, name, T_RESET);
    } else {
        fprintf(stdout, "\n%s\n", name);
    }
    fflush(stdout);
}

void log_step_header(const char *name) {
    char ts[32];
    timestamp(ts, sizeof(ts));

    /* Log file: plain [INFO] with no phase number */
    if (s_exec_file) {
        fprintf(s_exec_file, "[%s] [INFO] %s\n", ts, name);
        fflush(s_exec_file);
    }

    /* Terminal: blank line + bold-cyan ▶ name (same visual style as phase headers) */
    clear_progress_line(stdout);
    if (g_term_color) {
        fprintf(stdout, "\n%s%s%s%s\n", T_BCYAN, PHASE_MARK, name, T_RESET);
    } else {
        fprintf(stdout, "\n%s\n", name);
    }
    fflush(stdout);
}

void log_status(char icon, const char *fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[--len] = '\0';

    pthread_mutex_lock(&s_log_mutex);
    char ts[32];
    timestamp(ts, sizeof(ts));

    const char *color    = "";
    const char *icon_str = "";
    const char *tag      = "INFO";
    switch (icon) {
        case 'o': color = T_BGREEN;  icon_str = ICON_OK;   tag = "OK";   break;
        case 'w': color = T_BMAGENTA; icon_str = ICON_WARN; tag = "WARN"; break;
        case 'e': color = T_BRED;    icon_str = ICON_ERR;  tag = "ERR";  break;
        case 'i': color = T_DIM;     icon_str = ICON_INFO; tag = "INFO"; break;
        default:  break;
    }

    clear_progress_line(stdout);
    if (g_term_color) {
        fprintf(stdout, "%s%s%s%s\n", color, icon_str, buf, T_RESET);
    } else {
        fprintf(stdout, "[%s] %s\n", tag, buf);
    }
    fflush(stdout);

    if (s_exec_file) {
        fprintf(s_exec_file, "[%s] [%s] %s\n", ts, tag, buf);
        fflush(s_exec_file);
    }
    pthread_mutex_unlock(&s_log_mutex);
}
