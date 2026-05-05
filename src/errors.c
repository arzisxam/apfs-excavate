/*
 * errors.c — thread-safe error and warning collection.
 */

#define _GNU_SOURCE
#include "errors.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "apfs_globals.h"
#include "log.h"

void err_add(error_severity_t severity,
             uint64_t inode_id,
             const char *path,
             const char *msg) {
    pthread_mutex_lock(&g_stats_mutex);

    /* #22: enforce g_max_errors cap (documented but previously not enforced). */
    if (g_max_errors > 0 && (uint32_t)g_error_count >= g_max_errors) {
        pthread_mutex_unlock(&g_stats_mutex);
        return;
    }

    if (g_error_count >= (int)g_error_capacity) {
        uint32_t new_cap = g_error_capacity == 0 ? 1024 : g_error_capacity * 2;
        error_record_t *new_errors = realloc(g_errors, new_cap * sizeof(error_record_t));
        if (!new_errors) {
            pthread_mutex_unlock(&g_stats_mutex);
            return;
        }
        g_errors = new_errors;
        g_error_capacity = new_cap;
    }

    error_record_t *e = &g_errors[g_error_count++];
    e->severity  = severity;
    e->inode_id  = inode_id;
    e->block_num = 0;
    e->timestamp = time(NULL);

    bool path_truncated = path && strlen(path) >= sizeof(e->file_path);
    bool msg_truncated  = msg  && strlen(msg)  >= sizeof(e->message);

    strncpy(e->file_path, path ? path : "", sizeof(e->file_path) - 1);
    e->file_path[sizeof(e->file_path) - 1] = '\0';

    strncpy(e->message, msg ? msg : "", sizeof(e->message) - 1);
    e->message[sizeof(e->message) - 1] = '\0';

    pthread_mutex_unlock(&g_stats_mutex);

    if (path_truncated)
        LOG_EXEC_ONLY("[WARN] error record: file_path truncated to %zu bytes",
                      sizeof(e->file_path) - 1);
    if (msg_truncated)
        LOG_EXEC_ONLY("[WARN] error record: message truncated to %zu bytes",
                      sizeof(e->message) - 1);

    /* Emit real-time log entry so the message appears in execution.log
     * immediately (not just in error.log at end of run).
     * Use log_exec_only so high-volume I/O errors (e.g. disk-full fwrite
     * failures) don't flood the terminal — they remain in execution.log. */
    const char *sev_tag = (severity == ERR_ERROR) ? "ERROR" : "WARN";
    if (inode_id && path && path[0])
        LOG_EXEC_ONLY("[%s] [inode %llu] %s — %s", sev_tag,
                      (unsigned long long)inode_id, msg ? msg : "", path);
    else if (inode_id)
        LOG_EXEC_ONLY("[%s] [inode %llu] %s", sev_tag,
                      (unsigned long long)inode_id, msg ? msg : "");
    else if (path && path[0])
        LOG_EXEC_ONLY("[%s] %s — %s", sev_tag, msg ? msg : "", path);
    else
        LOG_EXEC_ONLY("[%s] %s", sev_tag, msg ? msg : "");
}
