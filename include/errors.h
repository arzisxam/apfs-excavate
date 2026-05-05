#pragma once
/*
 * errors.h — thread-safe error and warning collection.
 *
 * Errors are stored in g_errors[] (defined in globals.c) and written to
 * error.log at the end of the run by report_write_error_log().
 */

#include <stdint.h>
#include "apfs_types.h"

/*
 * err_add() — record an error event.
 * Thread-safe; dynamically grows the error buffer up to g_max_errors.
 */
void err_add(error_severity_t severity,
             uint64_t inode_id,
             const char *path,
             const char *msg);

/* Convenience wrappers */
#define ERR_ADD_ERROR(msg, inode, path)   err_add(ERR_ERROR,   (inode), (path), (msg))
#define ERR_ADD_WARNING(msg, inode, path) err_add(ERR_WARNING, (inode), (path), (msg))
#define ERR_ADD_INFO(msg, inode, path)    err_add(ERR_INFO,    (inode), (path), (msg))
