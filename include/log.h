#pragma once
/*
 * log.h — two-mode logging API
 *
 * Default mode: LOG_NORMAL messages go to stdout (and execution.log) with a
 *               timestamp prefix.
 * Debug mode:   LOG_DEBUG messages go to <output_dir>/debug_<ts>.log only.
 *
 * execution.log is always created in output_dir regardless of --debug.
 * It receives all LOG_NORMAL and LOG_ERROR messages with full timestamps.
 * Progress bar updates are terminal-only and never written to the log file.
 *
 * Enable debug mode by passing --debug on the command line; this sets
 * g_debug_mode = true before calling log_init().
 */

#include <stdbool.h>
#include <stdint.h>

/*
 * log_init() — open execution.log (always) in logs_dir, and the debug log
 * file (if debug mode is active).  Must be called after g_logs_dir is set.
 * logs_dir is the path to the logs/ subdirectory under output_dir.
 */
void log_init(const char *logs_dir, bool debug_mode);

/*
 * log_shutdown() — flush and close all log files.
 */
void log_shutdown(void);

/*
 * log_normal() — written to stdout AND execution.log with timestamp prefix.
 * If a progress bar is currently displayed it is cleared first.
 */
void log_normal(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/*
 * log_debug() — written to the debug log file only; never to stdout.
 * No-op when debug mode is off.
 */
void log_debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/*
 * log_error() — written to stderr AND execution.log; also to debug file if open.
 * Clears any active progress bar line first.
 */
void log_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/*
 * log_exec_only() — written to execution.log and debug log only; NOT to
 * the terminal.  Use for verbose messages that should be recorded but should
 * not interrupt the progress display (e.g. "Skipping massive file").
 */
void log_exec_only(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/*
 * log_progress_snapshot() — write a progress line to execution.log at every
 * 10% boundary.  Call from within progress bar update functions so the log
 * file contains a readable timeline even though the terminal shows in-place
 * progress bars.  No-op when execution log is not open or threshold not met.
 */
void log_progress_snapshot(const char *desc, uint64_t current, uint64_t total,
                            double start_ms);

/*
 * Convenience macros — prefer these over calling the functions directly
 * so the call site is easy to grep.
 */
#define LOG_NORMAL(...)    log_normal(__VA_ARGS__)
#define LOG_DEBUG(...)     log_debug(__VA_ARGS__)
#define LOG_ERROR(...)     log_error(__VA_ARGS__)
#define LOG_EXEC_ONLY(...) log_exec_only(__VA_ARGS__)

/*
 * Styled output macros (terminal gets colored icon; log file gets plain tag).
 *
 * LOG_PHASE(n, name) — bold-cyan ▶ Phase N: name header with blank line before
 * LOG_OK(...)        — green  ✓  success line
 * LOG_WARN(...)      — yellow ⚠  warning line
 * LOG_ERR(...)       — bold-red ✗  error line (goes to stdout, not stderr)
 * LOG_INFO(...)      — dim    ·  informational line
 */
#define LOG_PHASE(num, name)  log_phase_header(num, name)
#define LOG_STEP(name)        log_step_header(name)
#define LOG_OK(...)           log_status('o', __VA_ARGS__)
#define LOG_WARN(...)         log_status('w', __VA_ARGS__)
#define LOG_ERR(...)          log_status('e', __VA_ARGS__)
#define LOG_INFO(...)         log_status('i', __VA_ARGS__)

void log_phase_header(int num, const char *name);

/*
 * log_step_header() — ▶ name on terminal (same style as log_phase_header
 * but without a phase number in the exec log). Used for sub-steps.
 */
void log_step_header(const char *name);

void log_status(char icon, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
