#pragma once
/*
 * report.h — always-on Markdown report generation.
 *
 * Three files are written to <output_dir>/ at the end of every run:
 *
 *   recovery_summary.md   — run metadata, scan/recovery statistics, timing
 *   unrecovered_files.md  — files found in metadata but not extracted
 *   error.log             — timestamped errors and warnings from g_errors[]
 *
 * None of these require a CLI flag; they are generated unconditionally.
 */

#include "apfs_types.h"

/*
 * report_write_summary() — write recovery_summary.md.
 * image_path is the original image file path (for the image info table).
 */
void report_write_summary(const char *output_dir, const result_t *result,
                          const char *image_path);

/*
 * report_write_unrecovered() — write unrecovered_files.md from g_unrecovered[].
 * Includes both named failures and orphan placements.
 */
void report_write_unrecovered(const char *output_dir);

/*
 * report_write_error_log() — write error.log from g_errors[].
 * One line per event with ISO timestamp, severity, and context.
 */
void report_write_error_log(const char *output_dir);

/*
 * report_write_skipped_files() — write logs/skipped_files.md from g_unrecovered[]
 * entries that were skipped due to size filter (--max-size / --min-size).
 * Only written when g_skipped_size_count > 0.
 */
void report_write_skipped_files(const char *output_dir);
