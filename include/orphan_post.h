#pragma once
/*
 * orphan_post.h — post-extraction orphan file classification and decompression.
 *
 * Called after the extraction phase.  For every .dat file in orphan_dir:
 *   1. Detect and strip the APFS compression header (fpmc or simplified).
 *   2. Decompress using LZVN / LZFSE / ZLIB.
 *   3. Identify file type from magic bytes and text patterns.
 *   4. Rename with the correct extension.
 *   5. Move unidentifiable files to orphan_dir/unrecoverable/.
 *
 * Updates result->orphans_decompressed, ->orphans_identified, ->orphans_unrecoverable.
 */

#include "apfs_types.h"

bool orphan_post_process(const char *orphan_dir, const char *output_dir, result_t *result);

/* Classify raw bytes by magic / text patterns; returns extension string or NULL.
 * Exposed for unit testing — production code should call orphan_post_process(). */
const char *orphan_classify_content(const uint8_t *buf, size_t len);
