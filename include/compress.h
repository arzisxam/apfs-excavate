#pragma once
/*
 * compress.h — decompression for APFS transparent compression.
 *
 * Supported algorithms: zlib (COMP_ZLIB_*), LZVN (COMP_LZVN_*),
 * LZFSE (COMP_LZFSE_* — macOS only via <compression.h>).
 *
 * On Linux, LZFSE-compressed files produce a warning and return NULL.
 */

#include <stdint.h>
#include <stddef.h>
#include "apfs_types.h"

/*
 * cmp_lzvn() — decompress src_len bytes of LZVN data into dst.
 * Returns the number of bytes written to dst (0 on error).
 */
size_t cmp_lzvn(const uint8_t *src, size_t src_len,
                uint8_t *dst, size_t dst_len);

/*
 * cmp_lzfse() — decompress LZFSE / LZFSE-wrapped-LZVN / uncompressed data.
 * Returns the number of bytes written to dst (0 on error or unsupported).
 */
size_t cmp_lzfse(const uint8_t *src, size_t src_len,
                 uint8_t *dst, size_t dst_len);

/*
 * cmp_decompress_file() — transparently decompress a compressed inode.
 * Tries inline decmpfs xattr data first, then resource-fork extents.
 * Returns a malloc'd buffer (*out_len bytes) or NULL on failure.
 * Caller must free() the returned buffer.
 */
uint8_t *cmp_decompress_file(inode_t *ino, size_t *out_len);
