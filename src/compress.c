/*
 * compress.c — LZVN, LZFSE, and zlib decompression for APFS transparent
 *              compression (com.apple.decmpfs).
 */

#define _GNU_SOURCE
#include "compress.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#ifdef __APPLE__
#include <compression.h>
#endif

#include "apfs_globals.h"
#include "block_io.h"
#include "compat.h"
#include "crypto.h"
#include "log.h"
#include "errors.h"

/* ============================================================================
 * LZVN decompression
 * ============================================================================
 */

size_t cmp_lzvn(const uint8_t *src, size_t src_len,
                uint8_t *dst, size_t dst_len) {
    size_t src_pos = 0, dst_pos = 0;

    while (src_pos < src_len && dst_pos < dst_len) {
        uint8_t cmd = src[src_pos++];

        if (cmd == 0x06) break; /* End of stream */

        /* Small literal (0xE0–0xEF) */
        if ((cmd & 0xF0) == 0xE0) {
            size_t len = (cmd & 0x0F) + 1;
            if (src_pos + len > src_len || dst_pos + len > dst_len) break;
            memcpy(dst + dst_pos, src + src_pos, len);
            src_pos += len; dst_pos += len;
        }
        /* Large literal (0xF0) */
        else if ((cmd & 0xF0) == 0xF0) {
            if (cmd == 0xF0 && src_pos < src_len) {
                size_t len = src[src_pos++] + 16;
                if (src_pos + len > src_len || dst_pos + len > dst_len) break;
                memcpy(dst + dst_pos, src + src_pos, len);
                src_pos += len; dst_pos += len;
            } else {
                break; /* Unknown opcode 0xF1–0xFF: corrupt stream */
            }
        }
        /* Match with small distance */
        else if ((cmd & 0xF0) <= 0x50) {
            size_t match_len = ((cmd >> 4) & 0x07) + 3;
            if (src_pos >= src_len) break;
            size_t distance = ((size_t)(cmd & 0x0F) << 8) | src[src_pos++];
            if (distance == 0 || distance > dst_pos) break;
            for (size_t i = 0; i < match_len && dst_pos < dst_len; i++) {
                dst[dst_pos] = dst[dst_pos - distance];
                dst_pos++;
            }
        }
        /* Match with medium distance */
        else if ((cmd & 0xC0) == 0x80) {
            size_t match_len = (cmd & 0x0F) + 3;
            if (src_pos + 1 >= src_len) break;
            size_t distance = ((size_t)(cmd & 0x30) << 4) | src[src_pos] |
                              ((size_t)src[src_pos+1] << 8);
            src_pos += 2;
            distance &= 0x3FFF;
            if (distance == 0 || distance > dst_pos) break;
            for (size_t i = 0; i < match_len && dst_pos < dst_len; i++) {
                dst[dst_pos] = dst[dst_pos - distance];
                dst_pos++;
            }
        }
        /* Simple literal copy */
        else if (cmd < 0x06) {
            size_t len = cmd;
            if (src_pos + len > src_len || dst_pos + len > dst_len) break;
            memcpy(dst + dst_pos, src + src_pos, len);
            src_pos += len; dst_pos += len;
        }
    }
    return dst_pos;
}

size_t cmp_lzfse(const uint8_t *src, size_t src_len,
                 uint8_t *dst, size_t dst_len) {
    if (src_len < 4) return 0;

    if (memcmp(src, "bvx2", 4) == 0 || memcmp(src, "bvx1", 4) == 0) {
#ifdef __APPLE__
        return compression_decode_buffer(dst, dst_len, src, src_len,
                                         NULL, COMPRESSION_LZFSE);
#else
        ERR_ADD_WARNING("LZFSE decompression requires macOS (skipping file)", 0, "");
        return 0;
#endif
    }
    if (memcmp(src, "bvxn", 4) == 0) {
        /* LZFSE-wrapped LZVN block */
        if (src_len < 12) return 0;
        uint32_t uncompressed = get_u32(src + 4);
        uint32_t compressed   = get_u32(src + 8);
        if (compressed > src_len - 12) return 0;
        return cmp_lzvn(src + 12, compressed, dst,
                        uncompressed < dst_len ? uncompressed : dst_len);
    }
    if (memcmp(src, "bvx-", 4) == 0) {
        /* Uncompressed block */
        if (src_len < 8) return 0;
        uint32_t size = get_u32(src + 4);
        if (8 + size > src_len || size > dst_len) return 0;
        memcpy(dst, src + 8, size);
        return size;
    }
    /* Fallback: try raw LZVN */
    return cmp_lzvn(src, src_len, dst, dst_len);
}

/* ============================================================================
 * Transparent file decompression
 * ============================================================================
 */

uint8_t *cmp_decompress_file(inode_t *ino, size_t *out_len) {
    *out_len = 0;
    if (!ino->is_compressed || !g_enable_compression) return NULL;

    uint32_t comp_type  = ino->compression_type;
    uint64_t uncomp_sz  = ino->uncompressed_size;
    if (uncomp_sz == 0) uncomp_sz = ino->size;
    /* 512 MB cap — prevents OOM from corrupt metadata */
    if (uncomp_sz == 0 || uncomp_sz > 512ULL * 1024 * 1024) return NULL;

    uint8_t *output = malloc(uncomp_sz);
    if (!output) return NULL;

    /* ---- Try inline data from decmpfs xattr first ---- */
    if (ino->decmpfs_data && ino->decmpfs_len > 16) {
        const uint8_t *cdata = ino->decmpfs_data + 16;
        size_t         clen  = ino->decmpfs_len  - 16;

        if (comp_type == COMP_ZLIB_ATTR || comp_type == COMP_ZLIB_RSRC) {
            uLongf dest_len = (uLongf)uncomp_sz;
            if (uncompress(output, &dest_len, cdata, (uLong)clen) == Z_OK) {
                *out_len = dest_len;
                return output;
            }
        } else if (comp_type == COMP_LZVN_ATTR || comp_type == COMP_LZVN_RSRC) {
            size_t len = cmp_lzvn(cdata, clen, output, uncomp_sz);
            if (len > 0) { *out_len = len; return output; }
        } else if (comp_type == COMP_LZFSE_ATTR || comp_type == COMP_LZFSE_RSRC) {
            size_t len = cmp_lzfse(cdata, clen, output, uncomp_sz);
            if (len > 0) { *out_len = len; return output; }
        }
    }

    /* ---- Try resource-fork extents ---- */
    if (ino->extent_count > 0) {
        /* Cap at 4× the uncompressed size or 1 GB; guard against overflow. */
        size_t cap = (uncomp_sz <= 256ULL * 1024 * 1024)
                     ? uncomp_sz * 4
                     : 1024ULL * 1024 * 1024;
        size_t total_size = 0;
        for (int i = 0; i < ino->extent_count; i++) {
            uint64_t ext_len = ino->extents[i].length;
            if (ext_len > cap - total_size) { total_size = cap; break; }
            total_size += (size_t)ext_len;
        }
        if (total_size == 0) { free(output); return NULL; }

        uint8_t *compressed = malloc(total_size);
        if (!compressed) { free(output); return NULL; }

        uint8_t *tmp_block = malloc(g_block_size);
        if (!tmp_block) { free(compressed); free(output); return NULL; }

        size_t pos = 0;
        for (int i = 0; i < ino->extent_count && pos < total_size; i++) {
            uint64_t ext_bytes  = ino->extents[i].length;
            uint64_t ext_blocks = (ext_bytes + g_block_size - 1) / g_block_size;
            /* Resolve per-extent crypto state once per extent, matching the
             * same logic used in recovery.c so encrypted resource forks
             * decrypt with the correct key even when multiple crypto states
             * are present on the volume. */
            aes_xts_ctx_t ext_ctx;
            bool ext_ctx_ok = false;
            if (g_encryption_enabled) {
                uint64_t cid = (ino->extents[i].crypto_id == 0 &&
                                ino->default_crypto_id != 0)
                             ? ino->default_crypto_id
                             : ino->extents[i].crypto_id;
                crypto_state_t *cs = crypto_lookup_state(cid);
                if (cs && cs->initialized) {
                    crypto_aes_xts_init(&ext_ctx, cs->key, cs->key + 16);
                    ext_ctx_ok = true;
                }
            }
            for (uint64_t b = 0; b < ext_blocks && pos < total_size; b++) {
                uint64_t phys_blk = ino->extents[i].physical + b;
                bool rd_ok = bio_read_block(phys_blk, tmp_block);
                if (rd_ok && g_encryption_enabled) {
                    const aes_xts_ctx_t *ctx = ext_ctx_ok ? &ext_ctx : &g_aes_xts;
                    (void)crypto_aes_xts_decrypt_with_sector_offset(
                        ctx, tmp_block, tmp_block, g_block_size,
                        0, (int64_t)(phys_blk * (g_block_size / 512)));
                }
                size_t to_copy = g_block_size;
                if (pos + to_copy > total_size) to_copy = total_size - pos;
                memcpy(compressed + pos, tmp_block, to_copy);
                pos += to_copy;
            }
        }
        free(tmp_block);

        /* APFS resource-fork compressed data is preceded by a 256-byte header
         * whose first four bytes are always the big-endian value 0x00000100. */
        const uint8_t *rsrc_data = compressed;
        size_t         rsrc_len  = total_size;
        if (total_size > 256 &&
            compressed[0] == 0x00 && compressed[1] == 0x00 &&
            compressed[2] == 0x01 && compressed[3] == 0x00) {
            rsrc_data = compressed + 256;
            rsrc_len  = total_size - 256;
        }

        if (comp_type == COMP_ZLIB_RSRC || comp_type == COMP_ZLIB_ATTR) {
            uLongf dest_len = (uLongf)uncomp_sz;
            if (uncompress(output, &dest_len, rsrc_data, (uLong)rsrc_len) == Z_OK) {
                free(compressed);
                *out_len = dest_len;
                return output;
            }
            /* Raw deflate fallback */
            z_stream zs = {0};
            if (inflateInit2(&zs, -15) == Z_OK) {
                zs.next_in   = (Bytef *)rsrc_data;
                zs.avail_in  = (uInt)rsrc_len;
                zs.next_out  = output;
                zs.avail_out = (uInt)uncomp_sz;
                int ret = inflate(&zs, Z_FINISH);
                inflateEnd(&zs);
                if (ret == Z_STREAM_END) {
                    free(compressed);
                    *out_len = uncomp_sz - zs.avail_out;
                    return output;
                }
            }
        } else if (comp_type == COMP_LZVN_RSRC || comp_type == COMP_LZVN_ATTR) {
            size_t len = cmp_lzvn(rsrc_data, rsrc_len, output, uncomp_sz);
            if (len > 0) { free(compressed); *out_len = len; return output; }
        } else if (comp_type == COMP_LZFSE_RSRC || comp_type == COMP_LZFSE_ATTR) {
            size_t len = cmp_lzfse(rsrc_data, rsrc_len, output, uncomp_sz);
            if (len > 0) { free(compressed); *out_len = len; return output; }
        }
        free(compressed);
    }

    free(output);
    return NULL;
}
