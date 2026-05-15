/*
 * block_io.c — disk block reading with retry logic and optional decryption.
 */

#define _GNU_SOURCE
#include "block_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "apfs_globals.h"
#include "crypto.h"
#include "log.h"

bool bio_read_block(uint64_t block_num, uint8_t *buffer) {
    /* Overflow guard */
    if (g_block_size > 0 &&
        block_num > (SIZE_MAX - g_partition_offset) / g_block_size) {
        memset(buffer, 0, g_block_size);
        return false;
    }
    size_t offset = g_partition_offset + block_num * g_block_size;
    if (offset + g_block_size > g_data_size) {
        memset(buffer, 0, g_block_size);
        return false;
    }

    if (g_fd >= 0) {
        int retries = 3;
        while (retries > 0) {
            ssize_t bytes = pread(g_fd, buffer, g_block_size, (off_t)offset);
            if (bytes == (ssize_t)g_block_size) return true;
            retries--;
            if (retries > 0)
                LOG_DEBUG("read_block retry at offset %zu (%d left)",
                          offset, retries);
        }
        /* pread failed after all retries.  Zero the buffer and return false so
         * callers can distinguish a clean read from a damaged-block read.
         * Do NOT fall through to the mmap memcpy: if pread is failing the
         * same region, the mmap access will SIGBUS on a torn page. */
        LOG_DEBUG("read_block: block %llu unreadable after 3 attempts",
                  (unsigned long long)block_num);
        memset(buffer, 0, g_block_size);
        return false;
    }

    /* mmap-only (no file descriptor): copy directly from the mapped region.
     * Bounds-checked above; a SIGBUS here means the backing file has a torn
     * page — acceptable risk for mmap-only mode. */
    memcpy(buffer, g_data + offset, g_block_size);
    return true;
}

bool bio_read_decrypt(uint64_t block_num, uint8_t *buffer) {
    if (!bio_read_block(block_num, buffer)) return false;
    /* XTS decrypts in-place safely: inner loop copies 16 bytes to locals
     * before writing, so ciphertext == plaintext pointer is fine. */
    if (g_encryption_enabled && g_aes_xts.initialized)
        (void)crypto_aes_xts_decrypt(&g_aes_xts, buffer, buffer, g_block_size, block_num);
    return true;
}
