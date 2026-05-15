#pragma once
/*
 * block_io.h — low-level disk block reading with optional AES-XTS decryption.
 */

#include <stdint.h>
#include <stdbool.h>

/*
 * bio_read_block() — read one block from the disk image into buffer.
 * Uses pread(2) with retries when a file descriptor is open; falls back
 * to the mmap region otherwise.
 * buffer must be at least g_block_size bytes.
 * Returns false if block_num is out of range (buffer is zeroed).
 */
bool bio_read_block(uint64_t block_num, uint8_t *buffer);

/*
 * bio_read_decrypt() — read one block then decrypt in-place with g_aes_xts
 * if encryption is enabled.  Otherwise identical to bio_read_block().
 * Returns false if bio_read_block returns false.
 */
bool bio_read_decrypt(uint64_t block_num, uint8_t *buffer);
