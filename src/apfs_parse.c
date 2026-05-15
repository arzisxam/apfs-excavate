/*
 * apfs_parse.c — APFS B-tree parsing.
 *
 * Parses leaf node key/value pairs and populates the in-memory
 * drec, inode, extent, xattr, and crypto-state tables.
 */

#define _GNU_SOURCE
#include "apfs_parse.h"

/* Max bytes examined from a crypto value record (prevents reading past valid data). */
#define BTREE_VAL_CAP       200
/* Max bytes scanned in partial-recovery key-area fallback pass. */
#define PARTIAL_RECOVERY_CAP 200

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "apfs_globals.h"
#include "compat.h"
#include "util.h"
#include "log.h"
#include "errors.h"

/* ============================================================================
 * B-tree node validation
 * ============================================================================
 */

bool apfs_is_valid_btree_node_sz(const uint8_t *block, uint32_t block_size) {
    if (block_size < APFS_BTNODE_HEADER_SIZE) return false;
    uint16_t flags = get_u16(block + APFS_BTNODE_FLAGS_OFF);
    uint16_t level = get_u16(block + APFS_BTNODE_LEVEL_OFF);
    uint32_t nkeys = get_u32(block + APFS_BTNODE_NKEYS_OFF);
    if (!(flags & 0x7)) return false;
    if (level > 15)     return false;
    if (nkeys == 0 || nkeys > 500) return false;
    return true;
}

bool apfs_is_valid_btree_node(const uint8_t *block) {
    return apfs_is_valid_btree_node_sz(block, g_block_size);
}

bool apfs_is_partial_btree_node_sz(const uint8_t *block, uint32_t block_size) {
    if (block_size < APFS_BTNODE_TABLE_SPACE_OFF + 2) return false;
    uint16_t flags          = get_u16(block + APFS_BTNODE_FLAGS_OFF);
    uint16_t level          = get_u16(block + APFS_BTNODE_LEVEL_OFF);
    uint32_t nkeys          = get_u32(block + APFS_BTNODE_NKEYS_OFF);
    uint16_t table_space_len = get_u16(block + APFS_BTNODE_TABLE_SPACE_OFF);

    if (!(flags & 0x7))    return false;
    if (level > 15)        return false;
    if (nkeys > 500)       return false;
    if (table_space_len > 4000) return false;

    uint32_t key_area_start = APFS_BTNODE_HEADER_SIZE + table_space_len;
    if (key_area_start + 64 > block_size) return false;

    int valid_keys = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t kh = get_u64(block + key_area_start + i * 8);
        uint8_t  kt = (kh >> 60) & 0xF;
        if (kt == 3 || kt == 4 || kt == 8 || kt == 9 || kt == 12)
            valid_keys++;
    }
    return valid_keys > 0;
}

bool apfs_is_partial_btree_node(const uint8_t *block) {
    return apfs_is_partial_btree_node_sz(block, g_block_size);
}

/* ============================================================================
 * Directory record helpers
 * ============================================================================
 */

static void add_drec(uint64_t dir_inode, uint64_t file_inode,
                     const char *name, uint16_t name_len, bool is_dir) {
    if (!name || name_len == 0) return;

    pthread_mutex_lock(&g_drec_mutex);
    if (g_drec_count >= (int)g_drec_capacity) {
        uint32_t new_cap  = g_drec_capacity == 0 ? 1024 : g_drec_capacity * 2;
        drec_t  *new_drecs = realloc(g_drecs, new_cap * sizeof(drec_t));
        if (!new_drecs) { pthread_mutex_unlock(&g_drec_mutex); return; }
        g_drecs        = new_drecs;
        g_drec_capacity = new_cap;
    }

    drec_t *drec       = &g_drecs[g_drec_count++];
    drec->parent_inode = dir_inode;
    drec->file_inode   = file_inode;
    drec->is_dir       = is_dir;

    size_t copy_len = name_len < MAX_NAME_LEN - 1 ? name_len : MAX_NAME_LEN - 1;
    memcpy(drec->name, name, copy_len);
    drec->name[copy_len] = '\0';
    pthread_mutex_unlock(&g_drec_mutex);
}

/* ============================================================================
 * Individual record parsers
 * ============================================================================
 */

static void parse_drec(const uint8_t *block, uint64_t parent_id,
                       uint32_t key_pos, uint32_t k_len,
                       uint32_t val_pos, uint32_t v_len) {
    if (k_len < 12 || key_pos + k_len > g_block_size) return;
    if (v_len < 18 || val_pos + v_len > g_block_size) return;

    uint32_t name_len_hash = get_u32(block + key_pos + 8);
    uint32_t name_len      = name_len_hash & 0x3FF;
    if (name_len == 0 || name_len > k_len - 12) return;

    uint64_t file_id = get_u64(block + val_pos);
    uint16_t flags   = get_u16(block + val_pos + 16);
    bool     is_dir  = (flags & 0xF) == DT_DIR;

    add_drec(parent_id, file_id,
             (const char *)(block + key_pos + 12), (uint16_t)name_len, is_dir);
}

static void parse_inode(const uint8_t *block, uint64_t inode_id,
                        uint32_t val_pos, uint32_t v_len) {
    if (val_pos + 8 > g_block_size) return;

    const uint8_t *val     = block + val_pos;
    uint32_t       val_len = (val_pos + v_len <= g_block_size) ? v_len : g_block_size - val_pos;

    uint64_t parent_id      = get_u64(val);
    /* private_id is the inode's own object ID — reserved for a future
     * cross-check against inode_id to detect B-tree corruption. */
    uint64_t private_id     = val_len > 16 ? get_u64(val + 8) : inode_id;
    (void)private_id;
    uint64_t create_time    = val_len > 24 ? get_u64(val + 16) : 0;
    uint64_t mod_time       = val_len > 32 ? get_u64(val + 24) : 0;
    uint64_t change_time    = val_len > 40 ? get_u64(val + 32) : 0;
    uint64_t access_time    = val_len > 48 ? get_u64(val + 40) : 0;
    uint64_t internal_flags = val_len > 56 ? get_u64(val + 48) : 0;
    uint32_t bsd_flags      = val_len > 72 ? get_u32(val + 68) : 0;
    uint32_t uid            = val_len > 76 ? get_u32(val + 72) : 0;
    uint32_t gid            = val_len > 80 ? get_u32(val + 76) : 0;
    uint16_t mode           = val_len > 82 ? get_u16(val + APFS_INO_MODE_OFF) : 0;
    bool     is_dir         = (mode & 0170000) == 0040000;
    bool     is_compressed  = (internal_flags & INODE_IS_COMPRESSED) != 0;

    /* Compute size, default_crypto_id, and symlink_target from xfields
     * without touching the inode table yet, so we need no lock here.
     * Type 8  = INO_EXT_TYPE_DSTREAM  (file size + crypto id)
     * Type 13 = INO_EXT_TYPE_SYMLINK  (inline symlink target string) */
    uint64_t size              = 0;
    uint64_t default_crypto_id = 0;
    char     symlink_buf[MAX_PATH_LEN] = {0};
    bool     has_symlink       = false;
    if (val_len > 96) {
        uint32_t xf_blob_offset = APFS_INO_XF_NFIELDS_OFF_B;
        uint16_t xf_num_92 = val_len > 94 ? get_u16(val + APFS_INO_XF_NFIELDS_OFF_B) : 0;
        uint16_t xf_num_84 = val_len > 86 ? get_u16(val + APFS_INO_XF_NFIELDS_OFF_A) : 0;
        if (xf_num_92 > 0 && xf_num_92 < 20)      xf_blob_offset = APFS_INO_XF_NFIELDS_OFF_B;
        else if (xf_num_84 > 0 && xf_num_84 < 20) xf_blob_offset = APFS_INO_XF_NFIELDS_OFF_A;

        uint16_t xf_num = get_u16(val + xf_blob_offset);
        if (xf_num > 0 && xf_num < 20) {
            uint8_t  x_types[10];
            uint16_t x_sizes[10];
            uint32_t hdr_off = xf_blob_offset + 4;

            for (int i = 0; i < (int)xf_num && i < 10; i++) {
                if (hdr_off + 4 > val_len) break;
                x_types[i] = val[hdr_off];
                x_sizes[i] = get_u16(val + hdr_off + 2);
                hdr_off += 4;
            }

            /* No padding between the xfield header array and the data area;
             * each field's DATA is padded to 8 bytes within xf_used_data. */
            uint32_t data_start = xf_blob_offset + 4 + (uint32_t)xf_num * 4;
            uint32_t data_off   = data_start;

            for (int i = 0; i < (int)xf_num && i < 10; i++) {
                if (data_off + 8 > val_len) break;
                if (x_types[i] == 8) {
                    if (data_off + 40 <= val_len) {
                        uint64_t raw_size = get_u64(val + data_off);
                        uint64_t part_sz  = g_data_size > g_partition_offset
                                            ? g_data_size - g_partition_offset : 0;
                        size = (part_sz > 0 && raw_size <= part_sz) ? raw_size : 0;
                        default_crypto_id = get_u64(val + data_off + 16);
                        if (default_crypto_id != 0)
                            LOG_DEBUG("inode %llu default_crypto_id=%llu",
                                      (unsigned long long)inode_id,
                                      (unsigned long long)default_crypto_id);
                    } else if (data_off + 8 <= val_len) {
                        size = get_u64(val + data_off);
                    }
                } else if (x_types[i] == 13) {
                    if (x_sizes[i] > 0 && x_sizes[i] < MAX_PATH_LEN &&
                               data_off + x_sizes[i] <= val_len) {
                        size_t slen = x_sizes[i];
                        memcpy(symlink_buf, val + data_off, slen);
                        symlink_buf[slen] = '\0';
                        has_symlink = true;
                    }
                }
                data_off += (x_sizes[i] + 7) & ~7;
            }
        }
    }

    /* Allocate symlink target copy outside the lock (mirrors decmpfs pattern). */
    char *symlink_copy = has_symlink ? strdup(symlink_buf) : NULL;

    /* Hold g_inode_mutex across the entire get+modify to prevent data races
     * between worker threads (concurrent realloc of extents[], double-free of
     * decmpfs_data, unsynchronised field writes). */
    pthread_mutex_lock(&g_inode_mutex);
    inode_t *ino = get_or_create_inode_nolock(inode_id);
    if (!ino) { free(symlink_copy); pthread_mutex_unlock(&g_inode_mutex); return; }
    ino->parent_id         = parent_id;
    ino->mode              = mode;
    ino->size              = size;
    ino->is_dir            = is_dir;
    ino->is_compressed     = is_compressed;
    ino->create_time       = create_time;
    ino->mod_time          = mod_time;
    ino->change_time       = change_time;
    ino->access_time       = access_time;
    ino->uid               = uid;
    ino->gid               = gid;
    ino->bsd_flags         = bsd_flags;
    if (default_crypto_id != 0)
        ino->default_crypto_id = default_crypto_id;
    if (symlink_copy) {
        free(ino->symlink_target);
        ino->symlink_target = symlink_copy;
    }
    pthread_mutex_unlock(&g_inode_mutex);
}


static void parse_extent(const uint8_t *block, uint64_t file_id,
                         uint32_t key_pos, uint32_t val_pos, uint32_t v_len) {
    if (key_pos + 16 > g_block_size || val_pos + 16 > g_block_size) return;

    uint64_t logical_addr    = get_u64(block + key_pos + 8);
    uint64_t length_and_flags = get_u64(block + val_pos);
    uint64_t physical_block  = get_u64(block + val_pos + 8);
    uint8_t  extent_flags    = (uint8_t)((length_and_flags >> 56) & 0xFF);
    uint64_t crypto_id       = 0;
    if (v_len >= 24 && val_pos + 24 <= g_block_size)
        crypto_id = get_u64(block + val_pos + 16);

    uint64_t length       = length_and_flags & 0x00FFFFFFFFFFFFFFULL;
    uint64_t total_blocks = (g_data_size - g_partition_offset) / g_block_size;

    if (physical_block >= total_blocks) return;

    uint64_t partition_bytes  = total_blocks * g_block_size;
    uint64_t max_extent_bytes = (total_blocks - physical_block) * g_block_size;
    if (length == 0 || length > max_extent_bytes) return;
    if (logical_addr > partition_bytes) return;

    /* Hold g_inode_mutex across the entire get+modify to prevent concurrent
     * realloc(ino->extents) use-after-free between worker threads. */
    pthread_mutex_lock(&g_inode_mutex);
    inode_t *ino = get_or_create_inode_nolock(file_id);
    if (!ino) { pthread_mutex_unlock(&g_inode_mutex); return; }

    /* Grow extent array on demand */
    if (ino->extent_count >= ino->extent_capacity) {
        int new_cap = ino->extent_capacity == 0 ? 8 : ino->extent_capacity * 2;
        extent_t *new_extents = realloc(ino->extents, new_cap * sizeof(extent_t));
        if (!new_extents) { pthread_mutex_unlock(&g_inode_mutex); return; }
        ino->extents        = new_extents;
        ino->extent_capacity = new_cap;
    }

    if (ino->inode_id == 0)             ino->inode_id = file_id;
    else if (ino->inode_id != file_id) { pthread_mutex_unlock(&g_inode_mutex); return; }

    /* Deduplicate / replace CoW extents at the same logical offset.
     * Higher physical block == more recently allocated == keep it. */
    for (int i = 0; i < ino->extent_count; i++) {
        if (ino->extents[i].logical == logical_addr) {
            if (ino->extents[i].physical == physical_block &&
                ino->extents[i].length   == length &&
                ino->extents[i].crypto_id == crypto_id) {
                LOG_DEBUG("extent: exact duplicate skipped (inode %llu)",
                          (unsigned long long)file_id);
                pthread_mutex_unlock(&g_inode_mutex);
                return;
            }
            if (physical_block > ino->extents[i].physical) {
                LOG_DEBUG("extent: replacing CoW (inode %llu, logical %llu)",
                          (unsigned long long)file_id,
                          (unsigned long long)logical_addr);
                ino->extents[i].physical  = physical_block;
                ino->extents[i].length    = length;
                ino->extents[i].crypto_id = crypto_id;
                ino->extents[i].flags     = extent_flags;
            }
            pthread_mutex_unlock(&g_inode_mutex);
            return;
        }
    }

    extent_t *ext    = &ino->extents[ino->extent_count++];
    ext->logical     = logical_addr;
    ext->physical    = physical_block;
    ext->length      = length;
    ext->crypto_id   = crypto_id;
    ext->flags       = extent_flags;
    pthread_mutex_unlock(&g_inode_mutex);
}

static void parse_crypto_state(const uint8_t *block, uint64_t crypto_id,
                                uint32_t val_pos, uint32_t v_len) {
    if (val_pos + 4 > g_block_size) return;

    const uint8_t *val     = block + val_pos;
    uint32_t       val_len = v_len < BTREE_VAL_CAP ? v_len : BTREE_VAL_CAP;
    if (val_len < 28) return;

    uint16_t key_len = get_u16(val + 22);
    if (val_len < 24 + (uint32_t)key_len) return;
    if (key_len > 32 || !g_encryption_enabled) return;

    /* Serialise writes to the shared g_crypto_states[] array.
     * g_stats_mutex is used here because crypto state records arrive from
     * multiple scan threads and the array has a fixed MAX_CRYPTO_STATES
     * capacity — the check + increment must be atomic. */
    pthread_mutex_lock(&g_stats_mutex);

    if (g_crypto_state_count < MAX_CRYPTO_STATES) {
        crypto_state_t *state = &g_crypto_states[g_crypto_state_count];
        state->crypto_id   = crypto_id;
        state->key_len     = key_len;
        /* Use VEK as unwrapping key (simplified — full class-key unwrap
         * would require the class keys from the keybag). */
        memcpy(state->key, g_vek, 32);
        state->initialized = true;
        g_crypto_state_count++;
        LOG_DEBUG("crypto_state: id=%llu key_len=%u",
                  (unsigned long long)crypto_id, key_len);
    }

    pthread_mutex_unlock(&g_stats_mutex);
}

static void parse_xattr(const uint8_t *block, uint64_t inode_id,
                        uint32_t key_pos, uint32_t k_len,
                        uint32_t val_pos, uint32_t v_len) {
    /* j_xattr_key_t: j_key_t hdr (8) + uint16_t name_len (2) + name (variable).
     * No padding between name_len and name — minimum key is 10 bytes, name at +10. */
    if (k_len < 10 || key_pos + k_len > g_block_size) return;
    if (v_len < 4  || val_pos + v_len > g_block_size) return;

    uint16_t name_len = get_u16(block + key_pos + 8);
    if (name_len == 0 || name_len > k_len - 10) return;

    char   name[256];
    size_t copy_len = name_len < 255 ? name_len : 255;
    memcpy(name, block + key_pos + 10, copy_len);
    name[copy_len] = '\0';

    uint16_t xattr_flags = get_u16(block + val_pos);
    uint16_t xattr_len   = get_u16(block + val_pos + 2);

    if (strcmp(name, "com.apple.decmpfs") == 0 &&
        (xattr_flags & 0x02) && xattr_len >= 16) {
        if (v_len < (uint32_t)(4 + 16)) return;

        /* Read all data from the block before acquiring the lock. */
        const uint8_t *data        = block + val_pos + 4;
        uint32_t compression_type  = get_u32(data + 4);
        uint64_t uncompressed_size = get_u64(data + 8);

        /* Allocate the decmpfs buffer outside the lock (malloc doesn't need it). */
        uint8_t *new_decmpfs    = NULL;
        uint16_t new_decmpfs_len = 0;
        if (xattr_len > 16 && xattr_len <= 65535 &&
            (uint32_t)(4 + xattr_len) <= v_len) {
            new_decmpfs = malloc(xattr_len);
            if (new_decmpfs) {
                memcpy(new_decmpfs, data, xattr_len);
                new_decmpfs_len = xattr_len;
            }
        }

        /* Hold g_inode_mutex across the entire get+modify to prevent
         * concurrent free(decmpfs_data) double-free between worker threads. */
        pthread_mutex_lock(&g_inode_mutex);
        inode_t *ino = get_or_create_inode_nolock(inode_id);
        if (!ino) {
            free(new_decmpfs);
            pthread_mutex_unlock(&g_inode_mutex);
            return;
        }
        ino->compression_type  = compression_type;
        ino->uncompressed_size = uncompressed_size;
        ino->is_compressed     = true;
        if (new_decmpfs) {
            free(ino->decmpfs_data);
            ino->decmpfs_data = new_decmpfs;
            ino->decmpfs_len  = new_decmpfs_len;
        }
        pthread_mutex_unlock(&g_inode_mutex);

    } else if (strcmp(name, "com.apple.fs.symlink") == 0 &&
               (xattr_flags & 0x02) && xattr_len > 0) {
        /* Symlink target stored inline as an xattr (APFS modern format).
         * xattr_len includes the null terminator. */
        if (v_len < (uint32_t)(4 + xattr_len)) return;
        const char *tgt  = (const char *)(block + val_pos + 4);
        size_t      tlen = strnlen(tgt, xattr_len);
        if (tlen == 0 || tlen >= MAX_PATH_LEN) return;

        char *target_copy = malloc(tlen + 1);
        if (!target_copy) return;
        memcpy(target_copy, tgt, tlen);
        target_copy[tlen] = '\0';

        pthread_mutex_lock(&g_inode_mutex);
        inode_t *ino = get_or_create_inode_nolock(inode_id);
        if (!ino) { free(target_copy); pthread_mutex_unlock(&g_inode_mutex); return; }
        free(ino->symlink_target);
        ino->symlink_target = target_copy;
        pthread_mutex_unlock(&g_inode_mutex);
    }
}

/* ============================================================================
 * Main B-tree leaf node dispatcher
 * ============================================================================
 */

void apfs_parse_btree_node(const uint8_t *block, uint64_t block_num) {
    uint16_t flags   = get_u16(block + APFS_BTNODE_FLAGS_OFF);
    uint32_t nkeys   = get_u32(block + APFS_BTNODE_NKEYS_OFF);
    uint16_t level   = get_u16(block + APFS_BTNODE_LEVEL_OFF);
    bool     is_leaf  = (flags & BTNODE_LEAF) != 0;
    bool     is_root  = (flags & BTNODE_ROOT) != 0;
    bool     is_fixed = (flags & BTNODE_FIXED) != 0;

    if (!is_leaf) {
        LOG_DEBUG("block %llu: non-leaf (level=%u, nkeys=%u), skipping",
                  (unsigned long long)block_num, level, nkeys);
        return;
    }

    uint16_t table_space_len = get_u16(block + APFS_BTNODE_TABLE_SPACE_OFF);
    if (table_space_len > 4000) return;

    uint32_t toc_start       = APFS_BTNODE_HEADER_SIZE;
    uint32_t key_area_start  = APFS_BTNODE_HEADER_SIZE + table_space_len;
    if (key_area_start >= g_block_size) return;

    uint32_t val_area_end = is_root
        ? (g_block_size > 40 ? g_block_size - 40 : g_block_size)
        : g_block_size;

    LOG_DEBUG("block %llu: leaf nkeys=%u is_root=%d is_fixed=%d tsl=%u",
              (unsigned long long)block_num, nkeys, is_root, is_fixed,
              table_space_len);

    uint32_t records_extracted = 0;
    for (uint32_t i = 0; i < nkeys && i < 500; i++) {
        uint32_t entry_pos = toc_start + i * (is_fixed ? 4 : 8);
        uint32_t entry_sz = is_fixed ? 4u : 8u;
        if (entry_pos + entry_sz > g_block_size || entry_pos + entry_sz > key_area_start) break;

        uint16_t k_off, v_off, k_len, v_len;
        if (is_fixed) {
            if (entry_pos + 4 > g_block_size) break;
            k_off = (uint16_t)(block[entry_pos]   | (block[entry_pos+1] << 8));
            v_off = (uint16_t)(block[entry_pos+2] | (block[entry_pos+3] << 8));
            k_len = 8; v_len = 16;
        } else {
            if (entry_pos + 8 > g_block_size) break;
            k_off = (uint16_t)(block[entry_pos]   | (block[entry_pos+1] << 8));
            k_len = (uint16_t)(block[entry_pos+2] | (block[entry_pos+3] << 8));
            v_off = (uint16_t)(block[entry_pos+4] | (block[entry_pos+5] << 8));
            v_len = (uint16_t)(block[entry_pos+6] | (block[entry_pos+7] << 8));
        }

        if (k_len == 0 || v_len == 0) continue;

        uint32_t key_pos = key_area_start + k_off;
        if (v_off > val_area_end) continue;
        uint32_t val_pos = val_area_end - v_off;
        /* #8: val_pos must not overlap the key/TOC area. */
        if (val_pos < key_area_start) continue;
        if (key_pos + 8 > g_block_size || val_pos > g_block_size) continue;

        uint64_t key_header = get_u64(block + key_pos);
        uint8_t  key_type   = (key_header >> 60) & 0xF;
        uint64_t key_id     = key_header & 0x0FFFFFFFFFFFFFFFULL;

        switch (key_type) {
        case JOBJ_TYPE_DIR_REC:
        case JOBJ_TYPE_SIBLING:
            parse_drec(block, key_id, key_pos, k_len, val_pos, v_len);
            records_extracted++;
            break;
        case JOBJ_TYPE_INODE:
            parse_inode(block, key_id, val_pos, v_len);
            records_extracted++;
            break;
        case JOBJ_TYPE_EXTENT:
            parse_extent(block, key_id, key_pos, val_pos, v_len);
            records_extracted++;
            break;
        case JOBJ_TYPE_XATTR:
            parse_xattr(block, key_id, key_pos, k_len, val_pos, v_len);
            break;
        case JOBJ_TYPE_CRYPTO_STATE:
            parse_crypto_state(block, key_id, val_pos, v_len);
            break;
        case 0:
            /* Fixed-size key with unknown type — try heuristics */
            if (val_pos + 16 < g_block_size && v_len >= 16) {
                uint16_t flags_val = get_u16(block + val_pos + 16);
                uint8_t  entry_type = flags_val & 0xF;
                bool looks_like_drec = (entry_type == DT_DIR || entry_type == DT_REG);
                if (!looks_like_drec && key_pos + 12 <= g_block_size) {
                    uint32_t nl = get_u32(block + key_pos + 8) & 0x3FF;
                    if (nl > 0 && nl < 256 && key_pos + 12 + nl <= g_block_size)
                        looks_like_drec = true;
                }
                uint64_t first_val = get_u64(block + val_pos);
                if (looks_like_drec &&
                    first_val > 0 && first_val < 0x1000000 && key_id < 0x1000000) {
                    parse_drec(block, key_id, key_pos, k_len, val_pos, v_len);
                    records_extracted++;
                } else if (first_val < 0x1000000 && key_id < 0x1000000) {
                    parse_inode(block, key_id, val_pos, v_len);
                    records_extracted++;
                }
            }
            break;
        default:
            break;
        }
    }

    /* Partial recovery: if TOC extracted very few records, scan key area directly */
    if (records_extracted < (nkeys / 2) && nkeys > 5 &&
        key_area_start < val_area_end) {
        uint32_t kp     = key_area_start;
        uint32_t max_kp = val_area_end > PARTIAL_RECOVERY_CAP
                        ? val_area_end - PARTIAL_RECOVERY_CAP
                        : key_area_start + PARTIAL_RECOVERY_CAP;
        if (max_kp > g_block_size) max_kp = g_block_size - 8;

        while (kp < max_kp && kp + 8 <= g_block_size) {
            uint64_t kh   = get_u64(block + kp);
            uint8_t  kt   = (kh >> 60) & 0xF;
            uint64_t kid  = kh & 0x0FFFFFFFFFFFFFFFULL;

            if (kt == JOBJ_TYPE_DIR_REC || kt == JOBJ_TYPE_SIBLING ||
                kt == JOBJ_TYPE_INODE   || kt == JOBJ_TYPE_EXTENT  ||
                kt == JOBJ_TYPE_XATTR) {
                for (uint32_t vo = 16;
                     vo < 512 && vo < (val_area_end - key_area_start);
                     vo += 16) {
                    uint32_t tvp = val_area_end - vo;
                    if (tvp <= kp || tvp + 8 > g_block_size) continue;

                    if ((kt == JOBJ_TYPE_DIR_REC || kt == JOBJ_TYPE_SIBLING)) {
                        uint64_t fid = get_u64(block + tvp);
                        /* Read name_len from the drec key's hash field (offset 8
                         * after the 8-byte OBJ_ID_AND_TYPE header), not from kid
                         * (which is the object ID and is unrelated to name length). */
                        if (fid > 0 && fid < 0x100000000 && kp + 12 <= g_block_size) {
                            uint32_t nl  = get_u32(block + kp + 8) & 0x3FF;
                            uint32_t ekl = 12 + nl;
                            if (nl > 0 && nl < 256 && kp + ekl <= g_block_size) {
                                parse_drec(block, kid, kp, (uint16_t)ekl, tvp, 18);
                                break;
                            }
                        }
                    } else if (kt == JOBJ_TYPE_INODE) {
                        uint64_t pid = get_u64(block + tvp);
                        if (pid < 0x100000000) {
                            parse_inode(block, kid, tvp, g_block_size - tvp);
                            break;
                        }
                    } else if (kt == JOBJ_TYPE_EXTENT) {
                        uint64_t lf = get_u64(block + tvp);
                        if ((lf & 0x00FFFFFFFFFFFFFFULL) < 0x00FFFFFFFFFFFFFFULL) {
                            parse_extent(block, kid, kp, tvp, 16);
                            break;
                        }
                    }
                }
            }
            kp += 8;
        }
    }
}
