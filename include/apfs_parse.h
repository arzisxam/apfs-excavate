#pragma once
/*
 * apfs_parse.h — APFS B-tree parsing: directory records, inodes, extents,
 *                extended attributes, and crypto state records.
 */

#include <stdint.h>
#include <stdbool.h>

/* APFS B-tree node header offsets (object header is 32 bytes; btnode header follows) */
#define APFS_BTNODE_FLAGS_OFF        32  /* uint16_t node flags */
#define APFS_BTNODE_LEVEL_OFF        34  /* uint16_t tree level (0 = leaf) */
#define APFS_BTNODE_NKEYS_OFF        36  /* uint32_t key count */
#define APFS_BTNODE_TABLE_SPACE_OFF  42  /* uint16_t TOC table-space length */
#define APFS_BTNODE_HEADER_SIZE      56  /* fixed header size; TOC and key area follow */

/* APFS inode value field offsets (relative to value start) */
#define APFS_INO_MODE_OFF            80  /* uint16_t POSIX mode */
#define APFS_INO_XF_NFIELDS_OFF_A    84  /* uint16_t xf_num (older inode layout) */
#define APFS_INO_XF_NFIELDS_OFF_B    92  /* uint16_t xf_num (newer inode layout) */

/*
 * apfs_is_valid_btree_node() — strict B-tree node validation.
 * Checks flags, level (≤ 15), and key count (1–500).
 */
bool apfs_is_valid_btree_node(const uint8_t *block);
bool apfs_is_valid_btree_node_sz(const uint8_t *block, uint32_t block_size);

/*
 * apfs_is_partial_btree_node() — lenient validation for damaged metadata.
 * Accepts nodes with 0 keys; uses key-type heuristics.
 */
bool apfs_is_partial_btree_node(const uint8_t *block);
bool apfs_is_partial_btree_node_sz(const uint8_t *block, uint32_t block_size);

/*
 * apfs_parse_btree_node() — dispatch key/value pairs from one leaf block
 * to the appropriate parse_drec / parse_inode / parse_extent / … function.
 */
void apfs_parse_btree_node(const uint8_t *block, uint64_t block_num);
