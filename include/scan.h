#pragma once
/*
 * scan.h — multi-threaded block scanner.
 *
 * scan_image() partitions the image into per-worker ranges, launches
 * scan_worker_thread() for each, and waits for completion.  Each worker
 * reads every block in its range, validates it as a B-tree leaf, and
 * dispatches it to apfs_parse_btree_node().  Zeroed blocks are skipped
 * quickly via memcmp.
 *
 * For encrypted volumes the worker tries three strategies in order:
 *   1. Plaintext + strict check   (container-level metadata)
 *   2. Decrypted + strict check   (volume-level encrypted metadata)
 *   3. Plaintext + lenient check  (damaged but readable plaintext)
 *
 * scan_for_deleted_inodes() is called on non-B-tree blocks and uses a
 * heuristic to detect orphaned inode records in free/overwritten areas.
 */

#include <stdint.h>
#include <stdbool.h>

/*
 * scan_image() — scan all partition blocks using g_workers threads.
 * Returns the total number of B-tree leaf nodes parsed across all workers.
 * Pass show_progress = true to display a progress bar on stdout.
 */
int scan_image(bool show_progress);
