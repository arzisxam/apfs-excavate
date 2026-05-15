#!/usr/bin/env python3
"""
find_min_xid.py — analyse B-tree Transaction IDs (XIDs) in an APFS image.

Use this tool to find a sensible value for apfs-excavate's --min-xid option.

Every APFS B-tree node is stamped with a Transaction ID (XID) — a
monotonically increasing integer that records when that node was last written.
Higher XID = more recent.  On a healthy filesystem all nodes cluster at a
similar high XID.  On a damaged or heavily fragmented image, stale old nodes
from earlier filesystem states still exist on disk with much lower XIDs, and
the tool can pick them up — producing phantom files, wrong paths, or duplicate
entries from an earlier state.

--min-xid tells apfs-excavate to ignore any B-tree leaf node whose XID is
below the given threshold, so only recent-state nodes are used.

This tool scans the image, finds all readable B-tree nodes, collects their
XIDs, and produces a distribution histogram so you can see where the clusters
are and pick a sensible cut-off.

Usage:
  python3 find_min_xid.py <image>
  python3 find_min_xid.py <image> --block-size 4096   # if known
  python3 find_min_xid.py <image> --max-blocks 500000 # limit scan (faster)

Note: scanning a large image can take a few minutes.  Use --max-blocks to
limit the scan to the first N blocks and get a representative sample quickly.
"""

import sys
import os
import struct
import mmap
import math
from collections import Counter

# ---------------------------------------------------------------------------
# APFS B-tree node header layout
# ---------------------------------------------------------------------------
#
# Every APFS object (including B-tree nodes) starts with an obj_phys_t header:
#   0x00  uint64  o_cksum       (Fletcher-64 checksum)
#   0x08  uint64  o_oid         (object identifier)
#   0x10  uint64  o_xid         (transaction ID)  ← what we want
#   0x18  uint32  o_type
#   0x1C  uint32  o_subtype
#
# B-tree node magic (BTOM) starts at offset 0x20:
#   0x20  uint32  btn_flags    (bit 1 = BTNODE_ROOT, bit 2 = BTNODE_LEAF)
#   0x22  uint16  btn_level
#   0x24  uint32  btn_nkeys
#   …
#
# We check for the magic pattern to identify valid B-tree nodes:
#   obj type 0x0000_0002 (OBJECT_TYPE_BTREE_NODE) in o_type's low 16 bits

OFF_CKSUM   = 0
OFF_OID     = 8
OFF_XID     = 16   # uint64 — transaction ID
OFF_OTYPE   = 24   # uint32 — object type + flags
OFF_SUBTYPE = 28   # uint32 — subtype

# Low 16 bits of o_type for a B-tree node
OTYPE_BTREE_NODE = 0x0002

# btn_flags: bit 0x0002 = BTNODE_LEAF
OFF_BTN_FLAGS = 32  # uint16

BTF_LEAF = 0x0002
BTF_ROOT = 0x0001

# Minimum plausible XID (filters out zero/garbage)
XID_MIN_PLAUSIBLE = 1
# Maximum plausible XID (2^48; sane upper bound)
XID_MAX_PLAUSIBLE = (1 << 48)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_u16(buf, offset): return struct.unpack_from('<H', buf, offset)[0]
def read_u32(buf, offset): return struct.unpack_from('<I', buf, offset)[0]
def read_u64(buf, offset): return struct.unpack_from('<Q', buf, offset)[0]

def is_valid_block_size(bs):
    return 4096 <= bs <= 65536 and (bs & (bs - 1)) == 0

def fmt_size(n_bytes):
    for unit, div in (('TB', 1 << 40), ('GB', 1 << 30), ('MB', 1 << 20), ('KB', 1 << 10)):
        if n_bytes >= div:
            return f'{n_bytes / div:.2f} {unit}'
    return f'{n_bytes} B'

def try_parse_node(chunk, block_size):
    """
    Try to parse a B-tree node from `chunk` (exactly block_size bytes).
    Returns (xid, is_leaf, is_root) or None if not a valid B-tree node.
    """
    if len(chunk) < 40:
        return None

    otype = read_u32(chunk, OFF_OTYPE)
    node_type = otype & 0x0000FFFF

    if node_type != OTYPE_BTREE_NODE:
        return None

    xid = read_u64(chunk, OFF_XID)
    if not (XID_MIN_PLAUSIBLE <= xid <= XID_MAX_PLAUSIBLE):
        return None

    btn_flags = read_u16(chunk, OFF_BTN_FLAGS)
    is_leaf   = bool(btn_flags & BTF_LEAF)
    is_root   = bool(btn_flags & BTF_ROOT)

    return xid, is_leaf, is_root


def detect_block_size(buf, image_size):
    """
    Heuristic: try to detect block size from any NXSB in the image.
    Falls back to 4096 if not found.
    """
    pos = buf.find(b'NXSB')
    while pos >= 0:
        block_start = pos - 32
        if block_start >= 0 and block_start + 40 <= image_size:
            try:
                bs = struct.unpack_from('<I', buf, block_start + 36)[0]
                if is_valid_block_size(bs):
                    return bs
            except Exception:
                pass
        pos = buf.find(b'NXSB', pos + 1)
    return 4096  # safe default


def histogram(values, buckets=20):
    """
    Build a text histogram of XID values.
    Returns list of (label, count, bar) tuples.
    """
    if not values:
        return []

    lo, hi = min(values), max(values)
    if lo == hi:
        return [(str(lo), len(values), '█' * 40)]

    bucket_size = (hi - lo) / buckets
    counts = Counter()
    for v in values:
        b = min(int((v - lo) / bucket_size), buckets - 1)
        counts[b] += 1

    max_count = max(counts.values()) if counts else 1
    bar_width  = 40

    rows = []
    for b in range(buckets):
        count  = counts.get(b, 0)
        lo_b   = int(lo + b * bucket_size)
        hi_b   = int(lo + (b + 1) * bucket_size) - 1
        label  = f'{lo_b:>14,} – {hi_b:>14,}'
        bar    = '█' * int(bar_width * count / max_count) if count else ''
        rows.append((label, count, bar))

    return rows


def percentile(sorted_vals, pct):
    if not sorted_vals:
        return 0
    idx = max(0, min(len(sorted_vals) - 1, int(len(sorted_vals) * pct / 100)))
    return sorted_vals[idx]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args      = [a for a in sys.argv[1:] if not a.startswith('--')]
    opt_bs    = None
    opt_max   = None

    for i, a in enumerate(sys.argv[1:]):
        if a == '--block-size' and i + 2 < len(sys.argv):
            try: opt_bs = int(sys.argv[i + 2])
            except ValueError: pass
        if a == '--max-blocks' and i + 2 < len(sys.argv):
            try: opt_max = int(sys.argv[i + 2])
            except ValueError: pass

    if not args:
        print(__doc__)
        sys.exit(1)

    image_path = args[0]
    if not os.path.isfile(image_path):
        print(f'Error: {image_path!r} is not a file.', file=sys.stderr)
        sys.exit(1)

    image_size = os.path.getsize(image_path)
    print(f'Image      : {image_path}')
    print(f'Image size : {fmt_size(image_size)} ({image_size:,} bytes)')

    with open(image_path, 'rb') as fh:
        try:
            buf = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, mmap.error) as e:
            print(f'mmap failed ({e}), reading fully...', file=sys.stderr)
            buf = fh.read()

        # Detect block size
        block_size = opt_bs if (opt_bs and is_valid_block_size(opt_bs)) \
                     else detect_block_size(buf, image_size)

        print(f'Block size : {block_size} bytes')

        total_blocks  = image_size // block_size
        scan_blocks   = min(total_blocks, opt_max) if opt_max else total_blocks

        print(f'Blocks     : {total_blocks:,} total, scanning {scan_blocks:,}')
        if scan_blocks < total_blocks:
            print(f'           (use --max-blocks {total_blocks} to scan all; this is a sample)')
        print()
        print('Scanning... ', end='', flush=True)

        all_xids    = []    # every valid node XID
        leaf_xids   = []    # leaf nodes only (what --min-xid filters)
        n_nodes     = 0
        n_leaves    = 0
        n_roots     = 0

        REPORT_EVERY = 100_000

        for blk in range(scan_blocks):
            if blk > 0 and blk % REPORT_EVERY == 0:
                print(f'{blk:,}... ', end='', flush=True)

            offset = blk * block_size
            try:
                chunk = buf[offset: offset + block_size]
            except Exception:
                continue

            result = try_parse_node(chunk, block_size)
            if result is None:
                continue

            xid, is_leaf, is_root = result
            n_nodes += 1
            all_xids.append(xid)
            if is_leaf:
                n_leaves += 1
                leaf_xids.append(xid)
            if is_root:
                n_roots += 1

        if hasattr(buf, 'close'):
            buf.close()

    print('done.\n')

    if not all_xids:
        print('No valid B-tree nodes found.')
        print()
        print('Possible reasons:')
        print('  • Wrong block size — try --block-size 8192 or 16384')
        print('  • Heavily encrypted image (nodes not readable without key)')
        print('  • The image is not APFS')
        print()
        print('In this case --min-xid is not useful; run apfs-excavate without it.')
        return

    all_xids.sort()
    leaf_xids.sort()

    # --- Summary statistics ---
    print(f'B-tree nodes found : {n_nodes:,}  ({n_leaves:,} leaf, {n_roots:,} root)')
    print(f'XID range          : {all_xids[0]:,}  →  {all_xids[-1]:,}')
    print()

    xids_for_hist = leaf_xids if leaf_xids else all_xids
    label = 'leaf node' if leaf_xids else 'all node'

    print(f'XID distribution ({label} XIDs):')
    print(f'  {"XID range":^33s}   {"count":>8s}  histogram')
    print(f'  {"-"*33}   {"--------":>8s}  {"-"*40}')

    rows = histogram(xids_for_hist, buckets=20)
    for label_r, count, bar in rows:
        if count > 0:
            print(f'  {label_r}   {count:>8,}  {bar}')
        else:
            print(f'  {label_r}   {"·":>8s}')

    print()

    # --- Percentile analysis ---
    p50  = percentile(xids_for_hist, 50)
    p75  = percentile(xids_for_hist, 75)
    p90  = percentile(xids_for_hist, 90)
    p95  = percentile(xids_for_hist, 95)
    p99  = percentile(xids_for_hist, 99)

    print('Percentiles (leaf XIDs):')
    print(f'  50th percentile (median) : {p50:>16,}')
    print(f'  75th percentile          : {p75:>16,}')
    print(f'  90th percentile          : {p90:>16,}')
    print(f'  95th percentile          : {p95:>16,}')
    print(f'  99th percentile          : {p99:>16,}')
    print(f'  Maximum (most recent)    : {xids_for_hist[-1]:>16,}')
    print()

    # --- Gap analysis: find the biggest XID gap (suggests old vs new state boundary) ---
    gap_threshold = max(1, (xids_for_hist[-1] - xids_for_hist[0]) // 50)
    gaps = []
    for i in range(1, len(xids_for_hist)):
        g = xids_for_hist[i] - xids_for_hist[i - 1]
        if g >= gap_threshold:
            gaps.append((g, xids_for_hist[i - 1], xids_for_hist[i]))

    gaps.sort(reverse=True)

    # --- Recommendation ---
    print('Recommendation:')
    print()

    spread = xids_for_hist[-1] - xids_for_hist[0]
    # If the distribution is tight (< 5% spread relative to max), nothing to filter
    if spread < xids_for_hist[-1] * 0.05:
        print('  The XID distribution is tight — all nodes appear to be from a')
        print('  similar time period.  You probably do not need --min-xid.')
        print()
        print(f'  If you still want to filter noise, try:  --min-xid {p75:,}')
    elif gaps:
        # There's a significant gap — the boundary between old and new state
        biggest_gap = gaps[0]
        boundary = biggest_gap[2]  # first XID above the gap
        above_gap = sum(1 for x in xids_for_hist if x >= boundary)
        pct_above  = 100 * above_gap / len(xids_for_hist)

        print(f'  A significant XID gap was detected:')
        print(f'    Gap of {biggest_gap[0]:,} between XID {biggest_gap[1]:,} and {biggest_gap[2]:,}')
        print(f'    {above_gap:,} nodes ({pct_above:.1f}%) are above the gap')
        print()

        if pct_above >= 20:
            print(f'  This suggests two distinct filesystem states.  To keep only the')
            print(f'  more recent state (above the gap):')
            print()
            print(f'    --min-xid {boundary:,}')
            print()
            print(f'  To keep recent nodes but include some older context:')
            print(f'    --min-xid {biggest_gap[1] // 2:,}')
        else:
            # Most nodes are below the gap — the "new" state is a thin layer
            print(f'  Most nodes ({100 - pct_above:.0f}%) are in the older state below the gap.')
            print(f'  The filesystem may have been mostly unchanged recently, or the')
            print(f'  newer state is sparsely represented in what survived.')
            print()
            print(f'  Recommended conservative cut-off:  --min-xid {p50:,}')
    else:
        # Gradual distribution — use the 75th percentile as a gentle filter
        print(f'  The XID distribution is gradual (no sharp gap).')
        print(f'  This is normal for a filesystem with many incremental writes.')
        print()
        print(f'  If you are getting too many stale/duplicate files, try:')
        print(f'    --min-xid {p75:,}   (cuts bottom 75% of nodes)')
        print()
        print(f'  For aggressive noise reduction:')
        print(f'    --min-xid {p90:,}   (keeps only top 10% most recent nodes)')
        print()
        print(f'  For a gentle filter:')
        print(f'    --min-xid {p50:,}   (cuts bottom 50%)')

    print()
    print('Note: --min-xid is only needed when a normal run produces excessive')
    print('phantom/stale files.  Start without it and only add it if needed.')


if __name__ == '__main__':
    main()
