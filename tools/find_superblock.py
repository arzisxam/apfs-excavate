#!/usr/bin/env python3
"""
find_superblock.py — locate APFS container superblocks in a disk image.

Use this tool to find the correct value for apfs-excavate's --block option.

apfs-excavate auto-detects the container superblock in most cases.  You only
need --block when:
  - The image contains multiple APFS containers (e.g. Fusion Drive, dual-boot)
  - Auto-detection picked a stale checkpoint copy instead of the right one
  - The tool reports a wrong partition size or block count

This tool scans the image for every NXSB magic ("NXSB") occurrence and prints
each one as a candidate --block LBA value (512-byte sector units, which is
what apfs-excavate expects).

Usage:
  python3 find_superblock.py <image>
  python3 find_superblock.py <image> --verbose
"""

import sys
import os
import struct
import mmap

# ---------------------------------------------------------------------------
# APFS on-disk constants
# ---------------------------------------------------------------------------

NXSB_MAGIC        = b'NXSB'
NXSB_MAGIC_OFFSET = 32       # magic is at byte 32 within the NXSB block
SECTOR_SIZE       = 512      # LBA unit expected by --block

# Minimum and maximum valid APFS block sizes
BLOCK_SIZE_MIN = 4096
BLOCK_SIZE_MAX = 65536

# Offsets within the NXSB block (from block start, i.e. magic_pos - 32)
OFF_MAGIC      = 32          # 4 bytes "NXSB"
OFF_BLOCK_SIZE = 36          # uint32: nx_block_size
OFF_BLOCK_COUNT= 40          # uint64: nx_block_count (total blocks in container)
OFF_UUID       = 56          # 16 bytes: container UUID
OFF_NEXT_OID   = 72          # uint64: next object identifier (proxy for XID range)

# Checkpoint area block count (standard layout: primary SB at block 0,
# checkpoint descriptor area starts at block 1).  Reading nx_block_count
# gives us the total container size.
CHECKPOINT_AREA_BLOCKS = 2000  # typical; actual range varies

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_u32(buf: bytes, offset: int) -> int:
    return struct.unpack_from('<I', buf, offset)[0]

def read_u64(buf: bytes, offset: int) -> int:
    return struct.unpack_from('<Q', buf, offset)[0]

def fmt_size(n_bytes: int) -> str:
    for unit, divisor in (('TB', 1 << 40), ('GB', 1 << 30), ('MB', 1 << 20), ('KB', 1 << 10)):
        if n_bytes >= divisor:
            return f'{n_bytes / divisor:.2f} {unit}'
    return f'{n_bytes} B'

def fmt_uuid(buf: bytes, offset: int) -> str:
    raw = buf[offset:offset + 16]
    h = raw.hex()
    return f'{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}'

def is_valid_block_size(bs: int) -> bool:
    return BLOCK_SIZE_MIN <= bs <= BLOCK_SIZE_MAX and (bs & (bs - 1)) == 0

def describe_candidate(buf: bytes, block_start: int, image_size: int,
                        verbose: bool) -> dict | None:
    """
    Parse one NXSB block starting at byte offset `block_start`.
    Returns a dict of interesting fields, or None if the block looks invalid.
    """
    if block_start + 128 > image_size:
        return None

    # Read the block header area
    try:
        chunk = buf[block_start: block_start + 128]
    except Exception:
        return None

    if chunk[OFF_MAGIC: OFF_MAGIC + 4] != NXSB_MAGIC:
        return None

    block_size  = read_u32(chunk, OFF_BLOCK_SIZE)
    block_count = read_u64(chunk, OFF_BLOCK_COUNT)

    if not is_valid_block_size(block_size):
        return None  # implausible block size — corrupt or not a real SB

    container_bytes = block_size * block_count
    lba = block_start // SECTOR_SIZE

    result = {
        'byte_offset':      block_start,
        'lba':              lba,
        'block_size':       block_size,
        'block_count':      block_count,
        'container_size':   container_bytes,
    }

    if verbose:
        try:
            result['uuid'] = fmt_uuid(chunk, OFF_UUID)
        except Exception:
            result['uuid'] = '(unreadable)'
        try:
            result['next_oid'] = read_u64(chunk, OFF_NEXT_OID)
        except Exception:
            result['next_oid'] = 0

    return result


def is_checkpoint_copy(byte_offset: int, primary: dict | None, block_size: int) -> bool:
    """
    Heuristic: if this NXSB is within the first CHECKPOINT_AREA_BLOCKS blocks
    of the container, it's likely a checkpoint copy, not the primary superblock.
    """
    if primary is None:
        return False
    dist = abs(byte_offset - primary['byte_offset'])
    if dist == 0:
        return False
    return dist < CHECKPOINT_AREA_BLOCKS * block_size


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    verbose = '--verbose' in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith('-')]

    if not args:
        print(__doc__)
        sys.exit(1)

    image_path = args[0]

    if not os.path.isfile(image_path):
        print(f'Error: {image_path!r} is not a file.', file=sys.stderr)
        sys.exit(1)

    image_size = os.path.getsize(image_path)
    print(f'Image            : {image_path}')
    print(f'Image size       : {fmt_size(image_size)} ({image_size:,} bytes)')
    print()

    candidates = []

    with open(image_path, 'rb') as fh:
        try:
            buf = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, mmap.error) as e:
            print(f'mmap failed ({e}), falling back to full read (may be slow)...',
                  file=sys.stderr)
            buf = fh.read()

        # --- Search for every NXSB occurrence ---
        search_from = 0
        while True:
            pos = buf.find(NXSB_MAGIC, search_from)
            if pos < 0:
                break
            # Magic sits at offset 32 within the block; block starts 32 bytes earlier
            block_start = pos - NXSB_MAGIC_OFFSET
            if block_start >= 0 and block_start % SECTOR_SIZE == 0:
                info = describe_candidate(buf, block_start, image_size, verbose)
                if info:
                    candidates.append(info)
            search_from = pos + 4

        if hasattr(buf, 'close'):
            buf.close()

    # --- Deduplicate by LBA (same block found multiple times) ---
    seen_lba = set()
    unique = []
    for c in candidates:
        if c['lba'] not in seen_lba:
            seen_lba.add(c['lba'])
            unique.append(c)

    # --- Classify: primary vs checkpoint copies ---
    # The primary is typically the one closest to the partition start with the
    # largest block_count (= largest container).
    primary = None
    if unique:
        primary = max(unique, key=lambda c: c['block_count'])

    # --- Print results ---
    if not unique:
        print('No APFS container superblocks (NXSB) found.')
        print()
        print('This could mean:')
        print('  • The image is not APFS (wrong format)')
        print('  • The image is heavily encrypted and the SB is not readable without a key')
        print('  • The primary SB was zeroed AND no checkpoint copies survive')
        print()
        print('In this case, apfs-excavate will fall back to a B-tree node scan')
        print('automatically — you do not need --block.')
        return

    print(f'Found {len(unique)} APFS container superblock(s):\n')

    for i, c in enumerate(unique):
        is_primary_candidate = (c is primary)
        is_checkpoint = is_checkpoint_copy(c['byte_offset'], primary,
                                           primary['block_size'] if primary else 4096)

        role = ''
        if is_primary_candidate and len(unique) > 1:
            role = '  ← largest container (most likely the right one)'
        elif is_checkpoint:
            role = '  ← checkpoint/backup copy'

        print(f'  Candidate {i + 1}:{role}')
        print(f'    --block value  : {c["lba"]}')
        print(f'    Byte offset    : {c["byte_offset"]:,} (0x{c["byte_offset"]:X})')
        print(f'    Block size     : {c["block_size"]} bytes')
        print(f'    Container size : {fmt_size(c["container_size"])} '
              f'({c["block_count"]:,} blocks)')
        if verbose:
            print(f'    UUID           : {c.get("uuid", "?")}')
            print(f'    Next OID       : {c.get("next_oid", 0):,}')
        print()

    # --- Advice ---
    if len(unique) == 1:
        c = unique[0]
        print('Only one superblock found.')
        print(f'  apfs-excavate should detect this automatically.')
        print(f'  If it does not, use:  --block {c["lba"]}')
    else:
        print('Multiple superblocks found — apfs-excavate may pick the wrong one.')
        best = primary
        print(f'  Recommended:  --block {best["lba"]}')
        print()
        print('  If that produces wrong results, try the other candidate(s).')
        print('  Checkpoint copies represent earlier states of the same container')
        print('  and usually contain less current data than the primary.')

    print()
    if not verbose:
        print('Tip: run with --verbose to see container UUIDs and object IDs.')


if __name__ == '__main__':
    main()
