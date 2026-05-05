#!/usr/bin/env python3
"""
inspect_checkpoint.py — inspect apfs-excavate checkpoint files.

Auto-detects the file type from the magic header:
  • scan_results.bin  (magic: APFSCKPT) — geometry, inode/drec/path counts
  • extracted_ids.bin (magic: APFSDONE) — cumulative extraction stats + ID set

Usage:
  python3 tools/inspect_checkpoint.py <file>
  python3 tools/inspect_checkpoint.py <file> --dump [output.json]
  python3 tools/inspect_checkpoint.py <file> --dump-ids [output.txt]   # extracted_ids.bin only

Requires Python 3.8+, standard library only.
"""

import struct
import sys
import os
import json
import argparse
from datetime import datetime, timezone

# Must match CP_VERSION in include/apfs_types.h
CP_VERSION    = 4
CP_SCAN_MAGIC = b'APFSCKPT'
CP_DONE_MAGIC = b'APFSDONE'

# ---------------------------------------------------------------------------
# C struct layouts (little-endian, matching macOS/Linux x86_64/arm64 ABI)
#
# drec_t: uint64 parent_inode, uint64 file_inode, char name[256], bool is_dir
#   sizeof = 8+8+256+1 + 7 pad = 280 bytes
FMT_DREC = struct.Struct('< Q Q 256s B 7x')

# cp_inode_hdr_t (v4): 9×uint64 + 7×uint32 + 2×uint8 + 2 pad = 104 bytes
FMT_INODE_HDR = struct.Struct('< Q Q Q Q Q Q Q Q Q I I I I I I I B B 2x')

# extent_t: 4×uint64 + uint8 + 7 pad = 40 bytes
FMT_EXTENT = struct.Struct('< Q Q Q Q B 7x')

# deleted_file_t: 2×uint64 = 16 bytes
FMT_DELETED = struct.Struct('< Q Q')

# cp_extract_stats_t: 8×uint32 = 32 bytes (last 3 are _pad)
FMT_STATS = struct.Struct('< I I I I I I I I')

# Sanity-check sizes match the C structs.
_EXPECTED = {FMT_DREC: 280, FMT_INODE_HDR: 104,
             FMT_EXTENT: 40, FMT_DELETED: 16, FMT_STATS: 32}
for _fmt, _expected in _EXPECTED.items():
    if _fmt.size != _expected:
        raise RuntimeError(
            f'Struct size mismatch: got {_fmt.size}, expected {_expected}. '
            'File a bug — the C ABI on this platform differs from macOS/Linux x86_64.')


# ---------------------------------------------------------------------------
# Helpers

def read_exact(f, n):
    data = f.read(n)
    if len(data) != n:
        raise EOFError(f'Truncated file: expected {n} bytes, got {len(data)}')
    return data


def ns_to_iso(ns):
    """APFS nanosecond timestamp → ISO-8601 string (UTC)."""
    if ns == 0:
        return '(not set)'
    try:
        secs = ns // 1_000_000_000
        nsec = ns % 1_000_000_000
        dt   = datetime.fromtimestamp(secs, tz=timezone.utc)
        return dt.strftime('%Y-%m-%dT%H:%M:%S') + f'.{nsec:09d}Z'
    except (OSError, OverflowError, ValueError):
        return f'(invalid: {ns})'


def fmt_num(n):
    return f'{n:,}'


def fmt_size(n):
    for unit, threshold in [('TB', 1 << 40), ('GB', 1 << 30),
                             ('MB', 1 << 20), ('KB', 1 << 10)]:
        if n >= threshold:
            return f'{n / threshold:.2f} {unit}  ({n:,} bytes)'
    return f'{n} bytes'


# ---------------------------------------------------------------------------
# Scan checkpoint parser

def _read_scan_header(f):
    """Read geometry + counts; return (hdr_dict, drec_count, inode_count,
    path_count, deleted_count).  f must be positioned right after magic+version.
    """
    partition_offset, = struct.unpack('< Q', read_exact(f, 8))
    block_size,       = struct.unpack('< I', read_exact(f, 4))
    container_offset, = struct.unpack('< Q', read_exact(f, 8))
    enc, cs, done, _  = struct.unpack('< BBBB', read_exact(f, 4))
    dc, ic, pc, delc  = struct.unpack('< IIII', read_exact(f, 16))
    return (
        {
            'partition_offset': partition_offset,
            'block_size':       block_size,
            'container_offset': container_offset,
            'encryption':       bool(enc),
            'case_sensitive':   bool(cs),
            'complete':         bool(done),
        },
        dc, ic, pc, delc,
    )


def _parse_drecs(f, count):
    drecs = []
    for _ in range(count):
        parent_inode, file_inode, name_raw, is_dir = FMT_DREC.unpack(
            read_exact(f, FMT_DREC.size))
        drecs.append({
            'parent_inode': parent_inode,
            'file_inode':   file_inode,
            'name':         name_raw.rstrip(b'\x00').decode('utf-8', errors='replace'),
            'is_dir':       bool(is_dir),
        })
    return drecs


def _parse_inodes(f, count):
    inodes = []
    for _ in range(count):
        fields = FMT_INODE_HDR.unpack(read_exact(f, FMT_INODE_HDR.size))
        (inode_id, parent_id, size, uncompressed_size, default_crypto_id,
         create_time, mod_time, access_time, change_time,
         mode, compression_type, extent_count, decmpfs_len,
         uid, gid, bsd_flags, is_dir, is_compressed) = fields

        extents = []
        for _ in range(extent_count):
            logical, physical, length, crypto_id, flags = FMT_EXTENT.unpack(
                read_exact(f, FMT_EXTENT.size))
            extents.append({'logical': logical, 'physical': physical,
                            'length': length, 'crypto_id': crypto_id,
                            'flags': flags})

        decmpfs_hex = None
        if decmpfs_len > 0:
            decmpfs_hex = read_exact(f, decmpfs_len).hex()

        inodes.append({
            'inode_id':          inode_id,
            'parent_id':         parent_id,
            'size':              size,
            'uncompressed_size': uncompressed_size,
            'default_crypto_id': default_crypto_id,
            'create_time':       ns_to_iso(create_time),
            'mod_time':          ns_to_iso(mod_time),
            'access_time':       ns_to_iso(access_time),
            'change_time':       ns_to_iso(change_time),
            'mode':              oct(mode),
            'uid':               uid,
            'gid':               gid,
            'bsd_flags':         bsd_flags,
            'compression_type':  compression_type,
            'is_dir':            bool(is_dir),
            'is_compressed':     bool(is_compressed),
            'extents':           extents,
            'decmpfs_hex':       decmpfs_hex,
        })
    return inodes


def _parse_paths(f, count):
    paths = []
    for _ in range(count):
        inode_id, = struct.unpack('< Q', read_exact(f, 8))
        plen,     = struct.unpack('< I', read_exact(f, 4))
        if plen == 0 or plen > 4096:
            raise ValueError(f'Suspicious path length: {plen}')
        path_str = read_exact(f, plen).rstrip(b'\x00').decode('utf-8', errors='replace')
        paths.append({'inode_id': inode_id, 'path': path_str})
    return paths


def _parse_deleted(f, count):
    deleted = []
    for _ in range(count):
        block_num, inode_id = FMT_DELETED.unpack(read_exact(f, FMT_DELETED.size))
        deleted.append({'block_num': block_num, 'inode_id': inode_id})
    return deleted


def handle_scan(path, dump_path):
    file_size = os.path.getsize(path)
    with open(path, 'rb') as f:
        magic   = read_exact(f, 8)
        ver,    = struct.unpack('< I', read_exact(f, 4))

        if ver != CP_VERSION:
            print(f'  ERROR: version {ver}, expected {CP_VERSION}')
            print('  Run a fresh extraction to regenerate this checkpoint.')
            return

        hdr, dc, ic, pc, delc = _read_scan_header(f)

    print(f'Type     : Scan checkpoint  (APFSCKPT)')
    print(f'Version  : {ver}')
    print(f'Status   : {"Complete" if hdr["complete"] else "INCOMPLETE — interrupted during scan"}')
    print(f'File     : {path}  ({fmt_size(file_size)})')
    print()
    print('Geometry:')
    print(f'  Partition offset : {hdr["partition_offset"]:#018x}  ({hdr["partition_offset"]:,} bytes)')
    print(f'  Block size       : {hdr["block_size"]:,} bytes')
    print(f'  Container offset : {hdr["container_offset"]:#018x}  ({hdr["container_offset"]:,} bytes)')
    print(f'  Encryption       : {"Yes" if hdr["encryption"] else "No"}')
    print(f'  Case-sensitive   : {"Yes" if hdr["case_sensitive"] else "No"}')
    print()
    print('Counts:')
    print(f'  Directory records : {fmt_num(dc)}')
    print(f'  Inodes            : {fmt_num(ic)}')
    print(f'  Resolved paths    : {fmt_num(pc)}')
    print(f'  Deleted fragments : {fmt_num(delc)}')

    if not dump_path:
        return

    print()
    est_mb = (dc * FMT_DREC.size + ic * FMT_INODE_HDR.size +
              delc * FMT_DELETED.size) / 1024 / 1024
    print(f'Dumping full content to: {dump_path}')
    print(f'  Estimated minimum JSON size: ~{est_mb:.0f} MB  (larger with extents + paths)')

    with open(path, 'rb') as f:
        read_exact(f, 8)  # magic
        read_exact(f, 4)  # version
        _read_scan_header(f)

        drecs   = _parse_drecs(f, dc)
        inodes  = _parse_inodes(f, ic)
        paths   = _parse_paths(f, pc)
        deleted = _parse_deleted(f, delc)

    out_data = {
        'magic':    'APFSCKPT',
        'version':  ver,
        'complete': hdr['complete'],
        'geometry': hdr,
        'counts': {
            'drecs': dc, 'inodes': ic, 'paths': pc, 'deleted': delc,
        },
        'drecs':   drecs,
        'inodes':  inodes,
        'paths':   paths,
        'deleted': deleted,
    }
    with open(dump_path, 'w') as out:
        json.dump(out_data, out, indent=2)
    written_mb = os.path.getsize(dump_path) / 1024 / 1024
    print(f'  Written: {dump_path}  ({written_mb:.1f} MB)')


# ---------------------------------------------------------------------------
# Extraction checkpoint parser

def handle_extracted(path, dump_path, dump_ids_path):
    file_size = os.path.getsize(path)
    with open(path, 'rb') as f:
        read_exact(f, 8)  # magic already verified
        ver, = struct.unpack('< I', read_exact(f, 4))

        if ver != CP_VERSION:
            print(f'  ERROR: version {ver}, expected {CP_VERSION}')
            print('  Run a fresh extraction to regenerate this checkpoint.')
            return

        raw_stats = FMT_STATS.unpack(read_exact(f, FMT_STATS.size))
        files_found, files_recovered, files_skipped, files_zero_byte, files_failed = raw_stats[:5]

        count, = struct.unpack('< I', read_exact(f, 4))

        ids = []
        for _ in range(count):
            iid, = struct.unpack('< Q', read_exact(f, 8))
            ids.append(iid)

    total_accounted = files_recovered + files_skipped + files_zero_byte + files_failed
    rate = (100.0 * files_recovered / files_found) if files_found > 0 else 0.0
    remaining = max(0, files_found - total_accounted) if files_found > 0 else 0

    print(f'Type     : Extraction checkpoint  (APFSDONE)')
    print(f'Version  : {ver}')
    print(f'File     : {path}  ({fmt_size(file_size)})')
    print()
    print('Extraction Stats  (cumulative across all runs):')
    print(f'  Files found       : {fmt_num(files_found)}')
    print(f'  Files recovered   : {fmt_num(files_recovered)}')
    if files_skipped > 0:
        print(f'  Files skipped     : {fmt_num(files_skipped)}  (size filter)')
    if files_zero_byte > 0:
        print(f'  Zero-byte files   : {fmt_num(files_zero_byte)}  (all extents out of range)')
    if files_failed > 0:
        print(f'  Files failed      : {fmt_num(files_failed)}')
    if files_found > 0:
        print(f'  Recovery rate     : {rate:.1f}%')
    print()
    print('Checkpoint:')
    print(f'  IDs in checkpoint : {fmt_num(count)}')
    if remaining > 0:
        print(f'  Remaining         : {fmt_num(remaining)}  (not yet processed)')
    elif files_found > 0:
        print('  Status            : All files accounted for')

    if dump_ids_path:
        with open(dump_ids_path, 'w') as out:
            for iid in ids:
                out.write(f'{iid}\n')
        print(f'\nID list written to: {dump_ids_path}  ({count:,} lines)')

    if dump_path:
        out_data = {
            'magic':   'APFSDONE',
            'version': ver,
            'stats': {
                'files_found':     files_found,
                'files_recovered': files_recovered,
                'files_skipped':   files_skipped,
                'files_zero_byte': files_zero_byte,
                'files_failed':    files_failed,
            },
            'checkpoint_count': count,
            'inode_ids': ids,
        }
        with open(dump_path, 'w') as out:
            json.dump(out_data, out, indent=2)
        written_mb = os.path.getsize(dump_path) / 1024 / 1024
        print(f'\nFull dump written to: {dump_path}  ({written_mb:.1f} MB)')


# ---------------------------------------------------------------------------
# Entry point

def main():
    ap = argparse.ArgumentParser(
        description='Inspect apfs-excavate checkpoint files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 tools/inspect_checkpoint.py out/logs/scan_results.bin
  python3 tools/inspect_checkpoint.py out/logs/extracted_ids.bin
  python3 tools/inspect_checkpoint.py out/logs/scan_results.bin --dump scan_dump.json
  python3 tools/inspect_checkpoint.py out/logs/extracted_ids.bin --dump ids_dump.json
  python3 tools/inspect_checkpoint.py out/logs/extracted_ids.bin --dump-ids ids.txt
""")
    ap.add_argument('file', help='Path to scan_results.bin or extracted_ids.bin')
    ap.add_argument(
        '--dump', metavar='output.json', nargs='?', const='checkpoint_dump.json',
        help='Write full content to a JSON file (default name: checkpoint_dump.json). '
             'Can be large for scan checkpoints.')
    ap.add_argument(
        '--dump-ids', metavar='output.txt', nargs='?', const='checkpoint_ids.txt',
        help='Write checkpointed inode ID list to a text file, one ID per line '
             '(extracted_ids.bin only; default name: checkpoint_ids.txt).')
    args = ap.parse_args()

    path = args.file
    if not os.path.exists(path):
        print(f'Error: file not found: {path}', file=sys.stderr)
        sys.exit(1)

    try:
        with open(path, 'rb') as f:
            magic = f.read(8)
    except OSError as e:
        print(f'Error: cannot open file: {e}', file=sys.stderr)
        sys.exit(1)

    print()
    try:
        if magic == CP_SCAN_MAGIC:
            if args.dump_ids:
                print('Note: --dump-ids is only applicable to extracted_ids.bin (ignored)')
            handle_scan(path, args.dump)
        elif magic == CP_DONE_MAGIC:
            handle_extracted(path, args.dump, args.dump_ids)
        else:
            print(f'Error: unrecognised magic {magic!r}', file=sys.stderr)
            print('Expected APFSCKPT (scan_results.bin) or APFSDONE (extracted_ids.bin)',
                  file=sys.stderr)
            sys.exit(1)
    except EOFError as e:
        print(f'\nError: {e}', file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, struct.error) as e:
        print(f'\nError parsing checkpoint: {e}', file=sys.stderr)
        sys.exit(1)
    print()


if __name__ == '__main__':
    main()
