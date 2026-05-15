#!/usr/bin/env python3
"""
decompress_orphans.py — decompress APFS-compressed orphan files in-place.

Orphan files extracted from APFS without inode metadata are left as raw
LZVN/LZFSE/ZLIB compressed blobs.  This script decompresses them using macOS
libcompression and overwrites each file with its actual content.

Two header formats are handled:
  fpmc + uint32 type + uint64 uncompressed_size + compressed_stream
  uint32 hdr_offset + uint32 compressed_len   + compressed_stream (LZVN)

Files that don't have a recognised compression header are left untouched
(they are already raw data — e.g. the JPG and MP4 files).

Usage:
  python3 decompress_orphans.py <orphan_dir>           # dry run
  python3 decompress_orphans.py <orphan_dir> --decompress
  python3 decompress_orphans.py <orphan_dir> --decompress --ext txt,html,xml
"""

import os
import sys
import struct
import ctypes
import zlib
from collections import defaultdict

# ---------------------------------------------------------------------------
# macOS libcompression
# ---------------------------------------------------------------------------

_lib = None

def _get_lib():
    global _lib
    if _lib is None:
        try:
            _lib = ctypes.CDLL('/usr/lib/libcompression.dylib')
            _lib.compression_decode_buffer.restype  = ctypes.c_size_t
            _lib.compression_decode_buffer.argtypes = [
                ctypes.c_char_p,   # dst_buffer
                ctypes.c_size_t,   # dst_size
                ctypes.c_char_p,   # src_buffer
                ctypes.c_size_t,   # src_size
                ctypes.c_char_p,   # scratch_buffer (NULL = use internal)
                ctypes.c_int,      # algorithm
            ]
        except OSError as e:
            sys.exit(f'Could not load libcompression.dylib: {e}')
    return _lib

COMPRESSION_LZVN = 0x900
COMPRESSION_LZFSE = 0x801
COMPRESSION_ZLIB  = 0x205   # raw deflate


def _decompress_libcomp(data: bytes, algorithm: int, uncompressed_size: int) -> bytes | None:
    lib = _get_lib()
    # Try the known size first, then double up to 64 MB if it fails
    for size in _size_sequence(uncompressed_size):
        dst = ctypes.create_string_buffer(size)
        written = lib.compression_decode_buffer(
            dst, size,
            data, len(data),
            None, algorithm
        )
        if written > 0:
            return dst.raw[:written]
    return None


def _size_sequence(hint: int):
    """Yield buffer sizes to try: hint, then doubling, up to 64 MB."""
    size = max(hint, 4096)
    yield size
    while size < 64 * 1024 * 1024:
        size *= 2
        yield size


def _decompress_zlib(data: bytes, uncompressed_size: int) -> bytes | None:
    try:
        return zlib.decompress(data)
    except zlib.error:
        try:
            return zlib.decompress(data, -15)  # raw deflate
        except zlib.error:
            return None


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------

# APFS decmpfs compression types
APFS_CTYPE = {
    1:  ('none',  None),             # uncompressed inline
    2:  ('none',  None),             # uncompressed resource fork
    3:  ('zlib',  COMPRESSION_ZLIB),
    4:  ('zlib',  COMPRESSION_ZLIB),
    7:  ('lzvn',  COMPRESSION_LZVN),
    8:  ('lzvn',  COMPRESSION_LZVN),
    11: ('lzfse', COMPRESSION_LZFSE),
    12: ('lzfse', COMPRESSION_LZFSE),
}


def parse_header(data: bytes):
    """
    Returns (compressed_data, algorithm_id, uncompressed_size) or None.
    algorithm_id is None for uncompressed inline data.
    uncompressed_size is 0 if unknown (estimate will be used).
    """
    if len(data) < 8:
        return None

    # --- fpmc header ---
    if data[:4] == b'fpmc':
        ctype = struct.unpack_from('<I', data, 4)[0]
        entry = APFS_CTYPE.get(ctype)
        if entry is None:
            return None
        name, algo = entry
        if name == 'none':
            # Data starts at offset 16, already uncompressed
            return (data[16:], None, len(data) - 16)
        uncompressed_size = struct.unpack_from('<Q', data, 8)[0]
        compressed_data = data[16:]
        return (compressed_data, algo, uncompressed_size)

    # --- Simplified header: uint32 hdr_offset + uint32 compressed_len ---
    if data[1] == 0 and data[2] == 0 and data[3] == 0:
        hdr = data[0]
        if 8 <= hdr <= 96 and hdr % 4 == 0:
            compressed_len = struct.unpack_from('<I', data, 4)[0]
            compressed_data = data[hdr: hdr + compressed_len]
            if len(compressed_data) < 4:
                return None
            # Heuristic uncompressed size: 20× compressed (capped at 64 MB)
            hint = min(compressed_len * 20, 64 * 1024 * 1024)
            return (compressed_data, COMPRESSION_LZVN, hint)

    return None


# ---------------------------------------------------------------------------
# Decompress one file
# ---------------------------------------------------------------------------

def decompress_file(path: str) -> tuple[str, int]:
    """
    Returns (status, original_size):
      status: 'ok', 'skip' (no header), 'uncompressed' (inline, no algo),
              'fail' (decompression error), 'error' (I/O error)
    """
    try:
        with open(path, 'rb') as fh:
            data = fh.read()
    except OSError:
        return ('error', 0)

    original_size = len(data)
    parsed = parse_header(data)

    if parsed is None:
        return ('skip', original_size)

    compressed_data, algo, uncompressed_size = parsed

    if algo is None:
        # Already uncompressed inline data
        try:
            with open(path, 'wb') as fh:
                fh.write(compressed_data)
            return ('uncompressed', original_size)
        except OSError:
            return ('error', original_size)

    if algo == COMPRESSION_ZLIB:
        result = _decompress_zlib(compressed_data, uncompressed_size)
    else:
        result = _decompress_libcomp(compressed_data, algo, uncompressed_size)

    if result is None or len(result) == 0:
        return ('fail', original_size)

    try:
        with open(path, 'wb') as fh:
            fh.write(result)
        return ('ok', original_size)
    except OSError:
        return ('error', original_size)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    orphan_dir   = sys.argv[1]
    do_decomp    = '--decompress' in sys.argv
    ext_filter   = None

    for arg in sys.argv[2:]:
        if arg.startswith('--ext'):
            val = arg.split('=', 1)[-1] if '=' in arg else (sys.argv[sys.argv.index(arg) + 1] if sys.argv.index(arg) + 1 < len(sys.argv) else '')
            ext_filter = set(e.lstrip('.').lower() for e in val.split(',') if e)

    if not os.path.isdir(orphan_dir):
        sys.exit(f'Error: {orphan_dir} is not a directory')

    # Collect files — skip .dat (unidentified) and already-decompressed
    all_files = sorted(os.listdir(orphan_dir))
    candidates = []
    for f in all_files:
        ext = os.path.splitext(f)[1].lstrip('.').lower()
        if not ext or ext == 'dat':
            continue
        if ext_filter and ext not in ext_filter:
            continue
        candidates.append(os.path.join(orphan_dir, f))

    if not candidates:
        print('No candidate files found.')
        return

    print(f'\nOrphan directory : {orphan_dir}')
    print(f'Candidates       : {len(candidates)}')
    if ext_filter:
        print(f'Extension filter : {", ".join(sorted(ext_filter))}')

    # Dry-run pass: probe headers without writing
    status_counts = defaultdict(int)
    sample_fails  = []

    for path in candidates:
        try:
            with open(path, 'rb') as fh:
                data = fh.read(256)
        except OSError:
            status_counts['error'] += 1
            continue

        parsed = parse_header(data)
        if parsed is None:
            status_counts['skip (already raw)'] += 1
        elif parsed[1] is None:
            status_counts['uncompressed inline'] += 1
        else:
            algo_name = {COMPRESSION_LZVN: 'lzvn', COMPRESSION_LZFSE: 'lzfse',
                         COMPRESSION_ZLIB: 'zlib'}.get(parsed[1], '?')
            status_counts[f'will decompress ({algo_name})'] += 1

    print()
    print('File breakdown:')
    for k, v in sorted(status_counts.items(), key=lambda x: -x[1]):
        print(f'  {v:6d}  {k}')

    if not do_decomp:
        print()
        print('Dry run — pass --decompress to decompress in-place.')
        return

    # Decompress pass
    print()
    results = defaultdict(int)
    bytes_saved = 0

    for i, path in enumerate(candidates):
        status, orig_size = decompress_file(path)
        results[status] += 1
        if status == 'ok':
            try:
                new_size = os.path.getsize(path)
                bytes_saved += new_size - orig_size  # usually positive (got bigger)
            except OSError:
                pass
        elif status == 'fail' and len(sample_fails) < 5:
            sample_fails.append(os.path.basename(path))

        if (i + 1) % 500 == 0 or (i + 1) == len(candidates):
            print(f'  {i+1}/{len(candidates)} processed ...', end='\r')

    print()
    print()
    print('Results:')
    print(f"  Decompressed OK      : {results['ok']}")
    print(f"  Already raw (skipped): {results['skip']}")
    print(f"  Inline uncompressed  : {results['uncompressed']}")
    print(f"  Decompression failed : {results['fail']}")
    print(f"  I/O errors           : {results['error']}")
    if bytes_saved != 0:
        mb = bytes_saved / (1024 * 1024)
        sign = '+' if mb >= 0 else ''
        print(f"  Size delta           : {sign}{mb:.1f} MB")
    if sample_fails:
        print(f"  Sample failures      : {', '.join(sample_fails)}")


if __name__ == '__main__':
    main()
