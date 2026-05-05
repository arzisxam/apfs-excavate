#!/usr/bin/env python3
"""
dir_stats.py — Snapshot filesystem statistics for all entries in a directory tree.

Outputs one tab-separated record per entry, sorted by relative path.
Designed for diffing between runs to identify added, removed, or changed files.

Usage:
    python3 dir_stats.py <directory> [--label NAME] [--output FILE] [--no-checksum]
                                     [--workers N]

Output columns (tab-separated):
    SHA256      Hex digest for regular files; '-' otherwise (or if --no-checksum)
    TYPE        F=file  D=directory  L=symlink  O=other
    PERM        Octal permission bits, e.g. 755
    OWNER       Username (or UID if lookup fails)
    GROUP       Group name (or GID if lookup fails)
    SIZE        File size in bytes; '-' for directories and symlinks
    MTIME       Modification time (ISO-8601 UTC)
    PATH        Relative path from root; symlinks shown as "path -> target"

Notes:
    - Entries are sorted by PATH for stable diffs across runs.
    - SHA256 is first so the file doubles as a checksum manifest:
          awk '$1!="-"{print $1"  "$NF}' stats.txt | sha256sum -c
    - Directories have SIZE='-'; their MTIME reflects the last child change.
"""

import sys
import os
import stat
import hashlib
import argparse
import pwd
import grp
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

_CHUNK   = 1 << 20                          # 1 MiB read buffer (vs old 64 KiB)
_WORKERS = min(16, (os.cpu_count() or 4) * 2)
_COLS    = "SHA256\tTYPE\tPERM\tOWNER\tGROUP\tSIZE\tMTIME\tPATH"

# Cache uid/gid lookups — called once per unique id across 600 K+ entries.
_uid_cache: dict = {}
_gid_cache: dict = {}


def _sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while True:
                buf = f.read(_CHUNK)
                if not buf:
                    break
                h.update(buf)
        return h.hexdigest()
    except OSError as e:
        return f'ERR:{e.errno}'


def _ts(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')


def _owner(uid):
    if uid not in _uid_cache:
        try:
            _uid_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _uid_cache[uid] = str(uid)
    return _uid_cache[uid]


def _group(gid):
    if gid not in _gid_cache:
        try:
            _gid_cache[gid] = grp.getgrgid(gid).gr_name
        except KeyError:
            _gid_cache[gid] = str(gid)
    return _gid_cache[gid]


def _collect(root):
    """Return sorted list of relative paths for every entry under root."""
    paths = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        rel = os.path.relpath(dirpath, root)
        if rel != '.':
            paths.append(rel)
        for name in sorted(filenames):
            paths.append(os.path.relpath(os.path.join(dirpath, name), root))
        # Symlinks to directories appear in dirnames but are not traversed;
        # capture them here since they will never appear as a dirpath.
        for name in sorted(dirnames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                paths.append(os.path.relpath(full, root))
    return sorted(paths)


def _record(root, relpath, checksum):
    full = os.path.join(root, relpath)
    try:
        st = os.lstat(full)
    except OSError as e:
        return f"ERR:{e.errno}\tE\t-\t-\t-\t-\t-\t{relpath}"

    m     = st.st_mode
    perm  = oct(stat.S_IMODE(m))[2:]
    owner = _owner(st.st_uid)
    group = _group(st.st_gid)
    mtime = _ts(st.st_mtime)

    if stat.S_ISREG(m):
        digest = _sha256(full) if checksum else '-'
        return f"{digest}\tF\t{perm}\t{owner}\t{group}\t{st.st_size}\t{mtime}\t{relpath}"
    if stat.S_ISDIR(m):
        return f"-\tD\t{perm}\t{owner}\t{group}\t-\t{mtime}\t{relpath}"
    if stat.S_ISLNK(m):
        try:
            target = os.readlink(full)
        except OSError:
            target = '?'
        return f"-\tL\t{perm}\t{owner}\t{group}\t-\t{mtime}\t{relpath} -> {target}"
    return f"-\tO\t{perm}\t{owner}\t{group}\t{st.st_size}\t{mtime}\t{relpath}"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('directory',     help='Directory to snapshot')
    ap.add_argument('--label',       default=None, help='Label for this snapshot (default: dir basename)')
    ap.add_argument('--output',      default=None, help='Write to FILE instead of stdout')
    ap.add_argument('--no-checksum', action='store_true',
                    help='Skip SHA256 (faster; cannot detect content changes)')
    ap.add_argument('--workers',     type=int, default=_WORKERS,
                    help=f'Parallel SHA256 workers (default: {_WORKERS})')
    args = ap.parse_args()

    root = os.path.realpath(args.directory)
    if not os.path.isdir(root):
        sys.exit(f"Error: not a directory: {root}")

    label    = args.label or os.path.basename(root)
    checksum = not args.no_checksum
    paths    = _collect(root)
    now      = datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    def record_fn(relpath):
        return _record(root, relpath, checksum)

    # Parallel SHA256: hashlib releases the GIL during digest computation so
    # threads genuinely run concurrently and keep multiple SSD queues busy.
    # executor.map preserves input order, so output remains sorted.
    workers = args.workers if checksum else 1
    with ThreadPoolExecutor(max_workers=workers) as ex:
        records = list(ex.map(record_fn, paths, chunksize=256))

    total_size = 0
    file_count = 0
    for rec in records:
        cols = rec.split('\t')
        if cols[1] == 'F':
            file_count += 1
            try:
                total_size += int(cols[5])
            except ValueError:
                pass

    header = [
        f"# label:     {label}",
        f"# root:      {root}",
        f"# generated: {now}",
        f"# checksum:  {'none (--no-checksum)' if args.no_checksum else 'sha256'}",
        f"# entries:   {len(paths)}  (files: {file_count}, total size: {total_size} bytes)",
        f"# {_COLS}",
    ]

    text = '\n'.join(header + records) + '\n'

    if args.output:
        with open(args.output, 'w') as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
