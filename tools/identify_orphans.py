#!/usr/bin/env python3
"""
identify_orphans.py — identify file types in a directory and rename extensions.

APFS orphan files are often LZVN-compressed blobs written without decompression
(because the tool had no inode metadata to know they were compressed).  Two
header formats are handled:

  fpmc  + uint32 type + uint64 uncompressed_size + LZVN stream  (decmpfs xattr)
  uint32 (header_len) + uint32 (compressed_len)  + LZVN stream  (simplified)

Content identification strategy (in order):
  1. Binary magic bytes against the peeked/decoded content window
  2. UTF-16 LE detection (null-byte interleaving, with or without BOM)
  3. UTF-8 text detection (valid multi-byte sequences OK, not just ASCII)
  4. Text-pattern rules against a latin-1 decoded preview
  5. Plain-text heuristic (>85% printable ASCII)
  6. Sliding-window text scan — if the LZVN stream started with a back-reference
     rather than a literal, scan the first 256 bytes for the first run of 12+
     consecutive printable chars and use that window for identification

Usage:
  python3 identify_orphans.py <dir>                    # dry run — print only
  python3 identify_orphans.py <dir> --rename           # rename extensions + delete zero-byte files
  python3 identify_orphans.py <dir> --dedup            # remove byte-identical duplicate files
  python3 identify_orphans.py <dir> --rename --dedup   # do both
"""

import hashlib
import os
import sys
import struct
from collections import defaultdict

# ---------------------------------------------------------------------------
# Magic-byte → extension table (checked against peeked content)
# ---------------------------------------------------------------------------
MAGIC_RULES = [
    # (offset_into_content, expected_bytes, extension)
    (0, b'\xff\xd8\xff',                     'jpg'),
    (0, b'\x89PNG\r\n\x1a\n',               'png'),
    (0, b'GIF87a',                            'gif'),
    (0, b'GIF89a',                            'gif'),
    (0, b'%PDF',                              'pdf'),
    (0, b'PK\x03\x04',                        'zip'),
    (0, b'PK\x05\x06',                        'zip'),
    (0, b'Rar!\x1a\x07',                      'rar'),
    (0, b'\x1f\x8b',                          'gz'),
    (0, b'BZh',                               'bz2'),
    (0, b'\xfd7zXZ\x00',                      'xz'),
    (0, b'7z\xbc\xaf\x27\x1c',               '7z'),
    (0, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'doc'),
    (0, b'SQLite format 3',                   'sqlite'),
    (0, b'bplist00',                           'plist'),
    (0, b'bplist15',                           'plist'),
    (0, b'bplist16',                           'plist'),
    (0, b'\xca\xfe\xba\xbe',                  'class'),
    (0, b'\xce\xfa\xed\xfe',                  'macho'),
    (0, b'\xcf\xfa\xed\xfe',                  'macho'),
    (0, b'\x7fELF',                            'elf'),
    (0, b'RIFF',                               'riff'),
    (0, b'OggS',                               'ogg'),
    (0, b'fLaC',                               'flac'),
    (0, b'ID3',                                'mp3'),
    (0, b'\xff\xfb',                           'mp3'),
    (0, b'\xff\xf3',                           'mp3'),
    (0, b'\xff\xf2',                           'mp3'),
    (0, b'\x1aE\xdf\xa3',                      'mkv'),
    (0, b'INDX',                               'idx'),
    (0, b'\x00\x01\x00\x00',                  'ttf'),
    (0, b'OTTO',                               'otf'),
    (0, b'wOFF',                               'woff'),
    (0, b'wOF2',                               'woff2'),
    (0, b'II\x2a\x00',                         'tiff'),
    (0, b'MM\x00\x2a',                         'tiff'),
    (0, b'BM',                                 'bmp'),
    (0, b'\x00\x00\x01\x00',                  'ico'),
    (0, b'8BPS',                               'psd'),
    (0, b'koly',                               'dmg'),
    (0, b'{\\rtf',                             'rtf'),
    (0, b'\x38\x42\x50\x53',                  'psd'),
    (0, b'\xff\xfe',                           'utf16'),  # UTF-16 LE BOM (refined below)
    (0, b'\xfe\xff',                           'utf16'),  # UTF-16 BE BOM
    # ftyp-based (MP4/MOV/HEIC)
    (4, b'ftypisom',                           'mp4'),
    (4, b'ftypMSNV',                           'mp4'),
    (4, b'ftypmp42',                           'mp4'),
    (4, b'ftyp\x00\x00\x00\x00',             'mp4'),
    (4, b'ftypqt  ',                           'mov'),
    (4, b'ftyp    ',                           'mov'),
    (4, b'ftypheic',                           'heic'),
    (4, b'ftypheis',                           'heic'),
    (4, b'ftypmif1',                           'heif'),
    (4, b'ftypM4A ',                           'm4a'),
    (4, b'ftypM4V ',                           'm4v'),
    (4, b'ftyp',                               'mp4'),
]

# Text-pattern → extension (case-insensitive match against first 512 bytes)
TEXT_RULES = [
    # HTML / XML / markup
    ('<!doctype html',            'html'),
    ('<html',                     'html'),
    ('<?xml',                     'xml'),
    ('<plist',                    'plist'),
    ('%!ps-adobe',                'ps'),
    # LaTeX
    ('\\begin{document}',         'tex'),
    ('\\documentclass',           'tex'),
    # Python
    ('# -*- coding',              'py'),
    ('#!/usr/bin/env python',      'py'),
    ('#!/usr/bin/python',          'py'),
    ('import sys\n',              'py'),
    ('import os\n',               'py'),
    ('import re\n',               'py'),
    # Shell
    ('#!/bin/bash',               'sh'),
    ('#!/bin/sh',                 'sh'),
    ('#! /bin/',                  'sh'),   # space-after-hash shebangs
    ('#!/usr/bin/env bash',        'sh'),
    ('#!/usr/bin/env sh',          'sh'),
    # Perl / Ruby
    ('#!/usr/bin/perl',           'pl'),
    ('#!/usr/bin/env perl',        'pl'),
    ('#!/usr/bin/ruby',           'rb'),
    ('#!/usr/bin/env ruby',        'rb'),
    # C# / .NET
    ('using system;',             'cs'),
    ('using system.',             'cs'),
    ('namespace ',                'cs'),   # also Java packages but good enough
    ('// <autogenerated>',        'cs'),
    ('// <auto-generated>',       'cs'),
    ('[assembly:',                'cs'),
    # Java
    ('public class ',             'java'),
    ('public interface ',         'java'),
    ('import java.',              'java'),
    # JavaScript / TypeScript
    ('var ',                      None),   # too generic alone
    ('function ',                 None),
    ('const ',                    None),
    ("'use strict'",              'js'),
    ('"use strict"',              'js'),
    ('module.exports',            'js'),
    ('require(',                  None),
    # CSS
    ('/* html elements */',       'css'),
    ('body {',                    'css'),
    ('body{',                     'css'),
    ('@charset ',                 'css'),
    ('@import ',                  'css'),
    # SQL
    ('select ',                   'sql'),
    ('create table',              'sql'),
    ('insert into',               'sql'),
    ('drop table',                'sql'),
    # CSV heuristic — handled separately in utf8_or_text_ext
    # Config / ini
    ('[general]\r\n',             'ini'),
    ('[general]\n',               'ini'),
    ('[settings]\n',              'ini'),
    ('[interntshortcut]',         'url'),
    # Certificates / keys
    ('-----begin certificate-----', 'pem'),
    ('-----begin rsa private key-----', 'pem'),
    ('-----begin private key-----',   'pem'),
    ('-----begin public key-----',    'pem'),
    # Email
    ('content-type: text/plain',  'eml'),
    ('mime-version:',             'eml'),
    ('return-path:',              'eml'),
    # JSON
    ('{"',                        'json'),
    ('[\n{',                      'json'),
    ('[{',                        'json'),
    # Specific text formats
    ('microsoft visual studio solution', 'sln'),
    ('windows registry editor',   'reg'),
    ('[hkey_',                    'reg'),
    ('network working group',     'txt'),
    ('metadata-version:',         'txt'),
    # Markdown
    ('# ',                        None),   # too generic
    # YAML
    ('---\n',                     None),
    # Makefile heuristic
    ('.phony:',                   'mk'),
    ('all:\n',                    None),
    # RTF (text-detected fallback for when magic missed it)
    ('{\\rtf',                    'rtf'),
    # Swift / ObjC
    ('import foundation',         'swift'),
    ('import uikit',              'swift'),
    ('@interface ',               'm'),
    ('@implementation ',          'm'),
    ('#import <foundation',       'm'),
    # Generic shebang fallback
    ('#!',                        'sh'),
]

ZIP_SUBTYPES = {
    'word/':           'docx',
    'xl/':             'xlsx',
    'ppt/':            'pptx',
    'META-INF/':       'jar',
    'AndroidManifest': 'apk',
}

RIFF_SUBTYPES = {
    b'WAVE': 'wav',
    b'AVI ': 'avi',
    b'WEBP': 'webp',
}

UTF16_TEXT_RULES = [
    ('windows registry editor', 'reg'),
    ('[hkey_',                  'reg'),
    ('<!doctype html',          'html'),
    ('<html',                   'html'),
    ('<?xml',                   'xml'),
    ('microsoft visual studio', 'sln'),
    ('using system',            'cs'),
]


# ---------------------------------------------------------------------------
# LZVN first-literal peek
# ---------------------------------------------------------------------------

def lzvn_peek_literal(data: bytes, offset: int) -> bytes:
    """
    Extract the first large literal run from an LZVN stream at `offset`.
    Returns up to 512 bytes, or b'' if opcode not recognised as literal.
    """
    if offset >= len(data):
        return b''

    op = data[offset]
    hi = op >> 4

    # Large literal: 0xE0-0xEF
    if hi == 0xE:
        if offset + 1 >= len(data):
            return b''
        count = ((op & 0x0F) << 8) | data[offset + 1]
        start = offset + 2
        return data[start: start + min(count, 512)]

    # Small literal + match: 0x00-0x5F — literal count in bits 3:2
    if hi <= 5:
        lit_count = (op >> 2) & 0x03
        if lit_count == 0:
            return b''
        start = offset + 3  # opcode + 2 distance bytes
        return data[start: start + min(lit_count, 512)]

    # Very small literal run: 0x60-0x6F
    if hi == 6:
        count = op & 0x0F
        return data[offset + 1: offset + 1 + count]

    return b''


def lzvn_scan_for_text(data: bytes, offset: int, scan_len: int = 256) -> bytes:
    """
    Slide through `scan_len` bytes of the LZVN stream starting at `offset`,
    looking for the first run of 12+ consecutive printable ASCII chars.
    Returns that window (up to 256 bytes from where the run starts), or b''.
    This handles streams that start with a back-reference rather than a literal.
    """
    end = min(offset + scan_len, len(data))
    run_start = -1
    run_len = 0
    for i in range(offset, end):
        b = data[i]
        if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d):
            if run_start < 0:
                run_start = i
            run_len += 1
            if run_len >= 12:
                return data[run_start: run_start + 256]
        else:
            run_start = -1
            run_len = 0
    return b''


# ---------------------------------------------------------------------------
# UTF-16 and UTF-8 helpers
# ---------------------------------------------------------------------------

def is_utf16_le(data: bytes) -> bool:
    """
    True if data looks like UTF-16 LE: every other byte is 0x00 and the
    non-null bytes are mostly printable ASCII (common in Windows text files).
    Requires at least 16 bytes.
    """
    if len(data) < 16:
        return False
    # BOM check
    if data[:2] == b'\xff\xfe':
        return True
    # Heuristic: bytes at odd offsets are mostly zero, even offsets mostly printable
    even = data[0:32:2]
    odd  = data[1:32:2]
    null_odd  = sum(1 for b in odd  if b == 0)
    ascii_even = sum(1 for b in even if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
    n = len(odd)
    return n > 0 and null_odd / n > 0.7 and ascii_even / n > 0.5


def decode_utf16(data: bytes) -> str:
    """Decode UTF-16 LE (with or without BOM) to a lowercase string."""
    bom = data[:2]
    enc = 'utf-16-le' if bom != b'\xfe\xff' else 'utf-16-be'
    start = 2 if bom in (b'\xff\xfe', b'\xfe\xff') else 0
    try:
        return data[start:start + 512].decode(enc, errors='replace').lower()
    except Exception:
        return ''


def is_valid_utf8_text(data: bytes) -> bool:
    """
    True if data is valid UTF-8 with a meaningful proportion of printable chars.
    Uses errors='replace' to avoid false negatives from multibyte sequences
    split at the 256-byte boundary.
    """
    if len(data) == 0:
        return False
    sample = data[:256].decode('utf-8', errors='replace')
    # Count replacement chars (U+FFFD) — too many means not real UTF-8
    invalid = sample.count('\ufffd')
    if invalid / max(len(sample), 1) > 0.10:
        return False
    printable = sum(1 for c in sample if c.isprintable() or c in '\t\n\r')
    return printable / max(len(sample), 1) > 0.60


# ---------------------------------------------------------------------------
# Content sniffer
# ---------------------------------------------------------------------------

def sniff(data: bytes) -> str:
    """Return an extension string (no dot) or '' for unknown."""

    if len(data) == 0:
        return ''

    if all(b == 0 for b in data) or all(b == 0xff for b in data):
        return '\x00zero'   # sentinel — all-zero or all-0xFF (noise), caller deletes

    # --- Determine the content window ---
    content = None
    lzvn_offset = -1  # set when we know the LZVN stream offset

    if data[:4] == b'fpmc':
        if len(data) >= 8:
            ctype = struct.unpack_from('<I', data, 4)[0]
            if ctype in (3,):
                content = None  # ZLIB — needs real decompressor
            else:
                lzvn_offset = 16
                content = lzvn_peek_literal(data, 16)

    elif len(data) >= 8 and data[1] == 0 and data[2] == 0 and data[3] == 0:
        hdr = data[0]
        if 8 <= hdr <= 32 and hdr % 4 == 0:
            lzvn_offset = hdr
            content = lzvn_peek_literal(data, hdr)

    if content is None:
        content = data

    # --- Binary magic rules ---
    for check_offset, magic, ext in MAGIC_RULES:
        end = check_offset + len(magic)
        if len(content) >= end and content[check_offset:end] == magic:
            if ext == 'zip':
                preview = content.decode('latin-1', errors='replace')
                for marker, sub_ext in ZIP_SUBTYPES.items():
                    if marker in preview:
                        return sub_ext
                return 'zip'
            if ext == 'riff' and len(content) >= 12:
                return RIFF_SUBTYPES.get(content[8:12], 'riff')
            if ext == 'utf16':
                return _classify_utf16(content)
            return ext

    # --- UTF-16 LE heuristic (no BOM) ---
    if is_utf16_le(content):
        return _classify_utf16(content)

    # --- UTF-8 multi-byte text ---
    if is_valid_utf8_text(content):
        # Still try text rules on the decoded string
        try:
            preview = content[:512].decode('utf-8', errors='replace').lower()
            for pattern, ext in TEXT_RULES:
                if ext and pattern in preview:
                    return ext
        except Exception:
            pass
        return 'txt'

    # --- Text-pattern rules (latin-1) ---
    try:
        preview = content[:512].decode('latin-1', errors='replace').lower()
    except Exception:
        preview = ''

    if preview:
        for pattern, ext in TEXT_RULES:
            if ext and pattern in preview:
                return ext

        # Plain ASCII text heuristic
        printable = sum(1 for b in content[:256] if 0x09 <= b <= 0x7e or b in (0x0a, 0x0d))
        if printable / max(min(len(content), 256), 1) > 0.85:
            return 'txt'

    # --- Sliding-window scan (handles LZVN back-reference starts) ---
    if lzvn_offset >= 0 and not content:
        window = lzvn_scan_for_text(data, lzvn_offset)
        if window:
            return sniff_window(window)
    elif lzvn_offset >= 0 and len(content) < 12:
        # Short literal — also scan forward for more content
        window = lzvn_scan_for_text(data, lzvn_offset)
        if window:
            result = sniff_window(window)
            if result:
                return result

    # Also scan even when lzvn_offset unknown, for compressed streams
    # that start with a match opcode at whatever offset we detected
    if not content and lzvn_offset < 0:
        # Try common LZVN stream offsets
        for try_off in (8, 10, 12, 16):
            window = lzvn_scan_for_text(data, try_off)
            if window:
                result = sniff_window(window)
                if result:
                    return result

    return ''


def _classify_utf16(content: bytes) -> str:
    """Identify UTF-16 content sub-type."""
    text = decode_utf16(content)
    if not text:
        return 'txt'
    for pattern, ext in UTF16_TEXT_RULES:
        if pattern in text:
            return ext
    return 'txt'


def sniff_window(window: bytes) -> str:
    """
    Run magic + text rules against a raw byte window found by the sliding
    scanner.  Used when the LZVN stream started with a back-reference.
    """
    # Binary magic
    for check_offset, magic, ext in MAGIC_RULES:
        end = check_offset + len(magic)
        if len(window) >= end and window[check_offset:end] == magic:
            if ext in ('zip', 'riff', 'utf16'):
                continue  # skip complex sub-type refinement in fallback path
            return ext

    # UTF-16
    if is_utf16_le(window):
        return _classify_utf16(window)

    # UTF-8
    if is_valid_utf8_text(window):
        try:
            preview = window[:256].decode('utf-8', errors='replace').lower()
            for pattern, ext in TEXT_RULES:
                if ext and pattern in preview:
                    return ext
        except Exception:
            pass
        return 'txt'

    # ASCII text rules
    try:
        preview = window[:256].decode('latin-1', errors='replace').lower()
    except Exception:
        return ''

    for pattern, ext in TEXT_RULES:
        if ext and pattern in preview:
            return ext

    printable = sum(1 for b in window[:128] if 0x09 <= b <= 0x7e or b in (0x0a, 0x0d))
    if printable / max(min(len(window), 128), 1) > 0.80:
        return 'txt'

    return ''


# ---------------------------------------------------------------------------
# Dedup helpers
# ---------------------------------------------------------------------------

def file_sha256(path: str) -> str:
    """SHA-256 of a file's full content; returns '' on I/O error."""
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ''


def find_dup_groups(fpaths: list) -> list:
    """
    Given a list of file paths that share the same size, return a list of
    duplicate groups.  Each group is a sorted list [keep, del1, del2, ...];
    the first entry (alphabetically lowest name) is the one to keep.
    Only groups with 2+ members are returned.
    """
    hash_map: dict = defaultdict(list)
    for fpath in fpaths:
        h = file_sha256(fpath)
        if h:
            hash_map[h].append(fpath)
    groups = []
    for group in hash_map.values():
        if len(group) >= 2:
            groups.append(sorted(group))
    return groups


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    orphan_dir = sys.argv[1]
    do_rename  = '--rename' in sys.argv
    do_dedup   = '--dedup'  in sys.argv

    if not os.path.isdir(orphan_dir):
        print(f'Error: {orphan_dir} is not a directory', file=sys.stderr)
        sys.exit(1)

    files = sorted(f for f in os.listdir(orphan_dir)
                   if os.path.isfile(os.path.join(orphan_dir, f)))
    if not files:
        print('No files found.')
        return

    _ZERO_SENTINEL = '\x00zero'

    ext_counts  = defaultdict(int)
    rename_plan = []   # list of (old_path, new_path)
    zero_files  = []
    skipped     = 0
    size_groups : dict = defaultdict(list)  # size -> [path, ...] for dedup

    for fname in files:
        fpath = os.path.join(orphan_dir, fname)
        try:
            fsize = os.path.getsize(fpath)
            with open(fpath, 'rb') as fh:
                data = fh.read(4096)
        except OSError:
            skipped += 1
            continue

        ext = sniff(data)
        if ext == _ZERO_SENTINEL and fsize > 10 * 1024 * 1024:
            # Large file: first 4 KB are noise bytes, but verify at mid and end
            # before deleting — the file may have real data after a zero-padded header.
            try:
                with open(fpath, 'rb') as fh:
                    fh.seek(fsize // 2)
                    mid = fh.read(4096)
                    fh.seek(max(0, fsize - 4096))
                    tail = fh.read(4096)
                noise_byte = data[0]  # 0x00 or 0xff
                if not (all(b == noise_byte for b in mid) and
                        all(b == noise_byte for b in tail)):
                    ext = ''   # has real content — treat as unknown, not noise
            except OSError:
                pass

        if ext == _ZERO_SENTINEL:
            zero_files.append(fpath)
            continue

        ext_counts[ext or '(unknown)'] += 1
        size_groups[fsize].append(fpath)

        if ext:
            base = os.path.splitext(fname)[0]
            new_name = f'{base}.{ext}'
            new_path = os.path.join(orphan_dir, new_name)
            if new_name != fname:
                rename_plan.append((fpath, new_path))

    # --- Dedup analysis (always computed for the report) ---
    dup_groups = []
    for fsize, fpaths in size_groups.items():
        if len(fpaths) >= 2:
            dup_groups.extend(find_dup_groups(fpaths))
    dup_redundant = sum(len(g) - 1 for g in dup_groups)

    # --- Report ---
    print(f'\nDirectory        : {orphan_dir}')
    print(f'Files scanned    : {len(files)}')
    print(f'Read errors      : {skipped}')
    print(f'All-zero (noise) : {len(zero_files)}')
    print(f'Would rename     : {len(rename_plan)}')
    print(f'Duplicate groups : {len(dup_groups)}  ({dup_redundant} redundant copies)')
    print(f'Unidentified     : {ext_counts.get("(unknown)", 0)}')
    print()
    print('Identified types:')
    for ext, count in sorted(ext_counts.items(), key=lambda x: -x[1]):
        print(f'  {count:6d}  .{ext}')

    print()
    if rename_plan:
        print('Sample renames (first 30):')
        for old, new in rename_plan[:30]:
            print(f'  {os.path.basename(old)}  →  {os.path.basename(new)}')
        if len(rename_plan) > 30:
            print(f'  ... and {len(rename_plan) - 30} more')

    if dup_groups:
        print()
        print('Sample duplicate groups (first 10):')
        for group in dup_groups[:10]:
            keep = os.path.basename(group[0])
            dups = [os.path.basename(p) for p in group[1:]]
            print(f'  keep {keep}  →  delete {", ".join(dups)}')
        if len(dup_groups) > 10:
            print(f'  ... and {len(dup_groups) - 10} more groups')

    if not do_rename and not do_dedup:
        print()
        print('Dry run — pass --rename to apply renames/deletions, --dedup to remove duplicates.')
        return

    # --- Dedup: delete redundant copies first so rename_plan stays consistent ---
    dedup_deleted = 0
    dedup_errors  = 0
    dedup_deleted_paths: set = set()
    if do_dedup:
        for group in dup_groups:
            for fpath in group[1:]:   # group[0] is the keeper (alphabetically first)
                try:
                    os.remove(fpath)
                    dedup_deleted_paths.add(fpath)
                    dedup_deleted += 1
                except OSError as e:
                    print(f'  Error deleting duplicate {os.path.basename(fpath)}: {e}',
                          file=sys.stderr)
                    dedup_errors += 1
        print(f'Removed {dedup_deleted} duplicate file(s) across {len(dup_groups)} group(s)'
              f'  ({dedup_errors} errors).  Kept alphabetically-first copy of each group.')

    if do_rename:
        # --- Delete all-zero files ---
        zero_deleted = 0
        for fpath in zero_files:
            try:
                os.remove(fpath)
                zero_deleted += 1
            except OSError as e:
                print(f'  Error deleting {os.path.basename(fpath)}: {e}', file=sys.stderr)
        if zero_deleted:
            print(f'Deleted {zero_deleted} all-zero file(s).')

        # --- Execute renames (skip files already removed by --dedup) ---
        done = 0
        errors = 0
        for old, new in rename_plan:
            if old in dedup_deleted_paths:
                continue
            if os.path.exists(new):
                base, ext2 = os.path.splitext(new)
                new = f'{base}_{os.path.basename(old).split(".")[0]}{ext2}'
            try:
                os.rename(old, new)
                done += 1
            except OSError as e:
                print(f'  Error renaming {os.path.basename(old)}: {e}', file=sys.stderr)
                errors += 1

        print(f'Renamed {done} files ({errors} errors).')


if __name__ == '__main__':
    main()
