/*
 * orphan_post.c — post-extraction orphan file classification and decompression.
 *
 * Orphan files are written as raw APFS compressed blobs because the extraction
 * phase has no inode metadata to know they are compressed.  This module
 * decompresses them, identifies the file type, renames them, and moves anything
 * that cannot be identified to orphan_dir/unrecoverable/.
 *
 * Compression formats handled:
 *   fpmc header  — standard APFS decmpfs xattr (type 3=ZLIB, 7/8=LZVN, 11/12=LZFSE)
 *   NN 00 00 00  — simplified blob where byte[0] is the stream offset (LZVN)
 *
 * File-type detection:
 *   1. Binary magic bytes
 *   2. ftyp / RIFF sub-type refinement
 *   3. UTF-16 LE detection (Windows files)
 *   4. Case-insensitive text-pattern table
 *   5. Plain-ASCII printability heuristic (>85%)
 *   6. Sliding-window scan (for streams that start with a back-reference)
 */

#define _GNU_SOURCE
#include "orphan_post.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasestr */
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <zlib.h>

#ifdef __APPLE__
#include <compression.h>
/* Stable ABI value — defined here in case the SDK omits it at the current
 * deployment target. */
#ifndef COMPRESSION_LZVN
#define COMPRESSION_LZVN 0x900
#endif
#endif

#include <unistd.h>

#include "compress.h"
#include "apfs_globals.h"
#include "errors.h"
#include "util.h"
#include "log.h"
#include "term.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

#define ORPHAN_READ_BYTES   (256 * 1024)   /* read up to 256 KB for decompression */
#define DECOMP_MAX_BYTES    (64 * 1024 * 1024)  /* 64 MB ceiling                  */
#define DECOMP_HINT_MULT    8              /* start buffer = compressed × this     */
#define TEXT_SCAN_BYTES     256            /* bytes to scan for sliding-window      */
#define TEXT_MIN_RUN        12             /* min consecutive printable chars       */
#define TEXT_ASCII_PCT      85             /* % printable to call something text    */

/* APFS decmpfs compression types */
#define APFS_COMP_NONE_INLINE   1
#define APFS_COMP_NONE_RSRC     2
#define APFS_COMP_ZLIB_INLINE   3
#define APFS_COMP_ZLIB_RSRC     4
#define APFS_COMP_LZVN_INLINE   7
#define APFS_COMP_LZVN_RSRC     8
#define APFS_COMP_LZFSE_INLINE  11
#define APFS_COMP_LZFSE_RSRC    12

/* ============================================================================
 * Decompression helpers
 * ============================================================================
 */

/* Thin wrapper so the calling code is platform-independent. */
static size_t do_lzvn(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_len) {
#ifdef __APPLE__
    return compression_decode_buffer(dst, dst_len, src, src_len,
                                     NULL, COMPRESSION_LZVN);
#else
    return cmp_lzvn(src, src_len, dst, dst_len);
#endif
}

static size_t do_lzfse(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_len) {
    return cmp_lzfse(src, src_len, dst, dst_len);
}

static size_t do_zlib(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_len) {
    uLongf out = (uLongf)dst_len;
    if (uncompress(dst, &out, src, (uLong)src_len) == Z_OK)
        return (size_t)out;
    /* Try raw deflate */
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, -15) != Z_OK) return 0;
    zs.next_in   = (Bytef *)src;
    zs.avail_in  = (uInt)src_len;
    zs.next_out  = dst;
    zs.avail_out = (uInt)dst_len;
    int ret = inflate(&zs, Z_FINISH);
    size_t written = dst_len - zs.avail_out;
    inflateEnd(&zs);
    return (ret == Z_STREAM_END) ? written : 0;
}

typedef size_t (*decomp_fn_t)(const uint8_t *, size_t, uint8_t *, size_t);

/*
 * Decompress with a growing buffer when the uncompressed size is unknown.
 * Returns a malloc'd buffer on success (caller must free), NULL on failure.
 */
static uint8_t *decompress_growing(const uint8_t *src, size_t src_len,
                                    decomp_fn_t fn, size_t hint,
                                    size_t *out_len) {
    size_t size = hint > 0 ? hint : src_len * DECOMP_HINT_MULT;
    if (size < 16384) size = 16384;
    if (size > DECOMP_MAX_BYTES) size = DECOMP_MAX_BYTES;

    for (int attempt = 0; attempt < 6; attempt++) {
        uint8_t *buf = malloc(size);
        if (!buf) return NULL;

        size_t written = fn(src, src_len, buf, size);

        /* Success: wrote something and didn't fill the entire buffer
         * (filling it means we may have been truncated). */
        if (written > 0 && written < size) {
            *out_len = written;
            return buf;
        }
        free(buf);

        /* If we filled the buffer exactly, double and retry. */
        if (written == size) {
            size_t next_size = size * 2;
            if (next_size > DECOMP_MAX_BYTES || next_size < size) break;
            size = next_size;
            continue;
        }
        /* wrote == 0: decompression failed, no point retrying with larger buf */
        break;
    }
    return NULL;
}

/* ============================================================================
 * Header parsing
 * ============================================================================
 */

typedef struct {
    const uint8_t *comp_data;   /* pointer into the raw file buffer */
    size_t         comp_len;
    decomp_fn_t    decomp;      /* NULL = already uncompressed      */
    uint64_t       uncomp_size; /* 0 = unknown (use growing buffer) */
} orphan_header_t;

static bool parse_header(const uint8_t *data, size_t data_len,
                          orphan_header_t *out) {
    if (data_len < 8) return false;

    /* ---- fpmc header ---- */
    if (memcmp(data, "fpmc", 4) == 0) {
        if (data_len < 16) return false;
        uint32_t ctype;
        memcpy(&ctype, data + 4, 4);
        uint64_t uncomp;
        memcpy(&uncomp, data + 8, 8);

        out->comp_data  = data + 16;
        out->comp_len   = data_len > 16 ? data_len - 16 : 0;
        out->uncomp_size = uncomp;

        switch (ctype) {
            case APFS_COMP_NONE_INLINE:
            case APFS_COMP_NONE_RSRC:
                out->decomp = NULL;
                return true;
            case APFS_COMP_ZLIB_INLINE:
            case APFS_COMP_ZLIB_RSRC:
                out->decomp = do_zlib;
                return true;
            case APFS_COMP_LZVN_INLINE:
            case APFS_COMP_LZVN_RSRC:
                out->decomp = do_lzvn;
                return true;
            case APFS_COMP_LZFSE_INLINE:
            case APFS_COMP_LZFSE_RSRC:
                out->decomp = do_lzfse;
                return true;
            default:
                return false;  /* unsupported type */
        }
    }

    /* ---- Simplified blob: byte[0] = stream offset, bytes[4-7] = comp_len ---- */
    if (data[1] == 0 && data[2] == 0 && data[3] == 0) {
        uint8_t hdr = data[0];
        if (hdr >= 8 && hdr <= 96 && (hdr % 4) == 0) {
            uint32_t comp_len;
            memcpy(&comp_len, data + 4, 4);
            /* Reject zero-length blobs — a real compressed block always has data.
             * This closes the false-positive where a binary file starts with a
             * small 4-aligned byte followed by three zero bytes and a zero length
             * field, which previously matched this heuristic. */
            if (comp_len == 0) return false;
            if ((size_t)hdr + comp_len > data_len)
                comp_len = (uint32_t)(data_len - hdr);
            if (comp_len == 0) return false;   /* hdr >= data_len */
            out->comp_data   = data + hdr;
            out->comp_len    = comp_len;
            out->decomp      = do_lzvn;
            out->uncomp_size = 0;   /* unknown */
            return true;
        }
    }

    return false;   /* no recognised header */
}

/* ============================================================================
 * File-type detection
 * ============================================================================
 */

typedef struct { size_t off; const char *magic; size_t len; const char *ext; } magic_rule_t;

static const magic_rule_t MAGIC[] = {
    { 0, "\xff\xd8\xff",                     3,  "jpg"    },
    { 0, "\x89PNG\r\n\x1a\n",               8,  "png"    },
    { 0, "GIF87a",                            6,  "gif"    },
    { 0, "GIF89a",                            6,  "gif"    },
    { 0, "%PDF",                              4,  "pdf"    },
    { 0, "PK\x03\x04",                        4,  "zip"    },
    { 0, "PK\x05\x06",                        4,  "zip"    },
    { 0, "Rar!\x1a\x07",                      6,  "rar"    },
    { 0, "\x1f\x8b",                          2,  "gz"     },
    { 0, "BZh",                               3,  "bz2"    },
    { 0, "\xfd\x37\x7a\x58\x5a\x00",         6,  "xz"     },
    { 0, "7z\xbc\xaf\x27\x1c",               6,  "7z"     },
    { 0, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8,  "doc"    },
    { 0, "SQLite format 3",                  15,  "sqlite" },
    { 0, "bplist00",                           8,  "plist"  },
    { 0, "bplist15",                           8,  "plist"  },
    { 0, "bplist16",                           8,  "plist"  },
    { 0, "\xca\xfe\xba\xbe",                  4,  "macho"  },
    { 0, "\xce\xfa\xed\xfe",                  4,  "macho"  },
    { 0, "\xcf\xfa\xed\xfe",                  4,  "macho"  },
    { 0, "\x7f" "ELF",                        4,  "elf"    },
    { 0, "RIFF",                              4,  "riff"   },  /* refined below */
    { 0, "OggS",                              4,  "ogg"    },
    { 0, "fLaC",                              4,  "flac"   },
    { 0, "ID3",                               3,  "mp3"    },
    { 0, "\xff\xfb",                          2,  "mp3"    },
    { 0, "\xff\xf3",                          2,  "mp3"    },
    { 0, "\x1a\x45\xdf\xa3",                  4,  "mkv"    },
    { 0, "\x00\x01\x00\x00",                  4,  "ttf"    },
    { 0, "OTTO",                              4,  "otf"    },
    { 0, "wOFF",                              4,  "woff"   },
    { 0, "wOF2",                              4,  "woff2"  },
    { 0, "II\x2a\x00",                        4,  "tiff"   },
    { 0, "MM\x00\x2a",                        4,  "tiff"   },
    { 0, "BM",                                2,  "bmp"    },
    { 0, "\x00\x00\x01\x00",                  4,  "ico"    },
    { 0, "8BPS",                              4,  "psd"    },
    { 0, "koly",                              4,  "dmg"    },
    { 0, "{\\rtf",                            5,  "rtf"    },
    { 0, "\x38\x42\x50\x53",                  4,  "psd"    },
    { 0, "\xff\xfe",                          2,  "utf16"  },  /* UTF-16 LE BOM, refined */
    { 0, "\xfe\xff",                          2,  "utf16"  },  /* UTF-16 BE BOM          */
    { 4, "ftyp",                              4,  "ftyp"   },  /* MP4/MOV/HEIC, refined  */
    { 0, NULL, 0, NULL }
};

/* Refine "riff" to wav / avi / webp */
static const char *riff_subtype(const uint8_t *buf, size_t len) {
    if (len < 12) return "riff";
    if (memcmp(buf + 8, "WAVE", 4) == 0) return "wav";
    if (memcmp(buf + 8, "AVI ", 4) == 0) return "avi";
    if (memcmp(buf + 8, "WEBP", 4) == 0) return "webp";
    return "riff";
}

/* Refine "ftyp" to mp4 / mov / heic / m4a / etc. */
static const char *ftyp_subtype(const uint8_t *buf, size_t len) {
    if (len < 12) return "mp4";
    const uint8_t *b = buf + 8;
    if (memcmp(b, "heic", 4) == 0 || memcmp(b, "heis", 4) == 0) return "heic";
    if (memcmp(b, "mif1", 4) == 0 || memcmp(b, "msf1", 4) == 0) return "heif";
    if (memcmp(b, "M4A ", 4) == 0) return "m4a";
    if (memcmp(b, "M4V ", 4) == 0) return "m4v";
    if (memcmp(b, "qt  ", 4) == 0) return "mov";
    return "mp4";
}

/* Returns true if the buffer looks like UTF-16 LE (heuristic). */
static bool is_utf16_le(const uint8_t *buf, size_t len) {
    if (len < 16) return false;
    if (buf[0] == 0xff && buf[1] == 0xfe) return true;   /* BOM */
    size_t check = len < 64 ? len : 64;
    size_t nulls = 0, printable = 0;
    for (size_t i = 1; i < check; i += 2) if (buf[i] == 0) nulls++;
    for (size_t i = 0; i < check; i += 2)
        if (buf[i] >= 0x20 && buf[i] <= 0x7e) printable++;
    size_t pairs = check / 2;
    return pairs > 0 && nulls * 100 / pairs > 70 && printable * 100 / pairs > 40;
}

/* Case-insensitive substring search (like strcasestr but portable). */
static bool icontains(const char *haystack, size_t hay_len, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > hay_len) return false;
    for (size_t i = 0; i + nlen <= hay_len; i++) {
        size_t j = 0;
        while (j < nlen && tolower((unsigned char)haystack[i+j]) ==
                           tolower((unsigned char)needle[j])) j++;
        if (j == nlen) return true;
    }
    return false;
}

typedef struct { const char *pattern; const char *ext; } text_rule_t;

static const text_rule_t TEXT_RULES[] = {
    { "<!doctype html",                 "html"  },
    { "<html",                          "html"  },
    { "<?xml",                          "xml"   },
    { "<plist",                         "plist" },
    { "%!ps-adobe",                     "ps"    },
    { "\\begin{document}",              "tex"   },
    { "\\documentclass",                "tex"   },
    { "#!/bin/bash",                    "sh"    },
    { "#!/bin/sh",                      "sh"    },
    { "#! /bin/",                       "sh"    },  /* space-after-hash shebangs */
    { "#!/usr/bin/env bash",             "sh"    },
    { "#!/usr/bin/env sh",               "sh"    },
    { "#!/usr/bin/perl",                "pl"    },
    { "#!/usr/bin/env perl",             "pl"    },
    { "#!/usr/bin/ruby",                "rb"    },
    { "#!/usr/bin/env ruby",             "rb"    },
    { "#!/usr/bin/env python",           "py"    },
    { "#!/usr/bin/python",              "py"    },
    { "# -*- coding",                   "py"    },
    { "import sys\n",                   "py"    },
    { "import os\n",                    "py"    },
    { "import re\n",                    "py"    },
    { "using system;",                  "cs"    },
    { "using system.",                  "cs"    },
    { "// <autogenerated>",             "cs"    },
    { "// <auto-generated>",            "cs"    },
    { "namespace ",                     "cs"    },
    { "import java.",                   "java"  },
    { "import android.",                "java"  },
    { "public class ",                  "java"  },
    { "@interface ",                    "m"     },
    { "@implementation ",               "m"     },
    { "#import <foundation",            "m"     },
    { "import foundation",              "swift" },
    { "import uikit",                   "swift" },
    { "@charset ",                      "css"   },
    { "/* html elements */",            "css"   },
    { "body {",                         "css"   },
    { "body{",                          "css"   },
    { "@import ",                       "css"   },
    { "select ",                        "sql"   },
    { "create table",                   "sql"   },
    { "insert into",                    "sql"   },
    { "drop table",                     "sql"   },
    { "-----begin certificate-----",    "pem"   },
    { "-----begin rsa private key-----","pem"   },
    { "-----begin private key-----",    "pem"   },
    { "-----begin public key-----",     "pem"   },
    { "windows registry editor",        "reg"   },
    { "[hkey_",                         "reg"   },
    { "mime-version:",                  "eml"   },
    { "return-path:",                   "eml"   },
    { "content-type: text/",            "eml"   },
    { "microsoft visual studio solution","sln"  },
    { "{\"",                            "json"  },
    { "'use strict'",                   "js"    },
    { "module.exports",                 "js"    },
    { "public interface ",              "java"  },
    { "[assembly:",                     "cs"    },
    /* INI / URL / plain-text formats (gap vs identify_orphans.py) */
    { "[general]\n",                    "ini"   },
    { "[general]\r\n",                  "ini"   },
    { "[settings]\n",                   "ini"   },
    { "[interntshortcut]",              "url"   },
    { "network working group",          "txt"   },
    { "metadata-version:",              "txt"   },
    { NULL, NULL }
};

static bool is_noise_content(const uint8_t *buf, size_t len) {
    if (len == 0) return true;
    uint8_t first = buf[0];
    if (first != 0x00 && first != 0xff) return false;
    for (size_t i = 1; i < len; i++)
        if (buf[i] != first) return false;
    return true;   /* all-zero or all-0xFF (erased flash) */
}

/*
 * True if buf looks like UTF-8 text: at least some valid multibyte sequences,
 * >= 70% of bytes are good (printable ASCII or valid UTF-8), < 10% invalid.
 */
static bool is_utf8_text(const uint8_t *buf, size_t len) {
    size_t check    = len < 256 ? len : 256;
    size_t ascii_ok = 0;
    size_t valid_mb = 0;   /* bytes in valid multibyte sequences   */
    size_t invalid  = 0;
    size_t i        = 0;

    while (i < check) {
        uint8_t b = buf[i];
        if (b <= 0x7f) {
            if ((b >= 0x09 && b <= 0x0d) || (b >= 0x20 && b <= 0x7e))
                ascii_ok++;
            else
                invalid++;
            i++;
        } else if (b >= 0xc2 && b <= 0xdf && i + 1 < check &&
                   (buf[i+1] & 0xc0) == 0x80) {
            valid_mb += 2; i += 2;
        } else if (b >= 0xe0 && b <= 0xef && i + 2 < check &&
                   (buf[i+1] & 0xc0) == 0x80 && (buf[i+2] & 0xc0) == 0x80) {
            valid_mb += 3; i += 3;
        } else if (b >= 0xf0 && b <= 0xf4 && i + 3 < check &&
                   (buf[i+1] & 0xc0) == 0x80 && (buf[i+2] & 0xc0) == 0x80 &&
                   (buf[i+3] & 0xc0) == 0x80) {
            valid_mb += 4; i += 4;
        } else {
            invalid++; i++;
        }
    }

    size_t good = ascii_ok + valid_mb;
    if (check == 0) return false;
    /* Mirror Python's identify_orphans.py: accept pure-ASCII files (no
     * multibyte sequences needed) and use a 60% printable / 10% invalid
     * threshold rather than requiring valid_mb > 0 at 70%. */
    return good * 100 / check >= 60
        && invalid * 100 / check < 10;
}

/* Returns a static string extension (no dot), or NULL if unidentified. */
static const char *classify_content(const uint8_t *buf, size_t len) {
    if (len == 0) return NULL;

    /* --- Binary magic --- */
    for (int i = 0; MAGIC[i].magic != NULL; i++) {
        const magic_rule_t *r = &MAGIC[i];
        if (len < r->off + r->len) continue;
        if (memcmp(buf + r->off, r->magic, r->len) == 0) {
            if (strcmp(r->ext, "riff")  == 0) return riff_subtype(buf, len);
            if (strcmp(r->ext, "ftyp")  == 0) return ftyp_subtype(buf, len);
            if (strcmp(r->ext, "utf16") == 0) {
                /* UTF-16 BOM found — peek at content */
                goto classify_utf16;
            }
            return r->ext;
        }
    }

    /* --- UTF-16 LE heuristic (no BOM) --- */
    if (is_utf16_le(buf, len)) {
classify_utf16:;
        /* Decode a preview: take even-offset bytes as ASCII characters */
        char preview[256];
        size_t p = 0;
        size_t start = (buf[0] == 0xff && buf[1] == 0xfe) ? 2 : 0;
        for (size_t i = start; i + 1 < len && p < sizeof(preview) - 1; i += 2)
            preview[p++] = (char)(buf[i] & 0x7f);
        preview[p] = '\0';
        for (const text_rule_t *r = TEXT_RULES; r->pattern; r++) {
            if (icontains(preview, p, r->pattern)) return r->ext;
        }
        return "txt";   /* UTF-16 text, type unknown */
    }

    /* --- Text pattern matching (latin-1 preview) --- */
    char preview[512];
    size_t plen = len < sizeof(preview) - 1 ? len : sizeof(preview) - 1;
    memcpy(preview, buf, plen);
    preview[plen] = '\0';

    for (const text_rule_t *r = TEXT_RULES; r->pattern; r++) {
        if (icontains(preview, plen, r->pattern)) return r->ext;
    }

    /* --- Plain ASCII heuristic --- */
    size_t check = len < 256 ? len : 256;
    size_t printable = 0;
    for (size_t i = 0; i < check; i++) {
        uint8_t b = buf[i];
        if ((b >= 0x09 && b <= 0x0d) || (b >= 0x20 && b <= 0x7e))
            printable++;
    }
    if (check > 0 && printable * 100 / check >= TEXT_ASCII_PCT)
        return "txt";

    /* --- UTF-8 multibyte text heuristic (Japanese, accented text, etc.) --- */
    if (is_utf8_text(buf, len))
        return "txt";

    return NULL;
}

/*
 * Slide through `scan_len` bytes looking for a run of TEXT_MIN_RUN+ consecutive
 * printable ASCII chars.  Returns a pointer into `buf` at the run start, or NULL.
 */
static const uint8_t *find_text_run(const uint8_t *buf, size_t buf_len,
                                     size_t scan_len, size_t *run_len_out) {
    size_t end       = buf_len < scan_len ? buf_len : scan_len;
    size_t run_start = SIZE_MAX;
    size_t run_len   = 0;

    for (size_t i = 0; i < end; i++) {
        uint8_t b = buf[i];
        if ((b >= 0x09 && b <= 0x0d) || (b >= 0x20 && b <= 0x7e)) {
            if (run_start == SIZE_MAX) run_start = i;
            run_len++;
            if (run_len >= TEXT_MIN_RUN) {
                *run_len_out = buf_len - run_start;
                return buf + run_start;
            }
        } else {
            run_start = SIZE_MAX;
            run_len   = 0;
        }
    }
    return NULL;
}

/* ============================================================================
 * Main post-processing loop
 * ============================================================================
 */

bool orphan_post_process(const char *orphan_dir, const char *output_dir, result_t *result) {
    if (!orphan_dir) return false;

    DIR *d = opendir(orphan_dir);
    if (!d) {
        LOG_DEBUG("orphan_post: cannot open %s: %s", orphan_dir, strerror(errno));
        return false;
    }

    /* Count .dat files first so we can show a progress bar. */
    int total = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen > 4 && strcmp(ent->d_name + nlen - 4, ".dat") == 0)
            total++;
    }
    rewinddir(d);

    if (total == 0) { closedir(d); return false; }

    /* Create unrecoverable/ at output root (not inside orphan_dir). */
    const char *unrec_base = (output_dir && output_dir[0]) ? output_dir : orphan_dir;
    char unrec_dir[MAX_PATH_LEN];
    snprintf(unrec_dir, sizeof(unrec_dir), "%s/recovered_unknown_format", unrec_base);
    mkdir(unrec_dir, 0755);
    LOG_EXEC_ONLY("Orphan post-processing: %d file%s", total, total == 1 ? "" : "s");

    int processed      = 0;
    int decompressed   = 0;
    int identified     = 0;
    int unrecoverable  = 0;
    int already_raw    = 0;
    int zero_count     = 0;   /* files deleted — all-zero content (sparse/unallocated blocks) */
    int fail_count     = 0;   /* files that could not be processed at all */

    double start = util_get_time_ms();

    while ((ent = readdir(d)) != NULL) {
        /* Ctrl-C: stop cleanly; already-processed files keep their new names */
        if (g_interrupted) break;

        /* Only process .dat files */
        size_t nlen = strlen(ent->d_name);
        if (nlen <= 4 || strcmp(ent->d_name + nlen - 4, ".dat") != 0)
            continue;

        char src_path[MAX_PATH_LEN];
        snprintf(src_path, sizeof(src_path), "%s/%s", orphan_dir, ent->d_name);

        /* Progress bar */
        util_print_progress("Post-processing", (uint64_t)processed,
                            (uint64_t)total, start);
        processed++;

        /* Unlock file before reading: ExFAT or a prior metadata-restore pass
         * may have applied the original APFS read-only or immutable flag. */
#ifdef __APPLE__
        lchflags(src_path, 0);
#endif
        chmod(src_path, 0644);

        /* Read file */
        FILE *fp = fopen(src_path, "rb");
        if (!fp) {
            char errmsg[320];
            snprintf(errmsg, sizeof(errmsg),
                     "Post-processing: cannot open orphan file — %s",
                     strerror(errno));
            ERR_ADD_WARNING(errmsg, 0, src_path);
            fail_count++;
            continue;
        }
        uint8_t *raw = malloc(ORPHAN_READ_BYTES);
        if (!raw) { fclose(fp); continue; }
        size_t raw_len = fread(raw, 1, ORPHAN_READ_BYTES, fp);
        bool had_read_error = ferror(fp);
        fclose(fp);

        if (raw_len == 0) {
            free(raw);
            if (had_read_error) {
                /* I/O error or truncation — don't delete, preserve in unrec_dir */
                goto move_unrec;
            }
            /* Genuinely empty file — nothing to recover */
            remove(src_path);
            zero_count++;
            continue;
        }

        /* All-zero or all-0xFF (erased flash): not real data, delete.
         * For any file larger than what we read, also sample mid and tail to
         * avoid false positives on files with a zero-padded first 256 KB but
         * real content beyond (e.g. audio files, encrypted disk images). */
        if (is_noise_content(raw, raw_len)) {
            bool confirmed = true;
            struct stat st_noise;
            if (stat(src_path, &st_noise) == 0 &&
                (uint64_t)st_noise.st_size > ORPHAN_READ_BYTES) {
                uint8_t noise_byte = raw[0];
                uint8_t sample[4096];
                FILE *fp2 = fopen(src_path, "rb");
                if (fp2) {
                    /* Sample at 50% and 90% */
                    off_t off_mid  = (off_t)(st_noise.st_size / 2);
                    off_t off_tail = (off_t)(st_noise.st_size - (off_t)sizeof(sample));
                    if (off_tail < 0) off_tail = 0;
                    for (int s = 0; s < 2 && confirmed; s++) {
                        off_t seek_to = (s == 0) ? off_mid : off_tail;
                        if (fseeko(fp2, seek_to, SEEK_SET) == 0) {
                            size_t nr = fread(sample, 1, sizeof(sample), fp2);
                            for (size_t k = 0; k < nr && confirmed; k++)
                                if (sample[k] != noise_byte) confirmed = false;
                        }
                    }
                    fclose(fp2);
                }
            }
            if (confirmed) {
                free(raw);
                remove(src_path);
                zero_count++;
                LOG_DEBUG("orphan_post: deleted noise file %s", ent->d_name);
                continue;
            }
            /* Not confirmed all-noise — fall through and classify normally. */
        }

        /* Parse header */
        orphan_header_t hdr;
        bool has_header = parse_header(raw, raw_len, &hdr);

        const uint8_t *content     = NULL;
        size_t         content_len = 0;
        uint8_t       *decomp_buf  = NULL;

        if (!has_header) {
            /* No compression header — classify the raw bytes directly. */
            content     = raw;
            content_len = raw_len;
            already_raw++;
        } else if (hdr.decomp == NULL) {
            /* Inline uncompressed data */
            content     = hdr.comp_data;
            content_len = hdr.comp_len;
            decompressed++;
        } else {
            /* Decompress */
            size_t out_len = 0;
            if (hdr.uncomp_size > 0 && hdr.uncomp_size <= DECOMP_MAX_BYTES) {
                /* Known uncompressed size: single allocation */
                uint8_t *buf = malloc((size_t)hdr.uncomp_size);
                if (buf) {
                    size_t written = hdr.decomp(hdr.comp_data, hdr.comp_len,
                                                buf, (size_t)hdr.uncomp_size);
                    if (written > 0) {
                        decomp_buf  = buf;
                        out_len     = written;
                    } else {
                        free(buf);
                    }
                }
            } else {
                /* Unknown size: growing buffer */
                decomp_buf = decompress_growing(hdr.comp_data, hdr.comp_len,
                                                hdr.decomp,
                                                hdr.comp_len * DECOMP_HINT_MULT,
                                                &out_len);
            }

            if (!decomp_buf || out_len == 0) {
                free(raw);
                if (decomp_buf) free(decomp_buf);
                goto move_unrec;
            }
            decompressed++;
            content     = decomp_buf;
            content_len = out_len;
        }

        /* All-zero / all-0xFF check on the resolved content (decompressed,
         * inline, or raw).  The earlier pre-header guard only fires when
         * buf[0] is 0x00 or 0xFF; compressed blobs with a valid header — and
         * raw files without any recognised header — both bypass it.  Check
         * unconditionally here so that every code path is covered.
         *
         * For raw (non-compressed) files larger than ORPHAN_READ_BYTES we
         * sample the middle and tail before deleting, matching the Python
         * identify_orphans.py behaviour. */
        if (is_noise_content(content, content_len)) {
            bool confirmed = true;
            if (!has_header) {
                struct stat st_noise;
                if (stat(src_path, &st_noise) == 0 &&
                    (uint64_t)st_noise.st_size > (uint64_t)ORPHAN_READ_BYTES) {
                    uint8_t noise_byte = content[0];
                    uint8_t sample[4096];
                    FILE *fp2 = fopen(src_path, "rb");
                    if (fp2) {
                        off_t off_mid  = (off_t)(st_noise.st_size / 2);
                        off_t off_tail = (off_t)(st_noise.st_size - (off_t)sizeof(sample));
                        if (off_tail < 0) off_tail = 0;
                        for (int s = 0; s < 2 && confirmed; s++) {
                            off_t seek_to = (s == 0) ? off_mid : off_tail;
                            if (fseeko(fp2, seek_to, SEEK_SET) == 0) {
                                size_t nr = fread(sample, 1, sizeof(sample), fp2);
                                for (size_t k = 0; k < nr && confirmed; k++)
                                    if (sample[k] != noise_byte) confirmed = false;
                            }
                        }
                        fclose(fp2);
                    }
                }
            }
            if (confirmed) {
                free(raw);
                if (decomp_buf) free(decomp_buf);
                remove(src_path);
                zero_count++;
                LOG_DEBUG("orphan_post: deleted noise file %s", ent->d_name);
                continue;
            }
            /* Not confirmed all-noise — fall through and classify normally. */
        }

        /* Classify content */
        const char *ext = classify_content(content, content_len);

        /* Sliding-window fallback: scan for the first text run in content */
        if (!ext && content_len > 0) {
            size_t run_len = 0;
            const uint8_t *run = find_text_run(content, content_len,
                                               TEXT_SCAN_BYTES, &run_len);
            if (run) ext = classify_content(run, run_len);
        }

        if (!ext && !has_header) {
            /* Also try scanning raw bytes at typical stream offsets
             * for compressed files that didn't match any header. */
            for (int off = 8; off <= 16; off += 4) {
                if ((size_t)off >= raw_len) break;
                size_t run_len = 0;
                const uint8_t *run = find_text_run(raw + off, raw_len - off,
                                                   TEXT_SCAN_BYTES, &run_len);
                if (run) { ext = classify_content(run, run_len); }
                if (ext) break;
            }
        }

        /*
         * Late-decompression fallback: the sliding window (or direct scan above)
         * found an extension, but parse_header() returned false — meaning byte[0]
         * was outside 8-96 range or bytes[1-3] were non-zero.  Try the most likely
         * case: a simplified blob with a larger-than-expected header offset.
         * We already extended the range to 96 above, but re-check here in case the
         * alignment or zero-byte pattern caused a miss, or the file was passed to us
         * without a recognised header at all.
         *
         * Condition: ext found, no decompressed buffer yet, file starts with a
         * plausible 4-byte LE offset (byte[0] multiple of 4, bytes[1-3] zero) that
         * places comp_data inside the file.
         */
        if (ext && !decomp_buf && !has_header && raw_len >= 8 &&
            raw[1] == 0 && raw[2] == 0 && raw[3] == 0) {
            uint8_t try_off = raw[0];
            if (try_off >= 8 && (try_off % 4) == 0 && (size_t)try_off < raw_len) {
                uint32_t comp_len;
                memcpy(&comp_len, raw + 4, 4);
                /* clamp to file bounds */
                if (comp_len > 0) {
                    if ((size_t)try_off + comp_len > raw_len)
                        comp_len = (uint32_t)(raw_len - try_off);
                    size_t out_len = 0;
                    uint8_t *try_buf = decompress_growing(raw + try_off, comp_len,
                                                          do_lzvn,
                                                          comp_len * DECOMP_HINT_MULT,
                                                          &out_len);
                    if (try_buf && out_len > 0) {
                        /* Reclassify the decompressed content */
                        const char *new_ext = classify_content(try_buf, out_len);
                        if (new_ext) ext = new_ext;
                        decomp_buf  = try_buf;
                        content     = decomp_buf;
                        content_len = out_len;
                        decompressed++;
                        already_raw--;   /* undo the increment from !has_header path */
                    } else {
                        free(try_buf);
                    }
                }
            }
        }

        free(raw);

        if (ext) {
            /* Build new filename: replace .dat with .ext */
            char base[MAX_PATH_LEN];
            snprintf(base, sizeof(base), "%s", ent->d_name);
            base[nlen - 4] = '\0';   /* strip ".dat" */

            char new_path[MAX_PATH_LEN];
            snprintf(new_path, sizeof(new_path), "%s/%s.%s",
                     orphan_dir, base, ext);

            bool write_ok = false;
            if (decomp_buf) {
                /* Write decompressed content to new path */
                FILE *out = fopen(new_path, "wb");
                if (out) {
                    size_t nw = fwrite(decomp_buf, 1, content_len, out);
                    fclose(out);
                    if (nw == content_len) {
                        remove(src_path);
                        write_ok = true;
                    } else {
                        /* Partial write (disk full?) — remove corrupt output */
                        remove(new_path);
                        LOG_WARN("Post-processing: partial write for %s (disk full?)",
                                 ent->d_name);
                    }
                } else {
                    LOG_WARN("Post-processing: cannot write %s — %s",
                             new_path, strerror(errno));
                }
            } else {
                /* Already raw — just rename */
                if (rename(src_path, new_path) == 0) {
                    write_ok = true;
                } else {
                    char errmsg[320];
                    snprintf(errmsg, sizeof(errmsg),
                             "Post-processing: rename failed — %s", strerror(errno));
                    ERR_ADD_WARNING(errmsg, 0, src_path);
                }
            }

            if (write_ok) {
                identified++;
            } else {
                /* Fall back: move to unrec_dir so .dat doesn't linger */
                char unrec_fb[256];
                snprintf(unrec_fb, sizeof(unrec_fb), "%s", ent->d_name);
                size_t fblen = strlen(unrec_fb);
                if (fblen > 4) unrec_fb[fblen - 4] = '\0';
                char unrec_fb_path[MAX_PATH_LEN];
                snprintf(unrec_fb_path, sizeof(unrec_fb_path),
                         "%s/%s", unrec_dir, unrec_fb);
                if (rename(src_path, unrec_fb_path) != 0) {
                    char fb_errmsg[320];
                    snprintf(fb_errmsg, sizeof(fb_errmsg),
                             "Post-processing: fallback rename to unrec also failed — %s",
                             strerror(errno));
                    ERR_ADD_WARNING(fb_errmsg, 0, src_path);
                    fail_count++;
                }
                unrecoverable++;
            }
        } else {
            /* Move to unrecoverable/ — strip .dat so the file has no extension
             * and won't be accidentally opened by media players. */
            char unrec_name[256];
            snprintf(unrec_name, sizeof(unrec_name), "%s", ent->d_name);
            size_t ulen = strlen(unrec_name);
            if (ulen > 4 && strcmp(unrec_name + ulen - 4, ".dat") == 0)
                unrec_name[ulen - 4] = '\0';

            if (decomp_buf) {
                /* Even though we couldn't classify, write the decompressed form
                 * into unrecoverable/ — it's still better than the compressed blob. */
                char unrec_path[MAX_PATH_LEN];
                snprintf(unrec_path, sizeof(unrec_path), "%s/%s",
                         unrec_dir, unrec_name);
                FILE *out = fopen(unrec_path, "wb");
                if (out) {
                    size_t nw = fwrite(content, 1, content_len, out);
                    int fc = fclose(out);
                    if (nw == content_len && fc == 0) {
                        remove(src_path);
                    } else {
                        remove(unrec_path);
                        rename(src_path, unrec_path);
                    }
                } else {
                    rename(src_path, unrec_path);
                }
            } else {
                char unrec_path[MAX_PATH_LEN];
                snprintf(unrec_path, sizeof(unrec_path), "%s/%s",
                         unrec_dir, unrec_name);
                rename(src_path, unrec_path);
            }
            unrecoverable++;
        }

        if (decomp_buf) free(decomp_buf);
        continue;

move_unrec:
        /* Jump here when we can't even read or parse the file */
        {
            char unrec_name2[256];
            snprintf(unrec_name2, sizeof(unrec_name2), "%s", ent->d_name);
            size_t u2len = strlen(unrec_name2);
            if (u2len > 4 && strcmp(unrec_name2 + u2len - 4, ".dat") == 0)
                unrec_name2[u2len - 4] = '\0';
            char unrec_path[MAX_PATH_LEN];
            snprintf(unrec_path, sizeof(unrec_path), "%s/%s",
                     unrec_dir, unrec_name2);
            rename(src_path, unrec_path);
            unrecoverable++;
        }
    }

    closedir(d);

    util_print_progress("Post-processing", (uint64_t)total, (uint64_t)total, start);
    util_progress_newline();

    /* Summary — exec log only; terminal gets a single LOG_OK from main() */
    {
        char b1[32], b2[32], b3[32], b4[32], b5[32];
        LOG_EXEC_ONLY("Orphans decompressed : %s",
                      util_format_num((uint64_t)decompressed, b1));
        LOG_EXEC_ONLY("Identified (renamed) : %s",
                      util_format_num((uint64_t)identified, b2));
        LOG_EXEC_ONLY("Already raw          : %s",
                      util_format_num((uint64_t)already_raw, b3));
        LOG_EXEC_ONLY("Unknown format       : %s  → %s/recovered_unknown_format/",
                      util_format_num((uint64_t)unrecoverable, b4), unrec_base);
        if (zero_count > 0)
            LOG_EXEC_ONLY("Deleted (all-zero)   : %s",
                          util_format_num((uint64_t)zero_count, b5));
    }

    if (result) {
        result->orphans_decompressed  = (uint32_t)decompressed;
        result->orphans_identified    = (uint32_t)identified;
        result->orphans_unrecoverable = (uint32_t)unrecoverable;
        result->orphans_zeroed        = (uint32_t)zero_count;
        result->orphan_fail_count     = fail_count;
    }
    return true;
}

/* Public wrapper around the static classify_content() for unit testing. */
const char *orphan_classify_content(const uint8_t *buf, size_t len) {
    return classify_content(buf, len);
}
