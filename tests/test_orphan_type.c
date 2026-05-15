/*
 * test_orphan_type.c — unit tests for orphan_classify_content().
 *
 * Feeds known magic byte sequences and text snippets to the classifier and
 * verifies the returned extension.  Protects the 40+ magic table entries and
 * all text-pattern rules against regressions.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "orphan_post.h"

static int s_run    = 0;
static int s_failed = 0;

static void check(int cond, const char *name) {
    s_run++;
    if (cond) {
        printf("  PASS  %s\n", name);
    } else {
        printf("  FAIL  %s\n", name);
        s_failed++;
    }
}

static void check_ext(const uint8_t *buf, size_t len,
                       const char *expected, const char *name) {
    const char *got = orphan_classify_content(buf, len);
    int ok;
    if (expected == NULL) {
        ok = (got == NULL);
    } else {
        ok = (got != NULL && strcmp(got, expected) == 0);
    }
    if (!ok) {
        printf("  FAIL  %s (expected=%s got=%s)\n",
               name,
               expected ? expected : "(null)",
               got      ? got      : "(null)");
        s_run++;
        s_failed++;
    } else {
        check(1, name);
    }
}

/* ============================================================================
 * Binary magic tests
 * ============================================================================
 */

static void test_binary_magic(void) {
    printf("\n--- Binary magic ---\n");

    /* JPEG */
    {
        uint8_t b[] = {0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46};
        check_ext(b, sizeof(b), "jpg", "JPEG SOI marker");
    }

    /* PNG */
    {
        uint8_t b[] = {0x89,'P','N','G','\r','\n',0x1a,'\n', 0,0,0,13};
        check_ext(b, sizeof(b), "png", "PNG signature");
    }

    /* GIF87a */
    {
        uint8_t b[] = "GIF87a\x00";
        check_ext(b, 6, "gif", "GIF87a");
    }

    /* GIF89a */
    {
        uint8_t b[] = "GIF89a\x00";
        check_ext(b, 6, "gif", "GIF89a");
    }

    /* PDF */
    {
        uint8_t b[] = "%PDF-1.5\n";
        check_ext(b, sizeof(b) - 1, "pdf", "PDF header");
    }

    /* ZIP (local file header) */
    {
        uint8_t b[] = {'P','K',0x03,0x04, 0x14,0x00,0x00,0x00};
        check_ext(b, sizeof(b), "zip", "ZIP local header PK\\x03\\x04");
    }

    /* ZIP (end of central dir) */
    {
        uint8_t b[] = {'P','K',0x05,0x06, 0x00,0x00,0x00,0x00};
        check_ext(b, sizeof(b), "zip", "ZIP end-of-central-dir PK\\x05\\x06");
    }

    /* gzip */
    {
        uint8_t b[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};
        check_ext(b, sizeof(b), "gz", "gzip magic");
    }

    /* bzip2 */
    {
        uint8_t b[] = "BZh9";
        check_ext(b, 4, "bz2", "bzip2 magic");
    }

    /* xz */
    {
        uint8_t b[] = {0xfd,'7','z','X','Z',0x00};
        check_ext(b, 6, "xz", "xz magic");
    }

    /* 7-zip */
    {
        uint8_t b[] = {'7','z',0xbc,0xaf,0x27,0x1c};
        check_ext(b, 6, "7z", "7-zip magic");
    }

    /* OLE compound doc (Word/Excel/etc.) */
    {
        uint8_t b[] = {0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1};
        check_ext(b, 8, "doc", "OLE compound doc magic");
    }

    /* SQLite */
    {
        uint8_t b[] = "SQLite format 3\x00";
        check_ext(b, 16, "sqlite", "SQLite header");
    }

    /* bplist00 */
    {
        uint8_t b[] = "bplist00\x00";
        check_ext(b, 8, "plist", "binary plist bplist00");
    }

    /* Mach-O fat binary */
    {
        uint8_t b[] = {0xca,0xfe,0xba,0xbe, 0x00,0x00,0x00,0x02};
        check_ext(b, 8, "macho", "Mach-O fat binary (cafebabe)");
    }

    /* Mach-O 32-bit LE */
    {
        uint8_t b[] = {0xce,0xfa,0xed,0xfe, 0x07,0x00,0x00,0x01};
        check_ext(b, 8, "macho", "Mach-O 32-bit LE (cefaedfe)");
    }

    /* Mach-O 64-bit LE */
    {
        uint8_t b[] = {0xcf,0xfa,0xed,0xfe, 0x0c,0x00,0x00,0x01};
        check_ext(b, 8, "macho", "Mach-O 64-bit LE (cffaedfe)");
    }

    /* ELF */
    {
        uint8_t b[] = {0x7f,'E','L','F', 0x02,0x01,0x01,0x00};
        check_ext(b, 8, "elf", "ELF magic");
    }

    /* MP3 ID3 */
    {
        uint8_t b[] = {'I','D','3', 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        check_ext(b, 10, "mp3", "MP3 ID3 tag");
    }

    /* MP3 sync frame (0xfffb) */
    {
        uint8_t b[] = {0xff, 0xfb, 0x90, 0x00};
        check_ext(b, 4, "mp3", "MP3 sync frame 0xfffb");
    }

    /* Matroska/WebM */
    {
        uint8_t b[] = {0x1a,0x45,0xdf,0xa3, 0x01,0x00,0x00,0x00};
        check_ext(b, 8, "mkv", "Matroska EBML magic");
    }

    /* TIFF little-endian */
    {
        uint8_t b[] = {'I','I',0x2a,0x00};
        check_ext(b, 4, "tiff", "TIFF LE magic");
    }

    /* TIFF big-endian */
    {
        uint8_t b[] = {'M','M',0x00,0x2a};
        check_ext(b, 4, "tiff", "TIFF BE magic");
    }

    /* BMP */
    {
        uint8_t b[] = {'B','M', 0x36,0x00,0x00,0x00};
        check_ext(b, 6, "bmp", "BMP magic");
    }

    /* ICO */
    {
        uint8_t b[] = {0x00,0x00,0x01,0x00, 0x01,0x00};
        check_ext(b, 6, "ico", "ICO magic");
    }

    /* PSD */
    {
        uint8_t b[] = {'8','B','P','S', 0x00,0x01};
        check_ext(b, 6, "psd", "PSD magic");
    }

    /* DMG (koly) */
    {
        uint8_t b[] = "koly\x00\x00\x00\x04";
        check_ext(b, 8, "dmg", "DMG koly magic");
    }

    /* RTF */
    {
        uint8_t b[] = "{\\rtf1\\ansi";
        check_ext(b, sizeof(b) - 1, "rtf", "RTF magic");
    }

    /* OGG */
    {
        uint8_t b[] = "OggS\x00\x02\x00\x00";
        check_ext(b, 8, "ogg", "Ogg magic");
    }

    /* FLAC */
    {
        uint8_t b[] = "fLaC\x00\x00\x00\x22";
        check_ext(b, 8, "flac", "FLAC magic");
    }

    /* TrueType font */
    {
        uint8_t b[] = {0x00,0x01,0x00,0x00, 0x00,0x12};
        check_ext(b, 6, "ttf", "TrueType magic");
    }

    /* OpenType font */
    {
        uint8_t b[] = "OTTO\x00\x09";
        check_ext(b, 6, "otf", "OpenType OTTO magic");
    }

    /* WOFF */
    {
        uint8_t b[] = "wOFF\x00\x01\x00\x00";
        check_ext(b, 8, "woff", "WOFF magic");
    }

    /* WOFF2 */
    {
        uint8_t b[] = "wOF2\x00\x01\x00\x00";
        check_ext(b, 8, "woff2", "WOFF2 magic");
    }

    /* UTF-16 LE BOM → txt (no pattern match) */
    {
        uint8_t b[] = {0xff, 0xfe, 'H',0, 'i',0, '\n',0};
        check_ext(b, 8, "txt", "UTF-16 LE BOM → txt");
    }
}

/* ============================================================================
 * RIFF sub-type tests
 * ============================================================================
 */

static void test_riff_subtypes(void) {
    printf("\n--- RIFF sub-types ---\n");

    /* WAV */
    {
        uint8_t b[12];
        memcpy(b + 0, "RIFF", 4);
        memcpy(b + 4, "\x24\x00\x00\x00", 4);
        memcpy(b + 8, "WAVE", 4);
        check_ext(b, 12, "wav", "RIFF/WAVE");
    }

    /* AVI */
    {
        uint8_t b[12];
        memcpy(b + 0, "RIFF", 4);
        memcpy(b + 4, "\x00\x00\x00\x00", 4);
        memcpy(b + 8, "AVI ", 4);
        check_ext(b, 12, "avi", "RIFF/AVI");
    }

    /* WEBP */
    {
        uint8_t b[12];
        memcpy(b + 0, "RIFF", 4);
        memcpy(b + 4, "\x00\x00\x00\x00", 4);
        memcpy(b + 8, "WEBP", 4);
        check_ext(b, 12, "webp", "RIFF/WEBP");
    }

    /* Unknown RIFF sub-type */
    {
        uint8_t b[12];
        memcpy(b + 0, "RIFF", 4);
        memcpy(b + 4, "\x00\x00\x00\x00", 4);
        memcpy(b + 8, "UNKN", 4);
        check_ext(b, 12, "riff", "RIFF/unknown stays riff");
    }
}

/* ============================================================================
 * ftyp sub-type tests
 * ============================================================================
 */

static void test_ftyp_subtypes(void) {
    printf("\n--- ftyp sub-types ---\n");

    /* MP4 (isom) */
    {
        uint8_t b[12];
        memcpy(b + 0, "\x00\x00\x00\x18", 4);   /* box size */
        memcpy(b + 4, "ftyp", 4);
        memcpy(b + 8, "isom", 4);
        check_ext(b, 12, "mp4", "ftyp/isom → mp4");
    }

    /* MOV (qt) */
    {
        uint8_t b[12];
        memcpy(b + 0, "\x00\x00\x00\x14", 4);
        memcpy(b + 4, "ftyp", 4);
        memcpy(b + 8, "qt  ", 4);
        check_ext(b, 12, "mov", "ftyp/qt → mov");
    }

    /* HEIC */
    {
        uint8_t b[12];
        memcpy(b + 0, "\x00\x00\x00\x18", 4);
        memcpy(b + 4, "ftyp", 4);
        memcpy(b + 8, "heic", 4);
        check_ext(b, 12, "heic", "ftyp/heic → heic");
    }

    /* M4A */
    {
        uint8_t b[12];
        memcpy(b + 0, "\x00\x00\x00\x18", 4);
        memcpy(b + 4, "ftyp", 4);
        memcpy(b + 8, "M4A ", 4);
        check_ext(b, 12, "m4a", "ftyp/M4A → m4a");
    }

    /* M4V */
    {
        uint8_t b[12];
        memcpy(b + 0, "\x00\x00\x00\x18", 4);
        memcpy(b + 4, "ftyp", 4);
        memcpy(b + 8, "M4V ", 4);
        check_ext(b, 12, "m4v", "ftyp/M4V → m4v");
    }
}

/* ============================================================================
 * Text pattern tests
 * ============================================================================
 */

static void test_text_patterns(void) {
    printf("\n--- Text patterns ---\n");

    check_ext((const uint8_t *)"<!DOCTYPE html><html>", 21, "html", "HTML doctype");
    check_ext((const uint8_t *)"<html lang=\"en\">",     16, "html", "HTML element");
    check_ext((const uint8_t *)"<?xml version=\"1.0\"?>", 21, "xml",  "XML declaration");
    check_ext((const uint8_t *)"<plist version=\"1.0\">", 21, "plist","plist element");
    check_ext((const uint8_t *)"%!PS-Adobe-3.0\n",       15, "ps",   "PostScript header");
    check_ext((const uint8_t *)"#!/bin/bash\necho hi",   19, "sh",   "bash shebang");
    check_ext((const uint8_t *)"#!/bin/sh\necho hi",     18, "sh",   "/bin/sh shebang");
    check_ext((const uint8_t *)"#! /bin/csh -f\n",       15, "sh",   "space-after-hash shebang");
    check_ext((const uint8_t *)"#!/usr/bin/env python3\n",22, "py",  "python3 env shebang");
    check_ext((const uint8_t *)"#!/usr/bin/perl\nuse strict;", 27, "pl", "perl shebang");
    check_ext((const uint8_t *)"#!/usr/bin/ruby\nputs 1", 21, "rb",  "ruby shebang");
    check_ext((const uint8_t *)"{\"key\": \"value\"}\n",   17, "json","JSON object");
    check_ext((const uint8_t *)"import Foundation\n",    18, "swift","Swift import");
    check_ext((const uint8_t *)"import java.util.List;\n",22, "java","Java import");
    check_ext((const uint8_t *)"using System;\nnamespace X {", 27, "cs", "C# using");
    check_ext((const uint8_t *)"SELECT * FROM users;\n", 21, "sql", "SQL SELECT");
    check_ext((const uint8_t *)"-----BEGIN CERTIFICATE-----\n", 27, "pem","PEM cert header");
    check_ext((const uint8_t *)"MIME-Version: 1.0\nFrom: a@b.com\n", 32, "eml","email MIME header");
}

/* ============================================================================
 * Edge cases
 * ============================================================================
 */

static void test_edge_cases(void) {
    printf("\n--- Edge cases ---\n");

    /* NULL / empty → NULL */
    check_ext(NULL, 0, NULL, "empty buffer returns NULL");

    /* All zeros → NULL (not text, not magic) */
    {
        uint8_t b[64] = {0};
        check_ext(b, 64, NULL, "all-zero buffer returns NULL");
    }

    /* Plain ASCII text → txt */
    {
        const char *s = "This is plain ASCII text without any magic bytes.\n";
        check_ext((const uint8_t *)s, strlen(s), "txt", "plain ASCII text → txt");
    }

    /* Buffer shorter than magic → no crash */
    {
        uint8_t b[] = {0x89};
        check_ext(b, 1, NULL, "1-byte PNG prefix does not crash");
    }

    /* Unknown binary → NULL */
    {
        uint8_t b[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
        check_ext(b, 8, NULL, "random binary returns NULL");
    }
}

/* ============================================================================
 * main
 * ============================================================================
 */

int main(void) {
    printf("test_orphan_type\n");

    test_binary_magic();
    test_riff_subtypes();
    test_ftyp_subtypes();
    test_text_patterns();
    test_edge_cases();

    printf("\n%d/%d passed", s_run - s_failed, s_run);
    if (s_failed == 0)
        printf("  OK\n");
    else
        printf("  FAILED\n");

    return s_failed > 0 ? 1 : 0;
}
