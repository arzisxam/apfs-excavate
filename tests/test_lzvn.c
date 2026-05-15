/*
 * test_lzvn.c — unit tests for cmp_lzvn().
 *
 * Uses hand-crafted LZVN byte streams derived directly from the opcode
 * table in compress.c.  No fixture file needed.
 *
 * Opcode reference (from compress.c):
 *   0x06              — end of stream
 *   0xE0–0xEF         — small literal: len = (cmd & 0x0F) + 1, then len bytes
 *   0xF0              — large literal: len = next_byte + 16, then len bytes
 *   (cmd & 0xF0)<=0x50 — match (small dist): match_len = ((cmd>>4)&7)+3,
 *                         distance = (cmd&0x0F)<<8 | next_byte
 *   (cmd & 0xC0)==0x80 — match (medium dist): match_len = (cmd&0x0F)+3
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "compress.h"

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

/* ============================================================================
 * Test 1: End-of-stream immediately — zero bytes out
 * ============================================================================
 */
static void test_empty_stream(void) {
    static const uint8_t src[] = {0x06};
    uint8_t dst[8];
    memset(dst, 0xFF, sizeof(dst));

    size_t n = cmp_lzvn(src, sizeof(src), dst, sizeof(dst));
    check(n == 0, "empty stream: output length is 0");
}

/* ============================================================================
 * Test 2: Small literal (opcode 0xE0–0xEF)
 *
 *   Stream: E4 48 45 4C 4C 4F 06
 *     0xE4 → len = (0x04)+1 = 5 literal bytes follow
 *     "HELLO"
 *     0x06 → EOS
 *   Expected: "HELLO" (5 bytes)
 * ============================================================================
 */
static void test_small_literal(void) {
    static const uint8_t src[]      = {0xE4, 'H','E','L','L','O', 0x06};
    static const char    expected[] = "HELLO";
    uint8_t dst[32] = {0};

    size_t n = cmp_lzvn(src, sizeof(src), dst, sizeof(dst));
    check(n == 5,                          "small literal: length == 5");
    check(memcmp(dst, expected, 5) == 0,   "small literal: bytes match");
}

/* ============================================================================
 * Test 3: Large literal (opcode 0xF0)
 *
 *   Stream: F0 <extra> <bytes…> 06
 *     0xF0 → len = extra + 16
 *     extra=2 → 18 literal bytes (all 0xAB)
 *     0x06 → EOS
 *   Expected: 18 × 0xAB
 * ============================================================================
 */
static void test_large_literal(void) {
    uint8_t src[22] = {0};
    src[0]  = 0xF0;
    src[1]  = 2;             /* extra = 2 → len = 18 */
    memset(src + 2, 0xAB, 18);
    src[20] = 0x06;

    uint8_t expected[18];
    memset(expected, 0xAB, 18);

    uint8_t dst[64] = {0};
    size_t n = cmp_lzvn(src, 21, dst, sizeof(dst));
    check(n == 18,                         "large literal: length == 18");
    check(memcmp(dst, expected, 18) == 0,  "large literal: bytes match");
}

/* ============================================================================
 * Test 4: Literal + small-distance back-reference
 *
 *   Stream: E5 41 42 43 41 42 43 00 03 06
 *     0xE5 → 6 literal bytes "ABCABC"
 *     0x00 0x03 → match: len=3, distance=3 → copies "ABC" from 3 back
 *     0x06 → EOS
 *   Expected: "ABCABCABC" (9 bytes)
 *
 *   Match opcode breakdown (cmd=0x00, next=0x03):
 *     (0x00 & 0xF0) = 0x00 ≤ 0x50 → small-distance match branch
 *     match_len = ((0x00 >> 4) & 0x07) + 3 = 0 + 3 = 3
 *     distance  = (0x00 & 0x0F) << 8 | 0x03 = 3
 * ============================================================================
 */
static void test_literal_plus_backreference(void) {
    static const uint8_t src[]      = {0xE5, 'A','B','C','A','B','C', 0x00, 0x03, 0x06};
    static const char    expected[] = "ABCABCABC";
    uint8_t dst[32] = {0};

    size_t n = cmp_lzvn(src, sizeof(src), dst, sizeof(dst));
    check(n == 9,                          "literal+backref: length == 9");
    check(memcmp(dst, expected, 9) == 0,   "literal+backref: bytes match");
}

/* ============================================================================
 * Test 5: Longer run with repeated back-references
 *
 *   Builds "XYZXYZXYZXYZ" (12 bytes):
 *     E2 58 59 5A  — literal "XYZ" (3 bytes)
 *     00 03        — match len=3, dist=3  → "XYZ"  (output so far: 6)
 *     00 03        — match len=3, dist=3  → "XYZ"  (output so far: 9)
 *     00 03        — match len=3, dist=3  → "XYZ"  (output so far: 12)
 *     06           — EOS
 * ============================================================================
 */
static void test_repeated_backreferences(void) {
    static const uint8_t src[] = {
        0xE2, 'X','Y','Z',
        0x00, 0x03,
        0x00, 0x03,
        0x00, 0x03,
        0x06
    };
    static const char expected[] = "XYZXYZXYZXYZ";
    uint8_t dst[32] = {0};

    size_t n = cmp_lzvn(src, sizeof(src), dst, sizeof(dst));
    check(n == 12,                          "repeated backref: length == 12");
    check(memcmp(dst, expected, 12) == 0,   "repeated backref: bytes match");
}

/* ============================================================================
 * Test 6: dst_len limit — must not write past the output buffer
 *
 *   Feed a 5-byte literal but give only 3 bytes of output space.
 *   Must return ≤ 3 and not corrupt memory past dst[2].
 * ============================================================================
 */
static void test_dst_limit(void) {
    static const uint8_t src[] = {0xE4, 'H','E','L','L','O', 0x06};
    uint8_t dst[8];
    memset(dst, 0xCC, sizeof(dst));   /* sentinel fill */

    size_t n = cmp_lzvn(src, sizeof(src), dst, 3);
    check(n <= 3,                  "dst limit: never exceeds dst_len");
    /* Bytes past the limit must be untouched (still 0xCC). */
    check(dst[3] == 0xCC,          "dst limit: no write past dst_len");
}

/* ============================================================================
 * Test 7: Truncated source — decoder must not read past src_len
 *
 *   Provide a literal header promising 5 bytes but supply only 2.
 *   The decoder should stop and return whatever it managed.
 * ============================================================================
 */
static void test_truncated_source(void) {
    /* 0xE4 says 5 bytes follow, but we only give 2 bytes of data + no EOS. */
    static const uint8_t src[] = {0xE4, 'H', 'E'};
    uint8_t dst[32] = {0};

    /* Must not crash or read out of bounds. Output is whatever fit. */
    size_t n = cmp_lzvn(src, sizeof(src), dst, sizeof(dst));
    check(n <= 2, "truncated source: does not over-read");
}

/* ============================================================================
 * main
 * ============================================================================
 */

int main(void) {
    printf("test_lzvn\n");
    printf("---------\n");
    test_empty_stream();
    test_small_literal();
    test_large_literal();
    test_literal_plus_backreference();
    test_repeated_backreferences();
    test_dst_limit();
    test_truncated_source();
    printf("\n%d/%d passed\n", s_run - s_failed, s_run);
    return s_failed ? 1 : 0;
}
