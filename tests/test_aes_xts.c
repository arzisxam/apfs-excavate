/*
 * test_aes_xts.c — unit tests for crypto_aes_xts_init() and
 *                  crypto_aes_xts_decrypt().
 *
 * Strategy: use OpenSSL EVP_aes_128_xts as the reference implementation.
 * Encrypt known plaintext with OpenSSL, decrypt with our code, compare.
 * This proves our XTS construction matches the standard without requiring
 * pre-computed hardcoded vectors.
 *
 * Also tests:
 *   - ctx.initialized flag
 *   - sector isolation (different sector → different ciphertext)
 *   - determinism (same inputs → same output)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/evp.h>

#include "crypto.h"
#include "apfs_types.h"

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
 * OpenSSL reference encrypt
 *
 * key1 and key2 are each 16 bytes (AES-128-XTS uses two 128-bit sub-keys).
 * sector_no is stored as a 64-bit little-endian value in a 128-bit IV field.
 * len must be a multiple of 16.
 * ============================================================================
 */
static bool openssl_xts_encrypt(const uint8_t *key1, const uint8_t *key2,
                                 uint64_t sector_no,
                                 const uint8_t *plaintext, size_t len,
                                 uint8_t *ciphertext_out) {
    /* OpenSSL EVP_aes_128_xts expects key = key1 || key2 (32 bytes). */
    uint8_t combined[32];
    memcpy(combined,      key1, 16);
    memcpy(combined + 16, key2, 16);

    /* IV = 128-bit little-endian sector number. */
    uint8_t iv[16] = {0};
    memcpy(iv, &sector_no, sizeof(sector_no));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    EVP_CIPHER_CTX_set_padding(ctx, 0);  /* XTS does not use block padding */

    int outl = 0, final_outl = 0;
    bool ok =
        EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, combined, iv) == 1 &&
        EVP_EncryptUpdate(ctx, ciphertext_out, &outl, plaintext, (int)len) == 1 &&
        EVP_EncryptFinal_ex(ctx, ciphertext_out + outl, &final_outl) == 1;

    EVP_CIPHER_CTX_free(ctx);
    return ok && (size_t)(outl + final_outl) == len;
}

/* ============================================================================
 * Test 1: ctx.initialized flag
 * ============================================================================
 */
static void test_init_flag(void) {
    aes_xts_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    check(!ctx.initialized, "init flag: false before crypto_aes_xts_init");

    uint8_t k[16] = {0};
    crypto_aes_xts_init(&ctx, k, k);
    check(ctx.initialized,  "init flag: true after  crypto_aes_xts_init");
}

/* ============================================================================
 * Test 2: Zero plaintext with distinct keys, sector 0
 *
 * Plaintext is all zeros; keys are distinct (OpenSSL 3.x rejects XTS when
 * key1 == key2 as a weak-key guard).  Verifies the basic XTS pipeline.
 * ============================================================================
 */
static void test_zero_plaintext(void) {
    /* key1 != key2 — required by OpenSSL 3.x XTS key validation */
    uint8_t key1[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t key2[16] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t plaintext[32] = {0};
    uint8_t ciphertext[32];
    uint8_t decrypted[32];

    bool enc_ok = openssl_xts_encrypt(key1, key2, 0,
                                       plaintext, 32, ciphertext);
    check(enc_ok, "zero-plaintext: OpenSSL encrypt succeeded");

    uint8_t zeros[32] = {0};
    check(memcmp(ciphertext, zeros, 32) != 0,
          "zero-plaintext: ciphertext differs from plaintext");

    aes_xts_ctx_t ctx;
    crypto_aes_xts_init(&ctx, key1, key2);
    crypto_aes_xts_decrypt_with_sector_offset(&ctx, ciphertext, decrypted,
                                               32, 0, 0);
    check(memcmp(decrypted, plaintext, 32) == 0,
          "zero-plaintext: our decrypt matches original plaintext");
}

/* ============================================================================
 * Test 3: Non-trivial key + ascending plaintext pattern, sector 7
 *
 * Exercises the real key schedule on a non-trivial input.
 * ============================================================================
 */
static void test_known_key_ascending_pattern(void) {
    uint8_t key1[16] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
                        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
    uint8_t key2[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t plaintext[32];
    for (int i = 0; i < 32; i++) plaintext[i] = (uint8_t)i;

    uint8_t ciphertext[32];
    uint8_t decrypted[32];

    bool enc_ok = openssl_xts_encrypt(key1, key2, 7, plaintext, 32, ciphertext);
    check(enc_ok, "known-key: OpenSSL encrypt succeeded");
    check(memcmp(ciphertext, plaintext, 32) != 0,
          "known-key: ciphertext differs from plaintext");

    aes_xts_ctx_t ctx;
    crypto_aes_xts_init(&ctx, key1, key2);
    crypto_aes_xts_decrypt_with_sector_offset(&ctx, ciphertext, decrypted,
                                               32, 7, 0);
    check(memcmp(decrypted, plaintext, 32) == 0,
          "known-key: our decrypt matches original plaintext");
}

/* ============================================================================
 * Test 4: Sector isolation — same key+plaintext, different sector → different ct
 *
 * XTS must produce distinct ciphertext per sector (tweak isolation).
 * Both sectors must still decrypt correctly.
 * ============================================================================
 */
static void test_sector_isolation(void) {
    uint8_t key1[16] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
                        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99};
    uint8_t key2[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
    uint8_t plaintext[32];
    memset(plaintext, 0x55, sizeof(plaintext));

    uint8_t ct0[32], ct1[32];
    openssl_xts_encrypt(key1, key2, 0, plaintext, 32, ct0);
    openssl_xts_encrypt(key1, key2, 1, plaintext, 32, ct1);

    check(memcmp(ct0, ct1, 32) != 0,
          "sector isolation: sector 0 and 1 produce different ciphertext");

    aes_xts_ctx_t ctx;
    crypto_aes_xts_init(&ctx, key1, key2);

    uint8_t dec0[32], dec1[32];
    crypto_aes_xts_decrypt_with_sector_offset(&ctx, ct0, dec0, 32, 0, 0);
    crypto_aes_xts_decrypt_with_sector_offset(&ctx, ct1, dec1, 32, 1, 0);
    check(memcmp(dec0, plaintext, 32) == 0,
          "sector isolation: sector 0 round-trips correctly");
    check(memcmp(dec1, plaintext, 32) == 0,
          "sector isolation: sector 1 round-trips correctly");
}

/* ============================================================================
 * Test 5: Key sensitivity — single-bit key difference → different ciphertext
 * ============================================================================
 */
static void test_key_sensitivity(void) {
    uint8_t key1_a[16] = {0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
                          0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42};
    uint8_t key1_b[16] = {0x43,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
                          0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42};
    uint8_t key2[16] = {0};
    uint8_t plaintext[32];
    memset(plaintext, 0xAB, sizeof(plaintext));

    uint8_t ct_a[32], ct_b[32];
    openssl_xts_encrypt(key1_a, key2, 0, plaintext, 32, ct_a);
    openssl_xts_encrypt(key1_b, key2, 0, plaintext, 32, ct_b);
    check(memcmp(ct_a, ct_b, 32) != 0,
          "key sensitivity: 1-bit key difference changes ciphertext");

    /* Decrypting ct_a with key_a must give back plaintext; key_b must not. */
    aes_xts_ctx_t ctx_a, ctx_b;
    crypto_aes_xts_init(&ctx_a, key1_a, key2);
    crypto_aes_xts_init(&ctx_b, key1_b, key2);

    uint8_t dec_correct[32], dec_wrong[32];
    crypto_aes_xts_decrypt_with_sector_offset(&ctx_a, ct_a, dec_correct, 32, 0, 0);
    crypto_aes_xts_decrypt_with_sector_offset(&ctx_b, ct_a, dec_wrong,   32, 0, 0);
    check(memcmp(dec_correct, plaintext, 32) == 0,
          "key sensitivity: correct key decrypts successfully");
    check(memcmp(dec_wrong, plaintext, 32) != 0,
          "key sensitivity: wrong key does not recover plaintext");
}

/* ============================================================================
 * Test 6: Determinism — same inputs always produce same output
 * ============================================================================
 */
static void test_determinism(void) {
    uint8_t key1[16] = {0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
                        0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x00};
    uint8_t key2[16] = {0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,
                        0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};
    uint8_t plaintext[32];
    memset(plaintext, 0x7F, sizeof(plaintext));

    uint8_t ct1[32], ct2[32];
    openssl_xts_encrypt(key1, key2, 42, plaintext, 32, ct1);
    openssl_xts_encrypt(key1, key2, 42, plaintext, 32, ct2);
    check(memcmp(ct1, ct2, 32) == 0, "determinism: identical inputs → identical output");

    aes_xts_ctx_t ctx;
    crypto_aes_xts_init(&ctx, key1, key2);
    uint8_t dec1[32], dec2[32];
    crypto_aes_xts_decrypt_with_sector_offset(&ctx, ct1, dec1, 32, 42, 0);
    crypto_aes_xts_decrypt_with_sector_offset(&ctx, ct2, dec2, 32, 42, 0);
    check(memcmp(dec1, dec2, 32) == 0, "determinism: our decrypt is also deterministic");
}

/* ============================================================================
 * main
 * ============================================================================
 */

int main(void) {
    printf("test_aes_xts\n");
    printf("------------\n");
    test_init_flag();
    test_zero_plaintext();
    test_known_key_ascending_pattern();
    test_sector_isolation();
    test_key_sensitivity();
    test_determinism();
    printf("\n%d/%d passed\n", s_run - s_failed, s_run);
    return s_failed ? 1 : 0;
}
