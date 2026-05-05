/*
 * crypto.c — AES-XTS, PBKDF2, RFC-3394 key wrap, keybag parsing, VEK pipeline.
 */

#define _GNU_SOURCE
#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include "apfs_globals.h"
#include "compat.h"
#include "log.h"

/* ============================================================================
 * Low-level AES block operations
 * ============================================================================
 */


static void multiply_tweak(uint8_t *tweak) {
    int carry = 0;
    for (int i = 0; i < 16; i++) {
        int new_carry  = (tweak[i] >> 7) & 1;
        tweak[i]       = ((tweak[i] << 1) | carry) & 0xFF;
        carry          = new_carry;
    }
    if (carry) tweak[0] ^= 0x87;
}

/* ============================================================================
 * AES-XTS public API
 * ============================================================================
 */

void crypto_aes_xts_init(aes_xts_ctx_t *ctx,
                          const uint8_t *key1, const uint8_t *key2) {
    memcpy(ctx->key1, key1, 16);
    memcpy(ctx->key2, key2, 16);
    ctx->initialized = true;
}

bool crypto_aes_xts_decrypt_with_sector_offset(const aes_xts_ctx_t *ctx,
                                                const uint8_t *ciphertext,
                                                uint8_t *plaintext,
                                                size_t len,
                                                uint64_t base_sector_no,
                                                int64_t sector_offset) {
    if (len % 16 != 0) return false;

    /* Expand key schedules once per call instead of once per block. */
    AES_KEY enc_sched, dec_sched;
    AES_set_encrypt_key(ctx->key2, 128, &enc_sched);
    AES_set_decrypt_key(ctx->key1, 128, &dec_sched);

    int     sector_size = 512;
    /* #25: avoid signed overflow; clamp result to [0, INT64_MAX]. */
    int64_t sector_no;
    if (base_sector_no > (uint64_t)INT64_MAX) {
        sector_no = INT64_MAX;
    } else {
        int64_t base = (int64_t)base_sector_no;
        if (sector_offset > 0 && base > INT64_MAX - sector_offset)
            sector_no = INT64_MAX;
        else if (sector_offset < 0 && base < INT64_MIN - sector_offset)
            sector_no = 0;
        else
            sector_no = base + sector_offset;
    }
    /* #36: negative sector_no produces wrong XTS tweak — signal failure. */
    if (sector_no < 0) return false;

    for (size_t sector_start = 0; sector_start < len; sector_start += sector_size) {
        uint8_t tweak_input[16] = {0};
        memcpy(tweak_input, &sector_no, sizeof(sector_no));

        uint8_t tweak[16];
        AES_encrypt(tweak_input, tweak, &enc_sched);

        for (int i = 0; i < sector_size && sector_start + i < len; i += 16) {
            const uint8_t *ct  = ciphertext + sector_start + i;
            uint8_t       *pt  = plaintext  + sector_start + i;
            uint8_t xored[16], decrypted[16];
            for (int j = 0; j < 16; j++) xored[j] = ct[j] ^ tweak[j];
            AES_decrypt(xored, decrypted, &dec_sched);
            for (int j = 0; j < 16; j++) pt[j] = decrypted[j] ^ tweak[j];
            multiply_tweak(tweak);
        }
        sector_no++;
    }
    return true;
}

bool crypto_aes_xts_decrypt(const aes_xts_ctx_t *ctx,
                             const uint8_t *ciphertext,
                             uint8_t *plaintext,
                             size_t len,
                             uint64_t block_no) {
    if (len % 16 != 0) return false;

    /* Expand key schedules once per call instead of once per block. */
    AES_KEY enc_sched, dec_sched;
    AES_set_encrypt_key(ctx->key2, 128, &enc_sched);
    AES_set_decrypt_key(ctx->key1, 128, &dec_sched);

    int sector_size = 512;
    /* Use actual block size so this stays correct if g_block_size != 4096. */
    int cs_factor   = (g_block_size > 0) ? (int)(g_block_size / (uint32_t)sector_size) : 8;
    /* Metadata blocks use container-relative (partition-offset-free) tweaks */
    uint64_t sector_no = block_no * (uint64_t)cs_factor;

    for (size_t sector_start = 0; sector_start < len; sector_start += sector_size) {
        uint8_t tweak_input[16] = {0};
        memcpy(tweak_input, &sector_no, sizeof(sector_no));

        uint8_t tweak[16];
        AES_encrypt(tweak_input, tweak, &enc_sched);

        for (int i = 0; i < sector_size && sector_start + i < len; i += 16) {
            const uint8_t *ct = ciphertext + sector_start + i;
            uint8_t       *pt = plaintext  + sector_start + i;
            uint8_t xored[16], decrypted[16];
            for (int j = 0; j < 16; j++) xored[j] = ct[j] ^ tweak[j];
            AES_decrypt(xored, decrypted, &dec_sched);
            for (int j = 0; j < 16; j++) pt[j] = decrypted[j] ^ tweak[j];
            multiply_tweak(tweak);
        }
        sector_no++;
    }
    return true;
}

/* ============================================================================
 * Key derivation
 * ============================================================================
 */

int crypto_pbkdf2_sha256(const char *password, size_t password_len,
                          const uint8_t *salt, size_t salt_len,
                          int iterations,
                          uint8_t *out, size_t out_len) {
    return PKCS5_PBKDF2_HMAC(password, (int)password_len,
                              salt, (int)salt_len,
                              iterations, EVP_sha256(),
                              (int)out_len, out);
}

bool crypto_aes_key_unwrap(const uint8_t *wrapped, size_t wrapped_len,
                            const uint8_t *kek, size_t kek_len,
                            uint8_t *unwrapped, size_t *unwrapped_len) {
    if (wrapped_len < 24 || wrapped_len % 8 != 0) return false;

    int n = (int)(wrapped_len / 8) - 1;
    uint8_t a[8];
    memcpy(a, wrapped, 8);

    uint8_t *r = malloc(n * 8);
    if (!r) return false;
    for (int i = 0; i < n; i++)
        memcpy(r + i * 8, wrapped + 8 + i * 8, 8);

    AES_KEY aes_key;
    AES_set_decrypt_key(kek, (int)(kek_len * 8), &aes_key);

    for (int j = 5; j >= 0; j--) {
        for (int i = n - 1; i >= 0; i--) {
            uint64_t t = (uint64_t)(n * j + i + 1);
            uint8_t t_bytes[8];
            for (int k = 7; k >= 0; k--) { t_bytes[k] = t & 0xFF; t >>= 8; }
            for (int k = 0; k < 8; k++) a[k] ^= t_bytes[k];

            uint8_t block[16], decrypted[16];
            memcpy(block,     a,         8);
            memcpy(block + 8, r + i * 8, 8);
            AES_decrypt(block, decrypted, &aes_key);
            memcpy(a,         decrypted,     8);
            memcpy(r + i * 8, decrypted + 8, 8);
        }
    }

    const uint8_t expected_iv[8] = {0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6};
    if (memcmp(a, expected_iv, 8) != 0) { free(r); return false; }

    *unwrapped_len = n * 8;
    memcpy(unwrapped, r, n * 8);
    free(r);
    return true;
}

/* ============================================================================
 * Keybag parsing
 * ============================================================================
 */

bool crypto_parse_keybag(const uint8_t *data, size_t len, keybag_t *keybag) {
    if (len < 48) return false;

    /* Entries start after obj header (32 bytes) + locker header (16 bytes) = 48 */
    uint16_t nkeys = get_u16(data + 34);
    keybag->count  = 0;
    size_t offset  = 48;

    if (nkeys > MAX_KEYBAG_ENTRIES)
        LOG_EXEC_ONLY("Warning: keybag has %u entries, reading first %d",
                   nkeys, MAX_KEYBAG_ENTRIES);

    for (int i = 0; i < nkeys && i < MAX_KEYBAG_ENTRIES; i++) {
        if (offset + 24 > len) break;

        keybag_entry_t *entry = &keybag->entries[keybag->count];
        memcpy(entry->uuid, data + offset, 16);
        entry->tag    = get_u16(data + offset + 16);
        entry->keylen = get_u16(data + offset + 18);

        if (offset + 24 + entry->keylen > len) break;

        entry->key_data = malloc(entry->keylen);
        if (!entry->key_data) break;
        memcpy(entry->key_data, data + offset + 24, entry->keylen);

        keybag->count++;
        size_t entry_size = ((24 + entry->keylen) + 15) & ~15;
        offset += entry_size;
    }
    return keybag->count > 0;
}

keybag_entry_t *crypto_find_keybag_entry(keybag_t *keybag,
                                          const uint8_t *uuid, uint16_t tag) {
    for (int i = 0; i < keybag->count; i++) {
        if (keybag->entries[i].tag == tag) {
            if (!uuid || memcmp(keybag->entries[i].uuid, uuid, 16) == 0)
                return &keybag->entries[i];
        }
    }
    return NULL;
}

void crypto_free_keybag(keybag_t *keybag) {
    for (int i = 0; i < keybag->count; i++)
        free(keybag->entries[i].key_data);
    keybag->count = 0;
}

/* ============================================================================
 * Crypto state lookup
 * ============================================================================
 */

crypto_state_t *crypto_lookup_state(uint64_t crypto_id) {
    for (int i = 0; i < g_crypto_state_count; i++) {
        if (g_crypto_states[i].crypto_id == crypto_id &&
            g_crypto_states[i].initialized)
            return &g_crypto_states[i];
    }
    return NULL;
}

/* ============================================================================
 * VEK pipeline helpers
 * ============================================================================
 */

/* Parse DER blob for KEK: salt (tag 0x85/len 0x10), iterations (tag 0x84),
 * wrapped_kek (tag 0x83/len 0x28). */
static bool parse_kek_blob(uint8_t *data, size_t len,
                            uint8_t **salt, uint32_t *iterations,
                            uint8_t **wrapped_kek) {
    *salt        = NULL;
    *iterations  = 0;
    *wrapped_kek = NULL;

    for (size_t idx = 0; idx + 2 < len; idx++) {
        if (data[idx] == 0x83 && data[idx+1] == 0x28 && idx + 2 + 40 <= len)
            *wrapped_kek = data + idx + 2;

        if (data[idx] == 0x84) {
            uint8_t length = data[idx+1];
            if (length <= 8 && idx + 2 + length <= len) {
                *iterations = 0;
                for (uint8_t i = 0; i < length; i++)
                    *iterations = (*iterations << 8) | data[idx + 2 + i];
            }
        }

        if (data[idx] == 0x85 && data[idx+1] == 0x10 && idx + 2 + 16 <= len)
            *salt = data + idx + 2;
    }
    return (*salt && *iterations > 0 && *wrapped_kek);
}

/* Parse DER blob for wrapped VEK (tag 0x83/len 0x28). */
static uint8_t *parse_vek_blob(uint8_t *data, size_t len) {
    for (size_t idx = 0; idx + 2 < len; idx++) {
        if (data[idx] == 0x83 && data[idx+1] == 0x28 && idx + 2 + 40 <= len)
            return data + idx + 2;
    }
    return NULL;
}

/* ============================================================================
 * VEK pipeline — public functions
 * ============================================================================
 */

bool crypto_find_and_decrypt_keybag(uint8_t **keybag_data, size_t *keybag_len) {
    if (!g_data || g_data_size < 36) return false;   /* #10: null/size guard */
    uint8_t *nxsb = memmem(g_data, g_data_size, "NXSB", 4);
    if (!nxsb) return false;
    if ((nxsb - g_data) < 32) return false;           /* #9: underflow guard */

    size_t container_offset  = (size_t)(nxsb - g_data) - 32;
    g_container_offset       = container_offset;
    uint8_t *container       = g_data + container_offset;

    memcpy(g_container_uuid, container + 72, 16);

    uint64_t keylocker_paddr = get_u64(container + 1296);
    uint64_t keylocker_count = get_u64(container + 1304);
    if (keylocker_paddr == 0 || keylocker_count == 0) return false;

    LOG_EXEC_ONLY("  Keylocker at block %llu", (unsigned long long)keylocker_paddr);

    size_t keybag_offset = g_partition_offset + keylocker_paddr * g_block_size;
    if (keybag_offset + g_block_size > g_data_size) return false;

    uint8_t *keybag_block = g_data + keybag_offset;

    /* Decrypt container keybag using container UUID as key material.
     * Keybag uses container-relative addressing (no partition offset in tweak). */
    aes_xts_ctx_t keybag_ctx;
    crypto_aes_xts_init(&keybag_ctx, g_container_uuid, g_container_uuid);

    *keybag_data = malloc(g_block_size);
    if (!*keybag_data) return false;

    int      sector_size     = 512;
    int      cs_factor       = (int)(g_block_size / sector_size);
    uint64_t keybag_sector   = keylocker_paddr * cs_factor;
    (void)crypto_aes_xts_decrypt_with_sector_offset(&keybag_ctx, keybag_block,
                                                    *keybag_data, g_block_size,
                                                    keybag_sector, 0);

    uint32_t obj_type = get_u32(*keybag_data + 24);
    if (obj_type != 0x6b657973) {
        LOG_EXEC_ONLY("  Container keybag decryption failed (type=0x%08x)", obj_type);
        free(*keybag_data);
        *keybag_data = NULL;
        return false;
    }

    LOG_EXEC_ONLY("  Container keybag decrypted successfully");
    *keybag_len = g_block_size;
    return true;
}

bool crypto_find_volume_uuid(void) {
    /* #30: apply g_partition_offset so we scan within the correct partition.
     * Also use g_block_size and memcpy for the unaligned type read (#14). */
    for (uint64_t i = 32; i < 200000; i++) {
        uint64_t off = g_partition_offset + i * g_block_size;
        if (off + g_block_size > g_data_size) break;
        uint32_t type;
        memcpy(&type, g_data + off + 24, 4);
        if (type == 0x80000003 || type == 0x00000003) {
            memcpy(g_volume_uuid, g_data + off + 264, 16);
            return true;
        }
    }
    return false;
}

bool crypto_derive_vek_from_password(keybag_t *keybag) {
    uint8_t  *vek_data      = NULL;
    size_t    vek_data_len  = 0;
    uint8_t  *kek_salt      = NULL;
    uint32_t  kek_iterations = 0;
    uint8_t  *kek_wrapped   = NULL;

    /* #4/#5: vol_kb_dec must outlive the inner block (kek_salt/kek_wrapped point
     * into it and are used after the loop).  Heap-alloc so size tracks g_block_size. */
    uint8_t *vol_kb_dec = malloc(g_block_size);
    if (!vol_kb_dec) return false;

    for (int i = 0; i < keybag->count; i++) {
        keybag_entry_t *entry = &keybag->entries[i];

        if (entry->tag == 2) {
            vek_data     = entry->key_data;
            vek_data_len = entry->keylen;
            LOG_EXEC_ONLY("  Found wrapped VEK (%zu bytes)", vek_data_len);
        } else if (entry->tag == 3 && entry->keylen >= 8) {
            uint64_t vol_kb_block  = get_u64(entry->key_data);
            LOG_EXEC_ONLY("  Found volume keybag at block %llu",
                       (unsigned long long)vol_kb_block);

            size_t vol_kb_offset = g_partition_offset + vol_kb_block * g_block_size;
            if (vol_kb_offset + g_block_size <= g_data_size) {
                uint8_t *vol_kb_enc = g_data + vol_kb_offset;

                aes_xts_ctx_t vol_ctx;
                crypto_aes_xts_init(&vol_ctx, entry->uuid, entry->uuid);
                int      sf  = (int)(g_block_size / 512);
                uint64_t sno = vol_kb_block * sf;
                (void)crypto_aes_xts_decrypt_with_sector_offset(&vol_ctx,
                    vol_kb_enc, vol_kb_dec, g_block_size, sno, 0);

                uint16_t vol_nkeys = get_u16(vol_kb_dec + 34);
                size_t   vol_off   = 48;
                for (int j = 0; j < vol_nkeys && j < 10; j++) {
                    if (vol_off + 24 > g_block_size) break;
                    uint16_t v_tag    = get_u16(vol_kb_dec + vol_off + 16);
                    uint16_t v_keylen = get_u16(vol_kb_dec + vol_off + 18);
                    if (vol_off + 24 + v_keylen > g_block_size) break;
                    if (v_tag == 3) {
                        uint8_t *kek_blob = vol_kb_dec + vol_off + 24;
                        if (parse_kek_blob(kek_blob, v_keylen,
                                           &kek_salt, &kek_iterations,
                                           &kek_wrapped))
                            LOG_EXEC_ONLY("  Found KEK info: iterations=%u", kek_iterations);
                    }
                    vol_off += (24 + v_keylen + 15) & ~15;
                }
            }
        }
    }

    bool ok = false;

    if (!kek_salt || !kek_wrapped || kek_iterations == 0) {
        LOG_EXEC_ONLY("  No KEK info found");
        goto done;
    }
    if (!vek_data) {
        LOG_EXEC_ONLY("  No VEK data found");
        goto done;
    }

    LOG_EXEC_ONLY("  Deriving KEK with PBKDF2 (%u iterations)...", kek_iterations);

    uint8_t derived_key[32];
    if (!crypto_pbkdf2_sha256(g_password, strlen(g_password),
                               kek_salt, 16, (int)kek_iterations,
                               derived_key, 32)) {
        LOG_EXEC_ONLY("  PBKDF2 failed");
        goto done;
    }

    uint8_t unwrapped_kek[32];
    size_t  unwrapped_len = 0;
    if (!crypto_aes_key_unwrap(kek_wrapped, 40, derived_key, 32,
                                unwrapped_kek, &unwrapped_len)) {
        LOG_EXEC_ONLY("  KEK unwrap failed — wrong password?");
        goto done;
    }

    uint8_t *wrapped_vek = parse_vek_blob(vek_data, vek_data_len);
    if (!wrapped_vek) {
        LOG_EXEC_ONLY("  Could not parse wrapped VEK");
        goto done;
    }

    size_t vek_len = 0;
    if (!crypto_aes_key_unwrap(wrapped_vek, 40, unwrapped_kek, 32,
                                g_vek, &vek_len)) {
        LOG_EXEC_ONLY("  VEK unwrap failed");
        goto done;
    }
    if (vek_len != 32) {
        LOG_EXEC_ONLY("  Invalid VEK length: %zu", vek_len);
        goto done;
    }

    crypto_aes_xts_init(&g_aes_xts, g_vek, g_vek + 16);
    g_encryption_enabled = true;
    LOG_EXEC_ONLY("  VEK derived successfully");
    ok = true;

done:
    /* Scrub sensitive key material from the stack before returning. */
    OPENSSL_cleanse(derived_key,   sizeof(derived_key));
    OPENSSL_cleanse(unwrapped_kek, sizeof(unwrapped_kek));
    free(vol_kb_dec);
    return ok;
}
