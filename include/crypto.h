#pragma once
/*
 * crypto.h — AES-XTS decryption, PBKDF2 key derivation, keybag parsing,
 *             and the full APFS volume encryption key (VEK) pipeline.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "apfs_types.h"

/* ---- AES-XTS -------------------------------------------------------------- */

void crypto_aes_xts_init(aes_xts_ctx_t *ctx, const uint8_t *key1, const uint8_t *key2);

/*
 * crypto_aes_xts_decrypt() — decrypt len bytes of ciphertext using the given
 * context and block_no as the AES-XTS tweak (sector number).
 * len must be a multiple of 16.  Returns false if len is not a multiple of 16.
 */
bool crypto_aes_xts_decrypt(const aes_xts_ctx_t *ctx,
                             const uint8_t *ciphertext,
                             uint8_t *plaintext,
                             size_t len,
                             uint64_t block_no);

/*
 * crypto_aes_xts_decrypt_with_sector_offset() — decrypt using an explicit
 * sector number (base_sector_no + sector_offset).  Used for keybag blocks
 * which use container-relative addressing without the partition offset.
 * Returns false if len is not a multiple of 16 or if sector_no is negative.
 */
bool crypto_aes_xts_decrypt_with_sector_offset(const aes_xts_ctx_t *ctx,
                                                const uint8_t *ciphertext,
                                                uint8_t *plaintext,
                                                size_t len,
                                                uint64_t base_sector_no,
                                                int64_t sector_offset);

/* ---- Key derivation ------------------------------------------------------- */

/* PBKDF2-SHA256.  Returns 1 on success, 0 on failure. */
int crypto_pbkdf2_sha256(const char *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         int iterations,
                         uint8_t *out, size_t out_len);

/* RFC 3394 AES key unwrap.  Returns true on success. */
bool crypto_aes_key_unwrap(const uint8_t *wrapped, size_t wrapped_len,
                           const uint8_t *kek, size_t kek_len,
                           uint8_t *unwrapped, size_t *unwrapped_len);

/* ---- Keybag --------------------------------------------------------------- */

bool crypto_parse_keybag(const uint8_t *data, size_t len, keybag_t *keybag);
keybag_entry_t *crypto_find_keybag_entry(keybag_t *keybag,
                                          const uint8_t *uuid, uint16_t tag);
void crypto_free_keybag(keybag_t *keybag);

/* ---- VEK pipeline --------------------------------------------------------- */

/*
 * crypto_find_and_decrypt_keybag() — locate and decrypt the container keybag.
 * Allocates *keybag_data (caller must free).  Returns true on success.
 */
bool crypto_find_and_decrypt_keybag(uint8_t **keybag_data, size_t *keybag_len);

bool crypto_find_volume_uuid(void);

/*
 * crypto_derive_vek_from_password() — run the full two-level keybag pipeline:
 * password → PBKDF2 → KEK unwrap → VEK unwrap → initialise g_aes_xts.
 */
bool crypto_derive_vek_from_password(keybag_t *keybag);

/*
 * crypto_lookup_state() — find a crypto_state_t entry by crypto_id.
 * Returns NULL if not found.
 */
crypto_state_t *crypto_lookup_state(uint64_t crypto_id);
