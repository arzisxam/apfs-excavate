# Encryption

APFS uses AES-XTS-128 to encrypt file data on a per-extent basis. This document describes how apfs-excavate derives the keys needed to decrypt a volume.

---

## Overview

```
User password
      │
      ▼ PBKDF2-SHA256 (iter count + salt from keybag)
Key Encryption Key (KEK)
      │
      ▼ RFC 3394 AES key unwrap
Volume Encryption Key (VEK) — one per volume
      │
      ▼ AES-XTS-128 (VEK + per-block tweak)
Plaintext file data
```

For per-extent encrypted volumes (most APFS volumes since macOS 10.15), each file extent has a `crypto_id` that selects a crypto state record from the B-tree. The crypto state holds a wrapped per-extent key; the VEK is used to unwrap it before decryption.

---

## Container keybag

The container keybag (`media_keybag`) is stored in a known location within the APFS container — typically at a fixed block offset from the container superblock (NXSB). It contains one or more entries tagged `KB_TAG_VOLUME_UNLOCK_RECORDS` (tag 3), each identified by a UUID.

`crypto_find_and_decrypt_keybag()` locates the keybag by scanning the image for the keybag magic (`locker\0\0`) and reads the raw keybag bytes.

---

## Volume UUID

Before parsing the keybag, the tool reads the volume UUID from the APSB (volume superblock) at offset 112. This UUID is used to select the correct keybag entry when multiple volumes share a container.

`crypto_find_volume_uuid()` scans for an APSB block and extracts the UUID.

---

## Key derivation

Given the raw keybag bytes, `crypto_parse_keybag()` parses the TLV (tag-length-value) structure and populates a `keybag_t`.

`crypto_derive_vek_from_password()` then:

1. Locates the keybag entry for the volume's UUID
2. Reads the PBKDF2 parameters (iteration count, salt) embedded in the entry
3. Derives the KEK: `PBKDF2-HMAC-SHA256(password, salt, iter_count, 32 bytes)`
4. Uses the KEK to unwrap the wrapped VEK via RFC 3394 AES key unwrap
5. Stores the VEK in `g_vek[32]` and initialises `g_aes_xts` with `key1 = VEK[0:16]`, `key2 = VEK[16:32]`

---

## Per-block decryption

`bio_read_decrypt()` decrypts one block using AES-XTS:

```
plaintext = AES-XTS-decrypt(ciphertext, key1=VEK[0:16], key2=VEK[16:32], tweak=block_number)
```

The tweak is the physical block number within the container (not the partition), ensuring that each block has a unique IV even when the same content appears at different offsets.

---

## Per-extent crypto states

APFS supports per-extent keys stored in `J_CRYPTO_STATE` B-tree records (`JOBJ_TYPE_CRYPTO_STATE` = 7). Each record maps a `crypto_id` to a wrapped key.

During scanning, `parse_crypto_state()` in `apfs_parse.c` collects these records into `g_crypto_states[]`. During extraction, `recovery_extract_files()` checks each extent's `crypto_id`:

- `crypto_id == 0` → use the inode's `default_crypto_id` (from the dstream xfield)
- Otherwise → look up the matching `crypto_state_t` in `g_crypto_states[]` and use its key

If no matching crypto state is found for an extent (common on badly damaged images where B-tree fragments are missing), the tool falls back to the global VEK and logs a warning.

---

## AES-XTS implementation

The AES-XTS implementation in `crypto.c` uses OpenSSL's low-level AES block cipher (`AES_encrypt`) to avoid dependency on the OpenSSL EVP layer's XTS support, which has had API differences across versions.

The standard XTS construction is used:
1. Encrypt the tweak with key2: `T = AES-encrypt(tweak_le64, key2)`
2. For each 16-byte block i: `plaintext[i] = AES-decrypt(ciphertext[i] XOR T_i, key1) XOR T_i`
3. Update T: `T = GF(2^128) multiply-by-alpha(T)`

---

## Limitations

- **T2 / Secure Enclave volumes**: Macs with a T2 chip or Apple Silicon use hardware-bound keys stored in the Secure Enclave. The VEK for these volumes cannot be derived from the password alone without the hardware. Recovery from such images without the original hardware is not possible.
- **FileVault personal recovery key**: Not currently supported; only password-based derivation is implemented.
- **Wrapped per-extent keys**: If the crypto state B-tree is too damaged to recover a particular extent's wrapped key, that extent will be decrypted with the global VEK. The result may be corrupt but is better than skipping the extent entirely.
