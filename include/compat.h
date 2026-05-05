#pragma once
/*
 * compat.h — safe unaligned-read helpers (fix #14).
 *
 * APFS block data is a raw byte stream; field offsets are not guaranteed to
 * satisfy the alignment requirements of uint16_t/uint32_t/uint64_t.  Using
 * direct pointer casts ( *(uint32_t *)ptr ) is undefined behaviour on
 * strict-alignment architectures.  memcpy-based reads are always safe and
 * compile to a single load instruction on x86/arm64.
 */

#include <stdint.h>
#include <string.h>

static inline uint16_t get_u16(const uint8_t *p) {
    uint16_t v; memcpy(&v, p, 2); return v;
}
static inline uint32_t get_u32(const uint8_t *p) {
    uint32_t v; memcpy(&v, p, 4); return v;
}
static inline uint64_t get_u64(const uint8_t *p) {
    uint64_t v; memcpy(&v, p, 8); return v;
}
