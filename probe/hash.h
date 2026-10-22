#ifndef PROBE_HASH_H
#define PROBE_HASH_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t h[8];
  uint64_t total;
  uint8_t block[64];
  size_t fill;
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t digest[32]);
void sha256_hex(const uint8_t digest[32], char hex[65]);

/* FNV-1a 64 over little-endian qwords, with every value whose top 16 bits are
 * 0xffff (a kernel or DMAP pointer) replaced by zero, so windows that only
 * differ by KASLR hash the same. len must be a multiple of 8.
 * probe/kdata_windows.py computes the same thing offline. */
#define FNV64_INIT 0xcbf29ce484222325ULL
uint64_t fnv64_masked(uint64_t hash, const void *data, size_t len);

#endif
