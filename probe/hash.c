#include "hash.h"

#include <string.h>

/* SHA-256 as in FIPS 180-4. The SDK has no libmd. */

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sha256_ctx *ctx, const uint8_t *p) {
  uint32_t w[64];
  uint32_t a, b, c, d, e, f, g, h;

  for (int i = 0; i < 16; i++)
    w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
           (uint32_t)p[i * 4 + 2] << 8 | (uint32_t)p[i * 4 + 3];
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  a = ctx->h[0];
  b = ctx->h[1];
  c = ctx->h[2];
  d = ctx->h[3];
  e = ctx->h[4];
  f = ctx->h[5];
  g = ctx->h[6];
  h = ctx->h[7];
  for (int i = 0; i < 64; i++) {
    uint32_t s1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + s1 + ch + K[i] + w[i];
    uint32_t s0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
  ctx->h[4] += e;
  ctx->h[5] += f;
  ctx->h[6] += g;
  ctx->h[7] += h;
}

void sha256_init(sha256_ctx *ctx) {
  static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                 0xa54ff53a, 0x510e527f, 0x9b05688c,
                                 0x1f83d9ab, 0x5be0cd19};
  memcpy(ctx->h, iv, sizeof(iv));
  ctx->total = 0;
  ctx->fill = 0;
}

void sha256_update(sha256_ctx *ctx, const void *data, size_t len) {
  const uint8_t *p = data;

  ctx->total += len;
  if (ctx->fill) {
    size_t take = 64 - ctx->fill;
    if (take > len)
      take = len;
    memcpy(ctx->block + ctx->fill, p, take);
    ctx->fill += take;
    p += take;
    len -= take;
    if (ctx->fill < 64)
      return;
    sha256_block(ctx, ctx->block);
    ctx->fill = 0;
  }
  while (len >= 64) {
    sha256_block(ctx, p);
    p += 64;
    len -= 64;
  }
  memcpy(ctx->block, p, len);
  ctx->fill = len;
}

void sha256_final(sha256_ctx *ctx, uint8_t digest[32]) {
  uint64_t bits = ctx->total * 8;

  ctx->block[ctx->fill++] = 0x80;
  if (ctx->fill > 56) {
    memset(ctx->block + ctx->fill, 0, 64 - ctx->fill);
    sha256_block(ctx, ctx->block);
    ctx->fill = 0;
  }
  memset(ctx->block + ctx->fill, 0, 56 - ctx->fill);
  for (int i = 0; i < 8; i++)
    ctx->block[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
  sha256_block(ctx, ctx->block);
  for (int i = 0; i < 8; i++) {
    digest[i * 4] = (uint8_t)(ctx->h[i] >> 24);
    digest[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 16);
    digest[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 8);
    digest[i * 4 + 3] = (uint8_t)ctx->h[i];
  }
}

void sha256_hex(const uint8_t digest[32], char hex[65]) {
  static const char digits[] = "0123456789abcdef";

  for (int i = 0; i < 32; i++) {
    hex[i * 2] = digits[digest[i] >> 4];
    hex[i * 2 + 1] = digits[digest[i] & 15];
  }
  hex[64] = 0;
}

uint64_t fnv64_masked(uint64_t hash, const void *data, size_t len) {
  const uint8_t *p = data;

  for (size_t off = 0; off + 8 <= len; off += 8) {
    uint64_t q;
    memcpy(&q, p + off, sizeof(q));
    if ((q >> 48) == 0xffffULL)
      q = 0;
    for (int i = 0; i < 8; i++) {
      hash ^= (uint8_t)(q >> (8 * i));
      hash *= 0x100000001b3ULL;
    }
  }
  return hash;
}
