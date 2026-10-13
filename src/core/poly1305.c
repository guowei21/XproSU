/* RFC 8439 section 2.5 Poly1305, 26-bit limb ("donna") form.
 *
 * Why this shape: the engine runs on aarch64 and is checked offline on x86_64,
 * and both must produce byte-identical tags.  32-bit limbs with explicit
 * carries are endian- and word-size-independent, which a 64-bit-limb variant
 * using the host's natural multiply would not be without extra masking.  The
 * table is a couple of kilobytes, so speed is irrelevant. */
#include "poly1305.h"

#include <string.h>

static uint32_t load32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static void store32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

void poly1305_init(poly1305_ctx *st, const uint8_t key[32]) {
  /* r is clamped: the top 4 bits of each 32-bit half of the first 16 bytes are
   * cleared (RFC 8439 section 2.5). */
  st->r[0] = load32(key + 0) & 0x3ffffffu;
  st->r[1] = (load32(key + 3) >> 2) & 0x3ffff03u;
  st->r[2] = (load32(key + 6) >> 4) & 0x3ffc0ffu;
  st->r[3] = (load32(key + 9) >> 6) & 0x3f03fffu;
  st->r[4] = (load32(key + 12) >> 8) & 0x00fffffu;

  st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;

  st->pad[0] = load32(key + 16);
  st->pad[1] = load32(key + 20);
  st->pad[2] = load32(key + 24);
  st->pad[3] = load32(key + 28);

  st->leftover = 0;
  st->final = 0;
  memset(st->buf, 0, sizeof(st->buf));
}

static void poly1305_blocks(poly1305_ctx *st, const uint8_t *m, size_t bytes) {
  /* Bit 128 lives at bit 24 of limb 4 in a 26-bit-limb layout.  The padded
   * tail block carries its own terminator byte instead, so it must not set it
   * (RFC 8439 section 2.5, step 2). */
  const uint32_t hibit = st->final ? 0u : (1u << 24);
  const uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3],
                 r4 = st->r[4];
  const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
  uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3],
           h4 = st->h[4];

  while (bytes >= 16) {
    /* h += m[i] (little-endian, 130 bits) */
    h0 += load32(m + 0) & 0x3ffffffu;
    h1 += (load32(m + 3) >> 2) & 0x3ffffffu;
    h2 += (load32(m + 6) >> 4) & 0x3ffffffu;
    h3 += (load32(m + 9) >> 6) & 0x3ffffffu;
    h4 += (load32(m + 12) >> 8) | hibit;

    /* h *= r mod 2^130-5, folded into 5 limbs of 26 bits */
    uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 +
                  (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
    uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 +
                  (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
    uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 +
                  (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
    uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 +
                  (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
    uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 +
                  (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

    uint32_t c;
    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffffu;
    d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffffu;
    d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffffu;
    d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffffu;
    d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffffu;
    h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffffu;
    h1 += c;

    m += 16;
    bytes -= 16;
  }

  st->h[0] = h0;
  st->h[1] = h1;
  st->h[2] = h2;
  st->h[3] = h3;
  st->h[4] = h4;
}

void poly1305_update(poly1305_ctx *st, const uint8_t *m, size_t bytes) {
  if (st->leftover) {
    size_t want = 16 - st->leftover;
    if (want > bytes) want = bytes;
    memcpy(st->buf + st->leftover, m, want);
    st->leftover += want;
    m += want;
    bytes -= want;
    if (st->leftover < 16) return;
    poly1305_blocks(st, st->buf, 16);
    st->leftover = 0;
  }
  if (bytes >= 16) {
    size_t want = bytes & ~(size_t)15;
    poly1305_blocks(st, m, want);
    m += want;
    bytes -= want;
  }
  if (bytes) {
    memcpy(st->buf, m, bytes);
    st->leftover = bytes;
  }
}

void poly1305_finish(poly1305_ctx *st, uint8_t tag[16]) {
  if (st->leftover) {
    st->buf[st->leftover] = 1;
    if (st->leftover + 1 < 16) {
      memset(st->buf + st->leftover + 1, 0, 16 - st->leftover - 1);
    }
    st->final = 1;
    poly1305_blocks(st, st->buf, 16);
  }

  uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3],
           h4 = st->h[4], c;

  /* fully carry h */
  c = h1 >> 26; h1 &= 0x3ffffffu;
  h2 += c; c = h2 >> 26; h2 &= 0x3ffffffu;
  h3 += c; c = h3 >> 26; h3 &= 0x3ffffffu;
  h4 += c; c = h4 >> 26; h4 &= 0x3ffffffu;
  h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffffu;
  h1 += c;

  /* compute h + -p */
  uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffffu;
  uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffffu;
  uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffffu;
  uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffffu;
  uint32_t g4 = h4 + c - (1u << 26);

  /* select h if h < p, else h + -p */
  uint32_t mask = (g4 >> 31) - 1;
  g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  /* h = h % 2^128 */
  h0 = (h0 | (h1 << 26)) & 0xffffffffu;
  h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffu;
  h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffu;
  h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffu;

  /* mac = (h + pad) % 2^128 */
  uint64_t f;
  f = (uint64_t)h0 + st->pad[0]; h0 = (uint32_t)f;
  f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
  f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
  f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

  store32(tag + 0, h0);
  store32(tag + 4, h1);
  store32(tag + 8, h2);
  store32(tag + 12, h3);

  /* The accumulator held key material; do not leave it on the stack. */
  memset(st, 0, sizeof(*st));
}

int poly1305_selftest(void) {
  /* RFC 8439 section 2.5.2 */
  static const uint8_t key[32] = {
      0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52,
      0xfe, 0x42, 0xd5, 0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d,
      0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b};
  static const char msg[] = "Cryptographic Forum Research Group";
  static const uint8_t want[16] = {0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51,
                                   0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf,
                                   0x0c, 0x01, 0x27, 0xa9};
  poly1305_ctx st;
  uint8_t tag[16];

  poly1305_init(&st, key);
  poly1305_update(&st, (const uint8_t *)msg, sizeof(msg) - 1);
  poly1305_finish(&st, tag);
  if (memcmp(tag, want, sizeof(want)) != 0) return -1;

  /* Feeding the same message one byte at a time must give the same tag: this
   * is what catches a broken leftover buffer. */
  poly1305_init(&st, key);
  for (size_t i = 0; i < sizeof(msg) - 1; i++) {
    poly1305_update(&st, (const uint8_t *)msg + i, 1);
  }
  poly1305_finish(&st, tag);
  if (memcmp(tag, want, sizeof(want)) != 0) return -2;

  /* An empty message still authenticates (tag == pad). */
  poly1305_init(&st, key);
  poly1305_finish(&st, tag);
  if (memcmp(tag, key + 16, 16) != 0) return -3;

  return 0;
}
