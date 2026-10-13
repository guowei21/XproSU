/* RFC 8439 ChaCha20.  Deliberately small and dependency-free: the engine is
 * statically linked against nothing but libc, and the offsets table is a
 * couple of kilobytes, so throughput is irrelevant next to keeping the code
 * auditable against the RFC. */
#include "chacha20.h"
#include "poly1305.h"

#include <string.h>

#define ROTL32(v, c) ((uint32_t)(((v) << (c)) | ((v) >> (32 - (c)))))

/* The state words come from the RFC; `in` is the pre-permutation state so the
 * caller can add it back at the end of the block. */
static void chacha20_permute(uint32_t out[16], const uint32_t in[16]) {
  uint32_t x[16];
  memcpy(x, in, sizeof(x));

  for (int i = 0; i < 10; i++) {
    /* column rounds */
    x[0] += x[4];   x[12] = ROTL32(x[12] ^ x[0], 16);
    x[8] += x[12];  x[4]  = ROTL32(x[4] ^ x[8], 12);
    x[0] += x[4];   x[12] = ROTL32(x[12] ^ x[0], 8);
    x[8] += x[12];  x[4]  = ROTL32(x[4] ^ x[8], 7);

    x[1] += x[5];   x[13] = ROTL32(x[13] ^ x[1], 16);
    x[9] += x[13];  x[5]  = ROTL32(x[5] ^ x[9], 12);
    x[1] += x[5];   x[13] = ROTL32(x[13] ^ x[1], 8);
    x[9] += x[13];  x[5]  = ROTL32(x[5] ^ x[9], 7);

    x[2] += x[6];   x[14] = ROTL32(x[14] ^ x[2], 16);
    x[10] += x[14]; x[6]  = ROTL32(x[6] ^ x[10], 12);
    x[2] += x[6];   x[14] = ROTL32(x[14] ^ x[2], 8);
    x[10] += x[14]; x[6]  = ROTL32(x[6] ^ x[10], 7);

    x[3] += x[7];   x[15] = ROTL32(x[15] ^ x[3], 16);
    x[11] += x[15]; x[7]  = ROTL32(x[7] ^ x[11], 12);
    x[3] += x[7];   x[15] = ROTL32(x[15] ^ x[3], 8);
    x[11] += x[15]; x[7]  = ROTL32(x[7] ^ x[11], 7);

    /* diagonal rounds */
    x[0] += x[5];   x[15] = ROTL32(x[15] ^ x[0], 16);
    x[10] += x[15]; x[5]  = ROTL32(x[5] ^ x[10], 12);
    x[0] += x[5];   x[15] = ROTL32(x[15] ^ x[0], 8);
    x[10] += x[15]; x[5]  = ROTL32(x[5] ^ x[10], 7);

    x[1] += x[6];   x[12] = ROTL32(x[12] ^ x[1], 16);
    x[11] += x[12]; x[6]  = ROTL32(x[6] ^ x[11], 12);
    x[1] += x[6];   x[12] = ROTL32(x[12] ^ x[1], 8);
    x[11] += x[12]; x[6]  = ROTL32(x[6] ^ x[11], 7);

    x[2] += x[7];   x[13] = ROTL32(x[13] ^ x[2], 16);
    x[8] += x[13];  x[7]  = ROTL32(x[7] ^ x[8], 12);
    x[2] += x[7];   x[13] = ROTL32(x[13] ^ x[2], 8);
    x[8] += x[13];  x[7]  = ROTL32(x[7] ^ x[8], 7);

    x[3] += x[4];   x[14] = ROTL32(x[14] ^ x[3], 16);
    x[9] += x[14];  x[4]  = ROTL32(x[4] ^ x[9], 12);
    x[3] += x[4];   x[14] = ROTL32(x[14] ^ x[3], 8);
    x[9] += x[14];  x[4]  = ROTL32(x[4] ^ x[9], 7);
  }
  for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

static void le32_store(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static uint32_t le32_load(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static void chacha20_state(uint32_t st[16], const uint8_t key[32],
                           uint32_t counter, const uint8_t nonce[12]) {
  /* "expand 32-byte k" */
  st[0] = 0x61707865u;
  st[1] = 0x3320646eu;
  st[2] = 0x79622d32u;
  st[3] = 0x6b206574u;
  for (int i = 0; i < 8; i++) st[4 + i] = le32_load(key + 4 * i);
  st[12] = counter;
  st[13] = le32_load(nonce + 0);
  st[14] = le32_load(nonce + 4);
  st[15] = le32_load(nonce + 8);
}

void chacha20_block(uint8_t out[64], const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12]) {
  uint32_t st[16], ks[16];
  chacha20_state(st, key, counter, nonce);
  chacha20_permute(ks, st);
  for (int i = 0; i < 16; i++) le32_store(out + 4 * i, ks[i]);
}

/* Keystream XOR with an explicit starting counter.  AEAD_CHACHA20_POLY1305
 * takes the Poly1305 key from block 0 and starts the payload keystream at
 * block 1 (RFC 8439 section 2.8), so the start counter cannot be implicit. */
static void chacha20_xor_at(uint8_t *out, const uint8_t *in, size_t len,
                            uint32_t counter, const uint8_t key[32],
                            const uint8_t nonce[12]) {
  uint8_t block[64];
  size_t done = 0;
  while (done < len) {
    chacha20_block(block, key, counter++, nonce);
    size_t n = len - done;
    if (n > sizeof(block)) n = sizeof(block);
    for (size_t i = 0; i < n; i++) {
      out[done + i] = in ? (uint8_t)(in[done + i] ^ block[i]) : block[i];
    }
    done += n;
  }
  /* Do not leave keystream material on the stack. */
  memset(block, 0, sizeof(block));
}

void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                  const uint8_t key[32], const uint8_t nonce[12]) {
  chacha20_xor_at(out, in, len, 0, key, nonce);
}

int chacha20_selftest(void) {
  /* RFC 8439 section 2.3.2 */
  static const uint8_t key[32] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  static const uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
                                    0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
  static const uint8_t want[64] = {
      0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd,
      0x1f, 0xa3, 0x20, 0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0,
      0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e, 0xd2,
      0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05,
      0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e,
      0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e};
  uint8_t got[64];
  chacha20_block(got, key, 1, nonce);
  if (memcmp(got, want, sizeof(want)) != 0) return -1;

  /* The transform must be its own inverse. */
  uint8_t plain[100], buf[100], back[100];
  for (size_t i = 0; i < sizeof(plain); i++) plain[i] = (uint8_t)(i * 7 + 1);
  static const uint8_t n2[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  chacha20_xor(buf, plain, sizeof(plain), key, n2);
  chacha20_xor(back, buf, sizeof(plain), key, n2);
  if (memcmp(plain, back, sizeof(plain)) != 0) return -1;
  if (memcmp(plain, buf, sizeof(plain)) == 0) return -1;
  return 0;
}

/* ---- AEAD_CHACHA20_POLY1305 (RFC 8439 section 2.8) --------------------- */

/* MAC input is aad || pad16(aad) || ct || pad16(ct) || le64(aad_len) ||
 * le64(ct_len), keyed by the first 32 bytes of ChaCha20 block 0. */
static void poly1305_mac(uint8_t tag[16], const uint8_t otk[32],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len) {
  static const uint8_t zeros[16] = {0};
  uint8_t lens[16];
  poly1305_ctx st;

  poly1305_init(&st, otk);
  if (aad_len) poly1305_update(&st, aad, aad_len);
  if (aad_len & 15u) poly1305_update(&st, zeros, 16 - (aad_len & 15u));
  if (ct_len) poly1305_update(&st, ct, ct_len);
  if (ct_len & 15u) poly1305_update(&st, zeros, 16 - (ct_len & 15u));
  for (int i = 0; i < 8; i++) {
    lens[i] = (uint8_t)((uint64_t)aad_len >> (8 * i));
    lens[8 + i] = (uint8_t)((uint64_t)ct_len >> (8 * i));
  }
  poly1305_update(&st, lens, sizeof(lens));
  poly1305_finish(&st, tag);
}

void chacha20_poly1305_encrypt(uint8_t *ct, uint8_t tag[16],
                               const uint8_t *pt, size_t len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t key[32], const uint8_t nonce[12]) {
  uint8_t otk[64];
  chacha20_block(otk, key, 0, nonce);
  chacha20_xor_at(ct, pt, len, 1, key, nonce);
  poly1305_mac(tag, otk, aad, aad_len, ct, len);
  memset(otk, 0, sizeof(otk));
}

/* Constant-time compare: a tag check that returns early leaks how many bytes
 * matched, which is enough to forge a tag byte by byte. */
static int tag_differs(const uint8_t *a, const uint8_t *b, size_t n) {
  uint8_t acc = 0;
  for (size_t i = 0; i < n; i++) acc |= (uint8_t)(a[i] ^ b[i]);
  return acc != 0;
}

int chacha20_poly1305_decrypt(uint8_t *pt, const uint8_t *ct, size_t len,
                              const uint8_t tag[16],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t key[32], const uint8_t nonce[12]) {
  uint8_t otk[64];
  uint8_t want[16];
  int bad;

  chacha20_block(otk, key, 0, nonce);
  poly1305_mac(want, otk, aad, aad_len, ct, len);
  memset(otk, 0, sizeof(otk));

  bad = tag_differs(want, tag, 16);
  memset(want, 0, sizeof(want));
  /* Never release unauthenticated plaintext: a wrong tag means the bytes are
   * either tampered with or belong to another device, and decrypting them
   * anyway would hand the caller attacker-controlled offset values. */
  if (bad) return -1;

  chacha20_xor_at(pt, ct, len, 1, key, nonce);
  return 0;
}

int chacha20_poly1305_selftest(void) {
  /* RFC 8439 section 2.8.2 */
  static const uint8_t key[32] = {
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a,
      0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
      0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
  static const uint8_t nonce[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                                    0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
  static const uint8_t aad[12] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                                  0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
  static const char pt[] =
      "Ladies and Gentlemen of the class of '99: If I could offer you only "
      "one tip for the future, sunscreen would be it.";
  static const uint8_t want_ct[114] = {
      0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
      0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
      0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
      0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
      0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
      0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
      0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
      0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
      0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
      0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16};
  static const uint8_t want_tag[16] = {
      0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
      0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91};

  const size_t len = sizeof(pt) - 1;
  uint8_t ct[sizeof(pt) - 1];
  uint8_t back[sizeof(pt) - 1];
  uint8_t tag[16];

  if (poly1305_selftest() != 0) return -1;

  chacha20_poly1305_encrypt(ct, tag, (const uint8_t *)pt, len, aad,
                            sizeof(aad), key, nonce);
  if (memcmp(ct, want_ct, len) != 0) return -2;
  if (memcmp(tag, want_tag, sizeof(want_tag)) != 0) return -3;

  if (chacha20_poly1305_decrypt(back, ct, len, tag, aad, sizeof(aad), key,
                                nonce) != 0) {
    return -4;
  }
  if (memcmp(back, pt, len) != 0) return -5;

  /* A flipped ciphertext bit, a flipped AAD bit and a wrong key must all be
   * rejected -- this is the property the container relies on. */
  ct[0] ^= 0x01;
  if (chacha20_poly1305_decrypt(back, ct, len, tag, aad, sizeof(aad), key,
                                nonce) == 0) {
    return -6;
  }
  ct[0] ^= 0x01;
  {
    uint8_t bad_aad[12];
    memcpy(bad_aad, aad, sizeof(aad));
    bad_aad[11] ^= 0x80;
    if (chacha20_poly1305_decrypt(back, ct, len, tag, bad_aad, sizeof(bad_aad),
                                  key, nonce) == 0) {
      return -7;
    }
  }
  {
    uint8_t bad_key[32];
    memcpy(bad_key, key, sizeof(key));
    bad_key[31] ^= 0x01;
    if (chacha20_poly1305_decrypt(back, ct, len, tag, aad, sizeof(aad),
                                  bad_key, nonce) == 0) {
      return -8;
    }
  }
  return 0;
}
