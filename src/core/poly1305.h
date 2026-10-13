#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>
#include <stdint.h>

/* RFC 8439 section 2.5 Poly1305 one-time authenticator.
 *
 * Used only through chacha20_poly1305_*() in chacha20.h -- the AEAD constructs
 * the one-time key by running ChaCha20 block 0 over the 32-byte Poly1305 key.
 * Kept in its own translation unit so the 26-bit limb arithmetic can be audited
 * against the RFC without the rest of the engine in the way.
 *
 * Portability note: the limbs are 32-bit because the engine must produce
 * bit-identical output on aarch64 (device) and x86_64 (offline test host). */

typedef struct {
  uint32_t r[5];      /* clamped key */
  uint32_t h[5];      /* accumulator */
  uint32_t pad[4];    /* s, the second half of the key */
  uint8_t buf[16];
  size_t leftover;
  int final;          /* set once the padded tail block has been fed */
} poly1305_ctx;

void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]);
void poly1305_update(poly1305_ctx *ctx, const uint8_t *m, size_t len);
void poly1305_finish(poly1305_ctx *ctx, uint8_t tag[16]);

/* RFC 8439 section 2.5.2 vector.  Returns 0 on pass, -1 on mismatch. */
int poly1305_selftest(void);

#endif
