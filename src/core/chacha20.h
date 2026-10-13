#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <stdint.h>

/* RFC 8439 ChaCha20 (20 rounds, 32-bit counter, 96-bit nonce).
 *
 * Used by the offsets container (offsets_bin.c) to turn the offset table into
 * something `strings` and `xxd` cannot read back.  Stage 1 runs it with a
 * compile-time key, so this is obfuscation and not secrecy -- see the note on
 * GLT_KEY in offsets_bin.c.  Stage 2 feeds the same primitive the per-device
 * key derived by HKDF-SHA256 and adds a Poly1305 tag, which is why the
 * keystream block is exposed separately below.
 *
 * Encryption and decryption are both `chacha20_xor()`: the transform is its
 * own inverse. */

/* XOR `len` bytes of keystream (counter starts at 0) into `out` (may alias
 * `in`; `in` may be NULL to emit the raw keystream). */
void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                  const uint8_t key[32], const uint8_t nonce[12]);

/* One 64-byte keystream block at an explicit counter.  Exposed for the RFC
 * test vectors (section 2.3.2 uses counter=1) and for stage 2's tag step. */
void chacha20_block(uint8_t out[64], const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12]);

int chacha20_selftest(void);


/* ---- AEAD_CHACHA20_POLY1305 (RFC 8439 section 2.8) -------------------- */

/* `ct` and `pt` may alias.  `aad` may be NULL when `aad_len` is 0. */
void chacha20_poly1305_encrypt(uint8_t *ct, uint8_t tag[16],
                               const uint8_t *pt, size_t len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t key[32], const uint8_t nonce[12]);

/* Returns 0 and writes `len` bytes to `pt`, or -1 when the tag does not
 * match.  On failure `pt` is left untouched -- unauthenticated plaintext is
 * never handed to the caller. */
int chacha20_poly1305_decrypt(uint8_t *pt, const uint8_t *ct, size_t len,
                              const uint8_t tag[16],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t key[32], const uint8_t nonce[12]);

/* RFC 8439 sections 2.5.2 and 2.8.2 vectors, plus round-trip and
 * tamper-rejection checks.  Returns 0 on pass, negative on the first failure
 * (see the return statements for which check tripped). */
int chacha20_poly1305_selftest(void);

#endif
