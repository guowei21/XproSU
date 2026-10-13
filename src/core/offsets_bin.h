#ifndef OFFSETS_BIN_H
#define OFFSETS_BIN_H

#include <stddef.h>
#include <stdint.h>

#include "../kernels/offsets.h"

/* Stage 2: open a per-device container.
 *
 *   header   64 B   "GLT2" | ver 2 | flags 0x02 | reserved | expire u64 |
 *                   device_fp[32] | card_tag[16]
 *   nonce    12 B
 *   ct        n B   ChaCha20-Poly1305(kd, nonce, AAD = header, plaintext = GLP)
 *   tag      16 B
 *
 * `device_fp` is the 32-byte device fingerprint, `card_tag` the first 16 bytes
 * of SHA-256(card_key), and `kd` the per-device key the server derived as
 * HKDF-SHA256(master, salt=SHA256(card_key), info=device_fp).
 *
 * Three checks, and all three are needed:
 *
 *   1. the header is the AEAD's associated data, so a container minted for a
 *      different device, card or expiry fails to open instead of opening with
 *      the wrong values;
 *   2. the header's device_fp is compared against the caller's before the open,
 *      which is what rejects the case where the whole container *and* its key
 *      were copied to a second device;
 *   3. the header's card_tag is compared against the caller's.  The card is
 *      what the user paid for, so this is the check that keeps the licence gate
 *      from being the only thing standing in the way: a build with the login
 *      branch patched out still has no card_tag to offer and refuses to
 *      decrypt.  (The card is already in the key through the HKDF salt; this
 *      makes the dependency explicit and cheap to verify *before* any
 *      ciphertext is touched.)
 *
 * Returns 0 on match, -1 otherwise.  Same contract as the legacy reader:
 * missing fields keep whatever the caller pre-seeded, the matched release is
 * copied into `release_buf`, and the entry must pass the shared gate set
 * before it is accepted. */
int load_offsets_aead(const char *path, const char *release,
                      const uint8_t device_fp[32], const uint8_t card_tag[16],
                      const uint8_t kd[32], struct kernel_offsets *out,
                      char *release_buf, size_t release_buf_cap);
void gl_wipe_plaintext(void);

#ifdef GL_VERBOSE
/* Stage 1 container ("GLT1"): field values XORed with a keystream from a fixed
 * key compiled into the binary.  It defeats `strings` and nothing else -- a
 * disassembler recovers the table -- so only a debugging build carries it.
 * Not compiled into the release engine at all. */
int load_offsets_bin(const char *path, const char *release,
                     struct kernel_offsets *out, char *release_buf,
                     size_t release_buf_cap);
#endif

#endif
