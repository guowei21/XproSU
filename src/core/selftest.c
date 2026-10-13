/* Verification entry point (see selftest.h).
 *
 * Two modes:
 *
 *   ghostlock --crypto-selftest
 *       RFC 8439 / RFC 5869 self-tests plus a fixed AEAD vector printed as
 *       hex, so the C, Python and Kotlin implementations can be diffed
 *       byte-for-byte without trusting anybody's memory of the RFC.
 *
 *   ghostlock --offsets-verify <file> <kd_hex> <device_fp_hex>
 *       Runs the production container path end to end: GLT2 header check,
 *       device-fingerprint comparison, AEAD open, GLP parse and the S1 gate
 *       set.  Prints the parsed values, which is the only way to prove the
 *       encrypted path still yields the same table the plaintext path did. */
#include "selftest.h"

/* Gated on GL_VERBOSE: the --offsets-verify labels below name struct fields,
 * and field names in the binary are exactly what stage 1 removed (leak #2 in
 * ENCRYPTION-PLAN.md section 1).  Verification is a QA activity, so the
 * release engine carries neither the labels nor the entry point; the AEAD and
 * parse code they exercise is the same translation unit either way. */
#ifdef GL_VERBOSE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chacha20.h"
#include "offsets_bin.h"
#include "poly1305.h"

static int hex_nibble(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Parse exactly 2*n hex digits.  Returns 0 on success. */
static int unhex(const char *s, uint8_t *out, size_t n) {
  if (!s) return -1;
  for (size_t i = 0; i < n; i++) {
    int hi = hex_nibble((unsigned char)s[2 * i]);
    int lo = hex_nibble((unsigned char)s[2 * i + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return s[2 * n] == '\0' ? 0 : -1;
}

static void print_hex(const char *label, const uint8_t *p, size_t n) {
  printf("%s=", label);
  for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
  printf("\n");
}

/* FNV-1a-64 over the decrypted body; the packer prints the same value. */
static uint64_t fnv1a64(const uint8_t *p, size_t n) {
  uint64_t h = 0xcbf29ce484222325ull;
  for (size_t i = 0; i < n; i++) {
    h ^= (uint64_t)p[i];
    h *= 0x100000001b3ull;
  }
  return h;
}

static int crypto_selftest(void) {
  int a = chacha20_selftest();
  int b = chacha20_poly1305_selftest();
  int c = poly1305_selftest();

  printf("chacha20_selftest        = %d\n", a);
  printf("poly1305_selftest        = %d\n", c);
  printf("chacha20_poly1305_selftest = %d\n", b);

  /* Fixed cross-check vector.  Deliberately not an RFC case: the point is to
   * diff C against the Python and Kotlin implementations on a input that is
   * cheap to reproduce in all three. */
  {
    uint8_t key[32], nonce[12], pt[100], ct[100], tag[16], back[100];
    const uint8_t aad[6] = {'g', 'l', '-', 'a', 'a', 'd'};
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(nonce); i++) nonce[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i * 3 + 1);

    chacha20_poly1305_encrypt(ct, tag, pt, sizeof(pt), aad, sizeof(aad), key,
                              nonce);
    print_hex("vector.ct", ct, sizeof(ct));
    print_hex("vector.tag", tag, sizeof(tag));
    printf("vector.pt_fnv64=%016llx\n", (unsigned long long)fnv1a64(pt, sizeof(pt)));

    int rc = chacha20_poly1305_decrypt(back, ct, sizeof(ct), tag, aad,
                                       sizeof(aad), key, nonce);
    printf("vector.roundtrip=%d\n", rc);
    if (rc == 0 && memcmp(back, pt, sizeof(pt)) != 0) rc = -100;
  }

  return (a == 0 && b == 0 && c == 0) ? 0 : 1;
}

static int offsets_verify(int argc, char **argv) {
  if (argc < 6) {
    fprintf(stderr,
            "usage: ghostlock --offsets-verify <file> <kd_hex> <device_fp_hex> "
            "<card_tag_hex>\n");
    return 2;
  }
  uint8_t kd[32], fp[32], card_tag[16];
  if (unhex(argv[3], kd, sizeof(kd)) != 0) {
    fprintf(stderr, "bad kd hex (need 64 chars)\n");
    return 2;
  }
  if (unhex(argv[4], fp, sizeof(fp)) != 0) {
    fprintf(stderr, "bad device_fp hex (need 64 chars)\n");
    return 2;
  }
  if (unhex(argv[5], card_tag, sizeof(card_tag)) != 0) {
    fprintf(stderr, "bad card_tag hex (need 32 chars)\n");
    return 2;
  }

  static struct kernel_offsets o;
  static char rel[128];
  memset(&o, 0, sizeof(o));
  memset(rel, 0, sizeof(rel));

  /* The release is taken from the environment so the command line stays short;
   * absent it, the 6.1.145 entry is used. */
  const char *release = getenv("GHOSTLOCK_RELEASE");
  if (!release || !*release) release = "6.1.145-android14-11-maybe-dirty";

  printf("verify.release=%s\n", release);
  print_hex("verify.kd", kd, sizeof(kd));
  print_hex("verify.device_fp", fp, sizeof(fp));
  print_hex("verify.card_tag", card_tag, sizeof(card_tag));

  int rc = load_offsets_aead(argv[2], release, fp, card_tag, kd, &o, rel,
                             sizeof(rel));
  printf("verify.load=%d\n", rc);
  if (rc != 0) return 1;

  printf("verify.uname=%s\n", o.uname_r ? o.uname_r : "(null)");
  printf("verify.kernel_phys_load=0x%llx\n", (unsigned long long)o.kernel_phys_load);
  printf("verify.off_init_task=0x%llx\n", (unsigned long long)o.off_init_task);
  printf("verify.off_init_cred=0x%llx\n", (unsigned long long)o.off_init_cred);
  printf("verify.off_root_task_group=0x%llx\n", (unsigned long long)o.off_root_task_group);
  printf("verify.off_security_hook_heads=0x%llx\n", (unsigned long long)o.off_security_hook_heads);
  printf("verify.off_tp_sys_exit_tp=0x%llx\n", (unsigned long long)o.off_tp_sys_exit_tp);
  printf("verify.off_tp_sys_exit_funcs=0x%llx\n", (unsigned long long)o.off_tp_sys_exit_funcs);
  printf("verify.task_prio=0x%x\n", (unsigned)o.task_prio);
  printf("verify.task_cred=0x%x\n", (unsigned)o.task_cred);
  printf("verify.task_seccomp=0x%x\n", (unsigned)o.task_seccomp);
  printf("verify.compact_waiter=%u\n", (unsigned)o.compact_waiter);
  printf("verify.mm_struct_sz=0x%x\n", (unsigned)o.mm_struct_sz);
  printf("verify.ok\n");
  return 0;
}

int gl_selftest_main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "--crypto-selftest") == 0) {
    return crypto_selftest();
  }
  if (argc > 1 && strcmp(argv[1], "--offsets-verify") == 0) {
    return offsets_verify(argc, argv);
  }
  fprintf(stderr, "unknown selftest mode\n");
  return 2;
}

#endif /* GL_VERBOSE */
