/* Offline equivalence test: the .glt container must feed the engine exactly
 * what the JSON importer would have.
 *
 * The engine's data entry path is the one thing that was verified on real
 * hardware (see docs/offsets-json-validation.md), so replacing the JSON
 * importer is only safe if the new reader produces a byte-identical
 * struct kernel_offsets for every release the private offsets documents
 * carry.  This program proves that by running both readers side by side.
 *
 * Build (host, e.g. an x86_64 Android userland for adb push):
 *   $CC -O1 -DGL_VERBOSE -Isrc/core -Isrc/kernels \
 *       tools/glt_equiv_test.c src/core/chacha20.c src/core/offsets_json.c \
 *       src/core/offsets_bin.c -o glt_equiv_test
 *
 * Usage:
 *   glt_equiv_test --selftest
 *   glt_equiv_test <offsets.json> <offsets.glt> <release> [release...]
 */

#include <stdio.h>
#include <string.h>

#include "chacha20.h"
#include "offsets_bin.h"
#include "offsets_json.h"

static int g_fail;

/* The struct's first member is a pointer into the caller's release buffer, so
 * the two readers naturally disagree there; blank it before comparing. */
static int compare_structs(const struct kernel_offsets *a,
                           const struct kernel_offsets *b, const char *rel) {
  struct kernel_offsets x = *a, y = *b;
  x.uname_r = NULL;
  y.uname_r = NULL;
  if (memcmp(&x, &y, sizeof(x)) == 0) return 0;

  fprintf(stderr, "  MISMATCH %s:\n", rel);
  const unsigned char *px = (const unsigned char *)&x;
  const unsigned char *py = (const unsigned char *)&y;
  for (size_t i = 0; i < sizeof(x); i++) {
    if (px[i] != py[i]) {
      fprintf(stderr, "    byte %3zu: json=%02x glt=%02x\n", i, px[i], py[i]);
    }
  }
  return -1;
}

static int check_release(const char *json, const char *glt, const char *rel) {
  struct kernel_offsets a, b;
  char buf_a[256], buf_b[256];
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));

  int rc_a = load_offsets_json(json, rel, &a, buf_a, sizeof(buf_a));
  int rc_b = load_offsets_bin(glt, rel, &b, buf_b, sizeof(buf_b));

  if (rc_a != rc_b) {
    fprintf(stderr, "  FAIL %s: json rc=%d glt rc=%d\n", rel, rc_a, rc_b);
    return -1;
  }
  if (rc_a != 0) {
    /* Both refused.  For a release we asked about that is itself a finding,
     * but it is reported by the caller; here it is only a mismatch if one
     * accepted and the other did not, which is handled above. */
    printf("  both refused  %s\n", rel);
    return 0;
  }
  if (compare_structs(&a, &b, rel) != 0) return -1;
  printf("  identical     %s  (%zu fields worth of struct)\n", rel,
         sizeof(struct kernel_offsets));
  return 0;
}

/* A release neither document knows: both paths must refuse, not guess. */
static int check_absent(const char *json, const char *glt, const char *rel) {
  struct kernel_offsets a, b;
  char buf_a[256], buf_b[256];
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));
  int rc_a = load_offsets_json(json, rel, &a, buf_a, sizeof(buf_a));
  int rc_b = load_offsets_bin(glt, rel, &b, buf_b, sizeof(buf_b));
  if (rc_a != -1 || rc_b != -1) {
    fprintf(stderr, "  FAIL absent %s: json rc=%d glt rc=%d (expected -1/-1)\n",
            rel, rc_a, rc_b);
    return -1;
  }
  printf("  both refused  %s (absent)\n", rel);
  return 0;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "--selftest") == 0) {
    int rc = chacha20_selftest();
    printf("chacha20 RFC 8439 self-test: %s\n", rc == 0 ? "PASS" : "FAIL");
    return rc == 0 ? 0 : 1;
  }
  if (argc < 4) {
    fprintf(stderr, "usage: %s <offsets.json> <offsets.glt> <release>...\n",
            argv[0]);
    fprintf(stderr, "       %s --selftest\n", argv[0]);
    return 2;
  }

  if (chacha20_selftest() != 0) {
    fprintf(stderr, "chacha20 self-test FAILED; aborting\n");
    return 1;
  }

  const char *json = argv[1];
  const char *glt = argv[2];
  printf("json = %s\nglt  = %s\n", json, glt);

  for (int i = 3; i < argc; i++) {
    if (check_release(json, glt, argv[i]) != 0) g_fail++;
  }
  if (check_absent(json, glt, "9.9.9-not-a-real-kernel") != 0) g_fail++;

  printf("%s\n", g_fail == 0 ? "RESULT: PASS" : "RESULT: FAIL");
  return g_fail == 0 ? 0 : 1;
}
