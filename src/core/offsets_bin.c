/* Offsets container reader.
 *
 * Two containers, one parser:
 *
 *   GLT2 (stage 2, the only one a release engine accepts)
 *     A per-device AEAD container: the payload is sealed with the key the
 *     server derived for this handset, and the 48-byte header travels as the
 *     associated data.  Nothing in the binary can open it, so an APK lifted
 *     off a paying user's phone carries no usable table.
 *
 *   GLT1 (stage 1, GL_VERBOSE builds only)
 *     Field values XORed with a keystream from a compile-time key.  It exists
 *     so the table does not survive `strings`; a disassembler recovers it.
 *     Kept behind #ifdef because shipping it would undo stage 2.
 *
 * Both decode to the same body layout, so the parser, the field table and the
 * gate set below are shared verbatim -- the S1 validation rules are unchanged
 * from the plaintext importer, because they check the parsed struct, not the
 * bytes it came from.
 *
 *   header   64 B   "GLT2" | ver 2 | flags | reserved | expire u64 |
 *                   device_fp[32] | card_tag[16]
 *                   flags 0x02 = paid/permanent, 0x03 = trial (0x01 bit set:
 *                   the engine enforces `expire`, and only for trial)
 *   nonce    12 B
 *   ct        n B   ChaCha20-Poly1305(kd, nonce, AAD = header, plaintext = GLP)
 *   tag      16 B
 *
 * GLP body (little-endian), identical shape to the GLT1 body:
 *   header    8 B  "GLP1" | ver 1 | reserved | entry_count u16
 *   entry     8 B  release_hash u32 | field_count u16 | reserved u16
 *   field    10 B  id u16 | value u64
 *
 * GLT1 layout (little-endian), GL_VERBOSE only:
 *   header   16 B  "GLT1" | ver 1 | flags 0x01 | entry_count u16 | salt u64
 *   then the same entry/field records, with each value XORed by the ChaCha20
 *   keystream keyed on (salt, entry index). */

#include "offsets_bin.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "chacha20.h"

/* ---- 失败上报 ----------------------------------------------------------
 * 发布版**不叙述**它检查了什么：像 "bound to a different device" 这样的字符串
 * 既是设计说明书，也是逆向者的搜索锚点（在 .so 里搜字符串就能直接定位到对应
 * 的判断）。发布版只输出一个不透明错误码，码表在 docs/hardening.md 里，
 * **不在二进制里**。GL_VERBOSE（调试）构建保留原文，方便排障。
 *
 * 注意用宏而不是普通函数：宏在非 verbose 构建里**不展开** __VA_ARGS__，
 * 那些字符串字面量才真正不会进二进制。
 */
#ifndef GL_VERBOSE
static void gl_reject_code(unsigned code) {
  fprintf(stderr, "E%02X\n", code & 0xFFu);
}
#define GL_REJECT(code, ...) gl_reject_code(code)
#else
#include <stdarg.h>
static void gl_reject_verbose(const char *fmt, ...) {
  char buf[192];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  fprintf(stderr, "offsets REJECTED: %s\n", buf);
}
#define GL_REJECT(code, ...) gl_reject_verbose(__VA_ARGS__)
#endif

/* The gates used to live in the JSON importer and reported field *names*.
 * They now live here and report numeric ids, because the names were themselves
 * a leak: `strings` on the shipped .so listed all 26 of them. */

#define GLP_MAGIC "GLP1"
#define GLP_VERSION 1u
#define GLP_HDR_SIZE 8u

#define GLT2_MAGIC "GLT2"
#define GLT2_VERSION 2u
#define GLT2_FLAG_AEAD 0x02u
#define GLT2_FLAG_TRIAL 0x01u
#define GLT2_HDR_SIZE 64u
#define GLT2_DEVICE_FP_OFF 16u
#define GLT2_CARD_TAG_OFF 48u
#define GLT2_CARD_TAG_SIZE 16u
#define GLT2_NONCE_SIZE 12u
#define GLT2_TAG_SIZE 16u
#define GLT2_OVERHEAD (GLT2_HDR_SIZE + GLT2_NONCE_SIZE + GLT2_TAG_SIZE)

#define GLT_ENTRY_HDR_SIZE 8u
#define GLT_FIELD_SIZE 10u
#define GLT_MAX_ENTRIES 64u
#define GLT_MAX_FIELDS 64u
#define GLT_MAX_FILE (1u << 20)
#define GLP_MAX_BODY (1u << 18)

#ifdef GL_VERBOSE
#define GLT_MAGIC "GLT1"
#define GLT_VERSION 1u
#define GLT_FLAG_OBFUSCATED 0x01u
#define GLT_HDR_SIZE 16u

/* Stage-1 obfuscation key.  NOT a secret: it is compiled into the binary and a
 * disassembler will find it.  Present only in GL_VERBOSE builds, so the
 * release engine has no fixed key at all. */
static const uint8_t GLT_KEY[32] = {
    0x9e, 0x37, 0x4b, 0x12, 0x7c, 0xa5, 0x0d, 0x66, 0x21, 0x8f, 0xd3,
    0x5a, 0xb4, 0x70, 0x1c, 0xe9, 0x53, 0x2d, 0x88, 0xaf, 0x06, 0x91,
    0x4e, 0x3b, 0xc2, 0x65, 0x19, 0xf7, 0x08, 0xda, 0x72, 0x4d};
#endif

/* On-disk field ids.  Deliberately not the struct order, so the file layout
 * does not hand out the field semantics for free. */
enum glt_fid {
  GLT_FID_KERNEL_PHYS_LOAD = 0x11,
  GLT_FID_PSELECT_WAITER_SHIFT = 0x12,
  GLT_FID_INIT_TASK = 0x21,
  GLT_FID_INIT_CRED = 0x22,
  GLT_FID_ROOT_TASK_GROUP = 0x23,
  GLT_FID_SELINUX_ENFORCING = 0x24,
  GLT_FID_SELINUX_BLOB_SIZES = 0x25,
  GLT_FID_SECURITY_HOOK_HEADS = 0x26,
  GLT_FID_SLIDE_NFULNL_LOGGER = 0x27,
  GLT_FID_SLIDE_LOGGERS_0_1 = 0x28,
  GLT_FID_SLIDE_BOOT_ID = 0x29,
  GLT_FID_TP_SYS_EXIT_TP = 0x31,
  GLT_FID_TP_SYS_EXIT_FUNCS = 0x32,
  GLT_FID_TASK_PRIO = 0x41,
  GLT_FID_TASK_NORMAL_PRIO = 0x42,
  GLT_FID_TASK_SCHED_TASK_GROUP = 0x43,
  GLT_FID_TASK_PI_LOCK = 0x44,
  GLT_FID_TASK_PI_WAITERS = 0x45,
  GLT_FID_TASK_PI_TOP_TASK = 0x46,
  GLT_FID_TASK_PI_BLOCKED_ON = 0x47,
  GLT_FID_TASK_PID = 0x48,
  GLT_FID_TASK_TGID = 0x49,
  GLT_FID_TASK_ATOMIC_FLAGS = 0x4A,
  GLT_FID_TASK_REAL_CRED = 0x4B,
  GLT_FID_TASK_CRED = 0x4C,
  GLT_FID_TASK_COMM = 0x4D,
  GLT_FID_TASK_TASKS = 0x4E,
  GLT_FID_TASK_SECCOMP = 0x4F,
  GLT_FID_COMPACT_WAITER = 0x51,
  GLT_FID_MM_STRUCT_SZ = 0x52,
};

/* id -> destination field.  Width is the struct member width, not the encoded
 * one: every value travels as u64 on disk and is narrowed on store. */
static const struct {
  uint16_t id;
  uint16_t width;
  size_t off;
} g_glt_fields[] = {
    {GLT_FID_KERNEL_PHYS_LOAD, 8, offsetof(struct kernel_offsets, kernel_phys_load)},
    {GLT_FID_PSELECT_WAITER_SHIFT, 4, offsetof(struct kernel_offsets, pselect_waiter_shift)},
    {GLT_FID_INIT_TASK, 8, offsetof(struct kernel_offsets, off_init_task)},
    {GLT_FID_INIT_CRED, 8, offsetof(struct kernel_offsets, off_init_cred)},
    {GLT_FID_ROOT_TASK_GROUP, 8, offsetof(struct kernel_offsets, off_root_task_group)},
    {GLT_FID_SELINUX_ENFORCING, 8, offsetof(struct kernel_offsets, off_selinux_enforcing)},
    {GLT_FID_SELINUX_BLOB_SIZES, 8, offsetof(struct kernel_offsets, off_selinux_blob_sizes)},
    {GLT_FID_SECURITY_HOOK_HEADS, 8, offsetof(struct kernel_offsets, off_security_hook_heads)},
    {GLT_FID_SLIDE_NFULNL_LOGGER, 8, offsetof(struct kernel_offsets, off_slide_nfulnl_logger)},
    {GLT_FID_SLIDE_LOGGERS_0_1, 8, offsetof(struct kernel_offsets, off_slide_loggers_0_1)},
    {GLT_FID_SLIDE_BOOT_ID, 8, offsetof(struct kernel_offsets, off_slide_boot_id)},
    {GLT_FID_TP_SYS_EXIT_TP, 8, offsetof(struct kernel_offsets, off_tp_sys_exit_tp)},
    {GLT_FID_TP_SYS_EXIT_FUNCS, 8, offsetof(struct kernel_offsets, off_tp_sys_exit_funcs)},
    {GLT_FID_TASK_PRIO, 4, offsetof(struct kernel_offsets, task_prio)},
    {GLT_FID_TASK_NORMAL_PRIO, 4, offsetof(struct kernel_offsets, task_normal_prio)},
    {GLT_FID_TASK_SCHED_TASK_GROUP, 4, offsetof(struct kernel_offsets, task_sched_task_group)},
    {GLT_FID_TASK_PI_LOCK, 4, offsetof(struct kernel_offsets, task_pi_lock)},
    {GLT_FID_TASK_PI_WAITERS, 4, offsetof(struct kernel_offsets, task_pi_waiters)},
    {GLT_FID_TASK_PI_TOP_TASK, 4, offsetof(struct kernel_offsets, task_pi_top_task)},
    {GLT_FID_TASK_PI_BLOCKED_ON, 4, offsetof(struct kernel_offsets, task_pi_blocked_on)},
    {GLT_FID_TASK_PID, 4, offsetof(struct kernel_offsets, task_pid)},
    {GLT_FID_TASK_TGID, 4, offsetof(struct kernel_offsets, task_tgid)},
    {GLT_FID_TASK_ATOMIC_FLAGS, 4, offsetof(struct kernel_offsets, task_atomic_flags)},
    {GLT_FID_TASK_REAL_CRED, 4, offsetof(struct kernel_offsets, task_real_cred)},
    {GLT_FID_TASK_CRED, 4, offsetof(struct kernel_offsets, task_cred)},
    {GLT_FID_TASK_COMM, 4, offsetof(struct kernel_offsets, task_comm)},
    {GLT_FID_TASK_TASKS, 4, offsetof(struct kernel_offsets, task_tasks)},
    {GLT_FID_TASK_SECCOMP, 4, offsetof(struct kernel_offsets, task_seccomp)},
    {GLT_FID_COMPACT_WAITER, 1, offsetof(struct kernel_offsets, compact_waiter)},
    {GLT_FID_MM_STRUCT_SZ, 4, offsetof(struct kernel_offsets, mm_struct_sz)},
};

/* Byte-wise little-endian accessors.  The device is aarch64 and the offline
 * test host is x86_64; assembling from bytes keeps both bit-identical and
 * sidesteps unaligned loads on the 10-byte field records. */
static uint16_t rd16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) v = (v << 8) | (uint64_t)p[i];
  return v;
}

/* Same hash the packer uses; the release string itself never hits the file. */
static uint32_t glt_release_hash(const char *release) {
  uint32_t h = 0x811C9DC5u;
  for (const unsigned char *p = (const unsigned char *)release; *p; p++) {
    h ^= (uint32_t)*p;
    h *= 0x01000193u;
  }
  return h;
}

static void glt_store_field(struct kernel_offsets *out, uint16_t id,
                            uint64_t value) {
  for (size_t i = 0; i < sizeof(g_glt_fields) / sizeof(g_glt_fields[0]); i++) {
    if (g_glt_fields[i].id != id) continue;
    char *dst = (char *)out + g_glt_fields[i].off;
    switch (g_glt_fields[i].width) {
      case 1: {
        uint8_t v = (uint8_t)value;
        memcpy(dst, &v, sizeof(v));
        break;
      }
      case 4: {
        uint32_t v = (uint32_t)value;
        memcpy(dst, &v, sizeof(v));
        break;
      }
      default: {
        uint64_t v = value;
        memcpy(dst, &v, sizeof(v));
        break;
      }
    }
    return;
  }
  /* Unknown ids are ignored on purpose: a newer packer may add fields, and an
   * older engine must still be able to read the entry it understands. */
}

/* Read one field back out of the parsed table; 0 when the id is unknown. */
static uint64_t glt_load_field(const struct kernel_offsets *o, uint16_t id) {
  for (size_t i = 0; i < sizeof(g_glt_fields) / sizeof(g_glt_fields[0]); i++) {
    if (g_glt_fields[i].id != id) continue;
    const char *src = (const char *)o + g_glt_fields[i].off;
    switch (g_glt_fields[i].width) {
      case 1: {
        uint8_t v;
        memcpy(&v, src, sizeof(v));
        return v;
      }
      case 4: {
        uint32_t v;
        memcpy(&v, src, sizeof(v));
        return v;
      }
      default: {
        uint64_t v;
        memcpy(&v, src, sizeof(v));
        return v;
      }
    }
  }
  return 0;
}

/* Fields the engine dereferences; a 0 here would fall back to a 6.6 default. */
static const uint16_t GLT_GATE_CORE[] = {
    GLT_FID_INIT_TASK,           GLT_FID_INIT_CRED,
    GLT_FID_ROOT_TASK_GROUP,     GLT_FID_SELINUX_ENFORCING,
    GLT_FID_SELINUX_BLOB_SIZES,  GLT_FID_SECURITY_HOOK_HEADS,
    GLT_FID_SLIDE_NFULNL_LOGGER, GLT_FID_SLIDE_LOGGERS_0_1,
    GLT_FID_SLIDE_BOOT_ID,
};

/* Every struct_fields key the engine reads. */
static const uint16_t GLT_GATE_STRUCT[] = {
    GLT_FID_TASK_PRIO,             GLT_FID_TASK_NORMAL_PRIO,
    GLT_FID_TASK_SCHED_TASK_GROUP, GLT_FID_TASK_PI_LOCK,
    GLT_FID_TASK_PI_WAITERS,       GLT_FID_TASK_PI_TOP_TASK,
    GLT_FID_TASK_PI_BLOCKED_ON,    GLT_FID_TASK_PID,
    GLT_FID_TASK_TGID,             GLT_FID_TASK_ATOMIC_FLAGS,
    GLT_FID_TASK_REAL_CRED,        GLT_FID_TASK_CRED,
    GLT_FID_TASK_COMM,             GLT_FID_TASK_TASKS,
    GLT_FID_TASK_SECCOMP,
};

/* Reject an entry that is incomplete or internally inconsistent.
 *
 * A field the packer omits reaches the engine as 0, and runtime_struct_offsets.h
 * substitutes its 6.6 default.  On a 6.1 kernel that is not cosmetic: the 6.6
 * task_cred default (0x900) is exactly the 6.1 task_seccomp offset, so one
 * missing key silently redirects the credential write into the seccomp field
 * and the kernel panics (PANIC_ON_OOPS=y + PANIC_TIMEOUT=-1 -> hang plus pstore
 * record).  Refuse the whole entry instead, so the caller exits cleanly and no
 * guessed address ever reaches the kernel.
 *
 * Same rules the plaintext importer enforced; only the reporting changed, from
 * field names to ids (see the note near the includes). */
static int glt_validate(const struct kernel_offsets *o, const char *release) {
  unsigned maj = 0, min = 0;

  if (!o->uname_r || strcmp(o->uname_r, release) != 0) {
    GL_REJECT(0x0D, "release mismatch for %s\n", release);
    return -1;
  }
  if (sscanf(release, "%u.%u", &maj, &min) != 2) {
    GL_REJECT(0x0D, "unparsable release %s\n", release);
    return -1;
  }

  for (size_t i = 0; i < sizeof(GLT_GATE_CORE) / sizeof(GLT_GATE_CORE[0]); i++) {
    if (!glt_load_field(o, GLT_GATE_CORE[i])) {
      GL_REJECT(0x0C, "field 0x%02x missing/zero\n",
                (unsigned)GLT_GATE_CORE[i]);
      return -1;
    }
  }

  /* vr.ko neutralize needs one of the two tracepoint offsets; when both are
   * present they must sit TRACEPOINT_FUNCS_OFF apart (0x40 on 6.1, 0x48 from
   * 6.6 on) -- the same rule main.c applies when it builds the write address. */
  {
    const uint64_t tp = o->off_tp_sys_exit_tp;
    const uint64_t funcs = o->off_tp_sys_exit_funcs;
    if (!tp && !funcs) {
      GL_REJECT(0x0C,
                "both tracepoint fields missing/zero (vr.ko "
                "would stay armed and kill the late-loaded ksud)\n");
      return -1;
    }
    if (tp && funcs) {
      const uint64_t delta = funcs - tp;
      const uint64_t expect =
          (maj > 6 || (maj == 6 && min >= 6)) ? 0x48u : 0x40u;
      if (delta != expect) {
        GL_REJECT(0x0C,
                  "tracepoint delta 0x%llx, expected 0x%llx "
                  "for %s\n",
                  (unsigned long long)delta, (unsigned long long)expect, release);
        return -1;
      }
    }
  }

  for (size_t i = 0; i < sizeof(GLT_GATE_STRUCT) / sizeof(GLT_GATE_STRUCT[0]);
       i++) {
    if (!glt_load_field(o, GLT_GATE_STRUCT[i])) {
      GL_REJECT(0x0C, "field 0x%02x missing/zero\n",
                (unsigned)GLT_GATE_STRUCT[i]);
      return -1;
    }
  }

  if (maj == 6 && min == 1 && o->compact_waiter != 1) {
    GL_REJECT(0x0C,
              "field 0x51=%u; 6.1 requires 1 (a 0 selects "
              "the 6.6 rb_node waiter layout and the route misses)\n",
              (unsigned)o->compact_waiter);
    return -1;
  }
  if (!o->mm_struct_sz) {
    GL_REJECT(0x0C, "field 0x52 missing/zero\n");
    return -1;
  }
  return 0;
}

static uint8_t g_file_buf[GLT_MAX_FILE];
static uint8_t g_plain_buf[GLP_MAX_BODY];

/* Scrub the decrypted plaintext table and the raw container bytes.  Called
 * before a rooted child parks (its memory copy outlives the run) and at the
 * end of the parent's run: without this the whole plaintext offset table sits
 * in a `for(;;) pause()` process until reboot. */
void gl_wipe_plaintext(void) {
  memset(g_plain_buf, 0, sizeof(g_plain_buf));
  memset(g_file_buf, 0, sizeof(g_file_buf));
}

/* Walk the entry/field records that both containers decode to.
 *
 * `ks_key` is NULL for GLT2 (the AEAD already protected the values) and the
 * stage-1 obfuscation key for GLT1, in which case `salt` seeds the per-entry
 * nonce.  This is the only place the two formats differ. */
static int glp_parse(const uint8_t *buf, size_t len, unsigned entry_count,
                     const char *release, const uint8_t *ks_key, uint64_t salt,
                     struct kernel_offsets *out, char *release_buf,
                     size_t release_buf_cap) {
  const uint32_t want = glt_release_hash(release);
  size_t pos = 0;

  for (unsigned e = 0; e < entry_count; e++) {
    if (pos + GLT_ENTRY_HDR_SIZE > len) {
      GL_REJECT(0x0A, "truncated entry header\n");
      return -1;
    }
    const uint8_t *eh = buf + pos;
    const uint32_t rel_hash = rd32(eh);
    const unsigned field_count = rd16(eh + 4);
    pos += GLT_ENTRY_HDR_SIZE;
    if (field_count > GLT_MAX_FIELDS ||
        pos + (size_t)field_count * GLT_FIELD_SIZE > len) {
      GL_REJECT(0x0A, "truncated field list\n");
      return -1;
    }
    if (rel_hash != want) {
      pos += (size_t)field_count * GLT_FIELD_SIZE;
      continue;
    }

    uint8_t ks[GLT_MAX_FIELDS * 8];
    if (ks_key) {
      /* Stage 1: the keystream is per entry so identical values in two entries
       * do not share ciphertext bytes. */
      uint8_t nonce[12];
      nonce[0] = (uint8_t)(e);
      nonce[1] = (uint8_t)(e >> 8);
      nonce[2] = (uint8_t)(e >> 16);
      nonce[3] = (uint8_t)(e >> 24);
      for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(salt >> (8 * i));
      chacha20_xor(ks, NULL, (size_t)field_count * 8, ks_key, nonce);
    }

    for (unsigned f = 0; f < field_count; f++) {
      const uint8_t *fp = buf + pos + (size_t)f * GLT_FIELD_SIZE;
      const uint16_t id = rd16(fp);
      const uint64_t raw = rd64(fp + 2);
      const uint64_t value = ks_key ? (raw ^ rd64(ks + (size_t)f * 8)) : raw;
      glt_store_field(out, id, value);
    }
    memset(ks, 0, sizeof(ks));

    if (strlen(release) >= release_buf_cap) return -1;
    strcpy(release_buf, release);
    out->uname_r = release_buf;
    return glt_validate(out, release);
  }

  GL_REJECT(0x0B, "no entry for release %s\n", release);
  return -1;
}

static int read_all(const char *path, ssize_t *out_len) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    GL_REJECT(0x01, "cannot open %s\n", path);
    return -1;
  }
  ssize_t n = read(fd, g_file_buf, sizeof(g_file_buf));
  /* A container larger than the buffer used to be truncated silently and then
   * rejected further down for a length mismatch -- correct outcome, misleading
   * reason.  Probe for one more byte so "too large" is reported as itself. */
  if (n == (ssize_t)sizeof(g_file_buf)) {
    uint8_t extra;
    if (read(fd, &extra, 1) > 0) {
      close(fd);
      GL_REJECT(0x01, "container larger than %zu bytes\n",
                sizeof(g_file_buf));
      return -1;
    }
  }
  close(fd);
  if (n <= 0) {
    GL_REJECT(0x01, "empty or unreadable %s\n", path);
    return -1;
  }
  *out_len = n;
  return 0;
}

int load_offsets_aead(const char *path, const char *release,
                      const uint8_t device_fp[32], const uint8_t card_tag[16],
                      const uint8_t kd[32], struct kernel_offsets *out,
                      char *release_buf, size_t release_buf_cap) {
  ssize_t n = 0;
  if (read_all(path, &n) != 0) return -1;
  if (n < (ssize_t)GLT2_OVERHEAD) {
    GL_REJECT(0x02, "shorter than GLT2 overhead\n");
    return -1;
  }

  const uint8_t *hdr = g_file_buf;
  if (memcmp(hdr, GLT2_MAGIC, 4) != 0) {
    /* A stage-1 file, a hand-made file, or a truncated one.  Refuse rather
     * than fall back: the whole point of stage 2 is that this engine has no
     * key of its own to open anything else with. */
    GL_REJECT(0x03,
              "not a GLT2 container (activation "
              "payload required)\n");
    return -1;
  }
  if (hdr[4] != GLT2_VERSION) {
    GL_REJECT(0x04, "version %u unsupported\n",
              (unsigned)hdr[4]);
    return -1;
  }
  if (!(hdr[5] & GLT2_FLAG_AEAD)) {
    GL_REJECT(0x05, "payload not sealed\n");
    return -1;
  }
  /* Checked before the open as well as through the AAD: this is what catches a
   * container *and* its key being copied onto a second device, which the AEAD
   * alone would happily open. */
  if (memcmp(hdr + GLT2_DEVICE_FP_OFF, device_fp, 32) != 0) {
    GL_REJECT(0x06,
              "bound to a different device\n");
    return -1;
  }
  /* The licence check that survives a patched login screen.  `card_tag` is
   * AAD-covered, so it cannot be rewritten without breaking the tag, and a
   * build that skipped activation has no card to derive it from. */
  if (memcmp(hdr + GLT2_CARD_TAG_OFF, card_tag, GLT2_CARD_TAG_SIZE) != 0) {
    GL_REJECT(0x07,
              "card key does not match this payload\n");
    return -1;
  }

  const size_t ct_len = (size_t)n - GLT2_OVERHEAD;
  if (ct_len == 0 || ct_len > sizeof(g_plain_buf)) {
    GL_REJECT(0x02, "bad payload length\n");
    return -1;
  }
  const uint8_t *nonce = hdr + GLT2_HDR_SIZE;
  const uint8_t *ct = nonce + GLT2_NONCE_SIZE;
  const uint8_t *tag = ct + ct_len;

  if (chacha20_poly1305_decrypt(g_plain_buf, ct, ct_len, tag, hdr,
                                GLT2_HDR_SIZE, kd, nonce) != 0) {
    GL_REJECT(0x08,
              "authentication failed (wrong key, "
              "tampered payload, or a header from another device/expiry)\n");
    return -1;
  }

  if (ct_len < GLP_HDR_SIZE || memcmp(g_plain_buf, GLP_MAGIC, 4) != 0) {
    GL_REJECT(0x03, "bad payload magic\n");
    return -1;
  }
  if (g_plain_buf[4] != GLP_VERSION) {
    GL_REJECT(0x04, "payload version %u\n",
              (unsigned)g_plain_buf[4]);
    return -1;
  }
  const unsigned entry_count = rd16(g_plain_buf + 6);
  if (entry_count == 0 || entry_count > GLT_MAX_ENTRIES) {
    GL_REJECT(0x09, "entry_count=%u\n",
              entry_count);
    return -1;
  }

  /* `expire` (header bytes 8..15) is authenticated by the AAD, so it cannot be
   * extended locally.  Whether it is *enforced* depends on the container kind:
   *
   *   flags & GLT2_FLAG_TRIAL -> trial container: enforce.  This is what stops
   *       a payload copied out of the app's private directory from working once
   *       the trial window closes.
   *   otherwise               -> paid/permanent container: do NOT enforce.  The
   *       server is the authority on a paid licence and a handset with a wrong
   *       clock must not lose it.
   *
   * Reading the wall clock here is deliberate.  The trial window is a product
   * boundary, not a security boundary: the server-side clock is what actually
   * bounds it (the app re-checks against the server on every launch and clears
   * the payload).  This check only raises the cost of lifting the payload. */
  if (hdr[5] & GLT2_FLAG_TRIAL) {
    const uint64_t expire = rd64(hdr + 8);
    const time_t now = time(NULL);
    if (expire == 0 || now == (time_t)-1 || (uint64_t)now > expire) {
      GL_REJECT(0x0E, "trial window closed\n");
      return -1;
    }
  }
  return glp_parse(g_plain_buf + GLP_HDR_SIZE, ct_len - GLP_HDR_SIZE,
                   entry_count, release, NULL, 0, out, release_buf,
                   release_buf_cap);
}

#ifdef GL_VERBOSE
int load_offsets_bin(const char *path, const char *release,
                     struct kernel_offsets *out, char *release_buf,
                     size_t release_buf_cap) {
  ssize_t n = 0;
  if (read_all(path, &n) != 0) return -1;
  if (n < (ssize_t)GLT_HDR_SIZE) return -1;

  const uint8_t *buf = g_file_buf;
  if (memcmp(buf, GLT_MAGIC, 4) != 0) {
    GL_REJECT(0x03, "bad magic\n");
    return -1;
  }
  if (buf[4] != GLT_VERSION) {
    GL_REJECT(0x04, "version %u unsupported\n",
              (unsigned)buf[4]);
    return -1;
  }
  if (!(buf[5] & GLT_FLAG_OBFUSCATED)) {
    GL_REJECT(0x05, "payload not obfuscated\n");
    return -1;
  }
  const unsigned entry_count = rd16(buf + 6);
  const uint64_t salt = rd64(buf + 8);
  if (entry_count == 0 || entry_count > GLT_MAX_ENTRIES) {
    GL_REJECT(0x09, "entry_count=%u\n", entry_count);
    return -1;
  }
  return glp_parse(buf + GLT_HDR_SIZE, (size_t)n - GLT_HDR_SIZE, entry_count,
                   release, GLT_KEY, salt, out, release_buf, release_buf_cap);
}
#endif
