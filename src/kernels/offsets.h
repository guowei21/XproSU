#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdint.h>

struct kernel_offsets {
  const char *uname_r;
  /* Bootloader-selected physical load address; 0 uses target.h. */
  uint64_t kernel_phys_load;
  /* pselect fd_set waiter word shift; 0 uses target.h default. */
  int pselect_waiter_shift;
  uint64_t off_init_task, off_init_cred;
  uint64_t off_root_task_group, off_selinux_enforcing;
  uint64_t off_selinux_blob_sizes, off_security_hook_heads;
  uint64_t off_slide_nfulnl_logger, off_slide_loggers_0_1, off_slide_boot_id;

  /* vr.ko global neutralize: offset of __tracepoint_sys_exit from
   * kimage_text_base. The funcs pointer lives at +TRACEPOINT_FUNCS_OFF (0x40 on
   * 6.1, 0x48 on 6.6); zeroing that field disables the sys_exit probe globally so
   * vr.ko stops killing KernelSU/ksud processes.  0 = skip. */
  uint64_t off_tp_sys_exit_tp;
  /* Legacy: pre-added absolute offset of the funcs field itself. Kept for
   * offsets.json compatibility; when set it must already include the
   * TRACEPOINT_FUNCS_OFF term. */
  uint64_t off_tp_sys_exit_funcs;

  /* Per-kernel struct offsets; 0 uses target.h defaults. */
  uint32_t task_prio, task_normal_prio, task_sched_task_group;
  uint32_t task_pi_lock, task_pi_waiters, task_pi_top_task, task_pi_blocked_on;
  uint32_t task_pid, task_tgid, task_atomic_flags;
  uint32_t task_real_cred, task_cred, task_comm, task_tasks, task_seccomp;

  /* rt_mutex_waiter layout: 0 = 6.6 rb_node, 1 = 6.1 compact tree_entry */
  uint8_t compact_waiter;
  /* mm_struct SLUB stride; 0 uses target.h default (6.6 GKI 0x500).
   * android14-6.1 uses 0x400 (BTF reports 0x3c0). */
  uint32_t mm_struct_sz;
  uint32_t _pad[3];
};

#define OFFSETS_ENTRY(uname, ...) { .uname_r = uname, __VA_ARGS__ }

#define STRUCT_OFFSETS_6_1                                                     \
  .task_prio = 0x84, .task_normal_prio = 0x8C, .task_sched_task_group = 0x348, \
  .task_pi_lock = 0x924, .task_pi_waiters = 0x938,                             \
  .task_pi_top_task = 0x948, .task_pi_blocked_on = 0x950,                      \
  .task_pid = 0x630, .task_tgid = 0x634,                                       \
  .task_atomic_flags = 0x5F0, .task_real_cred = 0x830, .task_cred = 0x838,     \
  .task_comm = 0x848, .task_tasks = 0x550, .task_seccomp = 0x900,              \
  .compact_waiter = 1, .mm_struct_sz = 0x400

#define STRUCT_OFFSETS_6_12                                                    \
  .task_prio = 0x94, .task_normal_prio = 0x9C, .task_sched_task_group = 0x420, \
  .task_pi_lock = 0x9EC, .task_pi_waiters = 0xA00,                             \
  .task_pi_top_task = 0xA10, .task_pi_blocked_on = 0xA18,                      \
  .task_pid = 0x708, .task_tgid = 0x70C,                                       \
  .task_atomic_flags = 0x6C8, .task_real_cred = 0x8F8, .task_cred = 0x900,     \
  .task_comm = 0x910, .task_tasks = 0x638, .task_seccomp = 0x9C8

#define STRUCT_OFFSETS_6_6                                                     \
  .task_prio = 0x84, .task_normal_prio = 0x8C, .task_sched_task_group = 0x348, \
  .task_pi_lock = 0x90C, .task_pi_waiters = 0x920,                             \
  .task_pi_top_task = 0x930, .task_pi_blocked_on = 0x938,                      \
  .task_pid = 0x618, .task_tgid = 0x61C,                                       \
  .task_atomic_flags = 0x5D8, .task_real_cred = 0x818, .task_cred = 0x820,     \
  .task_comm = 0x830, .task_tasks = 0x550, .task_seccomp = 0x8E8

static const struct kernel_offsets known_offsets[] = {
/* Add new kernels by creating src/kernels/<uname-release>/offsets.h */
/*
 * Left empty on purpose.  A built-in entry is matched on `uname -r` alone, and
 * that string is not a device identity: the same release runs on different
 * vendor vmlinux images where the same symbol lands elsewhere.  Offsets come
 * from the shipped container, which matches on release + build (`uname -v`) and
 * refuses rather than guesses; see load_offsets_json().
 */
  { .uname_r = NULL }
};

#endif
