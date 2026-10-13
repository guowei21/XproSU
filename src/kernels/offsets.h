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

/* There is deliberately no built-in table here any more.
 *
 * The three device tables that used to live in src/kernels/<release>/offsets.h
 * put every offset value into .rodata as a plaintext u64, so `strings` on the
 * shipped APK reproduced the whole table without any reversing.  The runtime
 * now takes its offsets from <GHOSTLOCK_HOME>/offsets.glt: a container that
 * addresses fields by numeric id and XORs the values with a ChaCha20 keystream
 * (src/core/offsets_bin.c, tools/pack_offsets.py,
 * docs/offsets-binary-format.md).
 *
 * Do not reintroduce a built-in table "just as a fallback".  A field the
 * packer omits reaches the engine as 0, runtime_struct_offsets.h substitutes
 * the 6.6 default, and on a 6.1 kernel the 6.6 task_cred default (0x900) is
 * exactly task_seccomp -- the credential write would land in the seccomp field
 * and the kernel would panic (PANIC_ON_OOPS=y + PANIC_TIMEOUT=-1).  Refusing
 * to run without a blob is the safe behaviour. */

#endif
