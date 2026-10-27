/* 6.1.124-android14-11-maybe-dirty */
/* Values: boot.img (PD2324) kallsyms manual parse, 112084 syms;
 device AUDIT img_off match + full W1-W3 & vr.ko success 2026-10-08 */
/* Emitted by gen_builtin.py from offsets-57+124+145-combined.json;
 * struct layout via STRUCT_OFFSETS_6_1 (verified == json struct_fields). */

OFFSETS_ENTRY(
    "6.1.124-android14-11-maybe-dirty",
    STRUCT_OFFSETS_6_1,
    .kernel_phys_load = 0x80000000,   /* MTK DRAM base */
    .pselect_waiter_shift = 1,
    .off_init_task = 0x020efac0,  /* init_task */
    .off_init_cred = 0x021023b0,  /* init_cred */
    .off_root_task_group = 0x02328740,  /* root_task_group */
    .off_selinux_enforcing = 0x0245d000,  /* selinux_enforcing (selinux_state) */
    .off_security_hook_heads = 0x0161bb48,  /* security_hook_heads */
    .off_selinux_blob_sizes = 0x0161c258,  /* selinux_blob_sizes */
    .off_slide_nfulnl_logger = 0x020e2e78,  /* slide: nfulnl_logger */
    .off_slide_loggers_0_1 = 0x020e2dc8,  /* slide: loggers[0..1] */
    .off_slide_boot_id = 0x0247e610,  /* slide: boot_id (sysctl) */
    .off_tp_sys_exit_tp = 0x022d19c0,  /* vr: __tracepoint_sys_exit */
    .off_tp_sys_exit_funcs = 0x022d1a00,  /* vr: funcs (tp + 0x40, 6.1) */
),
