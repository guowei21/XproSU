/* 6.1.145-android14-11-maybe-dirty */
/* Values: device kallsyms_full.txt (_text=ffffffe214600000) + upstream
 R15 table; full run success 2026-10-08 (exit 0, KernelSU ready) */
/* Emitted by gen_builtin.py from offsets-57+124+145-combined.json;
 * struct layout via STRUCT_OFFSETS_6_1 (verified == json struct_fields). */

OFFSETS_ENTRY(
    "6.1.145-android14-11-maybe-dirty",
    STRUCT_OFFSETS_6_1,
    .kernel_phys_load = 0x80000000,   /* MTK DRAM base */
    .pselect_waiter_shift = 1,
    .off_init_task = 0x0210fb40,  /* init_task */
    .off_init_cred = 0x02122430,  /* init_cred */
    .off_root_task_group = 0x0234a740,  /* root_task_group */
    .off_selinux_enforcing = 0x0247fb98,  /* selinux_enforcing (selinux_state) */
    .off_security_hook_heads = 0x01632cd0,  /* security_hook_heads */
    .off_selinux_blob_sizes = 0x016333e0,  /* selinux_blob_sizes */
    .off_slide_nfulnl_logger = 0x02102f00,  /* slide: nfulnl_logger */
    .off_slide_loggers_0_1 = 0x022d4e28,  /* slide: loggers[0..1] */
    .off_slide_boot_id = 0x02276810,  /* slide: boot_id (sysctl) */
    .off_tp_sys_exit_tp = 0x022f3600,  /* vr: __tracepoint_sys_exit */
    .off_tp_sys_exit_funcs = 0x022f3640,  /* vr: funcs (tp + 0x40, 6.1) */
),
