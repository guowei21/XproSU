/* 6.1.57-android14-11-maybe-dirty */
/* Values: upstream offsets-import-r15 6.1.57 entry; symbols EXACT vs
 reference/kernel-57/sym_6157.txt (device kallsyms via ksg.py) */
/* Emitted by gen_builtin.py from offsets-57+124+145-combined.json;
 * struct layout via STRUCT_OFFSETS_6_1 (verified == json struct_fields). */

OFFSETS_ENTRY(
    "6.1.57-android14-11-maybe-dirty",
    STRUCT_OFFSETS_6_1,
    .kernel_phys_load = 0x80000000,   /* MTK DRAM base */
    .pselect_waiter_shift = 1,
    .off_init_task = 0x0205f0c0,  /* init_task */
    .off_init_cred = 0x02072f10,  /* init_cred */
    .off_root_task_group = 0x02285700,  /* root_task_group */
    .off_selinux_enforcing = 0x023b8588,  /* selinux_enforcing (selinux_state) */
    .off_security_hook_heads = 0x015d0948,  /* security_hook_heads */
    .off_selinux_blob_sizes = 0x015d1050,  /* selinux_blob_sizes */
    .off_slide_nfulnl_logger = 0x02052cd8,  /* slide: nfulnl_logger */
    .off_slide_loggers_0_1 = 0x02052c28,  /* slide: loggers[0..1] */
    .off_slide_boot_id = 0x023d9910,  /* slide: boot_id (sysctl) */
    .off_tp_sys_exit_tp = 0x022320a0,  /* vr: __tracepoint_sys_exit */
    .off_tp_sys_exit_funcs = 0x022320e0,  /* vr: funcs (tp + 0x40, 6.1) */
),
