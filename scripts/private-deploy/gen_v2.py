#!/usr/bin/env python3
# 6.1.124 v2 偏移生成器（路径可移植版）
# 按 6.1.57 适配工程（build_offsets.py / finalize57.py / verify57.py）的同一套语义，
# 从本机 6.1.124 kallsyms 重新生成 offsets 条目，并逐符号断言 EXACT。
#
# 用法（可在项目任意位置运行）:
#   python3 scripts/gen_v2.py [kallsyms] [template] [out]
# 默认:
#   kallsyms = reference/kernel-124/kallsyms_manual.txt   （boot.img 解出，112084 符号）
#   template = offsets/offsets-6.1.145-maybe-dirty-R15.json
#   out      = offsets/offsets-6.1.124-v2.json
import json, re, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KALLSYMS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'reference', 'kernel-124', 'kallsyms_manual.txt')
TEMPLATE = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, 'offsets', 'offsets-6.1.145-maybe-dirty-R15.json')
OUT      = sys.argv[3] if len(sys.argv) > 3 else os.path.join(ROOT, 'offsets', 'offsets-6.1.124-v2.json')
BASE     = 0xffffffc008000000  # _text，两个内核一致，kallsyms 相对基址已验证

addr = {}
pat = re.compile(r'^([0-9a-f]{16})\s+(\S)\s+(\S+)$')
for line in open(KALLSYMS, errors='replace'):
    m = pat.match(line)
    if m:
        addr.setdefault(m.group(3), int(m.group(1), 16))

def off(name):
    assert name in addr, 'missing symbol: ' + name
    return addr[name] - BASE

# 57 工程语义表（verify57.py + sym_6157.txt EXACT 验证过的映射）
symbols = {
    'off_init_task':            off('init_task'),
    'off_init_cred':            off('init_cred'),
    'off_root_task_group':      off('root_task_group'),
    'off_selinux_enforcing':    off('selinux_state'),        # enforcing 在 struct 偏移 0（57 同语义）
    'off_security_hook_heads':  off('security_hook_heads'),
    'off_selinux_blob_sizes':   off('selinux_blob_sizes'),
    'off_tp_sys_exit_tp':       off('__tracepoint_sys_exit'),
    'off_tp_sys_exit_funcs':    off('__tracepoint_sys_exit') + 0x40,  # 6.1: funcs @ +0x40
    'off_slide_nfulnl_logger':  off('nfulnl_logger'),
    'off_slide_boot_id':        off('sysctl_bootid'),
    'off_slide_loggers_0_1':    off('loggers') + 8,          # loggers[0][1]，57 同语义
}

# 布局自检：6.1 tracepoint 结构（sys_exit - sys_enter = 0x48 → funcs@+0x40）
assert addr['__tracepoint_sys_exit'] - addr['__tracepoint_sys_enter'] == 0x48, 'tracepoint spacing!'

tpl = json.load(open(TEMPLATE))[0]
entry = {
    'btf_size': 5769202,                       # 本机 6.1.124 实测（loader 不读，仅存档）
    'compact_waiter': tpl['compact_waiter'],   # 1 —— 57/145 一致，不动
    'kernel_phys_load': tpl['kernel_phys_load'],
    'kimage_text_base': tpl['kimage_text_base'],  # = 0xffffffc008000000，与本机 kallsyms 一致
    'mm_struct_sz': tpl['mm_struct_sz'],
    'pselect_waiter_shift': tpl['pselect_waiter_shift'],
    'release': '6.1.124-android14-11-maybe-dirty',
    'struct_fields': dict(tpl['struct_fields']),   # 33 项原样照抄（57↔145 零改动）
    'symbols': {k: int(v) for k, v in symbols.items()},
}

# 输出格式与 offsets/ 中发布版一致（indent=2，逐字节可复现）
json.dump([entry], open(OUT, 'w'), indent=2)
print('written', OUT)
for k, v in sorted(symbols.items()):
    print('  %-26s %#010x  (%d)' % (k, v, v))

# 注：v1(local) → v2 的逐键 diff 已随 offsets-6.1.124-local.json 删除（2026-10-08 精简），
# 对照表保留在 docs/compare-57-145-124.md；本脚本输出不受影响（diff 段在写出之后）。
