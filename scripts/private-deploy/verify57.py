#!/usr/bin/env python3
# 6.1.57 偏移验证（路径可移植版）：把 offsets 表中的 6.1.57 条目逐符号钉死到
# 设备 kallsyms（sym_6157.txt，由 ksg.py 从设备自身 kernel Image 解出）。
# 全部通过（mismatch=0、funcs-tp=0x40、lag=-0xB0）才算对。
#
# 用法: python3 scripts/verify57.py [offsets.json] [sym_6157.txt]
import json, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
P   = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'offsets', 'offsets-57+124+145-combined.json')
SYM = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, 'reference', 'kernel-57', 'sym_6157.txt')

a = json.load(open(P))
a = a if isinstance(a, list) else [a]
entries = [x for x in a if x['release'].startswith('6.1.57')]
assert entries, 'no 6.1.57 entry in ' + P
e = entries[0]
T = 0xffffffc008000000
m = {}
for ln in open(SYM):
    p = ln.split()
    if len(p) >= 3:
        m[p[2]] = int(p[0], 16)
need = [('off_init_task','init_task'), ('off_init_cred','init_cred'),
        ('off_root_task_group','root_task_group'), ('off_selinux_enforcing','selinux_state'),
        ('off_security_hook_heads','security_hook_heads'), ('off_selinux_blob_sizes','selinux_blob_sizes'),
        ('off_tp_sys_exit_tp','__tracepoint_sys_exit'), ('off_slide_nfulnl_logger','nfulnl_logger'),
        ('off_slide_boot_id','sysctl_bootid')]
bad = 0
for k, v in need:
    exp = T + e['symbols'][k]
    if exp != m[v]:
        bad += 1
        print('BAD', k, hex(exp), hex(m[v]))
print('checked', len(need), 'mismatch', bad)
ft = e['symbols']['off_tp_sys_exit_funcs'] - e['symbols']['off_tp_sys_exit_tp']
lag = e['symbols']['off_slide_loggers_0_1'] - e['symbols']['off_slide_nfulnl_logger']
print('funcs-tp', ft, hex(ft))
print('lag', lag, hex(lag))
assert bad == 0, 'symbol mismatch'
assert ft == 0x40, 'funcs-tp != 0x40'
assert lag == -0xB0, 'loggers lag != -0xB0'
print('ALL OK')
