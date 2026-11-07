#!/usr/bin/env python3
"""
disasm_kernel.py — ARM64 内核函数反汇编工具

从 Image + kallsyms.txt 反汇编指定内核函数，用于推导 exploit 所需的静态地址和结构偏移。

依赖: pip install capstone

用法:
  python disasm_kernel.py <subcmd> [--image IMAGE] [--kallsyms KALLSYMS]

子命令:
  cred_security    — security_prepare_creds / selinux_cred_prepare 等
  lsm_order        — ordered_lsm_init / choose_major_lsm 等
  security_init    — security_init / lsm_set_blob_sizes
  selinux_complete — selinux_complete_init
  selinux_init     — selinux_init
  selinux_state    — selinux_status_update_setenforce 等 (定位 selinux_state 地址)
  targets          — do_timer_create / copy_process (定位 timer 分配调用点)
"""
import sys
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_GRP_CALL, CS_GRP_JUMP
except ImportError:
    print("需要 capstone: pip install capstone", file=sys.stderr)
    sys.exit(1)

IMAGE_PATH = Path('Image')
KALLSYMS_PATH = Path('kallsyms.txt')
TEXT_BASE = 0xffffffc008000000

def load():
    img = IMAGE_PATH.read_bytes()
    sy = {}
    for l in KALLSYMS_PATH.read_text().splitlines():
        parts = l.split()
        if len(parts) >= 3:
            sy[parts[2]] = int(parts[0], 16)
    return img, sy

def disasm_funcs(names):
    img, sy = load()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for n in names:
        if n not in sy:
            print('MISS', n)
            continue
        a = sy[n]
        b = min((v for v in sy.values() if v > a), default=a + 0x400)
        print(f'\n### {n} {a:#x} size={b - a:#x}')
        for i in md.disasm(img[a - TEXT_BASE:b - TEXT_BASE], a):
            print(f'{i.address:#x} +{i.address - a:#x}: {i.mnemonic:8} {i.op_str}')

def disasm_targets():
    img, sy = load()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    for name, start_name, size in [
        ('do_timer_create', 'do_timer_create', 0x600),
        ('copy_process', 'copy_process', 0xc00),
    ]:
        if start_name not in sy:
            print('MISS', start_name)
            continue
        start = sy[start_name]
        end = min((v for v in sy.values() if v > start), default=start + size)
        print(f'\n### {name} {start:#x} size={end - start:#x}')
        code = img[start - TEXT_BASE:end - TEXT_BASE]
        for i in md.disasm(code, start):
            print(f'{i.address:#x} +{i.address - start:#x}: {i.mnemonic:8} {i.op_str}')

def selinux_state():
    img, sy = load()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for name in ['selinux_status_update_setenforce', 'security_load_policy', 'security_read_state_kernel']:
        if name not in sy:
            print('MISS', name)
            continue
        a = sy[name]
        b = min((v for v in sy.values() if v > a), default=a + 0x1000)
        print(f'\n### {name} {a:#x} size={b - a:#x}')
        for i in md.disasm(img[a - TEXT_BASE:b - TEXT_BASE], a):
            # 只输出包含 selinux_state 相关地址的指令
            if any(x in i.op_str for x in ['0xffffffc00a55a', '0xa55a', '#0xa4f0']):
                print(f'{i.address:#x} +{i.address - a:#x}: {i.mnemonic:8} {i.op_str}')

CMDS = {
    'cred_security': lambda: disasm_funcs([
        'security_prepare_creds', 'selinux_cred_prepare',
        'selinux_cred_free', 'landlock_cred_free', 'landlock_cred_prepare']),
    'lsm_order': lambda: disasm_funcs([
        'ordered_lsm_init', 'choose_major_lsm',
        'choose_lsm_order', 'ordered_lsm_parse']),
    'security_init': lambda: disasm_funcs(['security_init', 'lsm_set_blob_sizes']),
    'selinux_complete': lambda: disasm_funcs(['selinux_complete_init']),
    'selinux_init': lambda: disasm_funcs(['selinux_init']),
    'selinux_state': selinux_state,
    'targets': disasm_targets,
}

if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] not in CMDS:
        print(f'用法: {sys.argv[0]} <{"|".join(CMDS.keys())}>')
        print('可选: --image <path> --kallsyms <path>')
        sys.exit(1)
    for i, arg in enumerate(sys.argv):
        if arg == '--image' and i + 1 < len(sys.argv):
            IMAGE_PATH = Path(sys.argv[i + 1])
        if arg == '--kallsyms' and i + 1 < len(sys.argv):
            KALLSYMS_PATH = Path(sys.argv[i + 1])
    CMDS[sys.argv[1]]()