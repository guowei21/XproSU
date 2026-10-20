#!/usr/bin/env python3
"""Full kallsyms parse from kernel.Image, then compare against user's JSON offsets"""
import struct, json, os

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
d = open(os.path.join(_ROOT, 'reference', 'kernel-124', 'kernel.Image'), 'rb').read()
N = struct.unpack_from('<I', d, 0x133a338)[0]
BASE = struct.unpack_from('<Q', d, 0x133a330)[0]
OFFT, NAMES, TTAB, TIDX = 0x12ccbe0, 0x133a340, 0x1507260, 0x1507600

tidx = struct.unpack_from('<256H', d, TIDX)
toks = []
for i in range(256):
    p = TTAB + tidx[i]
    e = d.find(b'\0', p)
    toks.append(d[p:e].decode('latin1'))

offs = struct.unpack_from('<%di' % N, d, OFFT)
syms = []
pos = NAMES
for i in range(N):
    ln = d[pos]; pos += 1
    seq = d[pos:pos+ln]; pos += ln
    nm = ''.join(toks[b] for b in seq)
    syms.append((BASE + offs[i], nm[0], nm[1:]))

print("parsed %d symbols, base=0x%x" % (len(syms), BASE))

with open(os.path.join(_ROOT, 'reference', 'kernel-124', 'kallsyms_manual.txt'), 'w') as f:
    for addr, t, name in syms:
        f.write("%016x %s %s\n" % (addr, t, name))

by_name = {}
for addr, t, name in syms:
    by_name.setdefault(name, []).append((addr, t))

print("=== sanity: anchor symbols ===")
for name in ['_text', '_stext', 'linux_banner', '__start_rodata', 'init_task']:
    for addr, t in by_name.get(name, [])[:2]:
        print(f"  {name}: 0x{addr:x} type={t} delta=0x{addr-BASE:x}")

print()
print("=== compare with user's JSON ===")
user = {
 'init_task': 34667328,
 'init_cred': 34743344,
 'root_task_group': 37005120,
 'security_hook_heads': 23276752,
 'selinux_blob_sizes': 23278560,
 'selinux_enforcing': 38271896,
}
for name, off in user.items():
    hits = by_name.get(name)
    if not hits:
        print(f"[?] {name}: NOT FOUND in kallsyms (json off=0x{off:x})")
        continue
    for addr, t in hits:
        delta = addr - BASE
        flag = "MATCH" if delta == off else "DIFF "
        print(f"[{flag}] {name} [{t}]: actual delta=0x{delta:x} ({delta})  json=0x{off:x} ({off})")

print()
print("=== fuzzy: boot_id / logger / enforcing ===")
for pat in ['boot_id', 'bootid', 'loggers', 'nfulnl_logger', 'enforcing']:
    print(f"-- {pat} --")
    for name in list(by_name.keys()):
        if pat in name:
            for addr, t in by_name[name][:4]:
                print(f"   {name} [{t}] delta=0x{addr-BASE:x} ({addr-BASE})")
