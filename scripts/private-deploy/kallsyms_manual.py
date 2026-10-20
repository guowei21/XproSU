#!/usr/bin/env python3
"""Manually parse arm64 kallsyms from kernel.Image - diagnostics first"""
import struct, os

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
d = open(os.path.join(_ROOT, 'reference', 'kernel-124', 'kernel.Image'), 'rb').read()
NSYM = 0x133a338
OFFT = 0x12ccbe0
NAMES = 0x133a340
TTAB = 0x1507260
TIDX = 0x1507600

N = struct.unpack_from('<I', d, NSYM)[0]
print("num_syms:", N, hex(N))

print("--- u64 probes ---")
for off in (0x12ccbd8, 0x12ccbe0, 0x133a330, 0x133a328):
    v = struct.unpack_from('<Q', d, off)[0]
    print(f"  @0x{off:x} = 0x{v:x}")

print("--- first offsets as s32/u32 ---")
for i in range(8):
    v = struct.unpack_from('<i', d, OFFT + 4*i)[0]
    u = struct.unpack_from('<I', d, OFFT + 4*i)[0]
    print(f"  [{i}] s32={v} 0x{u:x}")

print("--- token index/table sanity ---")
tidx = struct.unpack_from('<256H', d, TIDX)
print("  first 16 token indexes:", tidx[:16])
def tok(i):
    p = TTAB + tidx[i]
    e = d.find(b'\0', p)
    return d[p:e].decode('latin1')

print("  first 8 tokens:", [tok(i) for i in range(8)])

print("--- first 40 symbol names (decompressed) ---")
pos = NAMES
names = []
for i in range(40):
    ln = d[pos]; pos += 1
    seq = d[pos:pos+ln]; pos += ln
    names.append(''.join(tok(b) for b in seq))
for i, n in enumerate(names):
    print(f"  [{i}] {n}")
