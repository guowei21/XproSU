#!/usr/bin/env python3
"""BTF extra: selinux_state / nf_logger structs, VAR & DATASEC info"""
import struct, os
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
d = open(os.path.join(_ROOT, 'reference', 'kernel-124', 'kernel.btf'), 'rb').read()
magic, ver, flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from('<HBBIIIII', d, 0)
tb = d[hdr_len+type_off: hdr_len+type_off+type_len]
sb = d[hdr_len+str_off: hdr_len+str_off+str_len]
def gs(o):
    e = sb.find(b'\0', o); return sb[o:e].decode('utf-8', 'replace')
types = [None]; pos = 0
while pos < len(tb):
    name_off, info, size = struct.unpack_from('<III', tb, pos)
    kind = (info >> 24) & 0x1f; vlen = info & 0xffff; kflag = (info >> 31) & 1
    t = {'name': gs(name_off), 'kind': kind, 'val': size, 'kflag': kflag, 'members': None, 'extra': None}
    pos += 12
    if kind == 1: pos += 4
    elif kind == 3:
        et, it, ne = struct.unpack_from('<III', tb, pos); t['extra'] = ('array', et, it, ne); pos += 12
    elif kind in (4, 5):
        m = []
        for i in range(vlen):
            mn, mt, mo = struct.unpack_from('<III', tb, pos); pos += 12
            if kflag: bit = mo & 0xffffff; bf = mo >> 24
            else: bit = mo; bf = 0
            m.append((gs(mn), mt, bit, bf))
        t['members'] = m
    elif kind == 6: pos += 8 * vlen
    elif kind == 13: pos += 8 * vlen
    elif kind == 14: pos += 4
    elif kind == 15:
        e = []
        for i in range(vlen):
            vt, vo, vs = struct.unpack_from('<III', tb, pos); pos += 12
            e.append((vt, vo, vs))
        t['extra'] = ('datasec', e)
    elif kind == 17: pos += 8
    elif kind == 19: pos += 12 * vlen
    types.append(t)
print("types:", len(types) - 1)
by_name = {}
for tid, t in enumerate(types):
    if t and t['name']: by_name.setdefault(t['name'], []).append(tid)

def flat(tid, base=0, depth=0):
    out = {}; t = types[tid]
    if t is None or t['members'] is None or depth > 8: return out
    for mn, mt, bit, bf in t['members']:
        tot = base + bit
        if mn == '': out.update(flat(mt, tot, depth + 1))
        else: out[mn] = (tot // 8, bf)
    return out

for nm in ['selinux_state', 'nf_logger']:
    ids = by_name.get(nm)
    if not ids:
        print(f"struct {nm}: NOT FOUND"); continue
    tid = ids[0]
    f = flat(tid)
    print(f"=== struct {nm} size={types[tid]['val']} ===")
    for k, v in sorted(f.items(), key=lambda x: x[1][0]):
        print(f"   {k:28s} off={v[0]} bf={v[1]}")

want = {'loggers', 'nfulnl_logger', 'sysctl_bootid', 'selinux_state',
        'selinux_enforcing_boot', 'init_task', 'init_cred', 'root_task_group',
        'security_hook_heads', 'selinux_blob_sizes'}
var_ids = {}
for nm in want:
    for tid in by_name.get(nm, []):
        if types[tid]['kind'] == 14: var_ids[tid] = nm
print("=== VARs found:", list(var_ids.values()), "===")
for tid, nm in var_ids.items():
    rt = types[tid]['val']
    t2 = types[rt]
    if t2 is None: continue
    extra = ''
    if t2['kind'] == 3:
        _, et, it, ne = t2['extra']
        extra = f" nelems={ne} elem_kind={types[et]['kind']} elem={types[et]['name']!r}"
        e2 = types[et]
        if e2['kind'] == 3:
            _, et2, it2, ne2 = e2['extra']
            extra += f" | 2nd dim nelems={ne2} elem={types[et2]['name']!r}"
    print(f"VAR {nm}: type_id={rt} kind={t2['kind']} tname={t2['name']!r} tval={t2['val']}{extra}")
print("=== DATASEC entries for our vars ===")
for tid, t in enumerate(types):
    if t and t['kind'] == 15 and t['extra']:
        for vt, vo, vs in t['extra'][1]:
            if vt in var_ids:
                print(f"  {t['name']}: {var_ids[vt]}  secoff=0x{vo:x} size={vs} (0x{vs:x})")
