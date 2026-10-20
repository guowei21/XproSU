#!/usr/bin/env python3
"""BTF v2: decode kflag correctly (bit_off = mo & 0xffffff), flatten anonymous members, full compare"""
import struct, os

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
d = open(os.path.join(_ROOT, 'reference', 'kernel-124', 'kernel.btf'), 'rb').read()
magic, ver, flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from('<HBBIIIII', d, 0)
assert magic == 0xeb9f
tb = d[hdr_len+type_off: hdr_len+type_off+type_len]
sb = d[hdr_len+str_off: hdr_len+str_off+str_len]

def gs(o):
    e = sb.find(b'\0', o)
    return sb[o:e].decode('utf-8', 'replace')

types = [None]
pos = 0
while pos < len(tb):
    name_off, info, size = struct.unpack_from('<III', tb, pos)
    kind = (info >> 24) & 0x1f
    vlen = info & 0xffff
    kflag = (info >> 31) & 1
    t = {'name': gs(name_off), 'kind': kind, 'size': size, 'kflag': kflag, 'members': None}
    pos += 12
    if kind == 1: pos += 4
    elif kind == 3: pos += 12
    elif kind in (4, 5):
        mem = []
        for i in range(vlen):
            mn, mt, mo = struct.unpack_from('<III', tb, pos); pos += 12
            if kflag:
                bit_off = mo & 0xffffff
                bf = mo >> 24
            else:
                bit_off = mo
                bf = 0
            mem.append((gs(mn), mt, bit_off, bf))
        t['members'] = mem
    elif kind == 6: pos += 8 * vlen
    elif kind == 13: pos += 8 * vlen
    elif kind == 14: pos += 4
    elif kind == 15: pos += 12 * vlen
    elif kind == 17: pos += 8
    elif kind == 19: pos += 12 * vlen
    types.append(t)

print("types:", len(types) - 1)

by_name = {}
for tid, t in enumerate(types):
    if t and t['name']:
        by_name.setdefault(t['name'], []).append(tid)

def get_struct(name):
    for tid in by_name.get(name, []):
        if types[tid]['kind'] in (4, 5):
            return tid
    return None

def flatten(tid, base_bits=0, depth=0):
    """return {member_name: byte_offset} flattening anonymous members"""
    out = {}
    t = types[tid]
    if t is None or t['members'] is None or depth > 6:
        return out
    for (mn, mt, bit_off, bf) in t['members']:
        total = base_bits + bit_off
        if mn == '':
            out.update(flatten(mt, total, depth + 1))
        else:
            out[mn] = (total // 8, bf)
    return out

def cmp_struct(sname, fields):
    tid = get_struct(sname)
    if tid is None:
        return [f"[?] struct {sname} NOT FOUND"]
    flat = flatten(tid)
    lines = [f"--- {sname} (size={types[tid]['size']}) ---"]
    for f, exp in fields.items():
        got = flat.get(f)
        if got is None:
            lines.append(f"[MISS] {sname}.{f}: json={exp} (not in BTF)")
        else:
            off, bf = got
            st = "OK  " if off == exp and bf == 0 else "DIFF"
            lines.append(f"[{st}] {sname}.{f}: json={exp} btf={off} bf={bf}")
    return lines

out = []
out.append("======== JSON struct_fields vs BTF (this kernel) ========")
out += cmp_struct('cred', {'uid':4, 'securebits':36, 'security':120})
out += cmp_struct('seccomp', {'mode':0, 'filter':8, 'filter_count':4})
out += cmp_struct('rt_mutex_waiter', {'tree':0, 'pi_tree':24, 'task':48, 'lock':56, 'wake_state':64, 'ww_ctx':80})
out += cmp_struct('task_struct', {
    'prio':132, 'normal_prio':140, 'sched_task_group':840, 'tasks':1360,
    'atomic_flags':1520, 'pid':1584, 'tgid':1588, 'real_cred':2096, 'cred':2104,
    'comm':2120, 'seccomp':2304, 'pi_lock':2340, 'pi_waiters':2360,
    'pi_top_task':2376, 'pi_blocked_on':2384, 'mm':968})
out += cmp_struct('page', {'compound_head':8, 'page_type':48, '_page_type':48})
out += cmp_struct('slab', {'slab_cache':24})

out.append("")
out.append("======== cred full ========")
for k, v in sorted(flatten(get_struct('cred')).items(), key=lambda x: x[1][0]):
    out.append(f"   {k:34s} off={v[0]} bf={v[1]}")
out.append("")
out.append(f"sizeof(mm_struct) = {types[get_struct('mm_struct')]['size']}")
out.append(f"sizeof(task_struct) = {types[get_struct('task_struct')]['size']}")
out.append(f"sizeof(page) = {types[get_struct('page')]['size']}")
out.append("")
out.append("======== rt_mutex_waiter full ========")
for k, v in sorted(flatten(get_struct('rt_mutex_waiter')).items(), key=lambda x: x[1][0]):
    out.append(f"   {k:34s} off={v[0]} bf={v[1]}")

open(os.path.join(_ROOT, 'reference', 'kernel-124', 'btf_fields.txt'), 'w').write('\n'.join(out))
print('\n'.join(out[:75]))
