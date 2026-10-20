import struct
d = open('Image','rb').read()
TI = 0x14c13d0; TB = 0x14c1050; NS = 0x12e6828; N = 109631; SO = 0x127b718
RB = struct.unpack_from('<Q', d, 0x12e6818)[0]
v = [struct.unpack_from('<H', d, TI+2*k)[0] for k in range(256)]
T = [d[TB+v[k]:TB+v[k+1]-1] for k in range(255)]
T.append(d[TB+v[255]:TB+896].split(b'\0')[0])
raw = []; p = NS
for i in range(N):
    L = d[p]; p += 1
    raw.append(b''.join(T[x] for x in d[p:p+L])); p += L
offs = struct.unpack_from('<%dI' % N, d, SO)
addr = [RB + o for o in offs]
print("viol", sum(1 for i in range(N-1) if addr[i] > addr[i+1]))
print("first", raw[0], hex(addr[0]), "| last", raw[-1], hex(addr[-1]))
tab = {}
for r, a in zip(raw, addr):
    tab.setdefault(r[1:].decode('latin1'), a)
need = ['_text','init_task','init_cred','root_task_group','selinux_state',
        'security_hook_heads','selinux_blob_sizes','__tracepoint_sys_exit','_end']
for s in need:
    print("  %-24s %s" % (s, hex(tab[s]) if s in tab else "MISSING"))
with open('sym_6157.txt','w') as f:
    for r, a in zip(raw, addr):
        f.write("%016x %s %s\n" % (a, chr(r[0]) if r else '?', r[1:].decode('latin1')))
print("wrote sym_6157.txt lines=", len(raw))
