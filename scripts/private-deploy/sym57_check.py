#!/usr/bin/env python3
import json,re,bisect,os
BASE=0xffffffc008000000
_HERE=os.path.dirname(os.path.abspath(__file__))
_ROOT=os.path.dirname(_HERE)
path=os.path.join(_ROOT,'reference','kernel-57','sym_6157.txt')
exact={}; byname={}
for line in open(path,errors='replace'):
    m=re.match(r'^([0-9a-f]{16})\s+(\S)\s+(\S+)',line)
    if not m: continue
    a=int(m.group(1),16); n=m.group(3)
    exact.setdefault(a,[]).append(n)
    byname.setdefault(n,[]).append(a)
addrs=sorted(exact)
def near(a):
    i=bisect.bisect_right(addrs,a)-1
    return addrs[i] if i>=0 else None

imp=json.load(open(os.path.join(_ROOT,'offsets','offsets-import-r15-6.1.57+6.1.145.json')))
e57=[e for e in imp if e['release'].startswith('6.1.57')][0]

print('==== what really sits at each 6.1.57 json value (sym_6157.txt, base %#x) ===='%BASE)
for k,v in sorted(e57['symbols'].items()):
    a=BASE+v
    hit=exact.get(a)
    if hit:
        info='EXACT  %s'%','.join(hit)
    else:
        n=near(a)
        info='MISS  nearest=%s +%#x'%(','.join(exact[n]),a-n) if n else 'MISS'
    print('%-26s off=%#-10x -> %s'%(k,v,info))

print()
print('==== ground truth: candidate symbols in sym_6157.txt ====')
WANT=['init_task','init_cred','root_task_group','selinux_state','selinux_enforcing',
      'security_hook_heads','selinux_blob_sizes','tracepoint_sys_exit','tracepoint_sys_enter',
      'nfulnl_logger','nf_ulnl_logger','loggers','sysctl_bootid','boot_id','nf_ulnl']
for w in WANT:
    hits=set()
    for n,aa in byname.items():
        if w in n:
            for a in aa: hits.add((n,a))
    if not hits:
        print('%-24s : <not present>'%w); continue
    for n,a in sorted(hits,key=lambda t:t[1]):
        print('%-44s %016x  off=%#x'%(n,a,a-BASE))
