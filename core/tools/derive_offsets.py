#!/usr/bin/env python3
"""
derive_offsets.py — 从 arm64 内核 Image 提取 BTF 结构偏移 + kallsyms 符号表

纯 Python，无外部依赖。

用法:
  python derive_offsets.py [Image路径]

默认读取当前目录的 Image 文件。

输出:
  - BTF 结构偏移（task_struct, cred, k_itimer, seccomp_filter 等）
  - kallsyms.txt — 恢复的内核符号表
  - static-values.txt — 导出的偏移值

从 boot.img 提取 Image 的方法:
  1. 用 magiskboot 解包: magiskboot unpack boot.img → 得到 kernel
  2. 如果 kernel 是压缩的 (gzip/lz4): magiskboot decompress kernel kernel_raw
  3. 验证: hexdump -C kernel_raw | head  → 应看到 ARM\x64 magic
  4. 重命名: mv kernel_raw Image
"""
import sys
import struct
from pathlib import Path
from collections import defaultdict

IMAGE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('Image')
data = IMAGE.read_bytes()
assert data[0x38:0x3c] == b'ARM\x64'
image_size = struct.unpack_from('<Q', data, 0x10)[0]
EXTRA={0:0,1:4,2:0,3:12,4:0,5:0,6:8,7:0,8:0,9:0,10:0,11:0,12:0,13:8,14:4,15:12,16:0,17:8,18:0,19:12}

def cstr(blob,p):
    e=blob.find(b'\0',p)
    if e<0:e=len(blob)
    return blob[p:e].decode('utf-8','replace')

def read_btf(off):
    version=data[off+2]
    hdr,toff,tlen,soff,slen=struct.unpack_from('<IIIII',data,off+4)
    if version!=1 or hdr<24: raise ValueError('hdr')
    if toff+tlen>len(data)-hdr or soff+slen>len(data)-hdr: raise ValueError('range')
    if slen<0x1000 or tlen<0x1000: raise ValueError('small')
    base=off+hdr
    raw=data[base+toff:base+toff+tlen]
    strings=data[base+soff:base+soff+slen]
    if not strings.startswith(b'\0'): raise ValueError('str')
    types={}; by=defaultdict(list); cur=0; tid=1; hist=[]
    while cur<len(raw):
        if cur+12>len(raw): raise ValueError('type')
        no,info,stype=struct.unpack_from('<III',raw,cur);cur+=12
        kind=(info>>24)&31; v=info&65535
        if kind not in EXTRA: raise ValueError(f'kind {kind} cur {cur} tid {tid} info {info:#x} hist={hist[-8:]}')
        hist.append((tid,cur,kind,v,raw[cur-12:cur].hex())); t={'id':tid,'name':cstr(strings,no) if no<slen else '','kind':kind,'size':stype,'members':[],'enum':[]}
        if kind in (4,5):
            if cur+v*12>len(raw):raise ValueError('members')
            for _ in range(v):
                mn,mt,mo=struct.unpack_from('<III',raw,cur);cur+=12
                t['members'].append((cstr(strings,mn) if mn<slen else '',mt,mo&0xffffff))
        elif kind==6:
            if cur+v*8>len(raw):raise ValueError('enum')
            for _ in range(v):
                n,val=struct.unpack_from('<Ii',raw,cur);cur+=8
                t['enum'].append((cstr(strings,n) if n<slen else '',val))
        elif kind==19:
            if cur+v*12>len(raw):raise ValueError('enum64')
            for _ in range(v):
                n,lo,hi=struct.unpack_from('<III',raw,cur);cur+=12
                t['enum'].append((cstr(strings,n) if n<slen else '',(hi<<32)|lo))
        elif kind in (1,3,14,15,17):cur+=EXTRA[kind]
        elif kind==13:cur+=8*v
        types[tid]=t;by[t['name']].append(tid);tid+=1
    if cur!=len(raw):raise ValueError('trailing')
    return {'off':off,'types':types,'by':by,'strings':strings}
btf=None
for i in range(0,len(data)-24,4):
    if data[i:i+2]==b'\x9f\xeb':
        try:
            c=read_btf(i)
            # Embedded kernel BTF is large and has core type names.
            if len(c['types'])>10000:
                btf=c;break
        except Exception as e:
            if i == 0x17c991c: print("BTF exact error", repr(e))
if not btf:raise SystemExit('no BTF')
print(f'BTF off={btf["off"]:#x} types={len(btf["types"])}')

def resolve(tid):
    seen=set()
    while tid and tid not in seen:
        seen.add(tid);t=btf['types'].get(tid)
        if not t:return None
        if t['kind'] not in (8,9,10,11,18):return t
        tid=t['size']
    return None

def named(name):
    a=[btf['types'][i] for i in btf['by'].get(name,[]) if btf['types'][i]['kind'] in (4,5)]
    return max(a,key=lambda x:len(x['members'])) if a else None

def fm(t,name,base=0,depth=0,seen=None):
    if depth>64:return None
    seen=set() if seen is None else seen
    if t['id'] in seen:return None
    seen.add(t['id'])
    for n,tid,bits in t['members']:
        off=base+bits
        if n==name:return off//8
        if not n:
            c=resolve(tid)
            if c and c['kind'] in (4,5):
                r=fm(c,name,off,depth+1,seen)
                if r is not None:return r
    return None

def field(s,n):
    t=named(s);return None if t is None else fm(t,n)
btf_values={}
for s,n in [('selinux_task_security','osid'),('selinux_task_security','sid'),('task_security_struct','osid'),('task_security_struct','sid'),('selinux_state','initialized'),('selinux_state','enforcing'),('k_itimer','it'),('k_itimer','node'),('k_itimer','it_signal'),('k_itimer','it_process'),('k_itimer','it_cpu'),('k_itimer','list'),('k_itimer','tcpu'),('k_itimer','sigq'),('k_itimer','it_interval'),('k_itimer','it_value'),('kmem_cache','size'),('kmem_cache','object_size'),('kmem_cache','align'),('kmem_cache','inuse'),('task_struct','cred'),('task_struct','real_cred'),('cred','uid'),('cred','gid'),('cred','cap_inheritable'),('cred','cap_permitted'),('cred','cap_effective'),('cred','cap_bset'),('cred','cap_ambient'),('cred','user'),('cred','user_ns'),('cred','ucounts'),('cred','group_info'),('cred','security')]:
    v=field(s,n);btf_values[f'{s}.{n}']=v
    print(f'BTF {s}.{n}={v:#x}' if v is not None else f'BTF {s}.{n}=MISSING')
for s in ('task_struct','cred','k_itimer','tracepoint'):
    t=named(s);v=None if t is None else t['size'];btf_values[f'size.{s}']=v;print(f'SIZE {s}={v:#x}' if v is not None else f'SIZE {s}=MISSING')

def dump_members(t,prefix='',base=0,depth=0):
    if depth>5:return
    for n,tid,bits in t['members']:
        off=base+bits
        print('MEMBER',prefix+n,hex(off//8),'bits',hex(bits))
        c=resolve(tid)
        if c and c['kind'] in (4,5):
            dump_members(c,(prefix+n+'.'),off,depth+1)
_t=named('tracepoint')
if _t: dump_members(_t,'tracepoint.')
_t=named('selinux_state')
if _t: dump_members(_t,'selinux_state.')
_t=named('task_security_struct')
if _t: dump_members(_t,'task_security_struct.')
_t=named('cred')
if _t: dump_members(_t,'cred.')
_t=named('k_itimer')
if _t: dump_members(_t,'k_itimer.')
# kallsyms
A=8; TOKENS=256; MAXT=256; WINDOW=4*1024*1024; TAIL=0x40000
TYPES=set(b'aAbBcCdDeEfFgGiInNpPrRsStTuUvVwW?-'); REQ={'_text','_end','load_module'}
def up(x):return(x+A-1)&~(A-1)
def u16(o):return struct.unpack_from('<H',data,o)[0]
def u32(o):return struct.unpack_from('<I',data,o)[0]
def i32(o):return struct.unpack_from('<i',data,o)[0]
def u64(o):return struct.unpack_from('<Q',data,o)[0]
def token_at(start,digit):
    if start%A:return None
    toks=[];offs=[];starts=[];p=start
    for _ in range(TOKENS):
        starts.append(p);e=data.find(b'\0',p,min(len(data),p+MAXT+1))
        if e<0 or e==p:return None
        if any(not 0x20<=c<=0x7e for c in data[p:e]):return None
        offs.append(p-start);toks.append(data[p:e]);p=e+1
    if starts[48]!=digit:return None
    for c in b'0123456789_abcdefghijklmnopqrstuvwxyzT':
        if toks[c]!=bytes([c]):return None
    ix=up(p)
    if any(data[p:ix]) or ix+512>len(data):return None
    for i,v in enumerate(offs):
        if u16(ix+2*i)!=v:return None
    return toks,start,ix
needle=b''.join(bytes([x,0]) for x in range(48,58));tables=[];pos=0
while True:
    d=data.find(needle,pos)
    if d<0:break
    p=up(max(0,d-48*(MAXT+1)))
    while p<=d:
        r=token_at(p,d)
        if r:tables.append(r)
        p+=A
    pos=d+1
print('TOKEN TABLES',[(hex(t[1]),hex(t[2])) for t in tables])

def markers(start,limit):
    if start%A or start+8>limit:return []
    a,b=u32(start),u32(start+4)
    if a or not 0x200<=b<=0x40000:return []
    out=[a,b];p=start+8
    while len(out)<4096 and p+4<=limit:
        v=u32(p);d=v-out[-1]
        if not 0x200<=d<=0x40000:break
        out.append(v);p+=4
    return out if len(out)>=8 else []

def spans(names,count,marks,mo,uleb):
    if not count or len(marks)!=(count+255)//256:return None
    out=[];p=names
    for i in range(count):
        if i%256==0 and p-names!=marks[i//256]:return None
        if p>=len(data):return None
        ln=data[p];p+=1
        if uleb and ln&128:
            if p>=len(data):return None
            hi=data[p];p+=1
            if hi&128:return None
            ln=(ln&127)|(hi<<7)
        if not ln or ln>0x3fff or p+ln>len(data):return None
        out.append((p,ln));p+=ln
    if up(p)!=mo or any(data[p:mo]):return None
    return out

def names_decode(sp,toks):
    out=[];ns=set()
    for p,l in sp:
        x=b''.join(toks[i] for i in data[p:p+l])
        if not x or x[0] not in TYPES or not x[1:] or any(not 0x21<=c<=0x7e for c in x[1:]):return None
        n=x[1:].decode('ascii');out.append((x[0],n));ns.add(n)
    return out if REQ<=ns else None
name_tables=[]
for toks,tab,ix in tables:
    lo=up(max(0,tab-WINDOW));mc=[];p=lo
    while p+8<=tab:
        m=markers(p,tab)
        if m:mc.append((p,m))
        p+=A
    print('MARKERS',[(hex(p),len(m),hex(m[-1])) for p,m in mc])
    for mo,m in mc:
        mn=(len(m)-1)*256+1;mx=len(m)*256;approx=mo-m[-1];lo=max(0,approx-TAIL);n=(approx//A)*A
        while n>=lo:
            cnt=u32(n)
            if mn<=cnt<=mx and data[n+4:n+8]==b'\0'*4:
                seen=set()
                for uleb in (True,False):
                    sp=spans(n+8,cnt,m,mo,uleb)
                    if not sp:continue
                    key=tuple(sp)
                    if key in seen:continue
                    seen.add(key)
                    dec=names_decode(sp,toks)
                    if dec:name_tables.append((n,n+8,mo,dec))
            if n<lo+A:break
            n-=A
print('NAME TABLES',[(hex(n),len(d),hex(m)) for n,_,m,d in name_tables])

def decode_addr(num,names,tab,ix):
    cnt=len(names);oldbase=num-A;oldoff=oldbase-up(cnt*4);newoff=up(ix+512);newbase=up(newoff+cnt*4)
    for layout,off,base in [('pre-6.4',oldoff,oldbase),('6.4+',newoff,newbase)]:
        if off<0 or base+8>len(data) or off+cnt*4>base or any(data[off+cnt*4:base]):continue
        rel=u64(base)
        if rel>>48!=0xffff or rel%4096:continue
        raw=[i32(off+4*j) for j in range(cnt)];neg=sum(x<0 for x in raw)
        if neg*2>=cnt:aa=[rel-1-x if x<0 else x for x in raw]
        else:aa=[rel+(x&0xffffffff) for x in raw]
        if any(aa[i]>aa[i+1] for i in range(cnt-1)):continue
        es=list(zip(aa,[x[0] for x in names],[x[1] for x in names]));one=lambda n:[a for a,k,x in es if x==n]
        if len(one('_text'))!=1 or len(one('_end'))!=1 or one('_text')[0]!=rel or one('_end')[0]-rel!=image_size:continue
        yield layout,es
cands=[]
for num,names,mo,dec in name_tables:
    for tab,ix in [(t[1],t[2]) for t in tables]:
        cands.extend(decode_addr(num,dec,tab,ix))
# select unique by BTF boundaries when possible
sel=[]
for c in cands:
    one=lambda n:[a for a,k,x in c[1] if x==n]
    if len(one('__start_BTF'))==1 and len(one('__stop_BTF'))==1 and len(one('_text'))==1:
        if one('__start_BTF')[0]-one('_text')[0]==btf['off'] and one('__stop_BTF')[0]-one('__start_BTF')[0]>=0:
            sel.append(c)
if len(sel)==1:cands=sel
print('KALLSYMS CANDIDATES',[(x[0],len(x[1])) for x in cands])
if not cands:raise SystemExit('no kallsyms')
if len(cands)>1:
    # Prefer pre-6.4 candidate with exact BTF length from embedded blob strings.
    for c in cands:
        one=lambda n:[a for a,k,x in c[1] if x==n]
        if c[0]=='pre-6.4' and len(one('__start_BTF'))==1: cands=[c];break
layout,entries=cands[0]
sy=defaultdict(list)
for a,k,n in entries:sy[n].append(a)
print('SELECTED',layout,len(entries))
for n in ['_text','_end','do_timer_create','copy_process','selinux_state','panic_on_warn','root_user','init_user_ns','init_ucounts','init_groups','__tracepoint_sys_exit','__start_BTF','__stop_BTF']:
    print('SYM',n,[hex(x) for x in sy.get(n,[])])
Path(r'kallsyms.txt').write_text('\n'.join(f'{a:016x} {chr(k)} {n}' for a,k,n in entries)+'\n')
Path(r"static-values.txt").write_text("\n".join(f"{k}={'MISSING' if v is None else format(v, '#x')}" for k,v in btf_values.items())+"\n")



