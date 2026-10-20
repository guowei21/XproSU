#!/usr/bin/env python3
import json, os
_HERE=os.path.dirname(os.path.abspath(__file__))
_ROOT=os.path.dirname(_HERE)
P=os.path.join(_ROOT,'offsets','offsets-import-r15-6.1.57+6.1.145.json')
imp=json.load(open(P))
e145=[e for e in imp if e['release'].startswith('6.1.145')][0]
e57=[e for e in imp if e['release'].startswith('6.1.57')][0]
e124=[e for e in json.load(open(os.path.join(_ROOT,'offsets','offsets-57+124+145-combined.json'))) if e['release'].startswith('6.1.124')][0]

SYM=['off_init_task','off_init_cred','off_root_task_group','off_selinux_enforcing',
     'off_selinux_blob_sizes','off_security_hook_heads','off_slide_nfulnl_logger',
     'off_slide_loggers_0_1','off_slide_boot_id','off_tp_sys_exit_tp','off_tp_sys_exit_funcs']
TASK=['task_prio','task_normal_prio','task_sched_task_group','task_pi_lock','task_pi_waiters',
      'task_pi_top_task','task_pi_blocked_on','task_pid','task_tgid','task_atomic_flags',
      'task_real_cred','task_cred','task_comm','task_tasks','task_seccomp']

def h(v): return '<none>' if v is None else hex(v)
def d(a,b): return '' if (a is None or b is None) else '%+d (%+#x)'%(b-a,b-a)

print('==== A. top-level scalars ====')
print('   (offsets_json.c only parses: kernel_phys_load / pselect_waiter_shift / compact_waiter / mm_struct_sz)')
print('   (btf_size / kimage_text_base are NOT read by the loader at all)')
for k in ['release','btf_size','kimage_text_base','kernel_phys_load',
          'pselect_waiter_shift','compact_waiter','mm_struct_sz']:
    g=lambda e:e.get(k,'<absent>')
    tag='CONST ' if g(e57)==g(e145) else 'CHANGED'
    print('%-22s | %-30s | %-30s | %-30s | %s'%(k,str(g(e57)),str(g(e145)),str(g(e124)),tag))

print()
print('==== B. struct_fields: 6.1.57 vs 6.1.145 ====')
k57,k145,k124=e57['struct_fields'],e145['struct_fields'],e124['struct_fields']
allk=sorted(set(k57)|set(k145)|set(k124))
nch=0
for k in allk:
    a,b,c=k57.get(k),k145.get(k),k124.get(k)
    ch=(a!=b); nch+=ch
    parsed='PARSED' if k in TASK else 'ignored-by-loader'
    print('%-28s | %-6s | %-6s | %-6s | %-7s %s'%(k,a,b,c,'SAME' if not ch else 'DIFF',parsed))
print('-> changed 57->145: %d / %d   (parsed-by-loader keys: %d)'%(nch,len(allk),len(TASK)))

print()
print('==== C. symbols (all 11 PARSED by loader) ====')
for k in SYM:
    a,b,c=e57['symbols'].get(k),e145['symbols'].get(k),e124['symbols'].get(k)
    print('%-26s | %-10s | %-10s | %-10s | d(145-57)=%-20s | d(124-145)=%s'%(
        k,h(a),h(b),h(c),d(a,b),d(b,c)))

print()
print('==== D. internal spacings (cross-kernel fingerprint) ====')
PAIRS=[('selinux_blob_sizes - hook_heads',('off_selinux_blob_sizes','off_security_hook_heads')),
       ('tp_funcs - tp',('off_tp_sys_exit_funcs','off_tp_sys_exit_tp')),
       ('init_cred - init_task',('off_init_cred','off_init_task')),
       ('nfulnl_logger - init_task',('off_slide_nfulnl_logger','off_init_task')),
       ('loggers_0_1 - nfulnl_logger',('off_slide_loggers_0_1','off_slide_nfulnl_logger')),
       ('boot_id - selinux_enforcing',('off_slide_boot_id','off_selinux_enforcing')),
       ('enforcing - root_task_group',('off_selinux_enforcing','off_root_task_group'))]
for name,(x,y) in PAIRS:
    row=[]
    for label,e in [('6.1.57',e57),('6.1.145',e145),('6.1.124',e124)]:
        a,b=e['symbols'].get(x),e['symbols'].get(y)
        row.append('%s: %s'%(label,'n/a' if a is None or b is None else '%+#x'%(a-b)))
    print('%-34s | %s'%(name,' | '.join(row)))
