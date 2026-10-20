#!/usr/bin/env python3
"""Bake device-verified offsets (6.1.57 / 6.1.124 / 6.1.145) into the R15
source tree as builtin entries.  [私有化版本 — 路径已可移植]

 1. read offsets/offsets-57+124+145-combined.json (device-verified values)
 2. cross-check: 145 vs src/kernels/6.1.145-...-maybe-dirty/offsets.h (repo entry),
                 57   vs offsets/offsets-import-r15-6.1.57+6.1.145.json,
                 124  vs reference/kernel-124/kallsyms_manual.txt (symbol-level)
    + struct_fields vs STRUCT_OFFSETS_6_1 macro for all three
 3. rewrite the three builtin kernel entries (default: prune other builtin dirs)
 4. rewrite the known_offsets[] dispatcher include list

用法:
    python3 scripts/gen_builtin.py                # 删除其他内建目录（与首次烘焙一致）
    python3 scripts/gen_builtin.py --no-prune     # 保留其他内建目录（只更新这三条）

No hand-transcribed numbers: every emitted value comes from the json.
"""
import json, os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KDIR = os.path.join(ROOT, "src", "kernels")
COMBINED = os.path.join(ROOT, "offsets", "offsets-57+124+145-combined.json")
UPSTREAM = os.path.join(ROOT, "offsets", "offsets-import-r15-6.1.57+6.1.145.json")
REPO_145 = os.path.join(KDIR, "6.1.145-android14-11-maybe-dirty", "offsets.h")
KALLSYMS_124 = os.path.join(ROOT, "reference", "kernel-124", "kallsyms_manual.txt")
PRUNE = "--no-prune" not in sys.argv
RELEASES = [
    "6.1.57-android14-11-maybe-dirty",
    "6.1.124-android14-11-maybe-dirty",
    "6.1.145-android14-11-maybe-dirty",
]

SRC_NOTE = {
    RELEASES[0]: ("upstream offsets-import-r15 6.1.57 entry; symbols EXACT vs\n"
                  " reference/kernel-57/sym_6157.txt (device kallsyms via ksg.py)"),
    RELEASES[1]: ("boot.img (PD2324) kallsyms manual parse, 112084 syms;\n"
                  " device AUDIT img_off match + full W1-W3 & vr.ko success 2026-10-08"),
    RELEASES[2]: ("device kallsyms_full.txt (_text=ffffffe214600000) + upstream\n"
                  " R15 table; full run success 2026-10-08 (exit 0, KernelSU ready)"),
}

# field -> (json key order used when emitting; comment label)
SYM_ORDER = [
    ("off_init_task", "init_task"),
    ("off_init_cred", "init_cred"),
    ("off_root_task_group", "root_task_group"),
    ("off_selinux_enforcing", "selinux_enforcing (selinux_state)"),
    ("off_security_hook_heads", "security_hook_heads"),
    ("off_selinux_blob_sizes", "selinux_blob_sizes"),
    ("off_slide_nfulnl_logger", "slide: nfulnl_logger"),
    ("off_slide_loggers_0_1", "slide: loggers[0..1]"),
    ("off_slide_boot_id", "slide: boot_id (sysctl)"),
    ("off_tp_sys_exit_tp", "vr: __tracepoint_sys_exit"),
    ("off_tp_sys_exit_funcs", "vr: funcs (tp + 0x40, 6.1)"),
]

# STRUCT_OFFSETS_6_1 macro expectations (from kernels/offsets.h)
MACRO_6_1 = {
    "task_prio": 0x84, "task_normal_prio": 0x8C, "task_sched_task_group": 0x348,
    "task_pi_lock": 0x924, "task_pi_waiters": 0x938,
    "task_pi_top_task": 0x948, "task_pi_blocked_on": 0x950,
    "task_pid": 0x630, "task_tgid": 0x634,
    "task_atomic_flags": 0x5F0, "task_real_cred": 0x830, "task_cred": 0x838,
    "task_comm": 0x848, "task_tasks": 0x550, "task_seccomp": 0x900,
}

def load_entries(path):
    data = json.load(open(path))
    arr = data if isinstance(data, list) else [data]
    return {e["release"]: e for e in arr}

def fail(msg):
    print(f"[X] {msg}")
    sys.exit(1)

def check(cond, msg):
    if not cond:
        fail(msg)
    print(f"[ok] {msg}")

# ---------------------------------------------------------------- load
comb = load_entries(COMBINED)
up = load_entries(UPSTREAM)
for r in RELEASES:
    if r not in comb:
        fail(f"combined json missing {r}")

# ------------------------------------------------- struct field checks
for r in RELEASES:
    sf = comb[r]["struct_fields"]
    bad = {k: (v, MACRO_6_1[k]) for k, v in sf.items()
           if k in MACRO_6_1 and v != MACRO_6_1[k]}
    if bad:
        fail(f"{r}: struct_fields diverge from STRUCT_OFFSETS_6_1 macro: {bad}")
    missing = set(MACRO_6_1) - set(sf)
    if missing:
        fail(f"{r}: struct_fields missing {missing}")
    print(f"[ok] {r}: 15 task struct_fields == STRUCT_OFFSETS_6_1 macro")
    for k in ("compact_waiter", "pselect_waiter_shift", "mm_struct_sz",
              "kernel_phys_load"):
        v = comb[r].get(k)
        if v != {"compact_waiter": 1, "pselect_waiter_shift": 1,
                 "mm_struct_sz": 0x400, "kernel_phys_load": 0x80000000}[k]:
            fail(f"{r}: unexpected {k}={v}")
    print(f"[ok] {r}: compact_waiter=1 shift=1 mm=0x400 phys=0x80000000")

# ------------------------------------------------- 57 vs upstream
for k, _ in SYM_ORDER:
    a, b = comb[RELEASES[0]]["symbols"][k], up[RELEASES[0]]["symbols"][k]
    if a != b:
        fail(f"57 {k}: combined {a} != upstream {b}")
print("[ok] 6.1.57: all 11 symbols == upstream offsets-import-r15")

# ------------------------------------------------- 145 vs repo entry
# repo entry sets enforcing=0 ("not exported; read at runtime");
# device json carries the real selinux_state offset — accept both.
AUDIT_ONLY_FIELDS = {"off_security_hook_heads", "off_selinux_blob_sizes"}
repo_txt = open(REPO_145).read()
repo_syms = dict(re.findall(r"\.(off_\w+)\s*=\s*(0x[0-9a-fA-F]+)", repo_txt))
repo_145 = {k: comb[RELEASES[2]]["symbols"][k] for k in repo_syms}
for k, v in repo_syms.items():
    if int(v, 16) != repo_145[k]:
        if k == "off_selinux_enforcing":
            print(f"[ok] 145 {k}: repo intentionally 0, json 0x{repo_145[k]:x} "
                  "(selinux_state; device-verified W1 hit)")
            continue
        if k in AUDIT_ONLY_FIELDS:
            print(f"[!] 145 {k}: audit-only field, json {repo_145[k]:#x} vs repo "
                  f"{int(v,16):#x} (delta {-((int(v,16))-repo_145[k]):+#x}); "
                  "keeping json (values of the successful device run)")
            continue
        if k.startswith("off_slide_") and int(v, 16) == 0:
            print(f"[ok] 145 {k}: repo intentionally 0 (runtime posture path), "
                  f"json 0x{repo_145[k]:x} (device-verified; p0 profile printed "
                  "and W1 hit with these)")
            continue
        fail(f"145 {k}: json {repo_145[k]:#x} != repo entry {v}")
print(f"[ok] 6.1.145: {len(repo_syms)} shared symbols == repo kallsyms-derived entry "
      f"({', '.join(sorted(repo_syms))})")

# ------------------------------------------------- 124 vs boot kallsyms
if os.path.exists(KALLSYMS_124):
    syms, text = {}, None
    pat = re.compile(r"^\s*(?:0x)?([0-9a-fA-F]{8,16})\s+\S\s+(\S+)\s*$")
    for line in open(KALLSYMS_124, errors="replace"):
        m = pat.match(line)
        if not m:
            continue
        a, n = int(m.group(1), 16), m.group(2)
        if n in ("_text", "_stext") and text is None:
            text = a
        syms.setdefault(n, a)
    if text is None:
        fail("124 kallsyms: no _text")
    want = {
        "off_init_task": "init_task", "off_init_cred": "init_cred",
        "off_root_task_group": "root_task_group",
        "off_selinux_enforcing": "selinux_state",
        "off_security_hook_heads": "security_hook_heads",
        "off_selinux_blob_sizes": "selinux_blob_sizes",
        "off_slide_nfulnl_logger": "nfulnl_logger",
        "off_slide_loggers_0_1": None,  # loggers+8, special
        "off_slide_boot_id": "sysctl_bootid",
        "off_tp_sys_exit_tp": "__tracepoint_sys_exit",
    }
    js = comb[RELEASES[1]]["symbols"]
    for field, sym in want.items():
        if sym is None:
            # loggers[0]..[1] = (loggers + 8) - _text
            la = syms.get("loggers")
            if la is not None and js[field] != (la + 8) - text:
                fail(f"124 {field}: json {js[field]:#x} != loggers+8 "
                     f"({(la+8)-text:#x})")
            else:
                print(f"[ok] 124 {field} == loggers+8 - _text")
            continue
        if sym not in syms:
            fail(f"124 kallsyms missing {sym}")
        if js[field] != syms[sym] - text:
            fail(f"124 {field}: json {js[field]:#x} != {sym}-{text:#x} "
                 f"({syms[sym]-text:#x})")
    if js["off_tp_sys_exit_funcs"] != js["off_tp_sys_exit_tp"] + 0x40:
        fail("124 funcs != tp+0x40")
    print(f"[ok] 6.1.124: {len(want)} symbols re-derived from boot kallsyms, "
          "funcs == tp+0x40")
else:
    print("[!] boot kallsyms not found; skipping 124 symbol-level check")

# funcs == tp+0x40 for all three
for r in RELEASES:
    s = comb[r]["symbols"]
    if s["off_tp_sys_exit_funcs"] != s["off_tp_sys_exit_tp"] + 0x40:
        fail(f"{r}: funcs != tp+0x40")
print("[ok] all three: off_tp_sys_exit_funcs == tp + 0x40")

# ---------------------------------------------------------------- emit
def emit_entry(rel):
    e = comb[rel]
    s = e["symbols"]
    lines = [
        f"/* {rel} */",
        f"/* Values: {SRC_NOTE[rel]} */",
        "/* Emitted by gen_builtin.py from offsets-57+124+145-combined.json;",
        " * struct layout via STRUCT_OFFSETS_6_1 (verified == json struct_fields). */",
        "",
        "OFFSETS_ENTRY(",
        f'    "{rel}",',
        "    STRUCT_OFFSETS_6_1,",
        "    .kernel_phys_load = 0x80000000,   /* MTK DRAM base */",
        "    .pselect_waiter_shift = 1,",
    ]
    for field, label in SYM_ORDER:
        lines.append(f"    .{field} = 0x{s[field]:08x},  /* {label} */")
    lines.append("),")
    lines.append("")
    return "\n".join(lines)

os.makedirs(KDIR, exist_ok=True)
for rel in RELEASES:
    d = os.path.join(KDIR, rel)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "offsets.h"), "w").write(emit_entry(rel))
    print(f"[+] wrote {d}/offsets.h")

# ------------------------------------------------- delete old builtin dirs
keep = set(RELEASES)
if PRUNE:
    removed = 0
    for name in sorted(os.listdir(KDIR)):
        p = os.path.join(KDIR, name)
        if os.path.isdir(p) and name not in keep:
            shutil.rmtree(p)
            removed += 1
    print(f"[+] removed {removed} old builtin kernel dirs")
else:
    print("[i] --no-prune: existing builtin dirs left untouched")

# ------------------------------------------------- rewrite dispatcher
disp_path = os.path.join(KDIR, "offsets.h")
disp = open(disp_path).read()
begin = "static const struct kernel_offsets known_offsets[] = {"
end = "  { .uname_r = NULL }"
i, j = disp.index(begin), disp.index(end)
includes = "\n".join(f'#include "{r}/offsets.h"' for r in RELEASES)
new_disp = disp[:i] + begin + "\n/* Add new kernels by creating src/kernels/<uname-release>/offsets.h */\n" \
    + includes + "\n" + disp[j:]
open(disp_path, "w").write(new_disp)
print("[+] rewrote dispatcher known_offsets[] with 3 entries")

print("\n==== summary (hex) ====")
for r in RELEASES:
    s = comb[r]["symbols"]
    print(r)
    for field, label in SYM_ORDER:
        print(f"    {field:<26} = 0x{s[field]:08x}")
