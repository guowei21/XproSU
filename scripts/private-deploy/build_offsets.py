#!/usr/bin/env python3
"""
build_offsets.py — 从 kallsyms / System.map / vmlinux 生成 GhostLock 需要的
offsets.json 条目(symbols 块全部相对 _text)。

用法:
  # 1) 有 kallsyms 文本(例如 root 后 cat /proc/kallsyms,或 System.map)
  python3 build_offsets.py --kallsyms kallsyms.txt --release "6.1.57-android14-11-maybe-dirty"

  # 2) 有 vmlinux(带符号表)
  python3 build_offsets.py --vmlinux vmlinux --release "..."

  # 3) 想直接合并进现有 offsets.json(替换/追加同名 release 条目)
  python3 build_offsets.py --kallsyms kallsyms.txt --release "..." \
      --template device_offsets.json --merge -o offsets.fixed.json

需要的符号(R15 引擎实际会读的):
  off_selinux_enforcing  <- selinux_state            (enforcing 在 struct 偏移 0)
  off_init_cred          <- init_cred
  off_init_task          <- init_task
  off_root_task_group    <- root_task_group
  off_tp_sys_exit_tp     <- __tracepoint_sys_exit    (funcs = tp + 0x40 @6.1)
  off_security_hook_heads<- security_hook_heads      (仅审计打印,填上更保险)
  off_selinux_blob_sizes <- selinux_blob_sizes       (仅审计打印)
  off_slide_*            <- 只用于日志,填 0 即可
"""
import argparse, json, re, subprocess, sys

# 目标符号 -> 引擎字段名
SYMS = [
    ("init_task",             "off_init_task"),
    ("init_cred",             "off_init_cred"),
    ("root_task_group",       "off_root_task_group"),
    ("selinux_state",         "off_selinux_enforcing"),
    ("security_hook_heads",   "off_security_hook_heads"),
    ("selinux_blob_sizes",    "off_selinux_blob_sizes"),
    ("__tracepoint_sys_exit", "off_tp_sys_exit_tp"),
]
# 允许的别名(不同内核/符号修饰)
ALIAS = {
    "selinux_enforcing": "selinux_state",
    "selinux_state":     "selinux_state",
}
TEXT_NAMES = ["_text", "_stext", "__start_kernel"]  # __start_kernel 只作为最后兜底


def parse_kallsyms(path):
    addr = {}
    pat = re.compile(r"^\s*(?:0x)?([0-9a-fA-F]{8,16})\s+\S\s+(\S+)\s*$")
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = pat.match(line)
            if not m:
                continue
            a = int(m.group(1), 16)
            n = m.group(2)
            # 只保留第一个(同名符号取最早出现的)
            if n not in addr or a < addr[n]:
                addr[n] = a
    return addr


def parse_vmlinux_nm(path):
    try:
        out = subprocess.run(["llvm-nm", "-n", path], capture_output=True, text=True).stdout
        if not out.strip():
            raise FileNotFoundError
    except (FileNotFoundError, subprocess.SubprocessError):
        out = subprocess.run(["nm", "-n", path], capture_output=True, text=True).stdout
    addr = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 3 and re.fullmatch(r"[0-9a-fA-F]+", p[0]):
            addr.setdefault(p[2], int(p[0], 16))
    if not addr:
        sys.exit("[!] nm 没解析出符号;vmlinux 可能被 strip 了")
    return addr


def resolve(addr, name):
    n = ALIAS.get(name, name)
    if n in addr:
        return n, addr[n]
    # 带前缀的变体(例如某些内核里是 selinux_state.x)
    for k, v in addr.items():
        if k == n or k.split(".")[0] == n:
            return k, v
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kallsyms")
    ap.add_argument("--vmlinux")
    ap.add_argument("--release", required=True)
    ap.add_argument("--template", help="现有 offsets.json(取 struct_fields / kernel_phys_load 等)")
    ap.add_argument("--merge", action="store_true", help="把新条目写回 template 数组")
    ap.add_argument("-o", "--out", default="-")
    a = ap.parse_args()

    if a.kallsyms:
        addr = parse_kallsyms(a.kallsyms)
    elif a.vmlinux:
        addr = parse_vmlinux_nm(a.vmlinux)
    else:
        sys.exit("[!] 需要 --kallsyms 或 --vmlinux")

    text = None
    for t in TEXT_NAMES:
        if t in addr:
            text = addr[t]
            print(f"[+] 基址 {t} = 0x{text:016x}")
            break
    if text is None:
        mn = min(addr.values())
        text = mn
        print(f"[!] 找不到 _text,用最小地址 0x{mn:016x} 近似(可能有偏差)")

    sym = {}
    missing = []
    for want, field in SYMS:
        k, v = resolve(addr, want)
        if v is None:
            missing.append(want)
            print(f"[!] 缺符号 {want}  -> {field}")
        else:
            off = v - text
            sym[field] = off
            print(f"[+] {field:<24} = 0x{off:08x}   ({k} @0x{v:016x})")
    # 6.1: tracepoint->funcs 在 +0x40
    if "off_tp_sys_exit_tp" in sym:
        sym["off_tp_sys_exit_funcs"] = sym["off_tp_sys_exit_tp"] + 0x40
    for f in ("off_slide_nfulnl_logger", "off_slide_boot_id", "off_slide_loggers_0_1"):
        sym.setdefault(f, 0)

    entry = {"release": a.release, "symbols": sym}

    if a.template:
        tpl = json.load(open(a.template))
        arr = tpl if isinstance(tpl, list) else [tpl]
        base = next((e for e in arr if e.get("release", "").startswith("6.1.")), arr[0])
        for k in ("struct_fields", "kernel_phys_load", "mm_struct_sz",
                  "pselect_waiter_shift", "compact_waiter"):
            if k in base:
                entry[k] = base[k]
        if a.merge:
            arr = [e for e in arr if e.get("release") != a.release] + [entry]
            entry = arr
    out = json.dumps(entry, indent=2, ensure_ascii=False) + "\n"
    if a.out == "-":
        print(out)
    else:
        open(a.out, "w").write(out)
        print(f"[+] 写出 {a.out}")
    if missing:
        print("\n[!] 以上符号缺失。除 selinux_state / init_cred / init_task / "
              "root_task_group / __tracepoint_sys_exit 之外\n"
              "    (hook_heads / blob_sizes 只用于日志),缺一个都会让对应阶段失败。",
              file=sys.stderr)


if __name__ == "__main__":
    main()
