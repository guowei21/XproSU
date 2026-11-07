#!/usr/bin/env python3
"""Cross-check every anchor table's plan symbols against an independent
source: the old tool's parsed ic-syms-*.txt files (dist/).

Usage: verify_tables.py ANCHORS_H SYMS_DIR

For each (syms file, build version) pair it compares __tracepoint_sys_exit,
selinux_state, init_user_ns and init_cred; prints OK or the mismatching
symbol.  Exit status is non-zero if any table disagrees.
"""
import re
import sys

h, syms_dir = sys.argv[1], sys.argv[2]
rows = re.findall(r'\{ "([^"]*)", "([^"]*)", "([^"]*)", "([^"]*)", \{\s*([^}]*)\} \},',
                  open(h, encoding="utf-8").read())
tab = {}
for k, m, v, n, vals in rows:
    vv = [int(x.strip().replace("ULL", ""), 16) for x in vals.split(",") if x.strip()]
    tab.setdefault(v, []).append((n, vv[-4], vv[-3], vv[-2], vv[-1]))

pairs = [
    ("ic-syms-6.1.145-gf506252.txt", "16.1.15.0"),
    ("ic-syms-6.1.145-y500-g3de37d73fd1d.txt", "16.1.13.2"),
    ("ic-syms-6.1.145-y500pro-g486be3ece60a.txt", "16.1.11.0"),
    ("ic-syms-6.1.145-pd2307-16.2.20.7.txt", "16.2.20.7"),
    ("ic-syms-6.1.145-pd2307-16.2.21.1.txt", "16.2.21.1"),
    ("ic-syms-6.1.145-pd2324-maybe-dirty.txt", "16.2.12.0"),
    ("ic-syms-6.1.145-pd2324j-16.2.13.1.txt", "16.2.13.1"),
    ("ic-syms-6.1.145-pd2417-16.2.14.1.txt", "16.2.14.1"),
]
rc = 0
for f, ver in pairs:
    d = {}
    for line in open("%s/%s" % (syms_dir, f), encoding="utf-8", errors="replace"):
        m = re.match(r"(\w+)=(0x[0-9a-fA-F]+)", line.strip())
        if m:
            d[m.group(1)] = int(m.group(2), 16)
    cand = tab.get(ver)
    if not cand:
        print("%-10s NO TABLE ENTRY" % ver)
        rc = 1
        continue
    n, tp, sel, ns, cred = cand[0]
    bad = []
    for name, val in [("__tracepoint_sys_exit", tp), ("selinux_state", sel),
                      ("init_user_ns", ns), ("init_cred", cred)]:
        got = d.get(name)
        if got is not None and got != val:
            bad.append("%s table=%#x file=%#x" % (name, val, got))
    print("%-10s %-26s %s" % (ver, n, "OK" if not bad else "MISMATCH: " + "; ".join(bad)))
    if bad:
        rc = 1
sys.exit(rc)
