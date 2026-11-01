"""Map an upstream kernel profile (.conf, HOCON) onto our offsets.json schema.

Upstream moved kernel offsets out of compiled headers and into
app/src/main/assets/kernel_profiles/<release>.conf. Only part of that data is
portable to this tree:

    task_struct.<k>                     -> struct_fields.task_<k>
    kernelsnitch.mm_struct_sz           -> mm_struct_sz
    route.tcp_zerocopy.compact_waiter   -> compact_waiter
    fallback.select_stack.waiter_shift  -> pselect_waiter_shift

Everything else stays local on purpose:

    cred { copy_size, caps_offset, ... }  upstream copies the whole cred struct;
                                          we write fields one by one. Mixing the
                                          two strategies is not possible.
    kernel_phys_load / kernel_phys_offset upstream ships null and derives at
                                          runtime; ours are measured per device.
    btf_size, symbols.off_*, waiter_*     no upstream counterpart.

A key that upstream does not provide is left untouched -- losing a measured
value is worse than carrying a stale one, and a missing key falls back to the
compiled-in table silently.

Usage:
    # show what would change, write nothing
    python tools/sync/conf_to_offsets.py <profile.conf> --target <offsets.json> --diff

    # apply
    python tools/sync/conf_to_offsets.py <profile.conf> --target <offsets.json> --write
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# upstream field -> our flat struct_fields key
TASK_MAP = {
    "prio": "task_prio",
    "normal_prio": "task_normal_prio",
    "sched_task_group": "task_sched_task_group",
    "pi_lock": "task_pi_lock",
    "pi_waiters": "task_pi_waiters",
    "pi_top_task": "task_pi_top_task",
    "pi_blocked_on": "task_pi_blocked_on",
    "pid": "task_pid",
    "tgid": "task_tgid",
    "atomic_flags": "task_atomic_flags",
    "real_cred": "task_real_cred",
    "cred": "task_cred",
    "comm": "task_comm",
    "tasks": "task_tasks",
}


# ---------------------------------------------------------------- HOCON subset

_COMMENT = re.compile(r"(?:#|//)[^\n]*")


def _strip_comments(text: str) -> str:
    out, in_str, i = [], False, 0
    while i < len(text):
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        m = _COMMENT.match(text, i)
        if m:
            out.append(" " * (m.end() - m.start()))
            i = m.end()
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _tokens(text: str) -> list[str]:
    """Split into { } = and bare tokens, keeping quoted strings intact."""
    toks, buf, i = [], [], 0
    while i < len(text):
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < len(text):
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            if buf:
                toks.append("".join(buf))
                buf = []
            toks.append(text[i : j + 1])
            i = j + 1
            continue
        if ch in "{}=":
            if buf:
                toks.append("".join(buf).strip())
                buf = []
            toks.append(ch)
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        toks.append("".join(buf).strip())
    return [t for t in toks if t != ""]


def _tokens(text: str) -> list[str]:
    """Split into { } = and bare tokens, keeping quoted strings intact.

    Whitespace separates tokens too: the profiles put one assignment per line
    (`prio = 132`), and without this `132\n  normal_prio` collapses into one
    bogus value.
    """
    toks, buf, i = [], [], 0
    while i < len(text):
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < len(text):
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            if buf:
                toks.append("".join(buf).strip())
                buf = []
            toks.append(text[i : j + 1])
            i = j + 1
            continue
        if ch in "{}=":
            if buf:
                toks.append("".join(buf).strip())
                buf = []
            toks.append(ch)
            i += 1
            continue
        if ch.isspace() or ch == ",":
            if buf:
                toks.append("".join(buf).strip())
                buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        toks.append("".join(buf).strip())
    return [t for t in toks if t != ""]


def parse_hocon(text: str, base_dir: Path, _depth: int = 0) -> dict:
    """Nested dict from the HOCON subset upstream actually uses.

    Handles: include "x.conf", key = value, key { ... }, comments.
    """
    if _depth > 8:
        raise ValueError("include depth exceeded")
    toks = _tokens(_strip_comments(text))
    result: dict = {}
    stack = [result]
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok == "}":
            if len(stack) > 1:
                stack.pop()
            i += 1
            continue
        if tok == "include" or (i + 1 < len(toks) and toks[i + 1] == "=" and tok == "include"):
            # include "file"
            j = i + 1
            if j < len(toks) and toks[j] == "=":
                j += 1
            if j < len(toks) and toks[j].startswith('"'):
                name = toks[j].strip('"')
                inc = base_dir / name
                if inc.is_file():
                    merged = parse_hocon(inc.read_text(encoding="utf-8"), base_dir, _depth + 1)
                    for k, v in merged.items():
                        stack[-1].setdefault(k, v)
                i = j + 1
                continue
            i += 1
            continue
        if i + 1 < len(toks) and toks[i + 1] == "=":
            key = tok
            raw = toks[i + 2] if i + 2 < len(toks) else "null"
            stack[-1][key] = _value(raw)
            i += 3
            continue
        if i + 1 < len(toks) and toks[i + 1] == "{":
            child: dict = {}
            stack[-1][tok] = child
            stack.append(child)
            i += 2
            continue
        i += 1
    return result


def _value(raw: str):
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw in ("null", "NULL", "~"):
        return None
    if raw == "true":
        return True
    if raw == "false":
        return False
    try:
        return int(raw, 0)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw


# ------------------------------------------------------------------- mapping

def map_profile(conf: dict) -> dict:
    """Profile dict -> the subset of our offsets entry we are allowed to touch."""
    out: dict = {}
    task = conf.get("task_struct") or {}
    fields = {}
    for up_key, ours in TASK_MAP.items():
        if up_key in task and task[up_key] is not None:
            fields[ours] = task[up_key]
    if fields:
        out["struct_fields"] = fields

    snitch = conf.get("kernelsnitch") or {}
    if snitch.get("mm_struct_sz") is not None:
        out["mm_struct_sz"] = snitch["mm_struct_sz"]

    route = ((conf.get("route") or {}).get("tcp_zerocopy") or {})
    if route.get("compact_waiter") is not None:
        out["compact_waiter"] = route["compact_waiter"]

    fallback = conf.get("fallback") or {}
    select = ((fallback.get("route") or {}).get("select_stack") or {})
    shift = select.get("waiter_shift", fallback.get("waiter_shift"))
    if shift is not None:
        out["pselect_waiter_shift"] = shift

    return out


def apply_entry(target: dict, mapped: dict) -> list[tuple[str, object, object]]:
    """Merge mapped values into one offsets entry; return (key, old, new) changes."""
    changes: list[tuple[str, object, object]] = []
    for key, new in mapped.items():
        if key == "struct_fields":
            dst = target.setdefault("struct_fields", {})
            for fk, fv in new.items():
                old = dst.get(fk)
                if old != fv:
                    changes.append((f"struct_fields.{fk}", old, fv))
                    dst[fk] = fv
        else:
            old = target.get(key)
            if old != new:
                changes.append((key, old, new))
                target[key] = new
    return changes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("profile", type=Path, help="upstream kernel_profiles/<release>.conf")
    ap.add_argument("--target", type=Path, required=True, help="our offsets.json (array of entries)")
    ap.add_argument("--diff", action="store_true", help="print changes, write nothing (default)")
    ap.add_argument("--write", action="store_true", help="apply the changes to --target")
    ap.add_argument("--force-release", help="override the release used to pick the target entry")
    args = ap.parse_args()

    if not args.profile.is_file():
        raise SystemExit(f"no such profile: {args.profile}")
    if not args.target.is_file():
        raise SystemExit(f"no such target: {args.target}")

    conf = parse_hocon(args.profile.read_text(encoding="utf-8"), args.profile.parent)
    release = args.force_release or conf.get("release")
    if not release:
        raise SystemExit("profile has no release key; pass --force-release")

    mapped = map_profile(conf)
    if not mapped:
        raise SystemExit("profile carried nothing we are allowed to sync")

    data = json.loads(args.target.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit("target is not an array of entries")

    entry = next((e for e in data if e.get("release") == release), None)
    if entry is None:
        known = ", ".join(e.get("release", "?") for e in data)
        raise SystemExit(f"release {release!r} not in target; known: {known}")

    changes = apply_entry(entry, mapped)

    print(f"profile : {args.profile.name}")
    print(f"release : {release}")
    print(f"target  : {args.target.name}")
    print(f"mapped  : {len(mapped.get('struct_fields', {}))} struct fields, "
          f"{len(mapped) - (1 if 'struct_fields' in mapped else 0)} scalars")
    print("")
    if not changes:
        print("no changes: local values already match the upstream profile")
        return 0

    for key, old, new in changes:
        print(f"  {key:34} {old!r:>12} -> {new!r}")

    if args.write:
        args.target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print("")
        print(f"written: {args.target}")
        print("next    : python tools/pack_offsets_local.py app/src/main/assets/offsets.enc "
              f"{args.target}")
    else:
        print("")
        print("(dry run -- pass --write to apply)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
