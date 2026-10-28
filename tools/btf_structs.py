#!/usr/bin/env python3
"""Dump struct layouts from a live-kernel BTF blob (e.g. /sys/kernel/btf/vmlinux).

Usage: python tools/btf_structs.py <vmlinux.btf> [StructName ...]

Prints byte offsets of every member, resolving anonymous struct/union
members the way C does (nested offsets are added to the parent).
"""
import struct
import sys

BTF_MAGIC = 0xEB9F

KIND_INT = 1
KIND_PTR = 2
KIND_ARRAY = 3
KIND_STRUCT = 4
KIND_UNION = 5
KIND_ENUM = 6
KIND_FWD = 7
KIND_TYPEDEF = 8
KIND_VOLATILE = 9
KIND_CONST = 10
KIND_RESTRICT = 11
KIND_FUNC = 12
KIND_FUNC_PROTO = 13
KIND_VAR = 14
KIND_DATASEC = 15
KIND_FLOAT = 16
KIND_DECL_TAG = 17
KIND_TYPE_TAG = 18
KIND_ENUM64 = 19

KIND_NAMES = {
    1: "int", 2: "ptr", 3: "array", 4: "struct", 5: "union", 6: "enum",
    7: "fwd", 8: "typedef", 9: "volatile", 10: "const", 11: "restrict",
    12: "func", 13: "func_proto", 14: "var", 15: "datasec", 16: "float",
    17: "decl_tag", 18: "type_tag", 19: "enum64",
}


class BtfType:
    __slots__ = ("id", "name", "kind", "vlen", "kflag", "size", "members", "extra")

    def __init__(self, tid, name, kind, vlen, kflag, size):
        self.id = tid
        self.name = name
        self.kind = kind
        self.vlen = vlen
        self.kflag = kflag
        self.size = size
        self.members = []  # (name, type_id, bit_offset) for struct/union
        self.extra = None


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def s32(buf, off):
    return struct.unpack_from("<i", buf, off)[0]


def parse_types(buf):
    magic, version, flags, hdr_len = struct.unpack_from("<HBBI", buf, 0)
    if magic != BTF_MAGIC:
        raise SystemExit(f"not a BTF file (magic={magic:#x})")
    if version != 1:
        raise SystemExit(f"unsupported BTF version {version}")
    type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", buf, 8)
    types_blob = buf[hdr_len + type_off: hdr_len + type_off + type_len]
    strings = buf[hdr_len + str_off: hdr_len + str_off + str_len]

    def name_at(off):
        if off == 0:
            return ""
        end = strings.find(b"\0", off)
        return strings[off:end].decode("utf-8", "replace")

    out = {}
    off = 0
    tid = 1
    while off < len(types_blob):
        name_off = u32(types_blob, off)
        info = u32(types_blob, off + 4)
        size_or_type = u32(types_blob, off + 8)
        off += 12
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        kflag = info >> 31
        t = BtfType(tid, name_at(name_off), kind, vlen, kflag, size_or_type)

        if kind == KIND_INT:
            off += 4
        elif kind == KIND_ARRAY:
            t.extra = (
                u32(types_blob, off),
                u32(types_blob, off + 4),
                u32(types_blob, off + 8),
            )
            off += 12
        elif kind in (KIND_STRUCT, KIND_UNION):
            for _ in range(vlen):
                m_name = name_at(u32(types_blob, off))
                m_type = u32(types_blob, off + 4)
                m_off = u32(types_blob, off + 8)
                if kflag:
                    bit_off = m_off & 0xFFFFFF
                    bit_size = m_off >> 24
                else:
                    bit_off = m_off
                    bit_size = 0
                t.members.append((m_name, m_type, bit_off, bit_size))
                off += 12
        elif kind == KIND_ENUM:
            off += 8 * vlen
        elif kind == KIND_FUNC_PROTO:
            off += 8 * vlen
        elif kind == KIND_VAR:
            off += 4
        elif kind == KIND_DATASEC:
            off += 12 * vlen
        elif kind == KIND_DECL_TAG:
            off += 4
        elif kind == KIND_ENUM64:
            off += 12 * vlen
        # ptr/fwd/typedef/volatile/const/restrict/func/float/type_tag: no extra
        out[tid] = t
        tid += 1
    return out


def resolve(types, tid):
    """Follow typedef/const/volatile/restrict/type_tag to the underlying type."""
    seen = set()
    while tid in types and tid not in seen:
        seen.add(tid)
        t = types[tid]
        if t.kind in (KIND_TYPEDEF, KIND_CONST, KIND_VOLATILE, KIND_RESTRICT, KIND_TYPE_TAG):
            tid = t.size
        else:
            return t
    return types.get(tid)


def type_name(types, tid, depth=0):
    t = types.get(tid)
    if t is None:
        return f"<{tid}>"
    if t.kind == KIND_PTR:
        return type_name(types, t.size, depth + 1) + " *"
    if t.kind == KIND_ARRAY:
        elem, _index, n = t.extra
        return f"{type_name(types, elem, depth + 1)}[{n}]"
    if t.kind in (KIND_STRUCT, KIND_UNION):
        tag = KIND_NAMES[t.kind]
        return f"{tag} {t.name or '<anon>'}"
    if t.kind == KIND_TYPEDEF:
        return t.name
    if t.kind == KIND_INT:
        return t.name or "int"
    if t.kind == KIND_FUNC_PROTO:
        return "func_proto"
    if t.kind == KIND_FUNC:
        return "func"
    return t.name or KIND_NAMES.get(t.kind, f"kind{t.kind}")


def dump_struct(types, t, prefix="", depth=0, max_depth=6):
    tag = KIND_NAMES[t.kind]
    print(f"{prefix}{tag} {t.name} size={t.size:#x} ({t.size})")
    if depth >= max_depth:
        return
    for name, mtype, bit_off, bit_size in t.members:
        if bit_off % 8:
            off_note = f" bit={bit_off} bits={bit_size}"
        else:
            off_note = ""
        label = name.rsplit(":", 1)[-1] if ":" in name else name
        line = f"  {prefix}{label:<24} +{bit_off // 8:#05x}{off_note:<18} {type_name(types, mtype)}"
        print(line.rstrip())
        mt = resolve(types, mtype)
        if mt is not None and mt.kind in (KIND_STRUCT, KIND_UNION) and (not mt.name or "." in name or ":" in name or mt.name == ""):
            # Descend into anonymous inline struct/union members only.
            if mt.name == "" or ":" in name:
                dump_struct(types, mt, prefix + "    ", depth + 1, max_depth)


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    path = sys.argv[1]
    wanted = sys.argv[2:]
    buf = open(path, "rb").read()
    types = parse_types(buf)
    print(f"# parsed {len(types)} types from {path}")
    by_name = {}
    for t in types.values():
        if t.kind in (KIND_STRUCT, KIND_UNION) and t.name:
            by_name.setdefault(t.name, t)
    if not wanted:
        print("# pass one or more struct names, e.g. k_itimer task_struct cred")
        print("# known:", " ".join(sorted(by_name)[:40]), "...")
        return
    for name in wanted:
        t = by_name.get(name)
        if t is None:
            print(f"\n# {name}: not found")
            continue
        print()
        dump_struct(types, t)


if __name__ == "__main__":
    main()
