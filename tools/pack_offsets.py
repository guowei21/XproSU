#!/usr/bin/env python3
"""Pack one or more offsets JSON documents into a .glt binary container.

Companion to src/core/offsets_bin.c.  Run this on the build host; the engine
reads the result instead of plaintext JSON so that `strings` on the APK no
longer yields the offset table.

The input is the same shape load_offsets_json() accepts: either a top-level
array of entries or a single entry object, each carrying "release", the
scalars, "symbols" and "struct_fields".

    python tools/pack_offsets.py out.glt offsets/*.json
    python tools/pack_offsets.py out.glt --salt 0011223344556677 offsets/a.json

WHAT THIS IS NOT: encryption.  The keystream key below is compiled into
libghostlock.so as well, so a disassembler recovers the table.  This defeats
`strings`/`grep`/`xxd`, not a reverser.  Device binding arrives when the key
comes from the server (ENCRYPTION-PLAN.md section 3); the container layout and
the ChaCha20 transform are already what that stage needs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

MAGIC = b"GLT1"
VERSION = 1
FLAG_OBFUSCATED = 0x01
HDR_SIZE = 16
ENTRY_HDR_SIZE = 8
FIELD_SIZE = 10

# Must stay byte-identical to GLT_KEY in src/core/offsets_bin.c.
GLT_KEY = bytes(
    [
        0x9E, 0x37, 0x4B, 0x12, 0x7C, 0xA5, 0x0D, 0x66,
        0x21, 0x8F, 0xD3, 0x5A, 0xB4, 0x70, 0x1C, 0xE9,
        0x53, 0x2D, 0x88, 0xAF, 0x06, 0x91, 0x4E, 0x3B,
        0xC2, 0x65, 0x19, 0xF7, 0x08, 0xDA, 0x72, 0x4D,
    ]
)

# On-disk field ids; must match enum glt_fid in src/core/offsets_bin.c.
FID = {
    "kernel_phys_load": 0x11,
    "pselect_waiter_shift": 0x12,
    "off_init_task": 0x21,
    "off_init_cred": 0x22,
    "off_root_task_group": 0x23,
    "off_selinux_enforcing": 0x24,
    "off_selinux_blob_sizes": 0x25,
    "off_security_hook_heads": 0x26,
    "off_slide_nfulnl_logger": 0x27,
    "off_slide_loggers_0_1": 0x28,
    "off_slide_boot_id": 0x29,
    "off_tp_sys_exit_tp": 0x31,
    "off_tp_sys_exit_funcs": 0x32,
    "task_prio": 0x41,
    "task_normal_prio": 0x42,
    "task_sched_task_group": 0x43,
    "task_pi_lock": 0x44,
    "task_pi_waiters": 0x45,
    "task_pi_top_task": 0x46,
    "task_pi_blocked_on": 0x47,
    "task_pid": 0x48,
    "task_tgid": 0x49,
    "task_atomic_flags": 0x4A,
    "task_real_cred": 0x4B,
    "task_cred": 0x4C,
    "task_comm": 0x4D,
    "task_tasks": 0x4E,
    "task_seccomp": 0x4F,
    "compact_waiter": 0x51,
    "mm_struct_sz": 0x52,
}

# Only these keys are read by the engine, so only these travel.  The JSON
# documents carry ~18 further struct_fields (cred_*, seccomp_*, waiter_*,
# struct_*) that nothing dereferences; leaving them out keeps the container
# smaller and leaks less.
SCALAR_KEYS = ("kernel_phys_load", "pselect_waiter_shift", "compact_waiter",
               "mm_struct_sz")
SYMBOL_KEYS = (
    "off_init_task", "off_init_cred", "off_root_task_group",
    "off_selinux_enforcing", "off_selinux_blob_sizes",
    "off_security_hook_heads", "off_slide_nfulnl_logger",
    "off_slide_loggers_0_1", "off_slide_boot_id",
    "off_tp_sys_exit_tp", "off_tp_sys_exit_funcs",
)
STRUCT_KEYS = (
    "task_prio", "task_normal_prio", "task_sched_task_group",
    "task_pi_lock", "task_pi_waiters", "task_pi_top_task",
    "task_pi_blocked_on", "task_pid", "task_tgid", "task_atomic_flags",
    "task_real_cred", "task_cred", "task_comm", "task_tasks", "task_seccomp",
)


# ---------------------------------------------------------------- ChaCha20 ---

def _rotl32(v: int, c: int) -> int:
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF


def _qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl32(x[b] ^ x[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """RFC 8439 section 2.3.1 block function."""
    assert len(key) == 32 and len(nonce) == 12
    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    st += list(struct.unpack("<8I", key))
    st += [counter]
    st += list(struct.unpack("<3I", nonce))
    x = list(st)
    for _ in range(10):
        _qr(x, 0, 4, 8, 12)
        _qr(x, 1, 5, 9, 13)
        _qr(x, 2, 6, 10, 14)
        _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15)
        _qr(x, 1, 6, 11, 12)
        _qr(x, 2, 7, 8, 13)
        _qr(x, 3, 4, 9, 14)
    return struct.pack("<16I", *[(x[i] + st[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20_keystream(key: bytes, counter: int, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        out += chacha20_block(key, counter, nonce)
        counter += 1
    return bytes(out[:n])


def chacha20_selftest() -> None:
    """RFC 8439 section 2.3.2 vector; a wrong implementation must not ship."""
    key = bytes(range(32))
    nonce = bytes([0, 0, 0, 9, 0, 0, 0, 0x4A, 0, 0, 0, 0])
    want = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    )
    got = chacha20_block(key, 1, nonce)
    if got != want:
        raise SystemExit("pack_offsets: ChaCha20 self-test FAILED (RFC 8439 2.3.2)")


# ------------------------------------------------------------------ format ---

def release_hash(release: str) -> int:
    """FNV-1a-32, matching glt_release_hash() in src/core/offsets_bin.c."""
    h = 0x811C9DC5
    for b in release.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def collect_fields(entry: dict) -> dict:
    """Pull the fields the engine reads out of one JSON entry."""
    fields: dict = {}
    for k in SCALAR_KEYS:
        if k in entry and entry[k] is not None:
            fields[k] = int(entry[k])
    for group, keys in (("symbols", SYMBOL_KEYS), ("struct_fields", STRUCT_KEYS)):
        src = entry.get(group) or {}
        for k in keys:
            if k in src and src[k] is not None:
                fields[k] = int(src[k])
    return fields


def load_entries(paths) -> list:
    entries = []
    for p in paths:
        with open(p, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        if isinstance(doc, dict):
            doc = [doc]
        for e in doc:
            if not isinstance(e, dict) or "release" not in e:
                raise SystemExit(f"pack_offsets: {p}: entry without 'release'")
            entries.append(e)
    return entries


def build_container(entries, salt: int) -> bytes:
    # Deterministic order so the same inputs always produce the same file.
    entries = sorted(entries, key=lambda e: e["release"])

    seen = {}
    for e in entries:
        rel = e["release"]
        if rel in seen:
            raise SystemExit(f"pack_offsets: duplicate release {rel}")
        seen[rel] = True

    body = bytearray()
    for idx, e in enumerate(entries):
        rel = e["release"]
        fields = collect_fields(e)
        missing = [k for k in FID if k not in fields]
        if missing:
            # Refuse at build time: the engine's gates would reject this entry
            # on the device, where the failure is far more expensive to read.
            raise SystemExit(
                f"pack_offsets: {rel}: missing {len(missing)} field(s): "
                + ", ".join(sorted(missing))
            )

        nonce = struct.pack("<I", idx) + struct.pack("<Q", salt)
        ids = sorted(FID, key=lambda k: FID[k])
        ks = chacha20_keystream(GLT_KEY, 0, nonce, len(ids) * 8)

        body += struct.pack("<IHH", release_hash(rel), len(ids), 0)
        for i, k in enumerate(ids):
            value = fields[k] & 0xFFFFFFFFFFFFFFFF
            stream = struct.unpack("<Q", ks[i * 8:i * 8 + 8])[0]
            body += struct.pack("<HQ", FID[k], value ^ stream)

    header = MAGIC + bytes([VERSION, FLAG_OBFUSCATED])
    header += struct.pack("<H", len(entries))
    header += struct.pack("<Q", salt)
    assert len(header) == HDR_SIZE
    return bytes(header + body)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("output", help="path of the .glt to write")
    ap.add_argument("inputs", nargs="+", help="offsets JSON documents")
    ap.add_argument("--salt", default=None,
                    help="64-bit salt as 16 hex digits; random when omitted. "
                         "The reader takes it from the header, so any value "
                         "works -- pin it to reproduce a build byte for byte.")
    args = ap.parse_args()

    chacha20_selftest()

    if args.salt is None:
        salt = int.from_bytes(os.urandom(8), "little")
    else:
        salt = int(args.salt, 16) & 0xFFFFFFFFFFFFFFFF

    entries = load_entries(args.inputs)
    blob = build_container(entries, salt)
    with open(args.output, "wb") as fh:
        fh.write(blob)

    print(f"wrote {args.output}: {len(blob)} bytes, {len(entries)} entries, "
          f"salt=0x{salt:016x}")
    for e in sorted(entries, key=lambda x: x["release"]):
        n = len(collect_fields(e))
        print(f"  {release_hash(e['release']):08x}  {e['release']}  {n} fields")
    print(f"  sha256 {hashlib.sha256(blob).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
