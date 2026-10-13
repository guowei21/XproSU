#!/usr/bin/env python3
"""Decode a stage-1 GLT1 container back into a plaintext offset table.

Why this exists: the plaintext tables live in the private build tree
(`ghostlock-57-124-145-project/`), but the only artefact that is guaranteed to
be present here is the shipped `app/src/main/assets/offsets.glt`.  Stage 2 needs
a plaintext table on the *server* (as `payload.bin`), so this tool recovers it
from the shipped container -- it is the bridge between the stage-1 and stage-2
formats, and it is a PC-side tool that never ships.

The GLT1 keystream key is a compile-time constant in `src/core/offsets_bin.c`
(`GLT_KEY`).  It was never a secret -- see ENCRYPTION-PLAN.md section 4.4 item 2 --
which is exactly why stage 2 replaces it with a per-device key.

Usage:
    python glt1_extract.py <offsets.glt> [-o table.json]
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server" / "gl-license"))
from crypto import _chacha20_keystream, fnv1a32  # noqa: E402

# Stage-1 obfuscation key, verbatim from src/core/offsets_bin.c (GL_VERBOSE block).
GLT_KEY = bytes([
    0x9e, 0x37, 0x4b, 0x12, 0x7c, 0xa5, 0x0d, 0x66, 0x21, 0x8f, 0xd3,
    0x5a, 0xb4, 0x70, 0x1c, 0xe9, 0x53, 0x2d, 0x88, 0xaf, 0x06, 0x91,
    0x4e, 0x3b, 0xc2, 0x65, 0x19, 0xf7, 0x08, 0xda, 0x72, 0x4d,
])

GLT_MAGIC = b"GLT1"
GLT_VERSION = 1
GLT_FLAG_OBFUSCATED = 0x01
GLT_HDR_SIZE = 16
ENTRY_HDR_SIZE = 8
FIELD_SIZE = 10

# Field ids -> struct member names, mirroring enum glt_fid in offsets_bin.c.
FIELD_NAMES = {
    0x11: "kernel_phys_load",
    0x12: "pselect_waiter_shift",
    0x21: "off_init_task",
    0x22: "off_init_cred",
    0x23: "off_root_task_group",
    0x24: "off_selinux_enforcing",
    0x25: "off_selinux_blob_sizes",
    0x26: "off_security_hook_heads",
    0x27: "off_slide_nfulnl_logger",
    0x28: "off_slide_loggers_0_1",
    0x29: "off_slide_boot_id",
    0x31: "off_tp_sys_exit_tp",
    0x32: "off_tp_sys_exit_funcs",
    0x41: "task_prio",
    0x42: "task_normal_prio",
    0x43: "task_sched_task_group",
    0x44: "task_pi_lock",
    0x45: "task_pi_waiters",
    0x46: "task_pi_top_task",
    0x47: "task_pi_blocked_on",
    0x48: "task_pid",
    0x49: "task_tgid",
    0x4A: "task_atomic_flags",
    0x4B: "task_real_cred",
    0x4C: "task_cred",
    0x4D: "task_comm",
    0x4E: "task_tasks",
    0x4F: "task_seccomp",
    0x51: "compact_waiter",
    0x52: "mm_struct_sz",
}

# From app/src/main/kotlin/com/ghostlock/pro/domain/model/SupportedKernels.kt.
# The container stores only the hash, so the names have to come from the app.
KNOWN_RELEASES = [
    "6.1.57-android14-11-maybe-dirty",
    "6.1.124-android14-11-maybe-dirty",
    "6.1.145-android14-11-maybe-dirty",
]


def decode(blob: bytes) -> dict[str, dict[str, int]]:
    if len(blob) < GLT_HDR_SIZE:
        raise ValueError("container shorter than its header")
    if blob[0:4] != GLT_MAGIC:
        raise ValueError(f"not a GLT1 container (magic {blob[0:4]!r})")
    if blob[4] != GLT_VERSION:
        raise ValueError(f"unsupported version {blob[4]}")
    if not blob[5] & GLT_FLAG_OBFUSCATED:
        raise ValueError("payload is not obfuscated; nothing to undo")

    entry_count = struct.unpack_from("<H", blob, 6)[0]
    salt = struct.unpack_from("<Q", blob, 8)[0]

    by_hash = {fnv1a32(r): r for r in KNOWN_RELEASES}
    out: dict[str, dict[str, int]] = {}
    pos = GLT_HDR_SIZE

    for index in range(entry_count):
        rel_hash, field_count = struct.unpack_from("<IH", blob, pos)
        pos += ENTRY_HDR_SIZE
        nonce = struct.pack("<I", index) + struct.pack("<Q", salt)
        ks = _chacha20_keystream(GLT_KEY, 0, nonce, field_count * 8)

        fields: dict[str, int] = {}
        for f in range(field_count):
            fid, raw = struct.unpack_from("<HQ", blob, pos + f * FIELD_SIZE)
            value = raw ^ struct.unpack_from("<Q", ks, f * 8)[0]
            fields[FIELD_NAMES.get(fid, f"unknown_0x{fid:02x}")] = value
        pos += field_count * FIELD_SIZE

        release = by_hash.get(rel_hash)
        if release is None:
            raise ValueError(
                f"entry {index} has release hash 0x{rel_hash:08x}, which matches "
                "none of the releases the app ships; update KNOWN_RELEASES"
            )
        out[release] = fields

    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("container", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=None)
    args = ap.parse_args()

    table = decode(args.container.read_bytes())
    text = json.dumps(table, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out} ({len(table)} releases)")
    else:
        print(text)
    for release, fields in table.items():
        print(f"  {release}: {len(fields)} fields", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
