#!/usr/bin/env python3
"""Verify the shipped offsets container: decrypt it and print what it holds.

Same algorithm as app/src/main/kotlin/com/ghostlock/pro/data/LocalOffsets.kt:
AES-256-GCM, key = SHA-256(b"XproSU/local-offsets/v1"), AAD = b"XSO1".

Usage:
    python tools/verify_offsets_local.py app/src/main/assets/offsets.enc

Requires `cryptography` (same dependency as pack_offsets_local.py).
"""

from __future__ import annotations

import hashlib
import json
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"XSO1"
NONCE_SIZE = 12
KDF_LABEL = b"XproSU/local-offsets/v1"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    blob = open(sys.argv[1], "rb").read()
    if len(blob) < len(MAGIC) + NONCE_SIZE + 16:
        print("truncated asset", file=sys.stderr)
        return 1
    if blob[:4] != MAGIC:
        print("foreign magic", file=sys.stderr)
        return 1
    key = hashlib.sha256(KDF_LABEL).digest()
    plaintext = AESGCM(key).decrypt(blob[4:16], blob[16:], MAGIC)
    entries = json.loads(plaintext)

    print(f"{sys.argv[1]}: {len(blob)} bytes -> {len(plaintext)} plaintext")
    for e in entries:
        build = e.get("build") or "(no build tag: release-only match)"
        print(f"  {e['release']}")
        print(f"    build:   {build}")
        print(f"    symbols: {len(e.get('symbols', {}))} fields, "
              f"struct: {len(e.get('struct_fields', {}))} fields, "
              f"compact_waiter={e.get('compact_waiter')}, "
              f"kernel_phys_load={e.get('kernel_phys_load')}")
        missing = [k for k in ("off_tp_sys_exit_tp", "off_tp_sys_exit_funcs",
                               "off_init_task", "off_init_cred",
                               "task_cred") if k not in e.get("symbols", {})
                   and k not in e.get("struct_fields", {})]
        if missing:
            print(f"    MISSING: {', '.join(missing)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
