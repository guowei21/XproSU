"""End-to-end smoke test for the GhostLock licensing crypto chain.

No HTTP server is started.  It runs Kd derivation, GLT2 build/decrypt and
ECIES wrap/unwrap with fixed inputs, then writes the reproducible values to
vectors.json.
"""

from __future__ import annotations

import json
import os
import sys

from crypto import (
    ecies_unwrap,
    ecies_wrap,
    hkdf_sha256,
    p256_public_from_priv,
    sha256,
)
from payload import (
    FIELD_IDS,
    _deserialize_glp,
    _serialize_glp,
    build_glt2,
    decrypt_glt2,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    # A throwaway key, deliberately NOT config.json's.  This script writes
    # vectors.json, and a vector file that carries the production master key
    # would leak it to anyone who receives a copy of this directory -- one
    # leaked master key invalidates every card that was ever issued.  The
    # vectors exist to cross-check the C engine and the Kotlin client against
    # this implementation, and that check is just as strong with a test key.
    master_key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )

    card_key = "AAAAA-BBBBB-CCCCC-DDDDD"
    device_fp = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    expire = 1760000000
    release = "arm64-6.6.56"

    # Two releases, every real field id from docs/stage2-protocol.md section 4.1.
    entries = {
        "arm64-6.6.56": {name: 0x1000 + fid for name, fid in FIELD_IDS.items()},
        "arm64-5.10.198": {name: 0x2000 + fid for name, fid in FIELD_IDS.items()},
    }

    kd = hkdf_sha256(master_key, sha256(card_key), device_fp, 32)

    fixed_nonce = bytes.fromhex("000102030405060708090a0b")
    blob = build_glt2(entries, release, device_fp, card_key, kd, expire, nonce=fixed_nonce)

    glp = decrypt_glt2(blob, kd)
    assert glp == _serialize_glp(entries), "GLT2 plaintext does not match serialized payload"
    parsed = _deserialize_glp(glp)
    assert len(parsed) == 2, "expected 2 release entries in GLP"

    # Fixed device + ephemeral keys so wrapped is reproducible too.
    device_priv = bytes.fromhex("0101" * 16)
    eph_priv = bytes.fromhex("0202" * 16)
    device_pub = p256_public_from_priv(device_priv)
    wrapped_nonce = bytes.fromhex("0a0b0c0d0e0f000102030405")
    wrapped = ecies_wrap(device_pub, kd, card_key, eph_priv=eph_priv, nonce=wrapped_nonce)
    assert ecies_unwrap(device_priv, wrapped, card_key) == kd, "ECIES unwrap mismatch"

    print(f"Kd        : {kd.hex()}")
    print(f"blob      : {blob.hex()}")
    print(f"wrapped   : {wrapped.hex()}")
    print(f"glp bytes : {len(glp)}")

    vector = {
        "master_key": master_key.hex(),
        "card_key": card_key,
        "device_fp": device_fp.hex(),
        "expire": expire,
        "release": release,
        "kd_hex": kd.hex(),
        "glt2_hex": blob.hex(),
        "wrapped_hex": wrapped.hex(),
    }
    out_path = os.path.join(BASE_DIR, "vectors.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(vector, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"wrote      : {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
