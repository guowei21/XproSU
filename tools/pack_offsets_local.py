#!/usr/bin/env python3
"""Seal the offsets table into the asset the app decrypts on device.

The public build ships no licence server, so the kernel offsets have to travel
with the APK.  They are not stored as plaintext: `assets/offsets.enc` is the
offsets JSON sealed with AES-256-GCM under a key derived from a fixed label,
and the app opens it locally right before a run.

What that buys and what it does not:

* it keeps the table out of `strings`/`grep` on the APK and out of the
  `offsets.json` the engine writes to the private directory;
* it does not keep the table away from someone who reverse engineers the APK.
  The key derivation is in the app, so the table is recoverable -- there is no
  server to hold the key any more.  This is obfuscation with a real cipher, not
  a secret.

Layout::

    magic  4   b"XSO1"
    nonce 12   random per build
    body   ..  AES-256-GCM(json, aad = magic)

The key is SHA-256(b"XproSU/local-offsets/v1"), matching LocalOffsets.kt.

Usage:
    python tools/pack_offsets_local.py app/src/main/assets/offsets.enc \\
        docs/private-deploy/offsets/offsets-57+124+145-combined.json

Requires `cryptography` (only at pack time; the app does not need it).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"XSO1"
NONCE_SIZE = 12
KDF_LABEL = b"XproSU/local-offsets/v1"


def seal(plaintext: bytes, nonce: bytes | None = None) -> bytes:
    key = hashlib.sha256(KDF_LABEL).digest()
    nonce = nonce or os.urandom(NONCE_SIZE)
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must be 12 bytes")
    body = AESGCM(key).encrypt(nonce, plaintext, MAGIC)
    return MAGIC + nonce + body


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("output", help="path of the .enc asset to write")
    ap.add_argument("source", help="offsets JSON (array of release entries)")
    ap.add_argument("--nonce", default=None,
                    help="12-byte nonce as 24 hex digits; random when omitted")
    args = ap.parse_args()

    plaintext = open(args.source, "rb").read()
    nonce = bytes.fromhex(args.nonce) if args.nonce else None
    blob = seal(plaintext, nonce)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
    with open(args.output, "wb") as fh:
        fh.write(blob)

    print(f"wrote {args.output}: {len(blob)} bytes "
          f"({len(plaintext)} plaintext, nonce {blob[4:16].hex()})")
    print(f"sha256 {hashlib.sha256(blob).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
