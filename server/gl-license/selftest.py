"""Cryptographic self-test for XproSU licensing service.

Runs the frozen test vectors from docs/stage2-protocol.md section 7 plus a
random P-256 ECDH round-trip.  Exits non-zero if any check fails.

Usage:
    python selftest.py
"""

from __future__ import annotations

import os
import subprocess
import sys

from crypto import (
    aes128cbc_encrypt,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    hkdf_sha256,
    p256_ecdh,
    p256_generate_keypair,
    p256_public_from_priv,
    p256_scalar_mult,
    P256_GX,
    P256_GY,
)
from wire import (
    KIND_REQUEST,
    TAG_APP_VER,
    TAG_CARD,
    TAG_DEVICE_FP,
    decode,
    encode,
)

RESULTS: list[tuple[str, bool, str]] = []


SKIPPED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(ok), detail))
    safe_detail = detail.encode("ascii", "replace").decode("ascii")
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({safe_detail})" if safe_detail and not ok else ""))


def skip(name: str, detail: str = "") -> None:
    """An optional check whose prerequisites are absent is SKIP, not FAIL.

    The JDK cross-check is the only user of this: it needs a JDK and the
    tools_java_crosscheck source, neither of which ships in the container.  A
    skipped check must not colour the whole run red -- that hides real failures.
    """
    SKIPPED.append((name, detail))
    safe_detail = detail.encode("ascii", "replace").decode("ascii")
    print(f"SKIP  {name}" + (f"  ({safe_detail})" if safe_detail else ""))


def _expect_bytes(name: str, actual: bytes, expected_hex: str) -> None:
    ok = actual.hex() == expected_hex
    detail = f"got {actual.hex()}" if not ok else ""
    check(name, ok, detail)


def test_hkdf_rfc5869_case1() -> None:
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = hkdf_sha256(ikm, salt, info, 42)
    expected = (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    _expect_bytes("HKDF-SHA256 RFC 5869 Test Case 1", okm, expected)


def test_chacha20_poly1305_rfc8439() -> None:
    plaintext = (
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, sunscreen would be it."
    ).encode("ascii")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    )
    nonce = bytes.fromhex("070000004041424344454647")
    ct, tag = chacha20_poly1305_encrypt(key, nonce, aad, plaintext)
    expected_ct = (
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    )
    expected_tag = "1ae10b594f09e26a7e902ecbd0600691"
    ok = ct.hex() == expected_ct and tag.hex() == expected_tag
    detail = "" if ok else f"ct={ct.hex()[:32]}... tag={tag.hex()}"
    check("ChaCha20-Poly1305 RFC 8439 section 2.8.2", ok, detail)
    if ok:
        dec = chacha20_poly1305_decrypt(key, nonce, aad, ct, tag)
        check("ChaCha20-Poly1305 decrypt round-trip", dec == plaintext)


def test_aes128_cbc_nist() -> None:
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    ct = aes128cbc_encrypt(key, iv, pt)
    _expect_bytes("AES-128-CBC NIST SP 800-38A F.2.1 (single block)", ct, "7649abac8119b246cee98e9b12e9197d")


def test_p256() -> None:
    x, y = p256_scalar_mult(b"\x00" * 31 + b"\x01")
    ok = x == P256_GX and y == P256_GY
    detail = "" if ok else f"got x={x:064x}"
    check("P-256 scalar_mult(1) == generator G", ok, detail)

    ok_all = True
    for i in range(20):
        d, _ = p256_generate_keypair()
        e, e_pub = p256_generate_keypair()
        a = p256_ecdh(d, e_pub)
        b = p256_ecdh(e, p256_public_from_priv(d))
        if a != b:
            ok_all = False
            break
    check("P-256 ECDH symmetry (20 random pairs)", ok_all)


def test_wire() -> None:
    entries = [
        (TAG_CARD, b"AAAAA-BBBBB-CCCCC-DDDDD"),
        (TAG_DEVICE_FP, b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        (TAG_APP_VER, b"1.1"),
    ]
    blob = encode(KIND_REQUEST, 0, entries)
    decoded = decode(blob)
    check(
        "wire encode/decode round-trip",
        decoded == (KIND_REQUEST, {tag: value for tag, value in entries}),
    )

    bad_magic = bytearray(blob)
    bad_magic[0] ^= 0x01
    check("wire rejects bad magic", decode(bytes(bad_magic)) is None)

    check("wire rejects trailing bytes", decode(blob + b"\x00") is None)


def _find_jdk_tools() -> tuple[str | None, str | None]:
    """Locate javac/java: JAVA_HOME -> PATH -> the developer machine's JDK."""
    import shutil

    env_home = os.environ.get("JAVA_HOME", "").strip()
    if env_home:
        javac = os.path.join(env_home, "bin", "javac" + (".exe" if os.name == "nt" else ""))
        java = os.path.join(env_home, "bin", "java" + (".exe" if os.name == "nt" else ""))
        if os.path.exists(javac) and os.path.exists(java):
            return javac, java
    javac, java = shutil.which("javac"), shutil.which("java")
    if javac and java:
        return javac, java
    legacy = os.path.join("D:" + os.sep, "XM", "GJ", "jdk21", "jdk-21.0.12.1+1", "bin", "javac.exe")
    if os.path.exists(legacy):
        return legacy, legacy.replace("javac.exe", "java.exe")
    return None, None


def test_jdk_crosscheck() -> None:
    """Bonus check: compare our ECDH X coordinate with the JDK's KeyAgreement("ECDH")."""
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools_java_crosscheck", "CrossCheck.java")
    javac, java = _find_jdk_tools()
    if not javac or not java:
        skip("JDK ECDH crosscheck", "no JDK found (set JAVA_HOME); OpenSSL 版见 crosscheck_crypto.py")
        return
    if not os.path.exists(src):
        skip("JDK ECDH crosscheck", "tools_java_crosscheck/CrossCheck.java 未随包分发")
        return

    classes_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools_java_crosscheck", "classes")
    os.makedirs(classes_dir, exist_ok=True)
    try:
        subprocess.run([javac, "-d", classes_dir, src], check=True, capture_output=True, timeout=120)
    except subprocess.CalledProcessError as exc:
        check("JDK ECDH crosscheck", False, f"javac failed: {exc.stderr.decode(errors='replace')[:200]}")
        return

    cases = []
    for _ in range(5):
        d, _ = p256_generate_keypair()
        e, e_pub = p256_generate_keypair()
        cases.append((d, e_pub, p256_ecdh(d, e_pub)))

    lines = "".join(f"{d.hex()} {pub.hex()}\n" for d, pub, _ in cases)
    try:
        proc = subprocess.run(
            [java, "-cp", classes_dir, "CrossCheck"],
            input=lines.encode("ascii"),
            capture_output=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        check("JDK ECDH crosscheck", False, "java timed out")
        return

    if proc.returncode != 0:
        check("JDK ECDH crosscheck", False, proc.stderr.decode(errors="replace")[:200])
        return

    outs = [line.strip() for line in proc.stdout.decode("ascii").splitlines() if line.strip()]
    ok = len(outs) == len(cases) and all(o == x.hex() for o, (_, _, x) in zip(outs, cases))
    check("JDK ECDH crosscheck (5 random scalars)", ok, "" if ok else "mismatch between Python and JDK")


def main() -> int:
    print("=== XproSU license crypto self-test ===")
    test_hkdf_rfc5869_case1()
    test_chacha20_poly1305_rfc8439()
    test_aes128_cbc_nist()
    test_p256()
    test_wire()
    test_jdk_crosscheck()

    failed = [r for r in RESULTS if not r[1]]
    print("---")
    if SKIPPED:
        print(f"{len(SKIPPED)} skipped (prerequisites absent): " +
              ", ".join(name for name, _ in SKIPPED))
    if failed:
        print(f"{len(failed)} FAILED, {len(RESULTS) - len(failed)} passed")
        return 1
    print(f"ALL {len(RESULTS)} CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
