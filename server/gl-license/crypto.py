"""Pure-Python (standard library only) crypto primitives for XproSU licensing.

Implements exactly what docs/stage2-protocol.md requires:

- HKDF-SHA256 (RFC 5869)
- ChaCha20-Poly1305 AEAD (RFC 8439)
- AES-128-CBC (pure Python AES, with optional PKCS#7 helpers)
- NIST P-256 (secp256r1) scalar multiplication / ECDH
- FNV-1a-32, SHA-256, MD5

No third-party packages are imported.  Everything here runs on CPython >= 3.8.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import struct

# ---------------------------------------------------------------------------
# Small generic helpers
# ---------------------------------------------------------------------------


def sha256(data: bytes | str) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def fnv1a32(s: str) -> int:
    """FNV-1a 32-bit hash, offset basis 0x811C9DC5, prime 0x01000193."""
    h = 0x811C9DC5
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869)
# ---------------------------------------------------------------------------


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF with HMAC-SHA256."""
    if not isinstance(ikm, (bytes, bytearray)) or not isinstance(info, (bytes, bytearray)):
        raise TypeError("ikm/info must be bytes")
    if salt is None or (isinstance(salt, (bytes, bytearray)) and len(salt) == 0):
        salt = b"\x00" * 32
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes or None")
    if length <= 0 or length > 255 * 32:
        raise ValueError("invalid HKDF output length")

    prk = hmac.new(bytes(salt), bytes(ikm), hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + bytes(info) + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 (RFC 8439)
# ---------------------------------------------------------------------------

_CHACHA_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _rotl32(v: int, c: int) -> int:
    c &= 31
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF


def _chacha_quarter(a: int, b: int, c: int, d: int):
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = _rotl32(d, 16)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = _rotl32(b, 12)
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = _rotl32(d, 8)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = _rotl32(b, 7)
    return a, b, c, d


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("ChaCha20 requires 32-byte key and 12-byte nonce")
    k = struct.unpack("<8I", key)
    n = struct.unpack("<3I", nonce)
    state = list(_CHACHA_CONSTANTS) + list(k) + [counter & 0xFFFFFFFF] + list(n)
    x = state[:]
    for _ in range(10):
        x[0], x[4], x[8], x[12] = _chacha_quarter(x[0], x[4], x[8], x[12])
        x[1], x[5], x[9], x[13] = _chacha_quarter(x[1], x[5], x[9], x[13])
        x[2], x[6], x[10], x[14] = _chacha_quarter(x[2], x[6], x[10], x[14])
        x[3], x[7], x[11], x[15] = _chacha_quarter(x[3], x[7], x[11], x[15])
        x[0], x[5], x[10], x[15] = _chacha_quarter(x[0], x[5], x[10], x[15])
        x[1], x[6], x[11], x[12] = _chacha_quarter(x[1], x[6], x[11], x[12])
        x[2], x[7], x[8], x[13] = _chacha_quarter(x[2], x[7], x[8], x[13])
        x[3], x[4], x[9], x[14] = _chacha_quarter(x[3], x[4], x[9], x[14])
    out = [(x[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def _chacha20_keystream(key: bytes, counter: int, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    block_counter = counter
    while len(out) < length:
        out += _chacha20_block(key, block_counter, nonce)
        block_counter += 1
    return bytes(out[:length])


def _poly1305_mac(key: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    r = int.from_bytes(key[:16], "little")
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0

    def add_block(block: bytes) -> None:
        nonlocal acc
        n = int.from_bytes(block + b"\x01", "little")
        acc = (acc + n) * r % p

    for i in range(0, len(aad), 16):
        add_block(aad[i : i + 16].ljust(16, b"\x00"))
    for i in range(0, len(ciphertext), 16):
        add_block(ciphertext[i : i + 16].ljust(16, b"\x00"))
    add_block(struct.pack("<QQ", len(aad), len(ciphertext)))

    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def chacha20_poly1305_encrypt(
    key: bytes, nonce: bytes, aad: bytes, plaintext: bytes
):
    """RFC 8439 ChaCha20-Poly1305. Returns (ciphertext, tag)."""
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("key must be 32 bytes and nonce 12 bytes")
    poly_key = _chacha20_block(key, 0, nonce)[:32]
    keystream = _chacha20_keystream(key, 1, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, keystream))
    tag = _poly1305_mac(poly_key, aad, ct)
    return ct, tag


def chacha20_poly1305_decrypt(
    key: bytes, nonce: bytes, aad: bytes, ct: bytes, tag: bytes
) -> bytes:
    if len(key) != 32 or len(nonce) != 12 or len(tag) != 16:
        raise ValueError("bad ChaCha20-Poly1305 parameters")
    poly_key = _chacha20_block(key, 0, nonce)[:32]
    expected = _poly1305_mac(poly_key, aad, ct)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("Poly1305 authentication failed")
    keystream = _chacha20_keystream(key, 1, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, keystream))


# ---------------------------------------------------------------------------
# AES-128 (pure Python)
# ---------------------------------------------------------------------------


def _rotl8(v: int, c: int) -> int:
    c &= 7
    return ((v << c) | (v >> (8 - c))) & 0xFF


def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_inv(a: int) -> int:
    if a == 0:
        return 0
    # a^(254) == a^(-1) in GF(2^8)
    r = 1
    base = a
    exp = 254
    while exp:
        if exp & 1:
            r = _gf_mul(r, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return r


_SBOX = [0] * 256
_INV_SBOX = [0] * 256
for _i in range(256):
    inv = _gf_inv(_i)
    sb = inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
    _SBOX[_i] = sb
    _INV_SBOX[sb] = _i


def _aes_expand_key(key: bytes):
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    rcon = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
    w = [0] * 44
    for i in range(4):
        w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = ((temp << 8) & 0xFFFFFF00) | (temp >> 24)
            temp = (
                (_SBOX[(temp >> 24) & 0xFF] << 24)
                | (_SBOX[(temp >> 16) & 0xFF] << 16)
                | (_SBOX[(temp >> 8) & 0xFF] << 8)
                | _SBOX[temp & 0xFF]
            )
            temp ^= rcon[i // 4 - 1] << 24
        w[i] = w[i - 4] ^ temp
    return w


def _aes_add_round_key(s: list, w: list, rnd: int) -> None:
    for i in range(4):
        word = w[rnd * 4 + i]
        s[4 * i] ^= (word >> 24) & 0xFF
        s[4 * i + 1] ^= (word >> 16) & 0xFF
        s[4 * i + 2] ^= (word >> 8) & 0xFF
        s[4 * i + 3] ^= word & 0xFF


def _aes_shift_rows(s: list) -> None:
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]


def _aes_inv_shift_rows(s: list) -> None:
    s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]


def _aes_mix_columns(s: list) -> None:
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
        s[i] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        s[i + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        s[i + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        s[i + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)


def _aes_inv_mix_columns(s: list) -> None:
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
        s[i] = _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
        s[i + 1] = _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
        s[i + 2] = _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
        s[i + 3] = _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)


def _aes_encrypt_block(block: bytes, w: list) -> bytes:
    s = list(block)
    _aes_add_round_key(s, w, 0)
    for rnd in range(1, 10):
        for i in range(16):
            s[i] = _SBOX[s[i]]
        _aes_shift_rows(s)
        _aes_mix_columns(s)
        _aes_add_round_key(s, w, rnd)
    for i in range(16):
        s[i] = _SBOX[s[i]]
    _aes_shift_rows(s)
    _aes_add_round_key(s, w, 10)
    return bytes(s)


def _aes_decrypt_block(block: bytes, w: list) -> bytes:
    s = list(block)
    _aes_add_round_key(s, w, 10)
    for rnd in range(9, 0, -1):
        _aes_inv_shift_rows(s)
        for i in range(16):
            s[i] = _INV_SBOX[s[i]]
        _aes_add_round_key(s, w, rnd)
        _aes_inv_mix_columns(s)
    _aes_inv_shift_rows(s)
    for i in range(16):
        s[i] = _INV_SBOX[s[i]]
    _aes_add_round_key(s, w, 0)
    return bytes(s)


def aes128cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Raw AES-128-CBC (no padding).  ``data`` must be a multiple of 16 bytes."""
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("AES-128-CBC requires 16-byte key and IV")
    if len(data) % 16 != 0:
        raise ValueError("CBC input must be a multiple of 16 bytes")
    w = _aes_expand_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), 16):
        mixed = bytes(a ^ b for a, b in zip(data[i : i + 16], prev))
        enc = _aes_encrypt_block(mixed, w)
        out += enc
        prev = enc
    return bytes(out)


def aes128cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("AES-128-CBC requires 16-byte key and IV")
    if len(data) % 16 != 0:
        raise ValueError("CBC input must be a multiple of 16 bytes")
    w = _aes_expand_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), 16):
        dec = _aes_decrypt_block(data[i : i + 16], w)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = data[i : i + 16]
    return bytes(out)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("bad PKCS#7 length")
    n = data[-1]
    if n < 1 or n > block_size:
        raise ValueError("bad PKCS#7 padding")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("bad PKCS#7 padding")
    return data[:-n]


# ---------------------------------------------------------------------------
# NIST P-256 (secp256r1)
# ---------------------------------------------------------------------------

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _p256_on_curve(x: int, y: int) -> bool:
    return (y * y - (x * x * x + P256_A * x + P256_B)) % P256_P == 0


def _p256_point_double(point):
    if point is None:
        return None
    x1, y1 = point
    if y1 == 0:
        return None
    lam = (3 * x1 * x1 + P256_A) * pow(2 * y1, P256_P - 2, P256_P) % P256_P
    x3 = (lam * lam - 2 * x1) % P256_P
    y3 = (lam * (x1 - x3) - y1) % P256_P
    return (x3, y3)


def _p256_point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % P256_P == 0:
            return None
        return _p256_point_double(p)
    lam = (y2 - y1) * pow((x2 - x1) % P256_P, P256_P - 2, P256_P) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    y3 = (lam * (x1 - x3) - y1) % P256_P
    return (x3, y3)


def _p256_scalar_mult_point(d: int, point):
    if d < 1 or d >= P256_N:
        raise ValueError("P-256 scalar out of range")
    r = None
    for i in range(255, -1, -1):
        r = _p256_point_double(r)
        if (d >> i) & 1:
            r = _p256_point_add(r, point)
    return r


def p256_scalar_mult(scalar: bytes):
    """Multiply the P-256 generator by a 32-byte scalar, returning (x, y) ints."""
    if not isinstance(scalar, (bytes, bytearray)) or len(scalar) != 32:
        raise ValueError("P-256 scalar must be 32 bytes")
    d = int.from_bytes(bytes(scalar), "big")
    r = _p256_scalar_mult_point(d, (P256_GX, P256_GY))
    if r is None:
        raise ValueError("scalar produced point at infinity")
    return r


def p256_public_from_priv(priv: bytes) -> bytes:
    """Uncompressed public key: 0x04 || X(32) || Y(32)."""
    x, y = p256_scalar_mult(priv)
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def p256_generate_keypair():
    """Return (private_key_32, uncompressed_public_key_65)."""
    while True:
        priv = secrets.token_bytes(32)
        d = int.from_bytes(priv, "big")
        if 1 <= d < P256_N:
            break
    return priv, p256_public_from_priv(priv)


def p256_ecdh(priv: bytes, peer_pub_uncompressed: bytes) -> bytes:
    """ECDH shared secret: the X coordinate of priv * peer_pub (32 bytes)."""
    if not isinstance(priv, (bytes, bytearray)) or len(priv) != 32:
        raise ValueError("P-256 private key must be 32 bytes")
    if len(peer_pub_uncompressed) != 65 or peer_pub_uncompressed[0] != 0x04:
        raise ValueError("peer public key must be 65-byte uncompressed point")
    d = int.from_bytes(bytes(priv), "big")
    if d < 1 or d >= P256_N:
        raise ValueError("P-256 scalar out of range")
    px = int.from_bytes(peer_pub_uncompressed[1:33], "big")
    py = int.from_bytes(peer_pub_uncompressed[33:65], "big")
    if not _p256_on_curve(px, py):
        raise ValueError("peer public key is not on P-256 curve")
    shared = _p256_scalar_mult_point(d, (px, py))
    if shared is None:
        raise ValueError("invalid shared point")
    return shared[0].to_bytes(32, "big")


# ---------------------------------------------------------------------------
# ECIES / ECDH-ES wrapping of Kd (docs/stage2-protocol.md section 6)
# ---------------------------------------------------------------------------


def ecies_wrap(
    pubkey: bytes,
    kd: bytes,
    card_key: str | bytes,
    eph_priv: bytes | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Wrap a 32-byte Kd for a device public key.

    Returns eph_pub(65) || nonce(12) || ct(32) || tag(16) == 125 bytes.
    ``eph_priv`` and ``nonce`` are optional and only exist for reproducible
    test vectors; production callers must leave them as None (random).
    """
    if len(pubkey) != 65 or pubkey[0] != 0x04:
        raise ValueError("public key must be 65-byte uncompressed point")
    if len(kd) != 32:
        raise ValueError("Kd must be 32 bytes")
    if isinstance(card_key, str):
        card_key = card_key.encode("utf-8")
    if eph_priv is None:
        eph_priv, _ = p256_generate_keypair()
    if nonce is None:
        nonce = os.urandom(12)
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")

    eph_pub = p256_public_from_priv(eph_priv)
    ecdh_x = p256_ecdh(eph_priv, pubkey)
    kek = hkdf_sha256(ecdh_x, sha256(card_key), b"GL-KDW1", 32)
    ct, tag = chacha20_poly1305_encrypt(kek, nonce, eph_pub, kd)
    return eph_pub + nonce + ct + tag


def ecies_unwrap(priv: bytes, wrapped: bytes, card_key: str | bytes) -> bytes:
    """Unwrap a blob produced by :func:`ecies_wrap`, returning the 32-byte Kd."""
    if len(wrapped) != 125:
        raise ValueError("wrapped blob must be 125 bytes")
    if len(priv) != 32:
        raise ValueError("private key must be 32 bytes")
    if isinstance(card_key, str):
        card_key = card_key.encode("utf-8")

    eph_pub = wrapped[:65]
    nonce = wrapped[65:77]
    ct = wrapped[77:109]
    tag = wrapped[109:125]
    ecdh_x = p256_ecdh(priv, eph_pub)
    kek = hkdf_sha256(ecdh_x, sha256(card_key), b"GL-KDW1", 32)
    return chacha20_poly1305_decrypt(kek, nonce, eph_pub, ct, tag)


# ---------------------------------------------------------------------------
# Minimal built-in self-check (full vector suite lives in selftest.py)
# ---------------------------------------------------------------------------


def _selfcheck() -> None:
    okm = hkdf_sha256(b"\x0b" * 22, bytes.fromhex("000102030405060708090a0b0c"), bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ), "HKDF mismatch"
    assert p256_scalar_mult(b"\x00" * 31 + b"\x01") == (P256_GX, P256_GY), "P-256 G mismatch"
    priv, pub = p256_generate_keypair()
    eph_priv, eph_pub = p256_generate_keypair()
    assert p256_ecdh(priv, eph_pub) == p256_ecdh(eph_priv, pub), "ECDH mismatch"
    print("crypto.py built-in self-check OK")


if __name__ == "__main__":
    _selfcheck()
