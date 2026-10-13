"""Independent-implementation cross-check for the licence crypto.

The service ships zero third-party dependencies, so its P-256 / HKDF /
ChaCha20-Poly1305 are hand-written.  This compares them against the
'cryptography' library (OpenSSL) -- a different implementation of the same
standards, which is what the Kotlin client uses via JCE.

    python crosscheck_crypto.py            # run from the service directory
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))   # 服务端模块在上一层

import crypto

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FAIL = []


def ossl_ecdh(our_priv: bytes, their_pub_point: bytes) -> bytes:
    """OpenSSL-side ECDH, tolerant of the cryptography>=50 API rename."""
    priv = ec.derive_private_key(int.from_bytes(our_priv, "big"), ec.SECP256R1())
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), their_pub_point)
    # ECDH lives on the *private* key: priv.exchange(EC(), peer_pub)
    for call in (lambda: priv.exchange(ec.ECDH(), peer), lambda: priv.exchange_ecdh(peer)):
        try:
            return call()
        except AttributeError:
            continue
    raise RuntimeError("no usable ECDH entry point in this cryptography build")


def check(name, ok, detail=""):
    print("{:4} {:44} {}".format("PASS" if ok else "FAIL", name, detail))
    if not ok:
        FAIL.append(name)


# 1. HKDF-SHA256
ikm, salt, info = os.urandom(32), os.urandom(32), b"GL-TEST"
ours = crypto.hkdf_sha256(ikm, salt, info, 32)
theirs = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)
check("HKDF-SHA256 == OpenSSL", ours == theirs)

# 2. P-256 ECDH, both directions
priv_a, pub_a = crypto.p256_generate_keypair()
priv_b, pub_b = crypto.p256_generate_keypair()
their_secret = ossl_ecdh(priv_a, pub_b)
check("ECDH shared secret == OpenSSL", crypto.p256_ecdh(priv_a, pub_b) == their_secret)
# and the public key we hand out is a valid SEC1 point for OpenSSL
ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_a)
check("我方公钥是合法 SEC1 点", True)

# 3. ChaCha20-Poly1305 both directions
key, nonce, aad, msg = os.urandom(32), os.urandom(12), b"header", os.urandom(96)
ct, tag = crypto.chacha20_poly1305_encrypt(key, nonce, aad, msg)
their_ct = ChaCha20Poly1305(key).encrypt(nonce, msg, aad)
check("AEAD 密文+tag == OpenSSL", ct + tag == their_ct)
check("OpenSSL 密文可被我方解开",
      crypto.chacha20_poly1305_decrypt(key, nonce, aad, their_ct[:-16], their_ct[-16:]) == msg)

# 4. ECIES envelope: ours wrap -> OpenSSL unwrap（客户端 JCE 走的就是这条）
card = "AAAAA-BBBBB-CCCCC-DDDDD"
kd = os.urandom(32)
wrapped = crypto.ecies_wrap(pub_b, kd, card)
eph_pub, nonce_w, ct_w, tag_w = wrapped[:65], wrapped[65:77], wrapped[77:109], wrapped[109:]
their_shared = ossl_ecdh(priv_b, eph_pub)
kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=crypto.sha256(card), info=b"GL-KDW1").derive(their_shared)
plain = ChaCha20Poly1305(kek).decrypt(nonce_w, ct_w + tag_w, eph_pub)
check("服务端 ECIES 包裹可被 OpenSSL 解开", plain == kd)

# 5. GLT2 container: ours build -> OpenSSL decrypt
import payload as P
glp = os.urandom(200)
blob = P.build_glt2_from_glp(glp, b"\x01" * 32, card, kd, 0)
hdr, nonce_c, ct_c, tag_c = blob[:64], blob[64:76], blob[76:-16], blob[-16:]
check("GLT2 容器可被 OpenSSL 解开",
      ChaCha20Poly1305(kd).decrypt(nonce_c, ct_c + tag_c, hdr) == glp)

print()
print("FAIL {}".format(len(FAIL)) if FAIL else "ALL PASS")
raise SystemExit(1 if FAIL else 0)
