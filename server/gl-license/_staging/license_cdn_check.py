"""Public-path check: activate + heartbeat through the real CDN origin
(CDN -> nginx -> gl-license), not just against 127.0.0.1.

    python license_cdn_check.py https://yz.765163599.xyz/gl /app/config.json
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import crypto
import payload as P
import wire
from store import CardStore, card_hash, normalize_card_key

BASE = (sys.argv[1] if len(sys.argv) > 1 else "https://yz.765163599.xyz/gl").rstrip("/")
CFG = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(HERE), "config.json")
FAIL = []


def check(name, ok, detail=""):
    print("{:4} {:46} {}".format("PASS" if ok else "FAIL", name, detail))
    if not ok:
        FAIL.append(name)


def post(path, body):
    req = urllib.request.Request(BASE + path, data=body,
                                 headers={"Content-Type": "application/octet-stream"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def main():
    cfg = json.load(open(CFG, "r", encoding="utf-8"))
    db = cfg.get("db_path", "cards.db")
    if not os.path.isabs(db):
        db = os.path.join(os.path.dirname(os.path.abspath(CFG)), db)
    store = CardStore(db)
    card = store.gen_cards(1, 1, batch="cdn-audit", note="public path")[0]
    ch = card_hash(normalize_card_key(card))
    print("base =", BASE)
    print("card =", card)

    fp = hashlib.sha256(b"cdn-audit-device").digest()
    priv, pub = crypto.p256_generate_keypair()
    body = wire.encode(wire.KIND_REQUEST, 0, [
        (wire.TAG_CARD, card.encode()),
        (wire.TAG_DEVICE_FP, fp.hex().encode()),
        (wire.TAG_PUBKEY, pub.hex().encode()),
        (wire.TAG_APP_VER, b"1.1-cdn"),
    ])
    status, headers, raw = post("/api/activate", body)
    check("公网 activate HTTP 200", status == 200, "status={}".format(status))
    check("经 nginx/边缘返回", "server" in {k.lower() for k in headers},
          "server={}".format(headers.get("Server")))
    code = struct.unpack_from("<H", raw, 6)[0]
    check("activate code 0", code == 0, "code={}".format(code))
    if code != 0:
        return 1
    dec = wire.decode(raw)
    f = dec[1] if dec else {}
    kd = crypto.ecies_unwrap(priv, f[wire.TAG_WRAPPED], card)
    kd_expect = crypto.hkdf_sha256(bytes.fromhex(cfg["master_key"]), crypto.sha256(card), fp, 32)
    check("Kd 与本地推导一致", kd == kd_expect)
    glp = P.decrypt_glt2(f[wire.TAG_BLOB], kd)
    check("公网下发的容器可解开为 GLP", bool(P._deserialize_glp(glp)),
          "{} B".format(len(glp)))

    token = f[wire.TAG_TOKEN_RESP].decode()
    status, headers, raw = post("/api/heartbeat", wire.encode(
        wire.KIND_REQUEST, 0, [(wire.TAG_TOKEN, token.encode())]))
    code = struct.unpack_from("<H", raw, 6)[0]
    dec = wire.decode(raw)
    state = struct.unpack("<B", dec[1][wire.TAG_STATE])[0] if dec and wire.TAG_STATE in dec[1] else None
    check("公网 heartbeat code 0 / state 1", code == 0 and state == 1,
          "code={} state={}".format(code, state))

    store.delete_card(ch)
    with store._connect() as conn:
        conn.execute("DELETE FROM activation_audit WHERE card_hash = ?", (ch,))
    print("cleanup : 测试卡已删除")
    print()
    print("FAIL {}".format(len(FAIL)) if FAIL else "ALL PASS")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
