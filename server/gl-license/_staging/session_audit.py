"""会话接口（/api/session）专项审计：Kd 每次现场换，删卡/封卡立即断。"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import crypto
import payload as P
import wire
from store import CardStore, card_hash, normalize_card_key

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8787").rstrip("/")
CONFIG = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(HERE), "config.json")
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("{}: {:44} {}".format("PASS" if ok else "FAIL", name, detail))


def post(path, entries):
    body = wire.encode(wire.KIND_REQUEST, 0, entries)
    req = urllib.request.Request(BASE + path, data=body,
                                 headers={"Content-Type": "application/octet-stream"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
    code = struct.unpack_from("<H", raw, 6)[0]
    dec = wire.decode(raw)
    return code, (dec[1] if dec else {})


def activate(card, fp_hex, pub_hex):
    return post("/api/activate", [
        (wire.TAG_CARD, card.encode()),
        (wire.TAG_DEVICE_FP, fp_hex.encode()),
        (wire.TAG_PUBKEY, pub_hex.encode()),
        (wire.TAG_APP_VER, b"1.1-session"),
    ])


def session(card, fp_hex, pub_hex):
    return post("/api/session", [
        (wire.TAG_CARD, card.encode()),
        (wire.TAG_DEVICE_FP, fp_hex.encode()),
        (wire.TAG_PUBKEY, pub_hex.encode()),
    ])


def main():
    cfg = json.load(open(CONFIG, "r", encoding="utf-8"))
    master = bytes.fromhex(cfg["master_key"])
    db = cfg.get("db_path", "cards.db")
    if not os.path.isabs(db):
        db = os.path.join(os.path.dirname(os.path.abspath(CONFIG)), db)
    store = CardStore(db)
    admin = str(cfg.get("admin_key", ""))
    card = store.gen_cards(1, 1, batch="session-audit", note="session")[0]
    ch = card_hash(normalize_card_key(card))
    fp = hashlib.sha256(b"session-device").digest()
    print("card =", card)

    priv, pub = crypto.p256_generate_keypair()
    code, f = activate(card, fp.hex(), pub.hex())
    check("activate 成功", code == 0, "code={}".format(code))
    if code != 0:
        return 1

    # 1) session 可换到同一个 Kd
    code, f = session(card, fp.hex(), pub.hex())
    check("session code 0", code == 0, "code={}".format(code))
    kd = crypto.ecies_unwrap(priv, f[wire.TAG_WRAPPED], card)
    want = crypto.hkdf_sha256(master, crypto.sha256(card), fp, 32)
    check("session 的 Kd 与激活一致", kd == want)
    check("session 容器可解", bool(P._deserialize_glp(P.decrypt_glt2(f[wire.TAG_BLOB], kd))))

    # 2) 新公钥（重装后）也能换到
    priv2, pub2 = crypto.p256_generate_keypair()
    code, f = session(card, fp.hex(), pub2.hex())
    kd2 = crypto.ecies_unwrap(priv2, f[wire.TAG_WRAPPED], card) if code == 0 else None
    check("session 支持新公钥（重装）", code == 0 and kd2 == want, "code={}".format(code))

    # 3) 未激活的卡不能 session
    fresh = store.gen_cards(1, 1, batch="session-audit", note="fresh")[0]
    code, _ = session(fresh, fp.hex(), pub.hex())
    check("未激活卡 session 被拒 1002", code == 1002, "code={}".format(code))

    # 4) 别的设备不能 session
    fp2 = hashlib.sha256(b"other-device").digest()
    code, _ = session(card, fp2.hex(), pub.hex())
    check("他机 session 被拒 1002", code == 1002, "code={}".format(code))

    # 5) 禁用 → 立刻断
    post("/api/admin/disable", [(wire.TAG_TOKEN, b"")])
    with store._connect() as conn:
        conn.execute("UPDATE cards SET state='disabled' WHERE card_hash=?", (ch,))
    code, _ = session(card, fp.hex(), pub.hex())
    check("禁用后 session 1001", code == 1001, "code={}".format(code))
    with store._connect() as conn:
        conn.execute("UPDATE cards SET state='bound' WHERE card_hash=?", (ch,))

    # 6) 删除 → 立刻断
    store.delete_card(ch)
    code, _ = session(card, fp.hex(), pub.hex())
    check("删卡后 session 1001", code == 1001, "code={}".format(code))

    # 7) 过期 → 1003
    exp = store.gen_cards(1, 1, batch="session-audit", note="exp")[0]
    activate(exp, fp.hex(), pub.hex())
    with store._connect() as conn:
        conn.execute("UPDATE cards SET expire=? WHERE card_hash=?", (int(time.time()) - 60, card_hash(exp)))
    code, _ = session(exp, fp.hex(), pub.hex())
    check("过期卡 session 1003", code == 1003, "code={}".format(code))

    for c in (card, fresh, exp):
        h = card_hash(normalize_card_key(c))
        store.delete_card(h)
        with store._connect() as conn:
            conn.execute("DELETE FROM activation_audit WHERE card_hash=?", (h,))
    print("cleanup done")
    print("PASS {}  FAIL {}".format(len(PASS), len(FAIL)))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
