"""Full licensing-chain audit: issuance -> activate -> Kd -> container ->
heartbeat -> lifecycle -> negative paths -> no-unbind, plus a container dump for
the C-side (engine) harness.

    python license_audit.py [BASE_URL] [CONFIG] [OUTDIR]
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import struct
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import crypto
import payload as payload_mod
import wire
from store import CardStore, card_hash, normalize_card_key

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8787").rstrip("/")
CONFIG = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(HERE), "config.json")
OUTDIR = sys.argv[3] if len(sys.argv) > 3 else "/tmp/glt-audit"

PASS = []
FAIL = []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("{:4} {:46} {}".format("PASS" if ok else "FAIL", name, detail))
    return ok


def resp_code(data):
    return struct.unpack_from("<H", data, 6)[0]


def post(path, body, ctype, headers=None):
    h = {"Content-Type": ctype}
    if headers:
        h.update(headers)
    req = urllib.request.Request(BASE + path, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wire_post(path, entries):
    status, raw = post(path, wire.encode(wire.KIND_REQUEST, 0, entries),
                       "application/octet-stream")
    decoded = wire.decode(raw)
    return status, resp_code(raw), (decoded[1] if decoded else {})


def json_post(path, obj, admin_key=None):
    headers = {"Authorization": "Bearer " + admin_key} if admin_key else None
    status, raw = post(path, json.dumps(obj).encode("utf-8"), "application/json", headers)
    try:
        return status, json.loads(raw.decode("utf-8"))
    except Exception:
        return status, {}


def activate(card, fp_hex, pub_hex, ver=b"1.1-audit"):
    return wire_post("/api/activate", [
        (wire.TAG_CARD, card.encode()),
        (wire.TAG_DEVICE_FP, fp_hex.encode()),
        (wire.TAG_PUBKEY, pub_hex.encode()),
        (wire.TAG_APP_VER, ver),
    ])


def heartbeat(token):
    return wire_post("/api/heartbeat", [(wire.TAG_TOKEN, token.encode())])


def main():
    cfg = json.load(open(CONFIG, "r", encoding="utf-8"))
    master = bytes.fromhex(cfg["master_key"])
    db = cfg.get("db_path", "cards.db")
    if not os.path.isabs(db):
        db = os.path.join(os.path.dirname(os.path.abspath(CONFIG)), db)
    store = CardStore(db)
    os.makedirs(OUTDIR, exist_ok=True)

    print("== 0. 前置条件 ==")
    check("master_key 32B", len(master) == 32)
    pl_path = cfg.get("payload_path", "payload.bin")
    if not os.path.isabs(pl_path):
        pl_path = os.path.join(os.path.dirname(os.path.abspath(CONFIG)), pl_path)
    glp = open(pl_path, "rb").read()
    table = payload_mod._deserialize_glp(glp)
    check("payload.bin 可解析为 GLP", bool(table), "{} releases, {} B".format(len(table), len(glp)))

    fp1 = hashlib.sha256(b"audit-device-1").digest()
    fp2 = hashlib.sha256(b"audit-device-2").digest()
    card = store.gen_cards(1, 1, batch="audit", note="license audit")[0]
    ch = card_hash(normalize_card_key(card))
    print("   test card: {}".format(card))

    print()
    print("== 1. 激活：卡密 + device_fp + 公钥 → blob/wrapped/token ==")
    priv_a, pub_a = crypto.p256_generate_keypair()
    status, code, f = activate(card, fp1.hex(), pub_a.hex())
    check("activate HTTP 200 / code 0", status == 200 and code == 0,
          "http={} code={}".format(status, code))
    if code != 0:
        print("   abort: activation refused:", f)
        return 1
    blob = f[wire.TAG_BLOB]
    wrapped = f[wire.TAG_WRAPPED]
    token = f[wire.TAG_TOKEN_RESP].decode()
    expire = struct.unpack("<Q", f[wire.TAG_EXPIRE])[0]
    check("响应含 token/blob/wrapped/expire", bool(token) and bool(blob) and bool(wrapped),
          "token={} blob={}B wrapped={}B expire={}".format(token[:8] + "…", len(blob), len(wrapped), expire))

    kd_expected = crypto.hkdf_sha256(master, crypto.sha256(card), fp1, 32)
    kd = crypto.ecies_unwrap(priv_a, wrapped, card)
    check("Kd = HKDF(master, SHA256(卡密), device_fp)", kd == kd_expected)

    hdr = payload_mod.parse_glt2_header(blob)
    check("容器头绑定本机 device_fp", hdr["device_fp"] == fp1)
    check("容器头 card_tag = SHA256(卡密)[:16]", hdr["card_tag"] == crypto.sha256(card)[:16])
    check("容器头 flags 含 AEAD 位", hdr["flags"] & payload_mod.GLT2_FLAG_AEAD == payload_mod.GLT2_FLAG_AEAD,
          "flags=0x{:02x}".format(hdr["flags"]))

    glp_out = payload_mod.decrypt_glt2(blob, kd)
    check("GLT2 用 Kd 解开 == payload.bin", glp_out == glp,
          "{} B 明文".format(len(glp_out)))

    # 给 C 侧（引擎）审计留一份输入
    open(os.path.join(OUTDIR, "container.bin"), "wb").write(blob)
    open(os.path.join(OUTDIR, "params.json"), "w").write(json.dumps({
        "kd": kd.hex(),
        "device_fp": fp1.hex(),
        "card_tag": crypto.sha256(card)[:16].hex(),
        "release_hash": sorted(table.keys())[0],
    }, indent=2))
    print("   container/params -> {}".format(OUTDIR))

    print()
    print("== 2. 心跳：token 换 state/expire ==")
    status, code, f = heartbeat(token)
    check("heartbeat code 0", code == 0, "http={} code={}".format(status, code))
    if code == 0:
        state = struct.unpack("<B", f[wire.TAG_STATE])[0]
        hb_expire = struct.unpack("<Q", f[wire.TAG_EXPIRE])[0]
        check("heartbeat state=1（在线）", state == 1, "state={}".format(state))
        check("heartbeat expire 与激活一致", hb_expire == expire,
              "{} vs {}".format(hb_expire, expire))
    status, code, _ = heartbeat("0" * 32)
    check("未知 token 被拒", code == 1002, "code={}".format(code))

    print()
    print("== 3. 负面路径：篡改 / 换机 / 换卡 ==")
    tampered = bytearray(blob)
    tampered[80] ^= 0x01
    try:
        payload_mod.decrypt_glt2(bytes(tampered), kd)
        check("密文篡改会被 AEAD 拒", False, "意外成功")
    except Exception as exc:
        check("密文篡改会被 AEAD 拒", True, type(exc).__name__)
    tampered_hdr = bytearray(blob)
    tampered_hdr[16] ^= 0x01          # AAD 里的 device_fp
    try:
        payload_mod.decrypt_glt2(bytes(tampered_hdr), kd)
        check("容器头篡改会被 AEAD 拒", False, "意外成功")
    except Exception as exc:
        check("容器头篡改会被 AEAD 拒", True, type(exc).__name__)
    try:
        crypto.ecies_unwrap(priv_a, wrapped, "AAAAA-BBBBB-CCCCC-DDDDD")
        check("换一张卡密解不开 wrapped", False, "意外成功")
    except Exception as exc:
        check("换一张卡密解不开 wrapped", True, type(exc).__name__)
    status, code, _ = activate(card, fp2.hex(), pub_a.hex())
    check("另一台设备激活被拒 1002", code == 1002, "code={}".format(code))
    status, code, _ = activate("AAAAA-BBBBB-CCCCC-DDDDD", fp1.hex(), pub_a.hex())
    check("不存在的卡密 1001", code == 1001, "code={}".format(code))

    print()
    print("== 4. 生命周期：disable / enable / revoke ==")
    admin_key = str(cfg.get("admin_key", ""))
    status, _ = json_post("/api/admin/disable", {"card": card}, admin_key)
    status, code, f = heartbeat(token)
    # disable 会级联删除该卡全部 token → 心跳拿不到 token（1002），
    # 客户端 refresh() 收到明确拒绝即清除本地授权并回登录页。
    check("disable 后原 token 立即失效（1002）", code == 1002, "code={}".format(code))
    status, code, _ = activate(card, fp1.hex(), pub_a.hex())
    check("disable 后不能激活 1001", code == 1001, "code={}".format(code))
    status, _ = json_post("/api/admin/enable", {"card": card}, admin_key)
    status, code, _ = activate(card, fp1.hex(), pub_a.hex())
    check("enable 后可再次激活", code == 0, "code={}".format(code))
    token = _[wire.TAG_TOKEN_RESP].decode() if code == 0 else token
    status, code, _ = activate(card, fp1.hex(), pub_a.hex())
    check("同机重复激活幂等（仍 code 0）", code == 0, "code={}".format(code))

    print()
    print("== 5. 到期语义 ==")
    exp_card = store.gen_cards(1, 1, batch="audit", note="expired")[0]
    with store._connect() as conn:
        conn.execute("UPDATE cards SET expire = ? WHERE card_hash = ?",
                     (int(time.time()) - 60, card_hash(exp_card)))
    status, code, _ = activate(exp_card, fp1.hex(), pub_a.hex())
    check("过期卡激活 1003", code == 1003, "code={}".format(code))

    print()
    print("== 6. 解绑/换绑路径不存在 ==")
    status, payload = json_post("/api/admin/rebind", {"card": card, "device_fp": None}, admin_key)
    check("POST /api/admin/rebind → 404", status == 404, "http={}".format(status))
    status, payload = json_post("/admin/api/card_action",
                                {"action": "unbind", "card_hash": ch}, admin_key)
    check("card_action=unbind 被拒", payload.get("code") not in (0, None),
          "code={} msg={}".format(payload.get("code"), payload.get("msg")))
    with store._connect() as conn:
        row = conn.execute("SELECT device_fp FROM cards WHERE card_hash = ?", (ch,)).fetchone()
    check("绑定未被上述尝试改动", bool(row and row[0]))

    print()
    print("== 7. revoke 终态 ==")
    status, _ = json_post("/api/admin/revoke", {"card": card}, admin_key)
    status, code, _ = activate(card, fp1.hex(), pub_a.hex())
    check("revoke 后激活 1001", code == 1001, "code={}".format(code))
    status, code, _ = heartbeat(token)
    check("revoke 后 token 立即失效（1002）", code == 1002, "code={}".format(code))

    print()
    print("== 8. 审计留痕 ==")
    with store._connect() as conn:
        n = conn.execute("SELECT COUNT(*) FROM activation_audit WHERE card_hash = ?", (ch,)).fetchone()[0]
        kinds = [r[0] for r in conn.execute(
            "SELECT result FROM activation_audit WHERE card_hash = ? ORDER BY id", (ch,))]
    check("activation_audit 有记录", n >= 4, "rows={} {}".format(n, kinds))

    # 清理
    for c in (card, exp_card):
        store.delete_card(card_hash(normalize_card_key(c)))
        with store._connect() as conn:
            conn.execute("DELETE FROM activation_audit WHERE card_hash = ?",
                         (card_hash(normalize_card_key(c)),))
    print("cleanup  : 测试卡与审计行已删除")

    print()
    print("PASS {}  FAIL {}".format(len(PASS), len(FAIL)))
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
