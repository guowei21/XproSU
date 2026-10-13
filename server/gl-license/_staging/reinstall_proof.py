"""Reinstall / data-wipe proof: the same card + the same Widevine device_fp
must get the same Kd and a working GLT2 container back, even though the handset
presents a brand-new Keystore public key after a wipe.

Run against a live server:
    python reinstall_proof.py http://127.0.0.1:8787

What it proves, in order:
  1. first bind      -> unwrap with key A, Kd == HKDF(master, card, device_fp),
                        GLT2 opens and parses as GLP
  2. same device_fp + new key B (simulated reinstall / data wipe)
                     -> accepted, Kd identical, GLT2 opens with B
  3. the old key A can no longer unwrap the new envelope (sealed to B)
  4. a different device_fp with key C is still refused with 1002
  5. the DB records the rotation (pubkey/prev_pubkey/counter) and the audit rows
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
# The service modules (store/crypto/payload/wire) live one level up; make sure
# they win over anything that happens to sit next to this script.
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import crypto
import payload as payload_mod
import wire
from store import CardStore, card_hash, normalize_card_key

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8787"
CONFIG = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

PASS = []
FAIL = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    (PASS if ok else FAIL).append(name)
    print("{:4} {:38} {}".format("PASS" if ok else "FAIL", name, detail))
    return ok


def resp_code(data: bytes) -> int:
    return struct.unpack_from("<H", data, 6)[0]


def post(path: str, entries: list[tuple[int, bytes]]) -> tuple[int, dict[int, bytes]]:
    body = wire.encode(wire.KIND_REQUEST, 0, entries)
    req = urllib.request.Request(
        BASE + path,
        data=body,
        headers={"Content-Type": "application/octet-stream"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
    code = resp_code(raw)
    decoded = wire.decode(raw)
    entries_out = decoded[1] if decoded else {}
    return code, entries_out


def post_json(path: str, obj: dict, admin_key: str | None = None) -> tuple[int, dict]:
    body = json.dumps(obj).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if admin_key:
        headers["Authorization"] = "Bearer " + admin_key
    req = urllib.request.Request(BASE + path, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(), exc.code
    try:
        return status, json.loads(raw.decode("utf-8"))
    except Exception:
        return status, {}


def activate(card: str, device_fp_hex: str, pub_hex: str) -> tuple[int, dict[int, bytes]]:
    return post(
        "/api/activate",
        [
            (wire.TAG_CARD, card.encode("utf-8")),
            (wire.TAG_DEVICE_FP, device_fp_hex.encode("ascii")),
            (wire.TAG_PUBKEY, pub_hex.encode("ascii")),
            (wire.TAG_APP_VER, b"1.1-proof"),
        ],
    )


def main() -> int:
    cfg = json.load(open(CONFIG, "r", encoding="utf-8"))
    master = bytes.fromhex(cfg["master_key"])
    db_path = cfg.get("db_path", "cards.db")
    if not os.path.isabs(db_path):
        db_path = os.path.join(os.path.dirname(os.path.abspath(CONFIG)), db_path)

    store = CardStore(db_path)
    card = store.gen_cards(1, 1, batch="reinstall-proof", note="automated proof")[0]
    print("test card:", card)
    print("base     :", BASE)

    fp1 = hashlib.sha256(b"ghostlock-device-1").digest()
    fp2 = hashlib.sha256(b"ghostlock-device-2").digest()
    fp1_hex, fp2_hex = fp1.hex(), fp2.hex()

    kd_expected = crypto.hkdf_sha256(master, crypto.sha256(card), fp1, 32)

    # ---- 1. first bind -----------------------------------------------------
    priv_a, pub_a = crypto.p256_generate_keypair()
    code, fields = activate(card, fp1_hex, pub_a.hex())
    check("activate#1 first bind code==0", code == 0, "code={}".format(code))
    blob_a = fields.get(wire.TAG_BLOB)
    wrapped_a = fields.get(wire.TAG_WRAPPED)
    check("activate#1 returns blob+wrapped", bool(blob_a) and bool(wrapped_a),
          "blob={}B wrapped={}B".format(len(blob_a or b""), len(wrapped_a or b"")))
    kd_a = crypto.ecies_unwrap(priv_a, wrapped_a, card)
    check("activate#1 Kd == HKDF(master,card,device_fp)", kd_a == kd_expected)
    glp_a = payload_mod.decrypt_glt2(blob_a, kd_a)
    table_a = payload_mod._deserialize_glp(glp_a)
    check("activate#1 GLT2 opens to GLP", bool(table_a),
          "{} releases".format(len(table_a)))

    # ---- 2. reinstall: same device_fp, brand-new key ------------------------
    priv_b, pub_b = crypto.p256_generate_keypair()
    code, fields = activate(card, fp1_hex, pub_b.hex())
    check("activate#2 reinstall code==0 (was 1002)", code == 0, "code={}".format(code))
    if code == 0:
        wrapped_b = fields[wire.TAG_WRAPPED]
        blob_b = fields[wire.TAG_BLOB]
        kd_b = crypto.ecies_unwrap(priv_b, wrapped_b, card)
        check("activate#2 Kd identical to first bind", kd_b == kd_a)
        glp_b = payload_mod.decrypt_glt2(blob_b, kd_b)
        check("activate#2 GLT2 opens with the NEW key", bool(payload_mod._deserialize_glp(glp_b)))

    # ---- 3. the wiped key is dead ------------------------------------------
    try:
        crypto.ecies_unwrap(priv_a, fields[wire.TAG_WRAPPED], card)
        check("old key cannot unwrap new envelope", False, "unexpected success")
    except Exception as exc:
        check("old key cannot unwrap new envelope", True, type(exc).__name__)

    # ---- 4. second handset is still refused --------------------------------
    cooldown = int(cfg.get("pubkey_rotation_cooldown", 0) or 0)
    max_rot = int(cfg.get("pubkey_max_rotations", 0) or 0)
    print("policy   : cooldown={}s max_rotations={}".format(cooldown, max_rot or "unlimited"))
    priv_c, pub_c = crypto.p256_generate_keypair()
    code, _ = activate(card, fp2_hex, pub_c.hex())
    check("other device_fp refused with 1002", code == 1002, "code={}".format(code))
    code, _ = activate(card, fp1_hex, pub_c.hex())
    if cooldown > 0:
        # The rotation rate limit is live: an immediate second re-bind must be
        # refused, and the binding must still be the one from step 2.
        check("rotation cooldown holds off an immediate re-bind", code == 1002,
              "code={} (cooldown={}s)".format(code, cooldown))
        last_pubkey = pub_b.hex()
        expected_prev = pub_a.hex()          # 只有第 2 步真的换过，prev 停在 A
        expected_rotations = 1
        expected_results = ["bound", "rotated", "rejected", "rejected"]
        expected_rotated = [0, 1, 0, 0]
    else:
        check("back to bound device still accepted", code == 0, "code={}".format(code))
        last_pubkey = pub_c.hex()
        expected_prev = pub_b.hex()          # 换过两次，prev 是上一把
        expected_rotations = 2
        expected_results = ["bound", "rotated", "rejected", "rotated"]
        expected_rotated = [0, 1, 0, 1]

    # ---- 5. database state --------------------------------------------------
    row = store.get_card(card_hash(normalize_card_key(card)))
    check("db pubkey == last accepted key", (row["pubkey"] or "").lower() == last_pubkey.lower())
    check("db pubkey_rotations == {}".format(expected_rotations),
          int(row["pubkey_rotations"] or 0) == expected_rotations,
          "rotations={}".format(row["pubkey_rotations"]))
    check("db prev_pubkey == previous key", (row["prev_pubkey"] or "").lower() == expected_prev.lower(),
          "prev={}".format((row["prev_pubkey"] or "")[:12]))
    with store._connect() as conn:
        rows = conn.execute(
            "SELECT result, rotated FROM activation_audit WHERE card_hash = ? ORDER BY id",
            (card_hash(card),),
        ).fetchall()
    results = [r["result"] for r in rows]
    rotated = [int(r["rotated"] or 0) for r in rows]
    check("audit has one row per attempt", len(rows) == len(expected_results),
          "results={}".format(results))
    check("audit: bind, rotate, refuse, ...",
          results == expected_results,
          "results={}".format(results))
    check("audit flags the rotations", rotated == expected_rotated, "rotated={}".format(rotated))

    # ---- 6. the unbind/rebind capability does not exist ---------------------
    admin_key = str(cfg.get("admin_key", ""))
    status, payload = post_json("/api/admin/rebind", {"card": card, "device_fp": None}, admin_key)
    check("rebind endpoint removed (404)", status == 404, "http={} {}".format(status, payload))
    status, payload = post_json(
        "/admin/api/card_action", {"action": "unbind", "card_hash": card_hash(card)}, admin_key
    )
    check("unbind action refused", payload.get("code") not in (0, None),
          "http={} code={} msg={}".format(status, payload.get("code"), payload.get("msg")))
    row_after = store.get_card(card_hash(card))
    check("binding untouched by those attempts", bool(row_after and row_after["device_fp"]))

    if os.environ.get("KEEP_TEST_CARD", "") != "1":
        store.delete_card(card_hash(card))
        with store._connect() as conn:
            conn.execute(
                "DELETE FROM activation_audit WHERE card_hash = ?", (card_hash(card),)
            )
        print("cleanup  : test card and its audit rows removed")

    print()
    print("PASS {}  FAIL {}".format(len(PASS), len(FAIL)))
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
