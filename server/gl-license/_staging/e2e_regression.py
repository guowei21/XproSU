"""End-to-end regression against the running gl-license (standalone build).

Simulates a full handset lifecycle through the real HTTP endpoint:
    1. admin issues a card (direct store write, same as admin.py gen)
    2. device activates  -> gets token + blob + wrapped
    3. device heartbeat  -> state=1
    4. admin DISABLES    -> heartbeat must FAIL (code=1002, token gone)
    5. admin ENABLES     -> device re-activates -> heartbeat state=1
    6. admin REVOKES     -> heartbeat must FAIL; re-activation must fail
    7. orphan-token probe: delete the card row, heartbeat must NOT return state=1
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, "/app")
os.chdir("/app")

import server
import store as store_mod

cfg = server.load_config("/app/config.json")
ctx = server.LicensingContext(cfg)
st = ctx.store

BASE = "http://127.0.0.1:8787"
ok = True


def check(name, cond, extra=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(extra)) if extra else ""))
    if not cond:
        ok = False


def post(path, obj, admin=False):
    body = json.dumps(obj).encode()
    headers = {"Content-Type": "application/json"}
    if admin:
        headers["Authorization"] = "Bearer " + ctx.admin_key
    req = urllib.request.Request(BASE + path, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, None


# --- 1. issue ----------------------------------------------------------------
keys = st.gen_cards(1, 365, batch="E2E")
card = keys[0]
ch = store_mod.card_hash(card)
check("issue card", st.get_card(ch) is not None)

# --- 2. activate -------------------------------------------------------------
dev = bytes(range(32)).hex()
import crypto
priv, pub = crypto.p256_generate_keypair()
pubhex = pub.hex() if isinstance(pub, bytes) else bytes(pub).hex()
if len(pubhex) != 130:
    pubhex = ("04" + pubhex).hex() if False else pubhex
# p256_generate_keypair returns (priv, pub) with pub uncompressed (65 bytes).
status, resp = post("/api/activate", {"card": card, "device_fp": dev, "pubkey": pubhex})
check("activate HTTP 200", status == 200, status)
check("activate code=0", resp and resp.get("code") == 0, resp)
token = resp.get("token") if resp else None
check("got token", bool(token))

# --- 3. heartbeat OK ---------------------------------------------------------
status, resp = post("/api/heartbeat", {"token": token})
check("heartbeat state=1", resp and resp.get("state") == 1, resp)

# --- 4. DISABLE -> kicked ----------------------------------------------------
row = st.disable_card(ch)
check("disable -> state=disabled", row and row["state"] == "disabled", row and row["state"])
status, resp = post("/api/heartbeat", {"token": token})
check("heartbeat after disable fails", resp and resp.get("code") == 1002, resp)

# re-activation on a disabled card must be refused
status, resp = post("/api/activate", {"card": card, "device_fp": dev, "pubkey": pubhex})
check("activate on disabled refused", resp and resp.get("code") == 1001, resp)

# --- 5. ENABLE -> works again ------------------------------------------------
st.enable_card(ch)
status, resp = post("/api/activate", {"card": card, "device_fp": dev, "pubkey": pubhex})
check("activate after enable ok", resp and resp.get("code") == 0, resp)
token2 = resp.get("token") if resp else None
status, resp = post("/api/heartbeat", {"token": token2})
check("heartbeat state=1 after enable", resp and resp.get("state") == 1, resp)

# --- 6. REVOKE -> terminal ---------------------------------------------------
st.revoke_card(ch)
status, resp = post("/api/heartbeat", {"token": token2})
check("heartbeat after revoke fails", resp and resp.get("code") == 1002, resp)
status, resp = post("/api/activate", {"card": card, "device_fp": dev, "pubkey": pubhex})
check("activate on revoked refused", resp and resp.get("code") == 1001, resp)

# --- 7. orphan token probe (the original bug) --------------------------------
keys2 = st.gen_cards(1, 365, batch="E2E-ORPHAN")
card2 = keys2[0]
ch2 = store_mod.card_hash(card2)
status, resp = post("/api/activate", {"card": card2, "device_fp": dev, "pubkey": pubhex})
token3 = resp.get("token") if resp else None
import sqlite3
with sqlite3.connect(cfg["db_path"]) as c:
    c.execute("DELETE FROM cards WHERE card_hash = ?", (ch2,))
status, resp = post("/api/heartbeat", {"token": token3})
check("orphan token NOT state=1 (bug fixed)", not (resp and resp.get("code") == 0 and resp.get("state") == 1), resp)
check("orphan token returns state=0 (client clears)", resp and resp.get("state") == 0, resp)

# --- 8. admin HTTP surface ---------------------------------------------------
status, resp = post("/api/admin/list", {}, admin=True)
check("admin list 200", status == 200 and resp and resp.get("code") == 0, status)
status, resp = post("/api/admin/list", {})  # no auth
check("admin list without bearer -> 403", status == 403, status)

# --- cleanup: remove the E2E cards so production db stays clean ---------------
import sqlite3 as s3
with s3.connect(cfg["db_path"]) as c:
    c.execute("DELETE FROM cards WHERE batch IN ('E2E','E2E-ORPHAN')")
    c.execute("DELETE FROM tokens WHERE card_hash IN (?,?)", (ch, ch2))
print("cleanup done")

print("ALL_OK" if ok else "SOME_FAILED")
sys.exit(0 if ok else 1)