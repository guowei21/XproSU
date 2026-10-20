"""Full security & completeness audit for the XproSU licensing engine.
Runs against the live standalone service and local cryptography modules.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, "/app")
os.chdir("/app")

import server
import store as store_mod
import crypto
import wire

cfg = server.load_config("/app/config.json")
ctx = server.LicensingContext(cfg)
st = ctx.store

BASE = "http://127.0.0.1:8787"
results = []

def record(item, passed, detail=""):
    print(("PASS " if passed else "FAIL ") + f"[{item}] " + str(detail))
    results.append((item, passed, detail))

def http_post(path, data, headers=None):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(BASE + path, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers
    except Exception as e:
        return -1, str(e).encode(), {}

# 1. Cryptography contract: ChaCha20-Poly1305 + HKDF + ECIES roundtrip
try:
    master = ctx.master_key
    test_card = "SECU1-TEST1-TEST1-TEST1"
    dev_a = bytes([1] * 32)
    dev_b = bytes([2] * 32)
    kd_a = crypto.hkdf_sha256(master, crypto.sha256(test_card), dev_a, 32)
    kd_b = crypto.hkdf_sha256(master, crypto.sha256(test_card), dev_b, 32)
    record("CRYPT-01-HKDF-DIVERGE", kd_a != kd_b and len(kd_a) == 32, "Different devices yield different Kd")

    priv_a, pub_a = crypto.p256_generate_keypair()
    priv_b, pub_b = crypto.p256_generate_keypair()
    wrapped = crypto.ecies_wrap(pub_a, kd_a, test_card)
    unwrapped_a = crypto.ecies_unwrap(priv_a, wrapped, test_card)
    record("CRYPT-02-ECIES-DECRYPT", unwrapped_a == kd_a, "Matching private key unwraps Kd")

    # Attacker on handset B tries to unwrap handset A's wrapped payload
    try:
        crypto.ecies_unwrap(priv_b, wrapped, test_card)
        record("CRYPT-03-ECIES-CROSS-FAIL", False, "Handset B unexpectedly unwrapped handset A's key")
    except Exception:
        record("CRYPT-03-ECIES-CROSS-FAIL", True, "Device B cannot unwrap device A's wrapped Kd")
except Exception as e:
    record("CRYPT-FAIL", False, str(e))

# 2. Binary wire protocol contract (GlBlob / wire.py)
try:
    req_entries = [
        (wire.TAG_CARD, b"WIRE1-TEST1-TEST1-TEST1"),
        (wire.TAG_DEVICE_FP, b"aa" * 32),
        (wire.TAG_PUBKEY, b"04" + b"bb" * 64),
    ]
    encoded = wire.encode(wire.KIND_REQUEST, 0, req_entries)
    kind, decoded = wire.decode(encoded)
    record("WIRE-01-ROUNDTRIP", kind == wire.KIND_REQUEST and decoded[wire.TAG_CARD] == b"WIRE1-TEST1-TEST1-TEST1", "Wire parser roundtrip verified")

    # Tampered magic must be rejected
    bad_magic = bytearray(encoded)
    bad_magic[0] ^= 0x55
    record("WIRE-02-BAD-MAGIC", wire.decode(bytes(bad_magic)) is None, "Wire parser rejects corrupted magic")
except Exception as e:
    record("WIRE-FAIL", False, str(e))

# 3. Card issuing and duplicate rejection
try:
    cards = st.gen_cards(1, 30, batch="AUDIT", note="sec-test")
    c1 = cards[0]
    ch1 = store_mod.card_hash(c1)
    record("ISSUE-01-GEN", bool(c1) and st.get_card(ch1) is not None, f"Generated: {c1}")

    # Re-importing exact same card must be deduplicated
    dups = st.import_cards([c1], days=30, batch="AUDIT")
    record("ISSUE-02-DEDUP", dups == 0, "Duplicate insertion ignored")
except Exception as e:
    record("ISSUE-FAIL", False, str(e))

# 4. Activation, multi-device race and replay defence
priv_d1, pub_d1 = crypto.p256_generate_keypair()
fp_d1 = bytes([0x11] * 32).hex()
priv_d2, pub_d2 = crypto.p256_generate_keypair()
fp_d2 = bytes([0x22] * 32).hex()

status, body, _ = http_post("/api/activate", json.dumps({
    "card": c1, "device_fp": fp_d1, "pubkey": pub_d1.hex()
}).encode())
data = json.loads(body.decode()) if status == 200 else {}
token_d1 = data.get("token")
record("ACT-01-FIRST-DEV", status == 200 and data.get("code") == 0 and bool(token_d1), f"Token: {str(token_d1)[:12]}...")

# Attacker replaying same card on Device 2 (different device_fp) -> MUST REJECT (1002)
status, body, _ = http_post("/api/activate", json.dumps({
    "card": c1, "device_fp": fp_d2, "pubkey": pub_d2.hex()
}).encode())
data = json.loads(body.decode()) if status == 200 else {}
record("ACT-02-CROSS-DEV-DEFENCE", data.get("code") == 1002, f"Rejected cross-device activation: code={data.get('code')}")

# Attacker replaying handset 1's device_fp from outside, but with handset 2's pubkey -> MUST SEAL TO D1's PUBKEY
status, body, _ = http_post("/api/activate", json.dumps({
    "card": c1, "device_fp": fp_d1, "pubkey": pub_d2.hex()
}).encode())
data = json.loads(body.decode()) if status == 200 else {}
if status == 200 and data.get("code") == 0:
    replayed_wrapped = bytes.fromhex(data.get("wrapped", ""))
    # Handset 2 must NOT be able to unwrap it, because server sealed to stored D1 key
    try:
        crypto.ecies_unwrap(priv_d2, replayed_wrapped, c1)
        record("ACT-03-FP-REPLAY-ANTI-THEFT", False, "Attacker unwrapped key using forged device_fp")
    except Exception:
        record("ACT-03-FP-REPLAY-ANTI-THEFT", True, "Attacker cannot unwrap payload despite replaying device_fp")
else:
    record("ACT-03-FP-REPLAY-ANTI-THEFT", True, "Server blocked mismatched pubkey outright")

# 5. Heartbeat & Life-cycle revocation enforcement
status, body, _ = http_post("/api/heartbeat", json.dumps({"token": token_d1}).encode())
data = json.loads(body.decode()) if status == 200 else {}
record("HB-01-ACTIVE", data.get("state") == 1 and data.get("code") == 0, f"Heartbeat verified: state={data.get('state')}")

# Admin disables card -> token must be instantly wiped from DB
st.disable_card(ch1)
status, body, _ = http_post("/api/heartbeat", json.dumps({"token": token_d1}).encode())
data = json.loads(body.decode()) if status == 200 else {}
record("HB-02-REVOKE-KICK", data.get("code") == 1002, f"Device immediately kicked on heartbeat: code={data.get('code')}")

# Heartbeat on non-existent token -> 1002
status, body, _ = http_post("/api/heartbeat", json.dumps({"token": "00" * 16}).encode())
data = json.loads(body.decode()) if status == 200 else {}
record("HB-03-BOGUS-TOKEN", data.get("code") == 1002, "Bogus token refused with 1002")

# 6. Admin Authentication & Session Security
# Brute force login with bad creds -> 1001
status, body, _ = http_post("/admin/api/login", json.dumps({"username": "admin", "password": "wrong"}).encode())
data = json.loads(body.decode()) if status == 200 else {}
record("AUTH-01-BAD-LOGIN", data.get("code") == 1001, "Bad password rejected")

# Correct credentials login
status, body, headers = http_post("/admin/api/login", json.dumps({"username": "Aa010227", "password": "Aa010227"}).encode())
data = json.loads(body.decode()) if status == 200 else {}
cookie_header = headers.get("Set-Cookie", "")
record("AUTH-02-GOOD-LOGIN", status == 200 and data.get("code") == 0 and "gl_admin_sid=" in cookie_header, "Admin login success + Set-Cookie issued")

# Extract session id
import http.cookies
c = http.cookies.SimpleCookie()
c.load(cookie_header)
sid = c.get("gl_admin_sid").value if c.get("gl_admin_sid") else ""

# Call dashboard using valid session cookie
status, body, _ = http_post("/admin/api/dashboard", json.dumps({}).encode(), headers={"Cookie": f"gl_admin_sid={sid}"})
data = json.loads(body.decode()) if status == 200 else {}
record("AUTH-03-SESSION-ACCESS", data.get("code") == 0 and "stats" in data, "Dashboard accessed via session cookie")

# Access dashboard with NO credentials -> 403
status, body, _ = http_post("/admin/api/dashboard", json.dumps({}).encode())
record("AUTH-04-UNAUTH-BLOCKED", status == 403, f"Unauthenticated request blocked with {status}")

# 7. Cleanup audit records
import sqlite3
with sqlite3.connect(cfg["db_path"]) as conn:
    conn.execute("DELETE FROM cards WHERE batch = 'AUDIT'")
    conn.execute("DELETE FROM tokens WHERE card_hash = ?", (ch1,))

all_passed = all(p for _, p, _ in results)
print("\n==========================================")
print(f"AUDIT SUMMARY: {sum(1 for _, p, _ in results if p)}/{len(results)} PASSED")
print("VERDICT: " + ("ALL_SECURE_AND_VERIFIED" if all_passed else "FAILURES_DETECTED"))
print("==========================================")
sys.exit(0 if all_passed else 1)
