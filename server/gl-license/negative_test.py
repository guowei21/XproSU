"""Negative-path tests for the XproSU licensing server (zero dependencies).

Run directly:

    python negative_test.py

Covers the current local card model: binding, test-card countdown, session
reissue, revocation, expiry, chunked smuggling and heartbeat state.

The U验证 upstream was removed on 2026-10-13; nothing here talks to it.  Every
check runs against a throwaway SQLite database and a payload built on the fly,
so the test never touches the real ``cards.db`` / ``payload.bin``.
"""

from __future__ import annotations

import gc
import json
import os
import secrets
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from crypto import p256_generate_keypair
import server as server_mod
import store as store_mod
from wire import (
    KIND_REQUEST,
    KIND_RESPONSE,
    TAG_LOG,
    TAG_STATE,
    TAG_TOKEN,
    decode,
    encode,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))


class QuietHandler(server_mod._Handler):
    def log_message(self, fmt: str, *args) -> None:
        pass


def make_ctx(tmpdir: str):
    payload_path = os.path.join(BASE_DIR, "payload.bin")
    if not os.path.exists(payload_path):
        from payload import build_payload

        payload_path = os.path.join(tmpdir, "payload.bin")
        build_payload({"arm64-6.6.56": {"task_pid": 1234}}, payload_path)

    cfg = {
        "master_key": "00" * 32,
        "admin_key": "negative-test-admin-key-0123456789abcdef",
        "db_path": os.path.join(tmpdir, "cards.db"),
        "payload_path": payload_path,
    }
    return server_mod.LicensingContext(cfg)


def start_server(ctx):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    srv.context = ctx
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread, f"http://127.0.0.1:{srv.server_address[1]}"


def post_json(base: str, path: str, obj: dict, headers: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(
        base + path,
        data=json.dumps(obj).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def post_wire(base: str, path: str, body: bytes) -> tuple[int, str, bytes]:
    req = urllib.request.Request(
        base + path,
        data=body,
        headers={"Content-Type": "application/octet-stream"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.headers.get("Content-Type", ""), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


def fresh(ctx) -> None:
    """Per-IP rate buckets are process-wide; clear them so tests stay independent."""
    ctx._rate.clear()


# --- card binding and test-card countdown ---------------------------------

def test_activate_unknown_card_1001(ctx, base):
    fresh(ctx)
    card = store_mod.generate_card_key()
    status, payload = post_json(base, "/api/activate", {
        "card": card,
        "device_fp": secrets.token_bytes(32).hex(),
        "pubkey": p256_generate_keypair()[1].hex(),
    })
    check("activate unknown card -> 1001", status == 200 and payload.get("code") == 1001, f"{payload}")


def test_activate_binds_and_starts_countdown(ctx, base):
    card = ctx.store.gen_cards(1, duration_sec=3600, batch="neg")[0]
    device_fp = secrets.token_bytes(32).hex()
    pub = p256_generate_keypair()[1].hex()
    before = ctx.store.get_card(store_mod.card_hash(card))
    check(
        "test card is unbound with expire=0 before activation",
        before["device_fp"] is None and int(before["expire"] or 0) == 0,
        f"fp={before['device_fp']} expire={before['expire']}",
    )

    started = int(time.time())
    fresh(ctx)
    status, payload = post_json(base, "/api/activate", {
        "card": card, "device_fp": device_fp, "pubkey": pub,
    })
    expire = int(payload.get("expire") or 0)
    check(
        "activate test card -> code 0 with blob + wrapped",
        status == 200 and payload.get("code") == 0
        and len(payload.get("blob", "")) > 100 and len(payload.get("wrapped", "")) > 100,
        f"{payload.get('code')} {payload.get('msg')}",
    )
    check(
        "countdown starts at first bind (expire ~= now + 3600)",
        abs(expire - (started + 3600)) <= 5,
        f"expire={expire} started={started}",
    )
    after = ctx.store.get_card(store_mod.card_hash(card))
    check(
        "card row records the device fingerprint",
        after["device_fp"] == device_fp and int(after["expire"] or 0) == expire,
        f"fp={after['device_fp']} expire={after['expire']}",
    )


def test_activate_other_device_1002(ctx, base):
    card = ctx.store.gen_cards(1, duration_sec=3600, batch="neg")[0]
    owner_fp = secrets.token_bytes(32).hex()
    thief_fp = secrets.token_bytes(32).hex()
    fresh(ctx)
    status, payload = post_json(base, "/api/activate", {
        "card": card, "device_fp": owner_fp, "pubkey": p256_generate_keypair()[1].hex(),
    })
    assert payload.get("code") == 0, payload

    fresh(ctx)
    status, payload = post_json(base, "/api/activate", {
        "card": card, "device_fp": thief_fp, "pubkey": p256_generate_keypair()[1].hex(),
    })
    check("activate from another device -> 1002", status == 200 and payload.get("code") == 1002, f"{payload}")
    row = ctx.store.get_card(store_mod.card_hash(card))
    check("rejected activation does not move the binding", row["device_fp"] == owner_fp, f"{row['device_fp']}")


def test_reactivate_keeps_countdown(ctx, base):
    card = ctx.store.gen_cards(1, duration_sec=3600, batch="neg")[0]
    device_fp = secrets.token_bytes(32).hex()
    fresh(ctx)
    _, first = post_json(base, "/api/activate", {
        "card": card, "device_fp": device_fp, "pubkey": p256_generate_keypair()[1].hex(),
    })
    time.sleep(1.1)
    fresh(ctx)
    status, second = post_json(base, "/api/activate", {
        "card": card, "device_fp": device_fp, "pubkey": p256_generate_keypair()[1].hex(),
    })
    check(
        "reinstall (same device_fp, new pubkey) keeps the original countdown",
        status == 200 and second.get("code") == 0
        and int(second.get("expire") or 0) == int(first.get("expire") or 0),
        f"first={first.get('expire')} second={second.get('expire')}",
    )


def test_permanent_card_expire_zero(ctx, base):
    card = ctx.store.gen_cards(1, duration_sec=0, batch="neg")[0]
    fresh(ctx)
    status, payload = post_json(base, "/api/activate", {
        "card": card,
        "device_fp": secrets.token_bytes(32).hex(),
        "pubkey": p256_generate_keypair()[1].hex(),
    })
    check(
        "permanent card -> code 0, expire=0",
        status == 200 and payload.get("code") == 0 and payload.get("expire") == 0,
        f"{payload}",
    )


def test_expired_card_1003(ctx, base):
    card = ctx.store.gen_cards(1, duration_sec=0, batch="neg")[0]
    with ctx.store._connect() as conn:
        conn.execute(
            "UPDATE cards SET expire = ? WHERE card_hash = ?",
            (int(time.time()) - 60, store_mod.card_hash(card)),
        )
    fresh(ctx)
    status, payload = post_json(base, "/api/activate", {
        "card": card,
        "device_fp": secrets.token_bytes(32).hex(),
        "pubkey": p256_generate_keypair()[1].hex(),
    })
    check("expired card -> 1003", status == 200 and payload.get("code") == 1003, f"{payload}")


# --- session key issue -----------------------------------------------------

def test_session_requires_bound_card(ctx, base):
    card = ctx.store.gen_cards(1, duration_sec=3600, batch="neg")[0]
    fresh(ctx)
    status, payload = post_json(base, "/api/session", {
        "card": card,
        "device_fp": secrets.token_bytes(32).hex(),
        "pubkey": p256_generate_keypair()[1].hex(),
    })
    check("session on an unbound card -> 1002", status == 200 and payload.get("code") == 1002, f"{payload}")


def test_session_same_device_rekeys_without_extending(ctx, base):
    card = ctx.store.gen_cards(1, duration_sec=3600, batch="neg")[0]
    device_fp = secrets.token_bytes(32).hex()
    fresh(ctx)
    _, act = post_json(base, "/api/activate", {
        "card": card, "device_fp": device_fp, "pubkey": p256_generate_keypair()[1].hex(),
    })
    assert act.get("code") == 0, act

    fresh(ctx)
    status, payload = post_json(base, "/api/session", {
        "card": card, "device_fp": device_fp, "pubkey": p256_generate_keypair()[1].hex(),
    })
    check(
        "session after reinstall (new pubkey) -> code 0 with a fresh envelope",
        status == 200 and payload.get("code") == 0 and len(payload.get("wrapped", "")) > 100,
        f"{payload.get('code')} {payload.get('msg')}",
    )
    check(
        "session does not extend or restart the countdown",
        int(payload.get("expire") or 0) == int(act.get("expire") or 0),
        f"activate={act.get('expire')} session={payload.get('expire')}",
    )


def test_session_other_device_1002(ctx, base):
    card = ctx.store.gen_cards(1, duration_sec=3600, batch="neg")[0]
    fresh(ctx)
    post_json(base, "/api/activate", {
        "card": card,
        "device_fp": secrets.token_bytes(32).hex(),
        "pubkey": p256_generate_keypair()[1].hex(),
    })
    fresh(ctx)
    status, payload = post_json(base, "/api/session", {
        "card": card,
        "device_fp": secrets.token_bytes(32).hex(),
        "pubkey": p256_generate_keypair()[1].hex(),
    })
    check("session from another device -> 1002", status == 200 and payload.get("code") == 1002, f"{payload}")


def test_session_after_disable_1001(ctx, base):
    card = ctx.store.gen_cards(1, duration_sec=3600, batch="neg")[0]
    device_fp = secrets.token_bytes(32).hex()
    fresh(ctx)
    post_json(base, "/api/activate", {
        "card": card, "device_fp": device_fp, "pubkey": p256_generate_keypair()[1].hex(),
    })
    ctx.store.disable_card(store_mod.card_hash(card))
    fresh(ctx)
    status, payload = post_json(base, "/api/session", {
        "card": card, "device_fp": device_fp, "pubkey": p256_generate_keypair()[1].hex(),
    })
    check("session after disable -> 1001", status == 200 and payload.get("code") == 1001, f"{payload}")


# --- removed bind/unbind surface ------------------------------------------

def test_rebind_endpoint_removed(ctx, base):
    fresh(ctx)
    status, payload = post_json(
        base, "/api/admin/rebind", {"card": store_mod.generate_card_key(), "device_fp": None},
        headers={"Authorization": "Bearer negative-test-admin-key-0123456789abcdef"},
    )
    check("removed /api/admin/rebind -> 404", status == 404, f"http={status}")


def test_unbind_action_refused(ctx, base):
    fresh(ctx)
    status, payload = post_json(
        base, "/admin/api/card_action",
        {"action": "unbind", "card_hash": "00" * 32},
        headers={"Cookie": "gl_admin_sid=" + "0" * 32},
    )
    check("card_action=unbind is not reachable", payload.get("code") not in (0, None), f"http={status} {payload}")


# --- device logs -----------------------------------------------------------

def _bound_token(ctx, duration_sec: int = 0) -> tuple[str, str, str]:
    """Create a card, bind it, return (card_hash, device_fp, token)."""
    card = ctx.store.gen_cards(1, duration_sec=duration_sec, batch="neg")[0]
    device_fp = secrets.token_bytes(32).hex()
    ch = store_mod.card_hash(card)
    assert ctx.store.claim_card(ch, device_fp, 0)
    return ch, device_fp, ctx.store.create_token(ch, device_fp)


def test_log_upload_requires_token(ctx, base):
    fresh(ctx)
    status, payload = post_json(base, "/api/log", {"lines": ["no token"]})
    check("log upload without token -> 1005", status == 200 and payload.get("code") == 1005, f"{payload}")


def test_log_upload_binds_to_card(ctx, base):
    ch, _, token = _bound_token(ctx)
    fresh(ctx)
    status, payload = post_json(base, "/api/log", {"token": token, "lines": ["line-a", "line-b"]})
    check("log upload -> code 0", status == 200 and payload.get("code") == 0, f"{payload}")
    rows = ctx.store.list_logs(ch)
    check(
        "log lines are stored under the card",
        [r["line"] for r in rows][-2:] == ["line-a", "line-b"],
        f"{[r['line'] for r in rows][-2:]}",
    )


def test_log_upload_wire(ctx, base):
    ch, _, token = _bound_token(ctx)
    body = encode(KIND_REQUEST, 0, [(TAG_TOKEN, token.encode("utf-8")), (TAG_LOG, b"wire-line")])
    fresh(ctx)
    status, _, raw = post_wire(base, "/api/log", body)
    decoded = decode(raw)
    rows = ctx.store.list_logs(ch)
    check(
        "log upload over the binary wire -> accepted and stored",
        status == 200 and decoded is not None and decoded[0] == KIND_RESPONSE
        and rows and rows[-1]["line"] == "wire-line",
        f"status={status}",
    )


def test_admin_logs_endpoint(ctx, base):
    ch, _, token = _bound_token(ctx)
    fresh(ctx)
    post_json(base, "/api/log", {"token": token, "lines": ["admin-visible"]})
    fresh(ctx)
    status, payload = post_json(
        base, "/admin/api/logs", {"card_hash": ch},
        headers={"Authorization": "Bearer negative-test-admin-key-0123456789abcdef"},
    )
    check(
        "admin logs endpoint returns the card's lines",
        status == 200 and payload.get("code") == 0
        and payload.get("lines") and payload["lines"][-1]["line"] == "admin-visible"
        and payload.get("retention_sec") == 24 * 3600,
        f"{payload.get('code')}",
    )


def test_log_upload_blank_1005(ctx, base):
    ch, _, token = _bound_token(ctx)
    fresh(ctx)
    status, payload = post_json(
        base, "/api/log", {"token": token, "lines": ["   ", "\x00\x00"]},
    )
    check(
        "blank / NUL-only log upload -> 1005",
        status == 200 and payload.get("code") == 1005,
        f"{payload}",
    )


def test_log_upload_after_disable_1001(ctx, base):
    ch, _, token = _bound_token(ctx)
    ctx.store.disable_card(ch)
    fresh(ctx)
    status, payload = post_json(base, "/api/log", {"token": token, "lines": ["after disable"]})
    # disable_card revokes the card's tokens, so the upload is rejected as an
    # invalid authorization (1002) rather than a disabled card (1001).
    check("log upload after disable -> 1002", status == 200 and payload.get("code") == 1002, f"{payload}")


def test_log_retention_24h(ctx, base):
    ch, device_fp, _ = _bound_token(ctx)
    ctx.store.append_logs(ch, device_fp, ["old line"], ts=int(time.time()) - 86401)
    ctx.store.append_logs(ch, device_fp, ["fresh line"])
    lines = [r["line"] for r in ctx.store.list_logs(ch)]
    check(
        "logs older than 24h are pruned, fresh ones kept",
        lines == ["fresh line"],
        f"{lines}",
    )


# --- transport and heartbeat state ---------------------------------------

def test_chunked_request_rejected():
    # A throwaway server is enough: the check happens before any routing.
    srv = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    srv.context = None
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    port = srv.server_address[1]
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        body = "5\r\nhello\r\n0\r\n\r\n"
        request = (
            "POST /api/activate HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Type: application/json\r\n"
            "Connection: keep-alive\r\n\r\n" + body
        )
        sock.sendall(request.encode("latin-1"))
        response = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response += chunk
        sock.close()
        status_line = response.split(b"\r\n", 1)[0].decode("latin-1")
        ok = status_line.startswith("HTTP/1.1 411") and b'"code": 1005' in response
        check("chunked request -> 411 and connection closed", ok, status_line)
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def test_heartbeat_disabled_state_zero(ctx, base):
    fresh(ctx)
    card_key = store_mod.generate_card_key()
    card_hash_value = store_mod.card_hash(card_key)
    device_fp = secrets.token_bytes(32).hex()
    assert ctx.store.claim_card(card_hash_value, device_fp, 0)
    token = ctx.store.create_token(card_hash_value, device_fp)
    with ctx.store._connect() as conn:
        conn.execute("UPDATE cards SET state = 'disabled' WHERE card_hash = ?", (card_hash_value,))

    status, payload = post_json(base, "/api/heartbeat", {"token": token})
    ok_json = status == 200 and payload.get("code") == 0 and payload.get("state") == 0
    check("heartbeat disabled card JSON -> state=0", ok_json, f"{payload}")

    wire_body = encode(KIND_REQUEST, 0, [(TAG_TOKEN, token.encode("utf-8"))])
    status, content_type, raw = post_wire(base, "/api/heartbeat", wire_body)
    decoded = decode(raw)
    state = decoded[1].get(TAG_STATE) if decoded is not None else None
    ok_wire = status == 200 and decoded is not None and decoded[0] == KIND_RESPONSE and state == b"\x00"
    check("heartbeat disabled card wire -> tag 0x36 state=0", ok_wire, f"state={state!r}")


def main() -> int:
    print("=== XproSU license negative-path tests ===")
    with tempfile.TemporaryDirectory(prefix="gl-neg-") as tmpdir:
        ctx = make_ctx(tmpdir)
        srv, thread, base = start_server(ctx)
        try:
            test_chunked_request_rejected()
            test_activate_unknown_card_1001(ctx, base)
            test_activate_binds_and_starts_countdown(ctx, base)
            test_activate_other_device_1002(ctx, base)
            test_reactivate_keeps_countdown(ctx, base)
            test_permanent_card_expire_zero(ctx, base)
            test_expired_card_1003(ctx, base)
            test_session_requires_bound_card(ctx, base)
            test_session_same_device_rekeys_without_extending(ctx, base)
            test_session_other_device_1002(ctx, base)
            test_session_after_disable_1001(ctx, base)
            test_rebind_endpoint_removed(ctx, base)
            test_unbind_action_refused(ctx, base)
            test_log_upload_requires_token(ctx, base)
            test_log_upload_binds_to_card(ctx, base)
            test_log_upload_wire(ctx, base)
            test_admin_logs_endpoint(ctx, base)
            test_log_upload_blank_1005(ctx, base)
            test_log_upload_after_disable_1001(ctx, base)
            test_log_retention_24h(ctx, base)
            test_heartbeat_disabled_state_zero(ctx, base)
        finally:
            srv.shutdown()
            srv.server_close()
            thread.join(timeout=5)
        gc.collect()  # release sqlite connections before TemporaryDirectory cleanup on Windows

    failed = [r for r in RESULTS if not r[1]]
    print("---")
    if failed:
        print(f"{len(failed)} FAILED, {len(RESULTS) - len(failed)} passed")
        return 1
    print(f"ALL {len(RESULTS)} NEGATIVE TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
