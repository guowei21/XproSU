"""Negative-path tests for GhostLock licensing server (zero dependencies).

Run directly:

    python negative_test.py

Covers the fail-open regressions the fix targets: upstream business-code
handling, fail-closed state checks, vipExpDate semantics, chunked request
smuggling and disabled-card heartbeat state.
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

from crypto import aes128cbc_encrypt, pkcs7_pad, p256_generate_keypair
import server as server_mod
import store as store_mod
import uverif as uverif_mod
from uverif import UVerifRejected, UVerifUnreachable
from wire import (
    KIND_REQUEST,
    KIND_RESPONSE,
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


def expect_raises(exc_type, fn) -> None:
    try:
        fn()
    except exc_type:
        return
    except Exception as exc:  # pragma: no cover - diagnostic detail only
        raise AssertionError(f"expected {exc_type.__name__}, got {type(exc).__name__}: {exc}") from exc
    raise AssertionError(f"expected {exc_type.__name__}, nothing raised")


class FakeUverif:
    def __init__(self, result=None, exc=None):
        self.result = result
        self.exc = exc

    def logon(self, account, password, udid):
        if self.exc is not None:
            raise self.exc
        return self.result


class FakeResponse:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.body


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
        "uverif": {
            "base_url": "http://127.0.0.1:1",
            "app_id": "1",
            "app_index": "x",
            "app_ver": "1.0.0",
            "app_key": "k",
            "aes_key": "0123456789abcdef",
        },
    }
    return server_mod.LicensingContext(cfg)


def start_server(ctx):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    srv.context = ctx
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread, f"http://127.0.0.1:{srv.server_address[1]}"


def post_json(base: str, path: str, obj: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        base + path,
        data=json.dumps(obj).encode("utf-8"),
        headers={"Content-Type": "application/json"},
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


def activation_payload(card: str):
    _, pub = p256_generate_keypair()
    return {
        "card": card,
        "device_fp": secrets.token_bytes(32).hex(),
        "pubkey": pub.hex(),
        "app_ver": "1.0.0",
    }


def assert_no_blob_wrapped(payload: dict) -> None:
    assert "blob" not in payload, payload
    assert "wrapped" not in payload, payload


# --- upstream business-code fail-closed -----------------------------------

def test_uverif_code_false_fails_closed():
    client = uverif_mod.UVerifClient(
        {
            "base_url": "http://127.0.0.1:1",
            "app_id": "1",
            "app_index": "x",
            "app_ver": "1",
            "app_key": "k",
            "aes_key": "0123456789abcdef",
        }
    )
    original = uverif_mod.urllib.request.urlopen

    def fake_urlopen(req, timeout):
        return FakeResponse(json.dumps({"code": False}).encode("utf-8"))

    uverif_mod.urllib.request.urlopen = fake_urlopen
    try:
        expect_raises(UVerifUnreachable, lambda: client.logon("a", "b", "c"))
    finally:
        uverif_mod.urllib.request.urlopen = original
    check("uverif code=false raises UVerifUnreachable", True)


def test_uverif_code_0_data_null_returns_none():
    client = uverif_mod.UVerifClient(
        {
            "base_url": "http://127.0.0.1:1",
            "app_id": "1",
            "app_index": "x",
            "app_ver": "1",
            "app_key": "k",
            "aes_key": "0123456789abcdef",
        }
    )
    original = uverif_mod.urllib.request.urlopen
    key = b"0123456789abcdef"
    iv = os.urandom(16)
    ct = aes128cbc_encrypt(key, iv, pkcs7_pad(b"null"))
    data_hex = (iv + ct).hex()

    def fake_urlopen(req, timeout):
        return FakeResponse(json.dumps({"code": 0, "data": data_hex}).encode("utf-8"))

    uverif_mod.urllib.request.urlopen = fake_urlopen
    try:
        result = client._call("logon", {"account": "a", "password": "b", "udid": "c"})
    finally:
        uverif_mod.urllib.request.urlopen = original
    check("uverif code=0 with AES-encrypted null returns None", result is None)


# --- server activation fail-closed ----------------------------------------

def test_activate_non_dict_upstream_rejected(ctx, base):
    ctx._rate.clear()
    ctx.uverif = FakeUverif(result=["not", "a", "dict"])
    status, payload = post_json(base, "/api/activate", activation_payload("TEST-NONDICT"))
    assert_no_blob_wrapped(payload)
    check("activate non-dict upstream -> 1004", status == 200 and payload.get("code") == 1004, f"{payload}")


def test_activate_null_upstream_rejected(ctx, base):
    ctx._rate.clear()
    ctx.uverif = FakeUverif(result=None)
    status, payload = post_json(base, "/api/activate", activation_payload("TEST-NULL"))
    assert_no_blob_wrapped(payload)
    check("activate null upstream (AES null) -> 1004", status == 200 and payload.get("code") == 1004, f"{payload}")


def test_activate_unreachable_rejected(ctx, base):
    ctx._rate.clear()
    ctx.uverif = FakeUverif(exc=UVerifUnreachable("down"))
    status, payload = post_json(base, "/api/activate", activation_payload("TEST-UNREACH"))
    assert_no_blob_wrapped(payload)
    check("activate UVerifUnreachable -> 1004", status == 200 and payload.get("code") == 1004, f"{payload}")


def test_activate_missing_state_rejected(ctx, base):
    ctx._rate.clear()
    ctx.uverif = FakeUverif(result={"code": 0})
    status, payload = post_json(base, "/api/activate", activation_payload("TEST-NOSTATE"))
    assert_no_blob_wrapped(payload)
    check("activate missing state -> 1001", status == 200 and payload.get("code") == 1001, f"{payload}")


def test_vip_exp_date_missing_is_permanent(ctx, base):
    ctx._rate.clear()
    ctx.uverif = FakeUverif(result={"state": "y"})
    status, payload = post_json(base, "/api/activate", activation_payload("TEST-PERM"))
    check(
        "activate missing vipExpDate -> expire=0 permanent",
        status == 200
        and payload.get("code") == 0
        and payload.get("expire") == 0
        and payload.get("blob")
        and payload.get("wrapped"),
        f"{payload}",
    )


def test_vip_exp_date_number_rejected(ctx, base):
    ctx._rate.clear()
    ctx.uverif = FakeUverif(result={"state": "y", "info": {"vipExpDate": 20261231}})
    status, payload = post_json(base, "/api/activate", activation_payload("TEST-NUMDATE"))
    assert_no_blob_wrapped(payload)
    check("activate numeric vipExpDate -> 1011", status == 200 and payload.get("code") == 1011, f"{payload}")


def test_vip_exp_date_garbage_rejected(ctx, base):
    ctx._rate.clear()
    ctx.uverif = FakeUverif(result={"state": "y", "vipExpDate": "not-a-date"})
    status, payload = post_json(base, "/api/activate", activation_payload("TEST-GARBAGE"))
    assert_no_blob_wrapped(payload)
    check("activate garbage vipExpDate -> 1011", status == 200 and payload.get("code") == 1011, f"{payload}")


# --- chunked transfer-encoding --------------------------------------------

def test_chunked_request_rejected():
    port = None
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





# --- heartbeat state -------------------------------------------------------

def test_heartbeat_disabled_state_zero(ctx, base):
    ctx._rate.clear()
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
    print("=== GhostLock license negative-path tests ===")
    with tempfile.TemporaryDirectory(prefix="gl-neg-") as tmpdir:
        ctx = make_ctx(tmpdir)
        srv, thread, base = start_server(ctx)
        try:
            test_uverif_code_false_fails_closed()
            test_uverif_code_0_data_null_returns_none()
            test_activate_non_dict_upstream_rejected(ctx, base)
            test_activate_null_upstream_rejected(ctx, base)
            test_activate_unreachable_rejected(ctx, base)
            test_activate_missing_state_rejected(ctx, base)
            test_vip_exp_date_missing_is_permanent(ctx, base)
            test_vip_exp_date_number_rejected(ctx, base)
            test_vip_exp_date_garbage_rejected(ctx, base)
            test_chunked_request_rejected()
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
