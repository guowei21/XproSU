"""HTTP end-to-end check for the binary/JSON wire fallback on /api/heartbeat.

Starts a throwaway local license server in-process, then sends one binary and
one JSON heartbeat with an invalid token.  Both must be rejected with the same
business code (1002), and each response must use the same encoding as its
request.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from server import LicensingContext, _Handler, load_config
from wire import (
    KIND_REQUEST,
    KIND_RESPONSE,
    MAGIC_WIRE,
    TAG_MSG,
    TAG_TOKEN,
    decode,
    encode,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class _QuietHandler(_Handler):
    def log_message(self, fmt: str, *args) -> None:
        pass


def _post(url: str, body: bytes, content_type: str) -> tuple[int, str, bytes]:
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": content_type},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.headers.get("Content-Type", ""), resp.read()


def main() -> int:
    cfg = load_config(os.path.join(BASE_DIR, "config.json"))
    ctx = LicensingContext(cfg)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
    srv.context = ctx
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/api/heartbeat"

    try:
        # Binary request, invalid token -> binary business rejection.
        wire_body = encode(KIND_REQUEST, 0, [(TAG_TOKEN, b"00" * 32)])
        status, content_type, body = _post(url, wire_body, "application/octet-stream")
        assert status == 200, f"binary heartbeat HTTP {status}"
        assert content_type.startswith("application/octet-stream"), content_type
        assert body[:4] == MAGIC_WIRE.to_bytes(4, "little"), "binary response has no wire magic"
        code = struct.unpack_from("<H", body, 6)[0]
        decoded = decode(body)
        assert decoded is not None and decoded[0] == KIND_RESPONSE, "binary response decode failed"
        assert code == 1002, f"expected business code 1002, got {code}"
        assert decoded[1].get(TAG_MSG) == "授权已失效".encode("utf-8"), decoded
        print("binary heartbeat -> wire rejection OK (code=1002, msg=授权已失效)")

        # JSON request, invalid token -> JSON business rejection.
        json_body = json.dumps({"token": "00" * 32}, ensure_ascii=False).encode("utf-8")
        status, content_type, body = _post(url, json_body, "application/json")
        assert status == 200, f"json heartbeat HTTP {status}"
        assert content_type.startswith("application/json"), content_type
        payload = json.loads(body.decode("utf-8"))
        assert payload.get("code") == 1002, payload
        assert payload.get("msg") == "授权已失效", payload
        print("json heartbeat -> json rejection OK (code=1002, msg=授权已失效)")

        print("wire_smoke.py ALL PASS")
        return 0
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
