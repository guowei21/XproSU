"""GhostLock licensing HTTP server + Web Admin Console (zero third-party dependencies).

Standalone build: the card authority lives entirely in ``cards.db``.
Provides both the binary/JSON client licensing endpoints and the Web UI console
at ``/admin`` (authenticated via username/password session cookies).
"""
from __future__ import annotations

import ipaddress
import hmac
import json
import os
import struct
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from payload import _deserialize_glp, build_glt2_from_glp
from crypto import chacha20_poly1305_decrypt, ecies_wrap, hkdf_sha256, sha256
from store import CardStore, LOG_RETENTION_SEC, card_hash, normalize_card_key
from wire import (
    KIND_REQUEST,
    KIND_RESPONSE,
    MAGIC_WIRE,
    TAG_APP_VER,
    TAG_BLOB,
    TAG_CARD,
    TAG_DEVICE_FP,
    TAG_EXPIRE,
    TAG_LOG,
    TAG_MSG,
    TAG_PUBKEY,
    TAG_TOKEN,
    TAG_TOKEN_RESP,
    TAG_STATE,
    TAG_WRAPPED,
    decode,
    encode,
)

MAX_BODY_BYTES = 256 * 1024

ACTIVATE_RATE_LIMIT = 30
ACTIVATE_RATE_WINDOW = 60.0
HEARTBEAT_RATE_LIMIT = 60
HEARTBEAT_RATE_WINDOW = 60.0
ADMIN_RATE_LIMIT = 60
ADMIN_RATE_WINDOW = 60.0
LOGIN_RATE_LIMIT = 10
LOGIN_RATE_WINDOW = 60.0
LOG_RATE_LIMIT = 60
LOG_RATE_WINDOW = 60.0
RATE_TABLE_MAX = 4096

INSECURE_ADMIN_KEYS = {"", "CHANGE-ME-admin", "changeme", "admin", "password"}

# 绑定策略：一张卡密绑定一台设备，绑定**不可解除**。
#
# 这不是一个可切换的功能开关，而是本服务的固定语义：同 device_fp 的激活
# （卸载重装 / 清数据 / 恢复出厂，Widevine id 不变）可以更新设备公钥，
# 不同 device_fp 一律拒绝，且**没有任何**解绑/换绑入口 —— 管理 API、Web 后台、
# CLI 三处都不存在该行为。仅用于给前端声明事实，不要把它接到 cfg 上。
DEVICE_REBIND_SUPPORTED = False

# 卡密类型只有两种：
#   test      → 测试卡，3600 秒（1 小时）。计时从**首次绑定那台机器**开始，
#               未激活期间不过期。
#   permanent → 永久卡，永不过期。
# 生成时 expire 一律写 0；真正的时间点由 claim_card_verbose 在首次绑定时写入。
TEST_CARD_DURATION = 3600

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SESSION_COOKIE = "gl_admin_sid"


def client_ip(headers, peer: str) -> str:
    raw = headers.get("X-Real-IP")
    if raw:
        candidate = raw.strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    return peer


WIRE_TAG_FIELDS: dict[int, str] = {
    TAG_CARD: "card",
    TAG_DEVICE_FP: "device_fp",
    TAG_PUBKEY: "pubkey",
    TAG_APP_VER: "app_ver",
    TAG_LOG: "log",
    TAG_TOKEN: "token",
}


def public_card(row: dict) -> dict:
    """Card row as sent to any admin client (device_fp included: support
    matches it against the code the app shows on its login screen)."""
    return dict(row)


def load_config(path: str | None = None) -> dict:
    cfg_path = path or os.path.join(BASE_DIR, "config.json")
    with open(cfg_path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    cfg["_config_path"] = os.path.abspath(cfg_path)
    cfg["_config_dir"] = os.path.dirname(os.path.abspath(cfg_path))
    return cfg


def resolve_path(cfg: dict, key: str) -> str:
    p = cfg.get(key, "")
    if not p:
        return ""
    if os.path.isabs(p):
        return p
    return os.path.join(cfg["_config_dir"], p)


class LicensingContext:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.cfg_lock = threading.Lock()
        master_hex = os.environ.get("GL_MASTER_KEY") or cfg.get("master_key", "")
        if os.environ.get("GL_MASTER_KEY"):
            cfg["master_key"] = "(env:GL_MASTER_KEY)"
        try:
            self.master_key = bytes.fromhex(master_hex)
        except ValueError:
            raise ValueError("master_key must be a hex string") from None
        if len(self.master_key) != 32:
            raise ValueError("master_key must be 64 hex chars (32 bytes)")
        self.admin_key = str(cfg.get("admin_key", "")).strip()
        if not self.admin_key or self.admin_key in INSECURE_ADMIN_KEYS:
            raise ValueError("admin_key is unset or insecure")
        self.admin_user = str(cfg.get("admin_user", "Aa010227")).strip()
        self.admin_pass_hash = str(cfg.get("admin_pass_hash", "")).strip()
        if not self.admin_pass_hash:
            default_pass = str(cfg.get("admin_pass", "Aa010227"))
            self.admin_pass_hash = sha256(default_pass).hex()

        self.store = CardStore(resolve_path(cfg, "db_path") or os.path.join(BASE_DIR, "cards.db"))
        self.payload_glp = self._load_payload(resolve_path(cfg, "payload_path") or os.path.join(BASE_DIR, "payload.bin"))
        try:
            self.store.purge_expired_tokens()
            self.store.prune_sessions()
        except Exception:
            pass
        self._rate: dict[tuple[str, str], list[float]] = {}
        self._rate_lock = threading.Lock()

    def verify_web_login(self, username: str, password: str) -> bool:
        if not username or not password:
            return False
        u_ok = hmac.compare_digest(username.encode("utf-8"), self.admin_user.encode("utf-8"))
        p_ok = hmac.compare_digest(sha256(password).hex().encode("ascii"), self.admin_pass_hash.encode("ascii"))
        return u_ok and p_ok

    def update_web_auth(self, new_user: str | None, new_pass: str | None) -> None:
        with self.cfg_lock:
            if new_user:
                self.admin_user = new_user
            if new_pass:
                self.admin_pass_hash = sha256(new_pass).hex()
            cfg_path = self.cfg.get("_config_path")
            if cfg_path and os.path.isfile(cfg_path):
                with open(cfg_path, "r", encoding="utf-8") as fh:
                    disk = json.load(fh)
                disk["admin_user"] = self.admin_user
                disk["admin_pass_hash"] = self.admin_pass_hash
                disk.pop("admin_pass", None)
                with open(cfg_path, "w", encoding="utf-8") as fh:
                    json.dump(disk, fh, ensure_ascii=False, indent=2)

    @staticmethod
    def _load_payload(payload_path: str) -> bytes | None:
        enc_path = payload_path + ".enc"
        enc_key_hex = os.environ.get("GL_PAYLOAD_KEY", "")
        if os.path.exists(enc_path):
            if not enc_key_hex:
                raise ValueError(f"{enc_path} exists but GL_PAYLOAD_KEY is not set")
            key = bytes.fromhex(enc_key_hex)
            if len(key) != 32:
                raise ValueError("GL_PAYLOAD_KEY must be 64 hex chars")
            with open(enc_path, "rb") as fh:
                blob = fh.read()
            if len(blob) < 34 or blob[:4] != b"GLPE":
                raise ValueError(f"invalid encrypted payload file {enc_path}")
            aad, nonce, ct, tag = blob[:6], blob[6:18], blob[18:-16], blob[-16:]
            glp = chacha20_poly1305_decrypt(key, nonce, aad, ct, tag)
            _deserialize_glp(glp)
            return glp
        try:
            with open(payload_path, "rb") as fh:
                data = fh.read()
            _deserialize_glp(data)
            return data
        except FileNotFoundError:
            return None
        except ValueError as exc:
            raise ValueError(f"invalid payload file {payload_path}: {exc}") from None

    def _allow(self, bucket: str, peer: str, limit: int, window: float) -> bool:
        now = time.monotonic()
        key = (bucket, peer)
        with self._rate_lock:
            hits = [t for t in self._rate.get(key, ()) if now - t < window]
            if len(hits) >= limit:
                self._rate[key] = hits
                return False
            hits.append(now)
            self._rate[key] = hits
            if len(self._rate) > RATE_TABLE_MAX:
                for stale_key in [k for k, v in self._rate.items() if not v or now - v[-1] > window]:
                    self._rate.pop(stale_key, None)
        return True

    def allow_activate(self, peer: str) -> bool:
        return self._allow("activate", peer, ACTIVATE_RATE_LIMIT, ACTIVATE_RATE_WINDOW)

    def allow_heartbeat(self, peer: str) -> bool:
        return self._allow("heartbeat", peer, HEARTBEAT_RATE_LIMIT, HEARTBEAT_RATE_WINDOW)

    def allow_admin(self, peer: str) -> bool:
        return self._allow("admin", peer, ADMIN_RATE_LIMIT, ADMIN_RATE_WINDOW)

    def allow_login(self, peer: str) -> bool:
        return self._allow("login", peer, LOGIN_RATE_LIMIT, LOGIN_RATE_WINDOW)

    def allow_log(self, peer: str) -> bool:
        return self._allow("log", peer, LOG_RATE_LIMIT, LOG_RATE_WINDOW)

    # 设备换绑（unbind / rebind）在本服务里**不存在**，且不是配置项：
    # 一张卡密绑定一台设备，绑定只由同 device_fp 的激活写入，永不解除。
    # 需要让设备脱离卡密时：revoke（终态，记审计）后重新发卡。


class _Handler(BaseHTTPRequestHandler):
    server_version = "GhostLockLicense/2.1"
    protocol_version = "HTTP/1.1"

    @property
    def ctx(self) -> LicensingContext:
        return self.server.context  # type: ignore[attr-defined]

    def _read_body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            self.close_connection = True
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            self.close_connection = True
            return None
        return self.rfile.read(length) if length else b""

    def _send_json(self, obj: dict, status: int = 200, extra_headers: list[tuple[str, str]] | None = None) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html_bytes: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(html_bytes)))
        self.end_headers()
        self.wfile.write(html_bytes)

    def _send_ok(self, obj: dict, extra_headers: list[tuple[str, str]] | None = None) -> None:
        obj.setdefault("code", 0)
        self._send_json(obj, extra_headers=extra_headers)

    def _send_error(self, code: int, msg: str, status: int = 200) -> None:
        self._send_json({"code": code, "msg": msg}, status=status)

    def _send_wire(self, code: int, entries: list[tuple[int, bytes]], status: int = 200) -> None:
        body = encode(KIND_RESPONSE, code, entries)
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_wire_ok(self, entries: list[tuple[int, bytes]]) -> None:
        self._send_wire(0, entries)

    def _send_wire_error(self, code: int, msg: str) -> None:
        self._send_wire(code, [(TAG_MSG, msg.encode("utf-8"))])

    def _fail(self, code: int, msg: str, wire: bool) -> None:
        if wire:
            self._send_wire_error(code, msg)
        else:
            self._send_error(code, msg)

    @staticmethod
    def _is_wire_body(body: bytes) -> bool:
        return body[:4] == MAGIC_WIRE.to_bytes(4, "little")

    def _parse_wire_request(self, body: bytes) -> dict[int, bytes] | None:
        decoded = decode(body)
        if decoded is None:
            return None
        kind, entries = decoded
        if kind != KIND_REQUEST:
            return None
        return entries

    @staticmethod
    def _wire_fields(entries: dict[int, bytes]) -> dict:
        fields: dict[str, str] = {}
        for tag, value in entries.items():
            name = WIRE_TAG_FIELDS.get(tag)
            if name is None:
                continue
            try:
                fields[name] = value.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"tag {tag:#x} is not valid UTF-8") from exc
        return fields

    def _parse_json(self, body: bytes) -> dict | None:
        if not body:
            return {}
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _get_session_cookie(self) -> str | None:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return None
        c = SimpleCookie()
        try:
            c.load(raw)
        except Exception:
            return None
        morsel = c.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def _check_admin(self) -> bool:
        # 1. Check Bearer token
        configured = self.ctx.admin_key
        auth = self.headers.get("Authorization", "")
        if configured and auth and hmac.compare_digest(auth.encode("utf-8"), f"Bearer {configured}".encode("utf-8")):
            return True
        # 2. Check Web UI session cookie
        sid = self._get_session_cookie()
        if sid and self.ctx.store.verify_session(sid):
            return True
        return False

    def _route(self) -> str:
        return urlsplit(self.path).path

    # -- HTTP entry points --------------------------------------------------

    def do_GET(self) -> None:
        route = self._route()
        if route in ("/admin", "/admin/", "/admin/index.html"):
            ui_path = os.path.join(BASE_DIR, "admin_ui.html")
            try:
                with open(ui_path, "rb") as fh:
                    self._send_html(fh.read())
            except FileNotFoundError:
                self._send_html(b"<h1>Admin UI file missing</h1>", status=404)
            return
        self._send_json({"code": 1005, "msg": "仅支持 POST"}, 404)

    def do_POST(self) -> None:
        is_wire = False
        try:
            if self.headers.get("Transfer-Encoding", "").strip():
                self.close_connection = True
                self._send_json({"code": 1005, "msg": "不支持 chunked 请求体"}, 411)
                return
            body = self._read_body()
            if body is None:
                self._send_json({"code": 1005, "msg": "请求体过大或非法"}, 413)
                return
            is_wire = self._is_wire_body(body)
            route = self._route()
            peer_ip = client_ip(self.headers, self.client_address[0])

            if route == "/api/session":
                if not self.ctx.allow_activate(peer_ip):
                    if is_wire:
                        self._send_wire_error(1005, "请求过于频繁，请稍后再试")
                    else:
                        self._send_json({"code": 1005, "msg": "请求过于频繁，请稍后再试"}, 429)
                    return
                if is_wire:
                    entries = self._parse_wire_request(body)
                    if entries is None:
                        self._send_wire_error(1005, "请求格式错误")
                        return
                    try:
                        data = self._wire_fields(entries)
                    except ValueError:
                        self._send_wire_error(1005, "请求格式错误")
                        return
                    self._session(data, True)
                else:
                    self._session(self._parse_json(body), False)
            elif route == "/api/activate":
                if not self.ctx.allow_activate(peer_ip):
                    if is_wire:
                        self._send_wire_error(1005, "请求过于频繁，请稍后再试")
                    else:
                        self._send_json({"code": 1005, "msg": "请求过于频繁，请稍后再试"}, 429)
                    return
                if is_wire:
                    entries = self._parse_wire_request(body)
                    if entries is None:
                        self._send_wire_error(1005, "请求格式错误")
                        return
                    try:
                        data = self._wire_fields(entries)
                    except ValueError:
                        self._send_wire_error(1005, "请求格式错误")
                        return
                    self._activate(data, True)
                else:
                    self._activate(self._parse_json(body), False)
            elif route == "/api/heartbeat":
                if not self.ctx.allow_heartbeat(peer_ip):
                    if is_wire:
                        self._send_wire_error(1005, "请求过于频繁，请稍后再试")
                    else:
                        self._send_json({"code": 1005, "msg": "请求过于频繁，请稍后再试"}, 429)
                    return
                if is_wire:
                    entries = self._parse_wire_request(body)
                    if entries is None:
                        self._send_wire_error(1005, "请求格式错误")
                        return
                    try:
                        data = self._wire_fields(entries)
                    except ValueError:
                        self._send_wire_error(1005, "请求格式错误")
                        return
                    self._heartbeat(data, True)
                else:
                    self._heartbeat(self._parse_json(body), False)
            elif route == "/api/log":
                if not self.ctx.allow_log(peer_ip):
                    if is_wire:
                        self._send_wire_error(1005, "请求过于频繁，请稍后再试")
                    else:
                        self._send_json({"code": 1005, "msg": "请求过于频繁，请稍后再试"}, 429)
                    return
                if is_wire:
                    entries = self._parse_wire_request(body)
                    if entries is None:
                        self._send_wire_error(1005, "请求格式错误")
                        return
                    try:
                        data = self._wire_fields(entries)
                    except ValueError:
                        self._send_wire_error(1005, "请求格式错误")
                        return
                    self._log(data, True)
                else:
                    self._log(self._parse_json(body), False)
            # -- Web Admin Console APIs --
            elif route == "/admin/api/login":
                if not self.ctx.allow_login(peer_ip):
                    self._send_json({"code": 1005, "msg": "登录尝试过于频繁，请1分钟后再试"}, 429)
                    return
                self._web_login(self._parse_json(body))
            elif route == "/admin/api/logout":
                self._web_logout()
            elif route == "/admin/api/dashboard":
                self._admin_guard(self._web_dashboard, self._parse_json(body))
            elif route == "/admin/api/logs":
                self._admin_guard(self._admin_logs, self._parse_json(body))
            elif route == "/admin/api/card_action":
                self._admin_guard(self._web_card_action, self._parse_json(body))
            elif route == "/admin/api/gencard":
                self._admin_guard(self._admin_gencard, self._parse_json(body))
            elif route == "/admin/api/importcards":
                self._admin_guard(self._admin_importcards, self._parse_json(body))
            elif route == "/admin/api/update_auth":
                self._admin_guard(self._web_update_auth, self._parse_json(body))
            # -- CLI / Bearer Admin APIs --
            #
            # 这里**故意没有** /api/admin/rebind：一张卡密一旦绑定设备就不再提供
            # 任何"解绑/换绑"入口。要让某台设备脱离卡密，只能 revoke（终态）后
            # 重新发卡 —— 这是产品决定，不是省事留下的缺口。
            elif route == "/api/admin/gencard":
                self._admin_guard(self._admin_gencard, self._parse_json(body))
            elif route == "/api/admin/importcards":
                self._admin_guard(self._admin_importcards, self._parse_json(body))
            elif route == "/api/admin/list":
                self._admin_guard(self._admin_list, self._parse_json(body))
            elif route == "/api/admin/disable":
                self._admin_guard(self._admin_disable, self._parse_json(body))
            elif route == "/api/admin/enable":
                self._admin_guard(self._admin_enable, self._parse_json(body))
            elif route == "/api/admin/revoke":
                self._admin_guard(self._admin_revoke, self._parse_json(body))
            else:
                if is_wire:
                    self._send_wire(1005, [(TAG_MSG, "未知接口".encode("utf-8"))], status=404)
                else:
                    self._send_json({"code": 1005, "msg": "未知接口"}, 404)
        except Exception as exc:
            sys.stderr.write(f"request failed: {exc!r}\n")
            try:
                if is_wire:
                    self._send_wire(1005, [(TAG_MSG, b"internal error")], status=500)
                else:
                    self._send_json({"code": 1005, "msg": "internal error"}, 500)
            except Exception:
                pass
            return

    def _admin_guard(self, handler, data: dict | None) -> None:
        if not self._check_admin():
            self._send_json({"code": 403, "msg": "未登录或无权限"}, 403)
            return
        if not self.ctx.allow_admin(client_ip(self.headers, self.client_address[0])):
            self._send_json({"code": 1005, "msg": "请求过于频繁，请稍后再试"}, 429)
            return
        if data is None:
            self._send_error(1005, "参数错误")
            return
        handler(data)

    # -- Web Console handlers -----------------------------------------------

    def _web_login(self, data: dict | None) -> None:
        if not data:
            self._send_error(1005, "参数错误")
            return
        u = str(data.get("username") or "").strip()
        p = str(data.get("password") or "")
        if not self.ctx.verify_web_login(u, p):
            self._send_error(1001, "账号或密码错误")
            return
        sid = self.ctx.store.create_session(u)
        cookie = f"{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800"
        self._send_ok({"code": 0, "msg": "ok"}, extra_headers=[("Set-Cookie", cookie)])

    def _web_logout(self) -> None:
        sid = self._get_session_cookie()
        if sid:
            self.ctx.store.delete_session(sid)
        cookie = f"{SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0"
        self._send_ok({"code": 0, "msg": "ok"}, extra_headers=[("Set-Cookie", cookie)])

    def _web_dashboard(self, data: dict) -> None:
        batch = str(data.get("batch") or "").strip() or None
        state = str(data.get("state") or "").strip() or None
        keyword = str(data.get("keyword") or "").strip() or None
        cards = [public_card(c) for c in self.ctx.store.list_cards(
            batch=batch, state=state, keyword=keyword
        )]
        stats = self.ctx.store.get_stats()
        sys_info = {
            "payload_bytes": len(self.ctx.payload_glp) if self.ctx.payload_glp else 0,
            # 管理密钥本身不回给前端：dashboard 的响应会经过浏览器、代理、
            # 会话录屏，明文就等于多一份副本。要核对时看指纹即可。
            "admin_key_fp": sha256(self.ctx.admin_key).hex()[:16],
            "master_key_fp": sha256(self.ctx.master_key).hex()[:16],
            # 固定值：本服务不提供换绑，前端据此隐藏入口（不是开关）
            "device_rebind_supported": DEVICE_REBIND_SUPPORTED,
            "pubkey_policy": str(self.ctx.cfg.get("pubkey_policy", "rotate")),
        }
        security = self.ctx.store.security_stats()
        self._send_ok({
            "code": 0, "stats": stats, "cards": cards, "sys": sys_info,
            "security": security,
        })

    def _web_card_action(self, data: dict) -> None:
        action = str(data.get("action") or "").strip()
        ch = str(data.get("card_hash") or "").strip().lower()
        if len(ch) != 64:
            self._send_error(1005, "card_hash 非法")
            return
        if action == "disable":
            self.ctx.store.disable_card(ch)
        elif action == "enable":
            self.ctx.store.enable_card(ch)
        # 没有 unbind：卡密一旦绑定设备就不能解除，只有 revoke（终态）/delete。
        elif action == "revoke":
            self.ctx.store.revoke_card(ch)
        elif action == "delete":
            self.ctx.store.delete_card(ch)
        else:
            self._send_error(1005, "未知操作")
            return
        self._send_ok({"code": 0, "msg": "ok"})

    def _web_update_auth(self, data: dict) -> None:
        nu = str(data.get("new_user") or "").strip() or None
        np = str(data.get("new_pass") or "") or None
        if not nu and not np:
            self._send_error(1005, "账号或密码至少填写一项")
            return
        self.ctx.update_web_auth(nu, np)
        self._send_ok({"code": 0, "msg": "ok"})

    # -- Client licensing endpoints -----------------------------------------

    def _activate(self, data: dict | None, wire: bool) -> None:
        # 诊断：拒绝时把「请求形态」写进日志（不落卡密明文，只看字节长度 / 是否纯 ASCII /
        # 哈希前缀），用来区分「卡密串被输入法改坏」与「设备参数畸形」。
        diag_ip = client_ip(self.headers, self.client_address[0])
        if data is None:
            self.log_message("activate REJECT unparsable-body ip=%s", diag_ip)
            self._fail(1005, "参数错误", wire)
            return
        card = normalize_card_key(data.get("card") or "")
        device_fp_hex = data.get("device_fp")
        pubkey_hex = data.get("pubkey")
        if not card:
            self.log_message("activate REJECT empty-card ip=%s", diag_ip)
            self._fail(1005, "参数错误", wire)
            return
        try:
            device_fp = bytes.fromhex(device_fp_hex or "")
            pubkey = bytes.fromhex(pubkey_hex or "")
        except (TypeError, ValueError):
            self.log_message(
                "activate REJECT bad-hex card_len=%d card_ascii=%s fp_chars=%d pk_chars=%d ip=%s",
                len(card.encode("utf-8")), card.isascii(),
                len(str(device_fp_hex or "")), len(str(pubkey_hex or "")), diag_ip,
            )
            self._fail(1005, "参数错误", wire)
            return
        if len(device_fp) != 32:
            self.log_message(
                "activate REJECT bad-fp bytes=%d card_len=%d ip=%s",
                len(device_fp), len(card.encode("utf-8")), diag_ip,
            )
            self._fail(1005, "参数错误", wire)
            return
        if len(pubkey) != 65 or pubkey[0] != 0x04:
            self.log_message(
                "activate REJECT bad-pubkey bytes=%d first=0x%02x ip=%s",
                len(pubkey), (pubkey[0] if pubkey else 0), diag_ip,
            )
            self._fail(1005, "参数错误", wire)
            return

        card_hash_value = card_hash(card)
        local = self.ctx.store.get_card(card_hash_value)
        if local is None:
            # 库里查不到这张卡。正常卡密是 23 个 ASCII 字符（4 组 5 位 + 3 个横杠）；
            # 长度不对或含非 ASCII 就说明输入被输入法/剪贴板改坏了（全角字符等）。
            self.log_message(
                "activate REJECT card-not-found hash=%s card_len=%d ascii=%s head=%s ip=%s",
                card_hash_value[:16], len(card.encode("utf-8")), card.isascii(),
                card[:5], diag_ip,
            )
            self._fail(1001, "卡密无效", wire)
            return
        if local.get("state") in ("disabled", "revoked"):
            self._fail(1001, "卡密已失效", wire)
            return
        expire = int(local.get("expire") or 0)
        if expire != 0 and expire <= int(time.time()):
            self._fail(1003, "卡密已过期", wire)
            return
        # 「是不是同一台设备、能不能换绑」全部交给 store.claim_card_verbose 判定：
        # 它把「device_fp 相同但公钥变了」当成同机重装/清数据放行，把
        # 「device_fp 不同」判成别人的设备。这里不再提前拒绝 —— 否则这类请求
        # 既不会落审计，也拿不到 1004/1002 的区分信息。
        if self.ctx.payload_glp is None:
            self._fail(1005, "服务暂不可用", wire)
            return

        kd = hkdf_sha256(self.ctx.master_key, sha256(card), device_fp, 32)

        # 绑定 / 换绑。
        #
        # device_fp 是设备级 Widevine ID（跨卸载重装、清数据、恢复出厂不变），
        # 而公钥来自 AndroidKeystore，是「本次安装」级别的：清掉 App 数据后旧私钥
        # 随条目一起消失，下一次激活必然是新公钥。所以「同一个 device_fp」就是
        # 同一台设备，允许它换公钥并把 Kd 封给**本次请求的公钥**，用户输入原来那张
        # 卡就能拿回同一把 Kd、照常解开载荷。
        #
        # device_fp 不同 = 别人的设备，仍然一机一码（1002）。
        # 换绑受 pubkey_policy / pubkey_max_rotations / pubkey_rotation_cooldown
        # 三个配置约束，每次绑定与换绑都写 activation_audit。
        peer_ip = client_ip(self.headers, self.client_address[0])
        claim = self.ctx.store.claim_card_verbose(
            card_hash_value,
            device_fp_hex,
            expire,
            pubkey_hex=pubkey.hex(),
            client_ip=peer_ip,
            user_agent=self.headers.get("User-Agent"),
            policy=str(self.ctx.cfg.get("pubkey_policy", "rotate")),
            max_rotations=int(self.ctx.cfg.get("pubkey_max_rotations", 0) or 0),
            cooldown_seconds=int(self.ctx.cfg.get("pubkey_rotation_cooldown", 0) or 0),
        )
        if not claim["claimed"]:
            reason = claim.get("reason")
            if reason in ("max_rotations", "cooldown"):
                self._fail(1002, "该卡密换绑次数已达上限，请联系客服", wire)
            else:
                self._fail(1002, "卡密已绑定其它设备", wire)
            return
        if claim.get("rotated"):
            self.log_message(
                "device key rotated card=%s device=%s rotations=%s",
                card_hash_value[:12],
                (device_fp_hex or "")[:12],
                claim.get("rotations"),
            )
            # 同一台设备重装后换公钥是正常的；换公钥**同时换了来源 IP**才是可疑信号
            # （一张被别人拿到卡密 + 指纹的卡，通常从另一个网络被抢注）。
            prev_ip = claim.get("last_ip")
            if prev_ip and prev_ip != peer_ip:
                self.log_message(
                    "SECURITY new-ip rekey card=%s device=%s prev_ip=%s ip=%s",
                    card_hash_value[:12],
                    (device_fp_hex or "")[:12],
                    prev_ip,
                    peer_ip,
                )
        # 测试卡的计时在**首次绑定**那一刻才开始（claim_card_verbose 写的），
        # 所以容器头与响应都必须用绑定后的生效到期时间，而不是绑之前的 0。
        expire = int(claim.get("expire") or expire)
        try:
            blob = build_glt2_from_glp(self.ctx.payload_glp, device_fp, card, kd, expire)
            wrapped = ecies_wrap(pubkey, kd, card)
        except Exception:
            self._fail(1005, "服务暂不可用", wire)
            return
        token = self.ctx.store.create_token(card_hash_value, device_fp_hex)
        if wire:
            self._send_wire_ok(
                [
                    (TAG_TOKEN_RESP, token.encode("utf-8")),
                    (TAG_EXPIRE, struct.pack("<Q", expire)),
                    (TAG_BLOB, blob),
                    (TAG_WRAPPED, wrapped),
                    (TAG_MSG, b"ok"),
                ]
            )
        else:
            self._send_ok(
                {
                    "code": 0,
                    "msg": "ok",
                    "token": token,
                    "expire": expire,
                    "blob": blob.hex(),
                    "wrapped": wrapped.hex(),
                }
            )

    def _heartbeat(self, data: dict | None, wire: bool) -> None:
        if data is None:
            self._fail(1005, "参数错误", wire)
            return
        token = data.get("token")
        if not isinstance(token, str) or not token:
            self._fail(1005, "缺少 token", wire)
            return
        row = self.ctx.store.lookup_token(token)
        if not row:
            self._fail(1002, "授权已失效", wire)
            return
        expires_at = int(row.get("expires_at", 0) or 0)
        if expires_at and expires_at <= int(time.time()):
            self._fail(1002, "授权已失效", wire)
            return
        expire = int(row.get("card_expire", 0) or 0)
        card_exists = int(row.get("card_exists", 0) or 0)
        card_state = row.get("card_state")
        state = 1 if (card_exists and card_state not in ("disabled", "revoked", None)) else 0
        if wire:
            self._send_wire_ok(
                [
                    (TAG_EXPIRE, struct.pack("<Q", expire)),
                    (TAG_STATE, struct.pack("<B", state)),
                ]
            )
        else:
            self._send_ok({"code": 0, "expire": expire, "state": state})

    # -- 设备运行日志：token 认证，24 小时保留 ------------------------------
    #
    # 只认 token，不认卡密：日志上传是高频动作，反复把卡密带上线路没有意义。
    # token 在激活时签发，服务端据此反查 card_hash / device_fp，所以一张卡的
    # 日志天然绑死在**那台机器**上；卡被禁用/吊销后上传同样返回 1001。
    def _log(self, data: dict | None, wire: bool) -> None:
        if data is None:
            self._fail(1005, "参数错误", wire)
            return
        token = data.get("token")
        if not isinstance(token, str) or not token.strip():
            self._fail(1005, "缺少 token", wire)
            return
        text = data.get("log")
        if text is None and isinstance(data.get("lines"), list):
            text = "\n".join(str(x) for x in data["lines"])
        if not isinstance(text, str) or not text.strip():
            self._fail(1005, "日志为空", wire)
            return

        row = self.ctx.store.lookup_token(token.strip())
        if not row:
            self._fail(1002, "授权已失效", wire)
            return
        expires_at = int(row.get("expires_at", 0) or 0)
        if expires_at and expires_at <= int(time.time()):
            self._fail(1002, "授权已失效", wire)
            return
        card_state = row.get("card_state")
        if not int(row.get("card_exists", 0) or 0) or card_state in ("disabled", "revoked", None):
            self._fail(1001, "卡密已失效", wire)
            return

        stored = self.ctx.store.append_logs(
            row["card_hash"], row.get("device_fp"), text.split("\n")
        )
        self.log_message(
            "log upload card=%s chars=%d nul=%d lines=%d stored=%d",
            row["card_hash"][:8], len(text), text.count("\x00"),
            len(text.split("\n")), stored,
        )
        if stored == 0:
            # 只有空白/NUL 的批次没有任何诊断价值，明确拒绝而不是回 ok。
            self._fail(1005, "日志为空", wire)
            return
        if wire:
            self._send_wire_ok([(TAG_MSG, b"ok")])
        else:
            self._send_ok({"code": 0, "stored": stored})

    # -- 会话式取密钥：每次启动/每次运行都要问服务端，Kd 从不落盘 -------------
    #
    # 与 activate 的区别：activate 是绑定（写库、发 token）；session 是"租借"——
    # 校验卡密与设备指纹，但**不写任何状态**，也**不发 token**。后台删卡/封卡
    # 立刻生效：下一次 session 直接 1001。离线 = 用不了，这是刻意的。
    def _session(self, data: dict | None, wire: bool) -> None:
        diag_ip = client_ip(self.headers, self.client_address[0])
        if data is None:
            self.log_message("session REJECT unparsable-body ip=%s", diag_ip)
            self._fail(1005, "参数错误", wire)
            return
        card = normalize_card_key(data.get("card") or "")
        device_fp_hex = data.get("device_fp")
        pubkey_hex = data.get("pubkey")
        if not card:
            self.log_message("session REJECT empty-card ip=%s", diag_ip)
            self._fail(1005, "参数错误", wire)
            return
        try:
            device_fp = bytes.fromhex(device_fp_hex or "")
            pubkey = bytes.fromhex(pubkey_hex or "")
        except (TypeError, ValueError):
            self.log_message(
                "session REJECT bad-hex card_len=%d card_ascii=%s ip=%s",
                len(card.encode("utf-8")), card.isascii(), diag_ip,
            )
            self._fail(1005, "参数错误", wire)
            return
        if len(device_fp) != 32 or len(pubkey) != 65 or pubkey[0] != 0x04:
            self.log_message(
                "session REJECT bad-params fp=%d pk=%d ip=%s",
                len(device_fp), len(pubkey), diag_ip,
            )
            self._fail(1005, "参数错误", wire)
            return

        card_hash_value = card_hash(card)
        local = self.ctx.store.get_card(card_hash_value)
        if local is None:
            self.log_message(
                "session REJECT card-not-found hash=%s card_len=%d ascii=%s head=%s ip=%s",
                card_hash_value[:16], len(card.encode("utf-8")), card.isascii(),
                card[:5], diag_ip,
            )
            self._fail(1001, "卡密无效", wire)
            return
        if local.get("state") in ("disabled", "revoked"):
            self._fail(1001, "卡密已失效", wire)
            return
        expire = int(local.get("expire") or 0)
        if expire != 0 and expire <= int(time.time()):
            self._fail(1003, "卡密已过期", wire)
            return
        # 必须已经绑定到这台设备（activate 做过的）；没绑过先去 activate。
        if not local.get("device_fp"):
            self._fail(1002, "卡密尚未激活", wire)
            return
        if local["device_fp"] != device_fp_hex.lower():
            self._fail(1002, "卡密已绑定其它设备", wire)
            return
        # 换了公钥（重装/清数据）在 session 里是允许的：Kd 永远封给"本次请求的公钥"，
        # 所以每次取都是新封包，设备上不需要留任何旧密钥。
        if self.ctx.payload_glp is None:
            self._fail(1005, "服务暂不可用", wire)
            return
        kd = hkdf_sha256(self.ctx.master_key, sha256(card), device_fp, 32)
        try:
            blob = build_glt2_from_glp(self.ctx.payload_glp, device_fp, card, kd, expire)
            wrapped = ecies_wrap(pubkey, kd, card)
        except Exception:
            self._fail(1005, "服务暂不可用", wire)
            return
        if wire:
            self._send_wire_ok(
                [
                    (TAG_EXPIRE, struct.pack("<Q", expire)),
                    (TAG_BLOB, blob),
                    (TAG_WRAPPED, wrapped),
                    (TAG_MSG, b"ok"),
                ]
            )
        else:
            self._send_ok(
                {
                    "code": 0,
                    "expire": expire,
                    "blob": blob.hex(),
                    "wrapped": wrapped.hex(),
                }
            )

    # -- CLI / JSON admin handlers ------------------------------------------

    # 没有 _admin_rebind：绑定不可解除，见 do_POST 里的说明。

    @staticmethod
    def _card_type_duration(data: dict) -> int | None:
        """把管理端传来的卡密类型翻成时长（秒）。None = 参数非法。

        只保留两种类型：
          test      → 3600 秒（1 小时），**首次绑定那台机器时**才开始计时；
          permanent → 0（永不过期）。

        `days` 是历史参数，仅为兼容旧脚本保留：days>0 走绝对到期（legacy）。
        """
        raw_type = str(data.get("type") or "").strip().lower()
        if raw_type in ("test", "trial", "测试", "测试卡"):
            return TEST_CARD_DURATION
        if raw_type in ("permanent", "forever", "perm", "永久", "永久卡"):
            return 0
        if raw_type:
            return None
        # 没给 type：默认永久卡；带了 days 的旧调用按绝对到期处理。
        return 0

    def _admin_gencard(self, data: dict) -> None:
        try:
            count = int(data.get("count", 1))
            days = int(data.get("days", 0) or 0)
        except (TypeError, ValueError):
            self._send_error(1005, "count/days 必须是整数")
            return
        if count < 1 or count > 10000:
            self._send_error(1005, "count 超出范围")
            return
        if days < 0:
            self._send_error(1005, "days 不能为负")
            return
        duration = self._card_type_duration(data)
        if duration is None:
            self._send_error(1005, "type 只能是 test 或 permanent")
            return
        batch = str(data.get("batch") or "").strip() or None
        note = str(data.get("note") or "").strip() or None
        cards = self.ctx.store.gen_cards(
            count, days, batch=batch, note=note, duration_sec=duration
        )
        self._send_ok({"code": 0, "cards": cards, "type": "test" if duration else "permanent"})

    def _admin_importcards(self, data: dict) -> None:
        keys = data.get("cards")
        if not isinstance(keys, list) or not keys:
            self._send_error(1005, "cards 必须是非空数组")
            return
        try:
            days = int(data.get("days", 0) or 0)
        except (TypeError, ValueError):
            self._send_error(1005, "days 必须是整数")
            return
        if days < 0:
            self._send_error(1005, "days 不能为负")
            return
        duration = self._card_type_duration(data)
        if duration is None:
            self._send_error(1005, "type 只能是 test 或 permanent")
            return
        batch = str(data.get("batch") or "").strip() or None
        note = str(data.get("note") or "").strip() or None
        inserted = self.ctx.store.import_cards(
            [str(k) for k in keys], days=days, batch=batch, note=note,
            duration_sec=duration,
        )
        self._send_ok({"code": 0, "inserted": inserted, "total": len(keys)})

    def _admin_list(self, data: dict) -> None:
        batch = str(data.get("batch") or "").strip() or None
        self._send_ok({
            "code": 0,
            "cards": [public_card(c) for c in self.ctx.store.list_cards(batch=batch)],
        })

    def _admin_logs(self, data: dict) -> None:
        """Return a card's device logs (last 24 h) for the Web console."""
        card_value = normalize_card_key(data.get("card") or "") if data.get("card") else ""
        card_hash_value = card_hash(card_value) if card_value else str(
            data.get("card_hash") or ""
        ).strip().lower()
        if not card_hash_value:
            self._send_error(1005, "缺少卡密或 card_hash")
            return
        try:
            limit = int(data.get("limit") or 400)
        except (TypeError, ValueError):
            limit = 400
        try:
            after_id = int(data.get("after_id") or 0)
        except (TypeError, ValueError):
            after_id = 0
        row = self.ctx.store.get_card(card_hash_value)
        if row is None:
            self._send_error(1001, "卡密不存在")
            return
        lines = self.ctx.store.list_logs(card_hash_value, limit=limit, after_id=after_id)
        self._send_ok({
            "code": 0,
            "card_hash": card_hash_value,
            "card_preview": row.get("card_preview"),
            "device_fp": row.get("device_fp"),
            "lines": lines,
            "total": self.ctx.store.count_logs(card_hash_value),
            "retention_sec": LOG_RETENTION_SEC,
        })

    def _admin_disable(self, data: dict) -> None:
        card = normalize_card_key(data.get("card") or "")
        if not card:
            self._send_error(1005, "缺少卡密")
            return
        row = self.ctx.store.disable_card(card_hash(card))
        self._send_ok({"code": 0, "msg": "ok", "state": row.get("state") if row else None})

    def _admin_enable(self, data: dict) -> None:
        card = normalize_card_key(data.get("card") or "")
        if not card:
            self._send_error(1005, "缺少卡密")
            return
        row = self.ctx.store.enable_card(card_hash(card))
        self._send_ok({"code": 0, "msg": "ok", "state": row.get("state") if row else None})

    def _admin_revoke(self, data: dict) -> None:
        card = normalize_card_key(data.get("card") or "")
        if not card:
            self._send_error(1005, "缺少卡密")
            return
        row = self.ctx.store.revoke_card(card_hash(card))
        self._send_ok({"code": 0, "msg": "ok", "state": row.get("state") if row else None})

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    cfg_path = args[0] if args else None
    cfg = load_config(cfg_path)
    ctx = LicensingContext(cfg)
    host = str(cfg.get("listen_host", "0.0.0.0"))
    port = int(cfg.get("listen_port", 8787))
    server = ThreadingHTTPServer((host, port), _Handler)
    server.context = ctx  # type: ignore[attr-defined]
    print(f"GhostLock license server + Web Console listening on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())