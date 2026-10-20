"""Command-line administration for the XproSU licensing service.

Reads the same config.json as server.py.
    python admin.py gen --days 365 --count 10 [--batch 2026Q1] [--note VIP]
    python admin.py list [--batch 2026Q1]
    python admin.py import --file cards.txt --days 365 [--batch X]
    python admin.py disable --card XXXXX-XXXXX-XXXXX-XXXXX
    python admin.py enable  --card XXXXX-XXXXX-XXXXX-XXXXX
    python admin.py revoke  --card XXXXX-XXXXX-XXXXX-XXXXX
    python admin.py delete  --card XXXXX-XXXXX-XXXXX-XXXXX
    python admin.py logs    --card XXXXX-XXXXX-XXXXX-XXXXX [--limit 400]
    python admin.py build-payload --table <json path>
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from payload import build_payload
from server import load_config, resolve_path
from store import CardStore, card_hash, normalize_card_key

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _resolve_card_hash(raw: str) -> str:
    s = raw.strip()
    if len(s) == 64:
        try:
            bytes.fromhex(s)
            return s.lower()
        except ValueError:
            pass
    return card_hash(normalize_card_key(s))


def _store(cfg: dict) -> CardStore:
    return CardStore(resolve_path(cfg, "db_path") or os.path.join(BASE_DIR, "cards.db"))


def _duration_for(card_type: str) -> int | None:
    """卡密类型 → 时长（秒）。只有两种：测试卡 1 小时 / 永久卡。"""
    t = (card_type or "permanent").strip().lower()
    if t in ("test", "trial", "测试", "测试卡"):
        return 3600
    if t in ("permanent", "forever", "perm", "永久", "永久卡"):
        return 0
    return None


def cmd_gen(cfg: dict, args) -> int:
    duration = _duration_for(args.type)
    if duration is None:
        print("error: --type 只能是 test 或 permanent", file=sys.stderr)
        return 2
    cards = _store(cfg).gen_cards(
        args.count, 0, batch=args.batch, note=args.note, duration_sec=duration
    )
    for c in cards:
        print(c)
    kind = "测试卡(1小时)" if duration else "永久卡"
    print(f"generated {len(cards)} card(s), type={kind}, batch={args.batch or '-'}")
    if duration:
        print("提示：测试卡的 1 小时从**首次绑定机器**开始算；未激活不过期。")
    return 0


def cmd_list(cfg: dict, args) -> int:
    cards = _store(cfg).list_cards(batch=args.batch)
    if not cards:
        print("(no cards)")
        return 0
    for c in cards:
        dur = int(c.get("duration_sec") or 0)
        exp = int(c["expire"] or 0)
        if dur > 0:
            kind = "测试卡" if exp else "测试卡(未激活)"
        elif exp > 0:
            kind = "限时(历史)"
        else:
            kind = "永久卡"
        exp_s = exp if exp else "-"
        print(
            f"{c.get('card_preview') or '-' :23s}  {c['card_hash'][:16]}  "
            f"{kind:14s}  fp={c['device_fp'] or '-'}  expire={exp_s}  "
            f"state={c['state']}  batch={c.get('batch') or '-'}"
        )
    return 0


def cmd_import(cfg: dict, args) -> int:
    with open(args.file, "r", encoding="utf-8") as fh:
        keys = [line.strip() for line in fh if line.strip()]
    if not keys:
        print("error: no cards in file", file=sys.stderr)
        return 2
    duration = _duration_for(args.type)
    if duration is None:
        print("error: --type 只能是 test 或 permanent", file=sys.stderr)
        return 2
    inserted = _store(cfg).import_cards(
        keys, 0, batch=args.batch, note=args.note, duration_sec=duration
    )
    kind = "测试卡(1小时)" if duration else "永久卡"
    print(f"imported {inserted}/{len(keys)} card(s), type={kind}, batch={args.batch or '-'}")
    return 0


# 没有 rebind 子命令：绑定不可解除（见 store.py 的说明）。
# 要让设备脱离卡密：先 revoke（终态），再 gen 一张新卡。


def _lifecycle(cfg: dict, args, action: str) -> int:
    ch = _resolve_card_hash(args.card)
    store = _store(cfg)
    if action == "delete":
        ok = store.delete_card(ch)
        print(f"deleted={ok} card_hash={ch}")
        return 0 if ok else 2
    fn = {
        "disable": store.disable_card,
        "enable": store.enable_card,
        "revoke": store.revoke_card,
    }[action]
    row = fn(ch)
    if row is None:
        print(f"error: card not found: {args.card}", file=sys.stderr)
        return 2
    print(f"card_hash={row['card_hash']} state={row['state']}")
    return 0


def cmd_disable(cfg: dict, args) -> int:
    return _lifecycle(cfg, args, "disable")


def cmd_enable(cfg: dict, args) -> int:
    return _lifecycle(cfg, args, "enable")


def cmd_revoke(cfg: dict, args) -> int:
    return _lifecycle(cfg, args, "revoke")


def cmd_delete(cfg: dict, args) -> int:
    return _lifecycle(cfg, args, "delete")


def cmd_encrypt_payload(cfg: dict, args) -> int:
    key_hex = os.environ.get("GL_PAYLOAD_KEY", "")
    if not key_hex:
        print("error: GL_PAYLOAD_KEY must be set (64 hex chars)", file=sys.stderr)
        return 2
    key = bytes.fromhex(key_hex)
    if len(key) != 32:
        print("error: GL_PAYLOAD_KEY must be 64 hex chars (32 bytes)", file=sys.stderr)
        return 2
    src = args.input or (resolve_path(cfg, "payload_path") or os.path.join(BASE_DIR, "payload.bin"))
    dst = args.output or (src + ".enc")
    with open(src, "rb") as fh:
        glp = fh.read()
    from crypto import chacha20_poly1305_encrypt
    aad = b"GLPE" + bytes([1, 0])
    nonce = os.urandom(12)
    ct, tag = chacha20_poly1305_encrypt(key, nonce, aad, glp)
    blob = aad + nonce + ct + tag
    with open(dst, "wb") as fh:
        fh.write(blob)
    os.chmod(dst, 0o600)
    print(f"wrote {dst} ({len(blob)} bytes); remove plaintext {src} on the server")
    return 0


def cmd_build_payload(cfg: dict, args) -> int:
    with open(args.table, "r", encoding="utf-8") as fh:
        table = json.load(fh)
    if not isinstance(table, dict):
        print("error: payload table must be a JSON object", file=sys.stderr)
        return 2
    path = resolve_path(cfg, "payload_path") or os.path.join(BASE_DIR, "payload.bin")
    data = build_payload(table, path)
    print(f"wrote {path} ({len(data)} bytes, {len(table)} release(s))")
    return 0


def cmd_logs(cfg: dict, args) -> int:
    ch = _resolve_card_hash(args.card)
    store = _store(cfg)
    rows = store.list_logs(ch, limit=args.limit)
    total = store.count_logs(ch)
    if not rows:
        print(f"(no logs in the last 24h) card_hash={ch}")
        return 0
    for row in rows:
        stamp = time.strftime("%m-%d %H:%M:%S", time.localtime(int(row["ts"])))
        print(f"{stamp}  {row['line']}")
    print(f"--- {len(rows)} line(s) shown, {total} kept (24h), card_hash={ch}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="admin.py", description="XproSU license admin tool")
    parser.add_argument("--config", default=os.path.join(BASE_DIR, "config.json"), help="config.json path")
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("gen", help="generate card keys")
    p_gen.add_argument("--type", default="permanent", choices=["test", "permanent"],
                       help="test = 测试卡(1小时，首次绑定开始计时) / permanent = 永久卡")
    p_gen.add_argument("--count", type=int, default=10)
    p_gen.add_argument("--batch", default=None)
    p_gen.add_argument("--note", default=None)
    p_gen.set_defaults(func=cmd_gen)

    p_list = sub.add_parser("list", help="list cards")
    p_list.add_argument("--batch", default=None)
    p_list.set_defaults(func=cmd_list)

    p_imp = sub.add_parser("import", help="import externally-issued card keys (one per line)")
    p_imp.add_argument("--file", required=True)
    p_imp.add_argument("--type", default="permanent", choices=["test", "permanent"],
                       help="test = 测试卡(1小时，首次绑定开始计时) / permanent = 永久卡")
    p_imp.add_argument("--batch", default=None)
    p_imp.add_argument("--note", default=None)
    p_imp.set_defaults(func=cmd_import)

    for name, fn, help_text in (
        ("disable", cmd_disable, "disable a card (recoverable; kicks the device offline)"),
        ("enable", cmd_enable, "re-enable a disabled card"),
        ("revoke", cmd_revoke, "revoke a card (terminal; the handset can no longer activate)"),
        ("delete", cmd_delete, "delete a card row and its tokens"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--card", required=True, help="card plaintext OR 64-hex card_hash")
        p.set_defaults(func=fn)

    p_logs = sub.add_parser("logs", help="show a card's device logs (last 24 h)")
    p_logs.add_argument("--card", required=True, help="card plaintext OR 64-hex card_hash")
    p_logs.add_argument("--limit", type=int, default=400)
    p_logs.set_defaults(func=cmd_logs)

    p_enc = sub.add_parser("encrypt-payload", help="wrap payload.bin into encrypted-at-rest payload.bin.enc")
    p_enc.add_argument("--input", default=None)
    p_enc.add_argument("--output", default=None)
    p_enc.set_defaults(func=cmd_encrypt_payload)

    p_build = sub.add_parser("build-payload", help="build payload.bin from a plaintext JSON table")
    p_build.add_argument("--table", required=True)
    p_build.set_defaults(func=cmd_build_payload)

    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    cfg = load_config(args.config)
    return args.func(cfg, args)


if __name__ == "__main__":
    sys.exit(main())