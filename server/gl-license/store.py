"""SQLite card/token store for the GhostLock licensing service.

Standalone (no U验证 upstream).  Card keys are never stored: only
``card_hash = SHA-256(card_key).hex()`` is persisted.  Card plaintext format:
20 base32 chars (A-Z2-7), upper case, one dash after every 5 chars ->
``XXXXX-XXXXX-XXXXX-XXXXX``.

Lifecycle state machine:
    unbound --activate--> bound --disable--> disabled --enable--> bound
                            |
                            +--revoke--> revoked (terminal)

Disable / revoke / delete all cascade-delete the card's tokens so the handset is
kicked offline on its next heartbeat.  The binding itself is permanent: there is
no rebind/unbind path anywhere in the service (see the note above disable_card).
"""
from __future__ import annotations

import base64
import secrets
import sqlite3
import time
from crypto import sha256

CARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

_CARDS_DDL = """
CREATE TABLE IF NOT EXISTS cards (
    card_hash   TEXT PRIMARY KEY,
    card_preview TEXT,
    device_fp   TEXT,
    pubkey      TEXT,
    expire      INTEGER NOT NULL,
    state       TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    bound_at    INTEGER,
    revoked_at  INTEGER,
    disabled_at INTEGER,
    note        TEXT,
    batch       TEXT
);
"""

_TOKENS_DDL = """
CREATE TABLE IF NOT EXISTS tokens (
    token      TEXT PRIMARY KEY,
    card_hash  TEXT NOT NULL,
    device_fp  TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
"""

_ADMIN_SESSIONS_DDL = """
CREATE TABLE IF NOT EXISTS admin_sessions (
    session_id TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
"""

_AUDIT_DDL = """
CREATE TABLE IF NOT EXISTS activation_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    card_hash   TEXT NOT NULL,
    device_fp   TEXT,
    pubkey      TEXT,
    prev_pubkey TEXT,
    rotated     INTEGER NOT NULL DEFAULT 0,
    rotations   INTEGER NOT NULL DEFAULT 0,
    client_ip   TEXT,
    user_agent  TEXT,
    result      TEXT NOT NULL,
    detail      TEXT
);
"""

_AUDIT_INDEX_DDL = (
    "CREATE INDEX IF NOT EXISTS idx_activation_audit_card "
    "ON activation_audit(card_hash, ts);"
)

TOKEN_TTL = 30 * 86400
SESSION_TTL = 7 * 86400

STATE_UNBOUND = "unbound"
STATE_BOUND = "bound"
STATE_DISABLED = "disabled"
STATE_REVOKED = "revoked"
DEAD_STATES = (STATE_DISABLED, STATE_REVOKED)


def normalize_card_key(card: str) -> str:
    """Upper-case and strip surrounding whitespace; keep the internal dashes."""
    if not isinstance(card, str):
        raise ValueError("card must be a string")
    return card.strip().upper()


def card_hash(card_key: str) -> str:
    return sha256(normalize_card_key(card_key)).hex()


def _format_card(raw20: str) -> str:
    return "-".join(raw20[i : i + 5] for i in range(0, 20, 5))


def generate_card_key() -> str:
    raw = base64.b32encode(secrets.token_bytes(12)).decode("ascii").rstrip("=")
    return _format_card(raw)


class CardStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        with self._connect() as conn:
            conn.executescript(
                _CARDS_DDL + _TOKENS_DDL + _ADMIN_SESSIONS_DDL + _AUDIT_DDL + _AUDIT_INDEX_DDL
            )
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        card_cols = {row["name"] for row in conn.execute("PRAGMA table_info(cards)")}
        for col, decl in (
            ("pubkey", "TEXT"),
            ("card_preview", "TEXT"),
            ("revoked_at", "INTEGER"),
            ("disabled_at", "INTEGER"),
            ("note", "TEXT"),
            ("batch", "TEXT"),
            ("pubkey_rotations", "INTEGER"),
            ("prev_pubkey", "TEXT"),
            ("last_pubkey_at", "INTEGER"),
        ):
            if col not in card_cols:
                conn.execute(f"ALTER TABLE cards ADD COLUMN {col} {decl}")
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(tokens)")}
        if "expires_at" not in cols:
            conn.execute("ALTER TABLE tokens ADD COLUMN expires_at INTEGER")
            conn.execute(
                "UPDATE tokens SET expires_at = created_at + ? WHERE expires_at IS NULL",
                (TOKEN_TTL,),
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
        return dict(row) if row is not None else None

    def get_card(self, card_hash_value: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM cards WHERE card_hash = ?", (card_hash_value,)).fetchone()
        return self._row_to_dict(row)

    def claim_card(
        self, card_hash_value: str, device_fp: str, expire: int = 0,
        pubkey_hex: str | None = None,
    ) -> bool:
        """Compatibility wrapper; True when the card ended up bound to device_fp."""
        return self.claim_card_verbose(
            card_hash_value, device_fp, expire, pubkey_hex=pubkey_hex
        )["claimed"]

    def _audit(
        self, conn: sqlite3.Connection, card_hash_value: str, device_fp: str | None,
        pubkey: str | None, prev_pubkey: str | None, rotated: bool, rotations: int,
        client_ip: str | None, user_agent: str | None, result: str,
        detail: str | None = None,
    ) -> None:
        conn.execute(
            "INSERT INTO activation_audit "
            "(ts, card_hash, device_fp, pubkey, prev_pubkey, rotated, rotations, "
            " client_ip, user_agent, result, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                int(time.time()), card_hash_value, device_fp, pubkey, prev_pubkey,
                1 if rotated else 0, rotations, client_ip,
                (user_agent or "")[:200] or None, result, detail,
            ),
        )

    def claim_card_verbose(
        self,
        card_hash_value: str,
        device_fp: str,
        expire: int = 0,
        pubkey_hex: str | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
        policy: str = "rotate",
        max_rotations: int = 0,
        cooldown_seconds: int = 0,
    ) -> dict:
        """Bind / re-bind a card and report exactly what happened.

        device_fp is the device-level Widevine id: it survives uninstall,
        data wipe and factory reset, so a matching device_fp means "the same
        handset".  The Keystore key pair, by contrast, is per installation --
        wiping the app data destroys the old private key and the next
        activation presents a brand-new public key.  Sealing Kd to a pinned old
        public key would lock a paying user out of a handset they still own, so
        a matching device_fp is allowed to rotate the public key.

        A *different* device_fp is another handset and keeps the
        one-card-one-device rule: the guard stays folded into the UPDATE WHERE
        clause, so concurrent activations still leave exactly one winner.

        policy:
          "rotate" (default) - same device_fp may rotate the public key;
          "pin"              - previous behaviour, a changed key is refused.

        Returns {"claimed", "rotated", "prev_pubkey", "rotations", "reason"}
        and writes one activation_audit row per attempt.
        """
        now = int(time.time())
        new_pk = (pubkey_hex or "").strip().lower()
        result = {
            "claimed": False,
            "rotated": False,
            "prev_pubkey": None,
            "rotations": 0,
            "reason": None,
            "last_ip": None,
        }
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT state FROM cards WHERE card_hash = ?", (card_hash_value,)
            ).fetchone()
            if existing and existing["state"] in DEAD_STATES:
                result["reason"] = "dead"
                self._audit(
                    conn, card_hash_value, device_fp, new_pk, None, False, 0,
                    client_ip, user_agent, "rejected", "card is disabled/revoked",
                )
                return result
            conn.execute(
                "INSERT OR IGNORE INTO cards (card_hash, device_fp, pubkey, expire, state, created_at, bound_at) "
                "VALUES (?, NULL, NULL, ?, 'unbound', ?, NULL)",
                (card_hash_value, expire, now),
            )
            row = conn.execute(
                "SELECT device_fp, pubkey, pubkey_rotations, prev_pubkey, last_pubkey_at "
                "FROM cards WHERE card_hash = ?",
                (card_hash_value,),
            ).fetchone()
            last_ok = conn.execute(
                "SELECT client_ip FROM activation_audit WHERE card_hash = ? "
                "AND result != 'rejected' ORDER BY id DESC LIMIT 1",
                (card_hash_value,),
            ).fetchone()
            result["last_ip"] = (last_ok["client_ip"] if last_ok else None)
            stored_fp = ((row["device_fp"] or "") if row else "").lower()
            stored_pk = ((row["pubkey"] or "") if row else "").lower()
            prev_pk = (row["prev_pubkey"] if row else None) or None
            rotations = int((row["pubkey_rotations"] or 0) if row else 0)
            last_at = int((row["last_pubkey_at"] or 0) if row else 0)
            result["rotations"] = rotations
            result["prev_pubkey"] = stored_pk or None

            if stored_fp and stored_fp != device_fp.lower():
                result["reason"] = "other_device"
                self._audit(
                    conn, card_hash_value, device_fp, new_pk, stored_pk or None, False,
                    rotations, client_ip, user_agent, "rejected",
                    "device_fp differs from the bound handset",
                )
                return result

            rotated = bool(stored_pk) and stored_pk != new_pk
            if rotated and new_pk:
                if policy == "pin":
                    result["reason"] = "pubkey_pinned"
                    self._audit(
                        conn, card_hash_value, device_fp, new_pk, stored_pk, False,
                        rotations, client_ip, user_agent, "rejected",
                        "pubkey_policy=pin refuses a changed public key",
                    )
                    return result
                if max_rotations and rotations >= max_rotations:
                    result["reason"] = "max_rotations"
                    self._audit(
                        conn, card_hash_value, device_fp, new_pk, stored_pk, False,
                        rotations, client_ip, user_agent, "rejected",
                        "rotation cap reached: {}/{}".format(rotations, max_rotations),
                    )
                    return result
                if cooldown_seconds and last_at and (now - last_at) < cooldown_seconds:
                    result["reason"] = "cooldown"
                    self._audit(
                        conn, card_hash_value, device_fp, new_pk, stored_pk, False,
                        rotations, client_ip, user_agent, "rejected",
                        "rotation cooldown: {}s < {}s".format(now - last_at, cooldown_seconds),
                    )
                    return result

            cursor = conn.execute(
                "UPDATE cards SET device_fp = ?, pubkey = ?, "
                "pubkey_rotations = ?, prev_pubkey = ?, last_pubkey_at = ?, "
                "state = 'bound', bound_at = ?, expire = ? "
                "WHERE card_hash = ? AND (device_fp IS NULL OR device_fp = '' OR device_fp = ?) "
                "AND state NOT IN ('disabled', 'revoked')",
                (
                    device_fp,
                    new_pk or None,
                    rotations + (1 if rotated else 0),
                    (stored_pk or prev_pk) if rotated else prev_pk,
                    now if rotated else (last_at or None),
                    now,
                    expire,
                    card_hash_value,
                    device_fp,
                ),
            )
            if cursor.rowcount != 1:
                result["reason"] = "contended"
                self._audit(
                    conn, card_hash_value, device_fp, new_pk, stored_pk or None, False,
                    rotations, client_ip, user_agent, "rejected",
                    "concurrent claim lost the race",
                )
                return result

            result["claimed"] = True
            result["rotated"] = rotated
            result["rotations"] = rotations + (1 if rotated else 0)
            self._audit(
                conn, card_hash_value, device_fp, new_pk, stored_pk or None, rotated,
                result["rotations"], client_ip, user_agent,
                "rotated" if rotated else "bound",
                None if rotated else "same public key",
            )
        return result

    # 没有 rebind()/unbind()：绑定一旦建立就不可移动、不可解除。
    #
    # 这个方法是**故意不存在**的。绑定只由 claim_card_verbose() 在每次激活时
    # 写入（同 device_fp 才允许更新公钥）。要让一台设备脱离某张卡，唯一途径是
    # revoke_card()（终态，记审计）后重新发卡；需要临时停用用 disable_card()。
    # 任何"把卡从 A 机挪到 B 机"的代码路径都不应该被加回来：那会同时废掉
    # 一机一码语义，并让 activation_audit 里的换绑记录失去意义。

    # -- lifecycle -----------------------------------------------------------

    def disable_card(self, card_hash_value: str) -> dict | None:
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                "UPDATE cards SET state = 'disabled', disabled_at = ? WHERE card_hash = ?",
                (now, card_hash_value),
            )
            conn.execute("DELETE FROM tokens WHERE card_hash = ?", (card_hash_value,))
            row = conn.execute("SELECT * FROM cards WHERE card_hash = ?", (card_hash_value,)).fetchone()
        return self._row_to_dict(row)

    def enable_card(self, card_hash_value: str) -> dict | None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE cards SET state = 'bound', disabled_at = NULL "
                "WHERE card_hash = ? AND state = 'disabled'",
                (card_hash_value,),
            )
            row = conn.execute("SELECT * FROM cards WHERE card_hash = ?", (card_hash_value,)).fetchone()
        return self._row_to_dict(row)

    def revoke_card(self, card_hash_value: str) -> dict | None:
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                "UPDATE cards SET state = 'revoked', revoked_at = ?, "
                "device_fp = NULL, pubkey = NULL, bound_at = NULL WHERE card_hash = ?",
                (now, card_hash_value),
            )
            conn.execute("DELETE FROM tokens WHERE card_hash = ?", (card_hash_value,))
            row = conn.execute("SELECT * FROM cards WHERE card_hash = ?", (card_hash_value,)).fetchone()
        return self._row_to_dict(row)

    def delete_card(self, card_hash_value: str) -> bool:
        with self._connect() as conn:
            conn.execute("DELETE FROM tokens WHERE card_hash = ?", (card_hash_value,))
            cur = conn.execute("DELETE FROM cards WHERE card_hash = ?", (card_hash_value,))
            return cur.rowcount > 0

    # -- issuing -------------------------------------------------------------

    def gen_cards(self, count: int, days: int, batch: str | None = None, note: str | None = None) -> list[str]:
        if not isinstance(count, int) or count < 1:
            raise ValueError("count must be a positive integer")
        if not isinstance(days, int) or days < 0:
            raise ValueError("days must be a non-negative integer")
        now = int(time.time())
        expire = now + days * 86400 if days > 0 else 0
        keys = []
        with self._connect() as conn:
            for _ in range(count):
                key = generate_card_key()
                conn.execute(
                    "INSERT OR IGNORE INTO cards (card_hash, card_preview, device_fp, expire, state, created_at, bound_at, batch, note) "
                    "VALUES (?, ?, NULL, ?, 'unbound', ?, NULL, ?, ?)",
                    (card_hash(key), key, expire, now, batch, note),
                )
                keys.append(key)
        return keys

    def import_cards(self, keys: list[str], days: int = 0, batch: str | None = None, note: str | None = None) -> int:
        now = int(time.time())
        expire = now + days * 86400 if days > 0 else 0
        inserted = 0
        with self._connect() as conn:
            for raw in keys:
                try:
                    key = normalize_card_key(raw)
                except ValueError:
                    continue
                if not key:
                    continue
                cur = conn.execute(
                    "INSERT OR IGNORE INTO cards (card_hash, card_preview, device_fp, expire, state, created_at, bound_at, batch, note) "
                    "VALUES (?, ?, NULL, ?, 'unbound', ?, NULL, ?, ?)",
                    (card_hash(key), key, expire, now, batch, note),
                )
                inserted += cur.rowcount
        return inserted

    def list_cards(self, batch: str | None = None, state: str | None = None, keyword: str | None = None) -> list[dict]:
        query = "SELECT * FROM cards WHERE 1=1"
        params: list[object] = []
        if batch:
            query += " AND batch = ?"
            params.append(batch)
        if state:
            query += " AND state = ?"
            params.append(state)
        if keyword:
            query += " AND (card_hash LIKE ? OR card_preview LIKE ? OR device_fp LIKE ? OR note LIKE ?)"
            k = f"%{keyword}%"
            params.extend([k, k, k, k])
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM cards").fetchone()[0]
            bound = conn.execute("SELECT COUNT(*) FROM cards WHERE state = 'bound'").fetchone()[0]
            unbound = conn.execute("SELECT COUNT(*) FROM cards WHERE state = 'unbound'").fetchone()[0]
            disabled = conn.execute("SELECT COUNT(*) FROM cards WHERE state = 'disabled'").fetchone()[0]
            revoked = conn.execute("SELECT COUNT(*) FROM cards WHERE state = 'revoked'").fetchone()[0]
            active_tokens = conn.execute("SELECT COUNT(*) FROM tokens WHERE expires_at > ?", (int(time.time()),)).fetchone()[0]
            batches = [r[0] for r in conn.execute("SELECT DISTINCT batch FROM cards WHERE batch IS NOT NULL AND batch != ''").fetchall()]
        return {
            "total_cards": total,
            "bound_cards": bound,
            "unbound_cards": unbound,
            "disabled_cards": disabled,
            "revoked_cards": revoked,
            "active_tokens": active_tokens,
            "batches": batches,
        }

    # -- tokens --------------------------------------------------------------

    def create_token(self, card_hash_value: str, device_fp: str) -> str:
        token = secrets.token_hex(16)
        now = int(time.time())
        expires_at = now + TOKEN_TTL
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO tokens (token, card_hash, device_fp, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (token, card_hash_value, device_fp, now, expires_at),
            )
        return token

    def lookup_token(self, token: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT t.token, t.card_hash, t.created_at, t.expires_at, "
                "c.expire AS card_expire, c.state AS card_state, "
                "CASE WHEN c.card_hash IS NULL THEN 0 ELSE 1 END AS card_exists "
                "FROM tokens t LEFT JOIN cards c ON c.card_hash = t.card_hash "
                "WHERE t.token = ?",
                (token,),
            ).fetchone()
        return self._row_to_dict(row)

    def purge_expired_tokens(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM tokens WHERE expires_at <= ?", (int(time.time()),))
        return cur.rowcount

    def prune_sessions(self, keep_per_user: int = 10) -> int:
        """Drop expired admin sessions and keep only the newest N per user.

        Sessions live for SESSION_TTL and nothing used to clean them, so the
        table accumulated one row per console login forever.
        """
        now = int(time.time())
        removed = 0
        with self._connect() as conn:
            removed += conn.execute(
                "DELETE FROM admin_sessions WHERE expires_at <= ?", (now,)
            ).rowcount
            users = [r["username"] for r in conn.execute(
                "SELECT DISTINCT username FROM admin_sessions"
            ).fetchall()]
            for user in users:
                ids = [r["session_id"] for r in conn.execute(
                    "SELECT session_id FROM admin_sessions WHERE username = ? "
                    "ORDER BY created_at DESC", (user,)
                ).fetchall()]
                for sid in ids[keep_per_user:]:
                    conn.execute("DELETE FROM admin_sessions WHERE session_id = ?", (sid,))
                    removed += 1
        return removed

    def security_stats(self, window_seconds: int = 1800) -> dict:
        """Cheap abuse signals for the console (computed, no extra tables).

        cards_multi_ip: one card activated from more than one address inside the
        window -- the shape a stolen (card, device_fp) pair produces.
        rotations_24h / rejections_24h: how often devices re-keyed / were turned
        away today.
        """
        now = int(time.time())
        with self._connect() as conn:
            multi = conn.execute(
                "SELECT COUNT(*) FROM (SELECT card_hash FROM activation_audit "
                " WHERE ts >= ? AND client_ip IS NOT NULL AND client_ip != '' "
                " GROUP BY card_hash HAVING COUNT(DISTINCT client_ip) > 1)",
                (now - window_seconds,),
            ).fetchone()[0]
            rotations = conn.execute(
                "SELECT COUNT(*) FROM activation_audit WHERE ts >= ? AND rotated = 1",
                (now - 86400,),
            ).fetchone()[0]
            rejections = conn.execute(
                "SELECT COUNT(*) FROM activation_audit WHERE ts >= ? AND result = 'rejected'",
                (now - 86400,),
            ).fetchone()[0]
            recent = [dict(r) for r in conn.execute(
                "SELECT ts, card_hash, device_fp, client_ip, result FROM activation_audit "
                "WHERE rotated = 1 OR result = 'rejected' ORDER BY id DESC LIMIT 20"
            ).fetchall()]
        return {
            "window_seconds": window_seconds,
            "cards_multi_ip": multi,
            "rotations_24h": rotations,
            "rejections_24h": rejections,
            "recent_events": recent,
        }

    # -- sessions (Admin Web UI) ---------------------------------------------

    def create_session(self, username: str) -> str:
        sid = secrets.token_hex(24)
        now = int(time.time())
        exp = now + SESSION_TTL
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO admin_sessions (session_id, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (sid, username, now, exp),
            )
        return sid

    def verify_session(self, session_id: str) -> bool:
        if not session_id:
            return False
        now = int(time.time())
        with self._connect() as conn:
            row = conn.execute(
                "SELECT expires_at FROM admin_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if not row:
                return False
            if row["expires_at"] <= now:
                conn.execute("DELETE FROM admin_sessions WHERE session_id = ?", (session_id,))
                return False
            return True

    def delete_session(self, session_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM admin_sessions WHERE session_id = ?", (session_id,))
