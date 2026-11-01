from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .device_verification import VerifiedDevicePrincipal
from .security import token_hash, utc_text

SCHEMA_VERSION = 2
MAX_ENROLLED_DEVICES = 10


class DeviceQuotaExceeded(Exception):
    pass


class DeviceConflict(Exception):
    pass


class Store:
    """SQLite 数据访问层；所有状态变更均通过 BEGIN IMMEDIATE 串行执行。"""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = str(database_path)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialize(self) -> None:
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin', 'user')), active INTEGER NOT NULL CHECK (active IN (0, 1)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS user_networks (username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE, network TEXT NOT NULL CHECK (network IN ('home', 'work')), PRIMARY KEY (username, network));
                CREATE TABLE IF NOT EXISTS devices (
                    account_id TEXT NOT NULL REFERENCES users(username), device_id TEXT NOT NULL,
                    vpn_certificate_id TEXT NOT NULL UNIQUE, web_certificate_id TEXT NOT NULL UNIQUE, state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'revoking', 'revoked')),
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revocation_requested_at TEXT,
                    PRIMARY KEY (account_id, device_id)
                );
                CREATE INDEX IF NOT EXISTS devices_account_state_idx ON devices(account_id, state);
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username),
                    device_id TEXT NOT NULL, web_certificate_id TEXT NOT NULL, csrf_hash TEXT NOT NULL,
                    expires_at TEXT NOT NULL, revoked_at TEXT, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS sessions_username_idx ON sessions(username);
                CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
                CREATE TABLE IF NOT EXISTS login_attempts (source_ip TEXT NOT NULL, username TEXT NOT NULL, window_started_at TEXT NOT NULL, failure_count INTEGER NOT NULL CHECK (failure_count >= 0), PRIMARY KEY (source_ip, username));
                CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL, actor TEXT, source_ip TEXT, action TEXT NOT NULL, target TEXT, outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')));
                CREATE INDEX IF NOT EXISTS audit_events_id_idx ON audit_events(id DESC);
                """
            )
            # sqlite3.executescript 会先提交事务，因此在此显式开启结构版本更新事务。
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT value FROM schema_metadata WHERE key = 'schema_version'").fetchone()
            if existing is None:
                connection.execute("INSERT INTO schema_metadata(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            elif existing["value"] == "1":
                columns = {row["name"] for row in connection.execute("PRAGMA table_info(sessions)")}
                if "device_id" not in columns:
                    connection.execute("ALTER TABLE sessions ADD COLUMN device_id TEXT")
                if "web_certificate_id" not in columns:
                    connection.execute("ALTER TABLE sessions ADD COLUMN web_certificate_id TEXT")
                # 版本 1 的会话没有设备证明，升级后必须撤销。
                connection.execute("UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL", (utc_text(),))
                connection.execute("UPDATE schema_metadata SET value = ? WHERE key = 'schema_version'", (str(SCHEMA_VERSION),))
            elif existing["value"] != str(SCHEMA_VERSION):
                raise RuntimeError("unsupported database schema version")
            connection.execute("CREATE INDEX IF NOT EXISTS sessions_device_idx ON sessions(username, device_id)")
            connection.commit()

    @contextmanager
    def write_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def user_from_row(connection: sqlite3.Connection, row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        networks = [item["network"] for item in connection.execute("SELECT network FROM user_networks WHERE username = ? ORDER BY network", (row["username"],))]
        return {"username": row["username"], "password_hash": row["password_hash"], "role": row["role"], "active": bool(row["active"]), "networks": networks, "created_at": row["created_at"], "updated_at": row["updated_at"]}

    @staticmethod
    def device_from_row(row: sqlite3.Row | None) -> dict | None:
        return None if row is None else dict(row)

    def active_device(self, principal: VerifiedDevicePrincipal) -> dict | None:
        with self.connect() as connection:
            return self.device_from_row(connection.execute("""SELECT d.* FROM devices d JOIN users u ON u.username = d.account_id WHERE d.account_id = ? AND d.device_id = ? AND d.web_certificate_id = ? AND d.state = 'active' AND u.active = 1""", (principal.account_id, principal.device_id, principal.web_certificate_id)).fetchone())

    @staticmethod
    def audit(connection: sqlite3.Connection, *, actor: str | None, source_ip: str | None, action: str, target: str | None, outcome: str) -> None:
        connection.execute("INSERT INTO audit_events(occurred_at, actor, source_ip, action, target, outcome) VALUES (?, ?, ?, ?, ?, ?)", (utc_text(), actor, source_ip, action, target, outcome))

    @staticmethod
    def revoke_sessions(connection: sqlite3.Connection, username: str) -> None:
        connection.execute("UPDATE sessions SET revoked_at = ? WHERE username = ? AND revoked_at IS NULL", (utc_text(), username))

    @staticmethod
    def revoke_device_sessions(connection: sqlite3.Connection, username: str, device_id: str) -> None:
        connection.execute("UPDATE sessions SET revoked_at = ? WHERE username = ? AND device_id = ? AND revoked_at IS NULL", (utc_text(), username, device_id))

    @staticmethod
    def revoke_session_in_transaction(connection: sqlite3.Connection, opaque_token: str, principal: VerifiedDevicePrincipal) -> bool:
        """只撤销当前正在退出的已认证设备绑定会话。"""
        changed = connection.execute(
            """UPDATE sessions SET revoked_at = ?
               WHERE token_hash = ? AND username = ? AND device_id = ? AND web_certificate_id = ?
                 AND revoked_at IS NULL""",
            (utc_text(), token_hash(opaque_token), principal.account_id, principal.device_id, principal.web_certificate_id),
        ).rowcount
        return changed == 1

    def session_user(self, opaque_token: str, principal: VerifiedDevicePrincipal) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("""SELECT u.* FROM sessions s JOIN users u ON u.username = s.username JOIN devices d ON d.account_id = s.username AND d.device_id = s.device_id AND d.web_certificate_id = s.web_certificate_id WHERE s.token_hash = ? AND s.username = ? AND s.device_id = ? AND s.web_certificate_id = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND u.active = 1 AND d.state = 'active'""", (token_hash(opaque_token), principal.account_id, principal.device_id, principal.web_certificate_id, utc_text())).fetchone()
            return self.user_from_row(connection, row)

    def csrf_valid(self, opaque_token: str, csrf_token: str, principal: VerifiedDevicePrincipal) -> bool:
        with self.connect() as connection:
            row = connection.execute("""SELECT csrf_hash FROM sessions WHERE token_hash = ? AND username = ? AND device_id = ? AND web_certificate_id = ? AND revoked_at IS NULL AND expires_at > ?""", (token_hash(opaque_token), principal.account_id, principal.device_id, principal.web_certificate_id, utc_text())).fetchone()
            return row is not None and row["csrf_hash"] == token_hash(csrf_token)

    def rotate_csrf(self, opaque_token: str, csrf_token: str, principal: VerifiedDevicePrincipal) -> bool:
        with self.write_transaction() as connection:
            changed = connection.execute("""UPDATE sessions SET csrf_hash = ? WHERE token_hash = ? AND username = ? AND device_id = ? AND web_certificate_id = ? AND revoked_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM users WHERE users.username = sessions.username AND users.active = 1) AND EXISTS (SELECT 1 FROM devices WHERE devices.account_id = sessions.username AND devices.device_id = sessions.device_id AND devices.web_certificate_id = sessions.web_certificate_id AND devices.state = 'active')""", (token_hash(csrf_token), token_hash(opaque_token), principal.account_id, principal.device_id, principal.web_certificate_id, utc_text())).rowcount
            return changed == 1

    @staticmethod
    def add_session_in_transaction(connection: sqlite3.Connection, username: str, principal: VerifiedDevicePrincipal, opaque_token: str, csrf_token: str, expires_at: datetime) -> None:
        connection.execute("INSERT INTO sessions(token_hash, username, device_id, web_certificate_id, csrf_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (token_hash(opaque_token), username, principal.device_id, principal.web_certificate_id, token_hash(csrf_token), utc_text(expires_at), utc_text()))

    def list_users(self) -> list[dict]:
        with self.connect() as connection:
            return [self.user_from_row(connection, row) for row in connection.execute("SELECT * FROM users ORDER BY username")]

    def list_devices(self, account_id: str) -> list[dict]:
        with self.connect() as connection:
            return [self.device_from_row(row) for row in connection.execute("SELECT * FROM devices WHERE account_id = ? ORDER BY created_at, device_id", (account_id,))]

    def reserve_device(self, account_id: str, device_id: str, vpn_certificate_id: str, web_certificate_id: str, actor: str | None = None, source_ip: str | None = None) -> dict:
        with self.write_transaction() as connection:
            if connection.execute("SELECT 1 FROM users WHERE username = ? AND active = 1", (account_id,)).fetchone() is None:
                raise DeviceConflict("account unavailable")
            if vpn_certificate_id == web_certificate_id:
                raise DeviceConflict("certificate IDs must be distinct by purpose")
            certificate_in_use = connection.execute(
                """SELECT 1 FROM devices
                   WHERE vpn_certificate_id IN (?, ?) OR web_certificate_id IN (?, ?)
                   LIMIT 1""",
                (vpn_certificate_id, web_certificate_id, vpn_certificate_id, web_certificate_id),
            ).fetchone()
            if certificate_in_use is not None:
                raise DeviceConflict("certificate ID is already assigned to a device purpose")
            count = connection.execute("SELECT COUNT(*) AS count FROM devices WHERE account_id = ? AND state IN ('pending', 'active', 'revoking')", (account_id,)).fetchone()["count"]
            if count >= MAX_ENROLLED_DEVICES:
                raise DeviceQuotaExceeded()
            now = utc_text()
            try:
                connection.execute("INSERT INTO devices(account_id, device_id, vpn_certificate_id, web_certificate_id, state, created_at, updated_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)", (account_id, device_id, vpn_certificate_id, web_certificate_id, now, now))
            except sqlite3.IntegrityError as error:
                raise DeviceConflict("device or certificate already reserved") from error
            self.audit(connection, actor=actor, source_ip=source_ip, action="device_reserve", target=f"{account_id}:{device_id}", outcome="success")
            return self.device_from_row(connection.execute("SELECT * FROM devices WHERE account_id = ? AND device_id = ?", (account_id, device_id)).fetchone())

    def mark_device_revoking(self, account_id: str, device_id: str, actor: str | None = None, source_ip: str | None = None) -> dict | None:
        with self.write_transaction() as connection:
            row = connection.execute("SELECT * FROM devices WHERE account_id = ? AND device_id = ?", (account_id, device_id)).fetchone()
            if row is None:
                return None
            if row["state"] != "revoked":
                now = utc_text()
                connection.execute("UPDATE devices SET state = 'revoking', updated_at = ?, revocation_requested_at = COALESCE(revocation_requested_at, ?) WHERE account_id = ? AND device_id = ?", (now, now, account_id, device_id))
                self.revoke_device_sessions(connection, account_id, device_id)
            self.audit(connection, actor=actor, source_ip=source_ip, action="device_revoke_requested", target=f"{account_id}:{device_id}", outcome="success")
            return self.device_from_row(connection.execute("SELECT * FROM devices WHERE account_id = ? AND device_id = ?", (account_id, device_id)).fetchone())

    def list_audit(self, cursor: int | None, limit: int) -> tuple[list[dict], int | None]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit + 1,)).fetchall() if cursor is None else connection.execute("SELECT * FROM audit_events WHERE id < ? ORDER BY id DESC LIMIT ?", (cursor, limit + 1)).fetchall()
        return [dict(row) for row in rows[:limit]], rows[limit - 1]["id"] if len(rows) > limit else None
