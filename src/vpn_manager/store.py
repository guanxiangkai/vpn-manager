"""账户、密码会话、设备管理记录与审计；设备记录不参与认证。"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .security import token_hash, utc_text

SCHEMA_VERSION = 4
MAX_ENROLLED_DEVICES = 10


class DeviceQuotaExceeded(Exception):
    pass


class DeviceConflict(Exception):
    pass


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


class Store:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = str(database_path)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5, isolation_level=None, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

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

    def initialize(self) -> None:
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self.write_transaction() as connection:
            tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            old = connection.execute("SELECT value FROM schema_metadata WHERE key='schema_version'").fetchone() if "schema_metadata" in tables else None
            version = old[0] if old else None
            if version not in {None, "1", "2", "3", "4"}:
                raise RuntimeError("不支持的数据库结构版本")
            if version is None and tables - {"sqlite_sequence"}:
                raise RuntimeError("已有数据库缺少结构版本，拒绝猜测迁移")
            statements = [
                "CREATE TABLE IF NOT EXISTS schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','user')), active INTEGER NOT NULL CHECK(active IN (0,1)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS user_networks (username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE, network TEXT NOT NULL CHECK(network IN ('home','work')), PRIMARY KEY(username,network))",
                "CREATE TABLE IF NOT EXISTS device_records (account_id TEXT NOT NULL REFERENCES users(username), device_id TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('registered','removed')), created_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(account_id,device_id))",
                "CREATE TABLE IF NOT EXISTS login_attempts (source_ip TEXT NOT NULL, username TEXT NOT NULL, window_started_at TEXT NOT NULL, failure_count INTEGER NOT NULL CHECK(failure_count>=0), PRIMARY KEY(source_ip,username))",
                "CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL, actor TEXT, source_ip TEXT, action TEXT NOT NULL, target TEXT, outcome TEXT NOT NULL CHECK(outcome IN ('success','failure','denied')))",
                "CREATE INDEX IF NOT EXISTS audit_events_id_idx ON audit_events(id DESC)",
            ]
            for sql in statements:
                connection.execute(sql)
            if version in {"1", "2", "3"} and "sessions" in tables:
                connection.execute("ALTER TABLE sessions RENAME TO sessions_before_password_auth")
            connection.execute("""CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username),
                csrf_hash TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, created_at TEXT NOT NULL,
                device_id TEXT, web_certificate_id TEXT)""")
            if version in {"1", "2", "3"} and "sessions" in tables:
                columns = {r[1] for r in connection.execute("PRAGMA table_info(sessions_before_password_auth)")}
                device = "device_id" if "device_id" in columns else "NULL"
                cert = "web_certificate_id" if "web_certificate_id" in columns else "NULL"
                connection.execute(f"""INSERT INTO sessions(token_hash,username,csrf_hash,expires_at,revoked_at,created_at,device_id,web_certificate_id)
                    SELECT token_hash,username,csrf_hash,expires_at,COALESCE(revoked_at,?),created_at,{device},{cert} FROM sessions_before_password_auth""", (utc_text(),))
                connection.execute("DROP TABLE sessions_before_password_auth")
            if version in {"1", "2", "3"} and "devices" in tables:
                connection.execute("""INSERT OR IGNORE INTO device_records(account_id,device_id,state,created_at,updated_at)
                    SELECT account_id,device_id,CASE WHEN state='revoked' THEN 'removed' ELSE 'registered' END,created_at,updated_at FROM devices""")
            connection.execute("CREATE INDEX IF NOT EXISTS sessions_username_idx ON sessions(username)")
            connection.execute("CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at)")
            if version != "4":
                self.audit(connection, actor=None, source_ip=None, action="authentication_schema_upgrade", target="password_auth_v4", outcome="success")
            connection.execute("INSERT INTO schema_metadata(key,value) VALUES ('schema_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(SCHEMA_VERSION),))

    @staticmethod
    def user_from_row(connection, row) -> dict | None:
        if row is None:
            return None
        networks = [r[0] for r in connection.execute("SELECT network FROM user_networks WHERE username=? ORDER BY network", (row["username"],))]
        return {**dict(row), "active": bool(row["active"]), "networks": networks}

    def find_user(self, username: str) -> dict | None:
        with self.connect() as connection:
            return self.user_from_row(connection, connection.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone())

    @staticmethod
    def audit(connection, *, actor, source_ip, action, target, outcome) -> None:
        connection.execute("INSERT INTO audit_events(occurred_at,actor,source_ip,action,target,outcome) VALUES (?,?,?,?,?,?)", (utc_text(), actor, source_ip, action, target, outcome))

    @staticmethod
    def revoke_sessions(connection, username) -> None:
        connection.execute("UPDATE sessions SET revoked_at=? WHERE username=? AND revoked_at IS NULL", (utc_text(), username))

    @staticmethod
    def revoke_session_in_transaction(connection, opaque_token: str, username: str) -> bool:
        return connection.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=? AND username=? AND revoked_at IS NULL", (utc_text(), token_hash(opaque_token), username)).rowcount == 1

    def session_user(self, opaque_token: str) -> dict | None:
        with self.connect() as connection:
            return self.session_user_in_transaction(connection, opaque_token)

    def session_user_in_transaction(self, connection, opaque_token: str) -> dict | None:
        return self.user_from_row(connection, connection.execute("SELECT u.* FROM sessions s JOIN users u ON u.username=s.username WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.active=1", (token_hash(opaque_token), utc_text())).fetchone())

    def csrf_valid(self, opaque_token: str, csrf_token: str) -> bool:
        with self.connect() as connection:
            return connection.execute("SELECT 1 FROM sessions s JOIN users u ON u.username=s.username WHERE s.token_hash=? AND s.csrf_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.active=1", (token_hash(opaque_token), token_hash(csrf_token), utc_text())).fetchone() is not None

    def rotate_csrf(self, opaque_token: str, csrf_token: str) -> bool:
        with self.write_transaction() as connection:
            return connection.execute("UPDATE sessions SET csrf_hash=? WHERE token_hash=? AND revoked_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM users WHERE username=sessions.username AND active=1)", (token_hash(csrf_token), token_hash(opaque_token), utc_text())).rowcount == 1

    @staticmethod
    def add_session_in_transaction(connection, username: str, opaque_token: str, csrf_token: str, expires_at: datetime) -> None:
        connection.execute("INSERT INTO sessions(token_hash,username,csrf_hash,expires_at,created_at) VALUES (?,?,?,?,?)", (token_hash(opaque_token), username, token_hash(csrf_token), utc_text(expires_at), utc_text()))

    def list_users(self) -> list[dict]:
        with self.connect() as connection:
            return [self.user_from_row(connection, row) for row in connection.execute("SELECT * FROM users ORDER BY username")]

    def list_devices(self, account_id: str) -> list[dict]:
        with self.connect() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM device_records WHERE account_id=? ORDER BY created_at,device_id", (account_id,))]

    def register_device(self, account_id: str, device_id: str, actor=None, source_ip=None) -> dict:
        with self.write_transaction() as connection:
            return self.register_device_in_transaction(connection, account_id, device_id, actor, source_ip)

    def register_device_in_transaction(self, connection, account_id: str, device_id: str, actor=None, source_ip=None) -> dict:
        if connection.execute("SELECT 1 FROM users WHERE username=? AND active=1", (account_id,)).fetchone() is None:
            raise DeviceConflict()
        row = connection.execute("SELECT state FROM device_records WHERE account_id=? AND device_id=?", (account_id,device_id)).fetchone()
        if row and row[0] == "registered":
            raise DeviceConflict()
        if connection.execute("SELECT COUNT(*) FROM device_records WHERE account_id=? AND state='registered'", (account_id,)).fetchone()[0] >= MAX_ENROLLED_DEVICES:
            raise DeviceQuotaExceeded()
        now = utc_text()
        connection.execute("INSERT INTO device_records(account_id,device_id,state,created_at,updated_at) VALUES (?,?,'registered',?,?) ON CONFLICT(account_id,device_id) DO UPDATE SET state='registered',updated_at=excluded.updated_at", (account_id,device_id,now,now))
        self.audit(connection, actor=actor, source_ip=source_ip, action="device_record_add", target=f"{account_id}:{device_id}", outcome="success")
        return dict(connection.execute("SELECT * FROM device_records WHERE account_id=? AND device_id=?", (account_id,device_id)).fetchone())

    def remove_device(self, account_id: str, device_id: str, actor=None, source_ip=None) -> dict | None:
        with self.write_transaction() as connection:
            return self.remove_device_in_transaction(connection, account_id, device_id, actor, source_ip)

    def remove_device_in_transaction(self, connection, account_id: str, device_id: str, actor=None, source_ip=None) -> dict | None:
        changed = connection.execute("UPDATE device_records SET state='removed',updated_at=? WHERE account_id=? AND device_id=?", (utc_text(),account_id,device_id)).rowcount
        if not changed:
            return None
        self.audit(connection, actor=actor, source_ip=source_ip, action="device_record_remove", target=f"{account_id}:{device_id}", outcome="success")
        return dict(connection.execute("SELECT * FROM device_records WHERE account_id=? AND device_id=?", (account_id,device_id)).fetchone())

    def list_audit(self, cursor: int | None, limit: int) -> tuple[list[dict], int | None]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit+1,)).fetchall() if cursor is None else connection.execute("SELECT * FROM audit_events WHERE id<? ORDER BY id DESC LIMIT ?", (cursor,limit+1)).fetchall()
        return [dict(r) for r in rows[:limit]], rows[limit-1]["id"] if len(rows)>limit else None
