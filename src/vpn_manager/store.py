"""账户、会话、设备 VPN 准入、网关投递与审计。"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .security import token_hash, utc_text

SCHEMA_VERSION = 8
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
            if version not in {None, "1", "2", "3", "4", "5", "6", "7", "8"}:
                raise RuntimeError("不支持的数据库结构版本")
            if version is None and tables - {"sqlite_sequence"}:
                raise RuntimeError("已有数据库缺少结构版本，拒绝猜测迁移")
            # Keep the existing account generations and encrypted delivery queue.
            # Only their foreign-key target changes to include device identities.
            legacy_gateway = "gateway_accounts" in tables and any(
                row["table"] == "users" for row in connection.execute("PRAGMA foreign_key_list(gateway_accounts)")
            )
            if legacy_gateway:
                connection.execute("ALTER TABLE gateway_accounts RENAME TO previous_gateway_accounts")
                connection.execute("ALTER TABLE gateway_outbox RENAME TO previous_gateway_outbox")
                connection.execute("DROP INDEX IF EXISTS gateway_outbox_pending_idx")
            statements = [
                "CREATE TABLE IF NOT EXISTS schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','user')), active INTEGER NOT NULL CHECK(active IN (0,1)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS user_networks (username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE, network TEXT NOT NULL CHECK(network IN ('home','work')), PRIMARY KEY(username,network))",
                "CREATE TABLE IF NOT EXISTS device_records (account_id TEXT NOT NULL REFERENCES users(username), device_id TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('registered','removed')), created_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(account_id,device_id))",
                "CREATE TABLE IF NOT EXISTS login_attempts (source_ip TEXT NOT NULL, username TEXT NOT NULL, window_started_at TEXT NOT NULL, failure_count INTEGER NOT NULL CHECK(failure_count>=0), PRIMARY KEY(source_ip,username))",
                "CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL, actor TEXT, source_ip TEXT, action TEXT NOT NULL, target TEXT, outcome TEXT NOT NULL CHECK(outcome IN ('success','failure','denied')))",
                "CREATE INDEX IF NOT EXISTS audit_events_id_idx ON audit_events(id DESC)",
                """CREATE TABLE IF NOT EXISTS gateway_identities (
                    username TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                    device_id TEXT, disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
                    CHECK((device_id IS NULL AND username=account_id AND disabled=0) OR
                          (device_id IS NOT NULL AND username<>account_id)),
                    UNIQUE(account_id,device_id),
                    FOREIGN KEY(account_id,device_id) REFERENCES device_records(account_id,device_id))""",
                "CREATE TABLE IF NOT EXISTS gateway_accounts (username TEXT PRIMARY KEY REFERENCES gateway_identities(username) ON DELETE CASCADE, generation INTEGER NOT NULL CHECK(generation>=1), applied_generation INTEGER, state TEXT NOT NULL CHECK(state IN ('queued','pending','applied','failed','superseded')), code TEXT, updated_at TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS gateway_outbox (operation_id TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES gateway_identities(username) ON DELETE CASCADE, generation INTEGER NOT NULL CHECK(generation>=1), active INTEGER NOT NULL CHECK(active IN (0,1)), networks_json TEXT NOT NULL, credential_envelope TEXT, state TEXT NOT NULL CHECK(state IN ('queued','pending','applied','failed','superseded')), code TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(username,generation))",
                "CREATE INDEX IF NOT EXISTS gateway_outbox_pending_idx ON gateway_outbox(state,created_at)",
            ]
            for sql in statements:
                connection.execute(sql)
            if legacy_gateway:
                connection.execute("INSERT INTO gateway_identities(username,account_id) SELECT username,username FROM users")
                connection.execute("INSERT INTO gateway_accounts SELECT * FROM previous_gateway_accounts")
                connection.execute("INSERT INTO gateway_outbox SELECT * FROM previous_gateway_outbox")
                connection.execute("DROP TABLE previous_gateway_outbox")
                connection.execute("DROP TABLE previous_gateway_accounts")
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
            if version in {None, "1", "2", "3"}:
                self.audit(connection, actor=None, source_ip=None, action="authentication_schema_upgrade", target="password_auth_v4", outcome="success")
            if version == "4":
                self.audit(connection, actor=None, source_ip=None, action="gateway_schema_upgrade", target="gateway_sync_v5", outcome="success")
            if version in {"1", "2", "3", "4", "5"}:
                # 历史版本允许 user 持有 home。升级时将其原子收敛为唯一
                # 的 work，之后所有公开写入口会拒绝该越权组合。
                affected_users = [row[0] for row in connection.execute(
                    "SELECT u.username FROM users u WHERE u.role='user' AND EXISTS(SELECT 1 FROM user_networks n WHERE n.username=u.username AND n.network<>'work')"
                )]
                connection.execute("DELETE FROM user_networks WHERE username IN (SELECT username FROM users WHERE role='user')")
                connection.execute("INSERT INTO user_networks(username,network) SELECT username,'work' FROM users WHERE role='user'")
                for username in affected_users:
                    self.revoke_sessions(connection, username)
                self.audit(connection, actor=None, source_ip=None, action="user_network_policy_upgrade", target="user_work_only_v6", outcome="success")
            # 增量创建目录，不重写既有授权表、会话、网关版本或路由。
            connection.execute("""CREATE TABLE IF NOT EXISTS network_catalog (
                id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                description TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('existing','draft')),
                version INTEGER NOT NULL CHECK(version>=1), created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
            if version not in {"7", "8"}:
                now = utc_text()
                connection.executemany("INSERT INTO network_catalog(id,name,description,state,version,created_at,updated_at) VALUES (?,?,?,'existing',1,?,?) ON CONFLICT(id) DO NOTHING", [
                    ("home", "家庭", "家庭局域网资源", now, now),
                    ("work", "工作", "工作内网资源", now, now),
                ])
                self.audit(connection, actor=None, source_ip=None, action="network_catalog_upgrade", target="network_catalog_v7", outcome="success")
            connection.execute("INSERT INTO schema_metadata(key,value) VALUES ('schema_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(SCHEMA_VERSION),))

    def list_networks(self, username: str | None = None) -> list[dict]:
        with self.connect() as connection:
            if username is None:
                rows = connection.execute("SELECT * FROM network_catalog ORDER BY created_at,id")
            else:
                rows = connection.execute("SELECT n.* FROM network_catalog n JOIN user_networks u ON u.network=n.id WHERE u.username=? ORDER BY n.created_at,n.id", (username,))
            return [dict(row) for row in rows]

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

    def list_device_access(self, account_id: str) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute("""SELECT d.*, i.username AS vpn_username, i.disabled,
                g.state AS gateway_state, g.generation, g.applied_generation, u.active AS account_active
                FROM device_records d JOIN users u ON u.username=d.account_id
                LEFT JOIN gateway_identities i ON i.account_id=d.account_id AND i.device_id=d.device_id
                LEFT JOIN gateway_accounts g ON g.username=i.username
                WHERE d.account_id=? ORDER BY d.created_at,d.device_id""", (account_id,))
            return [dict(row) for row in rows]

    @staticmethod
    def device_identity(connection, account_id: str, device_id: str):
        return connection.execute("""SELECT i.username,i.disabled,g.state AS gateway_state
            FROM gateway_identities i LEFT JOIN gateway_accounts g ON g.username=i.username
            WHERE i.account_id=? AND i.device_id=?""", (account_id, device_id)).fetchone()

    @staticmethod
    def enabled_device_identities(connection, account_id: str) -> list[str]:
        return [row[0] for row in connection.execute("""SELECT username FROM gateway_identities
            WHERE account_id=? AND device_id IS NOT NULL AND disabled=0 ORDER BY username""", (account_id,))]

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
        identity = self.device_identity(connection, account_id, device_id)
        if identity and (not identity["disabled"] or identity["gateway_state"] != "applied"):
            raise DeviceConflict()
        changed = connection.execute("UPDATE device_records SET state='removed',updated_at=? WHERE account_id=? AND device_id=?", (utc_text(),account_id,device_id)).rowcount
        if not changed:
            return None
        self.audit(connection, actor=actor, source_ip=source_ip, action="device_record_remove", target=f"{account_id}:{device_id}", outcome="success")
        return dict(connection.execute("SELECT * FROM device_records WHERE account_id=? AND device_id=?", (account_id,device_id)).fetchone())

    @staticmethod
    def next_gateway_generation(connection, username: str) -> int:
        row = connection.execute("SELECT generation FROM gateway_accounts WHERE username=?", (username,)).fetchone()
        return (row["generation"] + 1) if row else 1

    def queue_gateway_change(self, connection, username: str, generation: int, active: bool, networks: list[str], credential_envelope: dict | None, *, discard_pending_credential: bool = False) -> str:
        """将完整期望状态原子入队；后续版本会取代尚未执行的旧版本。"""
        if generation != self.next_gateway_generation(connection, username) or not isinstance(active, bool):
            raise ValueError("无效网关同步版本")
        if not isinstance(networks, list) or len(networks) != len(set(networks)) or set(networks) - {"home", "work"} or (active and not networks):
            raise ValueError("无效网关网络权限")
        envelope_json = None
        if credential_envelope is not None:
            envelope_json = json.dumps(credential_envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            if len(envelope_json.encode("utf-8")) > 8 * 1024:
                raise ValueError("凭据封装过大")
        connection.execute("""INSERT INTO gateway_identities(username,account_id)
            SELECT username,username FROM users WHERE username=? ON CONFLICT(username) DO NOTHING""", (username,))
        now, operation_id = utc_text(), uuid.uuid4().hex
        # 密文 AAD 绑定 generation。非密码变更必须保留前一含密文任务，待它先成功后才可应用新策略。
        if credential_envelope is not None or discard_pending_credential:
            connection.execute("UPDATE gateway_outbox SET state='superseded', credential_envelope=NULL, updated_at=? WHERE username=? AND state IN ('queued','pending','failed')", (now, username))
        else:
            connection.execute("UPDATE gateway_outbox SET state='superseded', credential_envelope=NULL, updated_at=? WHERE username=? AND state IN ('queued','pending','failed') AND credential_envelope IS NULL", (now, username))
        connection.execute("INSERT INTO gateway_outbox(operation_id,username,generation,active,networks_json,credential_envelope,state,created_at,updated_at) VALUES (?,?,?,?,?,?, 'queued',?,?)", (operation_id, username, generation, int(active), json.dumps(sorted(networks), separators=(",", ":")), envelope_json, now, now))
        blocking = connection.execute("SELECT code FROM gateway_outbox WHERE username=? AND credential_envelope IS NOT NULL AND state='failed' ORDER BY generation LIMIT 1", (username,)).fetchone()
        state, code = ("failed", blocking["code"]) if blocking else ("queued", None)
        connection.execute("INSERT INTO gateway_accounts(username,generation,applied_generation,state,code,updated_at) VALUES (?,?,NULL,?,?,?) ON CONFLICT(username) DO UPDATE SET generation=excluded.generation,state=excluded.state,code=excluded.code,updated_at=excluded.updated_at", (username, generation, state, code, now))
        return operation_id

    def pending_gateway_jobs(self) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute("""SELECT o.* FROM gateway_outbox o
                WHERE o.state IN ('queued','pending') AND NOT EXISTS (
                    SELECT 1 FROM gateway_outbox earlier WHERE earlier.username=o.username
                    AND earlier.generation<o.generation AND earlier.state NOT IN ('applied','superseded')
                ) ORDER BY o.created_at,o.operation_id""").fetchall()
        jobs = []
        for row in rows:
            item = dict(row)
            item["active"] = bool(item["active"])
            item["networks"] = json.loads(item.pop("networks_json"))
            item["credential_envelope"] = json.loads(item["credential_envelope"]) if item["credential_envelope"] else None
            jobs.append(item)
        return jobs

    def retry_failed_gateway_jobs(self) -> int:
        """显式重试最早未完成的失败投影，不改变操作、版本或密文。"""
        with self.write_transaction() as connection:
            rows = connection.execute("""SELECT o.operation_id,o.username,o.generation FROM gateway_outbox o
                WHERE o.state='failed' AND NOT EXISTS (
                    SELECT 1 FROM gateway_outbox earlier WHERE earlier.username=o.username
                    AND earlier.generation<o.generation AND earlier.state NOT IN ('applied','superseded')
                )""").fetchall()
            now = utc_text()
            for row in rows:
                connection.execute("UPDATE gateway_outbox SET state='pending',code=NULL,updated_at=? WHERE operation_id=?", (now, row["operation_id"]))
                # 若之后已有策略在等待本版本，账户状态仍代表最新版本；旧任务
                # 的 applied 回执会将其推进回 queued，绝不覆盖更新版本。
                connection.execute("UPDATE gateway_accounts SET state='pending',code=NULL,updated_at=? WHERE username=? AND generation=?", (now, row["username"], row["generation"]))
                self.audit(connection, actor="gateway_sync_cli", source_ip="unix_socket", action="gateway_sync_retry", target=row["username"], outcome="success")
        return len(rows)

    def record_gateway_reply(self, operation_id: str, username: str, generation: int, state: str, code: str | None) -> None:
        if state not in {"applied", "pending", "failed", "superseded"}:
            raise ValueError("无效网关回执")
        with self.write_transaction() as connection:
            job = connection.execute("SELECT * FROM gateway_outbox WHERE operation_id=? AND username=? AND generation=?", (operation_id, username, generation)).fetchone()
            if job is None:
                return
            if job["state"] == "superseded":
                return
            current = connection.execute("SELECT generation FROM gateway_accounts WHERE username=?", (username,)).fetchone()
            now = utc_text()
            if current is None or current["generation"] != generation:
                clear = ",credential_envelope=NULL" if state in {"applied", "superseded"} else ""
                connection.execute(f"UPDATE gateway_outbox SET state=?,code=?,updated_at=?{clear} WHERE operation_id=?", (state, code, now, operation_id))
                if state == "applied":
                    connection.execute("UPDATE gateway_accounts SET applied_generation=?,state='queued',code=NULL,updated_at=? WHERE username=?", (generation, now, username))
                    self.audit(connection, actor="gateway_agent", source_ip="unix_socket", action="gateway_sync_applied", target=username, outcome="success")
                elif state == "failed":
                    connection.execute("UPDATE gateway_accounts SET state='failed',code=?,updated_at=? WHERE username=?", (code, now, username))
                    self.audit(connection, actor="gateway_agent", source_ip="unix_socket", action="gateway_sync_failed", target=username, outcome="failure")
                return
            clear = ",credential_envelope=NULL" if state in {"applied", "superseded"} else ""
            connection.execute(f"UPDATE gateway_outbox SET state=?,code=?,updated_at=?{clear} WHERE operation_id=?", (state, code, now, operation_id))
            if state == "applied":
                connection.execute("UPDATE gateway_accounts SET applied_generation=?,state=?,code=?,updated_at=? WHERE username=?", (generation, state, code, now, username))
                self.audit(connection, actor="gateway_agent", source_ip="unix_socket", action="gateway_sync_applied", target=username, outcome="success")
            else:
                connection.execute("UPDATE gateway_accounts SET state=?,code=?,updated_at=? WHERE username=?", (state, code, now, username))
                if state == "failed":
                    self.audit(connection, actor="gateway_agent", source_ip="unix_socket", action="gateway_sync_failed", target=username, outcome="failure")

    def gateway_status(self, username: str) -> dict:
        with self.connect() as connection:
            row = connection.execute("SELECT username,generation,applied_generation,state,code,updated_at FROM gateway_accounts WHERE username=?", (username,)).fetchone()
        return dict(row) if row else {"username": username, "generation": 0, "applied_generation": None, "state": "not_provisioned", "code": None, "updated_at": None}

    def list_gateway_statuses(self) -> list[dict]:
        with self.connect() as connection:
            users = [row[0] for row in connection.execute("SELECT username FROM users ORDER BY username")]
        return [self.gateway_status(username) for username in users]

    def list_audit(self, cursor: int | None, limit: int) -> tuple[list[dict], int | None]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit+1,)).fetchall() if cursor is None else connection.execute("SELECT * FROM audit_events WHERE id<? ORDER BY id DESC LIMIT ?", (cursor,limit+1)).fetchall()
        return [dict(r) for r in rows[:limit]], rows[limit-1]["id"] if len(rows)>limit else None
