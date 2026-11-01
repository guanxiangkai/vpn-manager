from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from fastapi.testclient import TestClient
import pytest

from vpn_manager.app import ALLOWED_ORIGIN, create_app
from vpn_manager.bootstrap import bootstrap
from vpn_manager.device_verification import VerifiedDevicePrincipal
from vpn_manager.security import COOKIE_NAME, utc_text
from vpn_manager.store import DeviceQuotaExceeded, Store


class FixtureVerifier:
    """显式注入测试主体，绝不从 HTTP 输入推导设备身份。"""

    def __init__(self, principal: VerifiedDevicePrincipal) -> None:
        self.principal = principal

    def verify(self, _request) -> VerifiedDevicePrincipal:
        return self.principal


@pytest.fixture()
def database(tmp_path):
    path = tmp_path / "manager.sqlite3"
    bootstrap(str(path), [
        {"username": "adminone", "password": "correct-horse-admin-one", "role": "admin", "networks": ["home", "work"]},
        {"username": "member", "password": "correct-horse-member", "role": "user", "networks": ["work"]},
    ])
    enroll(path, "adminone", "admin-device", "vpn-admin", "web-admin", "active")
    enroll(path, "member", "member-device", "vpn-member", "web-member", "active")
    return path


def enroll(database, account: str, device: str, vpn_certificate: str, web_certificate: str, state: str) -> None:
    store = Store(database)
    with store.write_transaction() as connection:
        now = utc_text()
        connection.execute(
            "INSERT INTO devices(account_id, device_id, vpn_certificate_id, web_certificate_id, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (account, device, vpn_certificate, web_certificate, state, now, now),
        )


def principal(account: str, device: str, web_certificate: str) -> VerifiedDevicePrincipal:
    return VerifiedDevicePrincipal(account, device, web_certificate)


def client_for(database, device_principal: VerifiedDevicePrincipal) -> TestClient:
    return TestClient(create_app(database, device_verifier=FixtureVerifier(device_principal)), base_url="https://slimjoy.cn")


def login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/auth/login", headers={"Origin": ALLOWED_ORIGIN}, json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def csrf(token: str) -> dict[str, str]:
    return {"Origin": ALLOWED_ORIGIN, "X-CSRF-Token": token}


def test_default_is_locked_and_spoofed_headers_do_not_create_a_principal(database) -> None:
    client = TestClient(create_app(database), base_url="https://slimjoy.cn")
    response = client.post("/api/auth/login", headers={"Origin": ALLOWED_ORIGIN, "X-SSL-Client-CN": "member", "X-Device-Id": "member-device"}, json={"username": "member", "password": "correct-horse-member"})
    assert response.status_code == 503
    assert response.json() == {"error": {"code": "device_verification_unavailable", "message": "尚未配置设备验证服务。"}}


def test_validation_and_account_mismatch_use_typed_error_responses(database) -> None:
    member = client_for(database, principal("member", "member-device", "web-member"))
    malformed = member.post("/api/auth/login", headers={"Origin": ALLOWED_ORIGIN}, json={"username": "member", "password": "correct-horse-member", "extra": "rejected"})
    assert malformed.status_code == 422
    assert malformed.json()["error"]["code"] == "invalid_request"
    mismatch = member.post("/api/auth/login", headers={"Origin": ALLOWED_ORIGIN}, json={"username": "adminone", "password": "correct-horse-admin-one"})
    assert mismatch.status_code == 403
    assert mismatch.json()["error"]["code"] == "device_account_mismatch"


def test_pending_device_cannot_authenticate(database) -> None:
    admin = client_for(database, principal("adminone", "admin-device", "web-admin"))
    token = login(admin, "adminone", "correct-horse-admin-one")
    reserved = admin.post("/api/admin/users/member/devices/reservations", headers=csrf(token), json={"device_id": "pending-device", "vpn_certificate_id": "vpn-pending", "web_certificate_id": "web-pending"})
    assert reserved.status_code == 201
    assert reserved.json()["state"] == "pending"
    listed = admin.get("/api/admin/users/member/devices")
    assert any(item["device_id"] == "pending-device" for item in listed.json())
    pending = client_for(database, principal("member", "pending-device", "web-pending"))
    denied = pending.post("/api/auth/login", headers={"Origin": ALLOWED_ORIGIN}, json={"username": "member", "password": "correct-horse-member"})
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "device_not_active"


def test_copied_cookie_is_bound_to_the_original_device(database) -> None:
    original = client_for(database, principal("member", "member-device", "web-member"))
    login(original, "member", "correct-horse-member")
    copied = original.cookies.get(COOKIE_NAME)
    enroll(database, "member", "member-device-two", "vpn-member-two", "web-member-two", "active")
    other_device = client_for(database, principal("member", "member-device-two", "web-member-two"))
    other_device.cookies.set(COOKIE_NAME, copied, domain="slimjoy.cn", path="/")
    denied = other_device.get("/api/auth/me", headers={"Origin": ALLOWED_ORIGIN})
    assert denied.status_code == 401
    assert denied.json()["error"]["code"] == "authentication_required"


def test_logout_revokes_exact_session_audits_and_rejects_cookie_replay(database) -> None:
    member = client_for(database, principal("member", "member-device", "web-member"))
    csrf_token = login(member, "member", "correct-horse-member")
    old_cookie = member.cookies.get(COOKIE_NAME)
    logged_out = member.post("/api/auth/logout", headers=csrf(csrf_token))
    assert logged_out.status_code == 200
    assert logged_out.json() == {"message": "已退出登录"}
    replay = client_for(database, principal("member", "member-device", "web-member"))
    replay.cookies.set(COOKIE_NAME, old_cookie, domain="slimjoy.cn", path="/")
    denied = replay.get("/api/auth/me", headers={"Origin": ALLOWED_ORIGIN})
    assert denied.status_code == 401
    assert denied.json()["error"]["code"] == "authentication_required"
    with Store(database).connect() as connection:
        assert connection.execute("SELECT revoked_at FROM sessions WHERE username = 'member'").fetchone()["revoked_at"] is not None
        assert connection.execute("SELECT outcome FROM audit_events WHERE action = 'logout' ORDER BY id DESC LIMIT 1").fetchone()["outcome"] == "success"


def test_logout_preserves_a_second_active_session_on_the_same_device(database) -> None:
    first = client_for(database, principal("member", "member-device", "web-member"))
    first_csrf = login(first, "member", "correct-horse-member")
    second = client_for(database, principal("member", "member-device", "web-member"))
    login(second, "member", "correct-horse-member")
    assert first.post("/api/auth/logout", headers=csrf(first_csrf)).status_code == 200
    still_active = second.get("/api/auth/me", headers={"Origin": ALLOWED_ORIGIN})
    assert still_active.status_code == 200
    assert still_active.json()["username"] == "member"


def test_user_can_only_list_and_revoke_own_devices(database) -> None:
    member = client_for(database, principal("member", "member-device", "web-member"))
    csrf_token = login(member, "member", "correct-horse-member")
    listed = member.get("/api/devices")
    assert listed.status_code == 200
    assert [item["account_id"] for item in listed.json()] == ["member"]
    forbidden = member.post("/api/devices/admin-device/revoke", headers=csrf(csrf_token))
    assert forbidden.status_code == 404
    revoked = member.post("/api/devices/member-device/revoke", headers=csrf(csrf_token))
    assert revoked.status_code == 200
    assert revoked.json()["state"] == "revoking"
    assert revoked.json()["gateway_revocation"] == "pending"


def test_reservation_rejects_same_or_cross_purpose_certificate_ids_without_partial_record(database) -> None:
    admin = client_for(database, principal("adminone", "admin-device", "web-admin"))
    csrf_token = login(admin, "adminone", "correct-horse-admin-one")
    before = Store(database).list_devices("member")
    same_id = admin.post(
        "/api/admin/users/member/devices/reservations",
        headers=csrf(csrf_token),
        json={"device_id": "same-id", "vpn_certificate_id": "shared-id", "web_certificate_id": "shared-id"},
    )
    assert same_id.status_code == 409
    assert same_id.json()["error"]["code"] == "device_conflict"
    cross_account_exchange = admin.post(
        "/api/admin/users/member/devices/reservations",
        headers=csrf(csrf_token),
        json={"device_id": "cross-purpose", "vpn_certificate_id": "web-admin", "web_certificate_id": "vpn-admin"},
    )
    assert cross_account_exchange.status_code == 409
    assert cross_account_exchange.json()["error"]["code"] == "device_conflict"
    assert Store(database).list_devices("member") == before


def test_revoking_device_denies_manager_immediately_and_keeps_gateway_pending(database) -> None:
    member = client_for(database, principal("member", "member-device", "web-member"))
    login(member, "member", "correct-horse-member")
    admin = client_for(database, principal("adminone", "admin-device", "web-admin"))
    token = login(admin, "adminone", "correct-horse-admin-one")
    revoked = admin.post("/api/admin/users/member/devices/member-device/revoke", headers=csrf(token))
    assert revoked.status_code == 200
    assert revoked.json()["state"] == "revoking"
    assert revoked.json()["manager_access"] == "revoked"
    assert revoked.json()["gateway_revocation"] == "pending"
    assert member.get("/api/auth/me", headers={"Origin": ALLOWED_ORIGIN}).status_code == 403
    with Store(database).connect() as connection:
        assert connection.execute("SELECT revoked_at FROM sessions WHERE username = 'member'").fetchone()["revoked_at"] is not None


def test_quota_counts_pending_active_and_revoking_under_real_concurrent_reservations(database) -> None:
    for index, state in enumerate(["pending"] * 6 + ["active", "revoking"]):
        enroll(database, "member", f"quota-{index}", f"vpn-quota-{index}", f"web-quota-{index}", state)
    barrier = Barrier(2)

    def reserve(index: int) -> str:
        barrier.wait()
        try:
            Store(database).reserve_device("member", f"race-{index}", f"vpn-race-{index}", f"web-race-{index}")
            return "reserved"
        except DeviceQuotaExceeded:
            return "quota"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(reserve, (1, 2)))
    assert sorted(outcomes) == ["quota", "reserved"]
    assert len(Store(database).list_devices("member")) == 10


def test_v1_migration_revokes_unbound_sessions(tmp_path) -> None:
    database = tmp_path / "v1.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO schema_metadata VALUES ('schema_version', '1');
            CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            INSERT INTO users VALUES ('legacy', 'hash', 'admin', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
            CREATE TABLE user_networks (username TEXT NOT NULL, network TEXT NOT NULL, PRIMARY KEY (username, network));
            CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, csrf_hash TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, created_at TEXT NOT NULL);
            INSERT INTO sessions VALUES ('old', 'legacy', 'csrf', '2099-01-01T00:00:00Z', NULL, '2026-01-01T00:00:00Z');
            CREATE TABLE login_attempts (source_ip TEXT NOT NULL, username TEXT NOT NULL, window_started_at TEXT NOT NULL, failure_count INTEGER NOT NULL, PRIMARY KEY (source_ip, username));
            CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL, actor TEXT, source_ip TEXT, action TEXT NOT NULL, target TEXT, outcome TEXT NOT NULL);
            """
        )
    Store(database).initialize()
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT value FROM schema_metadata WHERE key = 'schema_version'").fetchone()[0] == "2"
        old_session = connection.execute("SELECT device_id, web_certificate_id, revoked_at FROM sessions WHERE token_hash = 'old'").fetchone()
        assert old_session[0] is None and old_session[1] is None and old_session[2] is not None
