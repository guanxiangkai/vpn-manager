"""系统管理员保护必须由服务端执行，不能依赖按钮是否可见。"""
import sqlite3

from fastapi.testclient import TestClient

from vpn_manager.app import ALLOWED_ORIGIN, SYSTEM_ADMIN_USERNAME, create_app
from vpn_manager.bootstrap import bootstrap


def test_system_admin_cannot_be_disabled_or_demoted_even_with_another_admin(tmp_path):
    path = tmp_path / "manager.sqlite3"
    bootstrap(str(path), [
        {"username": SYSTEM_ADMIN_USERNAME, "password": "protected-admin-test-password", "role": "admin", "networks": ["home", "work"]},
        {"username": "otheradmin", "password": "other-admin-test-password", "role": "admin", "networks": ["work"]},
    ])
    client = TestClient(create_app(path), base_url=ALLOWED_ORIGIN)
    result = client.post("/api/auth/login", headers={"Origin": ALLOWED_ORIGIN}, json={"username": "otheradmin", "password": "other-admin-test-password"})
    headers = {"Origin": ALLOWED_ORIGIN, "X-CSRF-Token": result.json()["csrf_token"]}
    users = client.get("/api/admin/users").json()
    assert next(user for user in users if user["username"] == SYSTEM_ADMIN_USERNAME)["protected"] is True
    assert next(user for user in users if user["username"] == "otheradmin")["protected"] is False
    with sqlite3.connect(path) as connection:
        before = connection.execute("SELECT * FROM users ORDER BY username").fetchall()
        audit_count = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    for method, suffix, body in [
        ("POST", "/deactivate", {}),
        ("PATCH", "", {"active": False}),
        ("PATCH", "", {"role": "user", "networks": ["work"]}),
    ]:
        response = client.request(method, f"/api/admin/users/{SYSTEM_ADMIN_USERNAME}{suffix}", headers=headers, json=body)
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "system_admin_protected"
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT * FROM users ORDER BY username").fetchall() == before
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == audit_count
        assert connection.execute("SELECT COUNT(*) FROM gateway_outbox").fetchone()[0] == 0
    assert client.get("/api/auth/me").status_code == 200


def test_system_admin_login_and_refresh_expose_same_protection(tmp_path):
    path = tmp_path / "manager.sqlite3"
    bootstrap(str(path), [{"username": SYSTEM_ADMIN_USERNAME, "password": "protected-admin-test-password", "role": "admin", "networks": ["home", "work"]}])
    client = TestClient(create_app(path), base_url=ALLOWED_ORIGIN)
    result = client.post("/api/auth/login", headers={"Origin": ALLOWED_ORIGIN}, json={"username": SYSTEM_ADMIN_USERNAME, "password": "protected-admin-test-password"})
    assert result.json()["user"]["protected"] is True
    assert client.get("/api/auth/me").json()["protected"] is True
    assert client.post("/api/auth/refresh", headers={"Origin": ALLOWED_ORIGIN}).json()["protected"] is True
