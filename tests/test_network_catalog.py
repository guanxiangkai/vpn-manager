"""网络目录必须可维护，但不能借资料编辑扩大实际 VPN 权限。"""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from vpn_manager.app import ALLOWED_ORIGIN, create_app
from vpn_manager.bootstrap import bootstrap
from vpn_manager.store import SCHEMA_VERSION, Store


@pytest.fixture()
def setup(tmp_path):
    path = tmp_path / "manager.sqlite3"
    bootstrap(path, [
        {"username": "adminone", "password": "catalog-admin-password", "role": "admin", "networks": ["home", "work"]},
        {"username": "member", "password": "catalog-member-password", "role": "user", "networks": ["work"]},
    ])
    client = TestClient(create_app(path), base_url=ALLOWED_ORIGIN)
    response = client.post("/api/auth/login", headers={"Origin": ALLOWED_ORIGIN}, json={"username": "adminone", "password": "catalog-admin-password"})
    headers = {"Origin": ALLOWED_ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}
    return path, client, headers


def test_catalog_edit_has_stable_identity_and_concurrency_guard(setup):
    path, client, headers = setup
    before = Store(path).find_user("adminone")["networks"]
    updated = client.patch("/api/admin/networks/home", headers=headers, json={"name": "住宅内网", "description": "家庭 NAS\n路由器管理", "version": 1})
    assert updated.status_code == 200
    assert updated.json()["id"] == "home"
    assert updated.json()["version"] == 2
    assert updated.json()["description"] == "家庭 NAS\n路由器管理"
    assert client.get("/api/networks").json()[0]["name"] == "住宅内网"
    stale = client.patch("/api/admin/networks/home", headers=headers, json={"name": "旧窗口覆盖", "version": 1})
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "network_version_conflict"
    assert Store(path).find_user("adminone")["networks"] == before
    assert client.get("/api/auth/me").status_code == 200
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM gateway_outbox").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM audit_events WHERE action='network_update'").fetchone()[0] == 1


def test_new_environment_is_draft_and_cannot_be_granted(setup):
    path, client, headers = setup
    response = client.post("/api/admin/networks", headers=headers, json={"name": "分支机构", "description": "待验证的新增环境"})
    assert response.status_code == 201
    draft = response.json()
    assert draft["state"] == "draft" and draft["id"].startswith("net-")
    assert len(client.get("/api/admin/networks").json()) == 3
    assert len(client.get("/api/networks").json()) == 2
    assert client.patch("/api/admin/users/adminone", headers=headers, json={"networks": [draft["id"]]}).status_code == 422
    assert client.post("/api/admin/networks", headers=headers, json={"name": "分支机构"}).status_code == 409
    assert client.patch("/api/admin/networks/work", headers=headers, json={"name": "家庭", "version": 1}).status_code == 409
    assert client.post("/api/admin/networks", headers=headers, json={"name": "   "}).status_code == 422
    assert client.post("/api/admin/networks", headers=headers, json={"name": "分\n部"}).status_code == 422
    assert client.post("/api/admin/networks", headers=headers, json={"name": "分部", "description": "不可见\x00字符"}).status_code == 422
    assert client.post("/api/admin/networks", headers=headers, json={"name": "分部", "state": "existing"}).status_code == 422
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM gateway_outbox").fetchone()[0] == 0


def test_catalog_authentication_csrf_and_member_resource_scope(setup):
    path, admin, headers = setup
    anonymous = TestClient(create_app(path), base_url=ALLOWED_ORIGIN)
    assert anonymous.get("/api/networks").status_code == 401
    assert admin.post("/api/admin/networks", json={"name": "未授权草稿"}).status_code == 403
    assert admin.post("/api/admin/networks", headers={**headers, "Origin": "https://evil.example"}, json={"name": "未授权草稿"}).status_code == 403
    member = TestClient(create_app(path), base_url=ALLOWED_ORIGIN)
    result = member.post("/api/auth/login", headers={"Origin": ALLOWED_ORIGIN}, json={"username": "member", "password": "catalog-member-password"})
    member_headers = {"Origin": ALLOWED_ORIGIN, "X-CSRF-Token": result.json()["csrf_token"]}
    assert [item["id"] for item in member.get("/api/networks").json()] == ["work"]
    assert member.get("/api/admin/networks").status_code == 403
    assert member.post("/api/admin/networks", headers=member_headers, json={"name": "越权草稿"}).status_code == 403
    assert member.patch("/api/admin/networks/work", headers=member_headers, json={"name": "越权改名", "version": 1}).status_code == 403


def test_v6_additive_migration_preserves_accounts_sessions_and_permissions(setup):
    path, client, headers = setup
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE network_catalog")
        connection.execute("UPDATE schema_metadata SET value='6' WHERE key='schema_version'")
        tables = ["users", "user_networks", "sessions", "gateway_accounts", "gateway_outbox"]
        before = {name: connection.execute(f"SELECT * FROM {name}").fetchall() for name in tables}
    store = Store(path)
    store.initialize()
    store.initialize()
    with sqlite3.connect(path) as connection:
        assert before == {name: connection.execute(f"SELECT * FROM {name}").fetchall() for name in tables}
        assert connection.execute("SELECT value FROM schema_metadata WHERE key='schema_version'").fetchone()[0] == str(SCHEMA_VERSION)
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert client.get("/api/auth/me").status_code == 200
    assert len(store.list_networks()) == 2
