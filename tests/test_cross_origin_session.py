"""OSS 前端与独立 API 的会话、跨域和撤权边界。"""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from vpn_manager.app import ALLOWED_ORIGIN, create_app
from vpn_manager.bootstrap import bootstrap
from vpn_manager.security import COOKIE_NAME, token_hash


@pytest.fixture()
def client(tmp_path):
    database = tmp_path / "accounts.sqlite3"
    bootstrap(str(database), [
        {"username": "owner", "password": "owner-example-password", "role": "admin", "networks": ["home", "work"]},
        {"username": "member", "password": "member-example-password", "role": "user", "networks": ["work"]},
    ])
    app = create_app(database, session_transport="bearer")
    with TestClient(app, base_url="https://198.51.100.10:8443") as instance:
        yield instance, database


def sign_in(client, username="owner"):
    response = client.post("/api/auth/login", headers={"Origin": ALLOWED_ORIGIN}, json={"username": username, "password": f"{username}-example-password"})
    assert response.status_code == 200
    assert "set-cookie" not in response.headers
    body = response.json()
    return {"Origin": ALLOWED_ORIGIN, "Authorization": f"Bearer {body['session_token']}", "X-CSRF-Token": body["csrf_token"]}


def test_cross_site_login_permissions_and_hashed_session(client):
    browser, database = client
    owner, member = sign_in(browser), sign_in(browser, "member")
    assert browser.get("/api/auth/me", headers={"Origin": ALLOWED_ORIGIN}).status_code == 401
    assert browser.get("/api/auth/me", headers=owner).json()["networks"] == ["home", "work"]
    assert browser.get("/api/auth/me", headers=member).json()["networks"] == ["work"]
    assert browser.get("/api/admin/users", headers=member).status_code == 403
    assert browser.get("/api/admin/audit", headers=member).status_code == 403
    with sqlite3.connect(database) as connection:
        stored = {row[0] for row in connection.execute("SELECT token_hash FROM sessions")}
    token = owner["Authorization"].removeprefix("Bearer ")
    assert token not in stored and token_hash(token) in stored


def test_cors_allows_exact_origin_and_authorization_header_only(client):
    browser, _ = client
    preflight = {"Origin": ALLOWED_ORIGIN, "Access-Control-Request-Method": "PATCH", "Access-Control-Request-Headers": "authorization,content-type,x-csrf-token"}
    response = browser.options("/api/admin/users/member", headers=preflight)
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
    assert "access-control-allow-credentials" not in response.headers
    for origin in ["https://evil.example", "null", "http://slimjoy.cn", "https://slimjoy.cn.evil.example"]:
        response = browser.options("/api/admin/users", headers={**preflight, "Origin": origin})
        assert response.status_code == 403
        assert "access-control-allow-origin" not in response.headers
        response = browser.post("/api/auth/login", headers={"Origin": origin}, json={"username": "owner", "password": "owner-example-password"})
        assert response.status_code == 403


def test_bearer_mode_rejects_cookie_and_ambiguous_authorization(client):
    browser, _ = client
    headers = sign_in(browser)
    token = headers["Authorization"].removeprefix("Bearer ")
    assert browser.get("/api/auth/me", headers={"Origin": ALLOWED_ORIGIN, "Cookie": f"{COOKIE_NAME}={token}"}).status_code == 401
    assert browser.get("/api/auth/me", headers={**headers, "Cookie": f"{COOKIE_NAME}={token}"}).status_code == 401
    assert browser.get("/api/auth/me", headers=[("Origin", ALLOWED_ORIGIN), ("Authorization", headers["Authorization"]), ("Authorization", headers["Authorization"])]).status_code == 401
    for value in [f"Basic {token}", f"Bearer  {token}", "Bearer broken"]:
        assert browser.get("/api/auth/me", headers={"Origin": ALLOWED_ORIGIN, "Authorization": value}).status_code == 401


def test_public_api_checks_origin_before_read_write_and_preflight(client):
    browser, database = client
    owner = sign_in(browser)
    with sqlite3.connect(database) as connection:
        attempts_before = connection.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0]
    for origins in [[], [("Origin", "null")], [("Origin", "https://evil.example")],
                    [("Origin", "http://slimjoy.cn")], [("Origin", "https://slimjoy.cn.evil.example")],
                    [("Origin", ALLOWED_ORIGIN), ("Origin", ALLOWED_ORIGIN)],
                    [("Origin", ALLOWED_ORIGIN), ("Origin", "https://evil.example")]]:
        headers = [(k,v) for k,v in owner.items() if k != "Origin"] + origins
        requests = [
            ("GET", "/api/auth/me", {}),
            ("GET", "/api/admin/users", {}),
            ("GET", "/api/admin/audit", {}),
            ("PATCH", "/api/admin/users/member", {"json": {"active": False}}),
            ("POST", "/api/auth/login", {"json": {"username": "owner", "password": "owner-example-password"}}),
            ("OPTIONS", "/api/admin/users", {}),
        ]
        for method, path, options in requests:
            response = browser.request(method, path, headers=headers, **options)
            assert response.status_code == 403
            assert response.json()["error"]["code"] == "origin_forbidden"
            assert "access-control-allow-origin" not in response.headers
            assert response.headers["cache-control"] == "no-store"
    # 被来源检查拒绝的请求不会冻结账户或进入账户修改逻辑。
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0] == attempts_before
    assert browser.get("/api/admin/users", headers=owner).status_code == 200
    assert sign_in(browser, "member")
    assert browser.get("/health").json() == {"message": "ok"}


def test_mutations_recheck_origin_csrf_and_revoke_changed_accounts(client):
    browser, _ = client
    owner, member = sign_in(browser), sign_in(browser, "member")
    url, change = "/api/admin/users/member", {"active": False}
    assert browser.patch(url, headers={**owner, "Origin": "https://evil.example"}, json=change).status_code == 403
    assert browser.patch(url, headers={k: v for k, v in owner.items() if k != "X-CSRF-Token"}, json=change).status_code == 403
    assert browser.patch(url, headers=member, json=change).status_code == 403
    assert browser.patch(url, headers=owner, json=change).status_code == 200
    assert browser.get("/api/auth/me", headers=member).status_code == 401
    events = browser.get("/api/admin/audit", headers=owner).json()["items"]
    assert any(event["action"] == "login" and event["actor"] == "member" and event["outcome"] == "success" for event in events)
    assert browser.post("/api/auth/logout", headers=owner).status_code == 200
    assert browser.get("/api/auth/me", headers=owner).status_code == 401


def test_cookie_mode_does_not_accept_header_token(tmp_path):
    # 使用独立数据库，避免任何认证方式的回退掩盖错误配置。
    app = create_app(tmp_path / "cookie.sqlite3")
    with TestClient(app) as browser:
        assert browser.get("/api/auth/me", headers={"Authorization": "Bearer " + "a" * 43}).status_code == 401
    with pytest.raises(ValueError, match="会话传输"):
        create_app(tmp_path / "invalid.sqlite3", session_transport="automatic")
