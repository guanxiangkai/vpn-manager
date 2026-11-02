"""Linux Chromium 双 HTTPS 来源的 Bearer 会话验收。"""
from __future__ import annotations
import os
from urllib.parse import urlsplit
import pytest
playwright = pytest.importorskip("playwright.sync_api")
from playwright.sync_api import expect  # noqa: E402
ADMIN = ("adminone", "correct-horse-admin-one")
MEMBER = ("member", "correct-horse-member")
def _env():
    frontend, api = os.environ.get("VPN_MANAGER_CROSS_ORIGIN_FRONTEND"), os.environ.get("VPN_MANAGER_CROSS_ORIGIN_API")
    if not frontend or not api: pytest.skip("跨站浏览器验收需要两个 HTTPS 来源")
    for value in (frontend, api):
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.netloc: pytest.fail("跨站来源必须是绝对 HTTPS URL")
    if urlsplit(frontend).netloc == urlsplit(api).netloc: pytest.fail("前端和 API 必须使用不同 origin")
    return {"frontend": frontend.rstrip("/"), "api": api.rstrip("/")}
@pytest.fixture(scope="module")
def env(): return _env()
@pytest.fixture(scope="module")
def browser():
    with playwright.sync_playwright() as instance:
        browser = instance.chromium.launch(); yield browser; browser.close()
@pytest.fixture
def context(browser):
    context = browser.new_context(ignore_https_errors=True); yield context; context.close()
def _login(page, env, credentials):
    page.goto(env["frontend"], wait_until="domcontentloaded")
    expect(page.locator("#login-view")).to_be_visible(timeout=15_000)
    form = page.locator("#login-form")
    form.get_by_label("账户名", exact=True).fill(credentials[0]); form.get_by_label("密码", exact=True).fill(credentials[1])
    with page.expect_response(lambda response: response.url.endswith("/api/auth/login")) as login_response:
        form.get_by_role("button", name="登录", exact=True).click()
    token = login_response.value.json()["session_token"]
    expect(page.locator("#app-view")).to_be_visible(timeout=15_000); expect(page.locator("#signed-in-user")).to_contain_text(credentials[0]); return token
def test_cross_origin_bearer_permissions_refresh_and_revocation(context, env):
    page = context.new_page(); _login(page, env, ADMIN)
    expect(page.locator("#network-list")).to_contain_text("家庭"); expect(page.locator("#network-list")).to_contain_text("工作")
    expect(page.locator("#vpn-integration-state")).to_contain_text("尚未切换")
    assert context.cookies() == []; assert page.evaluate("() => [localStorage.length, sessionStorage.length]") == [0, 0]
    page.locator('.nav-item[data-page="users"]').click(); expect(page.locator("#users-page")).to_be_visible(); expect(page.locator("#users-body")).to_contain_text("member")
    page.reload(wait_until="domcontentloaded"); expect(page.locator("#login-view")).to_be_visible(timeout=15_000)
    admin_token = _login(page, env, ADMIN); page.get_by_role("button", name="退出登录", exact=True).click(); expect(page.locator("#login-view")).to_be_visible(timeout=15_000)
    assert page.evaluate("""async args => (await fetch(args.api + '/api/auth/me', {headers: {Authorization: 'Bearer ' + args.token}})).status""", {"api": env["api"], "token": admin_token}) == 401
    member_token = _login(page, env, MEMBER); expect(page.locator("#network-list")).to_contain_text("工作"); expect(page.locator("#network-list")).not_to_contain_text("家庭"); expect(page.locator("#own-devices-content")).to_be_visible(timeout=15_000)
    for name in ("users", "devices", "audit"): expect(page.locator(f'.nav-item[data-page="{name}"]')).to_be_hidden()
    assert page.evaluate("""async args => (await fetch(args.api + '/api/admin/users', {headers: {Authorization: 'Bearer ' + args.token}})).status""", {"api": env["api"], "token": member_token}) == 403
