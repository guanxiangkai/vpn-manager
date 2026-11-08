"""隔离 Linux 环境中的密码认证浏览器验收。

仅从 ``VPN_MANAGER_TEST_URL`` 读取 HTTPS 入口。下方两组密码仅属于
隔离测试夹具账户，不得替换为生产凭据。
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest

playwright = pytest.importorskip("playwright.sync_api")
from playwright.sync_api import expect  # noqa: E402


ADMIN = ("adminone", "correct-horse-admin-one")
MEMBER = ("member", "correct-horse-member")


def _required_environment() -> dict[str, str]:
    url = os.environ.get("VPN_MANAGER_TEST_URL")
    if not url:
        pytest.skip("live browser acceptance requires VPN_MANAGER_TEST_URL")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc:
        pytest.fail("VPN_MANAGER_TEST_URL must be an absolute https URL")
    return {"url": url.rstrip("/") + "/"}


@pytest.fixture(scope="module")
def live_env() -> dict[str, str]:
    return _required_environment()


@pytest.fixture(scope="module")
def browser():
    with playwright.sync_playwright() as instance:
        browser = instance.chromium.launch()
        yield browser
        browser.close()


@pytest.fixture
def context(browser):
    # 隔离验收使用临时自签 HTTPS 证书；忽略其链错误不等于添加客户端认证。
    context = browser.new_context(ignore_https_errors=True)
    yield context
    context.close()


def _login(page, env: dict[str, str], credentials: tuple[str, str]) -> None:
    username, password = credentials
    page.goto(env["url"], wait_until="domcontentloaded")
    expect(page.locator("#login-view")).to_be_visible(timeout=15_000)
    expect(page.locator("#app-view")).to_be_hidden()
    expect(page.locator("#login-submit")).to_be_enabled(timeout=15_000)
    # 页面同时保留隐藏的账户编辑对话框，限定到实际登录表单。
    form = page.locator("#login-form")
    form.get_by_label("账户名", exact=True).fill(username)
    form.get_by_label("密码", exact=True).fill(password)
    form.get_by_role("button", name="登录", exact=True).click()
    expect(page.locator("#app-view")).to_be_visible(timeout=15_000)
    expect(page.locator("#login-view")).to_be_hidden()
    expect(form.get_by_label("密码", exact=True)).to_have_value("")
    expect(page.locator("#signed-in-user")).to_contain_text(username, timeout=15_000)


def _capture(page, name: str) -> None:
    """只为隔离测试夹具保留页面截图，不采集生产账户。"""
    output = os.environ.get("VPN_MANAGER_BROWSER_EVIDENCE")
    if output:
        directory = Path(output)
        directory.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(directory / f"{name}.png"), full_page=True)


def test_anonymous_api_request_is_rejected(context, live_env):
    page = context.new_page()
    page.goto(live_env["url"], wait_until="domcontentloaded")
    response = page.evaluate(
        """async () => {
          const response = await fetch('/api/auth/me', { credentials: 'include' });
          return { status: response.status, body: await response.json() };
        }"""
    )
    assert response["status"] == 401
    assert response["body"]["error"]["code"] == "authentication_required"
    expect(page.locator("#login-view")).to_be_visible()
    expect(page.locator("#app-view")).to_be_hidden()
    _capture(page, "anonymous-login")


def test_admin_login_refresh_pages_and_logout(context, live_env):
    page = context.new_page()
    _login(page, live_env, ADMIN)

    # 重载会清空页面内存中的 CSRF；界面必须通过 POST refresh 恢复会话。
    page.reload(wait_until="domcontentloaded")
    expect(page.locator("#app-view")).to_be_visible(timeout=15_000)
    expect(page.locator("#login-view")).to_be_hidden()
    expect(page.locator("#signed-in-user")).to_contain_text("adminone", timeout=15_000)
    _capture(page, "admin-overview")

    expect(page.locator('.nav-item[data-page="devices"], #devices-page, #my-devices-title, #device-dialog')).to_have_count(0)

    page.locator('.nav-item[data-page="users"]').click()
    expect(page.locator("#users-page")).to_be_visible()
    expect(page.locator("#users-content")).to_be_visible(timeout=15_000)
    expect(page.locator("#users-body")).to_contain_text("adminone")
    expect(page.locator("#users-body").get_by_role("button", name="设备记录")).to_have_count(0)

    page.locator('.nav-item[data-page="audit"]').click()
    expect(page.locator("#audit-page")).to_be_visible()
    expect(page.locator("#audit-content")).to_be_visible(timeout=15_000)
    assert page.locator("#audit-body tr").count() > 0
    _capture(page, "admin-audit")

    page.get_by_role("button", name="退出登录", exact=True).click()
    expect(page.locator("#login-view")).to_be_visible(timeout=15_000)
    expect(page.locator("#app-view")).to_be_hidden()

    page.reload(wait_until="domcontentloaded")
    expect(page.locator("#login-view")).to_be_visible(timeout=15_000)
    expect(page.locator("#app-view")).to_be_hidden()


def test_admin_live_connections_refreshes_and_adapts_to_narrow_screens(context, live_env):
    page = context.new_page()
    _login(page, live_env, ADMIN)
    page.clock.install()
    calls = []

    def respond(route):
        calls.append(route.request.url)
        number = len(calls)
        if number == 3:
            route.fulfill(status=503, json={"detail": "Gateway snapshot unavailable"})
            return

        sessions = [{
            "session_id": "1",
            "remote_address": "198.51.100.2",
            "remote_port": 4500,
            "virtual_addresses": ["10.77.64.2"],
            "connected_at": "2026-01-01T00:00:00Z",
        }]
        if number > 1:
            sessions.append({
                "session_id": "2",
                "remote_address": "2001:db8::2",
                "remote_port": 4500,
                "virtual_addresses": ["10.77.64.3"],
                "connected_at": None,
            })
        route.fulfill(status=200, json={
            "sampled_at": f"2026-01-01T00:0{number}:00Z",
            "accounts": [
                {"username": "member", "sessions": []},
                {"username": "adminone", "sessions": sessions},
            ],
        })

    page.route("**/api/admin/vpn-connections", respond)
    nav = page.locator('.nav-item[data-page="connections"]')
    nav.click()
    expect(page.locator("#connections-online")).to_have_text("1")
    expect(page.locator("#connections-account-total")).to_have_text("/ 2")
    expect(page.locator("#connections-total")).to_have_text("1")
    expect(page.locator(".connection-account h3").first).to_have_text("adminone")
    expect(page.locator("#connections-list")).to_contain_text("在线")
    expect(page.locator("#connections-list")).to_contain_text("离线")
    expect(page.locator("#connections-page")).to_contain_text("会话数可能与实际设备数不同")
    expect(page.locator("#connections-list")).to_contain_text("198.51.100.2:4500")
    assert len(calls) == 1

    page.clock.run_for(15_100)
    expect(page.locator("#connections-total")).to_have_text("2")
    expect(page.locator("#connections-sampled")).to_have_attribute("datetime", "2026-01-01T00:02:00Z")
    expect(page.locator("#connections-list")).to_contain_text("[2001:db8::2]:4500")
    detail = page.locator(".connection-detail").first
    assert detail.evaluate("el => getComputedStyle(el).gridTemplateColumns.split(' ').length") == 4
    _capture(page, "live-connections-desktop")
    page.set_viewport_size({"width": 390, "height": 844})
    assert detail.evaluate("el => getComputedStyle(el).gridTemplateColumns.split(' ').length") == 2
    assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
    _capture(page, "live-connections-mobile")

    page.clock.run_for(15_100)
    expect(page.locator("#connections-state")).to_contain_text("未知")
    expect(page.locator("#connections-content")).to_be_hidden()
    page.clock.run_for(15_100)
    expect(page.locator("#connections-content")).to_be_visible()
    expect(page.locator("#connections-sampled")).to_have_attribute("datetime", "2026-01-01T00:04:00Z")

    page.evaluate("""() => {
        Object.defineProperty(document, "hidden", { configurable: true, value: true });
        document.dispatchEvent(new Event("visibilitychange"));
    }""")
    page.clock.run_for(30_000)
    assert len(calls) == 4
    page.evaluate("""() => {
        delete document.hidden;
        document.dispatchEvent(new Event("visibilitychange"));
    }""")
    expect(page.locator("#connections-sampled")).to_have_attribute("datetime", "2026-01-01T00:05:00Z")

    page.locator('.nav-item[data-page="overview"]').click()
    page.clock.run_for(30_000)
    assert len(calls) == 5
    nav.click()
    expect(page.locator("#connections-sampled")).to_have_attribute("datetime", "2026-01-01T00:06:00Z")


def test_member_can_read_own_access_overview(context, live_env):
    page = context.new_page()
    _login(page, live_env, MEMBER)
    expect(page.get_by_role("heading", name="连接说明", exact=True)).to_be_visible()
    expect(page.locator("#my-devices-title")).to_have_count(0)
    for page_name in ("users", "networks", "audit", "connections"):
        expect(page.locator(f'.nav-item[data-page="{page_name}"]')).to_be_hidden()
    expect(page.get_by_role("button", name="退出登录", exact=True)).to_be_visible()
    _capture(page, "member-overview")
