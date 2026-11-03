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

    page.locator('.nav-item[data-page="devices"]').click()
    expect(page.locator("#devices-page")).to_be_visible()
    expect(page.locator("#device-account-select")).to_be_enabled(timeout=15_000)

    page.locator('.nav-item[data-page="users"]').click()
    expect(page.locator("#users-page")).to_be_visible()
    expect(page.locator("#users-content")).to_be_visible(timeout=15_000)
    expect(page.locator("#users-body")).to_contain_text("adminone")

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


def test_member_can_read_own_records_but_cannot_see_admin_management(context, live_env):
    page = context.new_page()
    _login(page, live_env, MEMBER)
    expect(page.get_by_role("heading", name="我的设备记录", exact=True)).to_be_visible()
    expect(page.locator("#own-devices-content")).to_be_visible(timeout=15_000)
    for page_name in ("users", "devices", "audit"):
        expect(page.locator(f'.nav-item[data-page="{page_name}"]')).to_be_hidden()
    expect(page.get_by_role("button", name="退出登录", exact=True)).to_be_visible()
    _capture(page, "member-overview")
