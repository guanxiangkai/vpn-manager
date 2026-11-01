# 路由依赖定义在 create_app 内，注解需立即求值以保留局部 Depends 引用。

import sqlite3
from ipaddress import ip_address
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any

from fastapi import Cookie, Depends, FastAPI, Header, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .device_verification import DeviceVerifier, VerifiedDevicePrincipal
from .models import AuditPage, DeviceReserve, DeviceView, ErrorResponse, LoginRequest, LoginResponse, MeResponse, MessageResponse, UserCreate, UserUpdate, UserView
from .security import COOKIE_NAME, SESSION_TTL, hash_password, needs_rehash, new_secret, utc_now, utc_text, verify_password
from .store import DeviceConflict, DeviceQuotaExceeded, Store

ALLOWED_ORIGIN = "https://slimjoy.cn"
LOGIN_WINDOW = timedelta(minutes=15)
LOGIN_ATTEMPT_LIMIT = 5
MAX_REQUEST_BODY_BYTES = 16 * 1024


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message


def public_device(device: dict[str, Any]) -> dict[str, Any]:
    state = device["state"]
    manager_access = "allowed" if state == "active" else "revoked"
    gateway_revocation = "pending" if state == "revoking" else ("acknowledged" if state == "revoked" else "not_requested")
    return {**device, "manager_access": manager_access, "gateway_revocation": gateway_revocation}


class BoundedBodyMiddleware:
    """在 FastAPI 解析 JSON 前，只缓存大小受限的 HTTP 请求体。"""

    def __init__(self, app: Any, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        raw_length = next((value for key, value in scope.get("headers", []) if key == b"content-length"), None)
        if raw_length is not None:
            try:
                if int(raw_length) > self.max_bytes:
                    await self._too_large(send)
                    return
            except ValueError:
                await self._invalid_length(send)
                return
        events: list[dict[str, Any]] = []
        size = 0
        while True:
            event = await receive()
            events.append(event)
            if event["type"] == "http.request":
                size += len(event.get("body", b""))
                if size > self.max_bytes:
                    await self._too_large(send)
                    return
                if not event.get("more_body", False):
                    break
            elif event["type"] == "http.disconnect":
                break

        async def replay() -> dict[str, Any]:
            if events:
                return events.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay, send)

    @staticmethod
    async def _send_error(send: Any, code: str, message: str, status: int) -> None:
        payload = f'{{"error":{{"code":"{code}","message":"{message}"}}}}'.encode("utf-8")
        await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode("ascii"))]})
        await send({"type": "http.response.body", "body": payload})

    async def _too_large(self, send: Any) -> None:
        await self._send_error(send, "request_too_large", "请求体过大。", 413)

    async def _invalid_length(self, send: Any) -> None:
        await self._send_error(send, "invalid_request", "请求无效。", 400)


class DefaultDeviceLockMiddleware:
    """未配置真实证书验证器时，在路由执行前拒绝访问。"""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http" and scope["path"].startswith("/api/") and scope["app"].state.device_verifier is None:
            payload = '{"error":{"code":"device_verification_unavailable","message":"尚未配置设备验证服务。"}}'.encode("utf-8")
            await send({"type": "http.response.start", "status": 503, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode("ascii"))]})
            await send({"type": "http.response.body", "body": payload})
            return
        await self.app(scope, receive, send)


def source_ip(request: Request) -> str | None:
    # 不使用 X-Forwarded-For 等可受代理控制的请求头判断来源。
    return request.client.host if request.client else None


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {key: user[key] for key in ("username", "role", "networks", "active", "created_at", "updated_at")}


def require_origin(request: Request) -> None:
    if request.headers.get("origin") != ALLOWED_ORIGIN:
        raise ApiError(403, "origin_forbidden", "请求来源不被允许。")


def create_app(database_path: str | Path = "./slimjoy-vpn-manager.sqlite3", device_verifier: DeviceVerifier | None = None) -> FastAPI:
    """创建应用并显式初始化数据库；导入模块时不执行初始化。"""
    store = Store(database_path)
    store.initialize()
    app = FastAPI(title="VPN 管理器", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    app.state.device_verifier = device_verifier
    app.add_middleware(BoundedBodyMiddleware, max_bytes=MAX_REQUEST_BODY_BYTES)
    app.add_middleware(DefaultDeviceLockMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[ALLOWED_ORIGIN],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
        max_age=600,
    )

    @app.exception_handler(ApiError)
    async def api_error_handler(_: Request, error: ApiError) -> JSONResponse:
        return JSONResponse(content={"error": {"code": error.code, "message": error.message}}, status_code=error.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_: Request, __: RequestValidationError) -> JSONResponse:
        return JSONResponse(content={"error": {"code": "invalid_request", "message": "请求无效。"}}, status_code=422)

    def current_device(request: Request) -> VerifiedDevicePrincipal:
        verifier = app.state.device_verifier
        if verifier is None:
            raise ApiError(503, "device_verification_unavailable", "尚未配置设备验证服务。")
        principal = verifier.verify(request)
        if principal is None:
            raise ApiError(403, "device_verification_required", "需要经过验证的管理设备。")
        if store.active_device(principal) is None:
            raise ApiError(403, "device_not_active", "此管理设备尚未启用或已被撤销。")
        return principal

    def current_user(device: Annotated[VerifiedDevicePrincipal, Depends(current_device)], session_token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None) -> dict[str, Any]:
        if not session_token:
            raise ApiError(401, "authentication_required", "请先登录。")
        user = store.session_user(session_token, device)
        if user is None:
            raise ApiError(401, "authentication_required", "请先登录。")
        return user

    def csrf_protected(
        request: Request,
        device: Annotated[VerifiedDevicePrincipal, Depends(current_device)],
        user: Annotated[dict[str, Any], Depends(current_user)],
        session_token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
        csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
    ) -> dict[str, Any]:
        require_origin(request)
        if session_token is None or csrf_token is None or not store.csrf_valid(session_token, csrf_token, device):
            raise ApiError(403, "csrf_invalid", "CSRF 校验失败，请刷新页面后重试。")
        return user

    def admin_user(request: Request, user: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
        if user["role"] != "admin":
            with store.write_transaction() as connection:
                store.audit(connection, actor=user["username"], source_ip=source_ip(request), action="admin_access", target=request.url.path, outcome="denied")
            raise ApiError(403, "permission_denied", "需要管理员权限。")
        return user

    def admin_mutation_user(
        request: Request,
        user: Annotated[dict[str, Any], Depends(csrf_protected)],
    ) -> dict[str, Any]:
        if user["role"] != "admin":
            with store.write_transaction() as connection:
                store.audit(connection, actor=user["username"], source_ip=source_ip(request), action="admin_access", target=request.url.path, outcome="denied")
            raise ApiError(403, "permission_denied", "需要管理员权限。")
        return user

    @app.get("/health", response_model=MessageResponse)
    def health(request: Request) -> dict[str, str]:
        try:
            is_loopback = request.client is not None and ip_address(request.client.host).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            raise ApiError(404, "not_found", "未找到请求的资源。")
        return {"message": "ok"}

    @app.post("/api/auth/login", response_model=LoginResponse, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 429: {"model": ErrorResponse}})
    def login(payload: LoginRequest, request: Request, response: Response, device: Annotated[VerifiedDevicePrincipal, Depends(current_device)]) -> dict[str, Any]:
        require_origin(request)
        if payload.username != device.account_id:
            raise ApiError(403, "device_account_mismatch", "已验证设备未绑定此账户。")
        now = utc_now()
        ip = source_ip(request)
        token, csrf = new_secret(), new_secret()
        login_error: ApiError | None = None
        user: dict[str, Any] | None = None
        with store.write_transaction() as connection:
            attempt = connection.execute(
                "SELECT * FROM login_attempts WHERE source_ip IS ? AND username = ?", (ip, payload.username)
            ).fetchone()
            if attempt is not None:
                started = attempt["window_started_at"].replace("Z", "+00:00")
                from datetime import datetime
                if now - datetime.fromisoformat(started) >= LOGIN_WINDOW:
                    connection.execute("DELETE FROM login_attempts WHERE source_ip IS ? AND username = ?", (ip, payload.username))
                    attempt = None
                elif attempt["failure_count"] >= LOGIN_ATTEMPT_LIMIT:
                    store.audit(connection, actor=payload.username, source_ip=ip, action="login", target=payload.username, outcome="failure")
                    login_error = ApiError(429, "rate_limited", "登录尝试次数过多，请稍后重试。")
            if login_error is None:
                row = connection.execute("SELECT * FROM users WHERE username = ?", (payload.username,)).fetchone()
                user = store.user_from_row(connection, row)
                valid = user is not None and user["active"] and verify_password(user["password_hash"], payload.password.get_secret_value())
            else:
                valid = False
            if login_error is None and not valid:
                if attempt is None:
                    connection.execute("INSERT INTO login_attempts(source_ip, username, window_started_at, failure_count) VALUES (?, ?, ?, 1)", (ip, payload.username, utc_text(now)))
                else:
                    connection.execute("UPDATE login_attempts SET failure_count = failure_count + 1 WHERE source_ip IS ? AND username = ?", (ip, payload.username))
                store.audit(connection, actor=payload.username, source_ip=ip, action="login", target=payload.username, outcome="failure")
                login_error = ApiError(401, "invalid_credentials", "账户名或密码错误。")
            if login_error is None:
                assert user is not None
                connection.execute("DELETE FROM login_attempts WHERE source_ip IS ? AND username = ?", (ip, payload.username))
                if needs_rehash(user["password_hash"]):
                    connection.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?", (hash_password(payload.password.get_secret_value()), utc_text(), user["username"]))
                    user = store.user_from_row(connection, connection.execute("SELECT * FROM users WHERE username = ?", (user["username"],)).fetchone())
                store.add_session_in_transaction(connection, user["username"], device, token, csrf, now + SESSION_TTL)
                store.audit(connection, actor=user["username"], source_ip=ip, action="login", target=user["username"], outcome="success")
        if login_error is not None:
            raise login_error
        assert user is not None
        response.set_cookie(COOKIE_NAME, token, max_age=int(SESSION_TTL.total_seconds()), httponly=True, secure=True, samesite="lax", path="/")
        return {"user": public_user(user), "csrf_token": csrf}

    @app.post("/api/auth/logout", response_model=MessageResponse, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}})
    def logout(request: Request, response: Response, user: Annotated[dict[str, Any], Depends(csrf_protected)], device: Annotated[VerifiedDevicePrincipal, Depends(current_device)], session_token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None) -> dict[str, str]:
        assert session_token is not None
        with store.write_transaction() as connection:
            if not store.revoke_session_in_transaction(connection, session_token, device):
                raise ApiError(401, "authentication_required", "请先登录。")
            store.audit(connection, actor=user["username"], source_ip=source_ip(request), action="logout", target=user["username"], outcome="success")
        response.delete_cookie(COOKIE_NAME, path="/")
        return {"message": "已退出登录"}

    @app.get("/api/auth/me", response_model=MeResponse, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}})
    def me(request: Request, user: Annotated[dict[str, Any], Depends(current_user)], device: Annotated[VerifiedDevicePrincipal, Depends(current_device)], session_token: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None) -> dict[str, Any]:
        # 此 GET 请求会轮换 CSRF 令牌，必须先拒绝跨来源请求。
        require_origin(request)
        assert session_token is not None
        csrf_token = new_secret()
        if not store.rotate_csrf(session_token, csrf_token, device):
            raise ApiError(401, "authentication_required", "请先登录。")
        return {**public_user(user), "csrf_token": csrf_token}

    @app.get("/api/devices", response_model=list[DeviceView], responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}})
    def list_own_devices(user: Annotated[dict[str, Any], Depends(current_user)]) -> list[dict[str, Any]]:
        return [public_device(item) for item in store.list_devices(user["username"])]

    @app.post("/api/devices/{device_id}/revoke", response_model=DeviceView, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}})
    def revoke_own_device(device_id: str, request: Request, user: Annotated[dict[str, Any], Depends(csrf_protected)]) -> dict[str, Any]:
        device = store.mark_device_revoking(user["username"], device_id, actor=user["username"], source_ip=source_ip(request))
        if device is None:
            raise ApiError(404, "device_not_found", "未找到设备。")
        return public_device(device)

    @app.get("/api/admin/users", response_model=list[UserView], responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}})
    def list_users(_: Annotated[dict[str, Any], Depends(admin_user)]) -> list[dict[str, Any]]:
        return [public_user(item) for item in store.list_users()]

    @app.post("/api/admin/users", response_model=UserView, status_code=201, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 409: {"model": ErrorResponse}})
    def create_user(payload: UserCreate, request: Request, actor: Annotated[dict[str, Any], Depends(admin_mutation_user)]) -> dict[str, Any]:
        with store.write_transaction() as connection:
            now = utc_text()
            try:
                connection.execute("INSERT INTO users(username, password_hash, role, active, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)", (payload.username, hash_password(payload.password.get_secret_value()), payload.role, now, now))
            except sqlite3.IntegrityError:
                raise ApiError(409, "username_conflict", "此账户名已存在。")
            connection.executemany("INSERT INTO user_networks(username, network) VALUES (?, ?)", [(payload.username, network) for network in payload.networks])
            created = store.user_from_row(connection, connection.execute("SELECT * FROM users WHERE username = ?", (payload.username,)).fetchone())
            store.audit(connection, actor=actor["username"], source_ip=source_ip(request), action="user_create", target=payload.username, outcome="success")
        return public_user(created)

    def protect_last_admin(connection: Any, current: dict[str, Any], next_role: str, next_active: bool) -> None:
        if current["active"] and current["role"] == "admin" and (next_role != "admin" or not next_active):
            count = connection.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND active = 1").fetchone()["count"]
            if count <= 1:
                raise ApiError(409, "last_admin_protected", "不能移除、降级或停用最后一个有效管理员。")

    @app.patch("/api/admin/users/{username}", response_model=UserView, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}})
    def update_user(username: str, payload: UserUpdate, request: Request, actor: Annotated[dict[str, Any], Depends(admin_mutation_user)]) -> dict[str, Any]:
        with store.write_transaction() as connection:
            current = store.user_from_row(connection, connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone())
            if current is None:
                raise ApiError(404, "user_not_found", "未找到账户。")
            next_role = payload.role if payload.role is not None else current["role"]
            next_active = payload.active if payload.active is not None else current["active"]
            protect_last_admin(connection, current, next_role, next_active)
            changed = next_role != current["role"] or next_active != current["active"]
            next_networks = payload.networks if payload.networks is not None else current["networks"]
            changed = changed or next_networks != current["networks"] or payload.password is not None
            if changed:
                password_hash = hash_password(payload.password.get_secret_value()) if payload.password is not None else current["password_hash"]
                connection.execute("UPDATE users SET password_hash = ?, role = ?, active = ?, updated_at = ? WHERE username = ?", (password_hash, next_role, int(next_active), utc_text(), username))
                if payload.networks is not None:
                    connection.execute("DELETE FROM user_networks WHERE username = ?", (username,))
                    connection.executemany("INSERT INTO user_networks(username, network) VALUES (?, ?)", [(username, network) for network in next_networks])
                store.revoke_sessions(connection, username)
            store.audit(connection, actor=actor["username"], source_ip=source_ip(request), action="user_update", target=username, outcome="success")
            updated = store.user_from_row(connection, connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone())
        return public_user(updated)

    @app.post("/api/admin/users/{username}/deactivate", response_model=UserView, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}})
    def deactivate_user(username: str, request: Request, actor: Annotated[dict[str, Any], Depends(admin_mutation_user)]) -> dict[str, Any]:
        with store.write_transaction() as connection:
            current = store.user_from_row(connection, connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone())
            if current is None:
                raise ApiError(404, "user_not_found", "未找到账户。")
            protect_last_admin(connection, current, current["role"], False)
            if current["active"]:
                connection.execute("UPDATE users SET active = 0, updated_at = ? WHERE username = ?", (utc_text(), username))
                store.revoke_sessions(connection, username)
            store.audit(connection, actor=actor["username"], source_ip=source_ip(request), action="user_deactivate", target=username, outcome="success")
            updated = store.user_from_row(connection, connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone())
        return public_user(updated)

    @app.get("/api/admin/users/{username}/devices", response_model=list[DeviceView], responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}})
    def list_devices(username: str, _: Annotated[dict[str, Any], Depends(admin_user)]) -> list[dict[str, Any]]:
        return [public_device(item) for item in store.list_devices(username)]

    @app.post("/api/admin/users/{username}/devices/reservations", response_model=DeviceView, status_code=201, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 409: {"model": ErrorResponse}})
    def reserve_device(username: str, payload: DeviceReserve, request: Request, actor: Annotated[dict[str, Any], Depends(admin_mutation_user)]) -> dict[str, Any]:
        try:
            device = store.reserve_device(username, payload.device_id, payload.vpn_certificate_id, payload.web_certificate_id, actor["username"], source_ip(request))
        except DeviceQuotaExceeded:
            raise ApiError(409, "device_quota_exceeded", "每个账户最多登记十台设备。")
        except DeviceConflict:
            raise ApiError(409, "device_conflict", "账户、设备或证书登记标识不可用。")
        return public_device(device)

    @app.post("/api/admin/users/{username}/devices/{device_id}/revoke", response_model=DeviceView, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}})
    def revoke_device(username: str, device_id: str, request: Request, actor: Annotated[dict[str, Any], Depends(admin_mutation_user)]) -> dict[str, Any]:
        device = store.mark_device_revoking(username, device_id, actor["username"], source_ip(request))
        if device is None:
            raise ApiError(404, "device_not_found", "未找到设备。")
        return public_device(device)

    @app.get("/api/admin/audit", response_model=AuditPage, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}})
    def audit_log(_: Annotated[dict[str, Any], Depends(admin_user)], cursor: int | None = Query(default=None, ge=1), limit: int = Query(default=50, ge=1, le=100)) -> dict[str, Any]:
        items, next_cursor = store.list_audit(cursor, limit)
        return {"items": items, "next_cursor": next_cursor}

    @app.api_route("/api/vpn/{operation:path}", methods=["GET", "POST", "PATCH", "PUT", "DELETE"], response_model=MessageResponse, responses={401: {"model": ErrorResponse}, 503: {"model": ErrorResponse}})
    def unavailable_gateway(_: Annotated[dict[str, Any], Depends(current_user)]) -> None:
        raise ApiError(503, "gateway_unavailable", "测试环境尚未接入 VPN 网关。")

    return app
