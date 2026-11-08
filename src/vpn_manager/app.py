# 工厂内部依赖的注解需要立即求值，不能启用 postponed annotations。
import sqlite3
import uuid
from datetime import datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from threading import BoundedSemaphore
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.staticfiles import StaticFiles

from .gateway_sync import GatewayClient, GatewayUnavailable, seal_credential
from .models import AuditPage, DeviceCreate, DeviceCredential, DeviceView, ErrorResponse, GatewayStatus, LoginRequest, LoginResponse, MeResponse, MessageResponse, NetworkCreate, NetworkUpdate, NetworkView, UserCreate, UserUpdate, UserView
from .security import COOKIE_NAME, SESSION_TTL, hash_password, needs_rehash, new_secret, token_hash, utc_now, utc_text, verify_password
from .store import DeviceConflict, DeviceQuotaExceeded, Store

ALLOWED_ORIGIN = "https://slimjoy.cn"
LOGIN_WINDOW = timedelta(minutes=15)
LOGIN_ATTEMPT_LIMIT = 5
MAX_REQUEST_BODY_BYTES = 16 * 1024
# 本部署的系统管理员是固定主体；不能通过新建其他管理员绕过保护。
SYSTEM_ADMIN_USERNAME = "guanxiangkai"


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        self.status_code, self.code, self.message = status_code, code, message


def source_ip(request: Request) -> str:
    # 直连 HTTPS 使用真实 TCP 地址；绝不相信客户端自报的 XFF。
    try:
        return str(ip_address(request.client.host)) if request.client else "unknown"
    except ValueError:
        return "unknown"


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {**{k: user[k] for k in ("username", "role", "networks", "active", "created_at", "updated_at")},
            "protected": user["username"] == SYSTEM_ADMIN_USERNAME}


def require_origin(request: Request) -> None:
    if request.headers.getlist("origin") != [request.app.state.allowed_origin]:
        raise ApiError(403, "origin_forbidden", "请求来源不被允许。")


class RequestBoundaryMiddleware:
    """请求来源、请求体上限和安全头；身份认证仍由账户及会话完成。"""
    def __init__(self, app, *, api_origin: str | None = None):
        self.app, self.api_origin = app, api_origin

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def secured_send(event):
            if event["type"] == "http.response.start":
                headers = [(k,v) for k,v in event.get("headers",[]) if k.lower() not in {b"cache-control",b"content-security-policy"}]
                headers.extend([(b"cache-control",b"no-store"),(b"x-content-type-options",b"nosniff"),(b"referrer-policy",b"no-referrer"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")])
                event = {**event,"headers":headers}
            await send(event)

        async def error(status, code, message):
            await JSONResponse({"error":{"code":code,"message":message}}, status_code=status)(scope,receive,secured_send)

        # OSS 跨站模式的读取、写入和预检都检查同一个精确来源。
        # Origin 可被非浏览器客户端伪造，因此不能取代登录、CSRF 和权限校验。
        path = scope.get("path", "")
        if self.api_origin is not None and (path == "/api" or path.startswith("/api/")):
            origins = [v.decode("latin-1") for k,v in scope.get("headers",[]) if k.lower() == b"origin"]
            if origins != [self.api_origin]:
                await error(403,"origin_forbidden","请求来源不被允许。")
                return

        lengths = [v for k,v in scope.get("headers",[]) if k.lower()==b"content-length"]
        try:
            if len(lengths)>1 or lengths and (not lengths[0].isdigit() or int(lengths[0])<0):
                raise ValueError()
            if lengths and int(lengths[0])>MAX_REQUEST_BODY_BYTES:
                await error(413,"request_too_large","请求体过大。")
                return
        except ValueError:
            await error(400,"invalid_request","请求无效。")
            return
        events, size = [], 0
        while True:
            event = await receive()
            events.append(event)
            if event["type"] == "http.disconnect":
                return
            size += len(event.get("body",b""))
            if size>MAX_REQUEST_BODY_BYTES:
                await error(413,"request_too_large","请求体过大。")
                return
            if not event.get("more_body",False):
                break
        async def replay():
            # 已缓冲请求读完后继续等待真实连接事件，不能不断伪造空请求。
            return events.pop(0) if events else await receive()
        await self.app(scope,replay,secured_send)


def create_app(database_path: str | Path = "./vpn-manager.sqlite3", *, allowed_origin: str = ALLOWED_ORIGIN, web_directory: str | Path | None = None, gateway_public_key: bytes | None = None, gateway_client: GatewayClient | None = None, session_transport: str = "cookie") -> FastAPI:
    origin = urlsplit(allowed_origin)
    if origin.scheme!="https" or not origin.hostname or origin.username or origin.password or origin.path or origin.query or origin.fragment:
        raise ValueError("管理入口必须是无路径的 HTTPS 来源")
    _ = origin.port
    if session_transport not in {"cookie", "bearer"}:
        raise ValueError("会话传输方式必须为 cookie 或 bearer")
    store = Store(database_path)
    store.initialize()
    app = FastAPI(title="VPN 管理器",docs_url=None,redoc_url=None,openapi_url=None)
    app.state.store, app.state.allowed_origin = store, allowed_origin
    app.state.gateway_public_key, app.state.gateway_client = gateway_public_key, gateway_client
    app.add_middleware(CORSMiddleware,allow_origins=[allowed_origin],allow_credentials=session_transport == "cookie",allow_methods=["GET","POST","PATCH","OPTIONS"],allow_headers=["Content-Type","X-CSRF-Token","Authorization"],max_age=600)
    app.add_middleware(RequestBoundaryMiddleware, api_origin=allowed_origin if session_transport == "bearer" else None)
    password_slots = BoundedSemaphore(2)
    dummy_hash = hash_password(new_secret())

    @app.exception_handler(ApiError)
    async def api_error_handler(_,error):
        return JSONResponse({"error":{"code":error.code,"message":error.message}},status_code=error.status_code)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_,__):
        return JSONResponse({"error":{"code":"invalid_request","message":"请求无效。"}},status_code=422)

    @app.exception_handler(sqlite3.Error)
    async def database_unavailable(_,__):
        return JSONResponse({"error":{"code":"service_unavailable","message":"服务暂不可用，请稍后重试。"}},status_code=503)

    def queue_gateway_change(connection: Any, username: str, active: bool, networks: list[str],
                             password: str | None, *, discard_pending_credential: bool = False) -> None:
        """仅已投影账户或显式重设密码可入队，避免为历史账户伪造 VPN 状态。"""
        if gateway_public_key is None:
            return
        projected = connection.execute("SELECT 1 FROM gateway_accounts WHERE username=?", (username,)).fetchone() is not None
        if not projected and password is None:
            return
        generation = store.next_gateway_generation(connection, username)
        envelope = seal_credential(gateway_public_key, username, generation, password) if password is not None else None
        store.queue_gateway_change(connection, username, generation, active, networks, envelope,
                                   discard_pending_credential=discard_pending_credential)
        store.audit(connection, actor=None, source_ip=None, action="gateway_sync_queued", target=username, outcome="success")

    def queue_device_grants(connection: Any, username: str, active: bool, networks: list[str]) -> None:
        for identity in store.enabled_device_identities(connection, username):
            queue_gateway_change(connection, identity, active, networks if active else [], None)

    def device_views(account_id: str) -> list[dict]:
        rows = store.list_device_access(account_id)
        identities = [row["vpn_username"] for row in rows
                      if row["vpn_username"] and not (row["disabled"] and row["gateway_state"] == "applied")]
        online = None
        if gateway_client is not None and identities:
            try:
                online = gateway_client.connected_identities(identities)
            except GatewayUnavailable:
                pass
        return [device_view(row, online) for row in rows]

    def device_view(row: dict, online: set[str] | None) -> dict:
        identity, state = row["vpn_username"], row["gateway_state"]
        connection_state = "unknown"
        if identity is None:
            vpn_state = "unmanaged"
        elif state in {"failed", "superseded", None}:
            vpn_state = "unavailable"
        elif state != "applied" or row["applied_generation"] != row["generation"]:
            vpn_state = "disabling" if row["disabled"] or not row["account_active"] else "provisioning"
        elif row["disabled"] or not row["account_active"]:
            vpn_state, connection_state = "disabled", "offline"
        else:
            vpn_state = "enabled"
            if online is not None:
                connection_state = "online" if identity in online else "offline"
        return {**{key: row[key] for key in ("account_id", "device_id", "state", "created_at", "updated_at")},
                "vpn_state": vpn_state, "connection_state": connection_state}

    def live_gateway_status(username: str) -> dict[str, Any]:
        """将数据库的当前期望与代理的实际状态合并，绝不以旧 ACK 冒充已生效。"""
        if gateway_client is None:
            raise ApiError(503, "gateway_unavailable", "管理服务尚未接入现有 VPN 网关。")
        try:
            actual = gateway_client.status(username)
        except GatewayUnavailable:
            raise ApiError(503, "gateway_unavailable", "VPN 网关暂不可用。")
        expected = store.gateway_status(username)
        expected_generation, actual_generation = expected["generation"], actual["generation"]
        actual_state = actual["state"]
        applied_generation = actual_generation if actual_state == "applied" and 1 <= actual_generation <= expected_generation else None
        if expected_generation == 0:
            state, code = "not_provisioned", None
        elif applied_generation == expected_generation:
            state, code = "applied", actual.get("code")
        elif actual_state in {"pending", "failed", "not_provisioned", "superseded"}:
            state, code = actual_state, actual.get("code")
        else:
            # 代理仍报告旧版本已应用时，返回最新期望的未完成状态。
            state = expected["state"] if expected["state"] != "applied" else "pending"
            code = expected.get("code")
        return {"username": username, "generation": expected_generation,
                "applied_generation": applied_generation, "state": state, "code": code,
                "updated_at": None}

    def request_session(request: Request) -> str | None:
        """显式选择一种认证方式，禁止在 Cookie 与请求头之间悄悄回退。"""
        authorization = request.headers.getlist("authorization")
        if session_transport == "cookie":
            return None if authorization else request.cookies.get(COOKIE_NAME)
        if len(authorization) != 1 or request.cookies.get(COOKIE_NAME):
            return None
        scheme, separator, token = authorization[0].partition(" ")
        if scheme.lower() != "bearer" or not separator or len(token) != 43 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for c in token):
            return None
        return token

    def current_user(request: Request):
        session_token = request_session(request)
        user = store.session_user(session_token) if session_token else None
        if user is None:
            raise ApiError(401,"authentication_required","请先登录。")
        return user

    def csrf_protected(request: Request,user: Annotated[dict,Depends(current_user)],csrf_token: Annotated[str | None,Header(alias="X-CSRF-Token")] = None):
        require_origin(request)
        session_token = request_session(request)
        if not session_token or not csrf_token or not store.csrf_valid(session_token,csrf_token):
            raise ApiError(403,"csrf_invalid","CSRF 校验失败，请刷新页面后重试。")
        return user

    def admin_user(request: Request,user: Annotated[dict,Depends(current_user)]):
        if user["role"]!="admin":
            with store.write_transaction() as connection:
                store.audit(connection,actor=user["username"],source_ip=source_ip(request),action="admin_access",target=request.url.path,outcome="denied")
            raise ApiError(403,"permission_denied","需要管理员权限。")
        return user

    def admin_mutation_user(request: Request,user: Annotated[dict,Depends(csrf_protected)]):
        return admin_user(request,user)

    def authorize_write(connection, request: Request, *, admin: bool = False):
        # 与写入共用事务，防止依赖检查之后的撤权被正在处理的请求绕过。
        token = request_session(request)
        user = store.session_user_in_transaction(connection, token) if token else None
        if user is None:
            raise ApiError(401, "authentication_required", "请重新登录。")
        csrf_token = request.headers.get("X-CSRF-Token")
        if not csrf_token or connection.execute("SELECT 1 FROM sessions WHERE token_hash=? AND csrf_hash=?", (token_hash(token), token_hash(csrf_token))).fetchone() is None:
            raise ApiError(403, "csrf_invalid", "CSRF 校验失败，请刷新页面后重试。")
        if admin and user["role"] != "admin":
            raise ApiError(403, "permission_denied", "需要管理员权限。")
        return user

    @app.get("/health",response_model=MessageResponse)
    def health():
        return {"message":"ok"}

    @app.post("/api/auth/login",response_model=LoginResponse,response_model_exclude_none=True)
    def login(payload: LoginRequest,request: Request,response: Response):
        require_origin(request)
        now, address = utc_now(), source_ip(request)
        limited = False
        with store.write_transaction() as connection:
            # 三个桶先占位再做昂贵哈希，避免并发绕过或换用户名绕过来源限流。
            buckets = ((address,payload.username,LOGIN_ATTEMPT_LIMIT),(address,"@source",30),("*",payload.username,20))
            for source,name,limit in buckets:
                row = connection.execute("SELECT * FROM login_attempts WHERE source_ip=? AND username=?",(source,name)).fetchone()
                expired = row is None or datetime.fromisoformat(row["window_started_at"].replace("Z","+00:00")) + LOGIN_WINDOW <= now
                count = 0 if expired else row["failure_count"]
                if count>=limit:
                    limited = True
                else:
                    connection.execute("INSERT INTO login_attempts(source_ip,username,window_started_at,failure_count) VALUES (?,?,?,?) ON CONFLICT(source_ip,username) DO UPDATE SET window_started_at=excluded.window_started_at,failure_count=excluded.failure_count",(source,name,utc_text(now) if expired else row["window_started_at"],count+1))
            if limited:
                store.audit(connection,actor=payload.username,source_ip=address,action="login_rate_limited",target=payload.username,outcome="denied")
        if limited:
            raise ApiError(429,"login_rate_limited","登录尝试过多，请稍后重试。")
        if not password_slots.acquire(blocking=False):
            raise ApiError(429,"login_busy","登录服务繁忙，请稍后重试。")
        try:
            candidate = store.find_user(payload.username)
            checked_hash = candidate["password_hash"] if candidate else dummy_hash
            valid = verify_password(checked_hash,payload.password.get_secret_value())
            replacement = hash_password(payload.password.get_secret_value()) if valid and candidate and needs_rehash(checked_hash) else None
        finally:
            password_slots.release()
        token, csrf_token = new_secret(), new_secret()
        with store.write_transaction() as connection:
            user = store.user_from_row(connection,connection.execute("SELECT * FROM users WHERE username=?",(payload.username,)).fetchone())
            accepted = valid and user is not None and user["active"] and user["password_hash"]==checked_hash
            if not accepted:
                store.audit(connection,actor=payload.username,source_ip=address,action="login",target=payload.username,outcome="failure")
            else:
                if replacement:
                    connection.execute("UPDATE users SET password_hash=? WHERE username=?",(replacement,payload.username))
                store.add_session_in_transaction(connection,payload.username,token,csrf_token,now+SESSION_TTL)
                connection.execute("DELETE FROM login_attempts WHERE source_ip=? AND username=?",(address,payload.username))
                store.audit(connection,actor=payload.username,source_ip=address,action="login",target=payload.username,outcome="success")
        if not accepted:
            raise ApiError(401,"invalid_credentials","账户或密码错误。")
        result = {"user":public_user(user),"csrf_token":csrf_token}
        if session_transport == "cookie":
            response.set_cookie(COOKIE_NAME,token,max_age=int(SESSION_TTL.total_seconds()),httponly=True,secure=True,samesite="lax",path="/")
        else:
            result["session_token"] = token
        return result

    @app.get("/api/auth/me",response_model=UserView)
    def me(user: Annotated[dict,Depends(current_user)]):
        return public_user(user)

    @app.post("/api/auth/refresh",response_model=MeResponse)
    def refresh(request: Request,user: Annotated[dict,Depends(current_user)]):
        require_origin(request)
        session_token = request_session(request)
        csrf_token = new_secret()
        if not store.rotate_csrf(session_token,csrf_token):
            raise ApiError(401,"authentication_required","请先登录。")
        return {**public_user(user),"csrf_token":csrf_token}

    @app.post("/api/auth/logout",response_model=MessageResponse)
    def logout(request: Request,response: Response,user: Annotated[dict,Depends(csrf_protected)]):
        session_token = request_session(request)
        with store.write_transaction() as connection:
            if not store.revoke_session_in_transaction(connection,session_token,user["username"]):
                raise ApiError(401,"authentication_required","请先登录。")
            store.audit(connection,actor=user["username"],source_ip=source_ip(request),action="logout",target=user["username"],outcome="success")
        if session_transport == "cookie":
            response.delete_cookie(COOKIE_NAME,path="/",secure=True,httponly=True,samesite="lax")
        return {"message":"已退出登录"}

    @app.get("/api/devices",response_model=list[DeviceView])
    def own_devices(user: Annotated[dict,Depends(current_user)]):
        return device_views(user["username"])

    @app.post("/api/devices/{device_id}/remove",response_model=DeviceView)
    def remove_own_device(device_id: str,request: Request,user: Annotated[dict,Depends(csrf_protected)]):
        with store.write_transaction() as connection:
            user = authorize_write(connection, request)
            item = remove_device_record(connection, user["username"], device_id, user["username"], request)
        if item is None:
            raise ApiError(404,"device_not_found","未找到设备记录。")
        return item

    @app.get("/api/networks", response_model=list[NetworkView])
    def own_networks(user: Annotated[dict, Depends(current_user)]):
        # 普通账户只读取自身授权的网络资料，草稿和其他网络不会泄露。
        return store.list_networks(user["username"])

    @app.get("/api/admin/networks", response_model=list[NetworkView])
    def list_networks(_: Annotated[dict, Depends(admin_user)]):
        return store.list_networks()

    @app.post("/api/admin/networks", response_model=NetworkView, status_code=201)
    def create_network(payload: NetworkCreate, request: Request, _: Annotated[dict, Depends(admin_mutation_user)]):
        with store.write_transaction() as connection:
            actor = authorize_write(connection, request, admin=True)
            identifier, now = "net-" + uuid.uuid4().hex, utc_text()
            try:
                connection.execute("INSERT INTO network_catalog(id,name,description,state,version,created_at,updated_at) VALUES (?,?,?,'draft',1,?,?)", (identifier, payload.name, payload.description, now, now))
            except sqlite3.IntegrityError:
                raise ApiError(409, "network_name_conflict", "此网络名称已存在。")
            store.audit(connection, actor=actor["username"], source_ip=source_ip(request), action="network_create", target=identifier, outcome="success")
            return dict(connection.execute("SELECT * FROM network_catalog WHERE id=?", (identifier,)).fetchone())

    @app.patch("/api/admin/networks/{network_id}", response_model=NetworkView)
    def update_network(network_id: str, payload: NetworkUpdate, request: Request, _: Annotated[dict, Depends(admin_mutation_user)]):
        with store.write_transaction() as connection:
            actor = authorize_write(connection, request, admin=True)
            current = connection.execute("SELECT * FROM network_catalog WHERE id=?", (network_id,)).fetchone()
            if current is None:
                raise ApiError(404, "network_not_found", "未找到此网络。")
            if current["version"] != payload.version:
                raise ApiError(409, "network_version_conflict", "此网络已被其他操作修改，请刷新列表后重新编辑。")
            try:
                connection.execute("UPDATE network_catalog SET name=?,description=?,version=version+1,updated_at=? WHERE id=?", (payload.name, payload.description, utc_text(), network_id))
            except sqlite3.IntegrityError:
                raise ApiError(409, "network_name_conflict", "此网络名称已存在。")
            store.audit(connection, actor=actor["username"], source_ip=source_ip(request), action="network_update", target=network_id, outcome="success")
            return dict(connection.execute("SELECT * FROM network_catalog WHERE id=?", (network_id,)).fetchone())

    @app.get("/api/admin/users", response_model=list[UserView], responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}})
    def list_users(_: Annotated[dict[str, Any], Depends(admin_user)]) -> list[dict[str, Any]]:
        return [public_user(item) for item in store.list_users()]

    @app.post("/api/admin/users", response_model=UserView, status_code=201, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 409: {"model": ErrorResponse}})
    def create_user(payload: UserCreate, request: Request, actor: Annotated[dict[str, Any], Depends(admin_mutation_user)]) -> dict[str, Any]:
        if payload.username.startswith("device-"):
            raise ApiError(422, "invalid_username", "此用户名由 VPN 设备管理保留。")
        password = payload.password.get_secret_value()
        password_hash = hash_password(password)
        with store.write_transaction() as connection:
            actor = authorize_write(connection, request, admin=True)
            now = utc_text()
            try:
                connection.execute("INSERT INTO users(username, password_hash, role, active, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)", (payload.username, password_hash, payload.role, now, now))
            except sqlite3.IntegrityError:
                raise ApiError(409, "username_conflict", "此账户名已存在。")
            connection.executemany("INSERT INTO user_networks(username, network) VALUES (?, ?)", [(payload.username, network) for network in payload.networks])
            queue_gateway_change(connection, payload.username, True, payload.networks, password)
            created = store.user_from_row(connection, connection.execute("SELECT * FROM users WHERE username = ?", (payload.username,)).fetchone())
            store.audit(connection, actor=actor["username"], source_ip=source_ip(request), action="user_create", target=payload.username, outcome="success")
        return public_user(created)

    def protect_last_admin(connection: Any, current: dict[str, Any], next_role: str, next_active: bool) -> None:
        if current["username"] == SYSTEM_ADMIN_USERNAME and (next_role != "admin" or not next_active):
            raise ApiError(409, "system_admin_protected", "系统管理员不能降级或停用。")
        if current["active"] and current["role"] == "admin" and (next_role != "admin" or not next_active):
            count = connection.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND active = 1").fetchone()["count"]
            if count <= 1:
                raise ApiError(409, "last_admin_protected", "不能移除、降级或停用最后一个有效管理员。")

    @app.patch("/api/admin/users/{username}", response_model=UserView, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}})
    def update_user(username: str, payload: UserUpdate, request: Request, actor: Annotated[dict[str, Any], Depends(admin_mutation_user)]) -> dict[str, Any]:
        password = payload.password.get_secret_value() if payload.password is not None else None
        replacement = hash_password(password) if password is not None else None
        with store.write_transaction() as connection:
            actor = authorize_write(connection, request, admin=True)
            current = store.user_from_row(connection, connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone())
            if current is None:
                raise ApiError(404, "user_not_found", "未找到账户。")
            next_role = payload.role if payload.role is not None else current["role"]
            next_active = payload.active if payload.active is not None else current["active"]
            protect_last_admin(connection, current, next_role, next_active)
            # 降为普通用户即使没有显式 networks 也必须收敛为唯一的 work
            # 权限；不让旧管理员的 home 授权滞留在账户或网关投影中。
            next_networks = payload.networks if payload.networks is not None else current["networks"]
            if next_role == "user":
                if payload.networks is None and current["role"] != "user":
                    next_networks = ["work"]
                if next_networks != ["work"]:
                    raise ApiError(422, "invalid_network_policy", "普通用户只能拥有 work 网络权限。")
            role_changed = next_role != current["role"]
            vpn_changed = (
                next_active != current["active"]
                or next_networks != current["networks"]
                or payload.password is not None
                or role_changed
            )
            changed = role_changed or vpn_changed
            if changed:
                password_hash = replacement if replacement is not None else current["password_hash"]
                connection.execute("UPDATE users SET password_hash = ?, role = ?, active = ?, updated_at = ? WHERE username = ?", (password_hash, next_role, int(next_active), utc_text(), username))
                if next_networks != current["networks"]:
                    connection.execute("DELETE FROM user_networks WHERE username = ?", (username,))
                    connection.executemany("INSERT INTO user_networks(username, network) VALUES (?, ?)", [(username, network) for network in next_networks])
                store.revoke_sessions(connection, username)
                if next_active != current["active"] or next_networks != current["networks"]:
                    queue_device_grants(connection, username, next_active, next_networks)
                if vpn_changed:
                    queue_gateway_change(connection, username, next_active, next_networks, password)
            store.audit(connection, actor=actor["username"], source_ip=source_ip(request), action="user_update", target=username, outcome="success")
            updated = store.user_from_row(connection, connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone())
        return public_user(updated)

    @app.post("/api/admin/users/{username}/deactivate", response_model=UserView, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}})
    def deactivate_user(username: str, request: Request, actor: Annotated[dict[str, Any], Depends(admin_mutation_user)]) -> dict[str, Any]:
        with store.write_transaction() as connection:
            actor = authorize_write(connection, request, admin=True)
            current = store.user_from_row(connection, connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone())
            if current is None:
                raise ApiError(404, "user_not_found", "未找到账户。")
            protect_last_admin(connection, current, current["role"], False)
            if current["active"]:
                connection.execute("UPDATE users SET active = 0, updated_at = ? WHERE username = ?", (utc_text(), username))
                store.revoke_sessions(connection, username)
                queue_device_grants(connection, username, False, [])
                queue_gateway_change(connection, username, False, [], None)
            store.audit(connection, actor=actor["username"], source_ip=source_ip(request), action="user_deactivate", target=username, outcome="success")
            updated = store.user_from_row(connection, connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone())
        return public_user(updated)

    @app.get("/api/admin/users/{username}/devices",response_model=list[DeviceView])
    def user_devices(username: str,_: Annotated[dict,Depends(admin_user)]):
        if store.find_user(username) is None:
            raise ApiError(404,"user_not_found","未找到账户。")
        return device_views(username)

    @app.post("/api/admin/users/{username}/devices",response_model=DeviceView,status_code=201)
    def add_device(username: str,payload: DeviceCreate,request: Request,actor: Annotated[dict,Depends(admin_mutation_user)]):
        try:
            with store.write_transaction() as connection:
                actor = authorize_write(connection, request, admin=True)
                return store.register_device_in_transaction(connection,username,payload.device_id,actor["username"],source_ip(request))
        except DeviceQuotaExceeded:
            raise ApiError(409,"device_quota_exceeded","每个账户最多登记十台设备。")
        except DeviceConflict:
            raise ApiError(409,"device_conflict","账户或设备记录不可用。")

    @app.post("/api/admin/users/{username}/devices/{device_id}/remove",response_model=DeviceView)
    def remove_device(username: str,device_id: str,request: Request,actor: Annotated[dict,Depends(admin_mutation_user)]):
        with store.write_transaction() as connection:
            actor = authorize_write(connection, request, admin=True)
            item = remove_device_record(connection, username, device_id, actor["username"], request)
        if item is None:
            raise ApiError(404,"device_not_found","未找到设备记录。")
        return item

    def remove_device_record(connection, username: str, device_id: str, actor: str, request: Request):
        try:
            return store.remove_device_in_transaction(connection, username, device_id, actor, source_ip(request))
        except DeviceConflict:
            raise ApiError(409, "device_disable_required", "请先禁用此设备的 VPN 凭据，并等待网关确认。")

    @app.post("/api/admin/users/{username}/devices/{device_id}/provision",
              response_model=DeviceCredential, status_code=201)
    def provision_device(username: str, device_id: str, request: Request,
                         actor: Annotated[dict, Depends(admin_mutation_user)]):
        if gateway_public_key is None or gateway_client is None:
            raise ApiError(503, "gateway_unavailable", "VPN 网关暂不可用。")
        if store.find_user(username) is None:
            raise ApiError(404, "user_not_found", "未找到账户。")
        try:
            gateway_client.connected_identities([username])
        except GatewayUnavailable:
            raise ApiError(503, "gateway_unavailable", "VPN 网关暂不可用。")
        password = new_secret()
        with store.write_transaction() as connection:
            actor = authorize_write(connection, request, admin=True)
            account = store.user_from_row(connection, connection.execute(
                "SELECT * FROM users WHERE username=?", (username,)).fetchone())
            record = connection.execute("SELECT state FROM device_records WHERE account_id=? AND device_id=?",
                                        (username, device_id)).fetchone()
            if record is None or record["state"] != "registered":
                raise ApiError(404, "device_not_found", "未找到已登记的设备。")
            if not account["active"]:
                raise ApiError(409, "device_conflict", "请先启用所属账户。")
            identity = store.device_identity(connection, username, device_id)
            if identity is None:
                vpn_username = "device-" + uuid.uuid4().hex
                connection.execute("INSERT INTO gateway_identities(username,account_id,device_id) VALUES (?,?,?)",
                                   (vpn_username, username, device_id))
            else:
                if not identity["disabled"] or identity["gateway_state"] != "applied":
                    raise ApiError(409, "device_conflict", "设备已有凭据，请先禁用并等待网关确认。")
                vpn_username = identity["username"]
                connection.execute("UPDATE gateway_identities SET disabled=0 WHERE username=?", (vpn_username,))
            queue_gateway_change(connection, vpn_username, True, account["networks"], password)
            connection.execute("UPDATE device_records SET updated_at=? WHERE account_id=? AND device_id=?",
                               (utc_text(), username, device_id))
            store.audit(connection, actor=actor["username"], source_ip=source_ip(request),
                        action="device_vpn_provision", target=f"{username}:{device_id}", outcome="success")
        return {"username": vpn_username, "password": password}

    @app.post("/api/admin/users/{username}/devices/{device_id}/disable", response_model=DeviceView)
    def disable_device(username: str, device_id: str, request: Request,
                       actor: Annotated[dict, Depends(admin_mutation_user)]):
        if gateway_public_key is None:
            raise ApiError(503, "gateway_unavailable", "VPN 网关暂不可用。")
        with store.write_transaction() as connection:
            actor = authorize_write(connection, request, admin=True)
            identity = store.device_identity(connection, username, device_id)
            if identity is None:
                raise ApiError(409, "device_not_managed", "此设备尚未使用独立 VPN 凭据。")
            if not identity["disabled"] or identity["gateway_state"] == "failed":
                vpn_username = identity["username"]
                connection.execute("UPDATE gateway_identities SET disabled=1 WHERE username=?", (vpn_username,))
                queue_gateway_change(connection, vpn_username, False, [], None, discard_pending_credential=True)
                connection.execute("UPDATE device_records SET updated_at=? WHERE account_id=? AND device_id=?",
                                   (utc_text(), username, device_id))
                store.audit(connection, actor=actor["username"], source_ip=source_ip(request),
                            action="device_vpn_disable", target=f"{username}:{device_id}", outcome="success")
        return next(row for row in device_views(username) if row["device_id"] == device_id)

    @app.get("/api/admin/audit",response_model=AuditPage)
    def audit_log(_: Annotated[dict,Depends(admin_user)],cursor: int | None = Query(default=None,ge=1),limit: int = Query(default=50,ge=1,le=100)):
        items,next_cursor=store.list_audit(cursor,limit)
        return {"items":items,"next_cursor":next_cursor}

    @app.get("/api/admin/gateway-status", response_model=list[GatewayStatus])
    def all_gateway_status(_: Annotated[dict, Depends(admin_user)]):
        # 每一项都需来自当前代理读回；任一读回失败时整个总表不可用。
        return [live_gateway_status(item["username"]) for item in store.list_gateway_statuses()]

    @app.get("/api/vpn/status", response_model=GatewayStatus)
    def gateway_status(user: Annotated[dict, Depends(current_user)]):
        return live_gateway_status(user["username"])

    @app.api_route("/api/vpn/{operation:path}",methods=["GET","POST","PATCH","PUT","DELETE"])
    def unavailable_gateway(_: Annotated[dict,Depends(current_user)]):
        raise ApiError(503,"gateway_unavailable","管理服务尚未接入现有 VPN 网关。")

    if web_directory is not None:
        app.mount("/",StaticFiles(directory=web_directory,html=True),name="web")
    return app
