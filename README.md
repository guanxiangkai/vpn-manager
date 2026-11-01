# VPN 管理器

管理 VPN 账户、设备、访问权限和审计日志，提供静态管理网页及配套接口。公开仓库只保存应用源码和测试，不保存生产密码、客户端私钥、服务器备份或 SSH 私钥。

**当前处于测试阶段。** 真实设备证书验证、证书签发、静态页面的受保护入口及 VPN 网关权限执行尚未接入。仓库内的自动测试不会部署或修改现有 VPN 服务。

后端使用 FastAPI，适用于小规模账户管理。`home`（家庭）和 `work`（工作）目前只是账户权限数据，不会直接配置或控制 VPN 网关。完成设备及账户认证后，所有 `/api/vpn/*` 操作仍返回 `503 gateway_unavailable`，直至接入真实网关。

所有 `/api/*` 请求默认拒绝访问，必须先通过专用于管理端的设备证书验证器。服务没有内置验证器、开发绕过开关，也不信任请求头、Cookie、IP、浏览器标识、请求体、证书主题或签发者名称作为设备证明。部署方尚未注入真实验证器时，接口统一返回 `503 device_verification_unavailable`。

## 运行环境与安装

目标环境为 Alibaba Cloud Linux 4、Python 3.11。以下命令只用于受控测试环境，不会配置现有 VPN 服务。

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
python -m pytest
uvicorn --factory vpn_manager.app:create_app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

应用工厂在显式调用时初始化所选 SQLite 数据库；导入模块不会创建数据库。默认文件为 `./slimjoy-vpn-manager.sqlite3`，部署时应从专用状态目录启动。源码没有预设账户，也不通过环境变量传递密码。

启动命令只监听本机回环地址，并关闭 Uvicorn 对代理请求头的信任。不要启用 `--reload`、公网监听地址或 `--proxy-headers`。OpenAPI、Swagger 和 ReDoc 页面已禁用。`/health` 额外拒绝非回环来源，不能通过外部入口暴露。

数据库结构版本 2 包含设备登记和设备绑定会话。若读取早期未发布的版本 1 数据库，初始化会补充设备绑定字段，并撤销无法证明设备身份的旧会话，保留账户和审计记录。在非一次性测试数据库执行前，应先完成 SQLite 一致性备份。

`pyproject.toml` 限定 FastAPI、Pydantic v2、Uvicorn 和 `argon2-cffi` 的版本范围；测试依赖为 pytest、HTTPX。GitHub 自动测试负责在 Linux、Python 3.11 环境安装依赖、检查一致性并运行接口测试。是否通过，以对应提交的运行结果为准。

## 首次初始化账户

源码不包含真实账户或初始密码。部署时只允许通过标准输入传入凭据管理方提供的 JSON，不应将密码写入命令行参数、环境变量或服务日志。

```sh
vault_command_that_emits_json | python -m vpn_manager.bootstrap --database /var/lib/vpn-manager/manager.sqlite3
```

上述 `vault_command_that_emits_json` 是占位命令，应替换为实际凭据管理入口。输入可以是账户数组，也可以是 `{"users": [...]}`。每个账户必须包含：`username`、长度为 10–256 个字符的 `password`、`role`（`admin` 或 `user`），以及非空且不重复的 `networks`（只能选择 `home`、`work`）。初始化只允许对没有账户的数据库执行一次。

## 浏览器认证与接口约定

当前允许的浏览器来源及 CORS 来源为 `https://slimjoy.cn`。登录、CSRF 刷新和所有修改状态的请求都必须发送完全匹配的 `Origin`。

登录与 `GET /api/auth/me` 返回 `csrf_token`；后者会轮换当前会话的 CSRF 令牌，让页面刷新后恢复登录状态，同时不向 JavaScript 暴露 HttpOnly 会话令牌。后续修改请求必须通过 `X-CSRF-Token` 发送最新令牌。

会话通过 `slimjoy_vpn_session` Cookie 保存随机令牌，启用 HttpOnly、Secure、SameSite=Lax，并绑定已验证设备及其管理端证书登记标识。复制 Cookie 到其他设备不能继续使用。修改账户密码、角色、启用状态或网络权限后，该账户的全部会话立即撤销。

## 设备登记与撤销边界

每台逻辑设备预留两个不同用途的证书登记标识：`vpn_certificate_id` 用于后续 EAP-TLS VPN，`web_certificate_id` 用于浏览器 mTLS 管理。管理端验证主体只接受管理用途证书对应的账户、设备和证书标识。

每个账户最多占用 10 个设备名额，`pending`（待处理）、`active`（已启用）和 `revoking`（撤销中）都会占用名额；事务以 `BEGIN IMMEDIATE` 串行执行，避免并发超额。换证应由未来的证书签发验证模块更新现有设备记录，不能通过重复预留占用新名额。

目前尚未实现设备虚拟 IP 分配、EAP-TLS 认证、浏览器 mTLS 证明、签发、激活、网关阻断及 IKE/IPsec 会话终止。

只有已启用的设备能使用管理接口。管理员可查询设备、预留待处理记录或发起撤销；没有公开自助登记、激活、签发或模拟网关成功的接口。撤销立即将设备变为 `revoking`，使其管理会话失效，并返回 `manager_access: "revoked"` 与 `gateway_revocation: "pending"`。此时只能确认管理权限已撤销，不能据此认定网关已经阻断 VPN 或终止连接。

VPN 与管理端证书登记标识必须不同，且不能被其他设备在任一用途字段中复用，跨账户同样禁止复用。

## 接口一览

应用主动处理的错误统一为 `{"error":{"code":"...","message":"..."}}`。未知字段会被拒绝，HTTP 请求体在解析 JSON 前限制为 16 KiB。时间采用 UTC ISO 8601 格式。

`User` 响应示例：

```json
{"username":"name","role":"admin","networks":["home","work"],"active":true,"created_at":"...","updated_at":"..."}
```

| 接口 | 请求条件 | 成功响应 | 主要错误 |
| --- | --- | --- | --- |
| `GET /health` | 仅本机回环来源 | `{"message":"ok"}` | 非回环来源返回 404 |
| `POST /api/auth/login` | 已验证设备；`{username,password}`；匹配来源 | `{user: User, csrf_token}` | 401 `invalid_credentials`、403、429 `rate_limited` |
| `POST /api/auth/logout` | 已验证设备、会话与 CSRF | 退出成功消息 | 401、403 |
| `GET /api/auth/me` | 已验证设备、会话与匹配来源 | `User` 字段与新 `csrf_token` | 401、403 |
| `GET /api/devices` | 已验证设备与会话 | 仅本账户的 `Device[]` | 401、403 |
| `POST /api/devices/{device_id}/revoke` | 本账户设备、会话与 CSRF | 状态为 `revoking` 的 `Device` | 401、403、404 |
| `GET /api/admin/users` | 管理员设备与会话 | `User[]` | 401、403 |
| `POST /api/admin/users` | 管理员 CSRF；`{username,password,role,networks}` | `201 User` | 401、403、409 `username_conflict` |
| `PATCH /api/admin/users/{username}` | 管理员 CSRF；`{password,role,networks,active}` 中至少一项 | `User` | 401、403、404、409 `last_admin_protected` |
| `POST /api/admin/users/{username}/deactivate` | 管理员 CSRF | `User` | 401、403、404、409 `last_admin_protected` |
| `GET /api/admin/audit?cursor=&limit=` | 管理员设备与会话 | `{items:[AuditEvent],next_cursor}` | 401、403 |
| `GET /api/admin/users/{username}/devices` | 管理员设备与会话 | `Device[]` | 401、403 |
| `POST /api/admin/users/{username}/devices/reservations` | 管理员 CSRF；`{device_id,vpn_certificate_id,web_certificate_id}` | 状态为 `pending` 的 `201 Device` | 401、403、409 |
| `POST /api/admin/users/{username}/devices/{device_id}/revoke` | 管理员 CSRF | 状态为 `revoking` 的 `Device` | 401、403、404 |
| `/api/vpn/*` | 已验证设备与会话 | 当前不提供成功响应 | 401、503 `gateway_unavailable` |

除表中业务错误外，所有管理接口还受设备验证门禁约束。未配置验证器返回 503；设备未验证、未启用或已撤销时拒绝访问。

`Device` 包含 `account_id`、`device_id`、两类证书登记标识、`state`、时间字段、`manager_access` 和 `gateway_revocation`。

`AuditEvent` 只包含 `id`、`occurred_at`、`actor`、`source_ip`、`action`、`target`、`outcome`，不记录请求体、密码、密码哈希、证书内容或会话及 CSRF 令牌。分页 `cursor` 使用上一页最后一条记录的数字 ID；`limit` 范围为 1–100，默认 50。日志覆盖登录成功或失败、退出、已完成的账户变更、设备预留与撤销请求、普通用户越权请求。

只有已启用管理员能管理账户。最后一个有效管理员不能被停用或降级。普通用户只能读取自己的身份、权限数据及设备；账户权限数据本身不代表网关访问已经生效。

## 验证范围

`tests/test_api.py` 覆盖默认设备门禁及伪造请求头拒绝、错误结构、跨账户隔离、待处理设备拒绝、跨设备 Cookie 重放拒绝、管理权限立即撤销与网关待确认、退出后会话重放拒绝、证书用途冲突、旧数据库会话撤销，以及设备名额的真实并发竞争。

自动测试通过只代表应用接口在相应测试环境通过。真实证书验证器、浏览器 mTLS、EAP-TLS、VPN 网关、反向代理、凭据入口及实际账户仍须分别验收。框架、网络与反向代理异常不包含在应用主动处理的错误结构承诺内。
