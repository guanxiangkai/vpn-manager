# VPN 管理器

用于小规模 VPN 账户、网络权限、设备登记记录和审计日志的管理服务，包含 FastAPI 接口与静态管理网页。公开仓库只保存应用源码和测试，不保存生产账户密码、私钥、证书或服务器备份。

**当前处于暂存测试阶段。** 本服务目前实现的是账户密码认证与管理会话，不接入实际 VPN 网关。`home`（家庭）和 `work`（工作）是持久化的账户权限元数据；它们尚未下发或执行为网关规则。任何 VPN 权限已经生效、设备已经阻止或连接已经建立的说法，均须在未来网关集成后另行验证。

## 已实现边界

- 账户使用 Argon2id 密码哈希；角色为 `admin` 或 `user`，网络权限只能是 `home`、`work`。
- 管理会话为随机的 HttpOnly、Secure、SameSite=Lax Cookie；登录和 `POST /api/auth/refresh` 返回仅存于页面内存的 CSRF 令牌。
- `GET /api/auth/me` 为无副作用的只读用户资料接口；刷新浏览器页面应调用 `POST /api/auth/refresh` 恢复会话并取得新的 CSRF 令牌。
- 管理员可管理账户、设备登记记录和审计；普通用户仅可访问自己的资料和设备记录，不能读取或修改他人数据。服务端执行角色与账户隔离。
- 修改账户密码、角色、启用状态或网络权限会立即撤销该账户的管理会话。
- 设备名单只是管理记录。每账户最多 10 条 `registered` 记录，`removed` 记录不占名额；它不认证设备，也不会阻止取得账户密码的新设备登录或连接 VPN。
- 审计记录登录成功/失败、退出和管理操作；不会写入密码、哈希、Cookie 或请求体。

## 运行环境与安装

目标环境为 Alibaba Cloud Linux 4、Python 3.11。以下步骤仅用于受控测试环境，不会配置或修改现有 VPN 网关。

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
python -m pytest
```

应用工厂仅在显式调用时初始化 SQLite；导入模块不会创建数据库。部署数据库应放在专用状态目录，源码不预设账户，也不通过环境变量传递密码。

## 首次初始化账户

源码不包含真实账户或初始密码。部署时只允许从标准输入接收凭据管理方提供的 JSON；不要将密码写入命令行参数、环境变量或服务日志。

```sh
vault_command_that_emits_json | python -m vpn_manager.bootstrap --database /var/lib/vpn-manager/manager.sqlite3
```

`vault_command_that_emits_json` 是占位命令，必须替换为实际的获授权凭据入口。输入可以是账户数组，或 `{"users": [...]}`。每个账户需要 `username`、长度 10–256 的 `password`、`role`（`admin` 或 `user`）及非空、无重复的 `networks`（`home`、`work`）。初始化只能对尚无账户的数据库执行。

## 原生 HTTPS 运行方式

暂存部署直接由 Uvicorn 提供 HTTPS，绑定服务器内部 IP；当前不需要 Nginx 或客户端证书。运行时只读取以下环境变量：

- `VPN_MANAGER_DB`：已完成账户初始化的 SQLite 数据库路径。
- `VPN_MANAGER_WEB_DIRECTORY`：静态网页目录（通常为仓库的 `web/`）。
- `VPN_MANAGER_ORIGIN`：唯一允许的 HTTPS 浏览器 Origin，例如 `https://manager.example.internal`。

将 `INTERNAL_IP` 替换为服务器的内部监听地址，并确保私钥文件只对运行服务的账户可读：

```sh
export VPN_MANAGER_DB=/var/lib/vpn-manager/manager.sqlite3
export VPN_MANAGER_WEB_DIRECTORY=/opt/slimjoy-vpn-manager/web
export VPN_MANAGER_ORIGIN=https://manager.example.internal
python -m vpn_manager.runtime --bind INTERNAL_IP --port 8443 \
  --cert /protected/server.pem --key /protected/server.key
```

不要使用 `--reload`，不要将监听地址改为未评估的公网地址，也不要把密钥、密码或 Cookie 写入日志。ECS 的内部地址可能由 EIP 映射，必须在安全组或主机防火墙验证只允许预期的 VPN 来源；仅绑定内部 IP 不构成公网隔离。OpenAPI、Swagger 和 ReDoc 不应作为公开入口。生产网络暴露、TLS 证书轮换、备份恢复、审计留存和真实浏览器验收仍待实际部署环境验证。

## 浏览器认证与接口约定

浏览器只能从 `VPN_MANAGER_ORIGIN` 指定的精确 HTTPS Origin 调用 API。浏览器自动携带会话 Cookie；前端使用 `credentials: "include"`，不读写 `localStorage` 或 `sessionStorage`。

`POST /api/auth/login` 成功后返回 `{ "user": UserView, "csrf_token": string }`。`GET /api/auth/me` 仅返回 `UserView`，不轮换 CSRF。`POST /api/auth/refresh` 依赖已有 Cookie 与严格 Origin，返回扁平 `UserView` 字段和新的 `csrf_token`。所有状态修改请求必须携带最新的 `X-CSRF-Token`；错误体为 `{ "error": { "code": string, "message": string } }`。

接口包括：

- 认证：`GET /health`、`POST /api/auth/login`、`POST /api/auth/logout`、`POST /api/auth/refresh`、`GET /api/auth/me`。
- 本人设备记录：`GET /api/devices`、`POST /api/devices/{device_id}/remove`。
- 管理员：`GET/POST /api/admin/users`、`PATCH /api/admin/users/{username}`、`POST /api/admin/users/{username}/deactivate`、`GET /api/admin/audit?cursor=&limit=20`、`GET/POST /api/admin/users/{username}/devices`、`POST /api/admin/users/{username}/devices/{device_id}/remove`。

创建设备记录的请求体只有 `{ "device_id": string }`。`DeviceView` 为 `account_id`、`device_id`、`state`（`registered` 或 `removed`）、`created_at`、`updated_at`；移除记录不等于撤销 VPN 访问。

## 验证边界

单元和接口测试在隔离数据库中运行：

```sh
python -m pytest
```

浏览器验收仅在隔离 Linux 环境、已准备 Chromium 和测试账户时运行：

```sh
VPN_MANAGER_TEST_URL=https://manager.example.internal \
  python -m pytest tests/browser_acceptance.py -q
```

这些测试不能证明生产 HTTPS 入口、网络防火墙、真实 VPN 网关授权、VPN 客户端连接或生产审计留存已经通过验收；上述项目均为待验证项。
