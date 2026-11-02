# VPN 管理器

用于小规模 VPN 账户、网络权限、设备登记记录和审计日志的管理服务，包含 FastAPI 接口与静态管理网页。公开仓库只保存应用源码和测试，不保存生产账户密码、私钥、证书或服务器备份。

**当前处于网关集成验收阶段。** 已实现账户变更事务、加密 outbox、独立 root 网关代理及 strongSwan VICI/nft 投影。只有网关确认具体版本为 `applied`，才能视为该版本已下发；数据库保存成功、排队成功和单元测试通过均不等于真实 VPN 验收。生产切换须先完成隔离 IKE/转发验收、备份和独立自动回滚。

## 已实现边界

- 管理网页登录使用 Argon2id 密码哈希；角色为 `admin` 或 `user`。普通用户只能获得 `work`；管理员可被授予 `home`、`work`。
- 管理会话支持明确选择的两种模式：同源 HttpOnly、Secure、SameSite=Lax Cookie，或供 OSS 跨站访问的内存 Bearer。会话和 CSRF 不写入浏览器持久存储。
- `GET /api/auth/me` 为无副作用的只读用户资料接口；Cookie 模式通过 `POST /api/auth/refresh` 恢复会话，Bearer 模式刷新页面后需重新登录。
- 管理员可管理账户、设备登记记录和审计；普通用户仅可访问自己的资料和设备记录，不能读取或修改他人数据。服务端执行角色与账户隔离。
- 修改账户密码、角色、启用状态或网络权限会立即撤销该账户的管理会话。
- 设备名单只是管理记录。每账户最多 10 条 `registered` 记录，`removed` 记录不占名额；它不认证设备，也不会阻止取得账户密码的新设备登录或连接 VPN。
- 审计记录登录成功/失败、退出和管理操作；不会写入密码、哈希、Cookie、Bearer 令牌或请求体。

## 运行环境与安装

目标环境为 Alibaba Cloud Linux 4、Python 3.11。以下步骤仅用于受控 Linux 测试环境。安装依赖和单元测试不会修改现有 VPN 网关；不要在办公 Mac 安装或运行后端。

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

`vault_command_that_emits_json` 是占位命令，必须替换为实际的获授权凭据入口。输入可以是账户数组，或 `{"users": [...]}`。每个账户需要 `username`、长度 10–256 的 `password`、`role`（`admin` 或 `user`）及非空、无重复的 `networks`（`home`、`work`）。初始化只能对尚无账户的数据库执行。配置网关时增加 `--gateway-public-key /protected/gateway-public.pem`，使同一初始化事务生成加密凭据投递任务；不能用网页的 Argon2 哈希代替 EAP 凭据。

## 原生 HTTPS 运行方式

暂存部署直接由 Uvicorn 提供 HTTPS，绑定服务器内部 IP；当前不需要 Nginx 或客户端证书。运行时只读取以下环境变量：

- `VPN_MANAGER_DB`：已完成账户初始化的 SQLite 数据库路径。
- `VPN_MANAGER_WEB_DIRECTORY`：可选静态网页目录；OSS 部署时不设置，进程只提供 API。
- `VPN_MANAGER_ORIGIN`：唯一允许的 HTTPS 浏览器 Origin，例如 `https://manager.example.internal`。
- `VPN_MANAGER_SESSION_TRANSPORT`：`cookie`（默认）或 `bearer`；跨站 OSS 前端必须明确使用 `bearer`，与静态配置一致。
- `VPN_MANAGER_GATEWAY_PUBLIC_KEY` 和 `VPN_MANAGER_GATEWAY_SOCKET`：可选但必须成对配置，分别为受控 X25519 公钥文件与绝对 Unix socket 路径。Web 进程不直接运行网关投递；需另启 `python -m vpn_manager.gateway_sync --database PATH --socket PATH --watch`，由 systemd 管理唯一实例。持续模式默认每 5 秒处理待同步任务，也可用 `--once` 执行一次。
- `VPN_MANAGER_REQUIRE_GATEWAY`：仅接受 `true` 或 `false`，默认 `false` 供开发使用。正式部署必须设为 `true`，缺少完整网关配置即拒绝启动；它不会把排队状态变成已生效状态，仍需确认 `applied` 并实测 VPN。

将 `INTERNAL_IP` 替换为服务器的内部监听地址，并确保私钥文件只对运行服务的账户可读：

```sh
export VPN_MANAGER_DB=/var/lib/vpn-manager/manager.sqlite3
export VPN_MANAGER_WEB_DIRECTORY=/opt/slimjoy-vpn-manager/web
export VPN_MANAGER_ORIGIN=https://manager.example.internal
python -m vpn_manager.runtime --bind INTERNAL_IP --port 8443 \
  --cert /protected/server.pem --key /protected/server.key
```

不要使用 `--reload`，不要将监听地址改为未评估的公网地址，也不要把密钥、密码或会话令牌写入日志。ECS 的内部地址可能由 EIP 映射；仅绑定内部 IP 不构成公网隔离。内网入口需限制 VPN 来源，公网 API 则需明确评估来源、端口、认证及限流，并单独验证主机防火墙和安全组。OpenAPI、Swagger 和 ReDoc 不应作为公开入口。独立管理 API 的部署约束见 [部署说明](deploy/README.md)；生产网络暴露、TLS 证书续期、备份恢复、审计留存和真实浏览器验收仍待实际部署环境验证。

## 浏览器认证与接口约定

浏览器只能从 `VPN_MANAGER_ORIGIN` 指定的精确 HTTPS Origin 调用 API。前端配置与服务端的会话模式必须一致，两种模式均不读写 `localStorage` 或 `sessionStorage`：

- 同源 `cookie` 模式使用 `credentials: "include"`，登录返回 `{ "user": UserView, "csrf_token": string }`，会话通过安全 Cookie 传递。`POST /api/auth/refresh` 依赖已有 Cookie 与严格 Origin，返回扁平 `UserView` 字段和新的 `csrf_token`。
- OSS 跨站 `bearer` 模式使用 `credentials: "omit"`，登录响应另含 `session_token`；前端仅在内存中保存，并通过 `Authorization: Bearer ...` 发送。刷新页面或关闭页面后需重新登录，不能借助 Cookie 恢复会话。

OSS 跨站模式下，所有 `/api` 请求（包括读取和预检）必须携带唯一且精确匹配 `VPN_MANAGER_ORIGIN` 的 `Origin`；来源缺失、重复、`null` 或其他域名均返回 `403 origin_forbidden`。`GET /health` 仅返回存活状态，供服务监测使用。来源检查用于限制浏览器跨站调用；非浏览器工具可以伪造这个请求头，因此账户密码、会话、CSRF 和角色权限仍是必要的准入校验。同源 Cookie 模式的读取请求可不携带 Origin，写入仍严格校验来源。

`GET /api/auth/me` 仅返回 `UserView`，不轮换 CSRF。所有状态修改请求必须携带最新的 `X-CSRF-Token`；错误体为 `{ "error": { "code": string, "message": string } }`。

接口包括：

- 认证：`GET /health`、`POST /api/auth/login`、`POST /api/auth/logout`、`POST /api/auth/refresh`、`GET /api/auth/me`。
- 本人设备记录：`GET /api/devices`、`POST /api/devices/{device_id}/remove`。
- 网络目录：`GET /api/networks` 只返回本人已授权网络；管理员使用 `GET/POST /api/admin/networks`、`PATCH /api/admin/networks/{id}` 维护名称、说明与草稿。修改时提交 `version`，旧版本返回 `409 network_version_conflict`。新增为草稿，不能直接用于账户授权或自动接通 VPN。
- 管理员：`GET/POST /api/admin/users`、`PATCH /api/admin/users/{username}`、`POST /api/admin/users/{username}/deactivate`、`GET /api/admin/audit?cursor=&limit=20`、`GET/POST /api/admin/users/{username}/devices`、`POST /api/admin/users/{username}/devices/{device_id}/remove`。

创建设备记录的请求体只有 `{ "device_id": string }`。`DeviceView` 为 `account_id`、`device_id`、`state`（`registered` 或 `removed`）、`created_at`、`updated_at`；移除记录不等于撤销 VPN 访问。

`UserView.protected` 标记固定系统管理员 `guanxiangkai`。该账户不能降级或停用，服务端在事务中返回 `409 system_admin_protected`，其他管理员也不能绕过。其密码、网络授权仍走既有更新及审计流程；普通用户仍只能拥有工作网络权限。

网络目录迁移将数据库 v6 增量升级到 v7，保留既有账户、会话和授权。目录编辑不生成网关投递任务；改名不更换网络标识。旧代码拒绝 v7 数据库，恢复时必须使用发布前一致快照和对应旧代码，不能只回退程序。

## 网关权限与恢复

账户创建、密码、角色、网络权限及启用状态变更，会与递增 generation 和 outbox 在同一 SQLite 事务内提交。密码用 X25519/HKDF/AES-GCM 封装，仅 root 网关可解密；成功回执后清除 outbox 密文。`pending` 保留原任务重试，显式失败可用同步命令的 `--retry-failed` 重试。不得把待下发状态显示成已生效。

持续同步使用 `--watch`，不自动重放明确失败的任务。排查失败原因后，先停止持续服务，再用 `--once --retry-failed` 执行受控重试，核对具体 generation 后恢复服务；不要同时启动多个消费者。

`vpn_manager.gateway_agent` 只连接专用 charon VICI socket，不操作旧证书连接。网关按已验证的 EAP 身份选择精确账户，每用户独立地址池及 reqid。权限减少先在既有过滤链前部隔离旧流量，再卸载认证、终止全部该账户 SA、装载并读回新策略，最后解除隔离；任何一步失败均保持 `pending` 并尝试维持隔离。普通用户的家庭访问同时受流量选择器和防火墙约束。

EAP-MSCHAPv2 要求网关持有受保护的 NT 凭据，无法只使用 Argon2 哈希。该材料只留在 Linux root 私有状态目录及 charon 内存；禁止写入仓库、交付文件或日志。账号密码登录仍必须验证 VPN 服务端证书。网关至少使用修正 EAP 身份匹配问题的 strongSwan 版本，当前候选为 6.1.0。

`GET /api/vpn/status` 和 `GET /api/admin/gateway-status` 返回期望版本与实际投影状态；未配置网关时返回不可用，既有账户未投递凭据时显示 `not_provisioned`。这些状态不能代替客户端登录及实际内网转发测试。

隔离 IKE 验收脚本为 `tests/ikev2_namespace_acceptance.py`，仅在专用 Linux root 环境运行；创建唯一网络命名空间和合成凭据，验证真实代理、EAP、管理员/普通用户转发及降权，退出时清理自身资源。不得在生产网络直接执行未经检查的端口接管或全量防火墙重载。

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
