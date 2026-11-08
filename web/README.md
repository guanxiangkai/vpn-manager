# VPN 管理器静态前端

`web/` 是无构建依赖的静态 ES 模块站点。支持同源部署，也支持香港 OSS 静态前端与独立 HTTPS API。公开目录只包含 `index.html`、JS、CSS 和 `config.json` 四个静态文件；不得上传账户秘密、数据库、私钥、源代码目录或服务器备份。

页面按访问概览、网络环境、账户与授权、登录审计组织，普通用户只显示自身授权。账户列表支持账户名搜索与状态组合筛选，列表错误可重试，审计使用服务端游标分页。网络卡片展示账户授权，实际连接状态以系统 VPN 为准。产品任务、视觉及状态边界见 [设计说明](DESIGN.md)。

## OSS 与独立 API

先在 Linux 验收环境运行以下打包命令；示例 IP 是占位地址，应替换为实际的 HTTPS API 来源：

```sh
python scripts/package_web.py --api-origin https://203.0.113.10:8443 --fingerprint-assets --output /tmp/vpn-manager-public
```

打包器将 API 来源写入公开配置和页面 CSP，只放行这一来源的连接。API 必须有浏览器信任且覆盖目标主机/IP 的服务器证书。OSS 只开放静态资源读取，不能开放匿名写入。默认首页设置为 `index.html`。是否需要备案应单独依据部署地域、接入方式及服务商规则核实，不能以接口名称替代判断。

`--fingerprint-assets` 会输出 `app.<内容哈希>.js` 和 `styles.<内容哈希>.css`，并同步首页引用；省略选项时保留原文件名兼容现有调用方。发布时先保存当前公开四文件及哈希作为恢复点，上传并验证新的 JS/CSS，再替换 `index.html`；API 配置不变时不必重复覆盖。旧版资源保留供已打开页面及回滚使用。仅将本次静态文件设置为公共读，保留 Bucket 私有、禁止匿名写入。

跨站配置使用 `sessionTransport: "bearer"`；服务端必须对应设置 `VPN_MANAGER_SESSION_TRANSPORT=bearer` 和唯一的 `VPN_MANAGER_ORIGIN`。浏览器不发送 API Cookie，随机会话令牌只保存在页面内存，刷新或关闭页面后需重新登录。不依赖第三方 Cookie，也不把令牌存进 URL、`localStorage` 或 `sessionStorage`。

管理 API 可由独立的 `vpn-manager-web-api.service` 运行，不启动网关、同步代理或旧 VPN 的替代服务。管理端登录成功不代表新的 IKEv2 认证已切换；页面会明确显示尚未接通的网关状态。实际切换仍需备份、自动回滚及真实权限验收。

## 浏览器会话安全

- API 只允许受服务端明确配置的 HTTPS Origin；CORS 是浏览器访问策略，不能代替账户认证与授权。同源 Cookie 模式保留 HttpOnly、Secure、SameSite=Lax 会话和启动恢复；跨站 Bearer 模式使用 `credentials: "omit"`，不设置会话 Cookie。
- 登录响应与 `POST /api/auth/refresh` 的 `csrf_token` 仅保存在页面内存。`GET /api/auth/me` 仅返回无副作用的扁平用户资料，不轮换 CSRF。登录只使用账户和密码；浏览器不发送设备指纹或自定义认证头。

两种模式都需要 HTTPS 服务器证书，不需要设备证书。生产 TLS、跨域登录、证书续期和公网网络边界须分别完成实际环境验收。

## 网络目录与系统管理员

登录页仅显示抽象访问关系，不读取或公开真实网络目录。登录后使用 `/api/networks` 获取本人已授权网络的名称和说明；管理员的“网络环境”维护完整目录，“账户与授权”提供独立的网络授权入口。改名沿用稳定标识，不改变账户权限。新建网络只能保存草稿，不能直接授权、修改 VPN 路由或宣称已接通。

`guanxiangkai` 为受保护系统管理员。前端禁用停用和降级控件；服务端在事务内独立拒绝这些请求，即使存在其他管理员也不能绕过。普通用户仍只允许工作网络权限。

网络目录数据库版本为 v7。发布前保存一致数据库快照与旧版代码；回滚必须同时恢复两者，仅回退代码不足以恢复 v6 兼容。

## API 兼容性

接口包括 `GET /health`，`POST /api/auth/login`、`POST /api/auth/logout`、`POST /api/auth/refresh`、`GET /api/auth/me`、`GET /api/vpn/status`，个人设备的 `GET /api/devices`、`POST /api/devices/{device_id}/remove`，`GET/POST /api/admin/users`、`PATCH /api/admin/users/{username}`、`POST /api/admin/users/{username}/deactivate`，`GET /api/admin/audit?cursor=&limit=20`，以及管理员专用的 `GET/POST /api/admin/users/{username}/devices`、`POST /api/admin/users/{username}/devices/{device_id}/remove`。Bearer 登录额外返回 `session_token`，Cookie 登录保持原响应且不返回该字段。写操作仍需严格 Origin、有效会话和内存 CSRF；账户变更会撤销旧会话。`GET /api/auth/me` 只返回扁平 `User`，不轮换凭据；错误体为 `{ "error": { "code": string, "message": string } }`。

普通用户在页面查看本人的网络授权。管理员可以管理网络、账户和审计。现有设备记录接口仍属于服务端兼容契约。服务端负责账户认证、角色授权和数据隔离。
