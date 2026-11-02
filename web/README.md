# VPN 管理器静态前端

`web/` 是无构建依赖的静态 ES 模块站点。支持同源部署，也支持香港 OSS 静态前端与独立 HTTPS API。公开目录只包含 `index.html`、`app.js`、`styles.css` 和 `config.json`；不得上传账户秘密、数据库、私钥、源代码目录或服务器备份。

## OSS 与独立 API

先在 Linux 验收环境运行以下打包命令；示例 IP 是占位地址，应替换为实际的 HTTPS API 来源：

```sh
python scripts/package_web.py --api-origin https://203.0.113.10:8443 --output /tmp/vpn-manager-public
```

打包器将 API 来源写入公开配置和页面 CSP，只放行这一来源的连接。API 必须有浏览器信任且覆盖目标主机/IP 的服务器证书。OSS 只开放静态资源读取，不能开放匿名写入。默认首页设置为 `index.html`。是否需要备案应单独依据部署地域、接入方式及服务商规则核实，不能以接口名称替代判断。

跨站配置使用 `sessionTransport: "bearer"`；服务端必须对应设置 `VPN_MANAGER_SESSION_TRANSPORT=bearer` 和唯一的 `VPN_MANAGER_ORIGIN`。浏览器不发送 API Cookie，随机会话令牌只保存在页面内存，刷新或关闭页面后需重新登录。不依赖第三方 Cookie，也不把令牌存进 URL、`localStorage` 或 `sessionStorage`。

管理 API 可由独立的 `vpn-manager-web-api.service` 运行，不启动网关、同步代理或旧 VPN 的替代服务。管理端登录成功不代表新的 IKEv2 认证已切换；页面会明确显示尚未接通的网关状态。实际切换仍需备份、自动回滚及真实权限验收。

## 浏览器会话安全

- API 只允许受服务端明确配置的 HTTPS Origin；CORS 是浏览器访问策略，不能代替账户认证与授权。同源 Cookie 模式保留 HttpOnly、Secure、SameSite=Lax 会话和启动恢复；跨站 Bearer 模式使用 `credentials: "omit"`，不设置会话 Cookie。
- 登录响应与 `POST /api/auth/refresh` 的 `csrf_token` 仅保存在页面内存。`GET /api/auth/me` 仅返回无副作用的扁平用户资料，不轮换 CSRF。登录只使用账户和密码；浏览器不发送设备指纹或自定义认证头。
- 设备名单是管理员维护的管理记录：每个账户至多 10 条 `registered` 记录，`removed` 记录不计数。它不验证设备身份、不签发或导入密钥，也不会阻止取得账户密码的新设备登录或连接 VPN；绝不能把设备记录或移除记录表示为实际 VPN 准入或撤销。

两种模式都需要 HTTPS 服务器证书，不需要设备证书。生产 TLS、跨域登录、证书续期和公网网络边界须分别完成实际环境验收。

## API 兼容性

接口包括 `GET /health`，`POST /api/auth/login`、`POST /api/auth/logout`、`POST /api/auth/refresh`、`GET /api/auth/me`、`GET /api/vpn/status`，个人设备的 `GET /api/devices`、`POST /api/devices/{device_id}/remove`，`GET/POST /api/admin/users`、`PATCH /api/admin/users/{username}`、`POST /api/admin/users/{username}/deactivate`，`GET /api/admin/audit?cursor=&limit=20`，以及管理员专用的 `GET/POST /api/admin/users/{username}/devices`、`POST /api/admin/users/{username}/devices/{device_id}/remove`。Bearer 登录额外返回 `session_token`，Cookie 登录保持原响应且不返回该字段。写操作仍需严格 Origin、有效会话和内存 CSRF；账户变更会撤销旧会话。`GET /api/auth/me` 只返回扁平 `User`，不轮换凭据；错误体为 `{ "error": { "code": string, "message": string } }`。

普通用户在页面查看自己的设备记录，不显示自助登记和移除入口；本人记录移除接口仅允许操作自己名下的记录。管理员才显示跨账户设备、账户和审计功能。服务端仍是账户认证、角色授权和数据隔离边界。
