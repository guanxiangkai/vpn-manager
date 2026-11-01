# VPN 管理器静态前端

`web/` 是无构建依赖的静态 ES 模块站点，只能用于受控暂存验收。不得上传至公开 OSS 或其他公开静态托管。`config.json` 的空 `apiBaseUrl` 表示**同源 API**（默认）；如确需分离 API 主机，只能填写单一 HTTPS URL，并且不得写入用户名、密码或令牌。

## 浏览器会话安全

- API 只允许受服务端明确配置的 HTTPS Origin。浏览器自动携带 HttpOnly Secure SameSite=Lax 会话 Cookie；前端采用 `credentials: "include"`，且不读写 `localStorage` 或 `sessionStorage`。启动恢复使用严格 Origin 保护的 `POST /api/auth/refresh`；页面不能伪造浏览器受限的 `Origin` 请求头。
- 登录响应与 `POST /api/auth/refresh` 的 `csrf_token` 仅保存在页面内存。`GET /api/auth/me` 仅返回无副作用的扁平用户资料，不轮换 CSRF。登录只使用账户和密码；浏览器不发送设备指纹或自定义认证头。
- 设备名单是管理员维护的管理记录：每个账户至多 10 条 `registered` 记录，`removed` 记录不计数。它不验证设备身份、不签发或导入密钥，也不会阻止取得账户密码的新设备登录或连接 VPN；绝不能把设备记录或移除记录表示为实际 VPN 准入或撤销。

此静态站点由服务的原生 HTTPS 入口提供，不依赖 Nginx 或客户端证书。生产部署的响应安全头、TLS 证书轮换、浏览器兼容性和公网网络边界仍待实际环境验收。

## API 兼容性

调用以下已冻结的 JSON 契约：`GET /health`，`POST /api/auth/login`、`POST /api/auth/logout`、`POST /api/auth/refresh`、`GET /api/auth/me`，个人设备的 `GET /api/devices`、`POST /api/devices/{device_id}/remove`，`GET/POST /api/admin/users`、`PATCH /api/admin/users/{username}`、`POST /api/admin/users/{username}/deactivate`，`GET /api/admin/audit?cursor=&limit=20`，以及管理员专用的 `GET/POST /api/admin/users/{username}/devices`、`POST /api/admin/users/{username}/devices/{device_id}/remove`。设备创建请求仅有 `{ "device_id": string }`；`DeviceView` 仅有 `account_id`、`device_id`、`state`（`registered` 或 `removed`）、`created_at` 和 `updated_at`。`POST /api/auth/refresh` 返回扁平 `User` 字段与新 `csrf_token`，并需要已有会话 Cookie 和严格 HTTPS Origin；`GET /api/auth/me` 只返回扁平 `User`。错误体固定为 `{ "error": { "code": string, "message": string } }`。

普通用户可读取自己的设备记录，不能自助登记或移除。管理员才显示跨账户设备、账户和审计功能。服务端仍是账户认证、角色授权和数据隔离边界。
