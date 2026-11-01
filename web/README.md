# VPN 管理器静态前端

`web/` 是无构建依赖的静态 ES 模块站点，只能用于受控的只读暂存验收。不得上传至公开 OSS 或其他公开静态托管。`config.json` 只含内部部署时注入的 `apiBaseUrl`，不得写入用户名、密码、令牌、设备证书或私钥。

## 前置安全边界

- 在提供任何页面前，前置代理必须对 **HTML、CSS、JavaScript、config.json 和 API** 全部执行设备 mTLS 验证；无已注入的服务端 web 客户端证书登记验证器时，所有 `/api/*` 会以 `503 device_verification_unavailable` 拒绝。
- API 只允许 `https://slimjoy.cn` Origin。浏览器自动携带 HttpOnly Secure SameSite=Lax 会话 Cookie；前端采用 `credentials: "include"`，且不读写 `localStorage` 或 `sessionStorage`。
- 登录响应与 `GET /api/auth/me` 的 `csrf_token` 仅保存在页面内存。`/api/auth/me` 会轮换 CSRF 令牌，前端立即替换旧值；浏览器不能自行建立设备身份，也不发送设备指纹或自定义认证头。
- 建议受控暂存代理使用至少：`default-src 'self'; connect-src 'self' https://<已配置的 API 主机>; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`。将 `<已配置的 API 主机>` 替换为单一内部 API 主机。
- 本网页不提供自助登记、激活、签发或导入设备密钥的入口。设备预留只由管理员录入受控流程已签发的标识；预留不是启用。撤销会立即标记管理访问为已撤销，但 VPN 网关状态为 `pending` 前不表示 VPN 撤销已经完成。

## API 兼容性

调用以下已冻结的 JSON 契约：`GET /health`，`POST /api/auth/login`、`POST /api/auth/logout`、`GET /api/auth/me`，个人设备的 `GET /api/devices`、`POST /api/devices/{device_id}/revoke`，`GET/POST /api/admin/users`、`PATCH /api/admin/users/{username}`、`POST /api/admin/users/{username}/deactivate`，`GET /api/admin/audit?cursor=&limit=20`，以及管理员专用的 `GET /api/admin/users/{username}/devices`、`POST /api/admin/users/{username}/devices/reservations`、`POST /api/admin/users/{username}/devices/{device_id}/revoke`。`/api/auth/me` 返回扁平 `User` 字段与 `csrf_token`，并需要已验证设备、现有会话 Cookie 和 `https://slimjoy.cn` Origin；错误体固定为 `{ "error": { "code": string, "message": string } }`。

普通用户可读取和撤销自己的设备，不能自助登记或激活。撤销后的管理访问已撤销与网关撤销确认是独立状态；再次使用必须由管理员按受控流程重新登记。管理员才显示跨账户设备、账户和审计功能。服务端仍是唯一的设备验证、授权和数据隔离边界。
