# 独立 Web API 部署

`vpn-manager-web-api.service` 只运行管理 API，没有 VPN 网关的 `Wants`、`Requires` 或 `Conflicts` 依赖。使用专用发布入口 `/opt/vpn-manager/web-current/venv`，不得为了发布网页而修改正在运行的网关虚拟环境。

部署前需在目标 Linux 上校验 unit、备份 SQLite 与配置，并验证由服务器独立执行的自动回滚。只读基线应同时记录原 VPN、家庭和工作回程的 PID、路由及防火墙；启动 Web 后重新核对。此文件不会开放防火墙，也不会切换 IKEv2。

`/etc/vpn-manager/web-api.env` 由 root 控制，只允许服务账户读取，需配置：

```ini
VPN_MANAGER_DB=/var/lib/vpn-manager/api/manager.sqlite3
VPN_MANAGER_ORIGIN=https://管理前端域名
VPN_MANAGER_SESSION_TRANSPORT=bearer
VPN_MANAGER_BIND=明确的本机私有IPv4
VPN_MANAGER_PORT=8443
```

正式 unit 设置 `VPN_MANAGER_REQUIRE_GATEWAY=true`，环境文件必须同时配置 `VPN_MANAGER_GATEWAY_PUBLIC_KEY` 与 `VPN_MANAGER_GATEWAY_SOCKET`。缺少任一项会拒绝启动。配置齐全仍不代表网关在线；账户变更通过加密队列投递，必须读回具体版本的 `applied` 状态并实测连接和权限，才能确认 VPN 生效。

前端通过 `scripts/package_web.py` 生成静态资源，API 地址须为证书覆盖的 HTTPS Origin。

TLS 证书和私钥存放在 `/etc/vpn-manager/web-api-fullchain.pem`、`web-api-key.pem`，均为 root 所有、0600；systemd 通过 `LoadCredential` 将只读副本交给服务进程。不要把服务器私钥放进前端、仓库或交付目录。

`scripts/deploy_web_certificate.py` 可作为 Certbot 续期部署钩子，使用项目虚拟环境运行：

```sh
/opt/vpn-manager/web-current/venv/bin/python /可信发布目录/scripts/deploy_web_certificate.py \
  --certificate-directory /etc/letsencrypt/live/公网IP \
  --address 公网IP --bind 本机私有监听IP --port 8443
```

钩子将 Certbot 的目录和文件链接解析到受 root 控制的 `/etc/letsencrypt` 内，校验 IP、有效期、用途、私钥匹配和系统 CA 信任链。只有原先运行的 Web 服务会重启；随后从本机监听地址发起 HTTPS `/health` 探测，仍按公网 IP 校验证书。更新失败会恢复原证书并再次校验服务；恢复失败会明确报错。首次放置证书不会自动启动服务。

IP 短期证书需要无人值守续期和到期监测，不能签发一次后长期不管。此钩子不修改 VPN 网关证书。

## 指定 IP 证书自动续期

`vpn-manager-web-certificate-renew.timer` 每天在 00:17 和 12:17 各触发一次，服务只调用带 `--cert-name` 的 Certbot `renew`，不会执行全局 `certbot renew`，不会自动接受 ToS，也不会创建新的 ACME 账户。Certbot 5.9 的续期配置必须已经由 root 人工完成；首次申请、账户注册和 ToS 确认不由 timer 代办。

续期使用 standalone HTTP-01，固定探测并占用明确的 `:80`。若端口已被任何程序占用，续期直接失败，不会停止或接管该程序，也不会修改防火墙或 VPN。公网地址、证书名和本机 Web 监听地址必须由 root 在 service 的 `ExecStart` 中替换为真实值；示例中的 `PUBLIC_IP` 不是可运行配置。

证书续期成功后复用 `deploy_web_certificate.py` 的证书链、IP SAN、服务端用途、私钥匹配、系统 CA、原值恢复和健康检查逻辑；只重启 `vpn-manager-web-api.service`。部署钩子失败、Web 仍使用旧证书、证书剩余有效期不足或恢复失败都会以非零状态退出并写入 systemd journal。timer 不接触 `ipsec`、家庭回程或 WireGuard。

首次人工准备至少包括：在 `/etc/letsencrypt` 完成指定 IP 证书和账户配置、确认公网 TCP/80 能到达本机、确认 80 未被服务占用、将 unit 中的占位地址替换为真实地址，并在启用 timer 前手动执行一次 `--dry-run` 或 staging 验证。生产启用后仍须检查 journal、实际证书 SAN/有效期和 API HTTPS 健康响应。

测试命令可在不部署、不重启 Web 的情况下运行：在续期服务参数末尾加入 `--dry-run`；该模式只执行指定证书的 Certbot 测试，明确不执行部署钩子。正式续期前会拒绝 Web 已停用的状态，绝不会自动启动停用服务。部署校验要求证书至少剩余 48 小时；160 小时是该类短期证书的 CA 生命周期，不是部署时必须剩余的时长。

## 原生 IKEv2 使用受信任的服务器证书

账户密码认证仍需要验证服务器身份。客户端可以手动添加系统原生 IKEv2，填写服务器地址、与证书一致的远程标识和普通账户密码；不需要生成 VPN 配置文件或客户端证书。地址为 IP 时，服务器证书必须包含对应 IP SAN，并由客户端系统信任的 CA 签发。不要关闭服务器证书验证。

`scripts/reload_gateway_certificate.py` 供已切换的新网关使用。它只读取 root 控制的 `/etc/vpn-manager/web-api-fullchain.pem`、`web-api-key.pem`，重新核对证书有效期、IP、服务端用途、私钥匹配与系统 CA 信任链，写入网关配置目录内固定的 `certificates/public-server.pem`。客户端密码、IP 池与网络权限不由此脚本修改。

首次启动时，在网关启动后、账户代理恢复连接模板前调用该脚本，不带 `--reload`。续期时，在 Web 证书部署成功后，通过独立 root oneshot 服务调用同一脚本并加上 `--reload`。参数 `--config`、`--state-directory` 必须是已有网关的 root 私有配置与状态目录，不能由 HTTP 请求传入。独立服务只需写入上述网关证书和状态目录，并访问已有 Unix socket；不授予 Web 进程 root 权限。

续期通过 VICI 加载服务器密钥及中间证书，再由账户代理的串行控制接口更新活动且已生效的账户连接模板。它不会重启 IKE 进程、终止现有 SA 或恢复停用账户；网关未运行时，续期调用直接返回 `gateway_inactive`。控制请求仅允许 `{"action":"reload_certificate"}`，不能指定账户、路径或其他服务器身份。模板更新失败会恢复原证书文件并报错，已加载的密钥仍留在进程内供现有会话使用；不宣称该异常路径可事务性撤销部分已更新的模板。

Web 证书钩子本身仍不操作 VPN。只有明确部署上述独立服务与续期后置调用，才会同步新网关证书。启用前应在独立 Linux 客户端验证续期后新连接可用、既有 SA 未被终止、停用账户未恢复，并分别完成 Mac、Windows 原生客户端验收。保存开机启动设置不等于已完成服务器重启验收。
