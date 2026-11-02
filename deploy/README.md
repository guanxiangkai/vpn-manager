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
