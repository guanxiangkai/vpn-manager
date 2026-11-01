#!/usr/bin/env bash
# 在隔离 Linux 中创建临时 HTTPS 服务并运行真实 Chromium 验收；不修改系统 VPN 或网络配置。
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/vpn-manager-browser.XXXXXX")
server_pid=""

cleanup() {
  status=$?
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$temporary_directory"
  exit "$status"
}
trap cleanup EXIT INT TERM

certificate="$temporary_directory/server.pem"
private_key="$temporary_directory/server.key"
database="$temporary_directory/manager.sqlite3"
server_log="$temporary_directory/runtime.log"

# SAN 必须包含 127.0.0.1，供 Chromium 访问本机 HTTPS 服务。
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -keyout "$private_key" -out "$certificate" \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
chmod 600 "$private_key"

# 仅使用已公开的隔离测试夹具账户；密码不会传给运行时环境变量。
printf '%s' '[{"username":"adminone","password":"correct-horse-admin-one","role":"admin","networks":["home","work"]},{"username":"member","password":"correct-horse-member","role":"user","networks":["work"]}]' \
  | python -m vpn_manager.bootstrap --database "$database" >/dev/null

export VPN_MANAGER_DB="$database"
export VPN_MANAGER_WEB_DIRECTORY="$repository_root/web"
export VPN_MANAGER_ORIGIN="https://127.0.0.1:18443"

python -m vpn_manager.runtime --bind 127.0.0.1 --port 18443 \
  --cert "$certificate" --key "$private_key" >"$server_log" 2>&1 &
server_pid=$!

# 只在本机临时服务返回健康响应后才启动浏览器；失败时输出该服务自己的日志。
for attempt in $(seq 1 80); do
  if curl --fail --silent --show-error --insecure https://127.0.0.1:18443/health | grep -q '"message":"ok"'; then
    export VPN_MANAGER_TEST_URL="https://127.0.0.1:18443"
    python -m pytest tests/browser_acceptance.py -q
    exit 0
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    break
  fi
  sleep 0.25
done

sed -n '1,200p' "$server_log" >&2
echo "临时 HTTPS 服务未在预期时间内通过健康检查。" >&2
exit 1
