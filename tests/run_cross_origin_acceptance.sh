#!/usr/bin/env bash
# 在 Linux CI 启动独立 API 与静态 HTTPS 来源，运行真实 Chromium 跨站验收。
set -euo pipefail
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/vpn-manager-cross-origin.XXXXXX")
api_pid=""; static_pid=""
cleanup() { status=$?; [[ -n "$api_pid" ]] && kill "$api_pid" 2>/dev/null || true; [[ -n "$static_pid" ]] && kill "$static_pid" 2>/dev/null || true; wait "$api_pid" 2>/dev/null || true; wait "$static_pid" 2>/dev/null || true; rm -rf "$temporary_directory"; exit "$status"; }
trap cleanup EXIT INT TERM
certificate="$temporary_directory/server.pem"; private_key="$temporary_directory/server.key"; database="$temporary_directory/manager.sqlite3"; web_directory="$temporary_directory/web"; api_log="$temporary_directory/api.log"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 -keyout "$private_key" -out "$certificate" -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1,IP:127.0.0.2" >/dev/null 2>&1
chmod 600 "$private_key"
printf '%s' '[{"username":"adminone","password":"correct-horse-admin-one","role":"admin","networks":["home","work"]},{"username":"member","password":"correct-horse-member","role":"user","networks":["work"]}]' | python -m vpn_manager.bootstrap --database "$database" >/dev/null
python scripts/package_web.py --api-origin https://127.0.0.2:18445 --output "$web_directory" >/dev/null
export VPN_MANAGER_DB="$database" VPN_MANAGER_ORIGIN=https://127.0.0.1:18444 VPN_MANAGER_SESSION_TRANSPORT=bearer
unset VPN_MANAGER_WEB_DIRECTORY
export NO_PROXY="127.0.0.1,127.0.0.2" no_proxy="127.0.0.1,127.0.0.2"
python -m vpn_manager.runtime --bind 127.0.0.2 --port 18445 --cert "$certificate" --key "$private_key" >"$api_log" 2>&1 & api_pid=$!
python - "$certificate" "$private_key" "$web_directory" <<'PY' &
import http.server, os, ssl, sys
os.chdir(sys.argv[3])
server = http.server.ThreadingHTTPServer(("127.0.0.1", 18444), http.server.SimpleHTTPRequestHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
static_pid=$!
for attempt in $(seq 1 80); do
  if curl --fail --silent --insecure https://127.0.0.2:18445/health | grep -q '"message":"ok"' && curl --fail --silent --insecure https://127.0.0.1:18444/config.json | grep -q 'sessionTransport'; then
    export VPN_MANAGER_CROSS_ORIGIN_FRONTEND=https://127.0.0.1:18444 VPN_MANAGER_CROSS_ORIGIN_API=https://127.0.0.2:18445
    python -m pytest tests/browser_cross_origin_acceptance.py -q
    exit 0
  fi
  kill -0 "$api_pid" 2>/dev/null || break
  sleep 0.25
done
sed -n '1,160p' "$api_log" >&2
exit 1
