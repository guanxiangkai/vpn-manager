#!/usr/bin/env python3
"""续期并部署唯一指定的 Web IP 证书；不执行全局 certbot renew。"""
from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import socket
import stat
import subprocess

import deploy_web_certificate as deployment

CERTBOT = "/usr/bin/certbot"
WEB_UNIT = "vpn-manager-web-api.service"
ROOT_UID = 0


def _root_path(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"{label}必须是绝对非符号链接路径")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{label}路径无效")
    return path


def _assert_port_free(bind: str, port: int) -> None:
    """只探测端口，不停止或接管任何现有服务。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((bind, port))
        except OSError as error:
            raise RuntimeError(f"HTTP-01 端口 {bind}:{port} 已被占用，拒绝续期") from error


def _run_certbot(cert_name: str, address: str, certbot_root: Path, *, bind: str = "127.0.0.1",
                 certbot: str = CERTBOT, dry_run: bool = False) -> None:
    command = [certbot, "renew", "--cert-name", cert_name, "--non-interactive",
               "--no-random-sleep-on-renew",
               "--authenticator", "standalone", "--preferred-challenges", "http-01",
               "--http-01-port", "80", "--http-01-address", bind,
               "--no-directory-hooks", "--config-dir", str(certbot_root),
               "--work-dir", str(certbot_root / "work"), "--logs-dir", str(certbot_root / "logs")]
    # IP SAN 与 cert-name 都来自受控 unit 参数；不拼接 shell 命令。
    if dry_run:
        command.append("--dry-run")
    # systemd timer 已负责随机错峰；避免 Certbot 再次等待并超过单次执行保护时限。
    # renew 沿用指定证书的续期配置，不重新提交 --ip-address 申请参数。
    subprocess.run(command, check=True, capture_output=True,
                   text=True, timeout=180)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert-name", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--certificate-directory", required=True, type=Path)
    parser.add_argument("--certbot-root", default="/etc/letsencrypt", type=Path)
    parser.add_argument("--certbot", default=CERTBOT, help="已安装的 Certbot 绝对路径")
    parser.add_argument("--port", default=80, type=int)
    parser.add_argument("--web-bind", default="127.0.0.1")
    parser.add_argument("--web-port", default=8443, type=int)
    parser.add_argument("--dry-run", action="store_true", help="仅执行 Certbot 测试，不部署、不重启 Web")
    args = parser.parse_args()
    if os.geteuid() != ROOT_UID:
        parser.error("证书续期必须由 root 执行")
    if not args.cert_name or args.cert_name.startswith("-") or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in args.cert_name):
        parser.error("证书名称包含不允许的字符")
    address = ipaddress.ip_address(args.address)
    bind = ipaddress.ip_address(args.bind)
    if address.is_unspecified or address.is_multicast or bind.is_unspecified or bind.is_multicast:
        parser.error("公网地址和 HTTP-01 监听地址必须明确")
    if args.port != 80 or not 1 <= args.port <= 65535:
        parser.error("HTTP-01 端口固定为 80")
    if not 1024 <= args.web_port <= 65535:
        parser.error("Web 健康检查端口无效")
    certbot_root = _root_path(str(args.certbot_root), "Certbot 根目录")
    certificate_directory = _root_path(str(args.certificate_directory), "证书目录")
    certbot = _root_path(args.certbot, "Certbot 程序")
    deployment._secure_directory(certbot.parent)
    executable = certbot.lstat()
    if not stat.S_ISREG(executable.st_mode) or executable.st_uid != ROOT_UID or executable.st_mode & 0o022 or not os.access(certbot, os.X_OK):
        parser.error("Certbot 程序必须由 root 控制且可执行")
    deployment._secure_directory(certbot_root)
    deployment._secure_directory(certificate_directory.parent)
    _assert_port_free(str(bind), 80)
    _run_certbot(args.cert_name, str(address), certbot_root, bind=str(bind),
                 certbot=str(certbot), dry_run=args.dry_run)
    if args.dry_run:
        return
    # 复用既有完整证书链验证、原值恢复和仅重启 Web 的部署逻辑。
    deployment.deploy_with_lock(certificate_directory, str(address), str(args.web_bind), args.web_port, require_active=True)


if __name__ == "__main__":
    main()
