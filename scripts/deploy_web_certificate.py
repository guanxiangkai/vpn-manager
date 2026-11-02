#!/usr/bin/env python3
"""校验并部署公网 API 证书；续期钩子只重启独立 Web 服务。"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import http.client
from ipaddress import ip_address
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

ROOT_UID = 0
CERTBOT_ROOT = Path("/etc/letsencrypt")
WEB_UNIT = "vpn-manager-web-api.service"


def validate(certificate: bytes, key: bytes, address: str) -> None:
    """校验证书有效期、IP、服务端用途及密钥匹配；失败时不改目标文件。"""
    certificates = x509.load_pem_x509_certificates(certificate)
    if not certificates:
        raise ValueError("证书链为空")
    leaf = certificates[0]
    now = datetime.now(timezone.utc)
    if leaf.not_valid_before_utc > now or leaf.not_valid_after_utc < now + timedelta(hours=48):
        raise ValueError("证书尚未生效或剩余有效期不足 48 小时")
    addresses = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if ip_address(address) not in addresses.get_values_for_type(x509.IPAddress):
        raise ValueError("证书未覆盖 API 公网 IP")
    usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if ExtendedKeyUsageOID.SERVER_AUTH not in usage:
        raise ValueError("证书不能用于服务端认证")
    private_key = serialization.load_pem_private_key(key, password=None)
    encoding = serialization.Encoding.DER
    form = serialization.PublicFormat.SubjectPublicKeyInfo
    if private_key.public_key().public_bytes(encoding, form) != leaf.public_key().public_bytes(encoding, form):
        raise ValueError("证书与私钥不匹配")


def _secure_directory(path: Path) -> None:
    for directory in (path, *path.parents):
        mode = directory.lstat()
        if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != ROOT_UID or mode.st_mode & 0o022:
            raise RuntimeError("证书目录必须由 root 控制，且不能是符号链接")


def _atomic_write(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        previous = path.lstat()
        if not stat.S_ISREG(previous.st_mode) or previous.st_uid != ROOT_UID or previous.st_mode & 0o077:
            raise RuntimeError("拒绝覆盖不受控的证书目标")
    descriptor, temporary = tempfile.mkstemp(prefix=".web-certificate-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _source_files(source: Path) -> dict[str, Path]:
    """允许 Certbot 的 live 链接，但解析后的所有文件须留在受控根内。"""
    if not source.is_absolute():
        raise ValueError("证书目录必须为绝对路径")
    _secure_directory(CERTBOT_ROOT)
    _secure_directory(source.parent)
    mode = source.lstat()
    if mode.st_uid != ROOT_UID or not (stat.S_ISDIR(mode.st_mode) or stat.S_ISLNK(mode.st_mode)):
        raise RuntimeError("证书来源目录不受控")
    allowed = CERTBOT_ROOT.resolve(strict=True)
    resolved = source.resolve(strict=True)
    if not resolved.is_relative_to(allowed):
        raise RuntimeError("证书来源超出 Certbot 根目录")
    _secure_directory(resolved)
    inputs = {}
    for name in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"):
        original = resolved / name
        if original.lstat().st_uid != ROOT_UID:
            raise RuntimeError("证书来源文件不受控")
        path = original.resolve(strict=True)
        if not path.is_relative_to(allowed):
            raise RuntimeError("证书文件超出 Certbot 根目录")
        _secure_directory(path.parent)
        mode = path.lstat()
        if not stat.S_ISREG(mode.st_mode) or mode.st_uid != ROOT_UID or mode.st_mode & (0o077 if name == "privkey.pem" else 0o022):
            raise RuntimeError("Certbot 证书文件权限不安全")
        inputs[name] = path
    return inputs


def _active() -> bool:
    result = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", WEB_UNIT], capture_output=True, timeout=10)
    if result.returncode not in {0, 3, 4}:
        raise RuntimeError("无法确定 Web 服务状态")
    return result.returncode == 0


def _health(bind: str, port: int, address: str) -> None:
    """连接本机监听地址，仍以公网 IP 校验系统 CA、主机名和 HTTP 健康响应。"""
    context = ssl.create_default_context()
    with socket.create_connection((bind, port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname=address) as connection:
            connection.sendall(f"GET /health HTTP/1.1\r\nHost: {address}:{port}\r\nConnection: close\r\n\r\n".encode("ascii"))
            response = http.client.HTTPResponse(connection)
            response.begin()
            body = response.read(4097)
            if response.status != 200 or len(body) > 4096 or json.loads(body) != {"message": "ok"}:
                raise RuntimeError("Web HTTPS 健康响应无效")


def _restart_and_wait(bind: str, port: int, address: str) -> None:
    subprocess.run(["/usr/bin/systemctl", "restart", WEB_UNIT], check=True, capture_output=True, timeout=45)
    deadline = time.monotonic() + 20
    while True:
        try:
            if not _active():
                raise RuntimeError("Web 服务未运行")
            _health(bind, port, address)
            return
        except (OSError, ValueError, RuntimeError, http.client.HTTPException) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError("Web 重启后未通过受信任 HTTPS 健康检查") from error
            time.sleep(0.5)


def _deploy(source: Path, address: str, bind: str, port: int, *, destination: Path = Path("/etc/vpn-manager")) -> None:
    inputs = _source_files(source)
    certificate = inputs["fullchain.pem"].read_bytes()
    key = inputs["privkey.pem"].read_bytes()
    validate(certificate, key, address)
    # 使用系统 CA 独立验证完整信任链，不因 PEM 可解析就信任自签证书。
    subprocess.run(["/usr/bin/openssl", "verify", "-purpose", "sslserver", "-verify_ip", str(ip_address(address)),
                    "-untrusted", str(inputs["chain.pem"]), str(inputs["cert.pem"])],
                   check=True, capture_output=True, timeout=20)
    deployed = x509.load_pem_x509_certificates(certificate)
    expected = x509.load_pem_x509_certificates(inputs["cert.pem"].read_bytes()) + x509.load_pem_x509_certificates(inputs["chain.pem"].read_bytes())
    if deployed != expected:
        raise ValueError("信任验证与实际部署的完整证书链不一致")
    _secure_directory(destination)
    was_active = _active()
    paths = (destination / "web-api-fullchain.pem", destination / "web-api-key.pem")
    old = {}
    for path in paths:
        if path.exists() or path.is_symlink():
            mode = path.lstat()
            if not stat.S_ISREG(mode.st_mode) or mode.st_uid != ROOT_UID or mode.st_mode & 0o077:
                raise RuntimeError("原有证书目标不安全")
            old[path] = path.read_bytes()
        else:
            old[path] = None
    try:
        _atomic_write(paths[0], certificate)
        _atomic_write(paths[1], key)
        if was_active:
            _restart_and_wait(bind, port, address)
    except BaseException as failure:
        try:
            for path, content in old.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    _atomic_write(path, content)
            if was_active:
                _restart_and_wait(bind, port, address)
        except BaseException as recovery:
            raise RuntimeError("证书部署失败，且原证书或 HTTPS 服务未能恢复；需要立即处理") from recovery
        raise RuntimeError("证书部署失败；原证书已恢复，原运行服务已重新验证") from failure


def deploy_with_lock(source: Path, address: str, bind: str, port: int, *, destination: Path = Path("/etc/vpn-manager"), require_active: bool = False) -> None:
    """以与 CLI 相同的 root 锁执行部署，供受控续期入口复用。"""
    _secure_directory(destination)
    descriptor = os.open(destination / "web-certificate.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+") as lock:
        mode = os.fstat(lock.fileno())
        if not stat.S_ISREG(mode.st_mode) or mode.st_uid != ROOT_UID or mode.st_mode & 0o077:
            raise RuntimeError("证书部署锁不安全")
        fcntl.flock(lock, fcntl.LOCK_EX)
        if require_active and not _active():
            raise RuntimeError("Web 服务未运行，拒绝续期部署；不会自动启动服务")
        _deploy(source, address, bind, port, destination=destination)


def main() -> None:
    """串行部署 Certbot 的续期证书；仅重启 Web，失败则恢复原证书。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate-directory", type=Path, required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--bind", required=True, help="Web 服务的明确本机私有监听地址")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("证书部署必须由 root 执行")
    ip_address(args.address)
    bind = ip_address(args.bind)
    if not bind.is_private or bind.is_unspecified or bind.is_multicast or not 1024 <= args.port <= 65535:
        parser.error("健康检查必须使用明确的本机私有 IP 和非特权端口")
    directory = Path("/etc/vpn-manager")
    _secure_directory(directory)
    deploy_with_lock(args.certificate_directory, args.address, str(bind), args.port, destination=directory)


if __name__ == "__main__":
    main()
