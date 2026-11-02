"""独立 HTTPS API 入口；不修改系统网络、VPN、代理或防火墙。"""
from __future__ import annotations

import argparse
from ipaddress import ip_address
import os
from pathlib import Path
import stat
import struct

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from .app import create_app
from .gateway_sync import GatewayClient


def _is_private_service_credential(info: os.stat_result, descriptor: int) -> bool:
    """仅兼容 systemd 给当前服务用户增加只读 ACL 的凭据文件。"""
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o440 or os.geteuid() == 0:
        return False
    # Linux POSIX ACL 的组权限位表示 ACL mask，不能据此认定整个组可读。
    # 只接受这一组完整条目：root 和当前 UID 只读，属组及其他用户无权限。
    undefined_id = 0xFFFFFFFF
    entries = ((1, 4, undefined_id), (2, 4, os.geteuid()),
               (4, 0, undefined_id), (16, 4, undefined_id), (32, 0, undefined_id))
    expected = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)
    try:
        return os.getxattr(descriptor, "system.posix_acl_access") == expected
    except (AttributeError, OSError):
        return False


def _validate_tls_private_key(path: Path) -> None:
    """通过已打开的文件核对权限；拒绝链接、非普通文件及额外读者。"""
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError("TLS 私钥文件权限或属主不安全")
        flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)
            if not stat.S_ISREG(info.st_mode) or identity(before) != identity(info):
                raise RuntimeError("TLS 私钥文件权限或属主不安全")
            private_mode = not info.st_mode & 0o077 and info.st_uid in {0, os.geteuid()}
            if not private_mode and not _is_private_service_credential(info, descriptor):
                raise RuntimeError("TLS 私钥文件权限或属主不安全")
        finally:
            os.close(descriptor)
    except OSError as error:
        raise RuntimeError("无法安全读取 TLS 私钥文件") from error


def _load_gateway_public_key(value: str) -> bytes:
    """只接受受控的常规 PEM 文件，拒绝链接、目录及可被旁人改写的配置。"""
    path = Path(value)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o022:
            raise RuntimeError("网关公钥文件不安全")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            after = os.fstat(descriptor)
            if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise RuntimeError("网关公钥文件不安全")
            data = os.read(descriptor, 16 * 1024 + 1)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise RuntimeError("无法安全读取网关公钥") from error
    if not data or len(data) > 16 * 1024:
        raise RuntimeError("网关公钥文件无效")
    try:
        key = serialization.load_pem_public_key(data)
    except (TypeError, ValueError) as error:
        raise RuntimeError("网关公钥文件无效") from error
    if not isinstance(key, X25519PublicKey):
        raise RuntimeError("网关公钥必须为 X25519")
    return data


def _require_gateway() -> bool:
    """解析生产保护开关；除 true/false 外拒绝启动，避免拼写被静默忽略。"""
    value = os.environ.get("VPN_MANAGER_REQUIRE_GATEWAY", "false").strip().lower()
    if value not in {"true", "false"}:
        raise RuntimeError("VPN_MANAGER_REQUIRE_GATEWAY 必须为 true 或 false")
    return value == "true"


def application():
    required = ("VPN_MANAGER_DB", "VPN_MANAGER_ORIGIN")
    if any(not os.environ.get(name) for name in required):
        raise RuntimeError("管理服务缺少必要配置，拒绝启动")
    database = Path(os.environ["VPN_MANAGER_DB"])
    if not database.is_file():
        raise RuntimeError("必须先完成账户初始化")
    require_gateway = _require_gateway()
    public_key_path, socket_path = os.environ.get("VPN_MANAGER_GATEWAY_PUBLIC_KEY"), os.environ.get("VPN_MANAGER_GATEWAY_SOCKET")
    if bool(public_key_path) != bool(socket_path):
        raise RuntimeError("网关公钥与 Unix socket 必须同时配置")
    if require_gateway and not (public_key_path and socket_path):
        raise RuntimeError("生产保护模式要求同时配置网关公钥与 Unix socket")
    gateway_public_key = _load_gateway_public_key(public_key_path) if public_key_path else None
    if socket_path and not Path(socket_path).is_absolute():
        raise RuntimeError("网关 Unix socket 必须使用绝对路径")
    gateway_client = GatewayClient(socket_path) if socket_path else None
    return create_app(database, allowed_origin=os.environ["VPN_MANAGER_ORIGIN"], web_directory=os.environ.get("VPN_MANAGER_WEB_DIRECTORY") or None, gateway_public_key=gateway_public_key, gateway_client=gateway_client, session_transport=os.environ.get("VPN_MANAGER_SESSION_TRANSPORT", "cookie"))


def main() -> None:
    parser = argparse.ArgumentParser(description="启动内部 HTTPS 管理服务，不提供设备证书认证")
    parser.add_argument("--bind",required=True)
    parser.add_argument("--port",type=int,default=8443)
    parser.add_argument("--cert",required=True,type=Path)
    parser.add_argument("--key",required=True,type=Path)
    args = parser.parse_args()
    address = ip_address(args.bind)
    if address.is_unspecified or address.is_multicast or not address.is_private:
        parser.error("服务必须绑定明确的本地内部 IP，公网映射由部署层单独配置")
    if not 1024 <= args.port <= 65535:
        parser.error("端口必须在 1024–65535 之间")
    # TLS 私钥必须在 Linux 主机受控保存，不能放进仓库或输出目录。
    try:
        _validate_tls_private_key(args.key)
    except RuntimeError as error:
        parser.error(str(error))
    if not args.cert.is_file():
        parser.error("HTTPS 服务证书不存在")
    uvicorn.run("vpn_manager.runtime:application",factory=True,host=str(address),port=args.port,
                proxy_headers=False,access_log=False,server_header=False,
                ssl_keyfile=str(args.key),ssl_certfile=str(args.cert),
                ssl_ciphers="ECDHE+AESGCM:ECDHE+CHACHA20",limit_concurrency=32,timeout_keep_alive=5)


if __name__ == "__main__":
    main()
