"""内部 HTTPS 服务入口；不修改系统网络、VPN、代理或防火墙。"""
from __future__ import annotations

import argparse
from ipaddress import ip_address
import os
from pathlib import Path
import stat

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from .app import create_app
from .gateway_sync import GatewayClient


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


def application():
    required = ("VPN_MANAGER_DB", "VPN_MANAGER_WEB_DIRECTORY", "VPN_MANAGER_ORIGIN")
    if any(not os.environ.get(name) for name in required):
        raise RuntimeError("管理服务缺少必要配置，拒绝启动")
    database = Path(os.environ["VPN_MANAGER_DB"])
    if not database.is_file():
        raise RuntimeError("必须先完成账户初始化")
    public_key_path, socket_path = os.environ.get("VPN_MANAGER_GATEWAY_PUBLIC_KEY"), os.environ.get("VPN_MANAGER_GATEWAY_SOCKET")
    if bool(public_key_path) != bool(socket_path):
        raise RuntimeError("网关公钥与 Unix socket 必须同时配置")
    gateway_public_key = _load_gateway_public_key(public_key_path) if public_key_path else None
    if socket_path and not Path(socket_path).is_absolute():
        raise RuntimeError("网关 Unix socket 必须使用绝对路径")
    gateway_client = GatewayClient(socket_path) if socket_path else None
    return create_app(database, allowed_origin=os.environ["VPN_MANAGER_ORIGIN"], web_directory=os.environ["VPN_MANAGER_WEB_DIRECTORY"], gateway_public_key=gateway_public_key, gateway_client=gateway_client)


def main() -> None:
    parser = argparse.ArgumentParser(description="启动内部 HTTPS 管理服务，不提供设备证书认证")
    parser.add_argument("--bind",required=True)
    parser.add_argument("--port",type=int,default=8443)
    parser.add_argument("--cert",required=True,type=Path)
    parser.add_argument("--key",required=True,type=Path)
    args = parser.parse_args()
    address = ip_address(args.bind)
    if address.is_unspecified or address.is_multicast or not address.is_private:
        parser.error("当前部署只允许绑定明确的内部 IP；公网入口等待备案后配置")
    if not 1024 <= args.port <= 65535:
        parser.error("端口必须在 1024–65535 之间")
    # TLS 私钥必须在 Linux 主机受控保存，不能放进仓库或输出目录。
    info = args.key.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid not in {0,os.geteuid()}:
        parser.error("TLS 私钥文件权限或属主不安全")
    if not args.cert.is_file():
        parser.error("HTTPS 服务证书不存在")
    uvicorn.run("vpn_manager.runtime:application",factory=True,host=str(address),port=args.port,
                proxy_headers=False,access_log=False,server_header=False,
                ssl_keyfile=str(args.key),ssl_certfile=str(args.cert),
                ssl_ciphers="ECDHE+AESGCM:ECDHE+CHACHA20",limit_concurrency=32,timeout_keep_alive=5)


if __name__ == "__main__":
    main()
