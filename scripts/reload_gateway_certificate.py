#!/usr/bin/env python3
"""为原生 IKEv2 加载受信任服务器证书；续期不重启网关、不终止会话。"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import deploy_web_certificate as web_certificate
from vpn_manager.gateway_agent import ViciDriver, atomic_private, private_directory, private_file


def reload_certificate(config: Path, state: Path, *, reload_connections: bool) -> dict:
    """所有路径来自 root 配置；公开控制接口不能更换证书来源。"""
    settings = json.loads(private_file(config))
    private_directory(state)
    fullchain_path = Path("/etc/vpn-manager/web-api-fullchain.pem")
    key_path = Path("/etc/vpn-manager/web-api-key.pem")
    fullchain, encoded_key = private_file(fullchain_path), private_file(key_path)
    web_certificate.validate(fullchain, encoded_key, settings["server_identity"])
    subprocess.run(["/usr/bin/openssl", "verify", "-purpose", "sslserver", "-verify_ip",
                    settings["server_identity"], "-untrusted", str(fullchain_path), str(fullchain_path)],
                   check=True, capture_output=True, timeout=15)
    certificates = x509.load_pem_x509_certificates(fullchain)
    key = serialization.load_pem_private_key(encoded_key, None)
    kind = "ecdsa" if isinstance(key, ec.EllipticCurvePrivateKey) else "rsa" if isinstance(key, rsa.RSAPrivateKey) else None
    if kind is None:
        raise RuntimeError("不支持的服务器密钥类型")
    target = Path(settings["server_certificate"])
    if target.parent != config.parent / "certificates" or target.name != "public-server.pem":
        raise RuntimeError("服务器证书目标不在专用目录内")
    leaf = certificates[0].public_bytes(serialization.Encoding.PEM)
    # root 独占锁与账户代理的串行请求共同避免并发续期/权限变更覆盖。
    with (state / "certificate.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = private_file(target) if target.exists() else None
        driver = ViciDriver(settings)
        with driver.session() as session:
            session.load_key({"type": kind, "data": encoded_key})
            for certificate in certificates[1:]:
                session.load_cert({"type": "X509", "flag": "CA", "data": certificate.public_bytes(serialization.Encoding.PEM)})
        atomic_private(target, leaf)
        if reload_connections:
            try:
                with socket.socket(socket.AF_UNIX) as peer:
                    peer.settimeout(20)
                    peer.connect(settings["agent_socket"])
                    peer.sendall(b'{"action":"reload_certificate"}\n')
                    response = peer.makefile("rb").readline(4097)
                result = json.loads(response)
                if result.get("state") != "certificate_reloaded":
                    raise RuntimeError("证书连接模板更新未完成")
            except Exception:
                if previous is not None:
                    atomic_private(target, previous)
                raise
    return {"state": "certificate_loaded", "reloaded": reload_connections,
            "expires": certificates[0].not_valid_after_utc.isoformat()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("必须由 root 执行")
    os.umask(0o077)
    # 仅有新版网关运行时才应用续期，旧 VPN 期间不接管端口或服务。
    active = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "vpn-manager-gateway"], capture_output=True, timeout=10)
    if args.reload and active.returncode != 0:
        print(json.dumps({"state": "gateway_inactive"}))
        return
    try:
        print(json.dumps(reload_certificate(args.config, args.state_directory, reload_connections=args.reload)))
    except Exception:
        raise SystemExit("gateway_certificate_reload_failed") from None


if __name__ == "__main__":
    main()
