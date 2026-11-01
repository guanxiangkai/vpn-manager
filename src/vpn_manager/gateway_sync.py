"""受限 Unix socket 网关代理协议、凭据封装与持久化 outbox 消费器。"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import sys
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .store import Store

MAX_MESSAGE_BYTES = 16 * 1024
SOCKET_TIMEOUT_SECONDS = 10
PROTOCOL_INFO = b"vpn-manager-gateway-v1"
_NETWORKS = {"home", "work"}
_STATES = {"applied", "pending", "failed", "superseded", "not_provisioned"}


class GatewayUnavailable(Exception):
    """代理不可达、协议无效或回执无法安全解释。"""


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object, length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ValueError("无效的凭据封装")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError("无效的凭据封装") from error
    if length is not None and len(decoded) != length:
        raise ValueError("无效的凭据封装")
    return decoded


def _credential_aad(username: str, generation: int) -> bytes:
    return _canonical_bytes({"generation": generation, "username": username, "version": 1})


def _validate_envelope(envelope: object) -> dict[str, object]:
    if not isinstance(envelope, dict) or set(envelope) != {"version", "key_id", "ephemeral_key", "nonce", "ciphertext"}:
        raise ValueError("无效的凭据封装")
    if envelope["version"] != 1 or not isinstance(envelope["key_id"], str) or re.fullmatch(r"[0-9a-f]{64}", envelope["key_id"]) is None:
        raise ValueError("无效的凭据封装")
    _unb64(envelope["ephemeral_key"], 32)
    _unb64(envelope["nonce"], 12)
    ciphertext = _unb64(envelope["ciphertext"])
    if not ciphertext or len(ciphertext) > 8 * 1024:
        raise ValueError("无效的凭据封装")
    return envelope


def _validate_username(username: object) -> str:
    if not isinstance(username, str) or not username or len(username) > 64:
        raise ValueError("无效账户名")
    import re

    if re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", username) is None:
        raise ValueError("无效账户名")
    return username


def _validate_generation(generation: object) -> int:
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise ValueError("无效网关版本")
    return generation


def seal_credential(public_key_pem: bytes, username: str, generation: int, password: str) -> dict[str, object]:
    """用代理 X25519 公钥封装单次账户密码，返回可持久化的无明文信封。"""
    username = _validate_username(username)
    generation = _validate_generation(generation)
    if not isinstance(password, str):
        raise ValueError("无效密码")
    plaintext = password.encode("utf-8")
    if not plaintext or len(plaintext) > 1024:
        raise ValueError("无效密码")
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as error:
        raise ValueError("无效代理公钥") from error
    if not isinstance(public_key, X25519PublicKey):
        raise ValueError("代理公钥必须为 X25519")
    public_bytes = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ephemeral_key = X25519PrivateKey.generate()
    ephemeral_bytes = ephemeral_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=PROTOCOL_INFO).derive(ephemeral_key.exchange(public_key))
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _credential_aad(username, generation))
    return {"version": 1, "key_id": hashlib.sha256(public_bytes).hexdigest(), "ephemeral_key": _b64(ephemeral_bytes), "nonce": _b64(nonce), "ciphertext": _b64(ciphertext)}


def open_credential(private_key_pem: bytes, envelope: dict[str, object], username: str, generation: int) -> str:
    """验证并解开信封；仅供本机网关代理使用，调用方不得记录返回值。"""
    username = _validate_username(username)
    generation = _validate_generation(generation)
    envelope = _validate_envelope(envelope)
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as error:
        raise ValueError("无效代理私钥") from error
    if not isinstance(private_key, X25519PrivateKey):
        raise ValueError("代理私钥必须为 X25519")
    public_bytes = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if envelope["key_id"] != hashlib.sha256(public_bytes).hexdigest():
        raise ValueError("凭据封装不属于当前代理密钥")
    ephemeral = _unb64(envelope["ephemeral_key"], 32)
    nonce = _unb64(envelope["nonce"], 12)
    ciphertext = _unb64(envelope["ciphertext"])
    try:
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=PROTOCOL_INFO).derive(private_key.exchange(X25519PublicKey.from_public_bytes(ephemeral)))
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, _credential_aad(username, generation))
        if not plaintext or len(plaintext) > 1024:
            raise ValueError("无效的凭据封装")
        return plaintext.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("无效的凭据封装") from error


def _safe_code(value: object) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value) else None


class GatewayClient:
    """严格 JSON 行 Unix socket 客户端；所有对端失败都被归一为不可用。"""

    def __init__(self, socket_path: str | Path) -> None:
        self.socket_path = str(socket_path)

    def _request(self, payload: dict[str, object]) -> dict[str, object]:
        encoded = _canonical_bytes(payload) + b"\n"
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise GatewayUnavailable()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(SOCKET_TIMEOUT_SECONDS)
                peer.connect(self.socket_path)
                peer.sendall(encoded)
                response = bytearray()
                while b"\n" not in response:
                    chunk = peer.recv(min(4096, MAX_MESSAGE_BYTES + 1 - len(response)))
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > MAX_MESSAGE_BYTES:
                        raise GatewayUnavailable()
            if not response or b"\n" not in response:
                raise GatewayUnavailable()
            line, remainder = bytes(response).split(b"\n", 1)
            if remainder or not line:
                raise GatewayUnavailable()
            decoded = json.loads(line.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise GatewayUnavailable()
            return decoded
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, GatewayUnavailable):
            raise GatewayUnavailable() from None

    def apply_account(self, operation_id: str, username: str, generation: int, active: bool, networks: list[str], credential_envelope: dict[str, object] | None) -> dict[str, object]:
        if uuid.UUID(hex=operation_id).hex != operation_id or not isinstance(active, bool) or not isinstance(networks, list) or len(networks) != len(set(networks)) or not set(networks).issubset(_NETWORKS) or (active and not networks):
            raise ValueError("无效网关请求")
        if credential_envelope is not None:
            _validate_envelope(credential_envelope)
        reply = self._request({"action": "apply_account", "operation_id": operation_id, "username": _validate_username(username), "generation": _validate_generation(generation), "active": active, "networks": networks, "credential_envelope": credential_envelope})
        allowed = {"operation_id", "username", "generation", "state", "code"}
        if set(reply) - allowed or not {"operation_id", "username", "generation", "state"}.issubset(reply) or reply["operation_id"] != operation_id or reply["username"] != username or reply["generation"] != generation or reply["state"] not in _STATES - {"not_provisioned"}:
            raise GatewayUnavailable()
        if "code" in reply and _safe_code(reply["code"]) is None:
            raise GatewayUnavailable()
        return {key: value for key, value in reply.items() if key != "code" or value is not None}

    def status(self, username: str) -> dict[str, object]:
        username = _validate_username(username)
        reply = self._request({"action": "status", "username": username})
        allowed = {"username", "generation", "state", "code"}
        if set(reply) - allowed or not {"username", "generation", "state"}.issubset(reply) or reply["username"] != username or not isinstance(reply["generation"], int) or isinstance(reply["generation"], bool) or reply["generation"] < 0 or reply["state"] not in _STATES:
            raise GatewayUnavailable()
        if "code" in reply and _safe_code(reply["code"]) is None:
            raise GatewayUnavailable()
        return {key: value for key, value in reply.items() if key != "code" or value is not None}


def run_once(database_path: str, socket_path: str, *, retry_failed: bool = False) -> int:
    """尝试每个待处理任务一次；显式重试复用失败任务的原操作标识。"""
    store, client = Store(database_path), GatewayClient(socket_path)
    store.initialize()
    if retry_failed:
        store.retry_failed_gateway_jobs()
    unavailable = False
    for job in store.pending_gateway_jobs():
        try:
            reply = client.apply_account(job["operation_id"], job["username"], job["generation"], job["active"], job["networks"], job["credential_envelope"])
        except GatewayUnavailable:
            unavailable = True
            continue
        store.record_gateway_reply(job["operation_id"], job["username"], job["generation"], reply["state"], _safe_code(reply.get("code")))
    return 1 if unavailable else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="处理一次本机 VPN 网关同步队列。")
    parser.add_argument("--database", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--once", action="store_true", required=True)
    parser.add_argument("--retry-failed", action="store_true", help="重试最早未完成的明确失败投影；复用原 operation_id 与密文。")
    arguments = parser.parse_args()
    return run_once(arguments.database, arguments.socket, retry_failed=arguments.retry_failed)


if __name__ == "__main__":
    raise SystemExit(main())
