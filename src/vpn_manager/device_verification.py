"""后续服务端设备与证书验证器的接口约定。

不提供请求头、Cookie、IP、浏览器标识或请求体等备用认证方式。
部署方必须注入基于真实证书证明的验证器。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from fastapi import Request


@dataclass(frozen=True)
class VerifiedDevicePrincipal:
    account_id: str
    device_id: str
    web_certificate_id: str


class DeviceVerifier(Protocol):
    def verify(self, request: Request) -> VerifiedDevicePrincipal | None:
        """只返回已由管理用途证书登记记录验证的设备身份。"""
