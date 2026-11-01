from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

Network = Literal["home", "work"]
Role = Literal["admin", "user"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    password: SecretStr = Field(min_length=1, max_length=256)


class UserCreate(StrictModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    password: SecretStr = Field(min_length=10, max_length=256)
    role: Role
    networks: list[Network] = Field(min_length=1, max_length=2)

    @field_validator("networks")
    @classmethod
    def unique_networks(cls, value: list[Network]) -> list[Network]:
        if len(value) != len(set(value)):
            raise ValueError("网络权限不能重复")
        return value


class UserUpdate(StrictModel):
    password: SecretStr | None = Field(default=None, min_length=10, max_length=256)
    role: Role | None = None
    networks: list[Network] | None = Field(default=None, min_length=1, max_length=2)
    active: bool | None = None

    @field_validator("networks")
    @classmethod
    def unique_networks(cls, value: list[Network] | None) -> list[Network] | None:
        if value is not None and len(value) != len(set(value)):
            raise ValueError("网络权限不能重复")
        return value


class UserView(StrictModel):
    username: str
    role: Role
    networks: list[Network]
    active: bool
    created_at: datetime
    updated_at: datetime


class LoginResponse(StrictModel):
    user: UserView
    csrf_token: str


class MeResponse(UserView):
    """当前有效账户及刚轮换的会话绑定 CSRF 令牌。"""

    csrf_token: str


class DeviceReserve(StrictModel):
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    vpn_certificate_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    web_certificate_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")


class DeviceView(StrictModel):
    account_id: str
    device_id: str
    vpn_certificate_id: str
    web_certificate_id: str
    state: Literal["pending", "active", "revoking", "revoked"]
    created_at: datetime
    updated_at: datetime
    revocation_requested_at: datetime | None
    manager_access: Literal["allowed", "revoked"]
    gateway_revocation: Literal["not_requested", "pending", "acknowledged"]


class MessageResponse(StrictModel):
    message: str


class AuditEvent(StrictModel):
    id: int
    occurred_at: datetime
    actor: str | None
    source_ip: str | None
    action: str
    target: str | None
    outcome: Literal["success", "failure", "denied"]


class AuditPage(StrictModel):
    items: list[AuditEvent]
    next_cursor: int | None


class ErrorDetail(StrictModel):
    code: str
    message: str


class ErrorResponse(StrictModel):
    error: ErrorDetail
