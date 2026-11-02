from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

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

    @model_validator(mode="after")
    def user_role_is_work_only(self) -> "UserCreate":
        if self.role == "user" and self.networks != ["work"]:
            raise ValueError("普通用户只能拥有 work 网络权限")
        return self


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

    @model_validator(mode="after")
    def explicit_user_role_is_work_only(self) -> "UserUpdate":
        # 未携带 role 时需由服务层按账户当前角色判断；这里先拒绝请求自身
        # 已明确把最终角色设为 user 的越权组合。
        if self.role == "user" and self.networks is not None and self.networks != ["work"]:
            raise ValueError("普通用户只能拥有 work 网络权限")
        return self


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
    # 仅跨站部署返回；浏览器只在内存保存，禁止写入本地存储。
    session_token: str | None = None


class MeResponse(UserView):
    """当前有效账户及刚轮换的会话绑定 CSRF 令牌。"""

    csrf_token: str


class DeviceCreate(StrictModel):
    device_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")


class DeviceView(StrictModel):
    account_id: str
    device_id: str
    state: Literal["registered", "removed"]
    created_at: datetime
    updated_at: datetime


class GatewayStatus(StrictModel):
    """当前期望版本及代理实际投影；只有版本相等的 applied 才表示已生效。"""

    username: str
    generation: int = Field(ge=0)
    applied_generation: int | None = Field(default=None, ge=1)
    state: Literal["not_provisioned", "queued", "pending", "applied", "failed", "superseded"]
    code: str | None = None
    updated_at: datetime | None = None


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
