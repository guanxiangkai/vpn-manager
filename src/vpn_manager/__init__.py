"""测试阶段的 VPN 账户管理接口；不配置 VPN 网关。"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import create_app

__all__ = ["create_app"]


def __getattr__(name: str):
    """仅检查 SQLite 结构更新层时，避免导入 FastAPI。"""
    if name == "create_app":
        from .app import create_app

        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
