"""私钥权限边界；systemd 凭据的真实运行仍须在 Linux 单元中验证。"""
import os
import stat
import struct
from types import SimpleNamespace

import pytest

from vpn_manager import runtime


def _acl(entries):
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


PRIVATE_ACL = [(1, 4, 0xFFFFFFFF), (2, 4, 992), (4, 0, 0xFFFFFFFF),
               (16, 4, 0xFFFFFFFF), (32, 0, 0xFFFFFFFF)]


def test_owner_only_key_is_accepted(tmp_path):
    key = tmp_path / "key.pem"
    key.write_text("测试用占位内容")
    key.chmod(0o600)
    runtime._validate_tls_private_key(key)


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o660, 0o666])
def test_group_or_public_readable_key_is_rejected(tmp_path, mode):
    key = tmp_path / "key.pem"
    key.write_text("测试用占位内容")
    key.chmod(mode)
    with pytest.raises(RuntimeError, match="不安全"):
        runtime._validate_tls_private_key(key)


def test_link_directory_and_missing_key_are_rejected(tmp_path):
    key = tmp_path / "key.pem"
    key.write_text("测试用占位内容")
    key.chmod(0o600)
    link = tmp_path / "linked.pem"
    link.symlink_to(key)
    for path in (link, tmp_path, tmp_path / "missing.pem"):
        with pytest.raises(RuntimeError):
            runtime._validate_tls_private_key(path)


def test_replaced_file_is_rejected(tmp_path, monkeypatch):
    key = tmp_path / "key.pem"
    key.write_text("测试用占位内容")
    key.chmod(0o600)
    original = os.fstat

    def replaced(descriptor):
        value = original(descriptor)
        fields = list(value)
        fields[stat.ST_INO] += 1
        return os.stat_result(fields)

    with monkeypatch.context() as patch:
        patch.setattr(runtime.os, "fstat", replaced)
        with pytest.raises(RuntimeError, match="不安全"):
            runtime._validate_tls_private_key(key)


def test_exact_systemd_read_acl_is_accepted(monkeypatch):
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 992)
    monkeypatch.setattr(runtime.os, "getxattr", lambda fd, name: _acl(PRIVATE_ACL), raising=False)
    info = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o440)
    assert runtime._is_private_service_credential(info, 123)


@pytest.mark.parametrize("entries", [
    PRIVATE_ACL[:1] + [(2, 4, 993)] + PRIVATE_ACL[2:],  # 其他 UID
    PRIVATE_ACL[:2] + [(4, 4, 0xFFFFFFFF)] + PRIVATE_ACL[3:],  # 属组也能读
    PRIVATE_ACL[:-1] + [(32, 4, 0xFFFFFFFF)],  # 其他用户可读
    PRIVATE_ACL[:2] + [(8, 4, 993)] + PRIVATE_ACL[2:],  # 新增组
    PRIVATE_ACL[:2] + [(2, 4, 993)] + PRIVATE_ACL[2:],  # 新增用户
    PRIVATE_ACL[:1] + [(2, 6, 992)] + PRIVATE_ACL[2:],  # 服务用户可写
    PRIVATE_ACL[:3] + [(16, 6, 0xFFFFFFFF)] + PRIVATE_ACL[4:],  # mask 可写
    PRIVATE_ACL + [PRIVATE_ACL[1]],  # 重复条目
    PRIVATE_ACL[1:],  # 缺少条目
])
def test_additional_acl_permissions_are_rejected(monkeypatch, entries):
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 992)
    monkeypatch.setattr(runtime.os, "getxattr", lambda fd, name: _acl(entries), raising=False)
    info = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o440)
    assert not runtime._is_private_service_credential(info, 123)


@pytest.mark.parametrize("acl", [b"", b"\x02", b"\x01\x00\x00\x00", _acl(PRIVATE_ACL) + b"\x00"])
def test_invalid_acl_is_rejected(monkeypatch, acl):
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 992)
    monkeypatch.setattr(runtime.os, "getxattr", lambda fd, name: acl, raising=False)
    info = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o440)
    assert not runtime._is_private_service_credential(info, 123)


def test_unavailable_acl_is_rejected(monkeypatch):
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 992)

    def unavailable(fd, name):
        raise OSError("不支持 ACL")

    monkeypatch.setattr(runtime.os, "getxattr", unavailable, raising=False)
    info = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o440)
    assert not runtime._is_private_service_credential(info, 123)


@pytest.mark.parametrize("uid,mode", [(992, 0o440), (0, 0o640), (0, 0o444), (0, 0o460)])
def test_acl_exception_does_not_expand_other_file_modes(monkeypatch, uid, mode):
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 992)
    monkeypatch.setattr(runtime.os, "getxattr", lambda fd, name: _acl(PRIVATE_ACL), raising=False)
    info = SimpleNamespace(st_uid=uid, st_mode=stat.S_IFREG | mode)
    assert not runtime._is_private_service_credential(info, 123)
