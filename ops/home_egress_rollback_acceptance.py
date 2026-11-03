#!/usr/bin/env python3
"""仅供隔离 Linux 网络命名空间执行的家庭出口回滚验收。

调用方必须先进入 ``unshare -n`` 创建的网络命名空间。本脚本只创建可丢弃的
临时文件、策略规则和 ``vpn_home_rollback`` 表；不连接真实服务或读取生产配置。
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ops.home_egress_rollback import (
    NON_PUBLIC_V4,
    ROLLBACK_FAMILY,
    ROLLBACK_TABLE,
    RollbackError,
    _default_runner,
    rollback,
)


PRIORITY = 24180
PROTOCOL = 186
TABLE = 150
POOL = "10.254.240.0/30"
FOREIGN_POOL = "10.254.241.0/30"


def _private(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    path.chmod(0o600)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _result(returncode: int = 0) -> Any:
    return SimpleNamespace(returncode=returncode, stdout="")


class ServiceFake:
    """仅替代本地 systemctl；ip 与 nft 仍由真实 runner 执行。"""

    def __init__(self, fail_stop: bool = False) -> None:
        self.active = True
        self.fail_stop = fail_stop

    def __call__(self, argv: list[str], input_text: str | None = None) -> Any:
        if argv[:2] == ["/bin/systemctl", "stop"]:
            if self.fail_stop:
                return _result(1)
            self.active = False
            return _result()
        if argv[:2] == ["/bin/systemctl", "start"]:
            self.active = True
            return _result()
        if argv[:3] == ["/bin/systemctl", "is-active", "--quiet"]:
            return _result(0 if self.active else 3)
        return _default_runner(argv, input_text)


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=8)


def _must(argv: list[str]) -> None:
    if _run(argv).returncode:
        raise RuntimeError("acceptance_command_failed")


def _rules() -> list[dict[str, Any]]:
    result = _run(["/sbin/ip", "-4", "-N", "-j", "rule", "show"])
    if result.returncode:
        raise RuntimeError("acceptance_rule_readback")
    value = json.loads(result.stdout)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise RuntimeError("acceptance_rule_readback")
    return value


def _number(value: Any) -> int | None:
    if type(value) is int:
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return None


def _network(rule: dict[str, Any], key: str) -> str | None:
    value = rule.get(key, "all")
    length = rule.get(key + "len")
    if value in {"all", "default"}:
        value = "0.0.0.0"
        length = 0 if length is None else length
    if not isinstance(value, str):
        return None
    if "/" in value:
        candidate = value
    elif type(length) is int and 0 <= length <= 32:
        candidate = f"{value}/{length}"
    else:
        return None
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return None
    if not isinstance(network, ipaddress.IPv4Network):
        return None
    if length is not None and (type(length) is not int or network.prefixlen != length):
        return None
    return str(network)


def _has_rule(pool: str, priority: int, destination: str, table: int) -> bool:
    for rule in _rules():
        rule_table = 254 if rule.get("table") == "main" else _number(rule.get("table"))
        if (_number(rule.get("priority")) == priority and _number(rule.get("protocol")) == PROTOCOL
                and _network(rule, "src") == pool and _network(rule, "dst") == destination
                and rule_table == table):
            return True
    return False


def _add_rules() -> None:
    for destination in NON_PUBLIC_V4:
        _must(["/sbin/ip", "-4", "rule", "add", "priority", str(PRIORITY), "from", POOL,
               "to", destination, "table", "main", "protocol", str(PROTOCOL)])
    _must(["/sbin/ip", "-4", "rule", "add", "priority", str(PRIORITY + 1), "from", POOL,
           "to", "0.0.0.0/0", "table", str(TABLE), "protocol", str(PROTOCOL)])
    _must(["/sbin/ip", "-4", "rule", "add", "priority", str(PRIORITY + 1), "from", FOREIGN_POOL,
           "to", "0.0.0.0/0", "table", str(TABLE), "protocol", str(PROTOCOL)])


def _delete_rules() -> None:
    for destination in NON_PUBLIC_V4:
        _run(["/sbin/ip", "-4", "rule", "del", "priority", str(PRIORITY), "from", POOL,
              "to", destination, "table", "main", "protocol", str(PROTOCOL)])
    for pool in (POOL, FOREIGN_POOL):
        _run(["/sbin/ip", "-4", "rule", "del", "priority", str(PRIORITY + 1), "from", pool,
              "to", "0.0.0.0/0", "table", str(TABLE), "protocol", str(PROTOCOL)])


def _block_exists() -> bool:
    return _run(["/usr/sbin/nft", "list", "table", ROLLBACK_FAMILY, ROLLBACK_TABLE]).returncode == 0


def _remove_block() -> None:
    if _block_exists():
        _run(["/usr/sbin/nft", "delete", "table", ROLLBACK_FAMILY, ROLLBACK_TABLE])


def _journal(directory: Path) -> tuple[Path, Path, Path, Path]:
    module = directory / "gateway_agent.py"
    config = directory / "gateway.json"
    extra = directory / "home_egress.py"
    accounts = directory / "accounts.json"
    lock = directory / "agent.lock"
    baseline_module = b"baseline module\n"
    baseline_config = b"baseline config\n"
    _private(module, b"candidate module\n")
    _private(config, b"candidate config\n")
    _private(extra, b"candidate extra\n")
    _private(accounts, json.dumps({"schema": 1, "accounts": {"smoke": {
        "pool": POOL, "reqid": 61001, "generation": 1, "state": "applied",
    }}}).encode())
    _private(lock, b"")
    _private(directory / "baseline-gateway_agent.py", baseline_module)
    _private(directory / "baseline-gateway.json", baseline_config)
    journal = {
        "status": "armed",
        "module_path": str(module),
        "config_path": str(config),
        "extra_module_path": str(extra),
        "baseline_module_hash": hashlib.sha256(baseline_module).hexdigest(),
        "config_hash": hashlib.sha256(baseline_config).hexdigest(),
        "candidate_module_hash": _digest(module),
        "candidate_config_hash": _digest(config),
        "extra_hash": _digest(extra),
        "accounts_path": str(accounts),
        "agent_service": "vpn-manager-agent.service",
        "state_lock_path": str(lock),
        "control_socket_path": str(directory / "agent.sock"),
        "routing": {"table": TABLE, "priority": PRIORITY, "protocol": PROTOCOL},
        "known_pools": [POOL],
    }
    _private(directory / "journal.json", json.dumps(journal).encode())
    return module, config, extra, directory / "journal.json"


def _assert_restored(module: Path, config: Path, extra: Path, journal: Path) -> None:
    if (module.read_bytes() != b"baseline module\n" or config.read_bytes() != b"baseline config\n"
            or extra.exists() or json.loads(journal.read_text()).get("status") != "rolled_back"):
        raise RuntimeError("acceptance_restore_failed")
    if any(_has_rule(POOL, PRIORITY, destination, 254) for destination in NON_PUBLIC_V4):
        raise RuntimeError("acceptance_owned_rule_remains")
    if _has_rule(POOL, PRIORITY + 1, "0.0.0.0/0", TABLE):
        raise RuntimeError("acceptance_owned_rule_remains")
    if not _has_rule(FOREIGN_POOL, PRIORITY + 1, "0.0.0.0/0", TABLE):
        raise RuntimeError("acceptance_foreign_rule_removed")
    if _block_exists():
        raise RuntimeError("acceptance_block_remains")


def _run_case(fail_stop: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="home-egress-rollback-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        module, config, extra, journal = _journal(directory)
        service = ServiceFake(fail_stop=fail_stop)
        try:
            _add_rules()
            if fail_stop:
                try:
                    rollback(directory, runner=service, enforce_root=True, status_probe=lambda _path, _expected: True)
                except RollbackError as error:
                    if str(error) != "rollback_service_failed":
                        raise RuntimeError("acceptance_unexpected_stop_failure") from error
                else:
                    raise RuntimeError("acceptance_stop_failure_not_reported")
                if not _block_exists() or json.loads(journal.read_text()).get("status") != "rolling_back":
                    raise RuntimeError("acceptance_stop_failure_not_closed")
                service.fail_stop = False
            result = rollback(directory, runner=service, enforce_root=True, status_probe=lambda _path, _expected: True)
            if result != "rolled_back":
                raise RuntimeError("acceptance_rollback_result")
            _assert_restored(module, config, extra, journal)
        finally:
            _remove_block()
            _delete_rules()


def _require_isolated_linux_root() -> None:
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise SystemExit("acceptance_requires_linux_root")
    try:
        isolated = os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net")
    except OSError as error:
        raise SystemExit("acceptance_namespace_unavailable") from error
    if not isolated:
        raise SystemExit("acceptance_requires_unshare_network_namespace")


def main() -> int:
    _require_isolated_linux_root()
    _run_case(fail_stop=False)
    _run_case(fail_stop=True)
    print("home_egress_rollback_acceptance_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
