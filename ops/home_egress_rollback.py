#!/usr/bin/env python3
"""家庭出口候选发布的独立、失败闭合回滚辅助程序。

本程序不依赖候选包，更不会实例化正常的路由协调器；即使候选的路由表或
配置无效，也必须能够回滚。它只接受由外部发布控制器创建的 root 私有事务目录。
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable, Iterable, Optional


ROLLBACK_FAMILY = "inet"
ROLLBACK_TABLE = "vpn_home_rollback"
ROLLBACK_COMMENT = "vpn-home-egress-rollback"
NON_PUBLIC_V4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
)

Runner = Callable[[list[str], Optional[str]], Any]
StatusProbe = Callable[[Path, dict[str, int]], bool]
READINESS_TIMEOUT_SECONDS = 20
READINESS_POLL_SECONDS = 0.2
SYSTEMCTL_TIMEOUT_SECONDS = 30
COMMAND_TIMEOUT_SECONDS = 8
USERNAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}")


class RollbackError(RuntimeError):
    """只返回固定错误码的回滚错误，不携带敏感内容。"""


def _default_runner(argv: list[str], input_text: str | None = None) -> Any:
    """为 systemctl 预留不短于服务 Stop 超时的本地等待窗口。"""
    timeout = SYSTEMCTL_TIMEOUT_SECONDS if argv[:1] == ["/bin/systemctl"] else COMMAND_TIMEOUT_SECONDS
    try:
        return subprocess.run(argv, input=input_text, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # 调用方只处理固定返回码，绝不把命令输出或超时对象带到错误路径。
        return subprocess.CompletedProcess(argv, 124, "", "")


def _rc(result: Any) -> int:
    value = getattr(result, "returncode", None)
    if not isinstance(value, int):
        raise RollbackError("rollback_runner_contract")
    return value


def _stdout(result: Any) -> str:
    value = getattr(result, "stdout", "")
    if not isinstance(value, str):
        raise RollbackError("rollback_runner_contract")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _private_file(path: Path, *, root_required: bool) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise RollbackError("rollback_file_missing") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RollbackError("rollback_unsafe_file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise RollbackError("rollback_file_mode")
    if root_required and info.st_uid != 0:
        raise RollbackError("rollback_file_owner")
    return info


def _safe_regular(path: Path, *, root_required: bool, writable_ok: bool = False) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise RollbackError("rollback_file_missing") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RollbackError("rollback_unsafe_file")
    if root_required and info.st_uid != 0:
        raise RollbackError("rollback_file_owner")
    if not writable_ok and stat.S_IMODE(info.st_mode) & 0o022:
        raise RollbackError("rollback_unsafe_mode")
    return info


def _private_txn(path: Path, *, root_required: bool) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise RollbackError("rollback_txn_missing") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RollbackError("rollback_unsafe_txn")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise RollbackError("rollback_txn_mode")
    if root_required and info.st_uid != 0:
        raise RollbackError("rollback_txn_owner")


def _absolute_path(value: Any) -> Path:
    if not isinstance(value, str):
        raise RollbackError("rollback_journal_invalid")
    path = Path(value)
    if not path.is_absolute():
        raise RollbackError("rollback_journal_invalid")
    return path


def _integer(value: Any, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RollbackError("rollback_journal_invalid")
    return value


def _canonical_network(value: Any) -> str:
    if not isinstance(value, str):
        raise RollbackError("rollback_pool_invalid")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as error:
        raise RollbackError("rollback_pool_invalid") from error
    if not isinstance(network, ipaddress.IPv4Network):
        raise RollbackError("rollback_pool_invalid")
    return str(network)


def _load_json(path: Path) -> tuple[dict[str, Any], str]:
    _private_file(path, root_required=False)
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RollbackError("rollback_journal_invalid") from error
    if not isinstance(value, dict):
        raise RollbackError("rollback_journal_invalid")
    return value, hashlib.sha256(raw).hexdigest()


def _validate_journal(value: dict[str, Any]) -> None:
    if value.get("status") not in {"armed", "accepted", "rolling_back", "rolled_back"}:
        raise RollbackError("rollback_journal_status")
    for key in ("module_path", "config_path", "extra_module_path", "accounts_path", "state_lock_path", "control_socket_path"):
        _absolute_path(value.get(key))
    for key in ("baseline_module_hash", "config_hash", "candidate_module_hash", "candidate_config_hash", "extra_hash"):
        if not _is_sha256(value.get(key)):
            raise RollbackError("rollback_journal_invalid")
    if "split_config" in value and (value["split_config"] not in ("staged", "applying")
                                    or value["baseline_module_hash"] != value["candidate_module_hash"]):
        raise RollbackError("rollback_journal_invalid")
    if not isinstance(value.get("agent_service"), str) or re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", value["agent_service"]) is None:
        raise RollbackError("rollback_journal_invalid")
    routing = value.get("routing")
    if not isinstance(routing, dict):
        raise RollbackError("rollback_journal_invalid")
    _integer(routing.get("table"), 1, 252)
    _integer(routing.get("priority"), 1000, 32764)
    _integer(routing.get("protocol"), 16, 255)
    pools = value.get("known_pools")
    if not isinstance(pools, list) or len(pools) != len(set(pools)):
        raise RollbackError("rollback_journal_invalid")
    for pool in pools:
        _canonical_network(pool)


def _replace_private_json(path: Path, before_digest: str, value: dict[str, Any], *, root_required: bool) -> str:
    _private_file(path, root_required=root_required)
    current = _sha256(path)
    if current != before_digest:
        raise RollbackError("rollback_journal_changed")
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary = tempfile.mkstemp(prefix=".rollback-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    _private_file(path, root_required=root_required)
    return hashlib.sha256(encoded).hexdigest()


def _set_status(path: Path, journal: dict[str, Any], digest: str, status: str, *, root_required: bool) -> tuple[dict[str, Any], str]:
    updated = dict(journal)
    updated["status"] = status
    return updated, _replace_private_json(path, digest, updated, root_required=root_required)


def _acquire_lock(path: Path) -> int:
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except (OSError, BlockingIOError) as error:
        try:
            os.close(descriptor)  # type: ignore[name-defined]  # 仅在 open 成功后关闭。
        except (OSError, UnboundLocalError):
            pass
        raise RollbackError("rollback_locked") from error


def _read_accounts(journal: dict[str, Any], *, root_required: bool) -> dict[str, dict[str, Any]]:
    """读取当前状态，但绝不记录、返回或输出其中的凭据字段。"""
    accounts_path = _absolute_path(journal["accounts_path"])
    _safe_regular(accounts_path, root_required=root_required)
    try:
        decoded = json.loads(accounts_path.read_bytes())
        accounts = decoded["accounts"]
    except (KeyError, OSError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RollbackError("rollback_accounts_invalid") from error
    if not isinstance(accounts, dict) or any(not isinstance(username, str) or USERNAME_RE.fullmatch(username) is None
                                             or not isinstance(account, dict)
                                             for username, account in accounts.items()):
        raise RollbackError("rollback_accounts_invalid")
    return accounts


def _pools_and_reqids(journal: dict[str, Any], *, root_required: bool) -> tuple[set[str], set[int]]:
    pools = {_canonical_network(pool) for pool in journal["known_pools"]}
    reqids: set[int] = set()
    for entry in _read_accounts(journal, root_required=root_required).values():
        pool = entry.get("pool")
        if pool is not None:
            pools.add(_canonical_network(pool))
        reqid = entry.get("reqid")
        if type(reqid) is int and 1 <= reqid <= 2**31 - 1:
            reqids.add(reqid)
    return pools, reqids


def _nft_table_exists(runner: Runner) -> bool:
    # list table 在表不存在时也返回非零；先列出表，避免把 nft 读取故障误判为不存在。
    result = runner(["/usr/sbin/nft", "-j", "list", "tables"], None)
    if _rc(result) != 0:
        raise RollbackError("rollback_nft_readback")
    try:
        payload = json.loads(_stdout(result))
        tables = payload.get("nftables", [])
        table = next((item["table"] for item in tables if isinstance(item, dict)
                      and isinstance(item.get("table"), dict)
                      and item["table"].get("family") == ROLLBACK_FAMILY
                      and item["table"].get("name") == ROLLBACK_TABLE), None)
        if table is None:
            return False
    except (AttributeError, TypeError, json.JSONDecodeError) as error:
        raise RollbackError("rollback_table_conflict") from error
    result = runner(["/usr/sbin/nft", "-j", "list", "table", ROLLBACK_FAMILY, ROLLBACK_TABLE], None)
    if _rc(result) != 0:
        raise RollbackError("rollback_nft_readback")
    try:
        payload = json.loads(_stdout(result))
        tables = payload.get("nftables", [])
        table = next((item["table"] for item in tables if isinstance(item, dict)
                      and isinstance(item.get("table"), dict)
                      and item["table"].get("family") == ROLLBACK_FAMILY
                      and item["table"].get("name") == ROLLBACK_TABLE), None)
        if table is None or table.get("comment") != ROLLBACK_COMMENT:
            raise RollbackError("rollback_table_conflict")
        return True
    except (AttributeError, TypeError, json.JSONDecodeError) as error:
        raise RollbackError("rollback_table_conflict") from error


def _run_nft(runner: Runner, input_text: str) -> None:
    for argv in (["/usr/sbin/nft", "--check", "-f", "-"], ["/usr/sbin/nft", "-f", "-"]):
        if _rc(runner(argv, input_text)) != 0:
            raise RollbackError("rollback_nft_failed")


def _install_block(runner: Runner, pools: Iterable[str], reqids: Iterable[int]) -> None:
    exists = _nft_table_exists(runner)
    lines: list[str] = []
    if exists:
        lines.append(f"delete table {ROLLBACK_FAMILY} {ROLLBACK_TABLE}")
    lines += [
        f'add table {ROLLBACK_FAMILY} {ROLLBACK_TABLE} {{ comment "{ROLLBACK_COMMENT}"; }}',
        f"add chain {ROLLBACK_FAMILY} {ROLLBACK_TABLE} input {{ type filter hook input priority -300; policy accept; }}",
        f"add chain {ROLLBACK_FAMILY} {ROLLBACK_TABLE} forward {{ type filter hook forward priority -300; policy accept; }}",
    ]
    for reqid in sorted(reqids):
        lines += [
            f"add rule {ROLLBACK_FAMILY} {ROLLBACK_TABLE} input ipsec in reqid {reqid} drop",
            f"add rule {ROLLBACK_FAMILY} {ROLLBACK_TABLE} forward ipsec in reqid {reqid} drop",
        ]
    for pool in sorted(pools):
        lines += [
            f"add rule {ROLLBACK_FAMILY} {ROLLBACK_TABLE} input ip saddr {pool} drop",
            f"add rule {ROLLBACK_FAMILY} {ROLLBACK_TABLE} forward ip saddr {pool} drop",
            f"add rule {ROLLBACK_FAMILY} {ROLLBACK_TABLE} forward ip daddr {pool} drop",
        ]
    _run_nft(runner, "\n".join(lines) + "\n")
    if not _nft_table_exists(runner):
        raise RollbackError("rollback_nft_readback")


def _remove_block(runner: Runner) -> None:
    if not _nft_table_exists(runner):
        return
    if _rc(runner(["/usr/sbin/nft", "delete", "table", ROLLBACK_FAMILY, ROLLBACK_TABLE], None)) != 0:
        raise RollbackError("rollback_nft_failed")
    if _nft_table_exists(runner):
        raise RollbackError("rollback_nft_readback")


def _network_from_rule(rule: dict[str, Any], field: str) -> str | None:
    value = rule.get(field, "all")
    length = rule.get(field + "len")
    if value in ("all", "default"):
        value = "0.0.0.0"
        if length is None:
            length = 0
    if not isinstance(value, str):
        return None
    if "/" in value:
        # 不同 iproute 版本可能同时给出 CIDR 文本和 *len；二者必须一致。
        candidate = value
    elif type(length) is int and 0 <= length <= 32:
        candidate = f"{value}/{length}"
    else:
        return None
    try:
        net = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return None
    if not isinstance(net, ipaddress.IPv4Network):
        return None
    if length is not None and (type(length) is not int or net.prefixlen != length):
        return None
    return str(net)


def _integer_like(value: Any) -> int | None:
    if type(value) is int:
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return None


def _owned_rule(rule: Any, pools: set[str], routing: dict[str, Any]) -> tuple[str, str, int, int] | None:
    if not isinstance(rule, dict):
        return None
    allowed = {"priority", "src", "srclen", "dst", "dstlen", "table", "protocol", "flags"}
    if set(rule) - allowed or rule.get("flags", []) not in ([], None):
        return None
    priority = _integer_like(rule.get("priority"))
    protocol = _integer_like(rule.get("protocol"))
    table = rule.get("table")
    if table == "main":
        table = 254
    table = _integer_like(table)
    source = _network_from_rule(rule, "src")
    destination = _network_from_rule(rule, "dst")
    if None in (priority, protocol, table, source, destination):
        return None
    if protocol != routing["protocol"] or source not in pools:
        return None
    if priority == routing["priority"] and table == 254 and destination in NON_PUBLIC_V4:
        return source, destination, priority, table
    if (priority == routing["priority"] + 1 and table == routing["table"]
            and destination == "0.0.0.0/0"):
        return source, destination, priority, table
    return None


def _read_rules(runner: Runner) -> list[dict[str, Any]]:
    # -N 强制协议号数值化；否则 186 可能被 iproute 显示成名称而误漏删。
    result = runner(["/sbin/ip", "-4", "-N", "-j", "rule", "show"], None)
    if _rc(result) != 0:
        raise RollbackError("rollback_rule_readback")
    try:
        rules = json.loads(_stdout(result))
    except json.JSONDecodeError as error:
        raise RollbackError("rollback_rule_readback") from error
    if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
        raise RollbackError("rollback_rule_readback")
    return rules


def _delete_owned_rules(runner: Runner, pools: set[str], routing: dict[str, Any]) -> None:
    matches = [_owned_rule(rule, pools, routing) for rule in _read_rules(runner)]
    for match in (item for item in matches if item is not None):
        source, destination, priority, table = match
        argv = ["/sbin/ip", "-4", "rule", "del", "priority", str(priority), "from", source,
                "to", destination, "table", str(table), "protocol", str(routing["protocol"])]
        if _rc(runner(argv, None)) != 0:
            raise RollbackError("rollback_rule_delete")
    if any(_owned_rule(rule, pools, routing) is not None for rule in _read_rules(runner)):
        raise RollbackError("rollback_rule_readback")


def _restore_file(target: Path, baseline: Path, candidate_hash: str, baseline_hash: str, *, root_required: bool) -> None:
    _safe_regular(target, root_required=root_required)
    _private_file(baseline, root_required=root_required)
    if _sha256(baseline) != baseline_hash:
        raise RollbackError("rollback_baseline_changed")
    target_hash = _sha256(target)
    if target_hash == baseline_hash:
        return
    if target_hash != candidate_hash:
        raise RollbackError("rollback_candidate_changed")
    mode = stat.S_IMODE(target.stat().st_mode)
    descriptor, temporary = tempfile.mkstemp(prefix=".rollback-", dir=target.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle, baseline.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                handle.write(block)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    if _sha256(target) != baseline_hash:
        raise RollbackError("rollback_restore_failed")


def _remove_extra(path: Path, expected_hash: str, *, root_required: bool) -> None:
    try:
        _safe_regular(path, root_required=root_required)
    except RollbackError as error:
        if error.args == ("rollback_file_missing",):
            return
        raise
    if _sha256(path) != expected_hash:
        raise RollbackError("rollback_candidate_changed")
    path.unlink()


def _service(runner: Runner, action: str, service: str) -> None:
    if _rc(runner(["/bin/systemctl", action, service], None)) != 0:
        raise RollbackError("rollback_service_failed")


def _service_active(runner: Runner, service: str) -> bool:
    return _rc(runner(["/bin/systemctl", "is-active", "--quiet", service], None)) == 0


def _expected_applied_accounts(journal: dict[str, Any], *, root_required: bool) -> dict[str, int] | None:
    """仅接受状态文件中所有账户均已完成投影的快照。"""
    expected: dict[str, int] = {}
    for username, account in _read_accounts(journal, root_required=root_required).items():
        generation = account.get("generation")
        if type(generation) is not int or not 1 <= generation < 2**53:
            raise RollbackError("rollback_accounts_invalid")
        if account.get("state") != "applied":
            return None
        expected[username] = generation
    return expected


def _safe_control_socket(path: Path, *, root_required: bool) -> bool:
    """验证控制套接字与其父目录，套接字尚未出现时返回 False。"""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise RollbackError("rollback_socket_unsafe") from error
    try:
        parent = path.parent.lstat()
    except OSError as error:
        raise RollbackError("rollback_socket_unsafe") from error
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode)
            or stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode)
            or info.st_mode & 0o007 or parent.st_mode & 0o022
            or (root_required and (info.st_uid != 0 or parent.st_uid != 0))):
        raise RollbackError("rollback_socket_unsafe")
    return True


def _socket_status_matches(path: Path, expected: dict[str, int], *, root_required: bool) -> bool:
    """对真实本地控制 socket 逐账户请求 status，且只比较非敏感字段。"""
    if not _safe_control_socket(path, root_required=root_required):
        return False
    checks = [(username, generation, "applied") for username, generation in sorted(expected.items())]
    if not checks:
        # 空账户也必须完成一次真实的请求/响应校验；仅 connect 成功不能证明控制循环可用。
        username = "rollback_healthcheck"
        suffix = 0
        while username in expected:
            suffix += 1
            username = f"rollback_healthcheck_{suffix}"
        checks.append((username, 0, "not_provisioned"))
    for username, generation, state in checks:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(1)
                peer.connect(str(path))
                peer.sendall(json.dumps({"action": "status", "username": username}, separators=(",", ":")).encode() + b"\n")
                chunks: list[bytes] = []
                total = 0
                while total <= 4096:
                    block = peer.recv(4097 - total)
                    if not block:
                        break
                    chunks.append(block)
                    total += len(block)
                    if b"\n" in block:
                        break
                raw = b"".join(chunks)
        except OSError:
            return False
        if len(raw) > 4096 or not raw.endswith(b"\n"):
            return False
        try:
            reply = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        if (not isinstance(reply, dict) or reply.get("username") != username
                or reply.get("generation") != generation
                or reply.get("state") != state):
            return False
    return True


def _wait_ready(journal: dict[str, Any], runner: Runner, *, root_required: bool,
                status_probe: Optional[StatusProbe]) -> bool:
    """在固定窗口内同时确认服务存活、账户投影和控制 socket 状态。"""
    socket_path = _absolute_path(journal["control_socket_path"])
    probe = status_probe or (lambda path, expected: _socket_status_matches(path, expected, root_required=root_required))
    deadline = time.monotonic() + READINESS_TIMEOUT_SECONDS
    while True:
        if not _service_active(runner, journal["agent_service"]):
            return False
        expected = _expected_applied_accounts(journal, root_required=root_required)
        if expected is not None and probe(socket_path, expected):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(READINESS_POLL_SECONDS)


def _release_agent_lock(descriptor: int) -> None:
    """启动旧服务前释放与其主入口相同的 flock。"""
    fcntl.flock(descriptor, fcntl.LOCK_UN)
    os.close(descriptor)


def _stop_split_timer(transaction: Path, runner: Runner) -> None:
    if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", transaction.name) is None:
        raise RollbackError("rollback_txn_name_invalid")
    timer = f"vpn-home-egress-rollback-{transaction.name}.timer"
    if (_rc(runner(["/bin/systemctl", "disable", "--now", timer], None)) != 0
            or _rc(runner(["/bin/systemctl", "is-active", "--quiet", timer], None)) != 3):
        raise RollbackError("rollback_timer_stop_failed")


def rollback(txn_dir: str | os.PathLike[str], *, runner: Runner = _default_runner, enforce_root: bool = True,
             status_probe: Optional[StatusProbe] = None) -> str:
    """执行或续接回滚；任一错误均保留阻断规则。"""
    if enforce_root and os.geteuid() != 0:
        raise RollbackError("rollback_requires_root")
    transaction = Path(txn_dir)
    _private_txn(transaction, root_required=enforce_root)
    journal_path = transaction / "journal.json"
    _private_file(journal_path, root_required=enforce_root)
    transaction_lock = _acquire_lock(transaction / "rollback.lock")
    agent_lock: int | None = None
    try:
        journal, digest = _load_json(journal_path)
        _validate_journal(journal)
        if journal["status"] == "accepted":
            return "accepted"
        split_config = journal.get("split_config")
        if journal["status"] == "rolled_back":
            if split_config:
                _stop_split_timer(transaction, runner)
            return "rolled_back"
        if split_config == "staged":
            _set_status(journal_path, journal, digest, "rolled_back", root_required=enforce_root)
            _stop_split_timer(transaction, runner)
            return "rolled_back"
        if split_config:
            for key, permitted_hashes in (
                ("module_path", {journal["baseline_module_hash"]}),
                ("extra_module_path", {journal["extra_hash"]}),
                ("config_path", {journal["config_hash"], journal["candidate_config_hash"]}),
            ):
                path = _absolute_path(journal[key])
                _safe_regular(path, root_required=enforce_root)
                if _sha256(path) not in permitted_hashes:
                    raise RollbackError("rollback_candidate_changed")
        if journal["status"] == "armed":
            journal, digest = _set_status(journal_path, journal, digest, "rolling_back", root_required=enforce_root)

        pools, reqids = _pools_and_reqids(journal, root_required=enforce_root)
        # 必须先阻断：即使 systemctl stop 失败，流量仍保持闭合，后续可从 rolling_back 续接。
        _install_block(runner, pools, reqids)
        _service(runner, "stop", journal["agent_service"])
        if _service_active(runner, journal["agent_service"]):
            raise RollbackError("rollback_service_still_active")

        state_lock_path = _absolute_path(journal["state_lock_path"])
        _safe_regular(state_lock_path, root_required=enforce_root)
        agent_lock = os.open(state_lock_path, os.O_RDWR | (getattr(os, "O_NOFOLLOW", 0)))
        try:
            fcntl.flock(agent_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RollbackError("rollback_agent_locked") from error

        _delete_owned_rules(runner, pools, journal["routing"])
        _restore_file(_absolute_path(journal["module_path"]), transaction / "baseline-gateway_agent.py",
                      journal["candidate_module_hash"], journal["baseline_module_hash"], root_required=enforce_root)
        _restore_file(_absolute_path(journal["config_path"]), transaction / "baseline-gateway.json",
                      journal["candidate_config_hash"], journal["config_hash"], root_required=enforce_root)
        if not split_config:
            _remove_extra(_absolute_path(journal["extra_module_path"]), journal["extra_hash"], root_required=enforce_root)

        # gateway_agent.main 会以 LOCK_NB 取得相同锁；持锁启动会使旧服务立即退出。
        _release_agent_lock(agent_lock)
        agent_lock = None
        try:
            _service(runner, "start", journal["agent_service"])
            if not _wait_ready(journal, runner, root_required=enforce_root, status_probe=status_probe):
                raise RollbackError("rollback_agent_not_ready")
        except Exception as error:
            # 启动或读回失败时主动停回旧服务；独立阻断表仍保留供下一次重试。
            _service(runner, "stop", journal["agent_service"])
            if isinstance(error, RollbackError):
                raise
            raise RollbackError("rollback_agent_not_ready") from error
        try:
            _remove_block(runner)
        except RollbackError:
            # 不允许运行中的服务与未确认解除的阻断并存。
            _service(runner, "stop", journal["agent_service"])
            raise
        _set_status(journal_path, journal, digest, "rolled_back", root_required=enforce_root)
        if split_config:
            _stop_split_timer(transaction, runner)
        return "rolled_back"
    finally:
        if agent_lock is not None:
            os.close(agent_lock)
        os.close(transaction_lock)


def main() -> int:
    parser = argparse.ArgumentParser(description="home-egress local rollback helper")
    parser.add_argument("--txn-dir", required=True)
    args = parser.parse_args()
    try:
        rollback(args.txn_dir)
    except RollbackError as error:
        # 不暴露 journal、备份、账户或系统命令输出。
        print(str(error))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
