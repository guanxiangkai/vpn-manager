#!/usr/bin/env python3
"""家庭出口的本机、可回滚发布事务。

此工具只准备和切换 gateway agent 的三个文件；不会重启 charon，也不会读取或
输出配置中的凭据。发生切换后，事务目录内的独立回滚脚本和 systemd timer 是唯一
的恢复路径，直到 ``accept`` 以 CAS 标记接受为止。
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Callable, Optional


SYSTEMD_DIRECTORY = Path("/etc/systemd/system")
SYSTEMCTL_TIMEOUT_SECONDS = 30
COMMAND_TIMEOUT_SECONDS = 8
TXN_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
SYSTEMD_SAFE_PATH_RE = re.compile(r"/[A-Za-z0-9_./-]+")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
Runner = Callable[[list[str], Optional[str]], Any]
ROLLBACK_PYTHON_MAGIC = "vpn-home-egress-python-3.11"
ROLLBACK_PYTHON_PROBE = (
    "import sys\n"
    "if sys.version_info < (3, 11): raise SystemExit(1)\n"
    f"print({ROLLBACK_PYTHON_MAGIC!r})\n"
)


class PublishError(RuntimeError):
    """固定错误码；调用方不得把命令或配置内容回显。"""


def _default_runner(argv: list[str], input_text: str | None = None) -> Any:
    timeout = SYSTEMCTL_TIMEOUT_SECONDS if argv[:1] == ["/bin/systemctl"] else COMMAND_TIMEOUT_SECONDS
    try:
        return subprocess.run(argv, input=input_text, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", "")


def _rc(result: Any) -> int:
    value = getattr(result, "returncode", None)
    if not isinstance(value, int):
        raise PublishError("publish_runner_contract")
    return value


def _stdout(result: Any) -> str:
    value = getattr(result, "stdout", "")
    if not isinstance(value, str):
        raise PublishError("publish_runner_contract")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _absolute(value: str | os.PathLike[str]) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise PublishError("publish_path_invalid")
    return path


def _journal_absolute(journal: dict[str, Any], key: str) -> Path:
    value = journal.get(key)
    if not isinstance(value, str):
        raise PublishError("publish_journal_invalid")
    return _absolute(value)


def _agent_service(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", value) is None:
        raise PublishError("publish_agent_service_invalid")
    return value


def _rollback_python(path: Path, *, root_required: bool) -> Path:
    if SYSTEMD_SAFE_PATH_RE.fullmatch(str(path)) is None:
        raise PublishError("publish_rollback_python_invalid")
    _regular(path, root_required=root_required)
    if not os.access(path, os.X_OK):
        raise PublishError("publish_rollback_python_invalid")
    return path


def _probe_rollback_python(path: Path, runner: Runner) -> None:
    """回滚脚本最低使用项目支持的 Python 3.11；不回显解释器输出。"""
    try:
        result = runner([str(path), "-I", "-c", ROLLBACK_PYTHON_PROBE], None)
        valid = _rc(result) == 0 and _stdout(result) == ROLLBACK_PYTHON_MAGIC + "\n"
    except Exception as error:
        raise PublishError("publish_rollback_python_unusable") from error
    if not valid:
        raise PublishError("publish_rollback_python_unusable")


def _regular(path: Path, *, root_required: bool, private: bool = False) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise PublishError("publish_file_missing") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PublishError("publish_unsafe_file")
    if root_required and info.st_uid != 0:
        raise PublishError("publish_file_owner")
    if private and stat.S_IMODE(info.st_mode) != 0o600:
        raise PublishError("publish_file_mode")
    if not private and stat.S_IMODE(info.st_mode) & 0o022:
        raise PublishError("publish_unsafe_mode")


def _private_txn(path: Path, *, root_required: bool) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise PublishError("publish_txn_missing") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise PublishError("publish_unsafe_txn")
    if root_required and info.st_uid != 0:
        raise PublishError("publish_txn_owner")


def _write_new_private(path: Path, content: bytes, *, root_required: bool) -> None:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise PublishError("publish_target_exists") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _regular(path, root_required=root_required, private=True)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _atomic_copy(source: Path, target: Path, expected_before: str | None, *, root_required: bool) -> None:
    _regular(source, root_required=False)
    if expected_before is not None and (not target.exists() or _sha256(target) != expected_before):
        raise PublishError("publish_compare_failed")
    descriptor, temporary = tempfile.mkstemp(prefix=".home-egress-", dir=target.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with source.open("rb") as origin, os.fdopen(descriptor, "wb", closefd=True) as destination:
            descriptor = -1
            shutil.copyfileobj(origin, destination)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, target)
        directory = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if os.path.exists(temporary):
            os.unlink(temporary)
    _regular(target, root_required=root_required, private=True)


def _load_journal(transaction: Path, *, root_required: bool) -> tuple[dict[str, Any], str]:
    path = transaction / "journal.json"
    _regular(path, root_required=root_required, private=True)
    raw = path.read_bytes()
    try:
        journal = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublishError("publish_journal_invalid") from error
    if not isinstance(journal, dict) or journal.get("status") not in {"prepared", "armed", "accepted"}:
        raise PublishError("publish_journal_invalid")
    return journal, hashlib.sha256(raw).hexdigest()


def _replace_journal(transaction: Path, before: str, journal: dict[str, Any], *, root_required: bool) -> str:
    path = transaction / "journal.json"
    _regular(path, root_required=root_required, private=True)
    if _sha256(path) != before:
        raise PublishError("publish_journal_changed")
    encoded = (json.dumps(journal, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary = tempfile.mkstemp(prefix=".journal-", dir=transaction)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(transaction, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    _regular(path, root_required=root_required, private=True)
    return hashlib.sha256(encoded).hexdigest()


def _lock(transaction: Path) -> int:
    path = transaction / "rollback.lock"
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise PublishError("publish_locked") from error


def _load_rollback(transaction: Path):
    path = transaction / "home_egress_rollback.py"
    _regular(path, root_required=False, private=True)
    spec = importlib.util.spec_from_file_location("home_egress_rollback_stable", path)
    if spec is None or spec.loader is None:
        raise PublishError("publish_rollback_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _known_pools(accounts_path: Path) -> list[str]:
    try:
        accounts = json.loads(accounts_path.read_bytes())["accounts"]
        values = [account["pool"] for account in accounts.values() if isinstance(account, dict) and isinstance(account.get("pool"), str)]
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError, OSError) as error:
        raise PublishError("publish_accounts_invalid") from error
    if len(values) != len(set(values)):
        raise PublishError("publish_accounts_invalid")
    return values


def _compile(path: Path) -> None:
    try:
        # 不生成 __pycache__；候选源码的字节码缓存不应成为发布副作用。
        compile(path.read_bytes(), str(path), "exec")
    except (OSError, SyntaxError) as error:
        raise PublishError("publish_candidate_compile_failed") from error


def _require_hash(path: Path, supplied: str) -> str:
    if SHA256_RE.fullmatch(supplied) is None or _sha256(path) != supplied:
        raise PublishError("publish_candidate_hash_mismatch")
    return supplied


def _render_candidate_config(config: Path, home_dns: str) -> bytes:
    try:
        settings = json.loads(config.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublishError("publish_config_invalid") from error
    if not isinstance(settings, dict):
        raise PublishError("publish_config_invalid")
    try:
        dns = str(ipaddress.IPv4Address(home_dns))
    except (ValueError, TypeError) as error:
        raise PublishError("publish_home_dns_invalid") from error
    settings["home_internet"] = {"enabled": True, "routing_table": 150, "rule_priority": 18000,
                                 "rule_protocol": 186, "dns": [dns]}
    return (json.dumps(settings, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _systemctl(runner: Runner, *arguments: str) -> Any:
    return runner(["/bin/systemctl", *arguments], None)


def _unit_names(transaction: Path) -> tuple[str, str]:
    if TXN_NAME_RE.fullmatch(transaction.name) is None or SYSTEMD_SAFE_PATH_RE.fullmatch(str(transaction)) is None:
        raise PublishError("publish_txn_name_invalid")
    prefix = "vpn-home-egress-rollback-" + transaction.name
    return prefix + ".service", prefix + ".timer"


def _unit_contents(transaction: Path, rollback_python: Path) -> tuple[bytes, bytes]:
    if SYSTEMD_SAFE_PATH_RE.fullmatch(str(rollback_python)) is None:
        raise PublishError("publish_rollback_python_invalid")
    service, timer = _unit_names(transaction)
    command = f"{rollback_python} {transaction}/home_egress_rollback.py --txn-dir {transaction}"
    service_text = "[Unit]\nDescription=VPN home egress transaction rollback\n\n[Service]\nType=oneshot\nExecStart=" + command + "\nRestart=on-failure\nRestartSec=10\nTimeoutStartSec=120\n"
    timer_text = "[Unit]\nDescription=VPN home egress rollback deadline\n\n[Timer]\nUnit=" + service + "\nOnActiveSec=20min\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
    return service_text.encode(), timer_text.encode()


def _timer_proof(transaction: Path, rollback_python: Path, runner: Runner) -> bool:
    service, timer = _unit_names(transaction)
    if _rc(_systemctl(runner, "is-active", "--quiet", timer)) != 0:
        return False
    service_result, timer_result = _systemctl(runner, "cat", service), _systemctl(runner, "cat", timer)
    if _rc(service_result) != 0 or _rc(timer_result) != 0:
        return False
    service_bytes, timer_bytes = _unit_contents(transaction, rollback_python)
    return service_bytes.decode() in _stdout(service_result) and timer_bytes.decode() in _stdout(timer_result)


def _unit_baseline(agent_service: str, runner: Runner) -> dict[str, str]:
    """只保存非敏感 unit 元数据的摘要，避免 journal 收入 Environment 等字段。"""
    runtime = _systemctl(runner, "show", agent_service, "--property=ActiveState", "--property=SubState",
                         "--property=LoadState", "--value")
    listing = _systemctl(runner, "cat", agent_service)
    if _rc(runtime) != 0 or _rc(listing) != 0:
        raise PublishError("publish_unit_baseline_failed")
    return {"runtime_sha256": hashlib.sha256(_stdout(runtime).encode()).hexdigest(),
            "cat_sha256": hashlib.sha256(_stdout(listing).encode()).hexdigest()}


def prepare(txn_dir: str | os.PathLike[str], *, candidate_module: str | os.PathLike[str], candidate_extra: str | os.PathLike[str],
            candidate_module_hash: str, candidate_extra_hash: str, baseline_module_hash: str, baseline_config_hash: str,
            module_path: Path, extra_module_path: Path, config_path: Path, state_directory: Path,
            agent_service: str, control_socket_path: Path, rollback_python: Path, home_dns: str,
            rollback_source: Path | None = None, runner: Runner = _default_runner, enforce_root: bool = True) -> str:
    """创建私有不可覆盖事务，并在切换前确认当前账户投影已实际 applied。"""
    if enforce_root and os.geteuid() != 0:
        raise PublishError("publish_requires_root")
    transaction = _absolute(txn_dir)
    if transaction.exists():
        raise PublishError("publish_txn_exists")
    transaction.mkdir(mode=0o700, parents=False)
    try:
        _private_txn(transaction, root_required=enforce_root)
        module_path, extra_module_path = _absolute(module_path), _absolute(extra_module_path)
        config_path, state_directory = _absolute(config_path), _absolute(state_directory)
        control_socket_path, rollback_python = _absolute(control_socket_path), _absolute(rollback_python)
        agent_service = _agent_service(agent_service)
        if extra_module_path.parent != module_path.parent or extra_module_path.name != "home_egress.py":
            raise PublishError("publish_extra_module_path_invalid")
        candidate_module_path, candidate_extra_path = _absolute(candidate_module), _absolute(candidate_extra)
        for path in (module_path, config_path, candidate_module_path, candidate_extra_path):
            _regular(path, root_required=False)
        _rollback_python(rollback_python, root_required=enforce_root)
        _probe_rollback_python(rollback_python, runner)
        if SHA256_RE.fullmatch(baseline_module_hash) is None or _sha256(module_path) != baseline_module_hash:
            raise PublishError("publish_baseline_module_changed")
        if SHA256_RE.fullmatch(baseline_config_hash) is None or _sha256(config_path) != baseline_config_hash:
            raise PublishError("publish_baseline_config_changed")
        if extra_module_path.exists():
            raise PublishError("publish_extra_already_exists")
        _require_hash(candidate_module_path, candidate_module_hash)
        _require_hash(candidate_extra_path, candidate_extra_hash)
        _compile(candidate_module_path)
        _compile(candidate_extra_path)
        accounts_path, lock_path = state_directory / "accounts.json", state_directory / "agent.lock"
        _regular(accounts_path, root_required=enforce_root)
        _regular(lock_path, root_required=enforce_root)
        pools = _known_pools(accounts_path)
        unit_baseline = _unit_baseline(agent_service, runner)
        candidate_config = _render_candidate_config(config_path, home_dns)
        _write_new_private(transaction / "baseline-gateway_agent.py", module_path.read_bytes(), root_required=enforce_root)
        _write_new_private(transaction / "baseline-gateway.json", config_path.read_bytes(), root_required=enforce_root)
        _write_new_private(transaction / "candidate-gateway_agent.py", candidate_module_path.read_bytes(), root_required=enforce_root)
        _write_new_private(transaction / "candidate-home_egress.py", candidate_extra_path.read_bytes(), root_required=enforce_root)
        _write_new_private(transaction / "candidate-gateway.json", candidate_config, root_required=enforce_root)
        source = rollback_source or Path(__file__).with_name("home_egress_rollback.py")
        _regular(source, root_required=False)
        _write_new_private(transaction / "home_egress_rollback.py", source.read_bytes(), root_required=enforce_root)
        journal = {"status": "prepared", "module_path": str(module_path), "config_path": str(config_path),
                   "extra_module_path": str(extra_module_path), "baseline_module_hash": baseline_module_hash,
                   "config_hash": baseline_config_hash, "candidate_module_hash": candidate_module_hash,
                   "candidate_config_hash": hashlib.sha256(candidate_config).hexdigest(), "extra_hash": candidate_extra_hash,
                   "accounts_path": str(accounts_path), "agent_service": agent_service, "state_lock_path": str(lock_path),
                   "control_socket_path": str(control_socket_path), "routing": {"table": 150, "priority": 18000, "protocol": 186},
                   "known_pools": pools, "unit_baseline": unit_baseline, "rollback_python": str(rollback_python)}
        _write_new_private(transaction / "journal.json", (json.dumps(journal, sort_keys=True, separators=(",", ":")) + "\n").encode(), root_required=enforce_root)
        rollback = _load_rollback(transaction)
        expected = rollback._expected_applied_accounts(journal, root_required=enforce_root)
        if expected is None or not rollback._socket_status_matches(control_socket_path, expected, root_required=enforce_root):
            raise PublishError("publish_baseline_not_ready")
        return "prepared"
    except Exception:
        # 不删除事务：任何准备失败都留存原始失败证据，且尚未改变生产文件。
        raise


def arm(txn_dir: str | os.PathLike[str], *, systemd_directory: Path = SYSTEMD_DIRECTORY, runner: Runner = _default_runner,
        enforce_root: bool = True) -> str:
    if enforce_root and os.geteuid() != 0:
        raise PublishError("publish_requires_root")
    transaction = _absolute(txn_dir)
    _private_txn(transaction, root_required=enforce_root)
    descriptor = _lock(transaction)
    created: list[Path] = []
    armed_digest: str | None = None
    try:
        journal, digest = _load_journal(transaction, root_required=enforce_root)
        if journal["status"] == "armed":
            _load_rollback(transaction)._validate_journal(journal)
            rollback_python = _rollback_python(_journal_absolute(journal, "rollback_python"), root_required=enforce_root)
            service, timer = _unit_names(transaction)
            service_content, timer_content = _unit_contents(transaction, rollback_python)
            service_path, timer_path = systemd_directory / service, systemd_directory / timer
            for path, expected in ((service_path, service_content), (timer_path, timer_content)):
                _regular(path, root_required=False)
                if path.read_bytes() != expected:
                    raise PublishError("publish_unit_changed")
            if _rc(_systemctl(runner, "enable", "--now", timer)) != 0 or not _timer_proof(transaction, rollback_python, runner):
                raise PublishError("publish_timer_not_active")
            return "armed"
        if journal["status"] != "prepared":
            raise PublishError("publish_not_prepared")
        validation_journal = dict(journal)
        validation_journal["status"] = "armed"
        _load_rollback(transaction)._validate_journal(validation_journal)
        rollback_python = _rollback_python(_journal_absolute(journal, "rollback_python"), root_required=enforce_root)
        service, timer = _unit_names(transaction)
        service_content, timer_content = _unit_contents(transaction, rollback_python)
        service_path, timer_path = systemd_directory / service, systemd_directory / timer
        if service_path.exists() or timer_path.exists():
            raise PublishError("publish_unit_exists")
        _write_new_private(service_path, service_content, root_required=False)
        created.append(service_path)
        os.chmod(service_path, 0o644)
        _write_new_private(timer_path, timer_content, root_required=False)
        created.append(timer_path)
        os.chmod(timer_path, 0o644)
        if _rc(_systemctl(runner, "daemon-reload")) != 0:
            raise PublishError("publish_daemon_reload_failed")
        armed = dict(journal); armed["status"] = "armed"
        armed_digest = _replace_journal(transaction, digest, armed, root_required=enforce_root)
        if _rc(_systemctl(runner, "enable", "--now", timer)) != 0 or not _timer_proof(transaction, rollback_python, runner):
            raise PublishError("publish_timer_not_active")
        return "armed"
    except Exception:
        # 只有 arm 成功后才允许进入 armed；未成功的 unit 由本次调用清除，事务可安全重试。
        if armed_digest is not None:
            _service, timer = _unit_names(transaction)
            _systemctl(runner, "disable", "--now", timer)
            try:
                _replace_journal(transaction, armed_digest, journal, root_required=enforce_root)
            except PublishError:
                pass
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        if created:
            _systemctl(runner, "daemon-reload")
        raise
    finally:
        os.close(descriptor)


def apply(txn_dir: str | os.PathLike[str], *, runner: Runner = _default_runner, enforce_root: bool = True) -> str:
    if enforce_root and os.geteuid() != 0:
        raise PublishError("publish_requires_root")
    transaction = _absolute(txn_dir)
    _private_txn(transaction, root_required=enforce_root)
    descriptor = _lock(transaction)
    requires_rollback = False
    failure: Exception | None = None
    try:
        journal, _digest = _load_journal(transaction, root_required=enforce_root)
        rollback = _load_rollback(transaction)
        rollback._validate_journal(journal)
        rollback_python = _rollback_python(_journal_absolute(journal, "rollback_python"), root_required=enforce_root)
        if journal["status"] != "armed" or not _timer_proof(transaction, rollback_python, runner):
            raise PublishError("publish_timer_not_active")
        if _sha256(Path(journal["module_path"])) != journal["baseline_module_hash"] or _sha256(Path(journal["config_path"])) != journal["config_hash"] or Path(journal["extra_module_path"]).exists():
            raise PublishError("publish_compare_failed")
        # prepare 与 apply 间状态可能变化；此处拒绝可避免的断流，不建立阻断也不停止服务。
        if not rollback._wait_ready(journal, runner, root_required=enforce_root, status_probe=None):
            raise PublishError("publish_baseline_not_ready")
        # 阻断在停 agent 前建立；任何中断均由 rollback 保持闭合直至旧服务确认就绪。
        requires_rollback = True
        pools, reqids = rollback._pools_and_reqids(journal, root_required=enforce_root)
        rollback._install_block(runner, pools, reqids)
        if _rc(_systemctl(runner, "stop", journal["agent_service"])) != 0 or _rc(_systemctl(runner, "is-active", "--quiet", journal["agent_service"])) == 0:
            raise PublishError("publish_agent_stop_failed")
        expected = rollback._expected_applied_accounts(journal, root_required=enforce_root)
        if expected is None or rollback._socket_status_matches(Path(journal["control_socket_path"]), expected,
                                                               root_required=enforce_root):
            raise PublishError("publish_control_socket_still_ready")
        lock_path = Path(journal["state_lock_path"])
        lock_fd = os.open(lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _atomic_copy(transaction / "candidate-gateway_agent.py", Path(journal["module_path"]), journal["baseline_module_hash"], root_required=enforce_root)
            _atomic_copy(transaction / "candidate-home_egress.py", Path(journal["extra_module_path"]), None, root_required=enforce_root)
            _atomic_copy(transaction / "candidate-gateway.json", Path(journal["config_path"]), journal["config_hash"], root_required=enforce_root)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        if _rc(_systemctl(runner, "start", journal["agent_service"])) != 0:
            raise PublishError("publish_agent_start_failed")
        if not rollback._wait_ready(journal, runner, root_required=enforce_root, status_probe=None):
            raise PublishError("publish_agent_not_ready")
        rollback._remove_block(runner)
    except Exception as error:
        failure = error
    finally:
        os.close(descriptor)
    if failure is not None:
        if requires_rollback:
            try:
                _load_rollback(transaction).rollback(transaction, runner=runner, enforce_root=enforce_root)
            except Exception:
                pass
        if isinstance(failure, PublishError):
            raise failure
        raise PublishError("publish_apply_failed") from failure
    return "applied"


def accept(txn_dir: str | os.PathLike[str], *, runner: Runner = _default_runner, enforce_root: bool = True) -> str:
    if enforce_root and os.geteuid() != 0:
        raise PublishError("publish_requires_root")
    transaction = _absolute(txn_dir)
    _private_txn(transaction, root_required=enforce_root)
    descriptor = _lock(transaction)
    try:
        journal, digest = _load_journal(transaction, root_required=enforce_root)
        _load_rollback(transaction)._validate_journal(journal)
        if journal["status"] == "accepted":
            # 上次 CAS 已接受但 timer 停用失败时，此处必须可继续收尾。
            _service, timer = _unit_names(transaction)
            if _rc(_systemctl(runner, "disable", "--now", timer)) != 0 or _rc(_systemctl(runner, "is-active", "--quiet", timer)) == 0:
                raise PublishError("publish_timer_stop_failed")
            return "accepted"
        if journal["status"] != "armed":
            raise PublishError("publish_not_armed")
        if (_sha256(Path(journal["module_path"])) != journal["candidate_module_hash"]
                or _sha256(Path(journal["config_path"])) != journal["candidate_config_hash"]
                or _sha256(Path(journal["extra_module_path"])) != journal["extra_hash"]):
            raise PublishError("publish_candidate_not_current")
        rollback = _load_rollback(transaction)
        if not rollback._wait_ready(journal, runner, root_required=enforce_root, status_probe=None):
            raise PublishError("publish_agent_not_ready")
        accepted = dict(journal); accepted["status"] = "accepted"
        _replace_journal(transaction, digest, accepted, root_required=enforce_root)
        _service, timer = _unit_names(transaction)
        if _rc(_systemctl(runner, "disable", "--now", timer)) != 0 or _rc(_systemctl(runner, "is-active", "--quiet", timer)) == 0:
            raise PublishError("publish_timer_stop_failed")
        return "accepted"
    finally:
        os.close(descriptor)


def status(txn_dir: str | os.PathLike[str], *, enforce_root: bool = True) -> str:
    transaction = _absolute(txn_dir)
    _private_txn(transaction, root_required=enforce_root)
    journal, _digest = _load_journal(transaction, root_required=enforce_root)
    return str(journal["status"])


def main() -> int:
    parser = argparse.ArgumentParser(description="home-egress local publish helper")
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--txn-dir", required=True); prepare_parser.add_argument("--candidate-module", required=True)
    prepare_parser.add_argument("--candidate-extra", required=True); prepare_parser.add_argument("--candidate-module-hash", required=True)
    prepare_parser.add_argument("--candidate-extra-hash", required=True); prepare_parser.add_argument("--baseline-module-hash", required=True)
    prepare_parser.add_argument("--baseline-config-hash", required=True)
    prepare_parser.add_argument("--module-path", required=True); prepare_parser.add_argument("--extra-module-path", required=True)
    prepare_parser.add_argument("--config-path", required=True); prepare_parser.add_argument("--state-directory", required=True)
    prepare_parser.add_argument("--agent-service", required=True); prepare_parser.add_argument("--control-socket-path", required=True)
    prepare_parser.add_argument("--rollback-python", required=True); prepare_parser.add_argument("--home-dns", required=True)
    for command in ("arm", "apply", "accept", "status"):
        item = sub.add_parser(command); item.add_argument("--txn-dir", required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare(args.txn_dir, candidate_module=args.candidate_module, candidate_extra=args.candidate_extra,
                             candidate_module_hash=args.candidate_module_hash, candidate_extra_hash=args.candidate_extra_hash,
                             baseline_module_hash=args.baseline_module_hash, baseline_config_hash=args.baseline_config_hash,
                             module_path=Path(args.module_path), extra_module_path=Path(args.extra_module_path),
                             config_path=Path(args.config_path), state_directory=Path(args.state_directory),
                             agent_service=args.agent_service, control_socket_path=Path(args.control_socket_path),
                             rollback_python=Path(args.rollback_python), home_dns=args.home_dns)
        elif args.command == "arm": result = arm(args.txn_dir)
        elif args.command == "apply": result = apply(args.txn_dir)
        elif args.command == "accept": result = accept(args.txn_dir)
        else: result = status(args.txn_dir)
    except PublishError as error:
        print(str(error))
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
