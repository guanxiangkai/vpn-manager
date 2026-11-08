from __future__ import annotations

import hashlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ops.home_egress_rollback import RollbackError, _default_runner, _socket_status_matches, rollback


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FakeRunner:
    def __init__(self, rules=None):
        self.rules = list(rules or [])
        self.calls = []
        self.active = True
        self.blocked = False
        self.fail_stop = False
        self.fail_start = False
        self.fail_timer_disable = False
        self.timer_active = True
        self.start_probe = None

    @staticmethod
    def result(returncode=0, stdout=""):
        return SimpleNamespace(returncode=returncode, stdout=stdout)

    @staticmethod
    def network(rule, field):
        value = rule.get(field, "0.0.0.0/0")
        length = rule.get(field + "len")
        if value == "default":
            value = "0.0.0.0"
        if length is not None and "/" not in value:
            value = f"{value}/{length}"
        return str(ipaddress.ip_network(value, strict=False))

    def __call__(self, argv, input_text=None):
        self.calls.append((list(argv), input_text))
        if argv == ["/usr/sbin/nft", "-j", "list", "tables"]:
            tables = [] if not self.blocked else [{"table": {
                "family": "inet", "name": "vpn_home_rollback",
            }}]
            return self.result(stdout=json.dumps({"nftables": tables}))
        if argv[:3] == ["/usr/sbin/nft", "-j", "list"]:
            if not self.blocked:
                return self.result(1)
            return self.result(stdout=json.dumps({"nftables": [{"table": {
                "family": "inet", "name": "vpn_home_rollback", "comment": "vpn-home-egress-rollback",
            }}]}))
        if argv[:2] == ["/usr/sbin/nft", "--check"]:
            return self.result()
        if argv[:2] == ["/usr/sbin/nft", "-f"]:
            self.blocked = "add table inet vpn_home_rollback" in (input_text or "")
            return self.result()
        if argv == ["/usr/sbin/nft", "delete", "table", "inet", "vpn_home_rollback"]:
            self.blocked = False
            return self.result()
        if argv == ["/sbin/ip", "-4", "-N", "-j", "rule", "show"]:
            return self.result(stdout=json.dumps(self.rules))
        if argv[:4] == ["/sbin/ip", "-4", "rule", "del"]:
            priority = int(argv[argv.index("priority") + 1])
            source = argv[argv.index("from") + 1]
            destination = argv[argv.index("to") + 1]
            table = int(argv[argv.index("table") + 1])
            protocol = int(argv[argv.index("protocol") + 1])
            for index, rule in enumerate(self.rules):
                rule_table = 254 if rule.get("table") == "main" else rule.get("table")
                if (rule.get("priority"), self.network(rule, "src"), self.network(rule, "dst"),
                    rule_table, int(rule.get("protocol"))) == (priority, source, destination, table, protocol):
                    self.rules.pop(index)
                    return self.result()
            return self.result(2)
        if argv[:2] == ["/bin/systemctl", "stop"]:
            if self.fail_stop:
                return self.result(1)
            self.active = False
            return self.result()
        if argv[:2] == ["/bin/systemctl", "start"]:
            if self.fail_start:
                return self.result(1)
            if self.start_probe is not None and not self.start_probe():
                return self.result(1)
            self.active = True
            return self.result()
        if argv[:3] == ["/bin/systemctl", "disable", "--now"] and argv[3].endswith(".timer"):
            if self.fail_timer_disable:
                return self.result(1)
            self.timer_active = False
            return self.result()
        if argv[:3] == ["/bin/systemctl", "is-active", "--quiet"]:
            active = self.timer_active if argv[3].endswith(".timer") else self.active
            return self.result(0 if active else 3)
        raise AssertionError(argv)


def write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def make_transaction(tmp_path: Path):
    txn = tmp_path / "txn"
    txn.mkdir(mode=0o700)
    module = tmp_path / "gateway_agent.py"
    config = tmp_path / "gateway.json"
    extra = tmp_path / "home_egress.py"
    accounts = tmp_path / "accounts.json"
    agent_lock = tmp_path / "agent.lock"
    write_private(module, b"candidate module\n")
    write_private(config, b"candidate config\n")
    write_private(extra, b"candidate extra\n")
    write_private(accounts, json.dumps({"accounts": {"id": {
        "pool": "198.51.100.20/30", "reqid": 17, "generation": 1, "state": "applied",
    }}}).encode())
    write_private(agent_lock, b"")
    baseline_module = b"baseline module\n"
    baseline_config = b"baseline config\n"
    write_private(txn / "baseline-gateway_agent.py", baseline_module)
    write_private(txn / "baseline-gateway.json", baseline_config)
    journal = {
        "status": "armed",
        "module_path": str(module),
        "config_path": str(config),
        "extra_module_path": str(extra),
        "baseline_module_hash": hashlib.sha256(baseline_module).hexdigest(),
        "config_hash": hashlib.sha256(baseline_config).hexdigest(),
        "candidate_module_hash": digest(module),
        "candidate_config_hash": digest(config),
        "extra_hash": digest(extra),
        "accounts_path": str(accounts),
        "agent_service": "vpn-manager-agent.service",
        "state_lock_path": str(agent_lock),
        "control_socket_path": str(tmp_path / "agent.sock"),
        "routing": {"table": 150, "priority": 18000, "protocol": 186},
        "known_pools": ["198.51.100.20/30"],
    }
    write_private(txn / "journal.json", json.dumps(journal).encode())
    return txn, journal, module, config, extra


def status(txn: Path) -> str:
    return json.loads((txn / "journal.json").read_text())["status"]


class TestHomeEgressRollback(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.txn, self.journal, self.module, self.config, self.extra = make_transaction(Path(self.temporary.name))

    def tearDown(self):
        self.temporary.cleanup()

    def test_accepted_is_a_noop(self):
        self.journal["status"] = "accepted"
        write_private(self.txn / "journal.json", json.dumps(self.journal).encode())
        runner = FakeRunner()

        self.assertEqual(rollback(self.txn, runner=runner, enforce_root=False), "accepted")
        self.assertEqual(self.module.read_bytes(), b"candidate module\n")
        self.assertEqual(self.config.read_bytes(), b"candidate config\n")
        self.assertTrue(self.extra.exists())
        self.assertEqual(runner.calls, [])

    def test_restores_exact_candidate_and_preserves_foreign_rule(self):
        owned = {"priority": 18001, "src": "198.51.100.20/30", "dst": "0.0.0.0/0", "table": 150, "protocol": 186}
        foreign = {"priority": 18001, "src": "198.51.100.24/30", "dst": "0.0.0.0/0", "table": 150, "protocol": 186}
        runner = FakeRunner([owned, foreign])
        readiness = iter((False, True))

        self.assertEqual(rollback(self.txn, runner=runner, enforce_root=False,
                                  status_probe=lambda _path, _expected: next(readiness)), "rolled_back")
        self.assertEqual(self.module.read_bytes(), b"baseline module\n")
        self.assertEqual(self.config.read_bytes(), b"baseline config\n")
        self.assertFalse(self.extra.exists())
        self.assertEqual(runner.rules, [foreign])
        self.assertTrue(runner.active)
        self.assertFalse(runner.blocked)
        self.assertEqual(status(self.txn), "rolled_back")

    def test_split_rollback_preserves_preexisting_modules(self):
        write_private(self.module, (self.txn / "baseline-gateway_agent.py").read_bytes())
        self.journal["candidate_module_hash"] = digest(self.module)
        self.journal["split_config"] = "applying"
        write_private(self.txn / "journal.json", json.dumps(self.journal).encode())
        runner = FakeRunner()
        readiness = iter((False, True))

        self.assertEqual(rollback(self.txn, runner=runner, enforce_root=False,
                                  status_probe=lambda _path, _expected: next(readiness)), "rolled_back")
        self.assertEqual(self.config.read_bytes(), b"baseline config\n")
        self.assertEqual(digest(self.module), self.journal["baseline_module_hash"])
        self.assertEqual(digest(self.extra), self.journal["extra_hash"])
        self.assertTrue(runner.active)
        self.assertFalse(runner.blocked)
        self.assertFalse(runner.timer_active)

    def test_expired_split_timer_before_apply_does_not_touch_runtime(self):
        write_private(self.config, (self.txn / "baseline-gateway.json").read_bytes())
        self.journal["candidate_module_hash"] = self.journal["baseline_module_hash"]
        self.journal["split_config"] = "staged"
        write_private(self.txn / "journal.json", json.dumps(self.journal).encode())
        runner = FakeRunner()
        runner.fail_timer_disable = True

        with self.assertRaisesRegex(RollbackError, "rollback_timer_stop_failed"):
            rollback(self.txn, runner=runner, enforce_root=False)
        self.assertEqual(status(self.txn), "rolled_back")
        runner.fail_timer_disable = False
        self.assertEqual(rollback(self.txn, runner=runner, enforce_root=False), "rolled_back")
        self.assertEqual(self.config.read_bytes(), b"baseline config\n")
        self.assertEqual(digest(self.extra), self.journal["extra_hash"])
        self.assertTrue(runner.active)
        self.assertFalse(runner.timer_active)
        self.assertTrue(all(argv[-1] == "vpn-home-egress-rollback-txn.timer" for argv, _ in runner.calls))

    def test_failed_stop_keeps_block_and_transaction_recoverable(self):
        runner = FakeRunner()
        runner.fail_stop = True

        with self.assertRaisesRegex(RollbackError, "service_failed"):
            rollback(self.txn, runner=runner, enforce_root=False)
        self.assertTrue(runner.blocked)
        self.assertTrue(runner.active)
        self.assertEqual(self.module.read_bytes(), b"candidate module\n")
        self.assertEqual(status(self.txn), "rolling_back")

        runner.fail_stop = False
        self.assertEqual(rollback(self.txn, runner=runner, enforce_root=False,
                                  status_probe=lambda _path, _expected: True), "rolled_back")
        self.assertFalse(runner.blocked)

    def test_real_ip_json_src_and_prefix_lengths_are_cleaned(self):
        runner = FakeRunner([{
            "priority": 18000, "src": "198.51.100.20", "srclen": 30,
            "dst": "203.0.113.0", "dstlen": 24, "table": "main", "protocol": "186",
        }, {
            "priority": 18001, "src": "198.51.100.20/30", "srclen": 30,
            "dst": "default", "dstlen": 0, "table": 150, "protocol": 186,
        }])

        self.assertEqual(rollback(self.txn, runner=runner, enforce_root=False,
                                  status_probe=lambda _path, _expected: True), "rolled_back")
        self.assertEqual(runner.rules, [])
        self.assertTrue(any(call == ["/sbin/ip", "-4", "-N", "-j", "rule", "show"]
                            for call, _input in runner.calls))

    def test_start_can_take_real_agent_lock_after_rollback_releases_it(self):
        lock_path = Path(self.journal["state_lock_path"])
        runner = FakeRunner()
        attempts = []

        def claim_agent_lock():
            descriptor = os.open(lock_path, os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                attempts.append(True)
                return True
            except BlockingIOError:
                attempts.append(False)
                return False
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

        runner.start_probe = claim_agent_lock
        self.assertEqual(rollback(self.txn, runner=runner, enforce_root=False,
                                  status_probe=lambda _path, _expected: True), "rolled_back")
        self.assertEqual(attempts, [True])

    def test_real_control_socket_status_is_required_for_default_readiness(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as socket_directory:
            socket_path = Path(socket_directory) / "agent.sock"
            self.journal["control_socket_path"] = str(socket_path)
            write_private(self.txn / "journal.json", json.dumps(self.journal).encode())
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(socket_path))
            except PermissionError:
                listener.close()
                self.skipTest("当前本地沙箱不允许创建 Unix 控制套接字")
            socket_path.chmod(0o660)
            listener.listen(1)

            def respond():
                connection, _address = listener.accept()
                with connection:
                    request = json.loads(connection.recv(4096))
                    connection.sendall(json.dumps({
                        "username": request["username"], "generation": 1, "state": "applied",
                    }).encode() + b"\n")

            thread = threading.Thread(target=respond)
            thread.start()
            try:
                self.assertEqual(rollback(self.txn, runner=FakeRunner(), enforce_root=False), "rolled_back")
            finally:
                thread.join(timeout=1)
                listener.close()
                socket_path.unlink(missing_ok=True)
            self.assertFalse(thread.is_alive())

    def test_empty_accounts_require_not_provisioned_status_response(self):
        accounts_path = Path(self.journal["accounts_path"])
        write_private(accounts_path, json.dumps({"accounts": {}}).encode())
        with tempfile.TemporaryDirectory(dir="/tmp") as socket_directory:
            socket_path = Path(socket_directory) / "agent.sock"
            self.journal["control_socket_path"] = str(socket_path)
            write_private(self.txn / "journal.json", json.dumps(self.journal).encode())
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(socket_path))
            except PermissionError:
                listener.close()
                self.skipTest("当前本地沙箱不允许创建 Unix 控制套接字")
            socket_path.chmod(0o660)
            listener.listen(1)
            requests = []

            def respond():
                connection, _address = listener.accept()
                with connection:
                    request = json.loads(connection.recv(4096))
                    requests.append(request)
                    connection.sendall(json.dumps({
                        "username": request["username"], "generation": 0, "state": "not_provisioned",
                    }).encode() + b"\n")

            thread = threading.Thread(target=respond)
            thread.start()
            try:
                self.assertEqual(rollback(self.txn, runner=FakeRunner(), enforce_root=False), "rolled_back")
            finally:
                thread.join(timeout=1)
                listener.close()
                socket_path.unlink(missing_ok=True)
            self.assertFalse(thread.is_alive())
            self.assertEqual(requests, [{"action": "status", "username": "rollback_healthcheck"}])

    def test_empty_accounts_reject_wrong_status_response(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as socket_directory:
            socket_path = Path(socket_directory) / "agent.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(socket_path))
            except PermissionError:
                listener.close()
                self.skipTest("当前本地沙箱不允许创建 Unix 控制套接字")
            socket_path.chmod(0o660)
            listener.listen(1)

            def respond():
                connection, _address = listener.accept()
                with connection:
                    request = json.loads(connection.recv(4096))
                    connection.sendall(json.dumps({
                        "username": request["username"], "generation": 0, "state": "applied",
                    }).encode() + b"\n")

            thread = threading.Thread(target=respond)
            thread.start()
            try:
                self.assertFalse(_socket_status_matches(socket_path, {}, root_required=False))
            finally:
                thread.join(timeout=1)
                listener.close()
                socket_path.unlink(missing_ok=True)
            self.assertFalse(thread.is_alive())

    def test_readiness_failure_stops_agent_and_keeps_block(self):
        runner = FakeRunner()
        with patch("ops.home_egress_rollback.READINESS_TIMEOUT_SECONDS", 0):
            with self.assertRaisesRegex(RollbackError, "agent_not_ready"):
                rollback(self.txn, runner=runner, enforce_root=False,
                         status_probe=lambda _path, _expected: False)
        self.assertTrue(runner.blocked)
        self.assertFalse(runner.active)
        self.assertEqual(status(self.txn), "rolling_back")

    def test_default_runner_gives_systemctl_a_separate_stop_budget(self):
        with patch("ops.home_egress_rollback.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="")) as run:
            _default_runner(["/bin/systemctl", "stop", "vpn-manager-agent.service"])
            self.assertEqual(run.call_args.kwargs["timeout"], 30)
            _default_runner(["/sbin/ip", "-4", "-N", "-j", "rule", "show"])
            self.assertEqual(run.call_args.kwargs["timeout"], 8)


if __name__ == "__main__":
    unittest.main()
