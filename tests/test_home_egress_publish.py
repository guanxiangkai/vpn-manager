import hashlib
import json
import os
import fcntl
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ops import home_egress_publish as publish


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_private(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


class FakeRollback:
    def __init__(self, runner=None):
        self.rollback_calls = 0
        self.events = []
        self.ready = True
        self.runner = runner

    def _validate_journal(self, journal):
        required = {"module_path", "config_path", "extra_module_path", "candidate_module_hash", "candidate_config_hash", "extra_hash"}
        if not required <= set(journal):
            raise AssertionError("journal fields")

    def _expected_applied_accounts(self, _journal, *, root_required):
        return {"id": 1}

    def _socket_status_matches(self, _path, expected, *, root_required):
        return expected == {"id": 1} and (self.runner is None or self.runner.socket_ready)

    def _wait_ready(self, _journal, _runner, *, root_required, status_probe):
        self.events.append("ready")
        return self.ready

    def _pools_and_reqids(self, _journal, *, root_required):
        return {"198.51.100.20/30"}, {17}

    def _install_block(self, _runner, _pools, _reqids):
        self.events.append("block")

    def _remove_block(self, _runner):
        self.events.append("unblock")

    def rollback(self, _transaction, *, runner, enforce_root):
        self.rollback_calls += 1
        return "rolled_back"


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.timer_active = False
        self.agent_active = True
        self.fail_disable = False
        self.contents = {}
        self.rollback_probe_code = 0
        self.rollback_probe_stdout = publish.ROLLBACK_PYTHON_MAGIC + "\n"
        self.socket_ready = True
        self.stopped_services = set()
        self.managed_service = "test-agent.service"

    def __call__(self, argv, input_text=None):
        self.calls.append(argv)
        if len(argv) == 4 and argv[1:3] == ["-I", "-c"]:
            return SimpleNamespace(returncode=self.rollback_probe_code, stdout=self.rollback_probe_stdout)
        if argv[:3] == ["/bin/systemctl", "is-active", "--quiet"]:
            name = argv[3]
            active = self.timer_active if name.endswith(".timer") else (
                False if name in self.stopped_services else self.agent_active if name == self.managed_service else True)
            return SimpleNamespace(returncode=0 if active else 3, stdout="")
        if argv[:3] == ["/bin/systemctl", "enable", "--now"]:
            self.timer_active = True
        elif argv[:3] == ["/bin/systemctl", "disable", "--now"]:
            if self.fail_disable:
                return SimpleNamespace(returncode=1, stdout="")
            self.timer_active = False
        elif argv[:2] == ["/bin/systemctl", "stop"]:
            name = argv[2]
            self.stopped_services.add(name)
            if name == self.managed_service:
                self.agent_active = False
                self.socket_ready = False
        elif argv[:2] == ["/bin/systemctl", "start"]:
            name = argv[2]
            self.stopped_services.discard(name)
            if name == self.managed_service:
                self.agent_active = True
                self.socket_ready = True
        if argv[:2] == ["/bin/systemctl", "cat"]:
            return SimpleNamespace(returncode=0, stdout=self.contents.get(argv[2], ""))
        if argv[:2] == ["/bin/systemctl", "show"]:
            return SimpleNamespace(returncode=0, stdout="active\nrunning\nloaded\n")
        return SimpleNamespace(returncode=0, stdout="")


class TestHomeEgressPublish(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.txn = self.root / "txn-1"
        self.module = self.root / "gateway_agent.py"
        self.extra = self.root / "home_egress.py"
        self.config = self.root / "gateway.json"
        self.state = self.root / "state"
        self.state.mkdir()
        self.candidate_module = self.root / "candidate_agent.py"
        self.candidate_extra = self.root / "candidate_egress.py"
        write_private(self.module, b"baseline_module = 1\n")
        write_private(self.config, json.dumps({"credential": "do-not-log", "networks": {"home": {"interface": "tun0"}}}).encode())
        write_private(self.candidate_module, b"candidate_module = 2\n")
        write_private(self.candidate_extra, b"candidate_extra = 3\n")
        write_private(self.state / "accounts.json", json.dumps({"accounts": {"id": {"pool": "198.51.100.20/30", "generation": 1, "state": "applied"}}}).encode())
        write_private(self.state / "agent.lock", b"")
        self.rollback = self.root / "rollback.py"
        write_private(self.rollback, b"# stable rollback\n")
        self.rollback_python = self.root / "rollback-python"
        write_private(self.rollback_python, b"#!/bin/sh\nexit 0\n")
        self.rollback_python.chmod(0o700)
        self.home_dns = "192.0.2.53"
        self.runner = FakeRunner()

    def tearDown(self):
        self.temporary.cleanup()

    def prepare(self, *, rollback_python=None, extra_module_path=None, split_tunnel=False):
        candidate_module = self.module if split_tunnel else self.candidate_module
        candidate_extra = self.extra if split_tunnel else self.candidate_extra
        with patch.object(publish, "_load_rollback", return_value=FakeRollback()):
            return publish.prepare(self.txn, candidate_module=candidate_module, candidate_extra=candidate_extra,
                                   candidate_module_hash=digest(candidate_module), candidate_extra_hash=digest(candidate_extra),
                                   baseline_module_hash=digest(self.module), baseline_config_hash=digest(self.config),
                                   module_path=self.module, extra_module_path=extra_module_path or self.extra, config_path=self.config,
                                   state_directory=self.state, agent_service="test-agent.service", control_socket_path=self.root / "control",
                                   rollback_python=rollback_python or self.rollback_python,
                                   home_dns=None if split_tunnel else self.home_dns, split_tunnel=split_tunnel,
                                   rollback_source=self.rollback,
                                   runner=self.runner, enforce_root=False)

    def journal(self):
        return json.loads((self.txn / "journal.json").read_text())

    def test_prepare_cas_mismatch_keeps_runtime_untouched(self):
        with self.assertRaisesRegex(publish.PublishError, "baseline_module_changed"):
            with patch.object(publish, "_load_rollback", return_value=FakeRollback()):
                publish.prepare(self.txn, candidate_module=self.candidate_module, candidate_extra=self.candidate_extra,
                                candidate_module_hash=digest(self.candidate_module), candidate_extra_hash=digest(self.candidate_extra),
                                baseline_module_hash="0" * 64, baseline_config_hash=digest(self.config),
                                module_path=self.module, extra_module_path=self.extra, config_path=self.config,
                                state_directory=self.state, agent_service="test-agent.service", control_socket_path=self.root / "control",
                                rollback_python=self.rollback_python, home_dns=self.home_dns, rollback_source=self.rollback,
                                runner=self.runner, enforce_root=False)
        self.assertEqual(self.module.read_bytes(), b"baseline_module = 1\n")
        self.assertFalse(self.extra.exists())

    def test_prepare_stages_secret_without_storing_it_in_journal(self):
        self.assertEqual(self.prepare(), "prepared")
        journal_text = (self.txn / "journal.json").read_text()
        self.assertNotIn("do-not-log", journal_text)
        staged = json.loads((self.txn / "candidate-gateway.json").read_text())
        self.assertEqual(staged["credential"], "do-not-log")
        self.assertEqual(staged["home_internet"], {"enabled": True, "routing_table": 150, "rule_priority": 18000,
                                                    "rule_protocol": 186, "dns": [self.home_dns]})
        self.assertEqual(oct((self.txn / "journal.json").stat().st_mode & 0o777), "0o600")

    def test_prepare_rejects_invalid_explicit_home_dns(self):
        self.home_dns = "not-an-ip-address"
        with self.assertRaisesRegex(publish.PublishError, "home_dns_invalid"):
            self.prepare()

    def test_rollback_python_rejects_systemd_unsafe_paths(self):
        for name in ("rollback python", "rollback\npython", "rollback%python", "rollback'python"):
            with self.subTest(name=name):
                path = self.root / name
                write_private(path, b"#!/bin/sh\nexit 0\n")
                path.chmod(0o700)
                with self.assertRaisesRegex(publish.PublishError, "rollback_python_invalid"):
                    publish._rollback_python(path, root_required=False)

    def test_rollback_python_requires_root_owner_when_requested(self):
        with patch.object(publish, "_regular") as regular:
            self.assertEqual(publish._rollback_python(self.rollback_python, root_required=True), self.rollback_python)
        regular.assert_called_once_with(self.rollback_python, root_required=True)

    def test_prepare_rejects_executable_non_python_rollback_program(self):
        non_python = self.root / "non-python"
        write_private(non_python, b"#!/bin/sh\nexit 0\n")
        non_python.chmod(0o700)
        self.runner.rollback_probe_stdout = "not-python\n"
        with self.assertRaisesRegex(publish.PublishError, "rollback_python_unusable"):
            self.prepare(rollback_python=non_python)
        self.assertEqual(self.module.read_bytes(), b"baseline_module = 1\n")
        self.assertFalse((self.txn / "candidate-gateway_agent.py").exists())

    def test_prepare_rejects_rollback_python_below_minimum_version(self):
        self.runner.rollback_probe_code = 1
        self.runner.rollback_probe_stdout = ""
        with self.assertRaisesRegex(publish.PublishError, "rollback_python_unusable"):
            self.prepare()
        self.assertEqual(self.module.read_bytes(), b"baseline_module = 1\n")
        self.assertFalse((self.txn / "candidate-gateway_agent.py").exists())

    def test_prepare_rejects_extra_module_outside_agent_package(self):
        with self.assertRaisesRegex(publish.PublishError, "extra_module_path_invalid"):
            self.prepare(extra_module_path=self.root / "other-package" / "home_egress.py")
        self.assertEqual(self.module.read_bytes(), b"baseline_module = 1\n")
        self.assertFalse((self.txn / "candidate-gateway_agent.py").exists())

    def test_arm_requires_timer_proof_and_restores_prepared_status(self):
        self.prepare()
        units = self.root / "units"; units.mkdir()
        with patch.object(publish, "_load_rollback", return_value=FakeRollback()), patch.object(publish, "_timer_proof", return_value=False):
            with self.assertRaisesRegex(publish.PublishError, "timer_not_active"):
                publish.arm(self.txn, systemd_directory=units, runner=self.runner, enforce_root=False)
        self.assertEqual(self.journal()["status"], "prepared")
        self.assertFalse(self.runner.timer_active)
        self.assertEqual(list(units.iterdir()), [])

    def test_accept_marks_journal_before_stopping_timer(self):
        self.prepare()
        journal = self.journal(); journal["status"] = "armed"
        write_private(self.txn / "journal.json", json.dumps(journal).encode())
        self.extra.write_bytes((self.txn / "candidate-home_egress.py").read_bytes()); self.extra.chmod(0o600)
        self.module.write_bytes((self.txn / "candidate-gateway_agent.py").read_bytes()); self.module.chmod(0o600)
        self.config.write_bytes((self.txn / "candidate-gateway.json").read_bytes()); self.config.chmod(0o600)
        with patch.object(publish, "_load_rollback", return_value=FakeRollback()):
            self.assertEqual(publish.accept(self.txn, runner=self.runner, enforce_root=False), "accepted")
        disable_index = next(i for i, value in enumerate(self.runner.calls) if value[:3] == ["/bin/systemctl", "disable", "--now"])
        self.assertEqual(self.journal()["status"], "accepted")
        self.assertGreater(disable_index, 0)

    def test_apply_refuses_changed_baseline_before_stopping_agent(self):
        self.prepare()
        journal = self.journal(); journal["status"] = "armed"
        write_private(self.txn / "journal.json", json.dumps(journal).encode())
        write_private(self.config, b'{"changed_elsewhere":true}')
        with patch.object(publish, "_load_rollback", return_value=FakeRollback()), patch.object(publish, "_timer_proof", return_value=True):
            with self.assertRaisesRegex(publish.PublishError, "compare_failed"):
                publish.apply(self.txn, runner=self.runner, enforce_root=False)
        self.assertFalse(any(call[:2] == ["/bin/systemctl", "stop"] for call in self.runner.calls))

    def test_accept_cannot_pass_rollback_transaction_lock(self):
        self.prepare()
        descriptor = os.open(self.txn / "rollback.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(publish.PublishError, "publish_locked"):
                publish.accept(self.txn, runner=self.runner, enforce_root=False)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def test_apply_rolls_back_after_agent_stop_when_agent_lock_is_busy(self):
        self.prepare()
        journal = self.journal(); journal["status"] = "armed"
        write_private(self.txn / "journal.json", json.dumps(journal).encode())
        held = os.open(self.state / "agent.lock", os.O_RDWR)
        rollback = FakeRollback(self.runner)
        try:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(publish, "_load_rollback", return_value=rollback), patch.object(publish, "_timer_proof", return_value=True):
                with self.assertRaises(publish.PublishError):
                    publish.apply(self.txn, runner=self.runner, enforce_root=False)
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
            os.close(held)
        self.assertEqual(rollback.rollback_calls, 1)
        self.assertEqual(rollback.events, ["ready", "block"])
        self.assertTrue(any(call[:2] == ["/bin/systemctl", "stop"] for call in self.runner.calls))

    def test_apply_keeps_block_until_candidate_is_ready_then_removes_it(self):
        self.prepare()
        journal = self.journal(); journal["status"] = "armed"
        write_private(self.txn / "journal.json", json.dumps(journal).encode())
        rollback = FakeRollback(self.runner)
        with patch.object(publish, "_load_rollback", return_value=rollback), patch.object(publish, "_timer_proof", return_value=True):
            self.assertEqual(publish.apply(self.txn, runner=self.runner, enforce_root=False), "applied")
        self.assertEqual(rollback.events, ["ready", "block", "ready", "unblock"])

    def test_split_apply_changes_only_the_gateway_configuration(self):
        config = json.loads(self.config.read_text())
        config["home_internet"] = {"enabled": True, "dns": ["192.0.2.53"], "routing_table": 151}
        write_private(self.config, json.dumps(config).encode())
        write_private(self.extra, b"baseline_egress = 1\n")
        source_digests = (digest(self.module), digest(self.extra))

        self.assertEqual(self.prepare(split_tunnel=True), "prepared")
        journal = self.journal()
        self.assertEqual(journal["routing"]["table"], 151)
        self.assertEqual(journal["split_config"], "staged")
        self.assertTrue(json.loads(self.config.read_text())["home_internet"]["enabled"])
        journal["status"] = "armed"
        write_private(self.txn / "journal.json", json.dumps(journal).encode())
        rollback = FakeRollback(self.runner)
        with patch.object(publish, "_load_rollback", return_value=rollback), patch.object(publish, "_timer_proof", return_value=True):
            self.assertEqual(publish.apply(self.txn, runner=self.runner, enforce_root=False), "applied")

        config["home_internet"]["enabled"] = False
        self.assertEqual(json.loads(self.config.read_text()), config)
        self.assertEqual((digest(self.module), digest(self.extra)), source_digests)
        self.assertEqual(self.journal()["split_config"], "applying")
        self.assertEqual(rollback.events, ["ready", "block", "ready", "unblock"])

    def test_apply_refuses_stale_baseline_before_block_or_stop(self):
        self.prepare()
        journal = self.journal(); journal["status"] = "armed"
        write_private(self.txn / "journal.json", json.dumps(journal).encode())
        rollback = FakeRollback(); rollback.ready = False
        with patch.object(publish, "_load_rollback", return_value=rollback), patch.object(publish, "_timer_proof", return_value=True):
            with self.assertRaisesRegex(publish.PublishError, "baseline_not_ready"):
                publish.apply(self.txn, runner=self.runner, enforce_root=False)
        self.assertEqual(rollback.events, ["ready"])
        self.assertFalse(any(call[:2] == ["/bin/systemctl", "stop"] for call in self.runner.calls))

    def test_apply_rejects_wrong_service_when_control_socket_stays_ready(self):
        self.prepare()
        journal = self.journal(); journal["status"] = "armed"; journal["agent_service"] = "wrong.service"
        write_private(self.txn / "journal.json", json.dumps(journal).encode())
        rollback = FakeRollback(self.runner)
        with patch.object(publish, "_load_rollback", return_value=rollback), patch.object(publish, "_timer_proof", return_value=True):
            with self.assertRaisesRegex(publish.PublishError, "control_socket_still_ready"):
                publish.apply(self.txn, runner=self.runner, enforce_root=False)
        self.assertEqual(rollback.rollback_calls, 1)
        self.assertEqual(rollback.events, ["ready", "block"])
        self.assertEqual(self.module.read_bytes(), b"baseline_module = 1\n")
        self.assertFalse(self.extra.exists())

    def test_arm_resumes_after_journal_was_armed_before_enable(self):
        self.prepare()
        units = self.root / "units"; units.mkdir()
        service, timer = publish._unit_names(self.txn)
        service_content, timer_content = publish._unit_contents(self.txn, self.rollback_python)
        (units / service).write_bytes(service_content); (units / service).chmod(0o644)
        (units / timer).write_bytes(timer_content); (units / timer).chmod(0o644)
        journal = self.journal(); journal["status"] = "armed"
        write_private(self.txn / "journal.json", json.dumps(journal).encode())
        self.runner.contents[service] = service_content.decode()
        self.runner.contents[timer] = timer_content.decode()
        with patch.object(publish, "_load_rollback", return_value=FakeRollback()):
            self.assertEqual(publish.arm(self.txn, systemd_directory=units, runner=self.runner, enforce_root=False), "armed")
        self.assertTrue(self.runner.timer_active)

    def test_unit_path_rejects_systemd_unsafe_characters(self):
        with self.assertRaisesRegex(publish.PublishError, "txn_name_invalid"):
            publish._unit_names(Path("/tmp/home egress/txn"))

    def test_accepted_retries_timer_stop_after_prior_failure(self):
        self.prepare()
        journal = self.journal(); journal["status"] = "armed"
        write_private(self.txn / "journal.json", json.dumps(journal).encode())
        self.extra.write_bytes((self.txn / "candidate-home_egress.py").read_bytes()); self.extra.chmod(0o600)
        self.module.write_bytes((self.txn / "candidate-gateway_agent.py").read_bytes()); self.module.chmod(0o600)
        self.config.write_bytes((self.txn / "candidate-gateway.json").read_bytes()); self.config.chmod(0o600)
        self.runner.fail_disable = True
        with patch.object(publish, "_load_rollback", return_value=FakeRollback()):
            with self.assertRaisesRegex(publish.PublishError, "timer_stop_failed"):
                publish.accept(self.txn, runner=self.runner, enforce_root=False)
            self.assertEqual(self.journal()["status"], "accepted")
            self.runner.fail_disable = False
            self.assertEqual(publish.accept(self.txn, runner=self.runner, enforce_root=False), "accepted")
        stops = [call for call in self.runner.calls if call[:3] == ["/bin/systemctl", "disable", "--now"]]
        self.assertEqual(len(stops), 2)


if __name__ == "__main__":
    unittest.main()
