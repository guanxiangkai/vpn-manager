from pathlib import Path
import importlib.util
import socket
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("renew_web_certificate", ROOT / "scripts/renew_web_certificate.py")
renew = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(renew)


def test_certbot_command_is_named_and_not_global(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(renew.subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs)) or SimpleNamespace())
    renew._run_certbot("vpn-manager-web-ip", "8.159.154.136", tmp_path)
    command, kwargs = calls[0]
    assert command[:2] == [renew.CERTBOT, "renew"]
    assert "--cert-name" in command and "vpn-manager-web-ip" in command
    assert "--authenticator" in command and "standalone" in command
    assert "--http-01-port" in command and "80" in command
    assert "--no-directory-hooks" in command
    assert "--ip-address" not in command
    assert "--all" not in command
    assert kwargs["check"] is True and kwargs.get("shell") is not True


def test_certbot_uses_installed_executable_and_exact_probe_address(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(renew.subprocess, "run", lambda command, **kwargs: calls.append(command) or SimpleNamespace())
    renew._run_certbot("vpn-manager-web-ip", "8.159.154.136", tmp_path,
                      bind="192.168.0.169", certbot="/opt/vpn-manager/certbot-venv/bin/certbot")
    command = calls[0]
    assert command[0] == "/opt/vpn-manager/certbot-venv/bin/certbot"
    assert command[command.index("--http-01-address") + 1] == "192.168.0.169"


def test_certbot_dry_run_does_not_deploy(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(renew.subprocess, "run", lambda command, **kwargs: calls.append(command) or SimpleNamespace())
    renew._run_certbot("vpn-manager-web-ip", "8.159.154.136", tmp_path, dry_run=True)
    assert "--dry-run" in calls[0]


def test_service_stopping_after_certbot_waits_for_lock_and_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(renew.deployment, "ROOT_UID", __import__("os").geteuid())
    monkeypatch.setattr(renew.deployment, "_secure_directory", lambda path: None)
    monkeypatch.setattr(renew.deployment, "_active", lambda: False)
    monkeypatch.setattr(renew.deployment, "_deploy", lambda *args, **kwargs: pytest.fail("stopped Web must not be written"))
    with pytest.raises(RuntimeError, match="不会自动启动"):
        renew.deployment.deploy_with_lock(tmp_path, "8.159.154.136", "127.0.0.1", 8443, destination=tmp_path, require_active=True)


def test_port_conflict_fails_without_stopping_service(monkeypatch):
    class Occupied:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def setsockopt(self, *args):
            pass
        def bind(self, address):
            raise OSError("occupied")

    monkeypatch.setattr(renew.socket, "socket", lambda *args: Occupied())
    with pytest.raises(RuntimeError, match="已被占用"):
        renew._assert_port_free("0.0.0.0", 80)


def test_service_and_timer_are_independent_and_twice_daily():
    service = (ROOT / "deploy/vpn-manager-web-certificate-renew.service").read_text()
    timer = (ROOT / "deploy/vpn-manager-web-certificate-renew.timer").read_text()
    assert "certbot renew" not in service
    assert "vpn-manager-web-certificate-renew.service" in timer
    assert "00,12:17:00" in timer
    assert "PUBLIC_IP" in service
    assert "PRIVATE_IP" in service and "--bind 0.0.0.0" not in service
    assert "/opt/vpn-manager/certbot-venv/bin/certbot" in service
