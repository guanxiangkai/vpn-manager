from __future__ import annotations

import json
import socket
import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vpn_manager.bootstrap import bootstrap
from vpn_manager.gateway_sync import GatewayClient, GatewayUnavailable, open_credential, seal_credential
from vpn_manager import gateway_sync, runtime
from vpn_manager.store import Store


def test_watch_retries_pending_without_replaying_failed_jobs(monkeypatch):
    calls = []
    monkeypatch.setattr(gateway_sync.sys, "argv", ["sync", "--database", "db", "--socket", "/run/agent", "--watch"])
    monkeypatch.setattr(gateway_sync, "run_once", lambda *args, **kwargs: calls.append((args, kwargs)) or 1)

    def sleep(interval):
        assert interval == 5
        if len(calls) == 2:
            raise KeyboardInterrupt()

    monkeypatch.setattr(gateway_sync.time, "sleep", sleep)
    with pytest.raises(KeyboardInterrupt):
        gateway_sync.main()
    assert calls == [(("db", "/run/agent"), {}), (("db", "/run/agent"), {})]


@pytest.mark.parametrize("extra", [["--retry-failed"], ["--interval", "0"], ["--interval", "301"]])
def test_watch_rejects_unsafe_retry_or_unbounded_frequency(monkeypatch, extra):
    monkeypatch.setattr(gateway_sync.sys, "argv", ["sync", "--database", "db", "--socket", "/run/agent", "--watch", *extra])
    monkeypatch.setattr(gateway_sync, "run_once", lambda *args, **kwargs: pytest.fail("不应开始同步"))
    with pytest.raises(SystemExit) as error:
        gateway_sync.main()
    assert error.value.code == 2


def key_pair():
    private = X25519PrivateKey.generate()
    return (
        private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
    )


def test_credential_envelope_binds_recipient_account_and_generation():
    private, public = key_pair()
    envelope = seal_credential(public, "member", 7, "correct-horse-member")
    assert open_credential(private, envelope, "member", 7) == "correct-horse-member"
    assert "correct-horse-member" not in json.dumps(envelope)
    with pytest.raises(ValueError, match="^无效的凭据封装$"):
        open_credential(private, envelope, "member", 8)
    with pytest.raises(ValueError, match="^无效的凭据封装$"):
        open_credential(private, envelope, "adminone", 7)
    with pytest.raises(ValueError):
        open_credential(private, {**envelope, "unexpected": True}, "member", 7)


def test_bootstrap_with_gateway_key_queues_encrypted_initial_projection(tmp_path):
    _, public = key_pair()
    database = tmp_path / "manager.sqlite3"
    bootstrap(str(database), [{"username": "adminone", "password": "correct-horse-admin-one", "role": "admin", "networks": ["home"]}], public)
    job = Store(database).pending_gateway_jobs()[0]
    assert job["generation"] == 1 and job["credential_envelope"]["version"] == 1
    assert "correct-horse-admin-one" not in json.dumps(job)


def test_outbox_generation_supersedes_stale_ack_without_losing_current_state(tmp_path):
    database = tmp_path / "manager.sqlite3"
    bootstrap(str(database), [{"username": "adminone", "password": "correct-horse-admin-one", "role": "admin", "networks": ["home"]}])
    store = Store(database)
    with store.write_transaction() as connection:
        first_generation = store.next_gateway_generation(connection, "adminone")
        first = store.queue_gateway_change(connection, "adminone", first_generation, True, ["home"], {"version": 1})
    with store.write_transaction() as connection:
        second_generation = store.next_gateway_generation(connection, "adminone")
        second = store.queue_gateway_change(connection, "adminone", second_generation, False, [], None)
    store.record_gateway_reply(first, "adminone", first_generation, "applied", None)
    assert store.gateway_status("adminone")["generation"] == second_generation
    assert store.gateway_status("adminone")["state"] == "queued"
    jobs = {job["operation_id"]: job for job in store.pending_gateway_jobs()}
    assert second in jobs and first not in jobs


def test_network_reduction_and_deactivation_follow_initial_credential_and_clear_it_after_ack(tmp_path):
    private, public = key_pair()
    database = tmp_path / "manager.sqlite3"
    bootstrap(str(database), [{"username": "adminone", "password": "correct-horse-admin-one", "role": "admin", "networks": ["home", "work"]}], public)
    store = Store(database)
    initial = store.pending_gateway_jobs()[0]
    with store.write_transaction() as connection:
        downgrade = store.queue_gateway_change(connection, "adminone", store.next_gateway_generation(connection, "adminone"), True, ["work"], None)
    # 新策略不能把 generation=1 的密码信封复制到 generation=2；必须等待初始投影确认。
    assert [job["operation_id"] for job in store.pending_gateway_jobs()] == [initial["operation_id"]]
    store.record_gateway_reply(initial["operation_id"], "adminone", 1, "applied", None)
    with store.connect() as connection:
        assert connection.execute("SELECT credential_envelope FROM gateway_outbox WHERE operation_id=?", (initial["operation_id"],)).fetchone()[0] is None
    pending = store.pending_gateway_jobs()[0]
    assert pending["operation_id"] == downgrade and pending["networks"] == ["work"]
    store.record_gateway_reply(downgrade, "adminone", 2, "applied", None)
    with store.write_transaction() as connection:
        deactivate = store.queue_gateway_change(connection, "adminone", store.next_gateway_generation(connection, "adminone"), False, [], None)
    pending = store.pending_gateway_jobs()[0]
    assert pending["operation_id"] == deactivate and pending["active"] is False and pending["networks"] == []


def test_expired_ack_for_superseded_operation_cannot_overwrite_newer_generation(tmp_path):
    database = tmp_path / "manager.sqlite3"
    bootstrap(str(database), [{"username": "adminone", "password": "correct-horse-admin-one", "role": "admin", "networks": ["home"]}])
    store = Store(database)
    with store.write_transaction() as connection:
        old = store.queue_gateway_change(connection, "adminone", 1, True, ["home"], None)
    with store.write_transaction() as connection:
        new = store.queue_gateway_change(connection, "adminone", 2, False, [], {"version": 1})
    store.record_gateway_reply(old, "adminone", 1, "applied", None)
    assert store.gateway_status("adminone")["generation"] == 2
    assert store.gateway_status("adminone")["state"] == "queued"
    assert store.pending_gateway_jobs()[0]["operation_id"] == new


def test_pending_reply_retains_envelope_and_explicit_retry_reuses_same_generation(tmp_path, monkeypatch):
    _, public = key_pair()
    database = tmp_path / "manager.sqlite3"
    bootstrap(str(database), [{"username": "adminone", "password": "correct-horse-admin-one", "role": "admin", "networks": ["home"]}], public)
    store = Store(database)
    job = store.pending_gateway_jobs()[0]
    store.record_gateway_reply(job["operation_id"], "adminone", 1, "pending", "infrastructure_unavailable")
    with store.connect() as connection:
        assert connection.execute("SELECT credential_envelope FROM gateway_outbox WHERE operation_id=?", (job["operation_id"],)).fetchone()[0] is not None
    store.record_gateway_reply(job["operation_id"], "adminone", 1, "failed", "invalid_projection")
    with store.write_transaction() as connection:
        newer = store.queue_gateway_change(connection, "adminone", 2, True, ["home", "work"], None)
    calls = []

    class Client:
        def __init__(self, _socket_path):
            pass

        def apply_account(self, operation_id, username, generation, active, networks, credential_envelope):
            calls.append((operation_id, username, generation, active, networks, credential_envelope))
            return {"operation_id": operation_id, "username": username, "generation": generation, "state": "applied"}

    monkeypatch.setattr(gateway_sync, "GatewayClient", Client)
    assert gateway_sync.run_once(str(database), "/run/vpn-manager.sock") == 0
    assert calls == []
    assert gateway_sync.run_once(str(database), "/run/vpn-manager.sock", retry_failed=True) == 0
    assert calls == [(job["operation_id"], "adminone", 1, True, ["home"], job["credential_envelope"])]
    assert gateway_sync.run_once(str(database), "/run/vpn-manager.sock") == 0
    assert calls[-1][:5] == (newer, "adminone", 2, True, ["home", "work"])
    with store.connect() as connection:
        assert connection.execute("SELECT credential_envelope FROM gateway_outbox WHERE operation_id=?", (job["operation_id"],)).fetchone()[0] is None
    assert store.gateway_status("adminone")["state"] == "applied"


def test_runtime_gateway_configuration_requires_pair_and_loads_safe_x25519_key(tmp_path, monkeypatch):
    _, public = key_pair()
    database, public_key = tmp_path / "manager.sqlite3", tmp_path / "gateway-public.pem"
    Store(database).initialize()
    public_key.write_bytes(public)
    public_key.chmod(0o600)
    base = {"VPN_MANAGER_DB": str(database), "VPN_MANAGER_WEB_DIRECTORY": str(tmp_path), "VPN_MANAGER_ORIGIN": "https://slimjoy.cn"}
    for name, value in base.items():
        monkeypatch.setenv(name, value)
    captured = {}
    sentinel = object()
    monkeypatch.setattr(runtime, "create_app", lambda database, **kwargs: captured.update(database=database, **kwargs) or sentinel)
    monkeypatch.setenv("VPN_MANAGER_GATEWAY_PUBLIC_KEY", str(public_key))
    monkeypatch.setenv("VPN_MANAGER_GATEWAY_SOCKET", "/run/vpn-manager/gateway.sock")
    assert runtime.application() is sentinel
    assert captured["gateway_public_key"] == public and captured["gateway_client"].socket_path == "/run/vpn-manager/gateway.sock"
    monkeypatch.delenv("VPN_MANAGER_GATEWAY_SOCKET")
    with pytest.raises(RuntimeError, match="必须同时配置"):
        runtime.application()
    monkeypatch.setenv("VPN_MANAGER_GATEWAY_SOCKET", "relative.sock")
    with pytest.raises(RuntimeError, match="绝对路径"):
        runtime.application()


def test_gateway_client_rejects_malformed_or_oversized_reply(tmp_path):
    path = str(tmp_path / "gateway.sock")
    ready = threading.Event()

    def server():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(path)
            listener.listen(1)
            ready.set()
            peer, _ = listener.accept()
            with peer:
                peer.recv(16384)
                peer.sendall(b"{" + b"x" * (16 * 1024) + b"}\n")

    worker = threading.Thread(target=server)
    worker.start()
    try:
        assert ready.wait(2)
        with pytest.raises(GatewayUnavailable):
            GatewayClient(path).status("adminone")
    finally:
        worker.join(timeout=2)


def test_gateway_client_uses_frozen_json_line_apply_contract(tmp_path):
    _, public = key_pair()
    path, ready, seen = str(tmp_path / "gateway.sock"), threading.Event(), {}
    operation_id = "a" * 32

    def server():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(path)
            listener.listen(1)
            ready.set()
            peer, _ = listener.accept()
            with peer:
                seen.update(json.loads(peer.recv(16384).split(b"\n", 1)[0]))
                peer.sendall(json.dumps({"operation_id": operation_id, "username": "adminone", "generation": 1, "state": "pending", "code": "accepted"}).encode() + b"\n")

    worker = threading.Thread(target=server)
    worker.start()
    try:
        assert ready.wait(2)
        envelope = seal_credential(public, "adminone", 1, "correct-horse-admin-one")
        assert GatewayClient(path).apply_account(operation_id, "adminone", 1, True, ["home"], envelope)["state"] == "pending"
        assert seen == {"action": "apply_account", "operation_id": operation_id, "username": "adminone", "generation": 1, "active": True, "networks": ["home"], "credential_envelope": envelope}
    finally:
        worker.join(timeout=2)
