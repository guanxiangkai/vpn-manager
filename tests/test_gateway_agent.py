"""Linux 网关代理的隔离状态机单元测试；不调用真实 VICI、nft 或 OpenSSL。"""
from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vpn_manager import gateway_agent


class RecordingDriver:
    """记录 VICI 边界调用，必要时模拟加载失败。"""

    def __init__(self, events: list[tuple], *, fail_load: bool = False) -> None:
        self.events, self.fail_load = events, fail_load

    def forget(self, username: str) -> None:
        self.events.append(("unload", username))

    def terminate(self, username: str) -> None:
        self.events.append(("terminate", username))

    def load(self, username: str, account: dict) -> None:
        self.events.append(("load", username, tuple(account["networks"])))
        if self.fail_load:
            raise gateway_agent.ProjectionError("fixture_load_failure")


class RecordingFirewall:
    """记录隔离集合；真实防火墙规则由 Linux 集成验收覆盖。"""

    def __init__(self, events: list[tuple]) -> None:
        self.events = events

    def install(self, _accounts: dict, quarantined: set[str]) -> None:
        self.events.append(("isolate", tuple(sorted(quarantined))))


def request(*, operation_id: str = "a" * 32, generation: int = 1, active: bool = True,
            networks: list[str] | None = None, credential_envelope: dict | None = None) -> dict:
    return {
        "action": "apply_account",
        "operation_id": operation_id,
        "username": "adminone",
        "generation": generation,
        "active": active,
        "networks": ["home"] if networks is None else networks,
        "credential_envelope": {"fixture": True} if credential_envelope is None and active and generation == 1 else credential_envelope,
    }


@pytest.fixture
def agent(tmp_path, monkeypatch):
    """创建受控私钥与纯替身依赖，避免测试运行系统命令。"""
    private = X25519PrivateKey.generate()
    key_path = Path(tmp_path) / "credential-key.pem"
    key_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    events: list[tuple] = []
    driver = RecordingDriver(events)
    firewall = RecordingFirewall(events)
    monkeypatch.setattr(gateway_agent, "open_credential", lambda *_args: "fixture-password")
    monkeypatch.setattr(gateway_agent, "nt_credential", lambda _password: "00" * 16)
    return gateway_agent.GatewayAgent(Path(tmp_path), driver, firewall), driver, events


@pytest.mark.parametrize("payload", [
    {"action": "status", "username": "AdminOne"},
    {"action": "status", "username": "adminone", "unexpected": True},
    {"action": "apply_account", "operation_id": "a" * 32, "username": "adminone", "generation": True,
     "active": True, "networks": ["home"], "credential_envelope": None},
    {"action": "apply_account", "operation_id": "a" * 32, "username": "adminone", "generation": 1,
     "active": True, "networks": [], "credential_envelope": None},
])
def test_gateway_agent_rejects_malformed_requests(payload):
    """协议入口拒绝伪造用户名、额外字段、布尔版本和空活动权限。"""
    with pytest.raises(gateway_agent.ProjectionError, match="invalid_request"):
        gateway_agent.check_request(payload)


def test_certificate_reload_preserves_sessions_and_excludes_inactive_accounts(agent):
    """续期不会撤销 SA、修改防火墙或恢复停用账户。"""
    gateway, _driver, events = agent
    gateway.apply(request())
    gateway.state["accounts"]["disabled"] = {"active": False, "state": "applied"}
    gateway.state["accounts"]["pending"] = {"active": True, "state": "pending"}
    events.clear()
    assert gateway.apply({"action": "reload_certificate"}) == {"state": "certificate_reloaded", "accounts": 1}
    assert events == [("load", "adminone", ("home",))]


@pytest.mark.parametrize("extra", [{"username": "adminone"}, {"certificate": "/tmp/foreign.pem"}])
def test_certificate_reload_cannot_select_identity_or_certificate(extra):
    """控制端无法通过续期接口指定其他证书或任意身份。"""
    with pytest.raises(gateway_agent.ProjectionError, match="invalid_request"):
        gateway_agent.check_request({"action": "reload_certificate", **extra})


def test_same_generation_is_idempotent_and_conflicting_payload_is_rejected(agent):
    """相同 operation 的已应用重投不触发系统操作；同版本不同内容拒绝。"""
    gateway, _driver, events = agent
    initial = request()
    assert gateway.apply(initial)["state"] == "applied"
    completed_events = list(events)
    assert gateway.apply(initial)["state"] == "applied"
    assert events == completed_events
    with pytest.raises(gateway_agent.ProjectionError, match="generation_conflict"):
        gateway.apply(request(operation_id="b" * 32, networks=["work"]))


def test_downgrade_isolates_before_unload_and_terminates_before_release(agent):
    """权限减少时先隔离，再卸载和踢掉 SA，成功读取新策略后才解除隔离。"""
    gateway, _driver, events = agent
    gateway.apply(request())
    events.clear()
    reply = gateway.apply(request(operation_id="b" * 32, generation=2, networks=["work"], credential_envelope=None))
    assert reply["state"] == "applied"
    assert events == [
        ("isolate", ("adminone",)),
        ("unload", "adminone"),
        ("terminate", "adminone"),
        ("load", "adminone", ("work",)),
        ("isolate", ()),
    ]


def test_projection_failure_stays_isolated_pending_and_same_request_retries(agent):
    """基础设施失败不伪装 applied；相同 generation/operation 可重试。"""
    gateway, driver, events = agent
    driver.fail_load = True
    initial = request()
    reply = gateway.apply(initial)
    assert reply["state"] == "pending"
    assert reply["code"] == "projection_load"
    assert all(event != ("isolate", ()) for event in events)
    assert events[:4] == [
        ("isolate", ("adminone",)),
        ("unload", "adminone"),
        ("terminate", "adminone"),
        ("load", "adminone", ("home",)),
    ]
    driver.fail_load = False
    events.clear()
    assert gateway.apply(initial)["state"] == "applied"
    assert events == [
        ("isolate", ("adminone",)),
        ("unload", "adminone"),
        ("terminate", "adminone"),
        ("load", "adminone", ("home",)),
        ("isolate", ()),
    ]
