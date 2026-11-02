"""验证续期证书的 IP、期限、用途和私钥边界。"""
from datetime import datetime, timedelta, timezone
import importlib.util
from ipaddress import ip_address
import os
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

spec = importlib.util.spec_from_file_location("deploy_web_certificate", Path(__file__).parents[1] / "scripts/deploy_web_certificate.py")
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)


def certificate(*, address="203.0.113.10", remaining_hours=100, before_hours=-1, server=True):
    """创建隔离测试证书；不使用任何真实服务密钥。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "certificate-test")])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now + timedelta(hours=before_hours))
               .not_valid_after(now + timedelta(hours=remaining_hours))
               .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address(address))]), critical=False)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
    pem = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pem, private


def test_valid_certificate_metadata():
    deployment.validate(*certificate(), "203.0.113.10")


@pytest.mark.parametrize("options", [
    {"address": "203.0.113.11"},
    {"remaining_hours": 1},
    {"remaining_hours": 47},
    {"before_hours": 1},
    {"server": False},
])
def test_rejects_wrong_endpoint_expiry_or_purpose(options):
    with pytest.raises(ValueError):
        deployment.validate(*certificate(**options), "203.0.113.10")


def test_rejects_wrong_private_key():
    pem, _ = certificate()
    _, other_key = certificate()
    with pytest.raises(ValueError, match="不匹配"):
        deployment.validate(pem, other_key, "203.0.113.10")


def test_refuses_symlink_target(tmp_path):
    target = tmp_path / "other"
    target.write_text("original")
    link = tmp_path / "web-api-key.pem"
    link.symlink_to(target)
    with pytest.raises(RuntimeError):
        deployment._atomic_write(link, b"replacement")
    assert target.read_text() == "original"


@pytest.fixture
def certbot_layout(tmp_path, monkeypatch):
    """隔离模拟 live 目录和文件链接；所有文件均为测试生成的证书。"""
    base = tmp_path / "letsencrypt"
    archive = base / "archive" / "endpoint"
    archive.mkdir(parents=True)
    live = base / "live"
    live.mkdir()
    source = live / "endpoint"
    source.symlink_to(archive, target_is_directory=True)
    pem, private = certificate()
    chain, _ = certificate()
    for name, data in {"cert.pem": pem, "chain.pem": chain, "fullchain.pem": pem + chain, "privkey.pem": private}.items():
        target = archive / ("version1-" + name)
        target.write_bytes(data)
        target.chmod(0o600)
        (archive / name).symlink_to(target.name)
    destination = tmp_path / "destination"
    destination.mkdir()
    monkeypatch.setattr(deployment, "CERTBOT_ROOT", base)
    monkeypatch.setattr(deployment, "ROOT_UID", os.getuid())
    # 本机测试目录的祖先为共享临时目录；生产检查不能因此放宽。
    monkeypatch.setattr(deployment, "_secure_directory", lambda path: None)
    monkeypatch.setattr(deployment, "_active", lambda: False)
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        assert command[:3] == ["/usr/bin/openssl", "verify", "-purpose"]
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(deployment.subprocess, "run", run)
    return source, destination, pem + chain, private, calls


def test_deploys_linked_certbot_layout_without_starting_inactive_service(certbot_layout, monkeypatch):
    source, destination, pem, private, commands = certbot_layout
    def unexpected_restart(*args):
        pytest.fail("首次放置证书不应自动启动服务")
    monkeypatch.setattr(deployment, "_restart_and_wait", unexpected_restart)
    deployment._deploy(source, "203.0.113.10", "192.168.1.2", 8443, destination=destination)
    assert (destination / "web-api-fullchain.pem").read_bytes() == pem
    assert (destination / "web-api-key.pem").read_bytes() == private
    assert (destination / "web-api-key.pem").stat().st_mode & 0o777 == 0o600
    assert commands[0][3:7] == ["sslserver", "-verify_ip", "203.0.113.10", "-untrusted"]


def test_rejects_source_links_outside_certbot_root(certbot_layout, tmp_path):
    source, *_ = certbot_layout
    outside = tmp_path / "external-key.pem"
    outside.write_text("must not be read")
    key = source.resolve() / "privkey.pem"
    key.unlink()
    key.symlink_to(outside)
    with pytest.raises(RuntimeError, match="超出"):
        deployment._source_files(source)


def test_rejects_unverified_fullchain_before_writing(certbot_layout):
    source, destination, *_ = certbot_layout
    (source / "chain.pem").resolve().write_bytes(certificate()[0])
    with pytest.raises(ValueError, match="不一致"):
        deployment._deploy(source, "203.0.113.10", "192.168.1.2", 8443, destination=destination)
    assert not list(destination.iterdir())


@pytest.mark.parametrize("recovery_fails", [False, True])
def test_restores_old_files_and_reports_recovery_health(certbot_layout, monkeypatch, recovery_fails):
    source, destination, *_ = certbot_layout
    old = {"web-api-fullchain.pem": b"old-cert", "web-api-key.pem": b"old-key"}
    for name, content in old.items():
        (destination / name).write_bytes(content)
        (destination / name).chmod(0o600)
    monkeypatch.setattr(deployment, "_active", lambda: True)
    calls = []
    def restart(*args):
        calls.append(args)
        if len(calls) == 1:
            raise RuntimeError("new service health failed")
        assert all((destination / name).read_bytes() == content for name, content in old.items())
        if recovery_fails:
            raise RuntimeError("restored service health failed")
    monkeypatch.setattr(deployment, "_restart_and_wait", restart)
    message = "未能恢复" if recovery_fails else "已恢复"
    with pytest.raises(RuntimeError, match=message):
        deployment._deploy(source, "203.0.113.10", "192.168.1.2", 8443, destination=destination)
    assert len(calls) == 2
    assert all((destination / name).read_bytes() == content for name, content in old.items())


def test_restart_waits_for_trusted_https_health(monkeypatch):
    commands, probes = [], []
    monkeypatch.setattr(deployment.subprocess, "run", lambda command, **kwargs: commands.append(command))
    monkeypatch.setattr(deployment, "_active", lambda: True)
    monkeypatch.setattr(deployment.time, "sleep", lambda seconds: None)
    def probe(*args):
        probes.append(args)
        if len(probes) == 1:
            raise OSError("server not ready")
    monkeypatch.setattr(deployment, "_health", probe)
    deployment._restart_and_wait("192.168.1.2", 8443, "203.0.113.10")
    assert commands == [["/usr/bin/systemctl", "restart", deployment.WEB_UNIT]]
    assert len(probes) == 2
