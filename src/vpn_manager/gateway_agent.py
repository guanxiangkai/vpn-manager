"""仅供 Linux root 运行的 IKEv2 账户投影；管理服务不能直接控制系统网络。"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import stat
import struct
import subprocess
import tempfile
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .gateway_sync import MAX_MESSAGE_BYTES, open_credential
from .home_egress import HomeEgressRouter, NON_PUBLIC_V4, home_enabled


class ProjectionError(Exception):
    """只传播固定错误码，不传播密码、NT 凭据、VICI 数据或系统命令输出。"""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def private_file(path: Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ProjectionError("unsafe_private_file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino):
            raise ProjectionError("private_file_changed")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            value = stream.read(4 * 1024 * 1024 + 1)
        if len(value) > 4 * 1024 * 1024:
            raise ProjectionError("private_file_too_large")
        return value
    finally:
        os.close(descriptor)


def private_directory(path: Path) -> None:
    info = path.lstat()
    if (not path.is_absolute() or not stat.S_ISDIR(info.st_mode)
            or info.st_mode & 0o077 or info.st_uid != os.geteuid()):
        raise ProjectionError("unsafe_state_directory")


def atomic_private(path: Path, value: bytes) -> None:
    """同目录 fsync + rename，崩溃时保留完整的前值或新值。"""
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".new", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def nt_credential(password: str) -> str:
    # EAP-MSCHAPv2 需要 NT 凭据；明文只经匿名管道传给系统 OpenSSL。
    result = subprocess.run(["/usr/bin/openssl", "dgst", "-md4", "-provider", "legacy", "-binary"],
                            input=password.encode("utf-16-le"), capture_output=True, timeout=3)
    if result.returncode or len(result.stdout) != 16:
        raise ProjectionError("nt_credential_failed")
    return result.stdout.hex()


def check_request(request: object) -> dict[str, Any]:
    if not isinstance(request, dict) or request.get("action") not in {"status", "apply_account", "reload_certificate"}:
        raise ProjectionError("invalid_request")
    if request["action"] == "reload_certificate":
        if set(request) != {"action"}:
            raise ProjectionError("invalid_request")
        return request
    username = request.get("username")
    if not isinstance(username, str) or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", username) is None:
        raise ProjectionError("invalid_request")
    if request["action"] == "status":
        if set(request) != {"action", "username"}:
            raise ProjectionError("invalid_request")
        return request
    if set(request) != {"action", "operation_id", "username", "generation", "active", "networks", "credential_envelope"}:
        raise ProjectionError("invalid_request")
    if not isinstance(request["operation_id"], str) or re.fullmatch(r"[0-9a-f]{32}", request["operation_id"]) is None:
        raise ProjectionError("invalid_request")
    generation = request["generation"]
    if type(generation) is not int or not 1 <= generation < 2**53 or type(request["active"]) is not bool:
        raise ProjectionError("invalid_request")
    networks = request["networks"]
    if (not isinstance(networks, list) or any(n not in ("home", "work") for n in networks)
            or len(networks) != len(set(networks)) or (request["active"] and not networks)):
        raise ProjectionError("invalid_request")
    if request["credential_envelope"] is not None and not isinstance(request["credential_envelope"], dict):
        raise ProjectionError("invalid_request")
    return request


class ViciDriver:
    """只操作独立 charon socket；凭据用 VICI 原始二进制传递。"""

    def __init__(self, settings: dict[str, Any]) -> None:
        self.settings = settings

    @contextlib.contextmanager
    def session(self):
        import vici
        socket_path = Path(self.settings["vici_socket"])
        info = socket_path.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o007 or str(socket_path.resolve()) in {"/run/charon.vici", "/var/run/charon.vici"}):
            raise ProjectionError("unsafe_vici_socket")
        peer = socket.socket(socket.AF_UNIX)
        peer.settimeout(3)
        try:
            peer.connect(self.settings["vici_socket"])
            yield vici.Session(peer)
        except Exception as error:
            raise ProjectionError("vici_unavailable") from error
        finally:
            peer.close()

    @staticmethod
    def name(username: str) -> str:
        return "account-" + username

    def forget(self, username: str) -> None:
        name = self.name(username)
        with self.session() as session:
            connections = session.get_conns().get("conns", [])
            if name.encode() in connections:
                session.unload_conn({"name": name})
            keys = session.get_shared().get("keys", [])
            if name.encode() in keys:
                session.unload_shared({"id": name})

    def terminate(self, username: str) -> None:
        name = self.name(username)
        with self.session() as session:
            # 清除账户全部 IKE SA；不触碰旧证书连接或其他账户。
            sas = list(session.list_sas({"ike": name}))
            for item in sas:
                for key, value in item.items():
                    if key != name:
                        continue
                    list(session.terminate({"ike-id": value["uniqueid"], "timeout": "1500", "force": "yes"}))
            if any(name in item for item in session.list_sas({"ike": name})):
                raise ProjectionError("account_sa_remains")

    def load(self, username: str, account: dict[str, Any]) -> None:
        name = self.name(username)
        local_ts = [self.settings["management_ip"] + "/32"]
        if home_enabled(self.settings, account):
            local_ts = ["0.0.0.0/0"]
        else:
            for network in account["networks"]:
                local_ts.extend(self.settings["networks"][network]["selectors"])
        # 每个用户只能匹配其已验证 EAP 身份，不能按可伪造的 IKE ID 分配权限。
        connection = {
            "version": "2", "local_addrs": [self.settings["local_address"]],
            "remote_addrs": ["%any"], "pools": [name], "unique": "never",
            "proposals": ["aes256gcm16-prfsha384-ecp384", "aes256-sha256-ecp256", "aes256-sha256-modp2048"],
            "mobike": "yes", "encap": "yes", "fragmentation": "yes", "send_cert": "always",
            "dpd_delay": "30s", "rekey_time": "4h", "reauth_time": "0s",
            "local": {"auth": "pubkey", "id": self.settings["server_identity"],
                      "certs": [Path(self.settings["server_certificate"]).read_bytes()]},
            "remote": {"auth": "eap-mschapv2", "eap_id": username},
            "children": {name + "-net": {
                "local_ts": local_ts, "remote_ts": ["dynamic"], "reqid": str(account["reqid"]),
                "esp_proposals": ["aes256gcm16", "aes256-sha256"], "start_action": "none",
                "dpd_action": "clear", "rekey_time": "1h", "life_time": "90m",
            }},
        }
        with self.session() as session:
            pool = {"addrs": account["pool"]}
            if home_enabled(self.settings, account) and self.settings.get("home_internet", {}).get("dns"):
                pool["dns"] = self.settings["home_internet"]["dns"]
            session.load_pool({name: pool})
            actual_pool = session.get_pools().get(name, {})
            subnet = ipaddress.IPv4Network(account["pool"])
            if (actual_pool.get("base") != str(next(subnet.hosts())).encode()
                    or int(actual_pool.get("size", b"0")) != subnet.num_addresses - 2):
                raise ProjectionError("pool_readback_failed")
            # VICI 不返回池的 DNS 属性；DNS 下发须由真实客户端重连验收。
            session.load_shared({"id": name, "type": "NTLM", "data": bytes.fromhex(account["nt"]), "owners": [username]})
            session.load_conn({name: connection})
            if name.encode() not in session.get_conns().get("conns", []):
                raise ProjectionError("connection_missing")
            loaded = [event[name] for event in session.list_conns() if name in event]
            if len(loaded) != 1:
                raise ProjectionError("connection_readback_failed")
            remote = [value for key, value in loaded[0].items() if key.startswith("remote") and isinstance(value, dict)]
            children = loaded[0].get("children", {})
            child = children.get(name + "-net", {})
            expected = {selector.encode() for selector in local_ts}
            if (len(remote) != 1 or remote[0].get("eap_id") != username.encode()
                    or set(child.get("local-ts", [])) != expected):
                raise ProjectionError("connection_policy_mismatch")
            if name.encode() not in session.get_shared().get("keys", []):
                raise ProjectionError("credential_readback_failed")


class NftFirewall:
    """在既有过滤链中安装有界跳转，避免独立 base chain 的 accept 被后续 DROP 覆盖。"""

    table = "pve2_vpn"
    input_chain = "vpn_manager_input"
    forward_chain = "vpn_manager_forward"
    nat_table = "vpn_manager_nat"

    def __init__(self, settings: dict[str, Any]) -> None:
        self.settings = settings
        self.egress = HomeEgressRouter(settings)

    @staticmethod
    def command(arguments: list[str], data: str | None = None) -> subprocess.CompletedProcess:
        result = subprocess.run(["/usr/sbin/nft", *arguments], input=data, text=True, capture_output=True, timeout=3)
        if result.returncode:
            raise ProjectionError("firewall_failed")
        return result

    def rules(self, accounts: dict[str, dict[str, Any]], quarantined: set[str]) -> str:
        result = [f"flush chain inet {self.table} {self.input_chain}",
                  f"flush chain inet {self.table} {self.forward_chain}",
                  f"flush chain ip {self.nat_table} prerouting", f"flush chain ip {self.nat_table} postrouting"]
        for username, account in sorted(accounts.items()):
            pool, reqid = account["pool"], account["reqid"]
            prefix_in = f"ipsec in reqid {reqid} ip saddr {pool}"
            prefix_out = f"ipsec out reqid {reqid} ip daddr {pool}"
            if account["active"] and username not in quarantined:
                result.append(f"add rule inet {self.table} {self.input_chain} {prefix_in} ip daddr {self.settings['management_ip']} tcp dport {self.settings['management_port']} accept")
                for network in account["networks"]:
                    net = self.settings["networks"][network]
                    destinations = ", ".join(net["forward_destinations"])
                    result.extend([
                        f'add rule inet {self.table} {self.forward_chain} {prefix_in} ip daddr {{ {destinations} }} oifname "{net["interface"]}" accept',
                        f'add rule inet {self.table} {self.forward_chain} {prefix_out} ip saddr {{ {destinations} }} iifname "{net["interface"]}" ct state established,related accept',
                        f'add rule ip {self.nat_table} postrouting ip saddr {pool} ip daddr {{ {destinations} }} oifname "{net["interface"]}" snat to {net["snat"]}',
                    ])
                    if "alias" in net:
                        result.append(f'add rule ip {self.nat_table} prerouting {prefix_in} ip daddr {net["alias"]} dnat ip prefix to ip daddr map {{ {net["alias"]} : {net["real"]} }}')
                if home_enabled(self.settings, account):
                    home = self.settings["networks"]["home"]
                    public = ", ".join(NON_PUBLIC_V4)
                    result.extend([
                        f'add rule inet {self.table} {self.forward_chain} {prefix_in} ip daddr != {{ {public} }} oifname "{home["interface"]}" accept',
                        f'add rule inet {self.table} {self.forward_chain} {prefix_out} ip saddr != {{ {public} }} iifname "{home["interface"]}" ct state established,related accept',
                        f'add rule ip {self.nat_table} postrouting ip saddr {pool} ip daddr != {{ {public} }} oifname "{home["interface"]}" snat to {home["snat"]}',
                    ])
            # 未通过 reqid+源地址双重验证的流量，以及降权前遗留的连接，都在 established 规则前拒绝。
            for condition in (f"ipsec in reqid {reqid}", f"ip saddr {pool}"):
                result.append(f"add rule inet {self.table} {self.input_chain} {condition} drop")
                result.append(f"add rule inet {self.table} {self.forward_chain} {condition} drop")
            result.append(f"add rule inet {self.table} {self.forward_chain} ip daddr {pool} drop")
        return "\n".join(result) + "\n"

    def install(self, accounts: dict[str, dict[str, Any]], quarantined: set[str]) -> None:
        document = json.loads(self.command(["-j", "list", "ruleset"]).stdout)
        objects = document["nftables"]
        chains = {(o["chain"]["family"], o["chain"]["table"], o["chain"]["name"]) for o in objects if "chain" in o}
        tables = {(o["table"]["family"], o["table"]["name"]) for o in objects if "table" in o}
        if any(("inet", self.table, c) not in chains for c in ("input", "forward")):
            raise ProjectionError("base_firewall_missing")
        commands = []
        for name in (self.input_chain, self.forward_chain):
            matching = [o["chain"] for o in objects if "chain" in o and (o["chain"]["family"], o["chain"]["table"], o["chain"]["name"]) == ("inet", self.table, name)]
            if matching and matching[0].get("comment") != "vpn-manager:" + name:
                raise ProjectionError("firewall_owner_conflict")
            if not matching:
                commands.append(f'add chain inet {self.table} {name} {{ comment "vpn-manager:{name}"; }}')
        matching_nat = [o["table"] for o in objects if "table" in o and (o["table"]["family"], o["table"]["name"]) == ("ip", self.nat_table)]
        if matching_nat and matching_nat[0].get("comment") != "vpn-manager:nat":
            raise ProjectionError("firewall_owner_conflict")
        if ("ip", self.nat_table) not in tables:
            commands.extend([f'add table ip {self.nat_table} {{ comment "vpn-manager:nat"; }}',
                             f"add chain ip {self.nat_table} prerouting {{ type nat hook prerouting priority -99; policy accept; }}",
                             f"add chain ip {self.nat_table} postrouting {{ type nat hook postrouting priority 99; policy accept; }}"])
        for base, target in (("input", self.input_chain), ("forward", self.forward_chain)):
            comment = "vpn-manager:" + base
            rules = [o["rule"] for o in objects if "rule" in o and o["rule"].get("comment") == comment]
            if rules:
                if len(rules) != 1 or rules[0]["family"] != "inet" or rules[0]["table"] != self.table or rules[0]["chain"] != base or {"jump": {"target": target}} not in rules[0]["expr"]:
                    raise ProjectionError("firewall_owner_conflict")
            else:
                commands.append(f'insert rule inet {self.table} {base} jump {target} comment "{comment}"')
        batch = "\n".join(commands + [self.rules(accounts, quarantined)])
        self.command(["--check", "-f", "-"], batch)
        if self.egress.configured:
            # 路由操作不具备事务性；先隔离全部托管池，失败也不会保留旧授权。
            blocked = "\n".join(commands + [self.rules(accounts, set(accounts))])
            self.command(["--check", "-f", "-"], blocked)
            self.command(["-f", "-"], blocked)
            self.egress.sync(accounts, quarantined)
            # 链已由隔离批次创建；仅在规则精确回读后开放目标权限。
            self.command(["-f", "-"], self.rules(accounts, quarantined))
        else:
            self.command(["-f", "-"], batch)


class GatewayAgent:
    def __init__(self, state_directory: Path, driver: Any, firewall: Any) -> None:
        private_directory(state_directory)
        self.directory = state_directory
        self.path = state_directory / "accounts.json"
        self.key = private_file(state_directory / "credential-key.pem")
        self.driver, self.firewall = driver, firewall
        self.state: dict[str, Any] = json.loads(private_file(self.path)) if self.path.exists() else {"schema": 1, "accounts": {}}
        if self.state.get("schema") != 1 or not isinstance(self.state.get("accounts"), dict):
            raise ProjectionError("invalid_state")

    def save(self) -> None:
        atomic_private(self.path, canonical(self.state))

    def status(self, username: str) -> dict[str, Any]:
        account = self.state["accounts"].get(username)
        if not account:
            return {"username": username, "generation": 0, "state": "not_provisioned"}
        result = {"username": username, "generation": account["generation"], "state": account["state"]}
        if account.get("code"):
            result["code"] = account["code"]
        return result

    def apply(self, request: dict[str, Any]) -> dict[str, Any]:
        request = check_request(request)
        if request["action"] == "reload_certificate":
            # 与权限变更在同一个串行控制循环执行，避免续期重新加载旧授权。
            # 只更新已生效的活动连接模板，不断开现有 SA，也不恢复被隔离的账户。
            count = 0
            for username, account in self.state["accounts"].items():
                if account["active"] and account["state"] == "applied":
                    self.driver.load(username, account)
                    count += 1
            return {"state": "certificate_reloaded", "accounts": count}
        username = request["username"]
        if request["action"] == "status":
            return self.status(username)
        old = self.state["accounts"].get(username)
        generation = request["generation"]
        digest = hashlib.sha256(canonical(request)).hexdigest()
        if old and generation < old["generation"]:
            return {"operation_id": request["operation_id"], "username": username, "generation": generation, "state": "superseded"}
        if old and generation == old["generation"]:
            if old["request_digest"] != digest:
                raise ProjectionError("generation_conflict")
            if old["state"] == "applied":
                return {"operation_id": request["operation_id"], **self.status(username)}
        else:
            credential = old.get("nt") if old else None
            if request["credential_envelope"] is not None:
                password = open_credential(self.key, request["credential_envelope"], username, generation)
                try:
                    credential = nt_credential(password)
                finally:
                    password = None
            if request["active"] and credential is None:
                raise ProjectionError("credential_required")
            index = old["index"] if old else len(self.state["accounts"])
            if index >= 1024:
                raise ProjectionError("account_capacity")
            pool = str(ipaddress.IPv4Network((int(ipaddress.IPv4Address("10.77.64.0")) + 16 * index, 28)))
            self.state["accounts"][username] = {
                "generation": generation, "request_digest": digest, "operation_id": request["operation_id"],
                "active": request["active"], "networks": sorted(request["networks"]), "nt": credential,
                "index": index, "pool": pool, "reqid": 60001 + index, "state": "pending",
            }
            self.save()
        self.reconcile(username)
        return {"operation_id": request["operation_id"], **self.status(username)}

    def reconcile(self, username: str) -> None:
        accounts = self.state["accounts"]
        account = accounts[username]
        quarantined = {u for u, a in accounts.items() if a["state"] != "applied"} | {username}
        stage = "quarantine"
        try:
            # 先阻断旧流量，再撤销认证和 SA；任何失败都保持隔离，不回退到旧授权。
            self.firewall.install(accounts, quarantined)
            stage = "unload"
            self.driver.forget(username)
            stage = "terminate"
            self.driver.terminate(username)
            if account["active"]:
                stage = "load"
                self.driver.load(username, account)
            stage = "release"
            self.firewall.install(accounts, quarantined - {username})
            account["state"] = "applied"
            account.pop("code", None)
        except Exception:
            account["state"] = "pending"
            account["code"] = "projection_" + stage
            # 第二次安装失败也不把原始错误或凭据写入日志。
            for attempt in (lambda: self.firewall.install(accounts, quarantined),
                            lambda: self.driver.forget(username), lambda: self.driver.terminate(username)):
                with contextlib.suppress(Exception):
                    attempt()
        self.save()

    def restore(self) -> None:
        for account in self.state["accounts"].values():
            account["state"] = "pending"
        self.save()
        self.firewall.install(self.state["accounts"], set(self.state["accounts"]))
        for username in self.state["accounts"]:
            self.reconcile(username)
        if any(a["state"] != "applied" for a in self.state["accounts"].values()):
            raise ProjectionError("startup_projection_failed")


def no_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProjectionError("invalid_request")
        value[key] = item
    return value


def serve(agent: GatewayAgent, path: Path, allowed_uid: int, group_id: int) -> None:
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(8)
            _, uid, _ = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid not in {0, allowed_uid}:
                return
            raw = self.rfile.readline(MAX_MESSAGE_BYTES + 1)
            if len(raw) > MAX_MESSAGE_BYTES or not raw.endswith(b"\n"):
                return
            try:
                request = json.loads(raw, object_pairs_hook=no_duplicate_keys)
                reply = agent.apply(request)
            except Exception:
                # 无合法请求身份的错误不回显用户名、密码信封或系统错误。
                reply = {"error": "gateway_request_failed"}
            self.wfile.write(canonical(reply) + b"\n")

    parent = path.parent.lstat()
    if (not path.is_absolute() or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != 0 or parent.st_mode & 0o022):
        raise ProjectionError("unsafe_socket_directory")
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o007:
            raise ProjectionError("unsafe_existing_socket")
        # 主入口已持独占锁；仅清理连接被拒绝的本代理 socket，不碰活动服务。
        with socket.socket(socket.AF_UNIX) as probe:
            probe.settimeout(1)
            try:
                probe.connect(str(path))
            except ConnectionRefusedError:
                path.unlink()
            except OSError:
                raise ProjectionError("socket_probe_failed") from None
            else:
                raise ProjectionError("socket_already_exists")
    with socketserver.UnixStreamServer(str(path), Handler) as server:
        os.chown(path, 0, group_id)
        os.chmod(path, 0o660)
        try:
            server.serve_forever(poll_interval=0.5)
        finally:
            path.unlink(missing_ok=True)


def initialize(directory: Path, public_path: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(directory)
    path = directory / "credential-key.pem"
    if path.exists():
        key = serialization.load_pem_private_key(private_file(path), password=None)
        if not isinstance(key, X25519PrivateKey):
            raise ProjectionError("invalid_credential_key")
    else:
        key = X25519PrivateKey.generate()
        atomic_private(path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if public_path.exists() and public_path.read_bytes() != public:
        raise ProjectionError("public_key_conflict")
    if not public_path.exists():
        atomic_private(public_path, public)
        os.chmod(public_path, 0o644)


def main() -> None:
    parser = argparse.ArgumentParser(description="Linux root IKEv2 账户代理；不管理旧证书连接。")
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--initialize-public-key", type=Path)
    parser.add_argument("--config", type=Path)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("网关代理必须由 root 启动")
    try:
        if arguments.initialize_public_key:
            initialize(arguments.state_directory, arguments.initialize_public_key)
            return
        if not arguments.config:
            parser.error("需要配置路径")
        settings = json.loads(private_file(arguments.config))
        private_directory(arguments.state_directory)
        lock = arguments.state_directory / "agent.lock"
        with lock.open("a") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            agent = GatewayAgent(arguments.state_directory, ViciDriver(settings), NftFirewall(settings))
            agent.restore()
            serve(agent, Path(settings["agent_socket"]), int(settings["manager_uid"]), int(settings["manager_gid"]))
    except Exception:
        raise SystemExit("gateway_startup_failed") from None


if __name__ == "__main__":
    main()
