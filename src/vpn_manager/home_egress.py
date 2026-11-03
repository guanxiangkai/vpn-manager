"""家庭出口策略路由：仅管理保留的协议和优先级，不修改既有出口表。"""
from __future__ import annotations

from collections import Counter
import ipaddress
import json
import re
import subprocess
from typing import Any, Callable

# 非公网目的交给主路由表，再由按账户授权的内网防火墙决定是否放行。
NON_PUBLIC_V4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
)


class ProjectionError(Exception):
    """固定错误码，避免系统输出进入管理接口。"""


def home_enabled(settings: dict[str, Any], account: dict[str, Any]) -> bool:
    return (settings.get("home_internet", {}).get("enabled") is True
            and account.get("active") is True and "home" in account.get("networks", []))


class HomeEgressRouter:
    def __init__(self, settings: dict[str, Any], command: Callable | None = None):
        self.settings = settings
        self.configured = "home_internet" in settings
        cfg = settings.get("home_internet", {})
        if not isinstance(cfg, dict):
            raise ProjectionError("invalid_home_egress_config")
        self.enabled = cfg.get("enabled") is True
        self.table = cfg.get("routing_table", 150)
        self.priority = cfg.get("rule_priority", 18000)
        self.protocol = cfg.get("rule_protocol", 186)
        networks = settings.get("networks", {})
        home = networks.get("home", {}) if isinstance(networks, dict) else None
        if self.configured and not isinstance(home, dict):
            raise ProjectionError("invalid_home_egress_config")
        self.interface = home.get("interface") if isinstance(home, dict) else None
        self.command = command or self._command
        if self.configured:
            try:
                valid = (type(cfg.get("enabled")) is bool
                         and type(self.table) is int and 1 <= self.table < 253
                         and type(self.priority) is int and 1000 <= self.priority < 32765
                         and type(self.protocol) is int and 16 <= self.protocol <= 255
                         and isinstance(self.interface, str)
                         and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", self.interface)
                         and isinstance(cfg.get("dns", []), list)
                         and all(isinstance(x, str) and ipaddress.IPv4Address(x)
                                 for x in cfg.get("dns", [])))
            except (ValueError, TypeError):
                valid = False
            if not valid:
                raise ProjectionError("invalid_home_egress_config")

    @staticmethod
    def _command(args: list[str]):
        result = subprocess.run(["/sbin/ip", "-4", *args], capture_output=True, text=True, timeout=3)
        if result.returncode:
            raise ProjectionError("home_egress_route_failed")
        return result

    def _json(self, args: list[str]) -> list[dict[str, Any]]:
        try:
            # 固定数字格式，避免协议号被 iproute2 转换成 bgp 等名称。
            value = json.loads(self.command(["-N", *args]).stdout)
            if not isinstance(value, list) or any(not isinstance(r, dict) for r in value):
                raise ValueError()
            return value
        except (ValueError, TypeError) as error:
            raise ProjectionError("home_egress_route_readback_failed") from error

    def _validate_table(self):
        routes = self._json(["-j", "route", "show", "table", str(self.table)])
        # 禁止隐藏的更具体路由及其他默认出口；隧道消失时保留 blackhole。
        def route_type(route):
            # `ip -N -j` 输出 rtnetlink 数字类型：RTN_UNICAST=1、
            # RTN_BLACKHOLE=6；只接受这些精确等价值。
            value = route.get("type", "unicast")
            if type(value) not in (int, str):
                return None
            return {1: "unicast", "1": "unicast", "unicast": "unicast",
                    6: "blackhole", "6": "blackhole", "blackhole": "blackhole"}.get(value)
        good = [r for r in routes if r.get("dst") == "default"
                and route_type(r) == "unicast"
                and r.get("dev") == self.interface and r.get("gateway")]
        blackhole = [r for r in routes if r.get("dst") == "default" and route_type(r) == "blackhole"]
        try:
            valid = (len(routes) == 2 and len(good) == 1 and len(blackhole) == 1
                     and int(good[0].get("metric", 0)) < int(blackhole[0].get("metric", 0)))
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise ProjectionError("home_egress_table_invalid")

    def _key(self, rule):
        allowed = {"priority", "src", "srclen", "dst", "dstlen", "table", "protocol", "flags"}
        if set(rule) - allowed or rule.get("flags", []):
            raise ProjectionError("home_egress_owner_conflict")
        table = rule.get("table")
        if table == "main":
            table = 254
        def network(field):
            value = rule.get(field, "all")
            length = rule.get(field + "len")
            if value == "all":
                if length not in (None, 0):
                    raise ValueError()
                return "0.0.0.0/0"
            if length is not None:
                if "/" in value or type(length) is not int or not 0 <= length <= 32:
                    raise ValueError()
                value += "/" + str(length)
            return str(ipaddress.IPv4Network(value))
        try:
            return (int(rule["priority"]), network("src"), network("dst"),
                    int(table), int(rule["protocol"]))
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            raise ProjectionError("home_egress_owner_conflict") from error

    def _owned(self, accounts):
        known = {str(ipaddress.IPv4Network(a["pool"])) for a in accounts.values()
                 if isinstance(a, dict) and "pool" in a}
        result = []
        for rule in self._json(["-j", "rule", "show"]):
            if rule.get("priority") not in (self.priority, self.priority + 1):
                continue
            if str(rule.get("protocol")) != str(self.protocol):
                raise ProjectionError("home_egress_owner_conflict")
            key = self._key(rule)
            if key[3] not in (self.table, 254):
                raise ProjectionError("home_egress_owner_conflict")
            if key[1] not in known:
                raise ProjectionError("home_egress_owner_conflict")
            if key[3] == self.table and key[2] != "0.0.0.0/0":
                raise ProjectionError("home_egress_owner_conflict")
            if key[3] == 254 and key[2] not in NON_PUBLIC_V4:
                raise ProjectionError("home_egress_owner_conflict")
            result.append(key)
        return result

    def _desired(self, accounts, quarantined):
        pools = sorted({str(ipaddress.IPv4Network(a["pool"])) for u, a in accounts.items()
                        if home_enabled(self.settings, a) and u not in quarantined})
        result = []
        for pool in pools:
            result.extend((self.priority, pool, dst, 254, self.protocol) for dst in NON_PUBLIC_V4)
            result.append((self.priority + 1, pool, "0.0.0.0/0", self.table, self.protocol))
        return result

    def _change(self, action, key):
        priority, source, destination, table, protocol = key
        self.command(["rule", action, "priority", str(priority), "from", source, "to", destination,
                      "lookup", str(table), "protocol", str(protocol)])

    def sync(self, accounts, quarantined):
        if not self.configured:
            return
        if self.enabled:
            self._validate_table()
        current, desired = Counter(self._owned(accounts)), Counter(self._desired(accounts, quarantined))
        # 先撤权再授权；完整选择条件避免按优先级误删其他规则。
        for key, count in (current - desired).items():
            for _ in range(count):
                self._change("del", key)
        for key, count in (desired - current).items():
            for _ in range(count):
                self._change("add", key)
        if Counter(self._owned(accounts)) != desired:
            raise ProjectionError("home_egress_route_readback_failed")
