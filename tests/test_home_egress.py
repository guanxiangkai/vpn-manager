import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
from vpn_manager.home_egress import HomeEgressRouter, NON_PUBLIC_V4, ProjectionError


class IpFake:
    def __init__(self, *, rules=None, routes=None):
        self.rules = list(rules or [])
        self.routes = list(routes or [{"dst": "default", "gateway": "192.0.2.1", "dev": "home", "metric": 10}, {"dst": "default", "type": "blackhole", "metric": 42700}])
        self.calls = []
        self.loss = False

    def __call__(self, args):
        self.calls.append(list(args))
        if "-j" in args:
            assert args[0] == "-N", "JSON 回读必须使用数字格式"
            args = args[1:]
        if args[1:3] == ["route", "show"]: return SimpleNamespace(stdout=json.dumps(self.routes))
        if args[1:3] == ["rule", "show"]:
            return SimpleNamespace(stdout=json.dumps([self._json_rule(r) for r in (self.rules[:-1] if self.loss else self.rules)]))
        if args[:2] in (["rule", "add"], ["rule", "del"]):
            key = self._rule(args)
            if args[1] == "add":
                self.rules.append(key)
                if self.loss: self.rules.pop()
            else: self.rules.remove(key)
        return SimpleNamespace(stdout="")

    @staticmethod
    def _json_rule(rule):
        result = dict(rule)
        for field in ("src", "dst"):
            value = result.get(field)
            if value and "/" in value:
                address, prefix = value.split("/", 1)
                result[field], result[field + "len"] = address, int(prefix)
        if result.get("table") == 254:
            result["table"] = "main"
        result["protocol"] = str(result["protocol"])
        return result

    @staticmethod
    def _rule(args):
        def value(name): return args[args.index(name) + 1]
        return {"priority": int(value("priority")), "src": value("from"), "dst": value("to"), "table": int(value("lookup")), "protocol": int(value("protocol"))}


def settings(enabled=True):
    return {"home_internet": {"enabled": enabled, "routing_table": 150, "rule_priority": 18000, "rule_protocol": 186, "dns": ["192.0.2.53"]}, "networks": {"home": {"interface": "home"}}}


def account(active=True, networks=("home",)):
    return {"active": active, "networks": list(networks), "pool": "198.51.100.64/28"}


class HomeEgressTests(unittest.TestCase):
    def test_account_filtering(self):
        r = HomeEgressRouter(settings(), IpFake())
        self.assertEqual(len(r._desired({"p": account(), "w": account(networks=("work",)), "i": account(False)}, set())), len(NON_PUBLIC_V4) + 1)
        self.assertEqual(r._desired({"p": account()}, {"p"}), [])

    def test_add_and_repeat_is_noop(self):
        f = IpFake(); r = HomeEgressRouter(settings(), f); r.sync({"a": account()}, set()); n = len(f.calls)
        self.assertEqual(len(f.rules), len(NON_PUBLIC_V4) + 1); r.sync({"a": account()}, set()); self.assertEqual(len(f.calls), n + 3)

    def test_revoke_and_disabled_clean(self):
        f = IpFake(); r = HomeEgressRouter(settings(), f); r.sync({"a": account()}, set()); r.sync({"a": account(False)}, set()); self.assertEqual(f.rules, [])
        f.rules = [{"priority": 18001, "src": "198.51.100.64/28", "dst": "0.0.0.0/0", "table": 150, "protocol": 186}, {"priority": 18001, "src": "198.51.100.64/28", "dst": "0.0.0.0/0", "table": 150, "protocol": 186}]
        # 清理保持保守：仍提供已撤权/非活动账户作为已知地址池；
        # 空账户映射不能授权删除无法区分归属的外来规则。
        HomeEgressRouter(settings(False), f).sync({"a": account(False)}, set()); self.assertEqual(f.rules, [])

    def test_home_to_work_downgrade_cleans_egress(self):
        f = IpFake(); r = HomeEgressRouter(settings(), f)
        r.sync({"a": account()}, set())
        before = len(f.calls)
        r.sync({"a": account(networks=("work",))}, set())
        self.assertEqual(f.rules, [])
        self.assertEqual(sum(1 for call in f.calls[before:] if call[:2] == ["rule", "del"]), len(NON_PUBLIC_V4) + 1)

    def test_missing_config_noop_and_foreign_conflict(self):
        f = IpFake(); HomeEgressRouter({"networks": {"home": {"interface": "home"}}}, f).sync({"a": account()}, set()); self.assertEqual(f.calls, [])
        f = IpFake(rules=[{"priority": 18000, "src": "203.0.113.0/24", "dst": "0.0.0.0/0", "table": 254, "protocol": 99}]); r = HomeEgressRouter(settings(), f)
        with self.assertRaisesRegex(ProjectionError, "owner_conflict"): r.sync({}, set())
        self.assertFalse(any(c[:2] in (["rule", "add"], ["rule", "del"]) for c in f.calls))

    def test_real_ip_json_shape_and_exact_prefix(self):
        rule = {"priority": 18001, "src": "198.51.100.20/30", "dst": "0.0.0.0/0", "table": 150, "protocol": 186}
        f = IpFake(rules=[rule]); r = HomeEgressRouter(settings(False), f)
        self.assertEqual(len(r._owned({"a": {"pool": "198.51.100.20/30"}})), 1)
        # 相同优先级/协议但源前缀不同，不属于该账户。
        foreign = IpFake(rules=[{"priority": 18001, "src": "198.51.100.24/30", "dst": "0.0.0.0/0", "table": 150, "protocol": 186}])
        self.assertEqual(len(HomeEgressRouter(settings(False), foreign)._owned({"a": {"pool": "198.51.100.24/30"}})), 1)

    def test_main_table_and_missing_dst_are_normalized_but_flags_are_not(self):
        rule = {"priority": 18000, "src": "198.51.100.20/30", "dst": "203.0.113.0/24", "table": 254, "protocol": 186}
        f = IpFake(rules=[rule]); self.assertEqual(len(HomeEgressRouter(settings(False), f)._owned({"a": {"pool": "198.51.100.20/30"}})), 1)
        no_dst = {"priority": 18001, "src": "198.51.100.20/30", "table": 150, "protocol": 186}
        f = IpFake(rules=[no_dst]); self.assertEqual(len(HomeEgressRouter(settings(False), f)._owned({"a": {"pool": "198.51.100.20/30"}})), 1)
        flagged = dict(no_dst, flags=["onlink"]); f = IpFake(rules=[flagged])
        with self.assertRaisesRegex(ProjectionError, "owner_conflict"): HomeEgressRouter(settings(False), f)._owned({"a": {"pool": "198.51.100.20/30"}})

    def test_unknown_pool_same_slot_is_not_deleted(self):
        key = {"priority": 18001, "src": "198.51.100.24/30", "dst": "0.0.0.0/0", "table": 150, "protocol": 186}
        f = IpFake(rules=[key]); r = HomeEgressRouter(settings(False), f)
        with self.assertRaisesRegex(ProjectionError, "owner_conflict"): r.sync({}, set())
        self.assertEqual(f.rules, [key])

    def test_bad_routes_and_readback_loss(self):
        bad = [[{"dst": "default", "gateway": "192.0.2.1", "dev": "home"}], [{"dst": "default", "gateway": "192.0.2.1", "dev": "other"}, {"dst": "default", "type": "blackhole"}], [{"dst": "default", "gateway": "192.0.2.1", "dev": "home"}, {"dst": "203.0.113.0/24", "dev": "home"}, {"dst": "default", "type": "blackhole"}]]
        for routes in bad:
            with self.assertRaisesRegex(ProjectionError, "table_invalid"): HomeEgressRouter(settings(), IpFake(routes=routes)).sync({}, set())
        f = IpFake(); r = HomeEgressRouter(settings(), f); r.sync({"a": account()}, set()); f.loss = True
        with self.assertRaisesRegex(ProjectionError, "readback_failed"): r.sync({"a": account()}, set())

    def test_numeric_iproute_route_types_are_normalized_strictly(self):
        routes = [{"dst": "default", "type": 1, "gateway": "192.0.2.1", "dev": "home", "metric": 10},
                  {"dst": "default", "type": 6, "metric": 42700}]
        HomeEgressRouter(settings(), IpFake(routes=routes)).sync({}, set())
        for bad_type in (2, "2", "throw", None, True):
            bad = [{"dst": "default", "type": 1, "gateway": "192.0.2.1", "dev": "home", "metric": 10},
                   {"dst": "default", "type": bad_type, "metric": 42700}]
            with self.assertRaisesRegex(ProjectionError, "table_invalid"):
                HomeEgressRouter(settings(), IpFake(routes=bad)).sync({}, set())


if __name__ == "__main__": unittest.main()
