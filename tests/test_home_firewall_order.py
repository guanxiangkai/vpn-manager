import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
try:
    from vpn_manager.gateway_agent import NftFirewall
except ModuleNotFoundError:
    NftFirewall = None


@unittest.skipIf(NftFirewall is None, "gateway test dependency cryptography is unavailable")
class FirewallOrderTest(unittest.TestCase):
    def test_quarantine_nft_precedes_egress_and_release_follows_success(self):
        events = []
        settings = {"management_ip": "198.18.0.2", "management_port": 8443,
                    "networks": {"home": {"selectors": [], "forward_destinations": [], "interface": "home", "snat": "192.0.2.2"}},
                    "home_internet": {"enabled": True, "dns": ["192.0.2.53"]}}
        firewall = NftFirewall(settings)
        firewall.rules = lambda accounts, quarantined: "RULES:" + ",".join(sorted(quarantined))
        firewall.egress = SimpleNamespace(configured=True, sync=lambda accounts, quarantined: events.append("egress"))
        ruleset = {"nftables": [{"chain": {"family": "inet", "table": "pve2_vpn", "name": "input"}},
                                 {"chain": {"family": "inet", "table": "pve2_vpn", "name": "forward"}}]}

        def command(args, data=None):
            if args[:3] == ["-j", "list", "ruleset"]: return SimpleNamespace(stdout=json.dumps(ruleset))
            events.append((args[:2], data))
            return SimpleNamespace(stdout="")

        firewall.command = command
        firewall.install({"alice": {"active": True, "networks": ["home"], "pool": "198.51.100.64/28", "reqid": 1}}, set())
        batches = [event[1] for event in events
                   if isinstance(event, tuple) and event[0] == ["-f", "-"]]
        self.assertEqual(len(batches), 2)
        self.assertTrue(batches[0].endswith("RULES:alice"))
        self.assertEqual(events[-2:], ["egress", (['-f', '-'], batches[-1])])
        self.assertTrue(batches[-1].endswith("RULES:"))

    def test_egress_failure_has_no_release(self):
        events = []
        settings = {"management_ip": "198.18.0.2", "management_port": 8443, "networks": {"home": {"interface": "home"}}, "home_internet": {"enabled": True, "dns": ["192.0.2.53"]}}
        firewall = NftFirewall(settings); firewall.rules = lambda accounts, quarantined: "RULES"
        firewall.egress = SimpleNamespace(configured=True, sync=lambda *_: (_ for _ in ()).throw(RuntimeError("route")))
        firewall.command = lambda args, data=None: (events.append((args, data)) or SimpleNamespace(stdout=json.dumps({"nftables": [{"chain": {"family": "inet", "table": "pve2_vpn", "name": "input"}}, {"chain": {"family": "inet", "table": "pve2_vpn", "name": "forward"}}]}) if args[:3] == ["-j", "list", "ruleset"] else ""))
        with self.assertRaises(RuntimeError): firewall.install({}, set())
        self.assertEqual(sum(1 for args, _ in events if args == ["-f", "-"]), 1)


if __name__ == "__main__": unittest.main()
