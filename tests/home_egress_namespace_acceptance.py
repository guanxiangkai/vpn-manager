#!/usr/bin/env python3
"""Linux root 隔离验收家庭出口能力，不访问真实公网。"""
from __future__ import annotations
import argparse, json, os, subprocess
from pathlib import Path

from ikev2_namespace_acceptance import Acceptance as BaseAcceptance


class Acceptance(BaseAcceptance):
    SYNTHETIC_INTERNET = '8.8.8.8'
    SYNTHETIC_HOME = '192.0.2.1'
    SYNTHETIC_HOME_ALIAS = '198.51.100.1'
    SYNTHETIC_WORK = '203.0.113.1'
    SYNTHETIC_MANAGEMENT = '198.18.0.2'
    LOCAL_DNS = '10.240.2.1'
    LOCAL_ADDRESS = '10.240.2.2'

    def topology(self):
        super().topology()
        # 基类提供隔离链路；本能力的所有目的地址均为文档或基准测试保留地址。
        for address in (self.SYNTHETIC_INTERNET, self.SYNTHETIC_HOME,
                        self.SYNTHETIC_HOME_ALIAS, self.SYNTHETIC_WORK):
            self.run(['ip', 'addr', 'add', address + '/32', 'dev', 'lo'], 'lan')
            self.run(['ip', 'route', 'add', address + '/32', 'via', '10.240.1.2'], 'gateway')
        self.run(['ip', 'addr', 'add', self.SYNTHETIC_MANAGEMENT + '/32', 'dev', 'lo'], 'gateway')
        self.run(['ip', 'route', 'add', 'default', 'via', '10.240.1.2', 'dev', 'site', 'metric', '10', 'table', '150'], 'gateway')
        self.run(['ip', 'route', 'add', 'blackhole', 'default', 'metric', '32767', 'table', '150'], 'gateway')

    def direct_internet(self):
        self.ns['isp'] = 'v' + self.root.name + 'i'
        self.run(['ip', 'netns', 'add', self.ns['isp']])
        self.created.append(self.ns['isp'])
        for key in ('all', 'default'):
            self.run(['sysctl', '-qw', f'net.ipv4.conf.{key}.rp_filter=0'], 'isp')
        self.run(['ip', 'link', 'add', 'uplink', 'type', 'veth', 'peer', 'name', 'isp0'], 'client')
        self.run(['ip', 'link', 'set', 'isp0', 'netns', self.ns['isp']], 'client')
        for role, link, address in (
            ('client', 'uplink', self.LOCAL_ADDRESS + '/24'),
            ('isp', 'isp0', self.LOCAL_DNS + '/24'),
        ):
            self.run(['ip', 'addr', 'add', address, 'dev', link], role)
            self.run(['ip', 'link', 'set', link, 'up'], role)
        self.run(['ip', 'link', 'set', 'lo', 'up'], 'isp')
        self.run(['ip', 'addr', 'add', self.SYNTHETIC_INTERNET + '/32', 'dev', 'lo'], 'isp')
        self.run(['ip', 'route', 'replace', 'default', 'via', self.LOCAL_DNS, 'dev', 'uplink'], 'client')
        self.verify_public_direct('baseline')

    def resolver_nameservers(self, filename):
        lines = (self.root / 'client' / filename).read_text().splitlines()
        return [line.split()[1] for line in lines if line.startswith('nameserver ')]

    def verify_public_direct(self, phase):
        route = self.run(['ip', '-j', 'route', 'get', self.SYNTHETIC_INTERNET], 'client')
        selected = json.loads(route.stdout)[0]
        self.check(phase + '_public_route_uses_local_uplink',
                   selected['dev'] == 'uplink' and selected['prefsrc'] == self.LOCAL_ADDRESS)
        result = self.run(['ping', '-n', '-c', '1', '-W', '1', self.SYNTHETIC_INTERNET],
                          'client', success=False, timeout=4)
        if result.returncode:
            evidence = [route.stdout, result.stdout, result.stderr]
            for command, role in ((['ip', '-j', 'addr'], 'client'),
                                  (['ip', '-j', 'rule'], 'client'),
                                  (['ip', '-j', 'xfrm', 'policy'], 'client'),
                                  (['ip', '-j', 'route', 'get', self.LOCAL_ADDRESS], 'isp')):
                diagnostic = self.run(command, role, success=False)
                evidence.extend((diagnostic.stdout, diagnostic.stderr))
            (self.root / 'last-command.stderr').write_bytes(b'\n'.join(evidence))
        self.check(phase + '_public_access_uses_local_uplink', result.returncode == 0)

    def verify_split(self):
        self.connect('admin')
        self.check('split_retains_local_dns', self.resolver_nameservers('resolv.conf') == [self.LOCAL_DNS])
        self.check('split_has_no_vpn_dns', not self.resolver_nameservers('received-dns.conf'))
        self.verify_public_direct('split')
        self.ping(self.SYNTHETIC_HOME, True, 'split_admin_home')
        self.ping(self.SYNTHETIC_HOME_ALIAS, True, 'split_admin_home_alias')
        self.ping(self.SYNTHETIC_WORK, True, 'split_admin_work')
        self.ping(self.SYNTHETIC_INTERNET, False, 'split_no_public_vpn_path')
        self.connect('member')
        self.ping(self.SYNTHETIC_WORK, True, 'split_member_work')
        self.ping(self.SYNTHETIC_HOME, False, 'split_member_home_denied')

    def execute(self, split_tunnel=False):
        self.topology(); ca, key, cert = self.certificates(); self.launch('gateway'); self.launch('client')
        with self.session('gateway') as s:
            self.check('strongswan_6_1_0', s.version()['version'] == b'6.1.0'); s.load_key({'type': 'rsa', 'data': key.read_bytes()})
        with self.session('client') as s: s.load_cert({'type': 'X509', 'flag': 'CA', 'data': ca.read_bytes()})
        settings = {'vici_socket': str(self.sockets['gateway']), 'local_address': '10.240.0.1', 'server_identity': 'gateway.test', 'server_certificate': str(cert), 'management_ip': self.SYNTHETIC_MANAGEMENT, 'management_port': 8443,
                    'home_internet': {'enabled': True, 'routing_table': 150, 'rule_priority': 18000, 'rule_protocol': 186, 'dns': [self.SYNTHETIC_HOME]},
                    'networks': {'home': {'selectors': ['192.0.2.0/24', '198.51.100.0/24'], 'forward_destinations': ['192.0.2.0/24'], 'interface': 'site', 'snat': '10.240.1.1', 'alias': '198.51.100.0/24', 'real': '192.0.2.0/24'},
                                 'work': {'selectors': ['203.0.113.0/24'], 'forward_destinations': ['203.0.113.0/24'], 'interface': 'site', 'snat': '10.240.1.1'}}}
        if split_tunnel:
            from ops.home_egress_publish import _render_candidate_config
            settings = json.loads(_render_candidate_config(json.dumps(settings).encode(), None, split_tunnel=True))
            self.direct_internet()
        harness = self
        class IsolatedNft(__import__('vpn_manager.gateway_agent', fromlist=['NftFirewall']).NftFirewall):
            @staticmethod
            def command(arguments, data=None):
                p = harness.run(['nft', *arguments], 'gateway', data=data.encode() if data else None); p.stdout = p.stdout.decode(); return p
        state = self.root / 'agent-state'; __import__('vpn_manager.gateway_agent', fromlist=['initialize']).initialize(state, self.root / 'gateway-public.pem')
        from vpn_manager.gateway_agent import GatewayAgent, ViciDriver
        firewall = IsolatedNft(settings)
        firewall.egress.command = lambda args: harness.run(['ip', '-4', *args], 'gateway')
        self.public = (self.root / 'gateway-public.pem').read_bytes()
        self.agent = GatewayAgent(state, ViciDriver(settings), firewall)
        self.project('admin', ['home', 'work'], password=True); self.project('member', ['work'], password=True)
        if split_tunnel:
            self.verify_split()
            return
        self.connect('admin'); self.ping(self.SYNTHETIC_INTERNET, True, 'admin_synthetic_internet')
        self.check('full_vpn_pushes_home_dns', self.resolver_nameservers('received-dns.conf') == [self.SYNTHETIC_HOME])
        self.ping(self.SYNTHETIC_HOME, True, 'admin_home'); self.ping(self.SYNTHETIC_HOME_ALIAS, True, 'admin_home_alias'); self.ping(self.SYNTHETIC_WORK, True, 'admin_work')
        self.connect('member'); self.ping(self.SYNTHETIC_INTERNET, False, 'member_synthetic_internet_denied')
        self.ping(self.SYNTHETIC_WORK, True, 'member_work'); self.ping(self.SYNTHETIC_HOME, False, 'member_home_denied')
        self.connect('member', outer='admin'); self.ping(self.SYNTHETIC_INTERNET, False, 'forged_ike_home_denied')
        self.connect('admin', wrong=True, expect=False)
        self.connect('admin'); self.project('admin', ['work']); self.ping(self.SYNTHETIC_INTERNET, False, 'existing_public_flow_revoked')
        self.connect('admin'); self.ping(self.SYNTHETIC_INTERNET, False, 'revoked_synthetic_internet')
        self.ping(self.SYNTHETIC_WORK, True, 'downgraded_work')
        self.project('member', ['work'], active=False); self.connect('member', expect=False)


def main():
    p = argparse.ArgumentParser(); p.add_argument('--prefix', type=Path, required=True); p.add_argument('--workdir', type=Path, required=True); p.add_argument('--timeout', type=int, default=300)
    p.add_argument('--split-tunnel', action='store_true'); a = p.parse_args()
    if os.uname().sysname != 'Linux' or os.geteuid() != 0: p.error('仅限 Linux root')
    if not a.workdir.is_dir() or a.workdir.stat().st_mode & 0o077: p.error('workdir 必须是已存在的私有目录')
    os.umask(0o077)
    runner = Acceptance(a.prefix, a.workdir, max(60, min(a.timeout, 900))); status, reason = 'passed', None
    try: runner.execute(split_tunnel=a.split_tunnel)
    except Exception as error: status, reason = 'failed', type(error).__name__; (runner.root / 'failure.txt').write_text(str(error))
    finally: cleaned = runner.cleanup()
    print(json.dumps({'status': status if cleaned else 'failed', 'reason': reason, 'checks': runner.checks, 'evidence_dir': str(runner.root), 'configuration_source': 'fixture', 'production_site_validated': False, 'resources_cleaned': cleaned})); return 0 if status == 'passed' and cleaned else 1


if __name__ == '__main__': raise SystemExit(main())
