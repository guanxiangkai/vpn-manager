#!/usr/bin/env python3
"""Linux root 隔离验收：实际代理投影、EAP、nft 转发；只用合成凭据。"""
from __future__ import annotations
import argparse
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import time
import uuid
import vici
from vpn_manager.gateway_agent import GatewayAgent, NftFirewall, ViciDriver, initialize
from vpn_manager.gateway_sync import seal_credential

class Acceptance:
    def __init__(self, prefix, workdir, timeout):
        self.prefix = prefix.resolve(strict=True)
        self.root = workdir / secrets.token_hex(4)
        self.root.mkdir(mode=0o700)
        self.end = time.monotonic() + timeout
        self.ns = {n:'v'+self.root.name+n[0] for n in ('client','gateway','lan')}
        self.created, self.processes, self.checks = [], [], []
        self.sockets, self.generation = {}, {'admin':0,'member':0}
        self.passwords = {n:secrets.token_urlsafe(24) for n in self.generation}
    def run(self, args, ns=None, data=None, success=True, timeout=10):
        command = (['ip','netns','exec',self.ns[ns]] if ns else []) + list(map(str,args))
        left = self.end-time.monotonic()
        if left <= 0: raise RuntimeError('acceptance_timeout')
        p = subprocess.run(command,input=data,capture_output=True,timeout=min(timeout,left))
        if success and p.returncode:
            (self.root/'last-command.stderr').write_bytes(p.stderr)
            raise RuntimeError('isolated_command_failed:'+str(args[0]))
        return p
    def check(self,name,condition):
        self.checks.append({'name':name,'passed':bool(condition)})
        if not condition: raise RuntimeError('check_failed:'+name)
    def topology(self):
        for role,name in self.ns.items():
            self.run(['ip','netns','add',name]); self.created.append(name)
            self.run(['ip','link','set','lo','up'],role)
            for key in ('all','default'):
                self.run(['sysctl','-qw',f'net.ipv4.conf.{key}.rp_filter=0'],role)
        for a,b,link,addresses in [('client','gateway','wan',('10.240.0.2/24','10.240.0.1/24')),('gateway','lan','site',('10.240.1.1/24','10.240.1.2/24'))]:
            self.run(['ip','link','add',link,'type','veth','peer','name','peer'],a)
            self.run(['ip','link','set','peer','netns',self.ns[b]],a)
            self.run(['ip','link','set','peer','name',link],b)
            for role,address in ((a,addresses[0]),(b,addresses[1])):
                self.run(['ip','addr','add',address,'dev',link],role)
                self.run(['ip','link','set',link,'up'],role)
        self.run(['ip','route','add','default','via','10.240.0.1'],'client')
        self.run(['ip','route','add','default','via','10.240.1.1'],'lan')
        for net,addr in [('192.168.50.0/24','192.168.50.1/32'),('192.168.3.0/24','192.168.3.1/32'),('10.77.30.0/24','10.77.30.1/32')]:
            self.run(['ip','addr','add',addr,'dev','lo'],'lan')
            self.run(['ip','route','add',net,'via','10.240.1.2'],'gateway')
        self.run(['ip','addr','add','10.77.60.1/32','dev','lo'],'gateway')
        self.run(['sysctl','-qw','net.ipv4.ip_forward=1'],'gateway')
        self.run(['nft','-f','-'],'gateway',data=b'add table inet pve2_vpn\nadd chain inet pve2_vpn input { type filter hook input priority 0; policy accept; }\nadd chain inet pve2_vpn forward { type filter hook forward priority 0; policy drop; }\n')
        self.check('isolated_topology',True)
    def certificates(self):
        ca,key,cert = [self.root/n for n in ('ca.pem','server-key.pem','server.pem')]
        cakey,csr = self.root/'ca-key.pem',self.root/'server.csr'
        self.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-sha256','-subj','/CN=fixture-ca','-keyout',cakey,'-out',ca],timeout=30)
        self.run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=gateway.test','-keyout',key,'-out',csr],timeout=30)
        ext=self.root/'server.ext'
        ext.write_text('subjectAltName=DNS:gateway.test\nextendedKeyUsage=serverAuth,1.3.6.1.5.5.8.2.2\nkeyUsage=digitalSignature\nbasicConstraints=CA:FALSE\n')
        self.run(['openssl','x509','-req','-in',csr,'-CA',ca,'-CAkey',cakey,'-CAcreateserial','-days','1','-sha256','-extfile',ext,'-out',cert])
        return ca,key,cert
    def launch(self,role):
        directory=self.root/role; directory.mkdir(mode=0o700)
        conf,control=directory/'strongswan.conf',directory/'vici'
        conf.write_text(f'''charon {{
 plugins {{
  vici {{
   socket = unix://{control}
  }}
 }}
}}
''')
        env=os.environ.copy();env['STRONGSWAN_CONF']=str(conf)
        # charon PID_FILE 编译时固定；每个实例用私有 mount namespace 的 tmpfs 隔离。
        (self.prefix/'run').mkdir(mode=0o700,exist_ok=True)
        with (directory/'daemon.log').open('wb') as log:
            p=subprocess.Popen(['ip','netns','exec',self.ns[role],'unshare','--mount','--propagation','private','sh','-c','mount -t tmpfs -o mode=0700 tmpfs "$1" && exec "$2"','fixture',str(self.prefix/'run'),str(self.prefix/'libexec/ipsec/charon')],env=env,stdout=log,stderr=log,start_new_session=True)
        self.processes.append(p)
        end=min(self.end,time.monotonic()+15)
        while not control.exists():
            if p.poll() is not None or time.monotonic()>end: raise RuntimeError('charon_start_failed:'+role)
            time.sleep(.1)
        self.sockets[role]=control
    @contextlib.contextmanager
    def session(self,role):
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(5);peer.connect(str(self.sockets[role]));yield vici.Session(peer)
    def project(self,username,networks,active=True,password=False):
        self.generation[username]+=1;g=self.generation[username]
        envelope=seal_credential(self.public,username,g,self.passwords[username]) if password else None
        reply=self.agent.apply({'action':'apply_account','operation_id':uuid.uuid4().hex,'username':username,'generation':g,'active':active,'networks':networks,'credential_envelope':envelope})
        self.check('projection_'+username+'_'+str(g),reply['state']=='applied')
    def clean_client(self):
        with self.session('client') as s:
            for item in list(s.list_sas()):
                for value in item.values():list(s.terminate({'ike-id':value['uniqueid'],'force':'yes','timeout':'1500'}))
            if list(s.list_sas()):raise RuntimeError('client_cleanup_failed')
            for name in s.get_conns().get('conns',[]):s.unload_conn({'name':name})
            for name in s.get_shared().get('keys',[]):s.unload_shared({'id':name})
    def connect(self,username,outer=None,wrong=False,expect=True):
        self.clean_client();name='fixture-'+uuid.uuid4().hex[:10]
        with self.session('client') as s:
            s.load_shared({'id':'fixture','type':'EAP','data':('incorrect-' if wrong else self.passwords[username]).encode(),'owners':[username]})
            s.load_conn({name:{'version':'2','local_addrs':['10.240.0.2'],'remote_addrs':['10.240.0.1'],'vips':['0.0.0.0'],'proposals':['aes256-sha256-modp2048'],'rekey_time':'0s','local':{'auth':'eap-mschapv2','id':outer or username,'eap_id':username},'remote':{'auth':'pubkey','id':'gateway.test'},'children':{name:{'local_ts':['dynamic'],'remote_ts':['0.0.0.0/0'],'esp_proposals':['aes256gcm16'],'start_action':'none'}}}})
            try:list(s.initiate({'child':name,'timeout':'8000'}))
            except Exception:pass
            sas=list(s.list_sas({'ike':name}))
        established=[v for item in sas for v in item.values() if v.get('state')==b'ESTABLISHED' and v.get('child-sas')]
        self.check('ike_'+username+('_wrong' if wrong else '')+('_outer' if outer else ''),bool(established)==expect)
        if not expect:self.clean_client();return
        addresses=established[0].get('local-vips',[])
        self.check('assigned_vip_'+username,len(addresses)==1)
        self.vip=addresses[0].decode()
        self.check('vip_verified_eap_'+username,ipaddress.ip_address(self.vip) in ipaddress.ip_network(self.agent.state['accounts'][username]['pool']))
    def ping(self,target,expected,label):
        p=self.run(['ping','-n','-I',self.vip,'-c','1','-W','1',target],'client',success=False,timeout=4)
        self.check(label,(p.returncode==0)==expected)
    def execute(self):
        self.topology();ca,key,cert=self.certificates();self.launch('gateway');self.launch('client')
        with self.session('gateway') as s:
            self.check('strongswan_6_1_0',s.version()['version']==b'6.1.0')
            s.load_key({'type':'rsa','data':key.read_bytes()})
        with self.session('client') as s:s.load_cert({'type':'X509','flag':'CA','data':ca.read_bytes()})
        settings={'vici_socket':str(self.sockets['gateway']),'local_address':'10.240.0.1','server_identity':'gateway.test','server_certificate':str(cert),'management_ip':'10.77.60.1','management_port':8443,'networks':{
          'home':{'selectors':['192.168.50.0/24','10.77.50.0/24'],'forward_destinations':['192.168.50.0/24'],'interface':'site','snat':'10.240.1.1','alias':'10.77.50.0/24','real':'192.168.50.0/24'},
          'work':{'selectors':['192.168.3.0/24','10.77.30.0/24'],'forward_destinations':['192.168.3.0/24','10.77.30.0/24'],'interface':'site','snat':'10.240.1.1'}}}
        harness=self
        class IsolatedNft(NftFirewall):
            @staticmethod
            def command(arguments,data=None):
                p=harness.run(['nft',*arguments],'gateway',data=data.encode() if data else None)
                p.stdout=p.stdout.decode();return p
        state=self.root/'agent-state';initialize(state,self.root/'gateway-public.pem')
        self.public=(self.root/'gateway-public.pem').read_bytes()
        self.agent=GatewayAgent(state,ViciDriver(settings),IsolatedNft(settings))
        self.project('admin',['home','work'],password=True);self.project('member',['work'],password=True)
        self.connect('admin');self.ping('192.168.50.1',True,'admin_home_real');self.ping('10.77.50.1',True,'admin_home_alias');self.ping('192.168.3.1',True,'admin_work')
        self.connect('member');self.ping('192.168.3.1',True,'member_work');self.ping('192.168.50.1',False,'member_home_denied');self.ping('10.77.50.1',False,'member_home_alias_denied')
        self.connect('member',outer='admin');self.ping('192.168.3.1',True,'outer_admin_eap_member_work');self.ping('192.168.50.1',False,'outer_admin_eap_member_home_denied')
        self.connect('admin',wrong=True,expect=False)
        self.connect('admin');self.project('admin',['work']);self.ping('192.168.50.1',False,'existing_home_flow_revoked')
        self.connect('admin');self.ping('192.168.3.1',True,'downgraded_work');self.ping('192.168.50.1',False,'downgraded_home_denied')
        self.project('member',['work'],active=False);self.connect('member',expect=False)
    def cleanup(self):
        for p in reversed(self.processes):
            if p.poll() is None:
                with contextlib.suppress(ProcessLookupError):os.killpg(p.pid,signal.SIGTERM)
                try:p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):os.killpg(p.pid,signal.SIGKILL)
                    p.wait(timeout=3)
        cleaned=True
        for n in reversed(self.created):
            p=subprocess.run(['ip','netns','del',n],capture_output=True,timeout=5);cleaned=cleaned and p.returncode==0
        # 删除合成认证材料，保留当前运行的日志和失败证据。
        for p in self.root.rglob('*'):
            if p.is_file() and (p.suffix in {'.pem','.csr','.srl'} or p.name=='accounts.json'):p.unlink()
        return cleaned

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prefix',type=Path,required=True);p.add_argument('--workdir',type=Path,required=True);p.add_argument('--timeout',type=int,default=300);a=p.parse_args()
    if os.uname().sysname!='Linux' or os.geteuid()!=0:p.error('仅限 Linux root')
    if not a.workdir.is_dir() or a.workdir.stat().st_mode & 0o077:p.error('workdir 必须是已存在的私有目录')
    os.umask(0o077);runner=Acceptance(a.prefix,a.workdir,max(60,min(a.timeout,900)));status='passed';reason=None
    try:runner.execute()
    except Exception as error:
        status='failed';reason=type(error).__name__;(runner.root/'failure.txt').write_text(str(error))
    finally:cleaned=runner.cleanup()
    result={'status':status if cleaned else 'failed','reason':reason,'checks':runner.checks,'evidence_dir':str(runner.root),'configuration_source':'fixture','actual_agent_projection_validated':status=='passed','production_site_validated':False,'not_tested':['independent_mschap_username_forgery','raw_esp_source_forgery','native_macos_windows_clients'],'resources_cleaned':cleaned}
    print(json.dumps(result));return 0 if result['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
