from __future__ import annotations

import sqlite3
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event

from fastapi.testclient import TestClient
import pytest

from vpn_manager.app import ALLOWED_ORIGIN, create_app
from vpn_manager.bootstrap import bootstrap
from vpn_manager.security import COOKIE_NAME, hash_password, token_hash, utc_text
from vpn_manager.store import DeviceQuotaExceeded, Store


@pytest.fixture()
def database(tmp_path):
    path = tmp_path / 'manager.sqlite3'
    bootstrap(str(path), [
        {'username':'adminone','password':'correct-horse-admin-one','role':'admin','networks':['home','work']},
        {'username':'member','password':'correct-horse-member','role':'user','networks':['work']},
    ])
    return path


def client_for(database, address='192.0.2.10'):
    return TestClient(create_app(database),base_url=ALLOWED_ORIGIN,client=(address,12345))


def login(client,username='adminone',password='correct-horse-admin-one'):
    response=client.post('/api/auth/login',headers={'Origin':ALLOWED_ORIGIN},json={'username':username,'password':password})
    assert response.status_code==200,response.text
    return response.json()['csrf_token']


def csrf(token):
    return {'Origin':ALLOWED_ORIGIN,'X-CSRF-Token':token}


def test_password_login_requires_no_device_and_preserves_cookie_controls(database):
    client=client_for(database)
    assert client.get('/api/auth/me').status_code==401
    assert client.get('/health').status_code==200
    token=login(client)
    response=client.get('/api/auth/me')
    assert response.json()['networks']==['home','work']
    assert 'csrf_token' not in response.json()
    assert client.post('/api/auth/logout',headers=csrf(token)).status_code==200
    assert client.get('/api/auth/me').status_code==401
    response=client.post('/api/auth/login',headers={'Origin':ALLOWED_ORIGIN},json={'username':'member','password':'correct-horse-member'})
    cookie=response.headers['set-cookie'].lower()
    assert 'secure' in cookie and 'httponly' in cookie and 'samesite=lax' in cookie
    assert response.json()['user']['networks']==['work']


def test_session_refresh_origin_csrf_and_single_session_logout(database):
    first,second=client_for(database),client_for(database)
    old=login(first)
    login(second)
    saved=first.cookies.get(COOKIE_NAME)
    assert first.post('/api/auth/refresh').status_code==403
    assert first.post('/api/auth/refresh',headers={'Origin':'https://evil.example'}).status_code==403
    refresh=first.post('/api/auth/refresh',headers={'Origin':ALLOWED_ORIGIN})
    fresh=refresh.json()['csrf_token']
    assert fresh!=old
    assert first.post('/api/auth/logout',headers=csrf(old)).status_code==403
    assert first.post('/api/auth/logout',headers=csrf(fresh)).status_code==200
    first.cookies.set(COOKIE_NAME,saved)
    assert first.get('/api/auth/me').status_code==401
    assert second.get('/api/auth/me').status_code==200


def test_role_and_cross_account_device_boundaries(database):
    admin,member=client_for(database),client_for(database)
    a=login(admin)
    m=login(member,'member','correct-horse-member')
    assert member.get('/api/admin/users').status_code==403
    assert member.get('/api/admin/audit').status_code==403
    assert member.post('/api/admin/users/member/devices',headers=csrf(m),json={'device_id':'member-pc'}).status_code==403
    assert admin.post('/api/admin/users/member/devices',headers=csrf(a),json={'device_id':'member-pc'}).status_code==201
    assert member.get('/api/devices').json()[0]['device_id']=='member-pc'
    assert member.post('/api/devices/admin-pc/remove',headers=csrf(m)).status_code==404
    assert admin.post('/api/admin/users/member/devices/member-pc/remove',headers=csrf(a)).json()['state']=='removed'
    # 设备只是记录，移除记录不能伪装为该设备已被阻止登录。
    assert member.get('/api/auth/me').status_code==200


@pytest.mark.parametrize('change',[{'password':'a-brand-new-password'},{'role':'admin','networks':['home']},{'active':False}])
def test_account_change_revokes_all_sessions_and_reenable_does_not_restore(database,change):
    admin,member=client_for(database),client_for(database)
    a=login(admin)
    login(member,'member','correct-horse-member')
    assert admin.patch('/api/admin/users/member',headers=csrf(a),json=change).status_code==200
    assert member.get('/api/auth/me').status_code==401
    if change.get('active') is False:
        assert admin.patch('/api/admin/users/member',headers=csrf(a),json={'active':True}).status_code==200
        assert member.get('/api/auth/me').status_code==401
    assert admin.get('/api/auth/me').status_code==200


def test_gateway_projection_is_queued_atomically_and_never_reported_as_applied(database):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    key = X25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    admin, member = TestClient(create_app(database, gateway_public_key=public), base_url=ALLOWED_ORIGIN), client_for(database)
    token = login(admin)
    assert login(member, 'member', 'correct-horse-member')
    assert admin.patch('/api/admin/users/member', headers=csrf(token), json={'password':'a-brand-new-password','networks':['work']}).status_code == 200
    assert member.get('/api/auth/me').status_code == 401
    store = Store(database)
    job = store.pending_gateway_jobs()[0]
    assert job['username'] == 'member' and job['generation'] == 1 and job['state'] == 'queued'
    assert 'a-brand-new-password' not in json.dumps(job)
    status = admin.get('/api/admin/gateway-status').json()
    assert next(item for item in status if item['username'] == 'member')['state'] == 'queued'
    store.record_gateway_reply(job['operation_id'], 'member', 1, 'failed', 'gateway_rejected')
    status = admin.get('/api/admin/gateway-status').json()
    assert next(item for item in status if item['username'] == 'member')['state'] == 'failed'


def test_user_role_is_work_only_across_create_update_bootstrap_and_downgrade(tmp_path):
    database = tmp_path / 'manager.sqlite3'
    bootstrap(str(database), [
        {'username': 'adminone', 'password': 'correct-horse-admin-one', 'role': 'admin', 'networks': ['home', 'work']},
        {'username': 'admintwo', 'password': 'correct-horse-admin-two', 'role': 'admin', 'networks': ['home']},
        {'username': 'member', 'password': 'correct-horse-member', 'role': 'user', 'networks': ['work']},
    ])
    client = client_for(database)
    token = login(client)
    rejected = client.post('/api/admin/users', headers=csrf(token), json={
        'username': 'badmember', 'password': 'correct-horse-bad-member', 'role': 'user', 'networks': ['home'],
    })
    assert rejected.status_code == 422
    assert Store(database).find_user('badmember') is None
    assert client.patch('/api/admin/users/member', headers=csrf(token), json={'networks': ['home']}).status_code == 422
    assert client.get('/api/auth/me').status_code == 200
    downgraded = client.patch('/api/admin/users/adminone', headers=csrf(token), json={'role': 'user'})
    assert downgraded.status_code == 200
    assert downgraded.json()['role'] == 'user'
    assert downgraded.json()['networks'] == ['work']
    assert client.get('/api/auth/me').status_code == 401
    with pytest.raises(ValueError, match='无效账户记录'):
        bootstrap(str(tmp_path / 'invalid.sqlite3'), [
            {'username': 'badmember', 'password': 'correct-horse-bad-member', 'role': 'user', 'networks': ['home']},
        ])


def test_role_downgrade_revokes_sessions_and_queues_gateway_policy(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    database = tmp_path / 'manager.sqlite3'
    key = X25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    bootstrap(str(database), [
        {'username': 'adminone', 'password': 'correct-horse-admin-one', 'role': 'admin', 'networks': ['home', 'work']},
        {'username': 'admintwo', 'password': 'correct-horse-admin-two', 'role': 'admin', 'networks': ['work']},
    ], public)
    client = TestClient(create_app(database, gateway_public_key=public), base_url=ALLOWED_ORIGIN)
    token = login(client)
    response = client.patch('/api/admin/users/adminone', headers=csrf(token), json={'role': 'user'})
    assert response.status_code == 200 and response.json()['networks'] == ['work']
    assert client.get('/api/auth/me').status_code == 401
    status = Store(database).gateway_status('adminone')
    assert status['generation'] == 2 and status['state'] == 'queued'


def test_last_admin_cannot_be_removed_and_errors_do_not_echo_password(database):
    client=client_for(database)
    a=login(client)
    assert client.patch('/api/admin/users/adminone',headers=csrf(a),json={'role':'user'}).status_code==409
    assert client.post('/api/admin/users/adminone/deactivate',headers=csrf(a)).status_code==409
    secret='do-not-echo-this-secret'
    response=client.post('/api/auth/login',headers={'Origin':ALLOWED_ORIGIN},json={'username':'member','password':secret,'extra':'invalid'})
    assert response.status_code==422 and secret not in response.text
    assert client.post('/api/admin/users',headers={'Origin':ALLOWED_ORIGIN},json={'username':'newuser','password':secret,'role':'user','networks':['work']}).status_code==403


def test_pair_source_and_account_limits_ignore_spoofed_forwarding_headers(database):
    app=create_app(database)
    client=TestClient(app,base_url=ALLOWED_ORIGIN,client=('192.0.2.11',12345))
    for i in range(5):
        r=client.post('/api/auth/login',headers={'Origin':ALLOWED_ORIGIN,'X-Forwarded-For':f'198.51.100.{i}'},json={'username':'member','password':'wrong-password'})
        assert r.status_code==401
    assert client.post('/api/auth/login',headers={'Origin':ALLOWED_ORIGIN},json={'username':'member','password':'correct-horse-member'}).status_code==429
    # 同一来源轮换账户名仍会耗尽来源桶。
    for i in range(24):
        r=client.post('/api/auth/login',headers={'Origin':ALLOWED_ORIGIN},json={'username':f'unknown{i}','password':'wrong-password'})
        assert r.status_code==401
    assert client.post('/api/auth/login',headers={'Origin':ALLOWED_ORIGIN},json={'username':'another','password':'wrong-password'}).status_code==429
    with Store(database).connect() as connection:
        addresses={r[0] for r in connection.execute("SELECT DISTINCT source_ip FROM audit_events WHERE action='login'")}
        assert addresses=={'192.0.2.11'}


def test_quota_is_atomic_and_removed_records_release_slots(database):
    store=Store(database)
    for i in range(9):store.register_device('member',f'pc-{i}')
    barrier=Barrier(2)
    def register(i):
        barrier.wait()
        try:
            Store(database).register_device('member',f'race-{i}')
            return 'added'
        except DeviceQuotaExceeded:return 'full'
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(register,(1,2)))==['added','full']
    store.remove_device('member','pc-0')
    store.register_device('member','replacement')
    assert sum(r['state']=='registered' for r in store.list_devices('member'))==10


@pytest.mark.parametrize('operation', ['create', 'update'])
def test_admin_revocation_wins_over_an_inflight_password_change(database, monkeypatch, operation):
    import vpn_manager.app as module
    first, second = client_for(database), client_for(database)
    first_csrf = login(first)
    assert first.post('/api/admin/users', headers=csrf(first_csrf), json={
        'username':'admintwo','password':'correct-horse-admin-two','role':'admin','networks':['work']
    }).status_code == 201
    second_csrf = login(second, 'admintwo', 'correct-horse-admin-two')
    entered, release = Event(), Event()
    original_hash = module.hash_password
    def paused_hash(value):
        result = original_hash(value)
        if value == 'inflight-change-password':
            entered.set()
            assert release.wait(10), '测试同步屏障超时'
        return result
    monkeypatch.setattr(module, 'hash_password', paused_hash)
    before = Store(database).find_user('member')['password_hash']
    def request():
        if operation == 'create':
            return first.post('/api/admin/users', headers=csrf(first_csrf), json={
                'username':'unwantedadmin','password':'inflight-change-password','role':'admin','networks':['home']
            })
        return first.patch('/api/admin/users/member', headers=csrf(first_csrf), json={'password':'inflight-change-password'})
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(request)
        try:
            assert entered.wait(10)
            assert second.patch('/api/admin/users/adminone', headers=csrf(second_csrf), json={'role':'user'}).status_code == 200
        finally:
            release.set()
        assert pending.result(timeout=10).status_code == 401
    assert Store(database).find_user('unwantedadmin') is None
    assert Store(database).find_user('member')['password_hash'] == before


@pytest.mark.parametrize('change', ['password', 'deactivate'])
def test_login_rechecks_credentials_and_account_state_before_committing(database, monkeypatch, change):
    import vpn_manager.app as module
    client = client_for(database)
    entered, release = Event(), Event()
    original_verify = module.verify_password
    def paused_verify(encoded, value):
        result = original_verify(encoded, value)
        entered.set()
        assert release.wait(10)
        return result
    monkeypatch.setattr(module, 'verify_password', paused_verify)
    replacement = hash_password('changed-during-login')
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(client.post, '/api/auth/login', headers={'Origin':ALLOWED_ORIGIN}, json={'username':'member','password':'correct-horse-member'})
        try:
            assert entered.wait(10)
            with Store(database).write_transaction() as connection:
                if change == 'password':
                    connection.execute("UPDATE users SET password_hash=? WHERE username='member'", (replacement,))
                else:
                    connection.execute("UPDATE users SET active=0 WHERE username='member'")
        finally:
            release.set()
        assert pending.result(timeout=10).status_code == 401
    with Store(database).connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions WHERE username='member'").fetchone()[0] == 0


def test_account_limit_survives_source_rotation_and_pair_limit_is_atomic(database):
    app = create_app(database)
    for i in range(20):
        client = TestClient(app, base_url=ALLOWED_ORIGIN, client=(f'192.0.2.{i+1}',12345))
        assert client.post('/api/auth/login', headers={'Origin':ALLOWED_ORIGIN}, json={'username':'member','password':'wrong-password'}).status_code == 401
    client = TestClient(app, base_url=ALLOWED_ORIGIN, client=('192.0.2.100',12345))
    assert client.post('/api/auth/login', headers={'Origin':ALLOWED_ORIGIN}, json={'username':'member','password':'correct-horse-member'}).status_code == 429
    with Store(database).write_transaction() as connection:
        connection.execute("INSERT INTO login_attempts VALUES ('192.0.2.200','unknown',?,4)", (utc_text(),))
    barrier = Barrier(2)
    def try_login(_):
        client = TestClient(app, base_url=ALLOWED_ORIGIN, client=('192.0.2.200',12345))
        barrier.wait(timeout=10)
        return client.post('/api/auth/login', headers={'Origin':ALLOWED_ORIGIN}, json={'username':'unknown','password':'wrong-password'}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(try_login, (1,2))) == [401,429]


def create_legacy_database(path, version):
    password_hash=hash_password('correct-horse-legacy')
    with sqlite3.connect(path) as c:
        c.execute('CREATE TABLE schema_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
        c.execute("INSERT INTO schema_metadata VALUES ('schema_version',?)",(str(version),))
        c.execute('CREATE TABLE users(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,role TEXT NOT NULL,active INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)')
        c.execute('INSERT INTO users VALUES (?,?,?,1,?,?)',('legacy',password_hash,'admin',utc_text(),utc_text()))
        c.execute('CREATE TABLE user_networks(username TEXT,network TEXT,PRIMARY KEY(username,network))')
        c.execute("INSERT INTO user_networks VALUES ('legacy','work')")
        suffix=',device_id TEXT NOT NULL,web_certificate_id TEXT NOT NULL' if version>1 else ''
        c.execute('CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,username TEXT NOT NULL,csrf_hash TEXT NOT NULL,expires_at TEXT NOT NULL,revoked_at TEXT,created_at TEXT NOT NULL'+suffix+')')
        values=[token_hash('old-cookie'),'legacy','csrf','2099-01-01T00:00:00Z',None,utc_text()]+(['old-device','old-certificate'] if version>1 else [])
        c.execute('INSERT INTO sessions VALUES ('+','.join('?' for _ in values)+')',values)
        c.execute('CREATE TABLE devices(account_id TEXT,device_id TEXT,state TEXT,created_at TEXT,updated_at TEXT,PRIMARY KEY(account_id,device_id))')
        for device_id, state in [('old-active','active'),('old-revoked','revoked')]:
            c.execute('INSERT INTO devices VALUES (?,?,?,?,?)', ('legacy',device_id,state,utc_text(),utc_text()))
        c.execute('CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,occurred_at TEXT NOT NULL,actor TEXT,source_ip TEXT,action TEXT NOT NULL,target TEXT,outcome TEXT NOT NULL)')
        c.execute("INSERT INTO audit_events(occurred_at,actor,source_ip,action,target,outcome) VALUES (?,'legacy','192.0.2.1','historical_login','legacy','success')", (utc_text(),))
        if version == 3:
            # 证书旧表仅作为历史保留；新认证不读它。
            c.execute('CREATE TABLE device_certificates(certificate_id TEXT PRIMARY KEY,purpose TEXT,status TEXT)')
            c.execute("INSERT INTO device_certificates VALUES ('old-certificate','web','active')")


@pytest.mark.parametrize('version',[1,2,3])
def test_migration_retains_accounts_history_and_rejects_old_sessions(tmp_path,version):
    path=tmp_path/f'v{version}.sqlite3'
    create_legacy_database(path, version)
    app=create_app(path)
    client=TestClient(app,base_url=ALLOWED_ORIGIN)
    client.cookies.set(COOKIE_NAME,'old-cookie')
    assert client.get('/api/auth/me').status_code==401
    login(client,'legacy','correct-horse-legacy')
    Store(path).initialize()
    assert client.get('/api/auth/me').status_code==200
    with Store(path).connect() as c:
        assert c.execute("SELECT value FROM schema_metadata WHERE key='schema_version'").fetchone()[0]=='6'
        assert c.execute('SELECT revoked_at FROM sessions WHERE token_hash=?',(token_hash('old-cookie'),)).fetchone()[0]
        assert c.execute("SELECT COUNT(*) FROM audit_events WHERE action='authentication_schema_upgrade'").fetchone()[0]==1
        assert c.execute("SELECT COUNT(*) FROM audit_events WHERE action='historical_login'").fetchone()[0] == 1
        assert c.execute('SELECT COUNT(*) FROM devices').fetchone()[0] == 2
        records = {r['device_id']:r['state'] for r in c.execute('SELECT * FROM device_records')}
        assert records == {'old-active':'registered','old-revoked':'removed'}
        if version == 3:
            assert tuple(c.execute('SELECT * FROM device_certificates').fetchone()) == ('old-certificate','web','active')


def test_schema_v4_migrates_to_gateway_v6_without_projecting_existing_accounts(tmp_path):
    path = tmp_path / 'v4.sqlite3'
    create_legacy_database(path, 3)
    Store(path).initialize()
    with sqlite3.connect(path) as connection:
        connection.execute('DROP INDEX gateway_outbox_pending_idx')
        connection.execute('DROP TABLE gateway_outbox')
        connection.execute('DROP TABLE gateway_accounts')
        connection.execute("UPDATE schema_metadata SET value='4' WHERE key='schema_version'")
    Store(path).initialize()
    assert Store(path).gateway_status('legacy')['state'] == 'not_provisioned'
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT value FROM schema_metadata WHERE key='schema_version'").fetchone()[0] == '6'
        assert connection.execute("SELECT COUNT(*) FROM audit_events WHERE action='gateway_schema_upgrade'").fetchone()[0] == 1


def test_schema_v5_migration_normalizes_legacy_user_networks(tmp_path):
    path = tmp_path / 'v5.sqlite3'
    bootstrap(str(path), [{'username': 'member', 'password': 'correct-horse-member', 'role': 'user', 'networks': ['work']}])
    client = client_for(path)
    login(client, 'member', 'correct-horse-member')
    with Store(path).write_transaction() as connection:
        connection.execute("DELETE FROM user_networks WHERE username='member'")
        connection.execute("INSERT INTO user_networks(username,network) VALUES ('member','home')")
        connection.execute("UPDATE schema_metadata SET value='5' WHERE key='schema_version'")
    Store(path).initialize()
    assert Store(path).find_user('member')['networks'] == ['work']
    assert client.get('/api/auth/me').status_code == 401
    with Store(path).connect() as connection:
        assert connection.execute("SELECT value FROM schema_metadata WHERE key='schema_version'").fetchone()[0] == '6'
        assert connection.execute("SELECT COUNT(*) FROM audit_events WHERE action='user_network_policy_upgrade'").fetchone()[0] == 1


def test_migration_failure_rolls_back_schema_and_old_session_revocation(tmp_path, monkeypatch):
    path = tmp_path/'rollback.sqlite3'
    create_legacy_database(path, 3)
    with sqlite3.connect(path) as c:
        before = list(c.iterdump())
    def failing_audit(*args, **kwargs):
        raise RuntimeError('注入迁移失败')
    monkeypatch.setattr(Store, 'audit', staticmethod(failing_audit))
    with pytest.raises(RuntimeError, match='注入迁移失败'):
        Store(path).initialize()
    with sqlite3.connect(path) as c:
        assert list(c.iterdump()) == before
        assert c.execute('SELECT revoked_at FROM sessions').fetchone()[0] is None


def test_unknown_or_unversioned_database_is_rejected_without_schema_rewrite(tmp_path):
    path = tmp_path/'unknown.sqlite3'
    with sqlite3.connect(path) as c:
        c.execute('CREATE TABLE unrelated(value TEXT)')
    with pytest.raises(RuntimeError, match='缺少结构版本'):
        Store(path).initialize()
    with sqlite3.connect(path) as c:
        assert [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")] == ['unrelated']


def test_body_limit_static_headers_and_unconnected_gateway(database):
    from pathlib import Path
    client=TestClient(create_app(database,web_directory=Path(__file__).resolve().parents[1]/'web'),base_url=ALLOWED_ORIGIN)
    assert client.get('/').status_code==200
    assert client.get('/app.js').headers['cache-control']=='no-store'
    assert client.post('/api/auth/login',content='a'*17000).status_code==413
    assert client.get('/api/vpn/status').status_code==401
    login(client)
    response=client.get('/api/vpn/status')
    assert response.status_code==503 and response.json()['error']['code']=='gateway_unavailable'
