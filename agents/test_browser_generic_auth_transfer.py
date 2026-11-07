"""Manager-only approved HTTPS transfer; disposable rows and fake adapter boundary."""
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'
spec = importlib.util.spec_from_file_location('browser_provisioner_generic_test', ROOT / 'browser_provisioner.py')
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)
import browser_profile_lease as profiles

ORIGIN = 'https://auth.example.test'
POOL = ('program', 'example.test', 'blue')
OWNERS = (('owner-source', 'run-source'), ('owner-destination', 'run-destination'))
SECRET = 'test-secret-not-for-receipts'


def contract_file(tmp_path, *, origin=ORIGIN, cookie='__Host-token',
                  keys=('program-auth', 'other-auth'), pool=POOL):
    private = tmp_path / 'auth-site-contracts'
    private.mkdir(mode=0o700, exist_ok=True)
    name = manager._auth_contract_filename(pool)
    path = private / name
    path.write_text(json.dumps({
        'program': pool[0], 'auth_domain': pool[1], 'account_alias': pool[2],
        'disposable_fixture': False, 'allowed_origins': [origin],
        'check': {'url': origin + '/me', 'method': 'GET',
                  'principal_selector': '[data-testid="identity"]', 'expected_principal': 'blue'},
        'local_storage_keys': list(keys),
        'cookie_selector': {'name': cookie, 'domain': 'auth.example.test', 'path': '/'},
    }))
    path.chmod(0o600)
    return path


def rows(tmp_path, monkeypatch):
    monkeypatch.setattr(manager, 'STATE', tmp_path / 'manager.sqlite')
    original, infos = [], []
    with manager.db() as db, profiles.connect(tmp_path / 'browser_profile_leases.sqlite') as leases:
        profiles.init_db(leases)
        for side, (agent, run) in zip(('source', 'destination'), OWNERS):
            profile = tmp_path / side
            profile.mkdir()
            launch = tmp_path / (side + '.launch.json')
            info = {'cdp_url': 'http://127.0.0.1:9222/private',
                    'control_socket': str(tmp_path / (side + '.sock')),
                    'process_identity': {'pid': 77}, 'unit_invocation': side + '-inv',
                    'control_mode': 'pipe-fenced'}
            manager.private_json(launch, info)
            db.execute('INSERT INTO browsers (lease_id,browser_id,program,account,auth_domain,agent_id,run_id,purpose,unit,profile_dir,launch_file,state,last_activity,created,updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (side, side, POOL[0], POOL[2], POOL[1], agent, run, 'test', side + '-unit', str(profile), str(launch), 'running', 1, 1, 1))
            leases.execute('INSERT INTO browser_profile_leases (lease_id,program,account_alias,auth_domain,owner_agent_id,owner_run_id,purpose,profile_dir,status,browser_status,cdp_url,service_unit,created_at,heartbeat_at,expires_at,manager_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                           (side, POOL[0], POOL[2], POOL[1], agent, run, 'test', str(profile), 'active', 'running', info['cdp_url'], side + '-unit', 1, 1, 9999999999, manager.manager_id()))
            original.append(db.execute('SELECT * FROM browsers WHERE lease_id=?', (side,)).fetchone())
            infos.append(info)
    monkeypatch.setattr(manager, '_transfer_candidates', lambda *args, **kwargs: [(r, i, side) for r, i, side in zip(original, infos, ('source', 'destination'))])
    monkeypatch.setattr(manager, 'unit_active', lambda unit: True)
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: unit.removesuffix('-unit') + '-inv')
    monkeypatch.setattr(manager, 'process_identity', lambda pid: {'pid': pid})
    return original, infos


def transfer(*, origin=ORIGIN, source_owner=OWNERS[0], destination_owner=OWNERS[1]):
    return manager.manager_approved_auth_transfer('source', 'destination', origin=origin,
        source_owner_agent_id=source_owner[0], source_owner_run_id=source_owner[1],
        destination_owner_agent_id=destination_owner[0], destination_owner_run_id=destination_owner[1])


def test_approved_check_url_and_selector_are_literal_not_nested_substitutions(tmp_path, monkeypatch):
    path = contract_file(tmp_path)
    data = json.loads(path.read_text())
    data['check']['url'] = ORIGIN + '/SELECTOR'
    data['check']['principal_selector'] = '[data-testid="URL"]'
    path.write_text(json.dumps(data))
    monkeypatch.setattr(manager, 'STATE', tmp_path / 'manager.sqlite')
    contract = manager._approved_site_contract(POOL, ORIGIN)
    expression = manager._fixture_check_expression(contract)
    assert 'fetch("https://auth.example.test/SELECTOR"' in expression
    assert 'querySelector("[data-testid=\\"URL\\"]")' in expression
    assert 'new DOMParser()' in expression
    assert "credentials: 'same-origin'" in expression


def test_json_principal_expression_extracts_only_exact_top_level_string(tmp_path, monkeypatch):
    path = contract_file(tmp_path)
    data = json.loads(path.read_text())
    del data['check']['principal_selector']
    data['check']['principal_json_key'] = 'id'
    data['check']['expected_principal'] = 'owned-id'
    data['check']['url'] = ORIGIN + '/1/member/me'
    path.write_text(json.dumps(data))
    monkeypatch.setattr(manager, 'STATE', tmp_path / 'manager.sqlite')
    contract = manager._approved_site_contract(POOL, ORIGIN)
    expression = manager._fixture_check_expression(contract)
    assert 'fetch("https://auth.example.test/1/member/me"' in expression
    assert "redirect: 'manual'" in expression
    assert "credentials: 'same-origin'" in expression
    assert 'new DOMParser()' not in expression
    negative_expression = manager._fixture_check_expression(contract, omit_credentials=True)
    assert "credentials: 'omit'" in negative_expression
    assert "credentials: 'same-origin'" not in negative_expression
    assert 'new DOMParser()' not in negative_expression
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is needed to execute browser-side expression offline')
    runtime = '''
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const logs = [];
console.log = (...args) => logs.push(args.join(' '));
globalThis.fetch = async (url, options) => {
  if (url !== input.url || options.redirect !== 'manual' || options.credentials !== 'same-origin')
    throw new Error('wrong fetch boundary');
  return {url, status: input.status, type: input.type || 'basic',
          json: async () => JSON.parse(input.body)};
};
(async () => {
  const result = await eval(input.expression);
  process.stdout.write(JSON.stringify({result, logs}));
})().catch(error => {process.stderr.write(error.message); process.exitCode = 1});
'''
    cases = [
        ('exact', '{"id":"owned-id","secret":"raw-value"}', 200, 'basic', 'owned-id', True),
        ('missing', '{"username":"owned-id","secret":"raw-value"}', 200, 'basic', '', False),
        ('nested', '{"account":{"id":"owned-id"}}', 200, 'basic', '', False),
        ('number', '{"id":123}', 200, 'basic', '', False),
        ('null', '{"id":null}', 200, 'basic', '', False),
        ('array', '[{"id":"owned-id"}]', 200, 'basic', '', False),
        ('malformed', '{"id":"raw-value",', 200, 'basic', '', False),
        ('html', '<div>raw-value</div>', 200, 'basic', '', False),
        ('whitespace differs', '{"id":" owned-id "}', 200, 'basic', ' owned-id ', False),
        ('redirect', '{"id":"owned-id"}', 302, 'opaqueredirect', '', False),
    ]
    for label, body, status, response_type, principal, valid in cases:
        reply = subprocess.run([node, '-e', runtime], input=json.dumps({
            'expression': expression, 'url': contract.check_url,
            'body': body, 'status': status, 'type': response_type,
        }), text=True, capture_output=True, check=True)
        observation = json.loads(reply.stdout)
        assert observation['logs'] == [], label
        assert observation['result']['principal'] == principal, label
        assert manager._fixture_verified_observation(contract, observation['result']) is valid, label
        assert 'raw-value' not in reply.stderr, label


@pytest.mark.parametrize('extra_destination_storage', [False, True])
@pytest.mark.parametrize('parent_domain_cookie', [False, True])
@pytest.mark.parametrize('session_store', [False, True])
@pytest.mark.parametrize('mode', ['selected-cookie', 'exact-origin'])
def test_approved_https_transfer_uses_manager_contract_and_native_principal(tmp_path, monkeypatch,
                                                                            extra_destination_storage,
                                                                            parent_domain_cookie,
                                                                            session_store, mode, import_fault=None,
                                                                            source_session_store=False,
                                                                            exact_host_cookie=None, scope_leak=False,
                                                                            source_scope_flip=False,
                                                                            mint_on_negative=False,
                                                                            mint_even_with_omit=False,
                                                                            destination_authenticated=False,
                                                                            post_import_session_store=False,
                                                                            post_import_unrelated_local_store=False,
                                                                            invalidate_source_on_recipient_failure=False):
    path = contract_file(tmp_path)
    if mode == 'exact-origin':
        contract = json.loads(path.read_text())
        del contract['local_storage_keys']
        del contract['cookie_selector']
        contract['state_mode'] = 'exact-origin'
        path.write_text(json.dumps(contract))
    rows(tmp_path, monkeypatch)
    state = {'source': {'cookie': True, 'parent_source': mode == 'exact-origin',
                        'exact_host': bool(exact_host_cookie),
                        'storage': {} if mode == 'exact-origin' else {'program-auth': SECRET, 'other-auth': 'opaque'},
                        'session_store': source_session_store,
                        'available': True, 'quarantined': False},
             'destination': {'cookie': destination_authenticated, 'exact_host': False,
                             'storage': {'unrelated-login': 'previous'} if extra_destination_storage else {},
                             'available': True, 'quarantined': False,
                             'parent_cookie': parent_domain_cookie,
                             'session_store': session_store}}
    calls = []
    old = 'http://127.0.0.1:9222/private'
    new = 'http://127.0.0.1:9222/rotated'
    class Reply:
        def __init__(self, payload): self.payload = payload
        def raise_for_status(self): pass
        def json(self): return self.payload
    class Client:
        def __init__(self, *, transport, timeout): self.side = Path(transport.uds).stem
        def post(self, url, json):
            action = url.rsplit('/', 1)[-1]
            s = state[self.side]
            calls.append((self.side, action))
            if action == 'begin':
                s['available'] = False
                s['binding'] = {k: json[k] for k in ('transaction', 'owner', 'generation')}
                assert json['owner'] == self.side and json['generation'] == old
                return Reply({'ticket': self.side})
            assert json['ticket'] == self.side
            assert all(json[k] == v for k, v in s['binding'].items())
            if action == 'status': return Reply({'phase': s.get('phase', 'pending'), 'cdp_url': new})
            if action == 'end':
                s['quarantined'] = self.side == 'destination'
                s['available'] = self.side == 'source'
                return Reply({'ended': True})
            if action == 'commit': s['rotated'] = True; return Reply({'quarantined': True, 'cdp_url': new})
            if action == 'activate': s['phase'] = 'activated'; s['quarantined'] = False; return Reply({'activated': True})
            if action == 'finalize': s['phase'] = 'finalized'; s['available'] = True; return Reply({'finalized': True})
            if action == 'abort': s['available'] = True; return Reply({'aborted': True})
            if action == 'call':
                method = json['method']
                params = json['params']
                calls.append((self.side, method))
                if method == 'Network.getAllCookies':
                    cookie = {'domain': 'auth.example.test', 'name': '__Host-token', 'path': '/',
                              'httpOnly': True, 'secure': True, 'value': SECRET,
                              'session': True, 'sameSite': 'Lax'}
                    parent = {'domain': '.example.test', 'name': 'old-auth', 'path': '/',
                              'value': 'previous', 'httpOnly': True, 'secure': True,
                              'session': False, 'expires': 2000000000, 'sameSite': 'Strict'}
                    plain = {'domain': (('auth.example.test' if s.get('scope_flipped') else exact_host_cookie)
                                        if self.side == 'source' else ORIGIN.removeprefix('https://')),
                             'name': 'session', 'path': '/',
                             'value': SECRET, 'httpOnly': True, 'secure': True,
                             'session': False, 'expires': 2000000000, 'sameSite': 'Strict'}
                    anonymous = {'domain': 'auth.example.test', 'name': 'dsc', 'path': '/',
                                 'httpOnly': True, 'secure': True, 'value': 'anonymous-only',
                                 'session': True, 'sameSite': 'Lax'}
                    return Reply({'result': {'cookies': ([cookie] if s['cookie'] else []) +
                                             ([parent] if s.get('parent_cookie') or s.get('parent_source') else []) +
                                             ([plain] if s['exact_host'] else []) +
                                             ([anonymous] if s.get('anonymous_cookie') else [])}})
                if method == 'Network.getCookies':
                    assert all(url.startswith('https://probe.auth.example.test/') for url in params['urls'])
                    return Reply({'result': {'cookies': (None if scope_leak == 'malformed' else
                                              [{'name': 'session', 'path': '/'}]
                                              if scope_leak and s['exact_host'] else [])}})
                if method == 'Network.setCookies':
                    assert params['cookies'][0]['value'] == SECRET
                    if mode == 'exact-origin':
                        assert len(params['cookies']) == (3 if exact_host_cookie else 2)
                        assert 'domain' not in params['cookies'][0]
                        assert params['cookies'][1]['domain'] == '.example.test'
                        assert params['cookies'][1]['expires'] == 2000000000
                        if exact_host_cookie:
                            assert params['cookies'][2]['name'] == 'session'
                            assert 'domain' not in params['cookies'][2]
                            assert params['cookies'][2]['url'] == ORIGIN + '/'
                            assert params['cookies'][2]['expires'] == 2000000000
                            s['exact_host'] = True
                        s['parent_source'] = True
                    s['cookie'] = True
                    return Reply({'result': {}})
                if method == 'Network.deleteCookies':
                    if import_fault == 'delete-fails':
                        raise httpx.ReadError(SECRET)
                    if params['name'] == '__Host-token': s['cookie'] = False
                    if params['name'] == 'old-auth': s['parent_source'] = False
                    if params['name'] == 'session': s['exact_host'] = False
                    return Reply({'result': {}})
                assert method == 'Runtime.evaluate'
                expr = params['expression']
                if expr == 'location.origin': value = ORIGIN
                elif expr == 'location.href': value = ORIGIN + '/app'
                elif expr == 'localStorage.length':
                    calls.append((self.side, 'localStorage.length'))
                    value = len(s['storage'])
                elif expr == 'sessionStorage.length':
                    calls.append((self.side, 'sessionStorage.length'))
                    value = int(s.get('session_store', False))
                elif expr == 'Object.entries(localStorage)': value = list(s['storage'].items())
                elif expr.startswith('(async () => {'):
                    omitted = "credentials: 'omit'" in expr
                    calls.append((self.side, 'app-check-omit' if omitted else 'app-check-same-origin'))
                    if self.side == 'destination' and not s['cookie'] and (
                            (mint_even_with_omit and omitted) or (mint_on_negative and not omitted)):
                        s['anonymous_cookie'] = True
                    auth = s['cookie'] and (s.get('parent_source') if mode == 'exact-origin'
                                            else s['storage'].get('program-auth') == SECRET)
                    if self.side == 'destination' and import_fault and s['cookie']:
                        auth = False
                        if post_import_session_store:
                            s['session_store'] = True
                        if post_import_unrelated_local_store:
                            s['storage']['unrelated-login'] = 'post-import'
                        if invalidate_source_on_recipient_failure:
                            state['source']['cookie'] = False
                    if self.side == 'destination' and source_scope_flip and auth:
                        state['source']['scope_flipped'] = True
                    value = {'url': ORIGIN + '/me', 'status': 200 if auth else 401,
                             'redirected': False, 'principal': 'blue' if auth else 'guest'}
                elif expr.startswith('localStorage.getItem('):
                    key = __import__('json').loads(expr[len('localStorage.getItem('):-1])
                    value = s['storage'].get(key)
                elif expr.startswith('localStorage.setItem('):
                    key, val = __import__('json').loads('[' + expr[len('localStorage.setItem('):-1] + ']')
                    s['storage'][key] = val; value = None
                elif expr.startswith('localStorage.removeItem('):
                    key = __import__('json').loads(expr[len('localStorage.removeItem('):-1])
                    s['storage'].pop(key, None); value = None
                else: raise AssertionError(expr)
                return Reply({'result': {'result': {'value': value}}})
            raise AssertionError(action)
        def get(self, url):
            assert url.endswith('/identity')
            s = state[self.side]
            return Reply({'available': s['available'], 'quarantined': s['quarantined'],
                          'process_identity': {'pid': 77},
                          'cdp_url': new if self.side == 'destination' and s.get('rotated') else old})
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
    monkeypatch.setattr(httpx, 'HTTPTransport', lambda *, uds: type('Transport', (), {'uds': uds})())
    monkeypatch.setattr(httpx, 'Client', Client)
    monkeypatch.setattr(httpx, 'get', lambda url, **kwargs: Reply({
        'webSocketDebuggerUrl': new.replace('http:', 'ws:') + '/devtools/browser'}))
    stops = []
    if import_fault or source_scope_flip:
        monkeypatch.setattr(manager, 'stop_recorded',
                            lambda row: stops.append(row['lease_id']) or
                            (import_fault == 'reject' or source_scope_flip))
    result = transfer()
    if destination_authenticated:
        assert result == {'status': 'auth-clone-unavailable', 'reason': 'destination-not-empty'}
        assert ('destination', 'app-check-omit') not in calls
        assert ('destination', 'app-check-same-origin') not in calls
        assert ('destination', 'Network.setCookies') not in calls
        return
    if mint_even_with_omit:
        assert result == {'status': 'auth-clone-unavailable', 'reason': 'destination-not-empty'}
        assert ('destination', 'app-check-omit') in calls
        assert ('destination', 'Network.setCookies') not in calls
        return
    if source_session_store:
        assert result == {'status': 'auth-clone-unavailable', 'reason': 'source-storage-unverified'}
        assert ('destination', 'commit') not in calls
        assert state['source']['cookie'] and state['source']['parent_source']
        return
    if post_import_session_store or post_import_unrelated_local_store:
        assert result['status'] != 'auth-transferred'
        assert ('destination', 'commit') not in calls
        assert stops == ['destination'], 'residual browser storage must dispose the recipient'
        return
    if invalidate_source_on_recipient_failure:
        assert result['status'] != 'auth-transferred'
        assert ('destination', 'commit') not in calls
        assert calls.count(('source', 'app-check-same-origin')) >= 2
        assert stops == ['destination'], 'unproved source must dispose the imported recipient'
        return
    if import_fault:
        assert state['source']['cookie'] and state['source']['parent_source']
        assert state['source']['storage'] == {}
        assert ('destination', 'commit') not in calls
        assert SECRET not in str(result)
        if import_fault == 'reject':
            assert result == {'status': 'auth-clone-unavailable',
                              'reason': 'destination-cookie-unverified' if scope_leak else 'destination-app-check-failed'}
            assert not state['destination']['cookie'] and not state['destination']['parent_source']
            assert not state['destination']['exact_host']
        else:
            assert stops == ['destination']
            assert result['status'] != 'auth-transferred'
            assert result['destination'] == 'cleanup-incomplete'
        return
    if extra_destination_storage or parent_domain_cookie or session_store:
        assert result == {'status': 'auth-clone-unavailable', 'reason': 'destination-not-empty'}
        assert ('destination', 'app-check-omit') not in calls
        assert ('destination', 'app-check-same-origin') not in calls
        assert ('destination', 'commit') not in calls
        assert state['destination']['storage'] == ({'unrelated-login': 'previous'}
                                                  if extra_destination_storage else {})
        assert state['source']['storage'] == ({} if mode == 'exact-origin' else
                                               {'program-auth': SECRET, 'other-auth': 'opaque'})
        return
    if source_scope_flip:
        assert result == {'status': 'auth-clone-unavailable', 'reason': 'source-changed',
                          'source': 'owner-preserved', 'destination': 'disposed'}
        assert stops == ['destination']
        assert ('destination', 'commit') not in calls
        assert not state['destination']['cookie'] and not state['destination']['exact_host']
        assert not state['destination']['parent_source']
        return
    assert result == {'status': 'auth-transferred'}
    assert ('source', 'app-check-same-origin') in calls
    assert ('destination', 'app-check-same-origin') in calls
    assert ('source', 'app-check-omit') not in calls
    if mint_on_negative:
        before_check = calls.index(('destination', 'app-check-omit'))
        before_import = calls.index(('destination', 'Network.setCookies'))
        assert calls.index(('destination', 'Network.getAllCookies')) < before_check
        assert calls.index(('destination', 'localStorage.length')) < before_check
        assert calls.index(('destination', 'sessionStorage.length')) < before_check
        assert calls[before_check:before_import].count(('destination', 'Network.getAllCookies')) >= 1
        assert ('destination', 'localStorage.length') in calls[before_check:before_import]
        assert ('destination', 'sessionStorage.length') in calls[before_check:before_import]
        assert not state['destination'].get('anonymous_cookie')
    assert ('source', 'end') in calls and ('destination', 'finalize') in calls
    assert state['source']['storage'] == ({} if mode == 'exact-origin' else
                                           {'program-auth': SECRET, 'other-auth': 'opaque'})
    assert state['source']['parent_source'] == (mode == 'exact-origin')
    assert state['source']['exact_host'] == bool(exact_host_cookie)
    assert state['destination']['exact_host'] == bool(exact_host_cookie)
    assert state['destination']['storage'] == state['source']['storage']
    assert SECRET not in str(result)


def test_initial_empty_recipient_negative_check_does_not_remint_anonymous_cookie(tmp_path, monkeypatch):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, False, False, False, 'exact-origin', mint_on_negative=True)


def test_selected_cookie_recipient_negative_check_does_not_remint_anonymous_cookie(tmp_path, monkeypatch):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, False, False, False, 'selected-cookie', mint_on_negative=True)


def test_initial_empty_recipient_refuses_cookie_minted_even_with_omit(tmp_path, monkeypatch):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, False, False, False, 'exact-origin', mint_even_with_omit=True)


def test_initial_recipient_with_auth_cookie_refuses_before_any_negative_check(tmp_path, monkeypatch):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, False, False, False, 'exact-origin', destination_authenticated=True)


def test_initial_recipient_with_storage_refuses_before_any_negative_check(tmp_path, monkeypatch):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, True, False, False, 'exact-origin')


def test_post_import_failure_with_new_session_storage_disposes_recipient(tmp_path, monkeypatch):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, False, False, False, 'exact-origin', import_fault='reject',
        post_import_session_store=True)

def test_selected_cookie_failure_with_new_unrelated_local_storage_disposes_recipient(tmp_path, monkeypatch):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, False, False, False, 'selected-cookie', import_fault='reject',
        post_import_unrelated_local_store=True)

def test_failed_recipient_check_rechecks_invalidated_source_before_rollback(tmp_path, monkeypatch):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, False, False, False, 'exact-origin', import_fault='reject',
        invalidate_source_on_recipient_failure=True)

@pytest.mark.parametrize('fault', ['reject', 'delete-fails'])
def test_exact_origin_post_import_rollback_or_uncertain_cleanup(tmp_path, monkeypatch, fault):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, False, False, False, 'exact-origin', fault)


def test_exact_origin_refuses_unsupported_source_session_storage(tmp_path, monkeypatch):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, False, False, False, 'exact-origin',
        source_session_store=True)

@pytest.mark.parametrize('domain', ['auth.example.test', '.auth.example.test'])
def test_exact_origin_unprefixed_cookie_import_and_scope_readback(tmp_path, monkeypatch, domain):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, False, False, False, 'exact-origin', exact_host_cookie=domain)

def test_exact_origin_refuses_source_scope_change_after_import(tmp_path, monkeypatch):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, False, False, False, 'exact-origin',
        exact_host_cookie='.auth.example.test', source_scope_flip=True)

@pytest.mark.parametrize('scope_leak', [True, 'malformed'])
def test_exact_origin_refuses_recipient_cookie_visible_at_child_host(tmp_path, monkeypatch, scope_leak):
    test_approved_https_transfer_uses_manager_contract_and_native_principal(
        tmp_path, monkeypatch, False, False, False, 'exact-origin',
        exact_host_cookie='auth.example.test', scope_leak=scope_leak, import_fault='reject')


@pytest.mark.parametrize('change', ['cross-program', 'owner-mismatch', 'caller-owner-mismatch'])
def test_cross_pool_or_owner_never_reaches_adapter(tmp_path, monkeypatch, change):
    contract_file(tmp_path)
    rows(tmp_path, monkeypatch)
    # An invalid manager/canonical pair is rejected before any socket contact.
    monkeypatch.setattr(manager, '_transfer_candidates',
                        lambda *args, **kwargs: pytest.fail('must not probe browser'))
    if change == 'cross-program':
        with manager.db() as store, profiles.connect(tmp_path / 'browser_profile_leases.sqlite') as leases:
            store.execute("UPDATE browsers SET program='other' WHERE lease_id='destination'")
            leases.execute("UPDATE browser_profile_leases SET program='other' WHERE lease_id='destination'")
        assert transfer()['reason'] == 'manager-identity-unverified'
    elif change == 'owner-mismatch':
        with profiles.connect(tmp_path / 'browser_profile_leases.sqlite') as leases:
            leases.execute("UPDATE browser_profile_leases SET owner_agent_id='another' WHERE lease_id='source'")
        assert transfer()['reason'] == 'manager-identity-unverified'
    else:
        assert transfer(source_owner=('another', OWNERS[0][1]))['reason'] == 'manager-identity-unverified'


@pytest.mark.parametrize('origin', [
    'http://auth.example.test', 'https://auth.example.test/path',
    'https://auth.example.test:443', 'https://evil.example.test',
])
def test_origin_mismatch_or_downgrade_never_transfers(tmp_path, monkeypatch, origin):
    contract_file(tmp_path)
    rows(tmp_path, monkeypatch)
    if origin != 'https://evil.example.test':
        monkeypatch.setattr(manager, '_transfer_candidates',
                            lambda *args, **kwargs: pytest.fail('invalid origin probed browser'))
    assert transfer(origin=origin)['reason'] == 'site-contract-unavailable'


def test_missing_manager_contract_refuses_before_adapter(tmp_path, monkeypatch):
    rows(tmp_path, monkeypatch)
    assert transfer()['reason'] == 'site-contract-unavailable'


def test_wrong_pool_contract_cannot_be_selected(tmp_path, monkeypatch):
    path = contract_file(tmp_path)
    data = json.loads(path.read_text())
    data['account_alias'] = 'different'
    path.write_text(json.dumps(data))
    rows(tmp_path, monkeypatch)
    assert transfer()['reason'] == 'site-contract-unavailable'


@pytest.mark.parametrize('unsupported', ['store', 'cookie'])
def test_unsupported_store_or_cookie_contract_refused(tmp_path, monkeypatch, unsupported):
    path = contract_file(tmp_path)
    data = json.loads(path.read_text())
    if unsupported == 'store':
        data['session_storage_keys'] = ['session']
    else:
        data['cookie_selector']['name'] = 'session; injected'
    path.write_text(json.dumps(data))
    rows(tmp_path, monkeypatch)
    assert transfer()['reason'] == 'site-contract-unavailable'


def test_single_session_policy_rejects_before_health_probe(tmp_path, monkeypatch):
    contract_file(tmp_path)
    rows(tmp_path, monkeypatch)
    with profiles.connect(tmp_path / 'browser_profile_leases.sqlite') as leases:
        profiles.init_resource_policy(leases)
        leases.execute('INSERT INTO browser_program_concurrency_policy VALUES (?,?,?,?,?)',
                       (POOL[0], 'single', 'manager', 'reviewed-test', 1))
    monkeypatch.setattr(manager, '_transfer_candidates',
                        lambda *args, **kwargs: pytest.fail('single policy must precede browser health'))
    assert transfer()['reason'] == 'single-browser-policy'
