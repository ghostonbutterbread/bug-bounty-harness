"""Deterministic fixture activation/cancellation terminal-state tests."""
import importlib.util
import json
import traceback
from pathlib import Path

import httpx
import pytest
from agents.test_browser_auth_site_contract import write_fixture_contract

ROOT = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'
spec = importlib.util.spec_from_file_location('browser_provisioner_activation_fault', ROOT / 'browser_provisioner.py')
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)
import browser_profile_lease as profiles


@pytest.mark.parametrize('fault', ['before', 'after', 'lost-ack', None,
                                   'lost-finalize-ack', 'finalize-unproved',
                                   'secondary-stop', 'secondary-readback',
                                   'readback-exit', 'stop-exit', 'published-readback-exit',
                                   'published-readback-unavailable', 'published-interrupted-readback-exit',
                                   'published-fence-unavailable'])
@pytest.mark.parametrize('stop_succeeds', [True, False])
def test_activation_is_irreversible_only_after_verified_application(tmp_path, monkeypatch, fault, stop_succeeds):
    monkeypatch.setattr(manager, 'STATE', tmp_path / 'manager.sqlite')
    old = 'http://127.0.0.1:9222/old-private-token'
    new = 'http://127.0.0.1:9222/new-private-token'
    secret = 'fixture-secret-must-not-appear'
    origin = 'http://localhost:31337'
    write_fixture_contract(tmp_path, origin)
    rows, infos = [], []
    with manager.db() as db, profiles.connect(tmp_path / 'browser_profile_leases.sqlite') as leases:
        profiles.init_db(leases)
        for side in ('source', 'destination'):
            launch = tmp_path / (side + '.json')
            info = {'cdp_url': old, 'control_socket': str(tmp_path / (side + '.sock')),
                    'process_identity': {'pid': 77}, 'unit_invocation': side + '-inv'}
            manager.private_json(launch, info)
            db.execute('INSERT INTO browsers (lease_id,browser_id,program,account,auth_domain,agent_id,run_id,purpose,unit,profile_dir,launch_file,state,last_activity,created,updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (side, side, 'fixture', 'anon', 'fixture.invalid', 'agent', side + '-run',
                        'fixture', side + '-unit', str(tmp_path / side), str(launch), 'running', 1, 1, 1))
            leases.execute('INSERT INTO browser_profile_leases (lease_id,program,account_alias,auth_domain,owner_agent_id,owner_run_id,purpose,profile_dir,status,browser_status,cdp_url,service_unit,created_at,heartbeat_at,expires_at,manager_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                           (side, 'fixture', 'anon', 'fixture.invalid', 'agent', side + '-run', 'fixture',
                            str(tmp_path / side), 'active', 'running', old, side + '-unit', 1, 1, 9999999999,
                            manager.manager_id()))
            rows.append(db.execute('SELECT * FROM browsers WHERE lease_id=?', (side,)).fetchone())
            infos.append(info)
        db.commit()
        leases.commit()
    monkeypatch.setattr(manager, '_transfer_candidates', lambda *args, **kwargs: [(r, i, side) for r, i, side in zip(rows, infos, ('source', 'destination'))])
    monkeypatch.setattr(manager, 'process_identity', lambda pid: {'pid': pid})
    monkeypatch.setattr(manager, 'unit_active', lambda unit: True)
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: unit.removesuffix('-unit') + '-inv')
    state = {'source': {'cookie': True, 'storage': True, 'available': True, 'quarantined': False},
             'destination': {'cookie': False, 'storage': False, 'available': True, 'quarantined': False}}
    stopped = []
    def stop(row):
        stopped.append(row['lease_id'])
        if fault in ('secondary-stop', 'stop-exit'):
            raise SystemExit(secret if fault == 'secondary-stop' else None)
        if stop_succeeds:
            state['destination']['available'] = False
        return stop_succeeds
    monkeypatch.setattr(manager, 'stop_recorded', stop)

    class Response:
        def __init__(self, value): self.value = value
        def raise_for_status(self): pass
        def json(self): return self.value

    class Client:
        def __init__(self, *, transport, timeout): self.side = Path(transport.uds).stem
        def post(self, url, json):
            side, action = self.side, url.rsplit('/', 1)[-1]
            s = state[side]
            if action == 'begin':
                s['available'] = False
                s['binding'] = {k: json[k] for k in ('transaction', 'owner', 'generation')}
                return Response({'ticket': side})
            assert json['ticket'] == side
            assert all(json[k] == s['binding'][k] for k in s['binding'])
            if action == 'status':
                return Response({'phase': s.get('phase', 'pending'),
                                 'cdp_url': new if s.get('rotated') else old})
            if action == 'end':
                s['quarantined'] = side == 'destination'
                s['available'] = side == 'source'
                return Response({'ended': True})
            if action == 'commit':
                s['rotated'] = True
                return Response({'quarantined': True, 'cdp_url': new})
            if action == 'activate':
                if fault in ('secondary-stop', 'secondary-readback'):
                    raise KeyboardInterrupt()
                if fault == 'before':
                    raise KeyboardInterrupt(secret)
                if fault in ('readback-exit', 'stop-exit'):
                    raise httpx.ReadError(secret)
                s['quarantined'], s['available'], s['phase'] = False, False, 'activated'
                if fault == 'published-interrupted-readback-exit':
                    raise KeyboardInterrupt(secret)
                if fault in ('after', 'lost-ack', 'published-readback-exit', 'published-readback-unavailable', 'published-fence-unavailable'):
                    raise httpx.ReadError(secret)
                return Response({'activated': True})
            if action == 'fence':
                if fault == 'published-fence-unavailable':
                    raise httpx.ReadError(secret)
                s['available'], s['quarantined'] = False, True
                s['fenced'] = True
                return Response({'fenced': True, 'quarantined': True, 'cdp_url': new + '-fenced'})
            if action == 'finalize':
                assert s['phase'] == 'activated' and not s['quarantined']
                if fault == 'finalize-unproved': raise httpx.ReadError(secret)
                s['phase'], s['available'] = 'finalized', True
                if fault == 'lost-finalize-ack': raise httpx.ReadError(secret)
                return Response({'finalized': True})
            method = json['method']
            if method == 'Network.getAllCookies':
                return Response({'result': {'cookies': [{'domain': 'localhost', 'name': '__Host-session',
                            'path': '/', 'httpOnly': True, 'secure': True, 'value': secret}] if s['cookie'] else []}})
            if method == 'Network.setCookies': s['cookie'] = True; return Response({'result': {}})
            if method == 'Network.deleteCookies': s['cookie'] = False; return Response({'result': {}})
            assert method == 'Runtime.evaluate'
            expression = json['params']['expression']
            if expression == 'location.origin': value = origin
            elif expression == 'location.href': value = origin + '/app'
            elif expression.startswith('(async () => {') and 'DOMParser' in expression:
                authenticated = s['cookie'] and s['storage']
                value = {'url': origin + '/me', 'status': 200 if authenticated else 401,
                         'redirected': False, 'principal': 'anon' if authenticated else 'guest'}
            elif expression.startswith('localStorage.getItem'): value = 'approved' if s['storage'] else None
            elif expression.startswith('localStorage.setItem'): s['storage'] = True; value = None
            elif expression.startswith('localStorage.removeItem'): s['storage'] = False; value = None
            else: raise AssertionError(expression)
            return Response({'result': {'result': {'value': value}}})
        def get(self, url):
            assert url.endswith('/identity')
            if self.side == 'destination' and fault in ('secondary-readback', 'readback-exit',
                                                       'published-readback-exit', 'published-interrupted-readback-exit') and state['destination'].get('rotated'):
                raise SystemExit(secret if fault == 'secondary-readback' else None)
            if self.side == 'destination' and fault in ('published-readback-unavailable', 'published-fence-unavailable') and state['destination'].get('rotated'):
                raise httpx.ReadError(secret)
            s = state[self.side]
            return Response({'available': s['available'], 'quarantined': s['quarantined'],
                             'process_identity': infos[0]['process_identity'],
                             'cdp_url': (new + '-fenced' if s.get('fenced') else new) if self.side == 'destination' and s.get('rotated') else old})
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
        def close(self): pass

    def json_load_url(path): return json.loads(Path(path).read_text())['cdp_url']
    monkeypatch.setattr(httpx, 'HTTPTransport', lambda *, uds: type('Transport', (), {'uds': uds})())
    monkeypatch.setattr(httpx, 'Client', Client)
    monkeypatch.setattr(httpx, 'get', lambda url, **kwargs: Response({
        'webSocketDebuggerUrl': new.replace('http:', 'ws:') + '/devtools/browser'}))
    if fault in ('before', 'secondary-stop', 'secondary-readback', 'readback-exit',
                 'stop-exit', 'published-readback-exit', 'published-interrupted-readback-exit'):
        expected = SystemExit if fault in ('readback-exit', 'stop-exit', 'published-readback-exit') else KeyboardInterrupt
        with pytest.raises(expected) as interrupted:
            manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)
        notes = str(interrupted.value.__notes__)
        assert 'before verified activation' in notes or 'terminal activation uncertain' in notes
        assert 'destination=' + ('disposed' if stop_succeeds and fault not in ('secondary-stop', 'stop-exit') else 'cleanup-incomplete') in notes
        assert secret not in notes
        if fault.startswith('secondary-') or fault in ('readback-exit', 'stop-exit', 'published-readback-exit'):
            rendered = ''.join(traceback.format_exception(interrupted.value))
            assert secret not in rendered
            assert old not in rendered and new not in rendered
            assert 'source=owner-preserved' in notes
        if fault in ('published-readback-exit', 'published-interrupted-readback-exit'):
            assert 'public-exposure=possible' in notes
        assert stopped == ['destination']
    elif fault == 'published-fence-unavailable' and not stop_succeeds:
        result = manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)
        assert result == {'status': 'fixture-auth-transfer-terminal-uncertain',
                          'source': 'owner-preserved', 'destination': 'cleanup-incomplete',
                          'public_exposure': 'possible'}
        assert stopped == ['destination']
        assert state['destination']['phase'] == 'activated' and not state['destination']['quarantined']
    elif fault == 'published-readback-unavailable' and not stop_succeeds:
        result = manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)
        assert result == {'status': 'auth-clone-unavailable', 'reason': 'destination-fenced-after-activation-uncertainty',
                          'source': 'owner-preserved', 'destination': 'fenced'}
        assert stopped == ['destination']
        assert secret not in str(result)
    elif fault == 'finalize-unproved' and not stop_succeeds:
        result = manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)
        assert result == {'status': 'auth-clone-unavailable',
                          'reason': 'destination-fenced-after-activation-uncertainty',
                          'source': 'owner-preserved', 'destination': 'fenced'}
        assert stopped == ['destination']
    elif fault in ('published-readback-unavailable', 'published-fence-unavailable', 'finalize-unproved'):
        result = manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)
        assert result == {'status': 'auth-clone-unavailable', 'reason': 'destination-disposed-after-end-uncertainty'}
        assert stopped == ['destination']
    else:
        result = manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)
        assert result == {'status': 'fixture-auth-transferred'}
        assert stopped == []
        assert state['destination']['available'] and not state['destination']['quarantined']
        assert secret not in str(result)
    assert state['source']['available'] and state['source']['cookie'] and state['source']['storage']
    with profiles.connect(tmp_path / 'browser_profile_leases.sqlite') as leases:
        canonical = leases.execute('SELECT cdp_url,owner_agent_id,owner_run_id FROM browser_profile_leases WHERE lease_id=?', ('destination',)).fetchone()
        source_owner = leases.execute('SELECT cdp_url,owner_agent_id,owner_run_id FROM browser_profile_leases WHERE lease_id=?', ('source',)).fetchone()
    assert (source_owner['cdp_url'], source_owner['owner_agent_id'], source_owner['owner_run_id']) == (old, 'agent', 'source-run')
    assert json_load_url(rows[0]['launch_file']) == old
    assert canonical['cdp_url'] == json_load_url(rows[1]['launch_file']) == new
    assert (canonical['owner_agent_id'], canonical['owner_run_id']) == ('agent', 'destination-run')
    if fault in ('before', 'secondary-stop', 'secondary-readback', 'readback-exit', 'stop-exit',
                 'published-readback-exit', 'published-readback-unavailable', 'published-interrupted-readback-exit',
                 'published-fence-unavailable'):
        if fault == 'published-fence-unavailable' and not stop_succeeds:
            return  # Explicitly unproved public fence and failed exact disposal.
        assert not state['destination']['available']
        assert state['destination']['quarantined'] or stop_succeeds
