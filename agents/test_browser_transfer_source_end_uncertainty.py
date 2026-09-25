"""Applied source end with a lost reply cannot strand an imported recipient."""
import importlib.util
from pathlib import Path
from agents.test_browser_auth_site_contract import write_fixture_contract

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'
spec = importlib.util.spec_from_file_location('browser_provisioner_source_end_fault', ROOT / 'browser_provisioner.py')
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


@pytest.mark.parametrize('stop_outcome', ['success', 'unit-active', 'root-active', 'cdp-ready'])
@pytest.mark.parametrize('source_failure', ['lost-end', 'recheck'])
def test_imported_recipient_disposed_when_source_unproved(tmp_path, monkeypatch, stop_outcome, source_failure):
    stop_succeeds = stop_outcome == 'success'
    monkeypatch.setattr(manager, 'STATE', tmp_path / 'manager.sqlite')
    origin = 'http://localhost:31337'
    write_fixture_contract(tmp_path, origin)
    rows = [dict(lease_id=side, browser_id=side, unit='unit-' + side,
                 state='running', program='fixture', auth_domain='fixture.invalid', account='anon')
            for side in ('source', 'destination')]
    candidates = [(row, {'control_socket': str(tmp_path / (side + '.sock')),
                         'cdp_url': 'http://127.0.0.1:9222/' + side,
                         'process_identity': {'pid': 1}, 'unit_invocation': 'inv-' + side}, None)
                  for row, side in zip(rows, ('source', 'destination'))]
    monkeypatch.setattr(manager, '_transfer_candidates', lambda *args, **kwargs: candidates)
    monkeypatch.setattr(manager, 'record_info', lambda row: candidates[0 if row['lease_id'] == 'source' else 1][1])

    state = {side: {'cookie': side == 'source', 'storage': side == 'source',
                    'open': True, 'quarantined': False, 'ends': 0}
             for side in ('source', 'destination')}
    stopped_units = []
    import browser_profile_lease as profiles
    monkeypatch.setattr(manager, 'unit_active', lambda unit: unit not in stopped_units or stop_outcome == 'unit-active')
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'inv-' + unit.removeprefix('unit-'))
    monkeypatch.setattr(manager, 'stop_unit', lambda unit: stopped_units.append(unit))
    monkeypatch.setattr(manager, 'owner_state', lambda identity: 'active' if stop_outcome == 'root-active' else 'terminal')
    monkeypatch.setattr(profiles, 'local_cdp_version',
                        lambda url: {'status': 'ready' if stop_outcome == 'cdp-ready' else 'unavailable'})
    if not stop_succeeds:
        # Avoid the real five-second wait in a deterministically failed stop.
        ticks = iter([0, 6])
        monkeypatch.setattr(manager.time, 'monotonic', lambda: next(ticks))
    class Response:
        def __init__(self, data): self.data = data
        def raise_for_status(self): pass
        def json(self): return self.data
    class Client:
        def __init__(self, *, transport, timeout): self.side = Path(transport.uds).stem
        def post(self, url, json):
            side = self.side
            s = state[side]
            action = url.rsplit('/', 1)[-1]
            if action == 'begin':
                s['open'] = False
                return Response({'ticket': side})
            assert json['ticket'] == side
            if action == 'end':
                s['ends'] += 1
                s['open'] = side == 'source'
                s['quarantined'] = side == 'destination'
                if side == 'source' and source_failure == 'lost-end':
                    raise httpx.ReadError('source end applied; reply lost')
                return Response({'ended': True})
            if action == 'abort':
                assert side != 'destination' or source_failure != 'recheck', 'recipient must stay private until stop'
                s['open'] = True
                return Response({'aborted': True})
            assert action == 'call'
            method = json['method']
            if method == 'Network.getAllCookies':
                cookies = [{'domain': 'localhost', 'name': '__Host-session', 'path': '/',
                            'httpOnly': True, 'secure': True}] if s['cookie'] else []
                return Response({'result': {'cookies': cookies}})
            if method == 'Network.setCookies': s['cookie'] = True; return Response({'result': {}})
            if method == 'Network.deleteCookies': s['cookie'] = False; return Response({'result': {}})
            assert method == 'Runtime.evaluate'
            expression = json['params']['expression']
            if expression == 'location.origin': value = origin
            elif expression == 'location.href': value = origin + '/app'
            elif expression.startswith('(async () => {') and 'DOMParser' in expression:
                authenticated = s['cookie'] and s['storage']
                if source_failure == 'recheck' and side == 'source' and state['destination']['storage']:
                    authenticated = False
                value = {'url': origin + '/me', 'status': 200 if authenticated else 401,
                         'redirected': False, 'principal': 'anon' if authenticated else 'guest'}
            elif expression.startswith('localStorage.getItem'): value = 'approved' if s['storage'] else None
            elif expression.startswith('localStorage.setItem'): s['storage'] = True; value = None
            elif expression.startswith('localStorage.removeItem'): s['storage'] = False; value = None
            else: raise AssertionError(expression)
            return Response({'result': {'result': {'value': value}}})
        def get(self, url):
            assert url.endswith('/identity')
            s = state[self.side]
            info = candidates[0 if self.side == 'source' else 1][1]
            # The source's end applied, but the probe cannot prove release.
            return Response({'available': False if self.side == 'source' else s['open'],
                             'quarantined': s['quarantined'], 'cdp_url': info['cdp_url'],
                             'process_identity': info['process_identity']})
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
        def close(self): pass
    monkeypatch.setattr(httpx, 'HTTPTransport', lambda *, uds: type('Transport', (), {'uds': uds})())
    monkeypatch.setattr(httpx, 'Client', Client)
    result = manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)
    assert stopped_units == ['unit-destination']
    assert state['source']['cookie'] and state['source']['storage'] and state['source']['open']
    assert not state['destination']['open']
    assert 'cdp_url' not in result and 'cookie' not in result
    assert result == {'status': 'auth-clone-unavailable',
                      'reason': 'source-cleanup-incomplete' if source_failure == 'lost-end' else 'source-changed',
                      'source': 'release-unverified' if source_failure == 'lost-end' else 'owner-preserved',
                      'destination': 'disposed' if stop_succeeds else 'cleanup-incomplete'}
    if source_failure == 'lost-end':
        assert state['source']['ends'] == 1 and state['destination']['ends'] == 1
    else:
        assert state['destination']['ends'] == 0
