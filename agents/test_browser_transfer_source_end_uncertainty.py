"""Applied source end with a lost reply cannot strand an imported recipient."""
import asyncio
import importlib.util
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'
spec = importlib.util.spec_from_file_location('browser_provisioner_source_end_fault', ROOT / 'browser_provisioner.py')
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


@pytest.mark.parametrize('stop_outcome', ['success', 'unit-active', 'root-active', 'cdp-ready'])
@pytest.mark.parametrize('source_failure', ['lost-end', 'recheck', 'interrupt-end', 'exit-end', 'cancel-recheck', 'unexpected-end'])
def test_imported_recipient_disposed_when_source_unproved(tmp_path, monkeypatch, stop_outcome, source_failure):
    stop_succeeds = stop_outcome == 'success'
    monkeypatch.setattr(manager, 'STATE', tmp_path / 'manager.sqlite')
    rows = [dict(lease_id=side, browser_id=side, unit='unit-' + side,
                 state='running', program='fixture', auth_domain='fixture.invalid', account='anon')
            for side in ('source', 'destination')]
    candidates = [(row, {'control_socket': str(tmp_path / (side + '.sock')),
                         'cdp_url': 'http://127.0.0.1:9222/' + side,
                         'process_identity': {'pid': 1}, 'unit_invocation': 'inv-' + side}, None)
                  for row, side in zip(rows, ('source', 'destination'))]
    monkeypatch.setattr(manager, '_transfer_candidates', lambda *args, **kwargs: candidates)
    monkeypatch.setattr(manager, 'record_info', lambda row: candidates[0 if row['lease_id'] == 'source' else 1][1])
    origin = 'http://127.0.0.1:31337'
    state = {side: {'cookie': side == 'source', 'storage': side == 'source',
                    'open': True, 'quarantined': False, 'ends': 0}
             for side in ('source', 'destination')}
    stopped_units = []
    checks = {'unit': 0, 'root': 0, 'cdp': 0}
    import browser_profile_lease as profiles
    def unit_active(unit):
        checks['unit'] += 1
        return unit not in stopped_units or stop_outcome == 'unit-active'
    def owner_state(identity):
        checks['root'] += 1
        return 'active' if stop_outcome == 'root-active' else 'terminal'
    def cdp_version(url):
        checks['cdp'] += 1
        return {'status': 'ready' if stop_outcome == 'cdp-ready' else 'unavailable'}
    monkeypatch.setattr(manager, 'unit_active', unit_active)
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'inv-' + unit.removeprefix('unit-'))
    monkeypatch.setattr(manager, 'stop_unit', lambda unit: stopped_units.append(unit))
    monkeypatch.setattr(manager, 'owner_state', owner_state)
    monkeypatch.setattr(profiles, 'local_cdp_version', cdp_version)
    if not stop_succeeds:
        # Avoid the real five-second wait in a deterministically failed stop.
        ticks = iter([0, 0, 6])
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
                if side == 'source':
                    if source_failure == 'lost-end':
                        raise httpx.ReadError('source end applied; reply lost')
                    if source_failure == 'interrupt-end':
                        raise KeyboardInterrupt()
                    if source_failure == 'exit-end':
                        raise SystemExit(12)
                    if source_failure == 'unexpected-end':
                        raise RuntimeError('unexpected adapter failure')
                return Response({'ended': True})
            if action == 'abort':
                assert side != 'destination' or source_failure != 'recheck', 'recipient must stay private until stop'
                s['open'] = True
                return Response({'aborted': True})
            assert action == 'call'
            method = json['method']
            if method == 'Network.getAllCookies':
                cookies = [{'domain': '127.0.0.1', 'name': 'session', 'path': '/', 'httpOnly': True}] if s['cookie'] else []
                return Response({'result': {'cookies': cookies}})
            if method == 'Network.setCookies': s['cookie'] = True; return Response({'result': {}})
            if method == 'Network.deleteCookies': s['cookie'] = False; return Response({'result': {}})
            assert method == 'Runtime.evaluate'
            expression = json['params']['expression']
            if expression == 'location.origin': value = origin
            elif expression == 'location.href': value = origin + '/app'
            elif expression.startswith("fetch('/whoami')"):
                if source_failure == 'cancel-recheck' and side == 'source' and state['destination']['storage']:
                    raise asyncio.CancelledError()
                value = s['cookie'] and s['storage']
                if source_failure == 'recheck' and side == 'source' and state['destination']['storage']:
                    value = False
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
    exceptional = {'interrupt-end': KeyboardInterrupt, 'exit-end': SystemExit,
                   'cancel-recheck': asyncio.CancelledError, 'unexpected-end': RuntimeError}
    if source_failure in exceptional:
        with pytest.raises(exceptional[source_failure]) as caught:
            manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)
        assert 'destination=' + ('disposed' if stop_succeeds else 'cleanup-incomplete') in str(caught.value.__notes__)
        assert 'source release unverified' in str(caught.value.__notes__)
        assert 'approved' not in str(caught.value.__notes__)
    else:
        result = manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)
        assert 'cdp_url' not in result and 'cookie' not in result
        assert result == {'status': 'auth-clone-unavailable',
                          'reason': 'source-cleanup-incomplete' if source_failure == 'lost-end' else 'source-changed',
                          'source': 'release-unverified' if source_failure == 'lost-end' else 'owner-preserved',
                          'destination': 'disposed' if stop_succeeds else 'cleanup-incomplete'}
    assert stopped_units == ['unit-destination']
    assert checks['unit'] >= 1
    if stop_outcome != 'unit-active':
        assert checks['root'] >= 1
    if stop_outcome in ('success', 'cdp-ready'):
        assert checks['cdp'] >= 1
    assert state['source']['cookie'] and state['source']['storage'] and state['source']['open']
    assert not state['destination']['open']
    if source_failure == 'lost-end':
        assert state['source']['ends'] == 1 and state['destination']['ends'] == 1
    elif source_failure in ('interrupt-end', 'exit-end', 'unexpected-end'):
        assert state['source']['ends'] == 1 and state['destination']['ends'] == 0
    else:
        assert state['destination']['ends'] == 0
