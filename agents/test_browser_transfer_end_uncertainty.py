"""Manager end-response loss dispositions using isolated simulated adapters."""
import importlib.util
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'
spec = importlib.util.spec_from_file_location('browser_provisioner_end_fault', ROOT / 'browser_provisioner.py')
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


@pytest.mark.parametrize('stop_succeeds', [True, False])
@pytest.mark.parametrize('lost_at', ['end', 'commit'])
def test_applied_destination_reply_loss_requires_exact_disposal(tmp_path, monkeypatch, stop_succeeds, lost_at):
    monkeypatch.setattr(manager, 'STATE', tmp_path / 'manager.sqlite')
    rows = [dict(lease_id=name, browser_id=name, unit='unit-' + name,
                 program='fixture', auth_domain='fixture.invalid', account='anon')
            for name in ('source', 'destination')]
    candidates = [(row, {'control_socket': str(tmp_path / (name + '.sock')),
                         'cdp_url': 'http://127.0.0.1:9222/old', 'process_identity': {'pid': 1}}, None)
                  for row, name in zip(rows, ('source', 'destination'))]
    monkeypatch.setattr(manager, '_transfer_candidates', lambda *args, **kwargs: candidates)
    monkeypatch.setattr(manager, 'stop_recorded', lambda row: stopped.append(row) or stop_succeeds)
    stopped = []
    origin = 'http://127.0.0.1:31337'
    state = {'source': {'cookie': True, 'storage': True, 'open': True},
             'destination': {'cookie': False, 'storage': False, 'open': True}}
    end_applied = []

    class Response:
        def __init__(self, data): self.data = data
        def raise_for_status(self): pass
        def json(self): return self.data

    class Client:
        def __init__(self, *, transport, timeout):
            self.side = Path(transport.uds).stem
        def post(self, url, json):
            side = self.side
            s = state[side]
            action = url.rsplit('/', 1)[-1]
            if action == 'begin':
                s['open'] = False
                s['destination'] = json.get('destination', False)
                return Response({'ticket': side})
            assert json['ticket'] == side
            if action == 'end':
                s['open'] = not s['destination']
                end_applied.append(side)
                if side == 'destination' and lost_at == 'end':
                    raise httpx.ReadError('response lost after application')
                return Response({'ended': True})
            if action == 'commit':
                s['open'] = False
                if lost_at == 'commit':
                    raise httpx.ReadError('commit reply lost after application')
                return Response({'cdp_url': 'http://127.0.0.1:9222/new', 'quarantined': True})
            method = json['method']
            if method == 'Network.getAllCookies':
                value = [{'domain': '127.0.0.1', 'name': 'session', 'path': '/', 'httpOnly': True}] if s['cookie'] else []
                return Response({'result': {'cookies': value}})
            if method == 'Network.setCookies': s['cookie'] = True; return Response({'result': {}})
            if method == 'Network.deleteCookies': s['cookie'] = False; return Response({'result': {}})
            if method == 'Runtime.evaluate':
                expression = json['params']['expression']
                if expression == 'location.origin': value = origin
                elif expression == 'location.href': value = origin + '/app'
                elif expression.startswith("fetch('/whoami')"): value = s['cookie'] and s['storage']
                elif expression.startswith('localStorage.getItem'): value = 'approved' if s['storage'] else None
                elif expression.startswith('localStorage.setItem'): s['storage'] = True; value = None
                elif expression.startswith('localStorage.removeItem'): s['storage'] = False; value = None
                else: raise AssertionError('unexpected expression')
                return Response({'result': {'result': {'value': value}}})
            raise AssertionError(method)
        def get(self, url):
            assert url.endswith('/identity')
            return Response({'quarantined': True, **candidates[1][1]})
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
        def close(self): pass

    monkeypatch.setattr(httpx, 'HTTPTransport', lambda *, uds: type('Transport', (), {'uds': uds})())
    monkeypatch.setattr(httpx, 'Client', Client)
    result = manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)
    assert end_applied == ['source', 'destination']
    assert stopped == [rows[1]]  # exact destination, never source
    assert state['source']['cookie'] and state['source']['storage']
    assert state['destination']['cookie'] and state['destination']['storage']
    assert not state['destination']['open']  # failed stop cannot reopen old public URL
    assert result == {'status': 'auth-clone-unavailable', 'reason':
                      'destination-disposed-after-end-uncertainty' if stop_succeeds else 'destination-cleanup-incomplete'}
