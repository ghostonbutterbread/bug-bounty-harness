"""Lost begin replies cannot strand the source or publish an uncertain clone."""
import asyncio
import importlib.util
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'
spec = importlib.util.spec_from_file_location('browser_provisioner_begin_fault', ROOT / 'browser_provisioner.py')
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


@pytest.mark.parametrize('interruption', [httpx.ReadError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
@pytest.mark.parametrize('lost_at', ['source', 'destination'])
@pytest.mark.parametrize('release_fails', [False, True])
@pytest.mark.parametrize('cleanup_interrupt', [False, True])
def test_applied_begin_interrupt_releases_exact_owner(tmp_path, monkeypatch, lost_at, release_fails, interruption, cleanup_interrupt):
    if cleanup_interrupt and interruption is httpx.ReadError:
        pytest.skip('cleanup cancellation requires an original cancellation')
    monkeypatch.setattr(manager, 'STATE', tmp_path / 'manager.sqlite')
    rows = [dict(lease_id=name, browser_id=name, unit='unit-' + name,
                 program='fixture', auth_domain='fixture.invalid', account='anon')
            for name in ('source', 'destination')]
    candidates = [(row, {'control_socket': str(tmp_path / (name + '.sock')),
                         'cdp_url': 'http://127.0.0.1:9222/' + name,
                         'process_identity': {'pid': 1}}, None)
                  for row, name in zip(rows, ('source', 'destination'))]
    monkeypatch.setattr(manager, '_transfer_candidates', lambda *args, **kwargs: candidates)
    origin = 'http://127.0.0.1:31337'
    state = {side: {'transaction': None, 'open': True, 'generation': side}
             for side in ('source', 'destination')}
    lost = []
    stopped = []
    monkeypatch.setattr(manager, 'stop_recorded', lambda row: stopped.append(row) or False)

    class Response:
        def __init__(self, data): self.data = data
        def raise_for_status(self): pass
        def json(self): return self.data

    class Client:
        def __init__(self, *, transport, timeout): self.side = Path(transport.uds).stem
        def post(self, url, json):
            side = self.side
            action = url.rsplit('/', 1)[-1]
            s = state[side]
            if action == 'begin':
                txn = json['transaction']
                assert isinstance(txn, str) and txn
                assert json['owner'] == side and json['generation'].endswith('/' + side)
                if s['transaction'] is None:
                    s['transaction'] = txn
                    s['open'] = False
                    if side == lost_at and not lost:
                        lost.append(side)
                        raise interruption('begin reply lost after application')
                assert txn == s['transaction'], 'different transaction cannot acquire locked adapter'
                if release_fails and side == lost_at:
                    raise httpx.ReadError('recovery reply unavailable')
                return Response({'ticket': side})
            assert json['ticket'] == side and s['transaction'] is not None
            assert json['transaction'] == s['transaction']
            assert json['owner'] == side and json['generation'].endswith('/' + side)
            if action in ('end', 'abort'):
                if cleanup_interrupt and lost and side == 'source':
                    raise SystemExit('cleanup interrupted')
                s['open'] = action == 'end' and side == 'source' or action == 'abort'
                s['transaction'] = None
                return Response({action + 'ed': True})
            if action == 'call':
                if side == 'destination':
                    raise AssertionError('no import after lost begin')
                method = json['method']
                if method == 'Runtime.evaluate':
                    expression = json['params']['expression']
                    value = origin if expression == 'location.origin' else origin + '/app' if expression == 'location.href' else True
                    return Response({'result': {'result': {'value': value}}})
                raise AssertionError(method)
            raise AssertionError(action)
        def get(self, url):
            assert url.endswith('/identity')
            s = state[self.side]
            return Response({'available': s['open'], 'quarantined': False,
                             'cdp_url': candidates[0 if self.side == 'source' else 1][1]['cdp_url'],
                             'process_identity': {'pid': 1}})
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
        def close(self): pass

    monkeypatch.setattr(httpx, 'HTTPTransport', lambda *, uds: type('Transport', (), {'uds': uds})())
    monkeypatch.setattr(httpx, 'Client', Client)
    if interruption is httpx.ReadError:
        result = manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)
        caught = None
    else:
        result = None
        with pytest.raises(interruption) as caught:
            manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)
    assert lost == [lost_at]
    assert not stopped
    if (not release_fails and not cleanup_interrupt) or (lost_at == 'destination' and not cleanup_interrupt):
        assert state['source']['open'] is True
    if not release_fails and not cleanup_interrupt:
        assert state['source']['transaction'] is None
        assert state['destination']['transaction'] is None
        if interruption is httpx.ReadError:
            assert result == {'status': 'auth-clone-unavailable', 'reason': 'transfer-control-unavailable'}
        else:
            assert caught is not None
            assert 'source=owner-preserved' in str(caught.value.__notes__)
    else:
        blocked = 'source' if cleanup_interrupt else lost_at
        if interruption is httpx.ReadError:
            assert result is not None and result['reason'] == blocked + '-cleanup-incomplete'
        else:
            assert caught is not None
            assert blocked + '=cleanup-incomplete' in str(caught.value.__notes__)
        assert state[blocked]['open'] is False
    if interruption is not httpx.ReadError:
        assert caught is not None
        assert 'approved' not in str(caught.value.__notes__)
