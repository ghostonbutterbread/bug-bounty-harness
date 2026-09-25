"""Promotion probe must release its exact source ticket, even on failure."""
import asyncio
import json

import httpx
import pytest
from test_browser_fixture_peer_generation import ORIGIN, setup
from test_browser_manager_transfer_gate import manager

SECRET = 'session=private-canary'


@pytest.mark.parametrize('fault', ['begin-lost', 'evaluate-failed', 'end-lost', 'begin-unproved', 'end-unproved', 'wrong-owner', 'wrong-generation'])
def test_promotion_probe_exact_release(tmp_path, monkeypatch, fault):
    row = {'lease_id': 'source'}
    info = {'cdp_url': 'http://127.0.0.1:9222/source', 'control_socket': str(tmp_path / 'source.sock'),
            'process_identity': {'pid': 123}}
    state = {'ticket': None, 'open': True, 'begin': 0, 'end': 0, 'calls': 0}

    class Response:
        def __init__(self, value): self.value = value
        def raise_for_status(self): pass
        def json(self): return self.value

    class Client:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, json):
            action = url.rsplit('/', 1)[-1]
            if action == 'begin':
                state['begin'] += 1
                assert json['owner'] == row['lease_id'] and json['generation'] == info['cdp_url']
                if state['ticket'] is None:
                    state['ticket'] = json['transaction']
                    state['open'] = False
                else:
                    assert json['transaction'] == state['ticket']
                if fault in ('begin-lost', 'begin-unproved') and (state['begin'] == 1 or fault == 'begin-unproved'):
                    raise httpx.ReadError(SECRET)
                return Response({'ticket': 'exact-ticket'})
            assert json['transaction'] == state['ticket'] and json['ticket'] == 'exact-ticket'
            assert json['owner'] == row['lease_id'] and json['generation'] == info['cdp_url']
            if action == 'call':
                state['calls'] += 1
                if fault == 'evaluate-failed': raise httpx.ReadError(SECRET)
                return Response({'result': {'result': {'value': ORIGIN if state['calls'] == 1 else True}}})
            if action == 'end':
                state['end'] += 1
                if fault in ('wrong-owner', 'wrong-generation'):
                    raise httpx.HTTPStatusError(SECRET, request=httpx.Request('POST', url), response=httpx.Response(403))
                state['ticket'] = None
                state['open'] = True
                if fault in ('end-lost', 'end-unproved'): raise httpx.ReadError(SECRET)
                return Response({'ended': True})
            raise AssertionError(action)
        def get(self, url):
            assert url.endswith('/identity')
            if fault in ('begin-unproved', 'end-unproved', 'wrong-owner', 'wrong-generation'):
                raise httpx.ReadError(SECRET)
            return Response({'available': state['open'], 'quarantined': False,
                             'cdp_url': info['cdp_url'], 'process_identity': info['process_identity']})

    monkeypatch.setattr(httpx, 'Client', Client)
    monkeypatch.setattr(manager, '_fixture_native_source_check', manager._fixture_native_source_check)
    # Direct probe without source generation publication.
    outcome = manager._fixture_native_source_check(row, info, ORIGIN)
    if fault == 'begin-unproved':
        assert state['open'] is False and outcome == 'source-cleanup-incomplete'
    elif fault in ('end-unproved', 'wrong-owner', 'wrong-generation'):
        assert outcome == 'source-cleanup-incomplete'
    else:
        assert state['open'] is True
        assert outcome is (fault in ('begin-lost', 'end-lost'))
    assert state['end'] == (0 if fault == 'begin-unproved' else 1)
    assert SECRET not in json.dumps(outcome)


@pytest.mark.parametrize('fault', [KeyboardInterrupt, asyncio.CancelledError])
@pytest.mark.parametrize('at', ['begin', 'call', 'end'])
def test_promotion_probe_cancellation_releases_or_reports_incomplete(tmp_path, monkeypatch, fault, at):
    row = {'lease_id': 'source'}
    info = {'cdp_url': 'http://127.0.0.1:9222/source', 'control_socket': str(tmp_path / 'source.sock'),
            'process_identity': {'pid': 123}}
    state = {'open': True, 'ends': 0, 'begins': 0, 'calls': 0}
    class Response:
        def __init__(self, value): self.value = value
        def raise_for_status(self): pass
        def json(self): return self.value
    class Client:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, json):
            action = url.rsplit('/', 1)[-1]
            if action == 'begin':
                state['begins'] += 1
                state['open'] = False
                if at == 'begin' and state['begins'] == 1: raise fault(SECRET)
                return Response({'ticket': 'exact-ticket'})
            if action == 'call':
                state['calls'] += 1
                if at == 'call': raise fault(SECRET)
                return Response({'result': {'result': {'value': ORIGIN if state['calls'] == 1 else True}}})
            if action == 'end':
                state['ends'] += 1
                state['open'] = True
                if at == 'end': raise fault(SECRET)
                return Response({'ended': True})
            raise AssertionError(action)
        def get(self, url):
            return Response({'available': state['open'], 'quarantined': False,
                             'cdp_url': info['cdp_url'], 'process_identity': info['process_identity']})
    monkeypatch.setattr(httpx, 'Client', Client)
    monkeypatch.setattr(manager, '_fixture_native_source_check', manager._fixture_native_source_check)
    with pytest.raises(fault) as caught:
        manager._fixture_native_source_check(row, info, ORIGIN)
    assert state['open'] is True and state['ends'] == 1
    assert state['begins'] == (2 if at == 'begin' else 1)
    assert 'source=owner-preserved' in str(caught.value.__notes__)
    assert SECRET not in str(caught.value.__notes__)


def test_unproved_promotion_never_publishes_generation(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    monkeypatch.setattr(manager, '_fixture_native_source_check', lambda *args: 'source-cleanup-incomplete')
    assert manager.manager_fixture_promote('source', origin=ORIGIN,
        owner_agent_id='source', owner_run_id='run') == {
            'status': 'auth-clone-unavailable', 'reason': 'source-cleanup-incomplete'}
    with manager.db() as store:
        assert store.execute('SELECT count(*) FROM fixture_generations').fetchone()[0] == 0
        assert store.execute('SELECT count(*) FROM fixture_peers').fetchone()[0] == 0


@pytest.mark.parametrize('state', ['pending', 'applying', 'applied'])
def test_direct_clone_cannot_consume_peer_update_or_change_ledger(tmp_path, monkeypatch, state):
    setup(tmp_path, monkeypatch)
    assert manager.manager_fixture_promote('source', origin=ORIGIN,
        owner_agent_id='source', owner_run_id='run')['generation'] == 1
    with manager.db() as store:
        store.execute("UPDATE fixture_peers SET state=? WHERE lease_id='destination'", (state,))
        before = ([tuple(row) for row in store.execute('SELECT * FROM fixture_generations')],
                  [tuple(row) for row in store.execute('SELECT * FROM fixture_peers ORDER BY lease_id')])
    # Direct initial-clone primitive must not reach either browser for a peer update.
    monkeypatch.setattr(manager, '_transfer_candidates', lambda *args, **kwargs: pytest.fail('browser I/O reached'))
    assert manager.manager_fixture_auth_transfer('source', 'destination', origin=ORIGIN) == {
        'status': 'auth-clone-unavailable', 'reason': 'recipient-approval-required'}
    with manager.db() as store:
        after = ([tuple(row) for row in store.execute('SELECT * FROM fixture_generations')],
                 [tuple(row) for row in store.execute('SELECT * FROM fixture_peers ORDER BY lease_id')])
    assert after == before
