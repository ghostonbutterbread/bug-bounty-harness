"""Fixture-only generation workflow: no account, site or Hoster integration."""
import json
import threading

import pytest
from test_browser_manager_transfer_gate import candidates, manager, lease
from agents.test_browser_auth_site_contract import write_fixture_contract

ORIGIN = 'http://localhost:31337'


def setup(tmp_path, monkeypatch):
    canonical = candidates(tmp_path, monkeypatch)
    write_fixture_contract(manager.STATE.parent, ORIGIN)
    with manager.db() as store:
        store.execute("UPDATE browsers SET program='fixture',auth_domain='fixture.invalid',account='anon'")
        for row in store.execute('SELECT * FROM browsers'):
            info = manager.record_info(row)
            info['control_socket'] = str(manager.STATE.parent / (row['browser_id'] + '.sock'))
            manager.private_json(row['launch_file'], info)
    with lease.connect(canonical) as store:
        store.execute("UPDATE browser_profile_leases SET program='fixture',auth_domain='fixture.invalid',account_alias='anon'")
    monkeypatch.setattr(manager, '_fixture_native_source_check', lambda *args: True)
    return canonical


def promote():
    return manager.manager_fixture_promote('source', origin=ORIGIN, owner_agent_id='source', owner_run_id='run')


def apply(**kwargs):
    return manager.manager_fixture_apply('destination', generation=1, owner_agent_id='destination',
                                         owner_run_id='run', approved_boundary=True, **kwargs)


def test_pending_metadata_and_no_automatic_or_label_approved_transfer(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    transfers = []
    monkeypatch.setattr(manager, 'manager_fixture_auth_transfer',
                        lambda *a, **k: transfers.append((a, k)) or {'status': 'fixture-auth-transferred'})
    assert promote() == {'status': 'fixture-generation-promoted', 'generation': 1}
    assert manager.manager_fixture_pending('source') == {'status': 'applied', 'generation': 1}
    assert manager.manager_fixture_pending('destination') == {'status': 'pending', 'generation': 1}
    with manager.db() as store:
        metadata = dict(store.execute('SELECT * FROM fixture_generations').fetchone())
    assert metadata['source_lease'] == 'source'
    assert metadata['contract_revision'] == manager.FIXTURE_CONTRACT_REVISION
    assert len(metadata['source_identity']) == 64
    assert set(metadata) == {'program', 'auth_domain', 'account', 'generation', 'source_lease',
                             'source_identity', 'contract_revision', 'origin'}
    assert 'approved' not in json.dumps(metadata) and 'session=' not in json.dumps(metadata)
    for approved in (False, True):
        assert manager.manager_fixture_apply('destination', generation=1, owner_agent_id='destination',
            owner_run_id='run', approved_boundary=approved)['reason'] == 'recipient-approval-required'
    assert apply()['reason'] == 'recipient-approval-required'
    assert transfers == []
    assert manager.manager_fixture_pending('destination') == {'status': 'pending', 'generation': 1}
    assert promote() == {'status': 'fixture-generation-promoted', 'generation': 2}
    assert manager.manager_fixture_pending('destination') == {'status': 'pending', 'generation': 2}


@pytest.mark.parametrize('key,column', [('program','program'), ('auth_domain','auth_domain'), ('account','account_alias')])
def test_pool_exactness(tmp_path, monkeypatch, key, column):
    canonical = setup(tmp_path, monkeypatch)
    with manager.db() as store:
        store.execute(f"UPDATE browsers SET {key}='other' WHERE lease_id='destination'")
    with lease.connect(canonical) as store:
        store.execute(f"UPDATE browser_profile_leases SET {column}='other' WHERE lease_id='destination'")
    assert promote()['status'] == 'fixture-generation-promoted'
    assert manager.manager_fixture_pending('destination')['reason'] == 'pending-peer-unavailable'
    assert apply()['reason'] == 'recipient-approval-required'
    with manager.db() as store:
        store.execute(f"UPDATE browsers SET {key}='other' WHERE lease_id='source'")
    with lease.connect(canonical) as store:
        store.execute(f"UPDATE browser_profile_leases SET {column}='other' WHERE lease_id='source'")
    assert promote()['reason'] == 'manager-identity-unverified'


def test_apply_cannot_be_unlocked_with_caller_labels_or_monkeypatched_seam(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    assert promote()['generation'] == 1
    monkeypatch.setattr(manager, 'manager_fixture_auth_transfer',
                        lambda *args, **kwargs: pytest.fail('transfer reached'))
    for agent in ('destination', 'source', 'intruder'):
        assert manager.manager_fixture_apply('destination', generation=1, owner_agent_id=agent,
            owner_run_id='run', approved_boundary=True)['reason'] == 'recipient-approval-required'
    assert manager.manager_fixture_pending('destination') == {'status': 'pending', 'generation': 1}


def test_concurrent_promotions_are_serialized(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    results = []
    threads = [threading.Thread(target=lambda: results.append(promote())) for _ in range(2)]
    for thread in threads: thread.start()
    for thread in threads: thread.join(timeout=5)
    assert sorted(result['generation'] for result in results) == [1, 2]
    assert manager.manager_fixture_pending('destination') == {'status': 'pending', 'generation': 2}


def test_failed_native_check_does_not_publish(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    monkeypatch.setattr(manager, '_fixture_native_source_check', lambda *args: False)
    assert promote()['reason'] == 'source-app-check-failed'
    with manager.db() as store:
        assert store.execute('SELECT count(*) FROM fixture_generations').fetchone()[0] == 0


@pytest.mark.parametrize('program_mode,exact_mode,denied', [
    ('single', 'multiple', True),
    ('single', None, True),
    ('multiple', 'single', True),
    ('unknown', 'single', True),
    ('multiple', 'multiple', False),
    ('multiple', None, False),
    ('unknown', 'multiple', False),
    (None, None, False),
])
def test_direct_transfer_policy_flip_on_two_running_browsers(
        tmp_path, monkeypatch, program_mode, exact_mode, denied):
    """A later policy change cannot authenticate an existing second owner."""
    canonical = setup(tmp_path, monkeypatch)
    with lease.connect(canonical) as store:
        assert store.execute("SELECT count(*) FROM browser_profile_leases WHERE status='active' AND browser_status='running'").fetchone()[0] == 2
        lease.init_resource_policy(store)
        if program_mode is not None:
            store.execute('INSERT INTO browser_program_concurrency_policy VALUES (?,?,?,?,?)',
                          ('fixture', program_mode, 'agent', 'fixture-policy', 1))
        if exact_mode is not None:
            store.execute('INSERT INTO browser_concurrency_policy VALUES (?,?,?,?)',
                          ('fixture', 'anon', 'fixture.invalid', exact_mode))
        before_leases = [tuple(row) for row in store.execute('SELECT * FROM browser_profile_leases ORDER BY lease_id')]
    with manager.db() as store:
        before_manager = [tuple(row) for row in store.execute('SELECT * FROM browsers ORDER BY lease_id')]
        before_peers = [tuple(row) for row in store.execute('SELECT * FROM fixture_peers ORDER BY lease_id')]
        before_generations = [tuple(row) for row in store.execute('SELECT * FROM fixture_generations')]

    # The negative must return before browser control, import, or even contract
    # evaluation; the permissive cases reach the contract expression seam.
    class Admitted(Exception):
        pass
    import httpx
    cdp_calls = []
    transport_calls = []
    original_cdp = lease.local_cdp_version
    original_transport = httpx.HTTPTransport
    def counted_cdp(url):
        cdp_calls.append(url)
        return original_cdp(url)
    def counted_transport(*args, **kwargs):
        transport_calls.append((args, kwargs))
        return original_transport(*args, **kwargs)
    monkeypatch.setattr(lease, 'local_cdp_version', counted_cdp)
    monkeypatch.setattr(httpx, 'HTTPTransport', counted_transport)
    monkeypatch.setattr(httpx, 'Client', lambda *args, **kwargs: pytest.fail('browser I/O reached'))
    monkeypatch.setattr(manager, '_fixture_check_expression', lambda contract: (_ for _ in ()).throw(Admitted()))
    if denied:
        assert manager.manager_fixture_auth_transfer('source', 'destination', origin=ORIGIN) == {
            'status': 'auth-clone-unavailable', 'reason': 'single-browser-policy'}
        assert cdp_calls == []
        assert transport_calls == []
    else:
        with pytest.raises(Admitted):
            manager.manager_fixture_auth_transfer('source', 'destination', origin=ORIGIN)
        assert len(cdp_calls) == 2
        assert transport_calls == []
    with lease.connect(canonical) as store:
        assert [tuple(row) for row in store.execute('SELECT * FROM browser_profile_leases ORDER BY lease_id')] == before_leases
    with manager.db() as store:
        assert [tuple(row) for row in store.execute('SELECT * FROM browsers ORDER BY lease_id')] == before_manager
        assert [tuple(row) for row in store.execute('SELECT * FROM fixture_peers ORDER BY lease_id')] == before_peers
        assert [tuple(row) for row in store.execute('SELECT * FROM fixture_generations')] == before_generations


@pytest.mark.parametrize('mutation,expected', [
    ('other-program-policy', 'site-contract-unavailable'),
    ('canonical-owner-mismatch', 'manager-identity-unverified'),
    ('canonical-account-mismatch', 'manager-identity-unverified'),
])
def test_early_policy_denial_requires_exact_verified_fixture_pool(tmp_path, monkeypatch, mutation, expected):
    canonical = setup(tmp_path, monkeypatch)
    with lease.connect(canonical) as store:
        lease.init_resource_policy(store)
        store.execute('INSERT INTO browser_program_concurrency_policy VALUES (?,?,?,?,?)',
                      ('fixture', 'single', 'agent', 'fixture-policy', 1))
        if mutation == 'other-program-policy':
            store.execute("UPDATE browser_program_concurrency_policy SET program='other'")
            store.execute("UPDATE browser_profile_leases SET program='other'")
        elif mutation == 'canonical-owner-mismatch':
            store.execute("UPDATE browser_profile_leases SET owner_agent_id='intruder' WHERE lease_id='source'")
        else:
            store.execute("UPDATE browser_profile_leases SET account_alias='other' WHERE lease_id='source'")
        before = [tuple(row) for row in store.execute('SELECT * FROM browser_profile_leases ORDER BY lease_id')]
    if mutation == 'other-program-policy':
        with manager.db() as store:
            store.execute("UPDATE browsers SET program='other'")
    with manager.db() as store:
        before_manager = [tuple(row) for row in store.execute('SELECT * FROM browsers ORDER BY lease_id')]
    cdp_calls = []
    def cdp(url):
        cdp_calls.append(url)
        return {'status': 'ready'}
    monkeypatch.setattr(lease, 'local_cdp_version', cdp)
    import httpx
    monkeypatch.setattr(httpx, 'Client', lambda *args, **kwargs: pytest.fail('adapter reached'))
    result = manager.manager_fixture_auth_transfer('source', 'destination', origin=ORIGIN)
    assert result == {'status': 'auth-clone-unavailable', 'reason': expected}
    assert len(cdp_calls) == (2 if mutation == 'other-program-policy' else 0)
    with lease.connect(canonical) as store:
        assert [tuple(row) for row in store.execute('SELECT * FROM browser_profile_leases ORDER BY lease_id')] == before
    with manager.db() as store:
        assert [tuple(row) for row in store.execute('SELECT * FROM browsers ORDER BY lease_id')] == before_manager
        assert store.execute('SELECT count(*) FROM fixture_peers').fetchone()[0] == 0
        assert store.execute('SELECT count(*) FROM fixture_generations').fetchone()[0] == 0
