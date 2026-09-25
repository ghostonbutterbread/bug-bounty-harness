"""Fixture-only generation workflow: no account, site or Hoster integration."""
import json
import threading

import pytest
from test_browser_manager_transfer_gate import candidates, manager, lease

ORIGIN = 'http://127.0.0.1:31337'


def setup(tmp_path, monkeypatch):
    canonical = candidates(tmp_path, monkeypatch)
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


def test_pending_applied_metadata_and_no_automatic_transfer(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    transfers = []
    monkeypatch.setattr(manager, 'manager_fixture_auth_transfer', lambda *a, **k: transfers.append((a, k)) or {'status': 'fixture-auth-transferred'})
    assert promote() == {'status': 'fixture-generation-promoted', 'generation': 1}
    assert transfers == []
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
    assert manager.manager_fixture_apply('destination', generation=1, owner_agent_id='destination', owner_run_id='run')['reason'] == 'recipient-approval-required'
    assert apply() == {'status': 'auth-clone-unavailable', 'reason': 'recipient-approval-required'}
    assert transfers == []
    assert manager.manager_fixture_pending('destination') == {'status': 'pending', 'generation': 1}
    monkeypatch.setattr(manager, '_fixture_authenticated_recipient', lambda: ('destination', 'run'))
    assert apply() == {'status': 'fixture-peer-applied', 'generation': 1}
    assert transfers[0][0] == ('source', 'destination')
    assert transfers[0][1]['expected_source_identity'] == metadata['source_identity']
    assert manager.manager_fixture_pending('destination') == {'status': 'applied', 'generation': 1}
    assert apply()['reason'] == 'pending-peer-unavailable'
    assert promote() == {'status': 'fixture-generation-promoted', 'generation': 2}
    assert manager.manager_fixture_pending('destination') == {'status': 'pending', 'generation': 2}
    assert apply()['reason'] == 'pending-peer-unavailable'


@pytest.mark.parametrize('key,column', [('program','program'), ('auth_domain','auth_domain'), ('account','account_alias')])
def test_pool_exactness(tmp_path, monkeypatch, key, column):
    canonical = setup(tmp_path, monkeypatch)
    monkeypatch.setattr(manager, '_fixture_authenticated_recipient', lambda: ('destination', 'run'))
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


def test_stale_source_owner_and_recipient_decline(tmp_path, monkeypatch):
    canonical = setup(tmp_path, monkeypatch)
    assert promote()['generation'] == 1
    # Copied owner labels do not grant authority to a different authenticated caller.
    monkeypatch.setattr(manager, '_fixture_authenticated_recipient', lambda: ('intruder', 'run'))
    assert apply()['reason'] == 'recipient-approval-required'
    assert manager.manager_fixture_pending('destination')['status'] == 'pending'
    monkeypatch.setattr(manager, '_fixture_authenticated_recipient', lambda: ('destination', 'run'))
    with lease.connect(canonical) as store:
        store.execute("UPDATE browser_profile_leases SET owner_run_id='changed' WHERE lease_id='source'")
    assert apply()['reason'] == 'stale-source'
    assert manager.manager_fixture_pending('destination')['status'] == 'pending'
    with manager.db() as store:
        assert store.execute('SELECT generation FROM fixture_generations').fetchone()[0] == 1


@pytest.mark.parametrize('reason', ['destination-app-check-failed', 'destination-not-empty'])
def test_failed_transfer_retains_pending_and_source(tmp_path, monkeypatch, reason):
    setup(tmp_path, monkeypatch)
    monkeypatch.setattr(manager, '_fixture_authenticated_recipient', lambda: ('destination', 'run'))
    assert promote()['generation'] == 1
    monkeypatch.setattr(manager, 'manager_fixture_auth_transfer', lambda *a, **k: {'status':'auth-clone-unavailable','reason':reason})
    assert apply()['reason'] == reason
    assert manager.manager_fixture_pending('destination') == {'status':'pending','generation':1}
    with manager.db() as store:
        assert store.execute('SELECT source_lease FROM fixture_generations').fetchone()[0] == 'source'


def test_uncertain_transfer_is_not_retryable(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    monkeypatch.setattr(manager, '_fixture_authenticated_recipient', lambda: ('destination', 'run'))
    assert promote()['generation'] == 1
    monkeypatch.setattr(manager, 'manager_fixture_auth_transfer', lambda *a, **k: {
        'status': 'auth-clone-unavailable', 'reason': 'destination-cleanup-incomplete'})
    assert apply()['reason'] == 'destination-cleanup-incomplete'
    assert manager.manager_fixture_pending('destination') == {'status':'applying','generation':1}
    assert apply()['reason'] == 'pending-peer-unavailable'
    assert promote()['reason'] == 'peer-transfer-in-progress'


def test_interleaved_handoff_waits_for_apply_disposition(tmp_path, monkeypatch):
    canonical = setup(tmp_path, monkeypatch)
    monkeypatch.setattr(manager, '_fixture_authenticated_recipient', lambda: ('destination', 'run'))
    assert promote()['generation'] == 1
    entered, attempted, changed = (threading.Event() for _ in range(3))
    def transfer(*args, **kwargs):
        entered.set()
        assert attempted.wait(3)
        assert not changed.wait(.1)
        return {'status': 'auth-clone-unavailable', 'reason': 'manager-identity-unverified'}
    monkeypatch.setattr(manager, 'manager_fixture_auth_transfer', transfer)
    def handoff():
        assert entered.wait(3)
        attempted.set()
        with manager.node_lock(manager.STATE):
            with manager.db() as store:
                store.execute("UPDATE browsers SET agent_id='new-owner' WHERE lease_id='destination'")
            with lease.connect(canonical) as store:
                store.execute("UPDATE browser_profile_leases SET owner_agent_id='new-owner' WHERE lease_id='destination'")
        changed.set()
    worker = threading.Thread(target=handoff)
    worker.start()
    try:
        assert apply()['reason'] == 'manager-identity-unverified'
    finally:
        worker.join(timeout=4)
    assert changed.is_set()
    assert manager.manager_fixture_pending('destination') == {'status': 'pending', 'generation': 1}
    assert apply()['reason'] == 'recipient-approval-required'


def test_canonical_handoff_before_transfer_is_rejected_and_pending(tmp_path, monkeypatch):
    canonical = setup(tmp_path, monkeypatch)
    monkeypatch.setattr(manager, '_fixture_authenticated_recipient', lambda: ('destination', 'run'))
    assert promote()['generation'] == 1
    def handoff_then_transfer(*args, **kwargs):
        with lease.connect(canonical) as store:
            store.execute("UPDATE browser_profile_leases SET owner_agent_id='new-owner' WHERE lease_id='destination'")
        return {'status': 'auth-clone-unavailable', 'reason': 'manager-identity-unverified'}
    monkeypatch.setattr(manager, 'manager_fixture_auth_transfer', handoff_then_transfer)
    assert apply()['reason'] == 'manager-identity-unverified'
    assert manager.manager_fixture_pending('destination') == {'status': 'pending', 'generation': 1}


def test_changed_recipient_after_transfer_cannot_mark_applied(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    monkeypatch.setattr(manager, '_fixture_authenticated_recipient', lambda: ('destination', 'run'))
    assert promote()['generation'] == 1
    def changed(*args, **kwargs):
        with manager.db() as store:
            store.execute("UPDATE browsers SET agent_id='new-owner' WHERE lease_id='destination'")
        return {'status': 'fixture-auth-transferred'}
    monkeypatch.setattr(manager, 'manager_fixture_auth_transfer', changed)
    assert apply()['status'] != 'fixture-peer-applied'
    assert manager.manager_fixture_pending('destination')['status'] != 'applied'


def test_interrupted_transfer_never_marks_peer_applied_or_retryable(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    monkeypatch.setattr(manager, '_fixture_authenticated_recipient', lambda: ('destination', 'run'))
    assert promote()['generation'] == 1
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(manager, 'manager_fixture_auth_transfer', interrupted)
    with pytest.raises(KeyboardInterrupt):
        apply()
    assert manager.manager_fixture_pending('destination') == {'status': 'applying', 'generation': 1}


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
