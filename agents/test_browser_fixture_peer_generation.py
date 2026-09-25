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
