"""Manager-bound transfer authorization tests; no browser or secret material."""
import importlib.util
import argparse
import threading
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/browser_profile_lease.py'
spec = importlib.util.spec_from_file_location('browser_profile_lease_fence', SOURCE)
lease = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lease)


def fixture_db(tmp_path):
    db = tmp_path / 'browser_profile_leases.sqlite'
    with lease.connect(db) as c:
        lease.init_db(c)
        for lid, owner, profile in [('source', 'alice', 'src'), ('destination', 'bob', 'dst')]:
            c.execute('''INSERT INTO browser_profile_leases
                (lease_id, program, account_alias, auth_domain, owner_agent_id, owner_run_id,
                 purpose, profile_dir, status, browser_status, manager_id, created_at, heartbeat_at, expires_at)
                VALUES (?, 'program', 'account', 'domain', ?, 'run', 'test', ?, 'active',
                        'running', 'manager', 1, 1, 99999999999)''', (lid, owner, profile))
            c.execute('UPDATE browser_profile_leases SET service_unit=?, instance_key=? WHERE lease_id=?',
                      ('unit-'+lid, profile+'-key', lid))
        c.commit()
    return db


def identity(lid, owner, profile):
    return dict(lease_id=lid, program='program', auth_domain='domain', account_alias='account',
                owner_agent_id=owner, owner_run_id='run', manager_id='manager',
                profile_dir=profile, service_unit='unit-'+lid, process_start='123-'+lid,
                root='root-'+lid, profile_identity='dev:inode-'+lid,
                control_generation='control-'+lid, auth_generation='auth-'+lid)


def ready(db):
    src, dst = identity('source', 'alice', 'src'), identity('destination', 'bob', 'dst')
    with lease.connect(db) as c:
        lease.init_db(c)
        for item in (src, dst):
            c.execute('''INSERT INTO browser_transfer_identity
                (lease_id, service_unit, process_start, root, profile_identity,
                 control_generation, auth_generation) VALUES (?, ?, ?, ?, ?, ?, ?)''',
                tuple(item[key] for key in ('lease_id', 'service_unit', 'process_start',
                    'root', 'profile_identity', 'control_generation', 'auth_generation')))
        c.commit()
    return src, dst


def test_migrated_rows_fail_closed(tmp_path):
    db = fixture_db(tmp_path)
    src, dst = identity('source', 'alice', 'src'), identity('destination', 'bob', 'dst')
    assert lease.issue_transfer_grant(db, src, dst)['status'] == 'auth-clone-unavailable'


def test_grant_one_use_and_exact_identity(tmp_path):
    db = fixture_db(tmp_path)
    src, dst = ready(db)
    result = lease.issue_transfer_grant(db, src, dst)
    assert result['status'] == 'authorized'
    grant = result['grant_id']
    assert lease.consume_transfer_grant(db, grant, src, dst)['status'] == 'authorized'
    assert lease.consume_transfer_grant(db, grant, src, dst)['status'] == 'auth-clone-unavailable'


@pytest.mark.parametrize('field,value', [('program', 'other'), ('auth_domain', 'other'),
    ('account_alias', 'other'), ('owner_agent_id', 'mallory'), ('owner_run_id', 'other'),
    ('manager_id', 'other'), ('profile_dir', 'other'), ('service_unit', 'other'),
    ('process_start', 'other'), ('root', 'other'), ('profile_identity', 'other'),
    ('control_generation', 'other'), ('auth_generation', 'other')])
@pytest.mark.parametrize('side', ['source', 'destination'])
def test_identity_mismatch_never_consumes(tmp_path, field, value, side):
    db = fixture_db(tmp_path)
    src, dst = ready(db)
    grant = lease.issue_transfer_grant(db, src, dst)['grant_id']
    changed = dict(src if side == 'source' else dst, **{field: value})
    got = lease.consume_transfer_grant(db, grant, changed if side == 'source' else src,
                                       changed if side == 'destination' else dst)
    assert got['status'] == 'auth-clone-unavailable'
    assert lease.consume_transfer_grant(db, grant, src, dst)['status'] == 'auth-clone-unavailable'


@pytest.mark.parametrize('mutation', ['release', 'handoff', 'rotate'])
def test_canonical_change_revokes_grant(tmp_path, mutation):
    db = fixture_db(tmp_path)
    src, dst = ready(db)
    grant = lease.issue_transfer_grant(db, src, dst)['grant_id']
    with lease.connect(db) as c:
        if mutation == 'rotate':
            c.execute("UPDATE browser_transfer_identity SET control_generation='new' WHERE lease_id='source'")
        else:
            c.execute("UPDATE browser_profile_leases SET status=? WHERE lease_id='source'",
                      ('released' if mutation == 'release' else 'released',))
        c.commit()
    assert lease.consume_transfer_grant(db, grant, src, dst)['status'] == 'auth-clone-unavailable'


def test_actual_release_revokes_old_owner(tmp_path):
    db = fixture_db(tmp_path)
    src, dst = ready(db)
    grant = lease.issue_transfer_grant(db, src, dst)['grant_id']
    args = argparse.Namespace(state_dir=str(tmp_path), lease_id='source', agent_id='alice',
                              manager_id='manager', disposition='completed', profile_health='healthy')
    assert lease.cmd_release(args)['status'] == 'released'
    assert lease.consume_transfer_grant(db, grant, src, dst)['status'] == 'auth-clone-unavailable'
    assert lease.issue_transfer_grant(db, src, dst)['status'] == 'auth-clone-unavailable'


def test_actual_handoff_revokes_old_owner(tmp_path):
    db = fixture_db(tmp_path)
    src, dst = ready(db)
    grant = lease.issue_transfer_grant(db, src, dst)['grant_id']
    result = lease.transfer_managed_lease(
        db, 'source', 'manager', 'charlie', 'new-run', 'test', 300,
        'http://127.0.0.1:9222', expected={'owner_agent_id': 'alice'})
    assert result['status'] == 'leased'
    assert result['lease']['owner_agent_id'] == 'charlie'
    assert lease.consume_transfer_grant(db, grant, src, dst)['status'] == 'auth-clone-unavailable'
    assert lease.issue_transfer_grant(db, src, dst)['status'] == 'auth-clone-unavailable'


def test_handoff_and_redemption_serialize(tmp_path):
    db = fixture_db(tmp_path)
    src, dst = ready(db)
    grant = lease.issue_transfer_grant(db, src, dst)['grant_id']
    barrier = threading.Barrier(3)
    outcomes = {}
    def handoff():
        barrier.wait()
        outcomes['handoff'] = lease.transfer_managed_lease(
            db, 'source', 'manager', 'charlie', 'new-run', 'test', 300,
            'http://127.0.0.1:9222', expected={'owner_agent_id': 'alice'})['status']
    def redeem():
        barrier.wait()
        outcomes['redeem'] = lease.consume_transfer_grant(db, grant, src, dst)['status']
    threads = [threading.Thread(target=handoff), threading.Thread(target=redeem)]
    for thread in threads: thread.start()
    barrier.wait()
    for thread in threads: thread.join()
    assert outcomes['handoff'] == 'leased'
    assert outcomes['redeem'] in ('authorized', 'auth-clone-unavailable')
    # A redemption serialized earlier cannot be replayed after the handoff.
    assert lease.consume_transfer_grant(db, grant, src, dst)['status'] == 'auth-clone-unavailable'
    assert lease.issue_transfer_grant(db, src, dst)['status'] == 'auth-clone-unavailable'


def test_concurrent_redemption_only_one_wins(tmp_path):
    db = fixture_db(tmp_path)
    src, dst = ready(db)
    grant = lease.issue_transfer_grant(db, src, dst)['grant_id']
    barrier = threading.Barrier(3)
    outcomes = []
    def redeem():
        barrier.wait()
        outcomes.append(lease.consume_transfer_grant(db, grant, src, dst)['status'])
    threads = [threading.Thread(target=redeem) for _ in range(2)]
    for thread in threads: thread.start()
    barrier.wait()
    for thread in threads: thread.join()
    assert sorted(outcomes) == ['auth-clone-unavailable', 'authorized']
