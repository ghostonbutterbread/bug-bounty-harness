"""Legacy boundary migration: SQLite races and manager selection, no live accounts."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import threading

import pytest

from agents.test_browser_lease_recovery import provisioner, record, args
import browser_profile_lease as profiles


def fixture(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    c, row = record(m, tmp_path, None)
    manager = hashlib.sha256(str(m.STATE.resolve()).encode()).hexdigest()
    owner = argparse.Namespace(program='demo', account='anon', auth_domain='legacy-global',
        agent_id='old-agent', run_id='old-run', purpose='fixture', ttl_seconds=3600,
        state_dir=str(m.STATE.parent), recover_profile=False, instance_key='', manager_id=manager)
    got = profiles.cmd_acquire(owner)
    assert got['status'] == 'leased'
    c.execute('UPDATE browsers SET lease_id=? WHERE lease_id=?', (got['lease']['lease_id'], row['lease_id']))
    c.commit()
    row = c.execute('SELECT * FROM browsers').fetchone()
    Path(row['launch_file']).write_text(json.dumps({'instance_key': '', 'instance_selection': 'legacy'}))
    return m, c, row, owner, manager


def take(owner, key, agent, manager=None):
    request = argparse.Namespace(**vars(owner))
    request.instance_key, request.agent_id, request.run_id = key, agent, (owner.run_id if agent == owner.agent_id else agent)
    request.manager_id = manager
    return profiles.cmd_acquire(request)


def test_manager_proven_migration_preserves_auth_and_owner(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(m, 'healthy', lambda r: r['lease_id'] == row['lease_id'])
    a = args()
    assert m.automatic_instance(c, a, 'anon', 'legacy-global') == ''
    key = m.automatic_instance(c, a, 'anon', 'legacy-global', allow_migration=True)
    assert key.startswith('auto-')
    assert take(owner, key, 'another', manager)['status'] == 'leased'
    assert take(owner, '', 'old-agent', manager)['status'] == 'already-owned'
    assert take(owner, 'auto-intruder', 'intruder')['status'] == 'locked'
    assert Path(row['profile_dir']).exists()
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        assert db.execute('SELECT profile_dir FROM browser_legacy_auto').fetchone()[0] == row['profile_dir']
        assert db.execute("SELECT COUNT(*) FROM browser_profile_leases WHERE status='active'").fetchone()[0] == 2


def test_canonical_transfer_preserves_legacy_parallel_conflict(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    key = m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True)
    auto = take(owner, key, 'peer', manager)['lease']
    result = profiles.transfer_managed_lease(m.STATE.parent / 'browser_profile_leases.sqlite',
        auto['lease_id'], manager, 'next', 'next', 'fixture', 60, 'http://127.0.0.1:9/fenced')
    assert result['status'] == 'leased'
    assert result['lease']['profile_dir'] == auto['profile_dir']
    assert take(owner, '', 'old-agent', manager)['status'] == 'already-owned'


def test_migration_requires_proven_live_manager_and_exact_history(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    a = args()
    monkeypatch.setattr(m, 'healthy', lambda _: False)
    assert m.automatic_instance(c, a, 'anon', 'legacy-global', allow_migration=True) == ''
    assert take(owner, 'auto-new', 'other', manager)['status'] == 'locked'
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        db.execute('UPDATE browser_profile_leases SET profile_dir=? WHERE lease_id=?', ('/wrong', row['lease_id']))
    assert m.automatic_instance(c, a, 'anon', 'legacy-global', allow_migration=True) == ''


def test_single_policy_blocks_migrated_parallel_and_is_domain_local(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    key = m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True)
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        profiles.init_resource_policy(db)
        db.execute('INSERT INTO browser_concurrency_policy VALUES(?,?,?,?)', ('demo', 'anon', 'legacy-global', 'single'))
    assert take(owner, key, 'other', manager)['status'] == 'locked'
    assert take(owner, 'auto-other', 'other', manager)['status'] == 'locked'
    assert m.account_policy('demo', 'anon', 'legacy-global')
    assert not m.account_policy('demo', 'anon', 'other.test')


def test_canonical_race_and_legacy_old_api_stay_exclusive(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True)
    barrier = threading.Barrier(2)
    def run(n):
        barrier.wait(timeout=5)
        return take(owner, 'auto-same', f'agent-{n}', manager)['status']
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(run, (1, 2))) == ['leased', 'locked']
    assert take(owner, '', 'new-legacy', None)['status'] == 'locked'
    assert take(owner, 'other-explicit', 'other', None)['status'] == 'locked'


def test_migrated_legacy_profile_excluded_from_age_sweep(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True)
    c.execute("UPDATE browsers SET state='stopped',updated=0")
    c.commit()
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    removed, skipped = m.sweep_rows(c, 14, True)
    assert removed == [] and skipped[0]['reason'] == 'legacy-auth-retained'
    assert Path(row['profile_dir']).exists()


@pytest.mark.parametrize('admitted,single', [(True, False), (False, False), (True, True)])
def test_start_migration_gate_never_retires_active_legacy(monkeypatch, tmp_path, capsys, admitted, single):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    monkeypatch.setattr(m, 'sweep_rows', lambda *_: ([], []))
    monkeypatch.setattr(m, 'cleanup_unused', lambda *_: [])
    monkeypatch.setattr(m, 'retire', lambda *_: pytest.fail('active legacy owner must survive'))
    monkeypatch.setattr(m, 'admission', lambda *_: {'status': 'admitted' if admitted else 'queued'})
    if single:
        with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
            profiles.init_resource_policy(db)
            db.execute('INSERT INTO browser_concurrency_policy VALUES(?,?,?,?)', ('demo', 'anon', 'legacy-global', 'single'))
    calls = []
    def acquire(_args, operation, *parts):
        calls.append((operation, parts))
        return {'status': 'locked'}
    monkeypatch.setattr(m, 'lease', acquire)
    with pytest.raises(SystemExit):
        m.start(args())
    result = json.loads(capsys.readouterr().out)
    if admitted and not single:
        assert result['reason'] == 'account-policy-locked'
        assert any(p.startswith('auto-') for operation, parts in calls for p in parts if isinstance(p, str))
    else:
        assert not any(p.startswith('auto-') for operation, parts in calls for p in parts if isinstance(p, str))
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE name='browser_legacy_auto'").fetchone()
        assert bool(exists) == (admitted and not single)
    assert c.execute('SELECT state FROM browsers').fetchone()[0] == 'running'


def test_null_domain_history_conservatively_blocks_migration(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        db.execute('UPDATE browser_profile_leases SET auth_domain=NULL WHERE lease_id=?', (row['lease_id'],))
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True) == ''
    assert take(owner, 'auto-other', 'other', manager)['status'] == 'locked'


def test_migration_marker_idempotent_and_stopped_legacy_with_active_auto(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    a = args()
    key = m.automatic_instance(c, a, 'anon', 'legacy-global', allow_migration=True)
    assert m.automatic_instance(c, a, 'anon', 'legacy-global', allow_migration=True) == key
    peer = take(owner, key, 'peer', manager)
    assert peer['status'] == 'leased'
    c.execute('INSERT INTO browsers VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (
        peer['lease']['lease_id'], 'peer-browser', 'demo', 'anon', 'legacy-global', 'peer', 'peer',
        'fixture', 'peer-unit', peer['lease']['profile_dir'], str(tmp_path / 'peer.json'),
        'running', 0, 1, 1, 1))
    (tmp_path / 'peer.json').write_text(json.dumps({'instance_key': key, 'instance_selection': 'automatic'}))
    c.execute("UPDATE browsers SET state='stopped' WHERE lease_id=?", (row['lease_id'],))
    c.commit()
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        db.execute("UPDATE browser_profile_leases SET status='released',released_at=1 WHERE lease_id=?", (row['lease_id'],))
    monkeypatch.setattr(m, 'stopped', lambda _: True)
    assert m.automatic_instance(c, a, 'anon', 'legacy-global', allow_migration=True).startswith('auto-')
    c.execute("UPDATE browsers SET state='stopped' WHERE browser_id='peer-browser'")
    c.commit()
    assert m.automatic_instance(c, a, 'anon', 'legacy-global', allow_migration=True) == ''
