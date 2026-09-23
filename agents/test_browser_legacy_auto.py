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


def take(owner, key, agent, manager=None, *, automatic=None):
    request = argparse.Namespace(**vars(owner))
    request.instance_key, request.agent_id, request.run_id = key, agent, (owner.run_id if agent == owner.agent_id else agent)
    request.manager_id = manager
    request.automatic_instance = key.startswith('auto-') if automatic is None else automatic
    if request.automatic_instance and manager:
        request.selection_proof = profiles.authorize_auto_slot(
            Path(owner.state_dir) / 'browser_profile_leases.sqlite', request.program, request.account,
            request.auth_domain, key, manager, request.agent_id, request.run_id)
    return profiles.cmd_acquire(request)


def test_stopped_missing_receipt_fails_closed_on_unit_or_profile_lock(monkeypatch, tmp_path, capsys):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    c.execute("UPDATE browsers SET state='stopped'")
    c.commit()
    Path(row['launch_file']).unlink()
    monkeypatch.setattr(m, 'unit_active', lambda _: True)
    with pytest.raises(SystemExit):
        m.automatic_instance(c, args(), 'anon', 'legacy-global')
    assert json.loads(capsys.readouterr().out)['reason'] == 'legacy-profile-not-quiescent'
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    (Path(row['profile_dir']) / 'SingletonLock').symlink_to('unknown-1')
    with pytest.raises(SystemExit):
        m.automatic_instance(c, args(), 'anon', 'legacy-global')
    assert json.loads(capsys.readouterr().out)['reason'] == 'legacy-profile-not-quiescent'
    assert Path(row['profile_dir']).exists()


def test_stopped_history_first_request_retains_auth_and_sweep(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    c.execute("UPDATE browsers SET state='stopped',updated=0")
    c.execute("INSERT INTO browsers SELECT 'older', 'older-browser', program, account, auth_domain, agent_id, run_id, purpose, 'older-unit', profile_dir, ?, state, tab_count, last_activity, created-1, 0 FROM browsers WHERE lease_id=?",
              (str(tmp_path / 'missing-launch.json'), row['lease_id']))
    c.commit()
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        db.execute("UPDATE browser_profile_leases SET status='released', released_at=1, profile_health='healthy' WHERE lease_id=?", (row['lease_id'],))
        for n in range(19):
            db.execute("INSERT INTO browser_profile_leases(lease_id, program, account_alias, auth_domain, owner_agent_id, owner_run_id, purpose, profile_dir, status, browser_status, created_at, heartbeat_at, expires_at, released_at, manager_id, instance_key) SELECT 'historical-'||?, program, account_alias, auth_domain, owner_agent_id, owner_run_id, purpose, profile_dir, 'released', browser_status, created_at, heartbeat_at, expires_at, 0, manager_id, instance_key FROM browser_profile_leases WHERE lease_id=?", (n, row['lease_id']))
        db.execute("UPDATE browser_profile_leases SET profile_health='healthy' WHERE lease_id LIKE 'historical-%'")
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    removed, skipped = m.sweep_rows(c, 14, True)
    assert not removed and len(skipped) == 2 and Path(row['profile_dir']).exists()
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True) == ''
    assert take(owner, '', 'new', manager)['status'] == 'leased'
    c.execute("UPDATE browsers SET state='running', agent_id='new', run_id='new', lease_id=? WHERE lease_id=?",
              (profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite').execute(
                  "SELECT lease_id FROM browser_profile_leases WHERE status='active'").fetchone()[0], row['lease_id']))
    c.commit()
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    key = m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True)
    assert key.startswith('auto-')
    assert take(owner, key, 'second', manager)['status'] == 'leased'


def test_forged_automatic_provenance_rejected(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    key = m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True)
    forged = argparse.Namespace(**vars(owner))
    forged.instance_key, forged.automatic_instance = key, True
    forged.agent_id, forged.run_id = 'intruder', 'intruder'
    assert profiles.cmd_acquire(forged)['reason'] == 'manager-selection-required'
    import subprocess, sys
    cli = subprocess.run([sys.executable, str(m.LEASE), '--state-dir', owner.state_dir,
        'acquire', 'demo', 'anon', '--auth-domain', 'legacy-global', '--agent-id', 'intruder',
        '--run-id', 'intruder', '--purpose', 'fixture', '--instance-key', key,
        '--manager-id', manager, '--automatic-instance'], capture_output=True, text=True)
    assert json.loads(cli.stdout)['reason'] == 'manager-selection-required'
    proof = profiles.authorize_auto_slot(m.STATE.parent / 'browser_profile_leases.sqlite',
        'demo', 'anon', 'legacy-global', key, manager, 'legitimate', 'legitimate')
    forged.selection_proof = proof
    assert profiles.cmd_acquire(forged)['reason'] == 'manager-selection-required'
    forged.agent_id = forged.run_id = 'legitimate'
    assert profiles.cmd_acquire(forged)['status'] == 'leased'
    assert profiles.cmd_acquire(forged)['reason'] == 'manager-selection-required'


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
    assert take(owner, 'auto-explicit', 'intruder', manager, automatic=False)['status'] == 'locked'
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
    def acquire(_args, operation, *parts, **_kwargs):
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
