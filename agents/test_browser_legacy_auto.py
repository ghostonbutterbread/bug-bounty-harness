"""Legacy boundary migration: SQLite races and manager selection, no live accounts."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import threading

import pytest

from agents.test_browser_lease_recovery import provisioner, record, args
import browser_profile_lease as profiles
from browser_lifecycle import process_identity


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


@pytest.mark.parametrize('conflict', ['none', 'other-path', 'null-domain', 'other-manager',
                                      'wrong-manager-row', 'arbitrary-path', 'active-peer'])
def test_stopped_pre_domain_inherits_only_exact_manager_history(monkeypatch, tmp_path, conflict):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    pre_domain = profiles.profile_dir('demo', 'legacy-global', 'anon').parent.parent / 'anon'
    pre_domain.mkdir(parents=True, exist_ok=True)
    sentinel = pre_domain / 'fixture-auth-sentinel'
    sentinel.write_text('authenticated')
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        db.execute("UPDATE browser_profile_leases SET profile_dir=?,status='released',released_at=1,profile_health='healthy' WHERE lease_id=?",
                   (str(pre_domain), row['lease_id']))
        if conflict == 'other-path':
            db.execute("INSERT INTO browser_profile_leases(lease_id,program,account_alias,auth_domain,owner_agent_id,owner_run_id,purpose,profile_dir,status,created_at,heartbeat_at,expires_at,manager_id) SELECT 'conflict',program,account_alias,auth_domain,owner_agent_id,owner_run_id,purpose,?,'released',created_at,heartbeat_at,expires_at,manager_id FROM browser_profile_leases WHERE lease_id=?", (str(profiles.profile_dir('demo', 'legacy-global', 'anon')), row['lease_id']))
        if conflict == 'null-domain':
            db.execute('UPDATE browser_profile_leases SET auth_domain=NULL WHERE lease_id=?', (row['lease_id'],))
        if conflict == 'other-manager':
            db.execute('UPDATE browser_profile_leases SET manager_id=? WHERE lease_id=?', ('different', row['lease_id']))
        if conflict == 'active-peer':
            db.execute("UPDATE browser_profile_leases SET status='active' WHERE lease_id=?", (row['lease_id'],))
    c.execute("UPDATE browsers SET profile_dir=?,state='stopped' WHERE lease_id=?", (str(pre_domain), row['lease_id']))
    c.commit()
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    selection = args()
    assert m.automatic_instance(c, selection, 'anon', 'legacy-global', allow_migration=True) == ''
    request = argparse.Namespace(**vars(owner))
    request.agent_id = request.run_id = 'first'
    request.stopped_legacy_lease_id = row['lease_id']
    request.stopped_legacy_profile_dir = str(pre_domain)
    request.stopped_legacy_agent_id = row['agent_id']
    request.stopped_legacy_run_id = row['run_id']
    if conflict == 'wrong-manager-row':
        request.stopped_legacy_agent_id = 'unrelated'
    if conflict == 'arbitrary-path':
        request.stopped_legacy_profile_dir = str(tmp_path / 'arbitrary')
    got = profiles.cmd_acquire(request)
    if conflict != 'none':
        assert got['status'] == 'locked'
        assert sentinel.read_text() == 'authenticated'
        return
    assert got['status'] == 'leased' and got['lease']['profile_dir'] == str(pre_domain)
    assert sentinel.read_text() == 'authenticated'
    c.execute('UPDATE browsers SET state=?,lease_id=?,agent_id=?,run_id=? WHERE lease_id=?',
              ('running', got['lease']['lease_id'], 'first', 'first', row['lease_id']))
    c.commit()
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    key = m.automatic_instance(c, selection, 'anon', 'legacy-global', allow_migration=True)
    assert key.startswith('auto-')
    peer = take(owner, key, 'second', manager)
    assert peer['status'] == 'leased' and peer['lease']['profile_dir'] != str(pre_domain)


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


@pytest.mark.parametrize('conflict', ['running-other-owner', 'stopped-other-path', 'running-other-run'])
def test_running_migration_reconciles_historical_unkeyed_manager_rows(monkeypatch, tmp_path, conflict):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    path = str(tmp_path / 'other-profile') if conflict == 'stopped-other-path' else row['profile_dir']
    agent = 'other-agent' if conflict == 'running-other-owner' else row['agent_id']
    run = 'other-run' if conflict == 'running-other-run' else row['run_id']
    state = 'stopped' if conflict == 'stopped-other-path' else 'running'
    c.execute('INSERT INTO browsers SELECT ?, ?, program, account, auth_domain, ?, ?, purpose, ?, ?, ?, ?, tab_count, last_activity, created-1, updated FROM browsers WHERE lease_id=?',
              ('older', 'older-browser', agent, run, 'older-unit', path,
               str(tmp_path / 'older.json'), state, row['lease_id']))
    c.commit()
    (tmp_path / 'older.json').write_text(json.dumps({'instance_key': '', 'instance_selection': 'legacy'}))
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True) == ''
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='browser_legacy_auto'").fetchone()
    assert take(owner, 'auto-peer', 'peer', manager)['status'] == 'locked'

def test_running_migration_allows_stopped_former_owner_on_same_profile(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    c.execute("INSERT INTO browsers SELECT 'older', 'older-browser', program, account, auth_domain, 'former-agent', 'former-run', purpose, 'older-unit', profile_dir, ?, 'stopped', tab_count, last_activity, created-1, updated FROM browsers WHERE lease_id=?",
              (str(tmp_path / 'older.json'), row['lease_id']))
    c.commit()
    (tmp_path / 'older.json').write_text(json.dumps({'instance_key': '', 'instance_selection': 'legacy'}))
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    key = m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True)
    assert key.startswith('auto-')
    assert take(owner, key, 'peer', manager)['status'] == 'leased'

@pytest.mark.parametrize('state,observable', [
    ('running', 'owner'), ('stopped', 'unit'), ('stopped', 'root'), ('stopped', 'cdp'),
])
def test_cross_domain_shared_path_blocks_stopped_reuse_and_marker(monkeypatch, tmp_path, capsys, state, observable):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    c.execute("UPDATE browsers SET state='stopped' WHERE lease_id=?", (row['lease_id'],))
    c.execute("INSERT INTO browsers SELECT 'cross', 'cross-browser', program, account, 'other.test', 'cross-owner', 'cross-run', purpose, 'cross-unit', profile_dir, ?, ?, tab_count, last_activity, created-1, updated FROM browsers WHERE lease_id=?",
              (str(tmp_path / 'cross.json'), state, row['lease_id']))
    c.commit()
    info = {'instance_key': '', 'instance_selection': 'legacy'}
    if observable == 'root':
        info['process_identity'] = process_identity(os.getpid())
    if observable == 'cdp':
        info['cdp_url'] = 'http://127.0.0.1:9222'
        monkeypatch.setattr(profiles, 'local_cdp_version', lambda _: {'status': 'ready'})
    (tmp_path / 'cross.json').write_text(json.dumps(info))
    monkeypatch.setattr(m, 'unit_active', lambda unit: unit == 'cross-unit' and observable == 'unit')
    with pytest.raises(SystemExit):
        m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True)
    assert json.loads(capsys.readouterr().out)['reason'] == 'legacy-profile-not-quiescent'
    monkeypatch.setattr(m, 'sweep_rows', lambda *_: ([], []))
    monkeypatch.setattr(m, 'cleanup_unused', lambda *_: [])
    with pytest.raises(SystemExit):
        m.start(args())
    assert json.loads(capsys.readouterr().out)['reason'] == 'legacy-profile-not-quiescent'
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='browser_legacy_auto'").fetchone()


def test_cross_domain_distinct_profile_does_not_block_migration(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    distinct = profiles.profile_dir('demo', 'other.test', 'anon')
    distinct.mkdir(parents=True)
    c.execute("INSERT INTO browsers SELECT 'cross', 'cross-browser', program, account, 'other.test', 'cross-owner', 'cross-run', purpose, 'cross-unit', ?, ?, 'running', tab_count, last_activity, created-1, updated FROM browsers WHERE lease_id=?",
              (str(distinct), str(tmp_path / 'cross.json'), row['lease_id']))
    c.commit()
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    key = m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True)
    assert key.startswith('auto-')
    assert take(owner, key, 'peer', manager)['status'] == 'leased'


def test_unrelated_program_with_unobservable_history_does_not_block_migration(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    c.execute("INSERT INTO browsers SELECT 'unrelated', 'other-browser', 'other-program', account, auth_domain, agent_id, run_id, purpose, 'other-unit', 'other-unit', ?, 'idle-stopped', tab_count, last_activity, created-1, updated FROM browsers WHERE lease_id=?",
              (str(tmp_path / 'other-launch.json'), row['lease_id']))
    c.commit()
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True).startswith('auto-')


def test_shifted_other_program_row_still_blocks_shared_physical_profile(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    alias = tmp_path / 'other-program-alias'
    alias.symlink_to(row['profile_dir'], target_is_directory=True)
    # Recreate the pre-auth-domain physical column order, then run db()'s real
    # ALTER TABLE migration. Old positional inserts still use this layout.
    c.execute("CREATE TABLE old_browsers AS SELECT lease_id,browser_id,program,account,agent_id,run_id,purpose,unit,profile_dir,launch_file,state,tab_count,last_activity,created,updated FROM browsers")
    c.execute('DROP TABLE browsers')
    c.execute('ALTER TABLE old_browsers RENAME TO browsers')
    c.commit()
    c.close()
    c = m.db()
    assert [r['name'] for r in c.execute('PRAGMA table_info(browsers)')][-1] == 'auth_domain'
    c.execute("INSERT INTO browsers SELECT 'shifted', 'shifted-browser', 'other-program', account, agent_id, run_id, purpose, 'browser-shifted-browser', ?, ?, 'running', 0, last_activity, created-1, updated, 'legacy-global' FROM browsers WHERE lease_id=?",
              (str(alias), str(tmp_path / 'shifted.launch.json'), row['lease_id']))
    c.commit()
    assert [r['lease_id'] for r in m.shared_profile_rows(c, row['profile_dir'], 'demo')] == [row['lease_id'], 'shifted']
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True) == ''
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='browser_legacy_auto'").fetchone()


def test_running_legacy_shared_path_other_domain_owner_cannot_mark(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    c.execute("INSERT INTO browsers SELECT 'cross', 'cross-browser', program, account, 'other.test', 'cross-agent', 'cross-run', purpose, 'cross-unit', profile_dir, ?, 'running', tab_count, last_activity, created-1, updated FROM browsers WHERE lease_id=?",
              (str(tmp_path / 'cross.json'), row['lease_id']))
    c.commit()
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True) == ''
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='browser_legacy_auto'").fetchone()


def test_quiescent_cross_domain_former_row_on_shared_path_allows_migration(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    c.execute("INSERT INTO browsers SELECT 'cross', 'cross-browser', program, account, 'other.test', 'former', 'former-run', purpose, 'cross-unit', profile_dir, ?, 'stopped', tab_count, last_activity, created-1, updated FROM browsers WHERE lease_id=?",
              (str(tmp_path / 'cross.json'), row['lease_id']))
    c.commit()
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    key = m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True)
    assert key.startswith('auto-')


@pytest.mark.parametrize('key', ['', 'explicit'])
def test_canonical_active_shared_path_blocks_marker_transaction(monkeypatch, tmp_path, key):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        db.execute("INSERT INTO browser_profile_leases(lease_id,program,account_alias,auth_domain,owner_agent_id,owner_run_id,purpose,profile_dir,status,created_at,heartbeat_at,expires_at,manager_id,instance_key) SELECT 'cross',program,account_alias,'other.test','cross-agent','cross-run',purpose,profile_dir,'active',created_at,heartbeat_at,expires_at,'other-manager',? FROM browser_profile_leases WHERE lease_id=?",
                   (key, row['lease_id']))
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True) == ''
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        assert not db.execute('SELECT 1 FROM browser_legacy_auto').fetchone()

def test_cross_domain_symlink_owner_blocks_stopped_reuse_and_running_marker(monkeypatch, tmp_path, capsys):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    alias = tmp_path / 'cross-alias'
    alias.symlink_to(row['profile_dir'], target_is_directory=True)
    c.execute("INSERT INTO browsers SELECT 'cross', 'cross-browser', program, account, 'other.test', 'cross-agent', 'cross-run', purpose, 'cross-unit', ?, ?, 'running', tab_count, last_activity, created-1, updated FROM browsers WHERE lease_id=?",
              (str(alias), str(tmp_path / 'cross.json'), row['lease_id']))
    c.commit()
    c.execute("UPDATE browsers SET state='stopped' WHERE lease_id=?", (row['lease_id'],))
    c.commit()
    with pytest.raises(SystemExit):
        m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True)
    assert json.loads(capsys.readouterr().out)['reason'] == 'legacy-profile-not-quiescent'
    c.execute("UPDATE browsers SET state='running' WHERE lease_id=?", (row['lease_id'],))
    c.commit()
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True) == ''
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='browser_legacy_auto'").fetchone()

def test_canonical_active_symlink_alias_blocks_marker(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    alias = tmp_path / 'canonical-alias'
    alias.symlink_to(row['profile_dir'], target_is_directory=True)
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        db.execute("INSERT INTO browser_profile_leases(lease_id,program,account_alias,auth_domain,owner_agent_id,owner_run_id,purpose,profile_dir,status,created_at,heartbeat_at,expires_at,manager_id,instance_key) SELECT 'cross',program,account_alias,'other.test','cross-agent','cross-run',purpose,?,'active',created_at,heartbeat_at,expires_at,'other-manager','manual' FROM browser_profile_leases WHERE lease_id=?", (str(alias), row['lease_id']))
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True) == ''
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        assert not db.execute('SELECT 1 FROM browser_legacy_auto').fetchone()

def test_sweep_does_not_remove_keyed_alias_of_legacy_profile(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    target = Path(row['profile_dir'])
    sentinel = target / 'auth-sentinel'
    sentinel.write_text('keep')
    alias = target.parent.parent / 'other.test' / 'anon'
    alias.parent.mkdir(parents=True)
    alias.symlink_to(target, target_is_directory=True)
    c.execute("UPDATE browsers SET profile_dir=?,state='stopped',updated=0 WHERE lease_id=?",
              (str(alias), row['lease_id']))
    c.commit()
    Path(row['launch_file']).write_text(json.dumps({'instance_key': 'manual'}))
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    removed, skipped = m.sweep_rows(c, 14, True)
    assert not removed and skipped[0]['reason'] == 'profile-identity-unverified'
    assert sentinel.read_text() == 'keep'


def test_sweep_blocks_canonical_active_symlink_alias(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    target = Path(row['profile_dir'])
    sentinel = target / 'auth-sentinel'
    sentinel.write_text('keep')
    canonical_alias = tmp_path / 'canonical-alias'
    canonical_alias.symlink_to(target, target_is_directory=True)
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        db.execute("UPDATE browser_profile_leases SET profile_dir=? WHERE lease_id=?",
                   (str(canonical_alias), row['lease_id']))
    c.execute("UPDATE browsers SET state='stopped',updated=0 WHERE lease_id=?", (row['lease_id'],))
    c.commit()
    Path(row['launch_file']).write_text(json.dumps({'instance_key': 'manual'}))
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    removed, skipped = m.sweep_rows(c, 14, True)
    assert not removed and skipped[0]['reason'] == 'legacy-auth-retained'
    assert sentinel.read_text() == 'keep'


def test_alias_claim_between_manager_check_and_marker_transaction(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    alias = tmp_path / 'racing-alias'
    alias.symlink_to(row['profile_dir'], target_is_directory=True)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    register = profiles.register_legacy_auto
    def competing_claim(db_path, *args, **kwargs):
        with profiles.connect(db_path) as db:
            db.execute("INSERT INTO browser_profile_leases(lease_id,program,account_alias,auth_domain,owner_agent_id,owner_run_id,purpose,profile_dir,status,created_at,heartbeat_at,expires_at,manager_id,instance_key) SELECT 'cross',program,account_alias,'other.test','cross-agent','cross-run',purpose,?,'active',created_at,heartbeat_at,expires_at,'other-manager','manual' FROM browser_profile_leases WHERE lease_id=?", (str(alias), row['lease_id']))
        return register(db_path, *args, **kwargs)
    monkeypatch.setattr(profiles, 'register_legacy_auto', competing_claim)
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True) == ''
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        assert not db.execute('SELECT 1 FROM browser_legacy_auto').fetchone()


@pytest.mark.parametrize('alias_kind', ['broken', 'inaccessible'])
def test_unobservable_manager_alias_blocks_selection(monkeypatch, tmp_path, alias_kind):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    alias = tmp_path / 'unknown-alias'
    alias.symlink_to(tmp_path / 'missing', target_is_directory=True)
    c.execute("INSERT INTO browsers SELECT 'cross', 'cross-browser', program, account, 'other.test', 'cross-agent', 'cross-run', purpose, 'cross-unit', ?, ?, 'running', tab_count, last_activity, created-1, updated FROM browsers WHERE lease_id=?",
              (str(alias), str(tmp_path / 'cross.json'), row['lease_id']))
    c.commit()
    if alias_kind == 'inaccessible':
        real_stat = profiles.os.stat
        def deny(path, *a, **kw):
            if os.fspath(path) == str(alias):
                raise PermissionError('fixture inaccessible')
            return real_stat(path, *a, **kw)
        monkeypatch.setattr(profiles.os, 'stat', deny)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True) == ''


def test_preselection_sweep_preserves_manager_legacy_with_malformed_canonical_history(monkeypatch, tmp_path, capsys):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    pre_domain = profiles.profile_dir('demo', 'legacy-global', 'anon').parent.parent / 'anon'
    pre_domain.mkdir(parents=True)
    (pre_domain / 'auth-sentinel').write_text('keep')
    c.execute("UPDATE browsers SET profile_dir=?,state='stopped',updated=0 WHERE lease_id=?",
              (str(pre_domain), row['lease_id']))
    c.commit()
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        db.execute("UPDATE browser_profile_leases SET profile_dir=?,status='released' WHERE lease_id=?",
                   ('/malformed/history', row['lease_id']))
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    removed, skipped = m.sweep_rows(c, 14, True)
    assert removed == [] and skipped[0]['reason'] == 'legacy-auth-retained'
    assert (pre_domain / 'auth-sentinel').read_text() == 'keep'
    assert c.execute('SELECT state FROM browsers WHERE lease_id=?', (row['lease_id'],)).fetchone()[0] == 'stopped'
    def selection(*_a, **_kw):
        assert (pre_domain / 'auth-sentinel').read_text() == 'keep'
        assert c.execute('SELECT state FROM browsers WHERE lease_id=?', (row['lease_id'],)).fetchone()[0] == 'stopped'
        m.emit({'status': 'fixture-selection-reached'}, 2)
    monkeypatch.setattr(m, 'automatic_instance', selection)
    with pytest.raises(SystemExit):
        m.start(args())
    assert json.loads(capsys.readouterr().out)['status'] == 'fixture-selection-reached'


@pytest.mark.parametrize('kind', ['keyed', 'arbitrary', 'task-owned'])
def test_preselection_sweep_does_not_blanket_retain_disposable_profiles(monkeypatch, tmp_path, kind):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    path = Path(row['profile_dir'])
    if kind == 'arbitrary':
        path = tmp_path / 'artifacts/demo/web/browser-profiles/unrelated'
        path.mkdir(parents=True)
    c.execute("UPDATE browsers SET profile_dir=?,program=?,state='stopped',updated=0 WHERE lease_id=?",
              (str(path), 'task-owned' if kind == 'task-owned' else 'demo', row['lease_id']))
    c.commit()
    if kind == 'keyed':
        Path(row['launch_file']).write_text(json.dumps({'instance_key': 'manual', 'instance_selection': 'explicit'}))
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        db.execute("UPDATE browser_profile_leases SET profile_dir=?,status='released' WHERE lease_id=?",
                   ('/malformed/history', row['lease_id']))
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    monkeypatch.setattr(m, 'stopped', lambda _: True)
    removed, skipped = m.sweep_rows(c, 14, True)
    assert len(removed) == 1 and not skipped
    assert not path.exists()

@pytest.mark.parametrize('observable', ['active-unit', 'active-root', 'active-cdp',
                                        'missing-receipt-active-unit'])
def test_running_migration_blocks_nonquiescent_stopped_history(monkeypatch, tmp_path, observable):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    receipt = tmp_path / 'older.json'
    c.execute("INSERT INTO browsers SELECT 'older', 'older-browser', program, account, auth_domain, 'former-agent', 'former-run', purpose, 'older-unit', profile_dir, ?, 'stopped', tab_count, last_activity, created-1, updated FROM browsers WHERE lease_id=?",
              (str(receipt), row['lease_id']))
    c.commit()
    if observable != 'missing-receipt-active-unit':
        info = {'instance_key': '', 'instance_selection': 'legacy'}
        if observable == 'active-root':
            info['process_identity'] = process_identity(os.getpid())
        if observable == 'active-cdp':
            info['cdp_url'] = 'http://127.0.0.1:9222'
            monkeypatch.setattr(profiles, 'local_cdp_version', lambda _: {'status': 'ready'})
        receipt.write_text(json.dumps(info))
    monkeypatch.setattr(m, 'unit_active', lambda unit: unit == 'older-unit' and
                        observable in ('active-unit', 'missing-receipt-active-unit'))
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    assert m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True) == ''
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as db:
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='browser_legacy_auto'").fetchone()
    assert take(owner, 'auto-peer', 'peer', manager)['status'] == 'locked'

def test_running_migration_allows_inactive_stopped_history_without_receipt(monkeypatch, tmp_path):
    m, c, row, owner, manager = fixture(monkeypatch, tmp_path)
    c.execute("INSERT INTO browsers SELECT 'older', 'older-browser', program, account, auth_domain, 'former-agent', 'former-run', purpose, 'older-unit', profile_dir, ?, 'stopped', tab_count, last_activity, created-1, updated FROM browsers WHERE lease_id=?",
              (str(tmp_path / 'missing-older.json'), row['lease_id']))
    c.commit()
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    monkeypatch.setattr(m, 'healthy', lambda _: True)
    key = m.automatic_instance(c, args(), 'anon', 'legacy-global', allow_migration=True)
    assert key.startswith('auto-')
    assert take(owner, key, 'peer', manager)['status'] == 'leased'

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
    Path(peer['lease']['profile_dir']).mkdir(parents=True)
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
