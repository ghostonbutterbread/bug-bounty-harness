"""Offline historical positional-order repair and fail-closed apply tests."""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'chromium-test' / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import browser_manager_row_repair as repair


def fixture(tmp_path, count=5):
    state = tmp_path / 'browser_provisioner.sqlite'
    lease_path = tmp_path / 'browser_profile_leases.sqlite'
    with sqlite3.connect(state) as c:
        c.execute('CREATE TABLE browsers (lease_id TEXT PRIMARY KEY,browser_id TEXT UNIQUE NOT NULL,program TEXT NOT NULL,account TEXT NOT NULL,agent_id TEXT NOT NULL,run_id TEXT NOT NULL,purpose TEXT NOT NULL,unit TEXT NOT NULL,profile_dir TEXT NOT NULL,launch_file TEXT NOT NULL,state TEXT NOT NULL,tab_count INTEGER NOT NULL DEFAULT 0,last_activity REAL NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,auth_domain TEXT NOT NULL DEFAULT "legacy-global")')
        c.execute('CREATE TABLE lifecycle (lease_id TEXT PRIMARY KEY, metadata TEXT NOT NULL)')
    with sqlite3.connect(lease_path) as c:
        c.execute('CREATE TABLE browser_profile_leases (lease_id TEXT PRIMARY KEY,program TEXT,account_alias TEXT,auth_domain TEXT,owner_agent_id TEXT,owner_run_id TEXT,purpose TEXT,profile_dir TEXT,status TEXT,service_unit TEXT)')
    manager_conn = sqlite3.connect(state)
    lease_conn = sqlite3.connect(lease_path)
    for n in range(count):
        bid, lid = f'bid-{n}', f'lid-{n}'
        program = 'neon' if n != 4 else 'other'
        account = 'blue' if n < 3 or n == 4 else 'green'
        profile = tmp_path / ('profile-' + bid)
        profile.mkdir()
        launch = tmp_path / (bid + '.launch.json')
        launch.write_text(json.dumps({'instance_id': bid, 'profile_dir': str(profile), 'agent_id': 'agent',
                                      'run_id': 'run', 'program': program, 'task': 'purpose',
                                      'account_label': account, 'cdp_url': 'http://127.0.0.1:55555'}))
        manager_conn.execute('INSERT INTO browsers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                             (lid, bid, program, account, 'domain', 'agent', 'run', 'purpose',
                              'browser-' + bid, str(profile), str(launch), 'running', 0, 1., 1., 1.))
        lease_conn.execute('INSERT INTO browser_profile_leases VALUES (?,?,?,?,?,?,?,?,?,?)',
                           (lid, program, account, 'domain', 'agent', 'run', 'purpose', str(profile), 'released', 'browser-' + bid))
    manager_conn.commit(); manager_conn.close()
    lease_conn.commit(); lease_conn.close()
    backup = tmp_path / 'backup'
    backup.mkdir(mode=0o700)
    return state, backup


def quiet(row, receipt, lease, metadata):
    repair.runtime_quiescent(row, receipt, lease, metadata)


@pytest.fixture
def runtime(monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: subprocess.CompletedProcess(a, 3, 'inactive\n', ''))
    monkeypatch.setattr(repair, 'no_profile_process', lambda *a: None)
    import socket
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **kw: (_ for _ in ()).throw(ConnectionRefusedError()))


def apply(state, backup, plan, **kw):
    return repair.run(state, 'neon', 'blue', apply=True, plan_hash=plan['plan_hash'],
                      confirmed=True, backup_dir=backup, **kw)


def test_exact_selector_and_partial_quarantine(tmp_path, runtime):
    state, backup = fixture(tmp_path)
    leases = tmp_path / 'browser_profile_leases.sqlite'
    with sqlite3.connect(leases) as c:
        c.execute("UPDATE browser_profile_leases SET status='active' WHERE lease_id='lid-1'")
        c.execute("UPDATE browser_profile_leases SET status='expired' WHERE lease_id='lid-2'")
    (tmp_path / 'bid-0.launch.json').unlink()  # no receipt; independent evidence
    plan = repair.run(state, 'neon', 'blue')
    assert plan['candidate_count'] == 1 and plan['blocked_count'] == 2
    assert list(plan['evidence'].values()) == ['missing']
    assert repair.run(state, 'neon', 'green')['candidate_count'] == 1
    assert repair.run(state, 'other', 'blue')['candidate_count'] == 1
    result = apply(state, backup, plan)
    assert result['applied_count'] == 1 and result['blocked_count'] == 2
    with sqlite3.connect(state) as c:
        assert c.execute("SELECT count(*) FROM browsers WHERE program='neon' AND account='blue' AND state='running'").fetchone()[0] == 1
        assert c.execute("SELECT count(*) FROM browsers WHERE tab_count='running'").fetchone()[0] == 4
    assert len(list(backup.iterdir())) == 2
    for p, a in [('blue', 'blue'), ('neon', 'green'), ('other', 'blue')]:
        with pytest.raises(repair.Refused, match='neon-blue'):
            repair.run(state, p, a, apply=True, plan_hash=plan['plan_hash'], confirmed=True, backup_dir=backup)
    with pytest.raises(repair.Refused, match='plan-changed'):
        apply(state, backup, plan)


def test_sparse_receipt_conflict_and_owner_ambiguity(tmp_path, runtime, monkeypatch):
    state, backup = fixture(tmp_path)
    receipt = tmp_path / 'bid-0.launch.json'
    receipt.write_text(json.dumps({'agent_id': 'other'}))
    sparse = tmp_path / 'bid-1.launch.json'
    sparse.write_text(json.dumps({'program': 'neon'}))
    (tmp_path / 'bid-2.launch.json').unlink()
    plan = repair.run(state, 'neon', 'blue')
    assert plan['candidate_count'] == 2 and list(plan['blocked'].values()) == ['receipt-conflict']
    assert list(plan['evidence'].values()) == ['sparse', 'missing']
    with sqlite3.connect(tmp_path / 'browser_profile_leases.sqlite') as c:
        c.execute("UPDATE browser_profile_leases SET status='active' WHERE lease_id='lid-1'")
    with pytest.raises(repair.Refused, match='plan-changed'):
        apply(state, backup, plan)
    assert repair.run(state, 'neon', 'blue')['candidate_count'] == 1


def test_runtime_rejects_process_lock_and_unknown_cdp(tmp_path, runtime, monkeypatch):
    state, backup = fixture(tmp_path)
    plan = repair.run(state, 'neon', 'blue')
    monkeypatch.setattr(repair, 'no_profile_process', lambda *a: (_ for _ in ()).throw(repair.Refused('profile-process-present')))
    with pytest.raises(repair.Refused, match='plan-changed'):
        apply(state, backup, plan)
    monkeypatch.setattr(repair, 'no_profile_process', lambda *a: None)
    (tmp_path / 'profile-bid-0' / 'SingletonLock').touch()
    with pytest.raises(repair.Refused, match='plan-changed'):
        apply(state, backup, plan)
    (tmp_path / 'profile-bid-0' / 'SingletonLock').unlink()
    import socket
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **kw: (_ for _ in ()).throw(TimeoutError()))
    with pytest.raises(repair.Refused, match='plan-changed'):
        apply(state, backup, plan)


def test_second_snapshot_failure_cleanup_and_retry(tmp_path, runtime, monkeypatch):
    state, backup = fixture(tmp_path, 1)
    plan = repair.run(state, 'neon', 'blue')
    original = repair.snapshot
    calls = []
    def fail_second(source, destination):
        calls.append(destination)
        if len(calls) == 2:
            raise OSError('injected second snapshot failure')
        return original(source, destination)
    monkeypatch.setattr(repair, 'snapshot', fail_second)
    with pytest.raises(OSError, match='second snapshot'):
        apply(state, backup, plan)
    assert not list(backup.iterdir())
    monkeypatch.setattr(repair, 'snapshot', original)
    assert apply(state, backup, plan)['applied_count'] == 1


def test_rollback_retry_and_row_race(tmp_path, runtime):
    state, backup = fixture(tmp_path, 2)
    plan = repair.run(state, 'neon', 'blue')
    def fault(conn, raw):
        if raw['lease_id'] == 'lid-1':
            raise RuntimeError('injected')
    with pytest.raises(RuntimeError, match='injected'):
        apply(state, backup, plan, before_update=fault)
    with sqlite3.connect(state) as c:
        assert c.execute("SELECT count(*) FROM browsers WHERE tab_count='running'").fetchone()[0] == 2
    assert apply(state, backup, plan)['applied_count'] == 2


def test_process_scan_detects_exact_profile(tmp_path):
    import subprocess
    profile = str(tmp_path / 'profile')
    proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)',
                             '--user-data-dir=' + profile])
    try:
        with pytest.raises(repair.Refused, match='profile-process-present'):
            repair.no_profile_process(profile, {})
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_other_profile_owner_quarantined(tmp_path):
    state, _ = fixture(tmp_path, 1)
    with sqlite3.connect(tmp_path / 'browser_profile_leases.sqlite') as c:
        c.execute('INSERT INTO browser_profile_leases VALUES (?,?,?,?,?,?,?,?,?,?)',
                  ('other-lease', 'neon', 'blue', 'domain', 'other', 'other', 'other',
                   str(tmp_path / 'profile-bid-0'), 'active', 'other-unit'))
    plan = repair.run(state, 'neon', 'blue')
    assert plan['candidate_count'] == 0
    assert list(plan['blocked'].values()) == ['profile-other-owner']


def test_active_unit_blocks(tmp_path, monkeypatch):
    state, _ = fixture(tmp_path, 1)
    import subprocess
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: subprocess.CompletedProcess(a, 0, 'active\n', ''))
    with repair.open_db(state) as c:
        c.execute('ATTACH DATABASE ? AS lease', (str(tmp_path / 'browser_profile_leases.sqlite'),))
        candidates, blocked, evidence = repair.inspect(c, 'neon', 'blue', probe=repair.runtime_quiescent)
    assert not candidates and list(blocked.values()) == ['unit-active-or-unknown']
