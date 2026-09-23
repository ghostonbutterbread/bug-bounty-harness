"""Offline fixture coverage for old appended physical order and fail-closed apply."""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'chromium-test' / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import browser_manager_row_repair as repair


def fixture(tmp_path, count=243):
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
        bid = f'bid-{n}'
        lid = f'lid-{n}'
        program = 'blue' if n < 22 else 'other'
        profile = str(tmp_path / ('profile-' + bid))
        launch = tmp_path / (bid + '.launch.json')
        launch.write_text(json.dumps({'instance_id': bid, 'profile_dir': profile, 'agent_id': 'agent',
                                      'run_id': 'run', 'program': program, 'task': 'purpose',
                                      'account_label': 'acct', 'process_identity': {'pid': 100, 'node': 'test'},
                                      'cdp_url': 'http://127.0.0.1:55555'}))
        manager_conn.execute('INSERT INTO browsers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                             (lid, bid, program, 'acct', 'domain', 'agent', 'run', 'purpose',
                              'browser-' + bid, profile, str(launch), 'running', 0, 1., 1., 1.))
        lease_conn.execute('INSERT INTO browser_profile_leases VALUES (?,?,?,?,?,?,?,?,?,?)',
                           (lid, program, 'acct', 'domain', 'agent', 'run', 'purpose', profile, 'released', 'browser-' + bid))
    manager_conn.commit(); manager_conn.close()
    lease_conn.commit(); lease_conn.close()
    backup = tmp_path / 'backup'
    backup.mkdir(mode=0o700)
    return state, backup


def quiet(row, receipt, lease, metadata):
    if lease['status'] == 'active':
        raise repair.Refused('active-lease')


def test_243_old_rows_blue_only_apply_idempotent(tmp_path):
    state, backup = fixture(tmp_path)
    plan = repair.run(state, 'blue')
    assert plan['candidate_count'] == 22 and plan['blocked_count'] == 0
    result = repair.run(state, 'blue', apply=True, plan_hash=plan['plan_hash'],
                        confirmed=True, backup_dir=backup, probe=quiet)
    assert result['applied_count'] == 22
    with sqlite3.connect(state) as c:
        assert c.execute("select count(*) from browsers where program='blue' and state='running' and auth_domain='domain'").fetchone()[0] == 22
        assert c.execute("select count(*) from browsers where program='other' and tab_count='running'").fetchone()[0] == 221
    assert len(list(backup.iterdir())) == 2
    assert repair.run(state, 'blue')['candidate_count'] == 0
    another = tmp_path / 'another'; another.mkdir(mode=0o700)
    with pytest.raises(repair.Refused, match='plan-changed'):
        repair.run(state, 'blue', apply=True, plan_hash=plan['plan_hash'], confirmed=True,
                   backup_dir=another, probe=quiet)


def test_active_conflict_missing_receipt_and_no_mutation(tmp_path):
    state, backup = fixture(tmp_path, 4)
    with sqlite3.connect(tmp_path / 'browser_profile_leases.sqlite') as c:
        c.execute("update browser_profile_leases set status='active' where lease_id='lid-0'")
        c.execute("update browser_profile_leases set auth_domain='wrong' where lease_id='lid-1'")
    (tmp_path / 'bid-2.launch.json').unlink()
    p = tmp_path / 'bid-3.launch.json'
    data = json.loads(p.read_text()); data['run_id'] = 'wrong'; p.write_text(json.dumps(data))
    plan = repair.run(state, 'blue')
    assert plan['candidate_count'] == 0 and plan['blocked_count'] == 4
    with pytest.raises(repair.Refused, match='plan-changed'):
        repair.run(state, 'blue', apply=True, plan_hash=plan['plan_hash'], confirmed=True,
                   backup_dir=backup, probe=quiet)
    with sqlite3.connect(state) as c:
        assert c.execute("select count(*) from browsers where tab_count='running'").fetchone()[0] == 4


def test_rollback_and_plan_race(tmp_path):
    state, backup = fixture(tmp_path, 2)
    plan = repair.run(state, 'blue')
    def fault(conn, raw):
        if raw['lease_id'] == 'lid-1':
            raise RuntimeError('injected failure')
    with pytest.raises(RuntimeError, match='injected'):
        repair.run(state, 'blue', apply=True, plan_hash=plan['plan_hash'], confirmed=True,
                   backup_dir=backup, probe=quiet, before_update=fault)
    with sqlite3.connect(state) as c:
        assert c.execute("select count(*) from browsers where tab_count='running'").fetchone()[0] == 2
    with sqlite3.connect(tmp_path / 'browser_profile_leases.sqlite') as c:
        c.execute("update browser_profile_leases set status='active' where lease_id='lid-1'")
    other = tmp_path / 'other'; other.mkdir(mode=0o700)
    with pytest.raises(repair.Refused, match='plan-changed'):
        repair.run(state, 'blue', apply=True, plan_hash=plan['plan_hash'], confirmed=True,
                   backup_dir=other, probe=quiet)


def test_manager_row_race_rolls_back(tmp_path):
    state, backup = fixture(tmp_path, 2)
    plan = repair.run(state, 'blue')
    def race(conn, raw):
        if raw['lease_id'] == 'lid-1':
            conn.execute('UPDATE browsers SET updated=? WHERE lease_id=?', (123., raw['lease_id']))
    with pytest.raises(repair.Refused, match='manager-row-race'):
        repair.run(state, 'blue', apply=True, plan_hash=plan['plan_hash'], confirmed=True,
                   backup_dir=backup, probe=quiet, before_update=race)
    with sqlite3.connect(state) as c:
        assert c.execute("select count(*) from browsers where tab_count='running'").fetchone()[0] == 2


def test_runtime_probe_requires_task_owner_evidence(tmp_path, monkeypatch):
    state, _ = fixture(tmp_path, 1)
    import subprocess
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: subprocess.CompletedProcess(a, 3, 'inactive\n', ''))
    with repair.open_db(state) as c:
        c.execute('ATTACH DATABASE ? AS lease', (str(tmp_path / 'browser_profile_leases.sqlite'),))
        candidates, blocked = repair.inspect(c, 'blue', probe=repair.runtime_quiescent)
    assert not candidates and list(blocked.values()) == ['task-owner-active-or-unknown']


def test_runtime_probe_blocks_active_unit(tmp_path, monkeypatch):
    state, _ = fixture(tmp_path, 1)
    import subprocess
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: subprocess.CompletedProcess(a, 0, 'active\n', ''))
    with repair.open_db(state) as c:
        c.execute('ATTACH DATABASE ? AS lease', (str(tmp_path / 'browser_profile_leases.sqlite'),))
        candidates, blocked = repair.inspect(c, 'blue', probe=repair.runtime_quiescent)
    assert not candidates and list(blocked.values()) == ['unit-active-or-unknown']
