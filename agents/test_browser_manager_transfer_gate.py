"""Fail-closed manager transfer gate; synthetic node state only."""
import importlib.util
import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts'
spec = importlib.util.spec_from_file_location('browser_provisioner_transfer_gate', ROOT / 'browser_provisioner.py')
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)
import browser_profile_lease as lease
from browser_lifecycle import node_lock, process_identity


def candidates(tmp_path, monkeypatch):
    state = tmp_path / 'browser_provisioner.sqlite'
    monkeypatch.setattr(manager, 'STATE', state)
    canonical = tmp_path / 'browser_profile_leases.sqlite'
    with lease.connect(canonical) as db:
        lease.init_db(db)
        for lid in ('source', 'destination'):
            profile = tmp_path / lid
            profile.mkdir()
            db.execute('''INSERT INTO browser_profile_leases
                (lease_id, program, account_alias, auth_domain, owner_agent_id, owner_run_id,
                 purpose, profile_dir, status, browser_status, manager_id, service_unit,
                 created_at, heartbeat_at, expires_at)
                VALUES (?, 'program', 'account', 'domain', ?, 'run', 'test', ?, 'active',
                        'running', ?, ?, 1, 1, ?)''',
                (lid, lid, str(profile), manager.manager_id(), 'unit-'+lid, time.time()+300))
            db.execute("UPDATE browser_profile_leases SET cdp_url='http://127.0.0.1:9222' WHERE lease_id=?", (lid,))
    with manager.db() as db:
        for lid in ('source', 'destination'):
            profile = tmp_path / lid
            launch = tmp_path / (lid + '.launch.json')
            launch.write_text(json.dumps({'process_identity': process_identity(__import__('os').getpid()),
                                          'unit_invocation': 'inv-'+lid, 'cdp_url': 'http://127.0.0.1:9222',
                                          'control_mode': 'pipe-fenced'}))
            db.execute('''INSERT INTO browsers
                (lease_id,browser_id,program,account,auth_domain,agent_id,run_id,purpose,unit,
                 profile_dir,launch_file,state,tab_count,last_activity,created,updated)
                VALUES (?, ?, 'program','account','domain',?,'run','test',?,?,?,'running',0,1,1,1)''',
                (lid, lid, lid, 'unit-'+lid, str(profile), str(launch)))
    monkeypatch.setattr(manager, 'unit_active', lambda unit: True)
    monkeypatch.setattr(manager, 'unit_identity', lambda unit: 'inv-'+unit.removeprefix('unit-'))
    monkeypatch.setattr(lease, 'local_cdp_version', lambda url: {'status': 'ready'})
    return canonical


def test_caller_cannot_self_attest_and_receipt_is_safe(tmp_path, monkeypatch):
    canonical = candidates(tmp_path, monkeypatch)
    result = manager.manager_transfer_attestation_gate('source', 'destination')
    assert result == {'status': 'auth-clone-unavailable', 'reason': 'attestation-hook-unavailable'}
    with lease.connect(canonical) as db:
        assert db.execute('SELECT COUNT(*) FROM browser_transfer_identity').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM browser_transfer_grants').fetchone()[0] == 0
    assert 'identity' not in json.dumps(result) and '9222' not in json.dumps(result)
    import subprocess, sys
    help_text = subprocess.run([sys.executable, str(ROOT / 'browser_provisioner.py'), '--help'],
                               capture_output=True, text=True, check=True).stdout
    assert 'attestation' not in help_text


def test_old_rows_and_mismatched_owner_fail_closed(tmp_path, monkeypatch):
    canonical = candidates(tmp_path, monkeypatch)
    with lease.connect(canonical) as db:
        db.execute("UPDATE browser_profile_leases SET owner_agent_id='other' WHERE lease_id='source'")
    assert manager.manager_transfer_attestation_gate('source', 'destination') == {
        'status': 'auth-clone-unavailable', 'reason': 'manager-identity-unverified'}
    with lease.connect(canonical) as db:
        db.execute("UPDATE browser_profile_leases SET owner_agent_id='source', manager_id='legacy' WHERE lease_id='source'")
    assert manager.manager_transfer_attestation_gate('source', 'destination')['reason'] == 'manager-identity-unverified'


def test_handoff_release_and_rotation_never_attest(tmp_path, monkeypatch):
    canonical = candidates(tmp_path, monkeypatch)
    for mutation in ('handoff', 'release', 'rotate'):
        if mutation == 'handoff':
            with lease.connect(canonical) as db:
                db.execute("UPDATE browser_profile_leases SET owner_run_id='new-run' WHERE lease_id='source'")
        elif mutation == 'release':
            with lease.connect(canonical) as db:
                db.execute("UPDATE browser_profile_leases SET status='released' WHERE lease_id='source'")
        else:
            with manager.db() as db:
                row = db.execute("SELECT * FROM browsers WHERE lease_id='source'").fetchone()
                info = manager.record_info(row)
                info['unit_invocation'] = 'rotated'
                Path(row['launch_file']).write_text(json.dumps(info))
        assert manager.manager_transfer_attestation_gate('source', 'destination')['reason'] == 'manager-identity-unverified'


@pytest.mark.parametrize('mutation', ['missing-manager-row', 'replaced-profile', 'replaced-process', 'changed-cdp'])
def test_manager_candidate_requires_live_exact_identity(tmp_path, monkeypatch, mutation):
    canonical = candidates(tmp_path, monkeypatch)
    with manager.db() as db:
        row = db.execute("SELECT * FROM browsers WHERE lease_id='source'").fetchone()
        if mutation == 'missing-manager-row':
            db.execute("DELETE FROM browsers WHERE lease_id='source'")
        elif mutation == 'replaced-profile':
            Path(row['profile_dir']).rename(tmp_path / 'original')
            Path(row['profile_dir']).mkdir()
            db.execute("UPDATE browsers SET profile_dir=? WHERE lease_id='source'", (str(tmp_path / 'original'),))
        elif mutation == 'replaced-process':
            info = manager.record_info(row)
            info['process_identity']['start'] = 'stale-start'
            Path(row['launch_file']).write_text(json.dumps(info))
        else:
            with lease.connect(canonical) as leases:
                leases.execute("UPDATE browser_profile_leases SET cdp_url='http://127.0.0.1:9223' WHERE lease_id='source'")
    assert manager.manager_transfer_attestation_gate('source', 'destination')['reason'] == 'manager-identity-unverified'


def test_manager_gate_serializes_with_node_ownership_change(tmp_path, monkeypatch):
    candidates(tmp_path, monkeypatch)
    entered = threading.Event()
    done = threading.Event()
    def gate():
        entered.set()
        manager.manager_transfer_attestation_gate('source', 'destination')
        done.set()
    with node_lock(manager.STATE):
        worker = threading.Thread(target=gate)
        worker.start()
        assert entered.wait(2)
        assert not done.wait(.1)
        with manager.db() as db:
            db.execute("UPDATE browsers SET agent_id='new-owner' WHERE lease_id='source'")
    worker.join(3)
    assert done.is_set()
    assert manager.manager_transfer_attestation_gate('source', 'destination')['reason'] == 'manager-identity-unverified'

@pytest.mark.parametrize('mutation', ['handoff', 'rotation', 'cross-program'])
def test_fixture_transfer_rejects_changed_source_or_scope_before_browser_io(tmp_path, monkeypatch, mutation):
    canonical = candidates(tmp_path, monkeypatch)
    if mutation == 'handoff':
        with lease.connect(canonical) as db:
            db.execute("UPDATE browser_profile_leases SET owner_run_id='next-owner' WHERE lease_id='source'")
    elif mutation == 'rotation':
        with manager.db() as db:
            row = db.execute("SELECT * FROM browsers WHERE lease_id='source'").fetchone()
            info = manager.record_info(row)
            info['unit_invocation'] = 'rotated'
            Path(row['launch_file']).write_text(json.dumps(info))
    else:
        with manager.db() as db:
            db.execute("UPDATE browsers SET program='other-program' WHERE lease_id='destination'")
        with lease.connect(canonical) as db:
            db.execute("UPDATE browser_profile_leases SET program='other-program' WHERE lease_id='destination'")
    assert manager.manager_fixture_auth_transfer('source', 'destination', origin='http://127.0.0.1:31337') == {
        'status': 'auth-clone-unavailable', 'reason': 'manager-identity-unverified'}

def test_fixture_transfer_has_no_generic_origin_or_production_contract(tmp_path, monkeypatch):
    candidates(tmp_path, monkeypatch)
    for origin in ('https://example.com', 'http://localhost:31337',
                   'http://127.0.0.1:31337/other'):
        assert manager.manager_fixture_auth_transfer('source', 'destination', origin=origin)['reason'] == 'site-contract-unavailable'
    assert manager.manager_fixture_auth_transfer('source', 'destination', origin='http://127.0.0.1:31337')['reason'] == 'site-contract-unavailable'


@pytest.mark.parametrize('program,domain,account', [
    ('other', 'fixture.invalid', 'anon'),
    ('fixture', 'other.invalid', 'anon'),
    ('fixture', 'fixture.invalid', 'other'),
])
def test_fixture_transfer_requires_all_three_exact_scope_keys(tmp_path, monkeypatch,
                                                              program, domain, account):
    canonical = candidates(tmp_path, monkeypatch)
    with manager.db() as db:
        db.execute('UPDATE browsers SET program=?, auth_domain=?, account=?',
                   (program, domain, account))
    with lease.connect(canonical) as db:
        db.execute('UPDATE browser_profile_leases SET program=?, auth_domain=?, account_alias=?',
                   (program, domain, account))
    assert manager.manager_fixture_auth_transfer(
        'source', 'destination', origin='http://127.0.0.1:31337') == {
            'status': 'auth-clone-unavailable', 'reason': 'site-contract-unavailable'}
