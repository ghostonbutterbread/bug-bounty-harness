"""Cross-store stop ownership and interrupted release (temporary registries only)."""
import json
import argparse
import subprocess
from pathlib import Path
import sqlite3
import threading

import pytest

from agents.test_browser_lease_recovery import provisioner, record, canonical_record, profiles


def setup(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    c, row = record(m, tmp_path, None)
    canonical_record(m, row)
    identity = {'pid': 98765, 'node': 'fixture', 'start': 'exact'}
    Path(row['launch_file']).write_text(json.dumps({
        'unit_invocation': 'exact-unit', 'process_identity': identity,
        'cdp_url': 'http://127.0.0.1:9301'}))
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        leases.execute("UPDATE browser_profile_leases SET browser_status='running',cdp_url=? WHERE lease_id=?",
                       ('http://127.0.0.1:9301', row['lease_id']))
    monkeypatch.setattr(m, 'unit_identity', lambda _: 'exact-unit')
    monkeypatch.setattr(m, 'owner_state', lambda _: 'active')
    m.__dict__['_real_stopped'] = m.stopped
    monkeypatch.setattr(m, 'stopped', lambda _: True)
    return m, c, row


def status(m):
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        return leases.execute('SELECT status FROM browser_profile_leases WHERE lease_id=?', ('old',)).fetchone()[0]


@pytest.mark.parametrize('field,value', [
    ('owner_run_id', 'other-run'), ('manager_id', 'other-manager'),
    ('service_unit', 'other-unit'), ('cdp_url', 'http://127.0.0.1:9999'),
    ('profile_dir', '/different'), ('browser_status', 'unreachable')])
def test_mismatch_never_stops(monkeypatch, tmp_path, field, value):
    m, c, row = setup(monkeypatch, tmp_path)
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        leases.execute(f'UPDATE browser_profile_leases SET {field}=? WHERE lease_id=?', (value, 'old'))
    monkeypatch.setattr(m, 'stop_recorded', lambda _: pytest.fail('must not stop'))
    assert not m.fenced_stop_release(c, 'old', 'old-agent')
    assert status(m) == 'active'


def test_lock_spans_stop_and_release_and_retry_recovers(monkeypatch, tmp_path):
    m, c, row = setup(monkeypatch, tmp_path)
    # Verify a competing canonical writer cannot acquire a write lock while
    # the stop proof is being obtained; it must remain fenced until release.
    def stop(_):
        observed = []
        def competing():
            with sqlite3.connect(m.STATE.parent / 'browser_profile_leases.sqlite', timeout=.01) as other:
                try:
                    other.execute('BEGIN IMMEDIATE')
                except sqlite3.OperationalError:
                    observed.append('locked')
        thread = threading.Thread(target=competing)
        thread.start(); thread.join()
        assert observed == ['locked']
        return True
    monkeypatch.setattr(m, 'stopped', lambda _: False)
    monkeypatch.setattr(m, 'stop_recorded', stop)
    assert m.fenced_stop_release(c, 'old', 'old-agent', disposition='completed')
    assert status(m) == 'released'
    assert c.execute('SELECT state FROM browsers WHERE lease_id=?', ('old',)).fetchone()[0] == 'stopped'


def test_reservation_inserted_before_lock_refuses_stop(monkeypatch, tmp_path):
    m, c, row = setup(monkeypatch, tmp_path)
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        profiles.init_db(leases)
        leases.execute('INSERT INTO browser_stopped_reservations '
            '(program,auth_domain,account_alias,source_lease,manager_id,owner_agent_id,'
            'owner_run_id,control_generation,service_unit,root,cdp_url,profile_dir,'
            'profile_device,profile_inode,phase,unit_invocation) VALUES '
            '(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            ('demo', 'legacy-global', 'anon', 'old', m.manager_id(), 'old-agent',
             'old-run', 'gen', row['unit'], '{}', 'http://127.0.0.1:9301',
             row['profile_dir'], 1, 2, 'reserved', 'exact-unit'))
    monkeypatch.setattr(m, 'stop_recorded', lambda _: pytest.fail('reservation protects stop'))
    assert not m.fenced_stop_release(c, 'old', 'old-agent')
    assert status(m) == 'active'


def test_released_canonical_recovers_manager_without_new_stop(monkeypatch, tmp_path):
    m, c, row = setup(monkeypatch, tmp_path)
    m.stop_receipt(row)
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        canonical = leases.execute('SELECT * FROM browser_profile_leases WHERE lease_id=?', ('old',)).fetchone()
        profiles.release_owned_in_transaction(leases, canonical, disposition='cancelled', profile_health='healthy')
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    monkeypatch.setattr(m, 'unit_identity', lambda _: None)
    monkeypatch.setattr(m, 'stop_recorded', lambda _: pytest.fail('no second stop'))
    assert m.fenced_stop_release(c, 'old', 'old-agent')
    assert c.execute('SELECT state FROM browsers WHERE lease_id=?', ('old',)).fetchone()[0] == 'stopped'


def test_interrupted_manager_commit_retry(monkeypatch, tmp_path):
    m, c, row = setup(monkeypatch, tmp_path)
    real_receipt = m.stop_receipt
    def interrupted(r):
        real_receipt(r)
        raise RuntimeError('interrupted after receipt')
    monkeypatch.setattr(m, 'stop_receipt', interrupted)
    with pytest.raises(RuntimeError):
        m.fenced_stop_release(c, 'old', 'old-agent')
    assert status(m) == 'active'
    monkeypatch.setattr(m, 'stop_receipt', real_receipt)
    monkeypatch.setattr(m, 'stop_recorded', lambda _: pytest.fail('already stopped'))
    assert m.fenced_stop_release(c, 'old', 'old-agent')
    assert status(m) == 'released'


def test_failed_unit_status_query_is_not_terminal(monkeypatch, tmp_path):
    m = provisioner(monkeypatch, tmp_path)
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    monkeypatch.setattr(m, 'owner_state', lambda _: 'terminal')
    monkeypatch.setattr(m, 'record_info', lambda _: {'process_identity': {'pid': 123}})
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: subprocess.CompletedProcess(a, 1, '', 'bus unavailable'))
    assert not m.stopped({'unit': 'fixture-unit', 'state': 'running'})


def test_direct_managed_release_denied_but_unstarted_cleanup_allowed(monkeypatch, tmp_path):
    m, c, row = setup(monkeypatch, tmp_path)
    request = argparse.Namespace(state_dir=str(m.STATE.parent), lease_id='old',
        agent_id='old-agent', manager_id=m.manager_id(), disposition='cancelled', profile_health='healthy')
    assert profiles.cmd_release(request)['status'] == 'managed-by-provisioner'
    assert status(m) == 'active'
    with profiles.connect(m.STATE.parent / 'browser_profile_leases.sqlite') as leases:
        leases.execute("UPDATE browser_profile_leases SET browser_status='not-started',cdp_url=NULL,service_unit=NULL WHERE lease_id='old'")
    assert profiles.cmd_release(request)['status'] == 'released'


@pytest.mark.parametrize('missing_invocation', [None, ''])
def test_interrupted_before_receipt_recovers_unloaded_unit(monkeypatch, tmp_path, missing_invocation):
    m, c, row = setup(monkeypatch, tmp_path)
    real_receipt = m.stop_receipt
    monkeypatch.setattr(m, 'stopped', lambda _: False)
    monkeypatch.setattr(m, 'stop_recorded', lambda _: True)
    monkeypatch.setattr(m, 'stop_receipt', lambda _: (_ for _ in ()).throw(RuntimeError('interrupted')))
    with pytest.raises(RuntimeError):
        m.fenced_stop_release(c, 'old', 'old-agent')
    assert status(m) == 'active'
    monkeypatch.setattr(m, 'unit_identity', lambda _: missing_invocation)
    monkeypatch.setattr(m, 'unit_inactive', lambda _: True)
    monkeypatch.setattr(m, 'owner_state', lambda _: 'terminal')
    monkeypatch.setattr(profiles, 'local_cdp_version', lambda _: {'status': 'unreachable'})
    monkeypatch.setattr(m, 'stopped', m.__dict__['_real_stopped'])
    monkeypatch.setattr(m, 'stop_recorded', lambda _: pytest.fail('already stopped'))
    monkeypatch.setattr(m, 'stop_receipt', real_receipt)
    assert m.fenced_stop_release(c, 'old', 'old-agent')
    assert status(m) == 'released'


@pytest.mark.parametrize('unit_terminal,root_state,cdp_status,invocation', [
    (False, 'terminal', 'unreachable', None),
    (False, 'terminal', 'unreachable', ''),
    (True, 'active', 'unreachable', None),
    (True, 'terminal', 'ready', None),
    (True, 'terminal', 'unreachable', 'other-unit'),
])
def test_unloaded_recovery_requires_independent_proof(monkeypatch, tmp_path,
        unit_terminal, root_state, cdp_status, invocation):
    m, c, row = setup(monkeypatch, tmp_path)
    monkeypatch.setattr(m, 'unit_identity', lambda _: invocation)
    monkeypatch.setattr(m, 'unit_inactive', lambda _: unit_terminal)
    monkeypatch.setattr(m, 'owner_state', lambda _: root_state)
    monkeypatch.setattr(profiles, 'local_cdp_version', lambda _: {'status': cdp_status})
    monkeypatch.setattr(m, 'stopped', m.__dict__['_real_stopped'])
    monkeypatch.setattr(m, 'stop_recorded', lambda _: pytest.fail('unproved stop'))
    assert not m.fenced_stop_release(c, 'old', 'old-agent')
    assert status(m) == 'active'
