"""Cross-store stop ownership and interrupted release (temporary registries only)."""
import json
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
