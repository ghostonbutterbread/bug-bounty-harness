"""Provisioner integration with synthetic state and no browser processes."""
import json
from pathlib import Path

import pytest

from agents.test_browser_provisioner import load, start_args
from agents.test_browser_lease_recovery import provisioner, record, args as recovery_args
import browser_profile_lease as profiles


def test_start_selects_local_fallback_via_real_lease_subprocess(monkeypatch, tmp_path):
    m = load(monkeypatch, tmp_path)
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('HARNESS_SHARED_BASE', str(tmp_path / 'Shared'))
    monkeypatch.setenv('HARNESS_BOUNTY_ARTIFACT_ROOT', str(tmp_path / 'Shared'))
    request = start_args()
    request.account = 'anon'
    request.url = 'about:blank'
    monkeypatch.setattr(m, 'sweep_rows', lambda *a: ([], []))
    monkeypatch.setattr(m, 'admission', lambda *_: {'status': 'admitted'})
    monkeypatch.setattr(m, 'select_display', lambda *_: None)
    real_lease = m.lease
    result = {}
    class StopBeforeLaunch(Exception):
        pass
    def intercept(args, *parts):
        result.update(real_lease(args, *parts))
        raise StopBeforeLaunch
    monkeypatch.setattr(m, 'lease', intercept)
    with pytest.raises(StopBeforeLaunch):
        m.start(request)
    assert result['status'] == 'leased'
    assert Path(result['lease']['profile_dir']).is_relative_to(tmp_path / '.local/bounty/browser-runtime/demo')
    assert not (tmp_path / 'Shared').exists()


def test_start_refuses_running_profile_on_unsafe_backing(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    c, row = record(m, tmp_path, None)
    request = recovery_args()
    request.agent_id, request.run_id = row['agent_id'], row['run_id']
    monkeypatch.setattr(m, 'sweep_rows', lambda *a: ([], []))
    monkeypatch.setattr(m, 'cleanup_unused', lambda *a: [])
    monkeypatch.setattr(m, 'admission', lambda *_: {'status': 'admitted'})
    monkeypatch.setattr(m, 'automatic_instance', lambda *a, **k: '')
    monkeypatch.setattr(profiles, 'safe_profile_path', lambda _: False)
    with pytest.raises(SystemExit):
        m.start(request)
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'profile-unavailable'
    assert c.execute('SELECT state FROM browsers WHERE lease_id=?', (row['lease_id'],)).fetchone()[0] == 'running'


def test_start_refuses_missing_running_profile_without_stopping(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    c, row = record(m, tmp_path, None)
    c.execute('UPDATE browsers SET profile_dir=? WHERE lease_id=?',
              (str(tmp_path / 'missing-profile'), row['lease_id']))
    c.commit()
    request = recovery_args()
    request.agent_id, request.run_id = row['agent_id'], row['run_id']
    monkeypatch.setattr(m, 'sweep_rows', lambda *a: ([], []))
    monkeypatch.setattr(m, 'cleanup_unused', lambda *a: [])
    monkeypatch.setattr(m, 'admission', lambda *_: {'status': 'admitted'})
    monkeypatch.setattr(m, 'automatic_instance', lambda *a, **k: '')
    monkeypatch.setattr(profiles, 'safe_profile_path', lambda _: True)
    monkeypatch.setattr(m, 'retire', lambda *a: pytest.fail('must not stop'))
    with pytest.raises(SystemExit) as exc:
        m.start(request)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'profile-unavailable'
    assert c.execute('SELECT state FROM browsers WHERE lease_id=?', (row['lease_id'],)).fetchone()[0] == 'running'


def test_start_guards_missing_profile_before_cleanup(monkeypatch, tmp_path, capsys):
    m = provisioner(monkeypatch, tmp_path)
    c, row = record(m, tmp_path, None)
    c.execute('UPDATE browsers SET profile_dir=? WHERE lease_id=?',
              (str(tmp_path / 'missing'), row['lease_id']))
    c.commit()
    request = recovery_args()
    request.agent_id, request.run_id = row['agent_id'], row['run_id']
    monkeypatch.setattr(m, 'sweep_rows', lambda *a: ([], []))
    monkeypatch.setattr(m, 'admission', lambda *_: {'status': 'admitted'})
    monkeypatch.setattr(m, 'automatic_instance', lambda *a, **k: '')
    monkeypatch.setattr(m, 'canonical_owner', lambda *a, **kw: True)
    monkeypatch.setattr(m, 'cleanup_headless', lambda *a: True)
    monkeypatch.setattr(m, 'owner_state', lambda *a: 'terminal')
    monkeypatch.setattr(m, 'activity_snapshot', lambda *a: {
        'idle_seconds': 8000, 'inflight': 0, 'reserved_seconds': 0, 'attached_clients': 0})
    monkeypatch.setattr(m, 'freeze_idle', lambda *a, **kw: True)
    stopped = []
    monkeypatch.setattr(m, 'retire', lambda c, item: stopped.append(item['browser_id']) or True)
    with pytest.raises(SystemExit) as exc:
        m.start(request)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'profile-unavailable'
    assert stopped == []
