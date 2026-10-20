"""Disposable manager fixtures; no live Chrome or systemd calls."""
import argparse
import importlib.util
import json
import time
from types import SimpleNamespace
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / 'skills/chromium-test/scripts/browser_provisioner.py'


def manager(monkeypatch, tmp_path):
    monkeypatch.setenv('BROWSER_PROVISIONER_STATE', str(tmp_path / 'manager.sqlite'))
    spec = importlib.util.spec_from_file_location('browser_safe_resume_fixture', SCRIPT)
    assert spec is not None and spec.loader is not None
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def rows(m, tmp_path, count=4, state='running'):
    c = m.db()
    for n in range(count):
        bid = f'browser-{n}'
        c.execute('INSERT INTO browsers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  (f'lease-{n}', bid, 'demo', 'blue', 'example.test', 'agent', 'run',
                   'fixture', f'unit-{n}', str(tmp_path / f'profile-{n}'),
                   str(tmp_path / f'{bid}.json'), state, 0, 0, 0, 0))
        (tmp_path / f'{bid}.json').write_text(json.dumps({'unit_invocation': f'invocation-{n}',
                                                       'command': ['--no-proxy-server']}))
    c.commit()
    return c


def result(call):
    with pytest.raises(SystemExit) as exc:
        call()
    return exc.value.code


def test_cleanup_four_live_units_zero_stops(monkeypatch, tmp_path, capsys):
    m = manager(monkeypatch, tmp_path)
    c = rows(m, tmp_path)
    monkeypatch.setattr(m, 'canonical_owner', lambda row, **_: True)
    monkeypatch.setattr(m, 'reservation_blocks', lambda row: False)
    monkeypatch.setattr(m, 'unit_identity', lambda unit: 'invocation-' + unit.rsplit('-', 1)[1])
    monkeypatch.setattr(m, 'unit_active', lambda unit: True)
    monkeypatch.setattr(m, 'healthy', lambda row: True)
    monkeypatch.setattr(m, 'owner_state', lambda owner: 'active')
    monkeypatch.setattr(m, 'activity_snapshot', lambda row: {'idle_seconds': 90000, 'inflight': 0, 'reserved_seconds': 0, 'attached_clients': 0})
    monkeypatch.setattr(m, 'admission', lambda *a: {'status': 'queued'})
    stops = []
    monkeypatch.setattr(m, 'retire', lambda *a: stops.append(a))
    assert result(lambda: m.cleanup(argparse.Namespace(apply=True))) == 0
    output = json.loads(capsys.readouterr().out)
    assert len(output['browsers']) == 4
    assert {entry['result'] for entry in output['browsers']} == {'owner-active-or-unverified'}
    assert output['stopped'] == [] and stops == []
    assert c.execute("SELECT count(*) FROM browsers WHERE state='running'").fetchone()[0] == 4


def test_cleanup_dry_run_and_terminal_apply(monkeypatch, tmp_path, capsys):
    m = manager(monkeypatch, tmp_path)
    rows(m, tmp_path, count=1)
    monkeypatch.setattr(m, 'canonical_owner', lambda row, **_: True)
    monkeypatch.setattr(m, 'reservation_blocks', lambda row: False)
    monkeypatch.setattr(m, 'unit_identity', lambda unit: 'invocation-0')
    monkeypatch.setattr(m, 'unit_active', lambda unit: True)
    monkeypatch.setattr(m, 'healthy', lambda row: True)
    monkeypatch.setattr(m, 'owner_state', lambda owner: 'terminal')
    monkeypatch.setattr(m, 'activity_snapshot', lambda row: {'idle_seconds': 7201, 'inflight': 0, 'reserved_seconds': 0, 'attached_clients': 0})
    monkeypatch.setattr(m, 'admission', lambda *a: {'status': 'queued'})
    stops = []
    monkeypatch.setattr(m, 'freeze_idle', lambda row, threshold, **kw: threshold == 7200 and kw['require_detached'])
    monkeypatch.setattr(m, 'retire', lambda c, row: stops.append(row['browser_id']) or True)
    assert result(lambda: m.cleanup(argparse.Namespace(apply=False))) == 0
    assert json.loads(capsys.readouterr().out)['browsers'][0]['result'] == 'eligible-terminal-idle'
    assert not stops
    assert result(lambda: m.cleanup(argparse.Namespace(apply=True))) == 0
    assert json.loads(capsys.readouterr().out)['stopped'] == ['browser-0']
    assert stops == ['browser-0']


def test_resume_exact_owner_healthy_and_stopped_blocker(monkeypatch, tmp_path, capsys):
    m = manager(monkeypatch, tmp_path)
    c = rows(m, tmp_path, count=1)
    args = argparse.Namespace(browser_id='browser-0', agent_id='agent', run_id='run')
    assert result(lambda: m.resume(argparse.Namespace(**{**vars(args), 'run_id': 'other'}))) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'not-owner'
    monkeypatch.setattr(m, 'canonical_owner', lambda row, **_: True)
    monkeypatch.setattr(m, 'reservation_blocks', lambda row: False)
    monkeypatch.setattr(m, 'lifecycle_state', lambda c, row: 'active')
    monkeypatch.setattr(m, 'healthy', lambda row: True)
    monkeypatch.setattr(m, 'activity_snapshot', lambda row: {'frozen': False, 'last_activity': 0})
    monkeypatch.setattr(m, 'matching_proxy', lambda c, args, row: True)
    monkeypatch.setattr(m, 'unit_active', lambda unit: True)
    monkeypatch.setattr(m, 'proxy_row', lambda c, args: None)
    assert result(lambda: m.resume(args)) == 0
    output = json.loads(capsys.readouterr().out)
    assert output['status'] == 'already-running' and output['browser_id'] == 'browser-0'
    c.execute("UPDATE browsers SET state='stopped' WHERE browser_id='browser-0'")
    c.commit()
    monkeypatch.setattr(m, 'stopped', lambda row: True)
    assert result(lambda: m.resume(args)) == 2
    output = json.loads(capsys.readouterr().out)
    assert output['reason'] == 'safe-launch-recipe-unavailable'
    assert output['state_lost'] is False


def test_cleanup_refuses_hold_and_missing_canonical_owner(monkeypatch, tmp_path, capsys):
    m = manager(monkeypatch, tmp_path)
    rows(m, tmp_path, count=3)
    monkeypatch.setattr(m, 'canonical_owner', lambda row, **_: row['browser_id'] != 'browser-0')
    monkeypatch.setattr(m, 'reservation_blocks', lambda row: False)
    monkeypatch.setattr(m, 'unit_identity', lambda unit: 'invocation-' + unit.rsplit('-', 1)[1])
    monkeypatch.setattr(m, 'unit_active', lambda unit: True)
    monkeypatch.setattr(m, 'healthy', lambda row: True)
    monkeypatch.setattr(m, 'owner_state', lambda owner: 'terminal')
    monkeypatch.setattr(m, 'activity_snapshot', lambda row: {'idle_seconds': 8000, 'inflight': 0,
        'reserved_seconds': 120 if row['browser_id'] == 'browser-1' else 0,
        'attached_clients': 1 if row['browser_id'] == 'browser-2' else 0})
    monkeypatch.setattr(m, 'admission', lambda *a: {'status': 'queued'})
    monkeypatch.setattr(m, 'retire', lambda *a: pytest.fail('protected browser stopped'))
    assert result(lambda: m.cleanup(argparse.Namespace(apply=True))) == 0
    reasons = [entry['result'] for entry in json.loads(capsys.readouterr().out)['browsers']]
    assert reasons == ['canonical-owner-unverified', 'inflight-or-held', 'controller-attached-or-unverified']


def test_task_owned_lost_profile_refusal(monkeypatch, tmp_path, capsys):
    m = manager(monkeypatch, tmp_path)
    c = rows(m, tmp_path, count=1, state='stopped')
    c.execute("UPDATE browsers SET program='task-owned' WHERE browser_id='browser-0'")
    c.commit()
    monkeypatch.setattr(m, 'canonical_owner', lambda row, **_: True)
    monkeypatch.setattr(m, 'stopped', lambda row: True)
    assert result(lambda: m.resume(argparse.Namespace(browser_id='browser-0', agent_id='agent', run_id='run'))) == 2
    assert json.loads(capsys.readouterr().out)['state_lost'] is True


def test_adapter_reports_attached_socket_even_without_session(monkeypatch, tmp_path):
    manager(monkeypatch, tmp_path)
    spec = importlib.util.spec_from_file_location('browser_control_fixture', SCRIPT.with_name('browser_control.py'))
    assert spec is not None and spec.loader is not None
    browser_control = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(browser_control)
    adapter = SimpleNamespace(last_activity=0, last_use=time.monotonic() - 8000,
        inflight=0, reserved_until=0, frozen=False, clients={object(): set()})
    assert browser_control.PipeBrowser.activity_status(adapter)['attached_clients'] == 1
