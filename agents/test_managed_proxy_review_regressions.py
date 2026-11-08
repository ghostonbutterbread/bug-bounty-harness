"""Offline regression tests for managed proxy capture and resume recovery."""
import argparse
import json
from pathlib import Path

import pytest
from test_task_proxy_mount_selection import setup, args


def test_finish_capture_disappears_after_verification(monkeypatch, tmp_path, capsys):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: argparse.Namespace(returncode=0))
    row, _ = m.start_proxy(m.db(), args())
    flow = Path(row['flow_path'])
    flow.write_bytes(b'owned fixture')
    verify = m.verify_task_capture
    def disappear(row):
        verify(row)
        flow.rename(flow.with_suffix('.saved'))
    monkeypatch.setattr(m, 'verify_task_capture', disappear)
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(args())
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'proxy-capture-unavailable'
    assert m.proxy_row(m.db(), args()) is not None
    assert flow.with_suffix('.saved').read_bytes() == b'owned fixture'


def test_capture_changed_during_index_preserves_reservation(monkeypatch, tmp_path, capsys):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    def dispatch(command, **kwargs):
        if 'index-lane' in command:
            flow = Path(command[command.index('--flow-file') + 1])
            flow.rename(flow.with_suffix('.saved'))
            return argparse.Namespace(returncode=0, stdout=json.dumps({'status': 'indexed'}))
        return argparse.Namespace(returncode=0)
    monkeypatch.setattr(m.subprocess, 'run', dispatch)
    row, _ = m.start_proxy(m.db(), args())
    Path(row['flow_path']).write_bytes(b'fixture')
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(args())
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'proxy-capture-unavailable'
    assert m.proxy_row(m.db(), args()) is not None


def test_interrupted_allocation_keeps_reservation_and_unrelated_files(monkeypatch, tmp_path, capsys):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    select = m.select_task_capture
    captures = []
    def interrupt(*a, **kw):
        flow, identity = select(*a, **kw)
        flow.write_bytes(b'uncommitted fixture')
        captures.append(flow)
        raise SystemExit('interrupted')
    monkeypatch.setattr(m, 'select_task_capture', interrupt)
    with pytest.raises(SystemExit):
        m.start_proxy(m.db(), args())
    unrelated = mount / 'unrelated'
    unrelated.write_bytes(b'keep')
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(args(), recovery=True)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'proxy-capture-unavailable'
    row = m.proxy_row(m.db(), args())
    assert row is not None and m.proxy_metadata(row)['flow_file'] is None
    assert captures[0].read_bytes() == b'uncommitted fixture'
    assert unrelated.read_bytes() == b'keep'


def test_running_resume_checks_exact_proxy_program(monkeypatch, tmp_path, capsys):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: argparse.Namespace(returncode=0))
    conn = m.db()
    task, _ = m.start_proxy(conn, args())
    meta = m.proxy_metadata(task)
    info = {'proxy_server': meta['proxy_server'], 'proxy_cert_mode': 'import',
            'proxy_cert_status': {'status': 'trusted', 'ca_cert': meta['ca_cert'], 'ca_sha256': 'fixture'},
            'launch_recipe': {'program': 'example-program', 'exact_program': 'Example Program'}}
    monkeypatch.setattr(m, 'record_info', lambda _: info)
    monkeypatch.setattr(m, 'ca_fingerprint', lambda _: 'fixture')
    monkeypatch.setattr(m, 'canonical_owner', lambda *_: True)
    monkeypatch.setattr(m, 'reservation_blocks', lambda *_: False)
    monkeypatch.setattr(m, 'lifecycle_state', lambda *_: 'active')
    monkeypatch.setattr(m, 'healthy', lambda *_: True)
    monkeypatch.setattr(m, 'activity_snapshot', lambda *_: None)
    monkeypatch.setattr(m, 'safe', lambda _: {})
    monkeypatch.setattr(m, 'monitor_unit', lambda _: 'fixture')
    with pytest.raises(SystemExit) as exc:
        m.resume_running(conn, {'browser_id': 'browser'}, args())
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'already-running'
    # A slug-colliding spelling must not be accepted as the same request.
    info['launch_recipe']['exact_program'] = 'example-program'
    with pytest.raises(SystemExit) as exc:
        m.resume_running(conn, {'browser_id': 'browser'}, args())
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['reason'] == 'proxy-or-ca-unverified'
    # Old recipes can recover the exact identity from the owned proxy row.
    del info['launch_recipe']['exact_program']
    with pytest.raises(SystemExit) as exc:
        m.resume_running(conn, {'browser_id': 'browser'}, args())
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'already-running'


def test_legacy_and_mismatched_resume_program(monkeypatch, tmp_path):
    m, _, _ = setup(monkeypatch, tmp_path)
    task = {'program': 'example-program', 'exact_program': 'Example Program'}
    assert m.resume_program({'program': 'example-program'}, task) == 'Example Program'
    assert m.resume_program({'program': 'example-program'}, None) == 'example-program'
    assert m.resume_program({'program': 'example-program', 'exact_program': 'Other'}, task) is None
    assert m.resume_program({'program': 'example-program', 'exact_program': 'Example Program'}, task) == 'Example Program'


def test_allocation_exception_retains_pending_reservation(monkeypatch, tmp_path):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    allocate = m._capture_file
    files = []
    def fail_after_allocation(path):
        flow = allocate(path)
        flow.write_bytes(b'preserve')
        files.append(flow)
        raise OSError('fixture failure')
    monkeypatch.setattr(m, '_capture_file', fail_after_allocation)
    with pytest.raises(OSError, match='fixture failure'):
        m.start_proxy(m.db(), args())
    row = m.proxy_row(m.db(), args())
    assert row['state'] == 'cleanup-failed' and row['capture_identity'] == 'allocation-pending'
    assert len(files) == 1 and files[0].read_bytes() == b'preserve'


@pytest.mark.parametrize('legacy', [False, True])
def test_stopped_resume_dispatches_exact_program(monkeypatch, tmp_path, capsys, legacy):
    from test_browser_safe_resume import prepared_resume
    import browser_profile_lease as profiles
    m, conn, row, recipe = prepared_resume(monkeypatch, tmp_path, task_owned=False)
    conn.execute("update browsers set program='example-program' where browser_id='browser-0'")
    conn.commit()
    recipe.update(program='example-program', proxy='mitm', proxy_cert_mode='import',
                  proxy_server='http://127.0.0.1:8081', ca_sha256='fixture')
    if not legacy:
        recipe['exact_program'] = 'Example Program'
    launch = Path(row['launch_file'])
    info = json.loads(launch.read_text())
    info['launch_recipe'] = recipe
    launch.write_text(json.dumps(info))
    task = {'program': 'example-program', 'exact_program': 'Example Program',
            'state': 'running', 'port': 8081, 'run_dir': str(tmp_path),
            'lane': 'fixture', 'unit': 'fixture', 'flow_path': None, 'capture_identity': None}
    monkeypatch.setattr(m, 'proxy_row', lambda *_: task)
    monkeypatch.setattr(m, 'proxy_ready', lambda *_: True)
    monkeypatch.setattr(m, 'ca_fingerprint', lambda *_: 'fixture')
    monkeypatch.setattr(profiles, 'resolve_account', lambda program, account: ({'alias': 'blue'}, None))
    monkeypatch.setattr(profiles, 'account_lease_eligible', lambda *_: True)
    monkeypatch.setattr(profiles, 'auth_domain_for', lambda *_: 'example.test')
    monkeypatch.setattr(m, 'account_policy', lambda *_: False)
    monkeypatch.setattr(m, 'account_auth_policy', lambda *_: None)
    calls = []
    def child(cmd, **kwargs):
        calls.append(cmd)
        return argparse.Namespace(returncode=2, stdout=json.dumps({'status': 'queued'}))
    monkeypatch.setattr(m.subprocess, 'run', child)
    with pytest.raises(SystemExit) as exc:
        m.resume(argparse.Namespace(browser_id='browser-0', agent_id='agent', run_id='run'))
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'queued'
    assert calls[0][3:5] == ['Example Program', 'blue']
