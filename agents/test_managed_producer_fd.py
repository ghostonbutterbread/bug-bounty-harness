"""Managed producer must verify and pin its capture inside the service."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import pytest
from agents.test_task_proxy_mount_selection import setup, args


def test_service_dispatch_uses_recorded_identity_not_mutable_write_path(monkeypatch, tmp_path):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    conn = m.db()
    seen = []
    def dispatch(command, **kwargs):
        seen.append(command)
        return argparse.Namespace(returncode=0)
    monkeypatch.setattr(m.subprocess, 'run', dispatch)
    row, _ = m.start_proxy(conn, args())
    cmd = seen[0]
    assert '--verified-capture-launch' in cmd
    assert row['capture_identity'] in cmd
    assert cmd[cmd.index('--verified-capture-launch') + 1] == row['flow_path']
    assert '-w' not in cmd
    assert '--property=UMask=0077' in cmd and '--property=MemoryMax=512M' in cmd
    assert cmd[-9:] == ['/fake/mitmdump', '--listen-host', '127.0.0.1', '--listen-port',
                        str(row['port']), '--set', f"confdir={row['run_dir']}/mitmproxy",
                        '--set', 'flow_detail=0']


def allocated(monkeypatch, tmp_path):
    m, profiles, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: argparse.Namespace(returncode=0))
    row, _ = m.start_proxy(m.db(), args())
    return m, profiles, mount, Path(row['flow_path']), json.loads(row['capture_identity'])


def test_leaf_replacement_refused_without_truncating(monkeypatch, tmp_path):
    m, _, _, flow, identity = allocated(monkeypatch, tmp_path)
    flow.rename(flow.with_name('original'))
    flow.write_bytes(b'keep replacement')
    flow.chmod(0o600)
    with pytest.raises(OSError, match='generation changed'):
        m._launch_verified_capture(flow, identity, ['/bin/false'])
    assert flow.read_bytes() == b'keep replacement'


def test_directory_replacement_refused_without_truncating(monkeypatch, tmp_path):
    m, _, _, flow, identity = allocated(monkeypatch, tmp_path)
    original = flow.parent.with_name(flow.parent.name + '-original')
    flow.parent.rename(original)
    flow.parent.mkdir(mode=0o700)
    flow.write_bytes(b'keep replacement')
    flow.chmod(0o600)
    with pytest.raises(OSError, match='generation changed'):
        m._launch_verified_capture(flow, identity, ['/bin/false'])
    assert flow.read_bytes() == b'keep replacement'
    assert (original / flow.name).read_bytes() == b''


def test_symlink_to_shared_refused_without_writing(monkeypatch, tmp_path):
    m, _, _, flow, identity = allocated(monkeypatch, tmp_path)
    shared = tmp_path / 'shared'
    shared.mkdir(exist_ok=True)
    target = shared / 'untouched'
    target.write_bytes(b'keep shared')
    flow.unlink()
    flow.symlink_to(target)
    with pytest.raises(OSError):
        m._launch_verified_capture(flow, identity, ['/bin/false'])
    assert target.read_bytes() == b'keep shared'


def test_unmounted_or_replaced_mount_refuses_producer(monkeypatch, tmp_path):
    m, profiles, mount, flow, identity = allocated(monkeypatch, tmp_path)
    monkeypatch.setattr(profiles, 'default_mount_available', lambda: False)
    with pytest.raises(OSError, match='mount unavailable'):
        m._launch_verified_capture(flow, identity, ['/bin/false'])
    monkeypatch.setattr(profiles, 'default_mount_available', lambda: True)
    identity['mount'] = [identity['mount'][0], identity['mount'][1] + 1]
    with pytest.raises(OSError, match='mount changed'):
        m._launch_verified_capture(flow, identity, ['/bin/false'])
    assert flow.read_bytes() == b''


def test_swap_after_open_writes_only_original_descriptor(monkeypatch, tmp_path):
    m, _, _, flow, identity = allocated(monkeypatch, tmp_path)
    old = flow.with_name('original')
    class ExecObserved(Exception):
        pass
    def execv(executable, command):
        flow.rename(old)
        flow.write_bytes(b'keep replacement')
        with open(command[-1], 'wb') as output:
            output.write(b'synthetic flow')
        raise ExecObserved()
    monkeypatch.setattr(m.os, 'execv', execv)
    with pytest.raises(ExecObserved):
        m._launch_verified_capture(flow, identity, ['/bin/false'])
    assert old.read_bytes() == b'synthetic flow'
    assert flow.read_bytes() == b'keep replacement'


def test_internal_launcher_execs_inherited_descriptor(monkeypatch, tmp_path):
    # Exercise the actual process entry point and exec, using private fallback.
    m, _, _ = setup(monkeypatch, tmp_path)
    root = tmp_path / 'private'
    root.mkdir(mode=0o700)
    flow = m._capture_file(root / 'capture')
    identity = m._capture_identity(flow)
    assert m.__file__ is not None
    script = Path(m.__file__)
    producer = "import sys; open(sys.argv[-1], 'wb').write(b'fixture producer')"
    result = subprocess.run([sys.executable, str(script), '--verified-capture-launch', str(flow),
                             json.dumps(identity), sys.executable, '-c', producer],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert flow.read_bytes() == b'fixture producer'


def test_internal_launcher_failure_reports_recovery(monkeypatch, tmp_path):
    m, _, _ = setup(monkeypatch, tmp_path)
    root = tmp_path / 'private'
    root.mkdir(mode=0o700)
    flow = m._capture_file(root / 'capture')
    identity = m._capture_identity(flow)
    flow.rename(flow.with_name('original'))
    flow.write_bytes(b'preserve')
    flow.chmod(0o600)
    assert m.__file__ is not None
    result = subprocess.run([sys.executable, m.__file__, '--verified-capture-launch', str(flow),
                             json.dumps(identity), '/bin/false', 'unused'],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert 'capture generation changed' in result.stderr
    assert 'preserve the capture' in result.stderr
    assert flow.read_bytes() == b'preserve'


def test_failed_service_identity_check_retains_generation_for_manual_reconciliation(monkeypatch, tmp_path, capsys):
    m, _, _ = setup(monkeypatch, tmp_path)
    request = args()
    request.task_owned = True  # private fallback works in the real child process
    conn = m.db()
    real_run = subprocess.run
    dispatched = {}

    def dispatch(command, **kwargs):
        child = command[command.index('--') + 1:]
        row = m.proxy_row(conn, request)
        dispatched.update(lane=row['lane'], path=row['flow_path'], identity=row['capture_identity'])
        flow = Path(row['flow_path'])
        flow.write_bytes(b'original capture')
        flow.rename(flow.with_name('original'))
        flow.write_bytes(b'replacement capture')
        flow.chmod(0o600)
        result = real_run(child, capture_output=True, text=True)
        assert result.returncode != 0 and 'capture generation changed' in result.stderr
        return argparse.Namespace(returncode=0)

    monkeypatch.setattr(m.subprocess, 'run', dispatch)
    monkeypatch.setattr(m, 'proxy_ready', lambda _: False)
    with pytest.raises(m.ProxyStartupError) as failure:
        m.start_proxy(conn, request)
    row = m.proxy_row(conn, request)
    assert row is not None
    assert 'reconcil' in str(failure.value)
    assert (row['lane'], row['flow_path'], row['capture_identity'], row['state']) == (
        dispatched['lane'], dispatched['path'], dispatched['identity'], 'cleanup-failed')
    flow = Path(row['flow_path'])
    assert flow.read_bytes() == b'replacement capture'
    assert flow.with_name('original').read_bytes() == b'original capture'
    assert conn.execute('select outcome from proxy_attempts where lane=?', (row['lane'],)).fetchone()[0] != 'aborted'
    with pytest.raises(SystemExit) as exc:
        m.task_proxy_status(request)
    captured = capsys.readouterr()
    status = json.loads(captured.out)
    assert json.dumps(m.PROXY_CLEANUP_UNVERIFIED) in captured.err.splitlines()
    assert exc.value.code == 0 and status['status'] == 'capture-uncertain'
    assert status['capture_identity'] == dispatched['identity']
    assert status['task_proxy']['flow_file'] == dispatched['path']
    # Even if the old inode reappears, a retry must not silently erase the
    # record of the observed service-side uncertainty.
    flow.rename(flow.with_name('replacement'))
    flow.with_name('original').rename(flow)
    for _ in range(2):
        with pytest.raises(SystemExit) as exc:
            m.finish_proxy(request, recovery=True)
        assert exc.value.code == 2
        response = json.loads(capsys.readouterr().out)
        assert response['reservation'] == 'retained'
        assert m.proxy_row(conn, request)['capture_identity'] == dispatched['identity']
    assert flow.read_bytes() == b'original capture'


def test_interrupted_dispatch_keeps_uncertain_capture_across_recovery(monkeypatch, tmp_path, capsys):
    m, _, _ = setup(monkeypatch, tmp_path)
    request = args()
    request.task_owned = True
    conn = m.db()
    class Interrupted(BaseException):
        pass
    def dispatch(*unused, **kwargs):
        raise Interrupted()
    monkeypatch.setattr(m.subprocess, 'run', dispatch)
    with pytest.raises(Interrupted):
        m.start_proxy(conn, request)
    row = m.proxy_row(conn, request)
    assert row['flow_path'] and row['capture_identity']
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(request, recovery=True)
    response = json.loads(capsys.readouterr().out)
    assert exc.value.code == 2 and response['reservation'] == 'retained'
    assert m.proxy_row(conn, request)['capture_identity'] == row['capture_identity']


def test_prelaunch_replacement_retains_identity(monkeypatch, tmp_path, capsys):
    m, _, _ = setup(monkeypatch, tmp_path)
    request = args()
    request.task_owned = True
    conn = m.db()
    def fail_before_dispatch():
        row = m.proxy_row(conn, request)
        flow = Path(row['flow_path'])
        flow.rename(flow.with_name('original'))
        flow.write_bytes(b'replacement')
        flow.chmod(0o600)
        raise RuntimeError('prelaunch failure')
    monkeypatch.setattr(m, 'mitm_runtime', fail_before_dispatch)
    with pytest.raises(m.ProxyStartupError, match='reconcile'):
        m.start_proxy(conn, request)
    row = m.proxy_row(conn, request)
    assert row['state'] == 'cleanup-failed' and row['flow_path'] and row['capture_identity']
    assert Path(row['flow_path']).read_bytes() == b'replacement'
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(request, recovery=True)
    assert exc.value.code == 2 and json.loads(capsys.readouterr().out)['reservation'] == 'retained'


def test_recovery_records_prelaunch_identity_loss_even_if_original_returns(monkeypatch, tmp_path, capsys):
    m, _, _ = setup(monkeypatch, tmp_path)
    request = args()
    request.task_owned = True
    conn = m.db()
    class Interrupted(BaseException):
        pass
    monkeypatch.setattr(m, 'mitm_runtime', lambda: (_ for _ in ()).throw(Interrupted()))
    with pytest.raises(Interrupted):
        m.start_proxy(conn, request)
    row = m.proxy_row(conn, request)
    flow = Path(row['flow_path'])
    flow.rename(flow.with_name('original'))
    flow.write_bytes(b'replacement')
    flow.chmod(0o600)
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(request, recovery=True)
    assert exc.value.code == 2
    capsys.readouterr()
    flow.rename(flow.with_name('replacement'))
    flow.with_name('original').rename(flow)
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(request, recovery=True)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['reservation'] == 'retained'
    assert m.proxy_row(conn, request)['capture_identity'] == row['capture_identity']
