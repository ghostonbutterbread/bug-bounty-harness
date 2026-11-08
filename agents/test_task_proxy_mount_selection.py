"""Managed task capture routing, entirely within a disposable mount fixture."""
import argparse
import importlib.util
import json
import os
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / 'skills/chromium-test/scripts/browser_provisioner.py'


def setup(monkeypatch, tmp_path):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    for key, value in {
        'HOME': home, 'XDG_CONFIG_HOME': home / 'config',
        'XDG_CACHE_HOME': home / 'cache', 'XDG_DATA_HOME': home / 'data',
        'XDG_STATE_HOME': home / 'state', 'TMPDIR': tmp_path,
        'HARNESS_SHARED_BASE': tmp_path / 'shared',
        'BROWSER_PROVISIONER_STATE': tmp_path / 'state/manager.sqlite',
    }.items():
        monkeypatch.setenv(key, str(value))
    spec = importlib.util.spec_from_file_location('proxy_mount_provisioner', SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    import browser_profile_lease as profiles
    mount = tmp_path / 'bounty'
    mount.mkdir()
    monkeypatch.setattr(profiles, 'DEFAULT_BOUNTY_ROOT', mount)
    monkeypatch.setattr(profiles, 'default_mount_available', lambda: True)
    monkeypatch.setattr(profiles, 'local_filesystem', lambda path: True)
    monkeypatch.setattr(m, 'port_open', lambda _: False)
    monkeypatch.setattr(m, 'unit_active', lambda _: False)
    monkeypatch.setattr(m, 'unit_identity', lambda _: 'fixture')
    monkeypatch.setattr(m, 'proxy_ready', lambda _: True)
    monkeypatch.setattr(m, 'mitm_runtime', lambda: ('/fake/mitmdump', '/fake/python'))
    return m, profiles, mount


def args(program='Example Program'):
    return argparse.Namespace(agent_id='agent', run_id='run', program=program,
                              account='fixture', purpose='test')


def test_exact_mount_path_persisted_before_dispatch(monkeypatch, tmp_path):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    conn = m.db()
    def dispatch(command, **kwargs):
        row = m.proxy_row(conn, args())
        assert row['flow_path'] == command[command.index('-w') + 1]
        assert row['capture_identity']
        return argparse.Namespace(returncode=0)
    monkeypatch.setattr(m.subprocess, 'run', dispatch)
    row, created = m.start_proxy(conn, args())
    flow = Path(m.proxy_metadata(row)['flow_file'])
    assert created and flow.is_relative_to(mount / 'Example Program/web')
    assert flow.is_file() and flow.stat().st_mode & 0o777 == 0o600
    assert flow.parent.stat().st_mode & 0o777 == 0o700
    assert json.loads(row['capture_identity'])


@pytest.mark.parametrize('program,kind', [
    ('example-program', 'missing'), ('../Example Program', 'invalid'),
    ('Example Program', 'unmounted'), ('Example Program', 'symlink'),
    ('Example Program', 'nonlocal'),
])
def test_unsuitable_mount_falls_back_without_normalization(monkeypatch, tmp_path, program, kind):
    m, profiles, mount = setup(monkeypatch, tmp_path)
    exact = mount / 'Example Program'
    if kind == 'symlink':
        shared = tmp_path / 'shared'
        shared.mkdir()
        exact.symlink_to(shared, target_is_directory=True)
    else:
        exact.mkdir()
    if kind == 'unmounted':
        monkeypatch.setattr(profiles, 'default_mount_available', lambda: False)
    if kind == 'nonlocal':
        monkeypatch.setattr(profiles, 'local_filesystem', lambda _: False)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: argparse.Namespace(returncode=0))
    row, _ = m.start_proxy(m.db(), args(program))
    flow = Path(row['flow_path'])
    assert flow.is_relative_to(Path(row['run_dir']))
    assert flow.is_file() and flow.stat().st_mode & 0o777 == 0o600
    assert not (exact / 'web').exists()


def test_mounted_capture_loss_retains_reservation_and_retry(monkeypatch, tmp_path, capsys):
    m, profiles, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: argparse.Namespace(returncode=0))
    row, _ = m.start_proxy(m.db(), args())
    original = row['flow_path']
    monkeypatch.setattr(profiles, 'default_mount_available', lambda: False)
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(args())
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'proxy-capture-unavailable'
    row = m.proxy_row(m.db(), args())
    assert row['flow_path'] == original and row['state'] == 'stopped'
    monkeypatch.setattr(profiles, 'default_mount_available', lambda: True)
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(args())
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)['flow_file'] == original


def test_fallback_is_sticky_when_mount_appears_and_next_capture_is_unique(monkeypatch, tmp_path, capsys):
    m, _, mount = setup(monkeypatch, tmp_path)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: argparse.Namespace(returncode=0))
    row, _ = m.start_proxy(m.db(), args())
    first = Path(row['flow_path'])
    assert first.is_relative_to(Path(row['run_dir']))
    (mount / 'Example Program').mkdir()
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(args())
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)['flow_file'] == str(first)
    row2, _ = m.start_proxy(m.db(), args())
    second = Path(row2['flow_path'])
    assert first.is_file() and second.is_file() and first != second
    assert second.is_relative_to(mount / 'Example Program/web')


def test_recovery_reports_missing_recorded_mount(monkeypatch, tmp_path, capsys):
    m, profiles, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: argparse.Namespace(returncode=0))
    row, _ = m.start_proxy(m.db(), args())
    conn = m.db()
    conn.execute("update task_proxies set state='cleanup-failed' where lane=?", (row['lane'],))
    conn.commit()
    monkeypatch.setattr(profiles, 'default_mount_available', lambda: False)
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(args(), recovery=True)
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'proxy-capture-unavailable'
    assert m.proxy_row(m.db(), args())['flow_path'] == row['flow_path']


def test_legacy_null_flow_path_preserves_original_location(monkeypatch, tmp_path):
    m, _, _ = setup(monkeypatch, tmp_path)
    conn = m.db()
    root = tmp_path / 'legacy'
    conn.execute("insert into task_proxies(agent_id,run_id,program,account,purpose,lane,port,unit,run_dir,state) values(?,?,?,?,?,?,?,?,?,?)",
                 ('agent', 'run', 'demo', 'fixture', 'test', 'legacy', 8081, 'unit', str(root), 'stopped'))
    conn.commit()
    row = m.proxy_row(conn, args())
    assert m.proxy_metadata(row)['flow_file'] == str(root / 'flows.mitm')
    m.verify_task_capture(row)


def test_replaced_capture_file_is_not_accepted(monkeypatch, tmp_path, capsys):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: argparse.Namespace(returncode=0))
    row, _ = m.start_proxy(m.db(), args())
    flow = Path(row['flow_path'])
    flow.rename(flow.with_suffix('.old'))
    flow.touch(mode=0o600)
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(args())
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'proxy-capture-unavailable'


def test_finish_indexes_actual_mounted_flow(monkeypatch, tmp_path, capsys):
    import sqlite3
    import subprocess
    import sys
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    request = args()
    request.owner_pid = 123
    monkeypatch.setattr(m, 'process_identity', lambda pid: {'pid': pid, 'start': 1})
    conn = m.db()
    conn.execute('insert into finished_proxies values(?,?,?,?)', ('agent', 'run', 'old-lane', 1))
    conn.commit()
    with monkeypatch.context() as fake:
        fake.setattr(m.subprocess, 'run', lambda *a, **k: argparse.Namespace(returncode=0))
        row, _ = m.start_proxy(conn, request)
    assert row['admitted'] == 1 and json.loads(row['owner']) == {'pid': 123, 'start': 1}
    assert conn.execute('select lane from finished_proxies').fetchone()[0] == 'old-lane'
    assert conn.execute('select outcome from proxy_attempts').fetchone()[0] == 'running'
    same, created = m.start_proxy(conn, request)
    assert not created and same['lane'] == row['lane']
    request.owner_pid = 124
    with pytest.raises(SystemExit) as conflict:
        m.start_proxy(conn, request)
    assert conflict.value.code == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'proxy-conflict'
    request.owner_pid = 123
    flow = Path(row['flow_path'])
    subprocess.run([sys.executable, '-c', (
        "import sys; from mitmproxy import http,connection; from mitmproxy.io import FlowWriter; "
        "f=http.HTTPFlow(connection.Client(peername=('127.0.0.1',1234),sockname=('127.0.0.1',8080),timestamp_start=1),connection.Server(address=('example.test',80))); "
        "f.request=http.Request.make('GET','http://example.test/mounted'); "
        "out=open(sys.argv[1],'wb'); FlowWriter(out).add(f); out.close()"), str(flow)], check=True)
    monkeypatch.setattr(m, 'mitm_runtime', lambda: ('/fixture/mitmdump', sys.executable))
    with pytest.raises(SystemExit) as exc:
        m.finish_proxy(args())
    assert exc.value.code == 0
    result = json.loads(capsys.readouterr().out)
    assert result['flow_file'] == str(flow) and result['indexed']
    assert conn.execute('select lane from finished_proxies').fetchone()[0] == row['lane']
    assert conn.execute('select outcome from proxy_attempts').fetchone()[0] == 'finished'
    store = Path.home() / '.local/share/ghost/proxy-store/proxy_store.sqlite'
    assert store.is_relative_to(tmp_path) and store.is_file()
    with sqlite3.connect(store) as conn:
        assert conn.execute('select count(*) from requests where lane=?', (row['lane'],)).fetchone()[0] == 1


def test_default_acl_inheritance_keeps_capture_private(monkeypatch, tmp_path):
    import shutil
    import subprocess
    if not shutil.which('setfacl'):
        pytest.skip('setfacl is required')
    m, _, mount = setup(monkeypatch, tmp_path)
    program = mount / 'Example Program'
    web = program / 'web'
    web.mkdir(parents=True)
    subprocess.run(['setfacl', '-m', 'd:u:65534:rwx', str(web)], check=True)
    before = (web.stat().st_mode, os.getxattr(web, 'system.posix_acl_default'))
    with monkeypatch.context() as fake:
        fake.setattr(m.subprocess, 'run', lambda *a, **k: argparse.Namespace(returncode=0))
        row, _ = m.start_proxy(m.db(), args())
    flow = Path(row['flow_path'])
    assert flow.is_relative_to(web)
    assert flow.stat().st_mode & 0o777 == 0o600
    assert flow.parent.stat().st_mode & 0o777 == 0o700
    assert (web.stat().st_mode, os.getxattr(web, 'system.posix_acl_default')) == before


def test_access_acl_writer_and_mask_with_reachable_ancestor_fixture(monkeypatch, tmp_path):
    import shutil
    import subprocess
    if not shutil.which('setfacl'):
        pytest.skip('setfacl is required')
    m, _, mount = setup(monkeypatch, tmp_path)
    web = mount / 'Example Program/web'
    web.mkdir(parents=True)
    subprocess.run(['setfacl', '-m', 'u:65534:rwx,m::r-x', str(web)], check=True)
    original_fstat = os.fstat
    def accessible(fd):
        info = original_fstat(fd)
        values = list(info)
        # Model ancestors as searchable and non-writable, leaving the target's
        # actual ACL and effective mask as the behavior under test.
        values[0] = (int(values[0]) | 0o055) & ~0o022
        return os.stat_result(values)
    with monkeypatch.context() as fake:
        fake.setattr(m.os, 'fstat', accessible)
        fd = m._capture_open_dir(web)
        os.close(fd)
        subprocess.run(['setfacl', '-m', 'm::rwx', str(web)], check=True)
        with pytest.raises(PermissionError, match='ACL writer'):
            m._capture_open_dir(web)


def test_task_owned_without_program_does_not_use_synthetic_program_directory(monkeypatch, tmp_path):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'task-owned').mkdir()
    request = args('task-owned')
    request.task_owned = True
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: argparse.Namespace(returncode=0))
    row, _ = m.start_proxy(m.db(), request)
    assert Path(row['flow_path']).is_relative_to(Path(row['run_dir']))
    assert not (mount / 'task-owned/web').exists()


def test_shared_bind_mount_alias_is_not_local_capture(monkeypatch, tmp_path):
    m, _, mount = setup(monkeypatch, tmp_path)
    shared = tmp_path / 'shared'
    monkeypatch.setenv('HARNESS_SHARED_BASE', str(shared))
    real_read = Path.read_text
    fixture = (f'1 0 8:1 / / rw - ext4 /dev/fixture rw\n'
               f'2 1 8:1 {shared} {mount} rw - ext4 /dev/fixture rw\n')
    def read(path, *args, **kwargs):
        return fixture if str(path) == '/proc/self/mountinfo' else real_read(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', read)
    assert not m._capture_local_private_path(mount / 'Example Program')


def test_shared_alias_to_program_is_never_used(monkeypatch, tmp_path):
    m, _, mount = setup(monkeypatch, tmp_path)
    program = mount / 'Example Program'
    program.mkdir()
    shared = tmp_path / 'shared-alias'
    shared.symlink_to(program, target_is_directory=True)
    monkeypatch.setenv('HARNESS_SHARED_BASE', str(shared))
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: argparse.Namespace(returncode=0))
    row, _ = m.start_proxy(m.db(), args())
    assert Path(row['flow_path']).is_relative_to(Path(row['run_dir']))
    assert not (program / 'web').exists()


def test_shared_state_is_not_used_for_private_fallback(monkeypatch, tmp_path):
    m, _, mount = setup(monkeypatch, tmp_path)
    shared = tmp_path / 'shared'
    shared.mkdir()
    monkeypatch.setenv('HARNESS_SHARED_BASE', str(shared))
    monkeypatch.setattr(m, 'STATE', shared / 'manager.sqlite')
    with pytest.raises(m.ProxyStartupError, match='Shared'):
        m.start_proxy(m.db(), args())
    assert not (shared / 'task-proxies').exists()
