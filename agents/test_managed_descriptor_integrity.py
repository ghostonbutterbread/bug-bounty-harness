"""Offline fault injection for managed capture allocation and indexing."""
import argparse
import errno
import json
import os
from pathlib import Path

import pytest
from test_task_proxy_mount_selection import setup, args


def test_mounted_lane_mkdir_eacces_uses_private_fallback(monkeypatch, tmp_path):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    mkdir = m.os.mkdir
    def deny(path, *a, **kw):
        fd = kw.get('dir_fd')
        if fd is not None and str(path).startswith('task-') and Path(os.readlink(f'/proc/self/fd/{fd}')) == mount / 'Example Program/web/proxy/flows':
            raise PermissionError(errno.EACCES, 'fixture denied before allocation')
        return mkdir(path, *a, **kw)
    monkeypatch.setattr(m.os, 'mkdir', deny)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: argparse.Namespace(returncode=0))
    row, _ = m.start_proxy(m.db(), args())
    assert Path(row['flow_path']).is_relative_to(Path(row['run_dir']))
    assert row['state'] == 'running' and row['capture_identity'] != 'allocation-pending'


def test_pending_status_explains_manual_recovery(monkeypatch, tmp_path, capsys):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    allocate = m._capture_file
    def interrupted(path):
        allocate(path)
        raise OSError('ambiguous')
    monkeypatch.setattr(m, '_capture_file', interrupted)
    with pytest.raises(OSError):
        m.start_proxy(m.db(), args())
    with pytest.raises(SystemExit):
        m.task_proxy_status(args())
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'allocation-pending'
    assert result['task_proxy']['flow_file'] is None
    assert 'manual' in result['detail'].lower() and 'preserve' in result['detail'].lower()


def test_index_reads_pinned_descriptor_during_path_swap(monkeypatch, tmp_path, capsys):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    seen = []
    def dispatch(cmd, **kw):
        if 'index-lane' in cmd:
            logical = Path(cmd[cmd.index('--flow-file') + 1])
            saved = logical.with_name('saved')
            logical.rename(saved)
            logical.write_bytes(b'wrong')
            try:
                fd = int(cmd[cmd.index('--flow-fd') + 1])
                assert fd in kw['pass_fds']
                seen.append(os.pread(fd, 100, 0))
            finally:
                logical.unlink()
                saved.rename(logical)
            return argparse.Namespace(returncode=0, stdout=json.dumps({'status': 'indexed'}))
        return argparse.Namespace(returncode=0)
    monkeypatch.setattr(m.subprocess, 'run', dispatch)
    row, _ = m.start_proxy(m.db(), args())
    Path(row['flow_path']).write_bytes(b'original')
    with pytest.raises(SystemExit) as out:
        m.finish_proxy(args())
    assert out.value.code == 0
    assert seen == [b'original']


def test_nonempty_capture_cannot_be_skipped_by_stat_swap(monkeypatch, tmp_path, capsys):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    calls = []
    def dispatch(cmd, **kw):
        calls.append(cmd)
        return argparse.Namespace(returncode=0, stdout=json.dumps({'status': 'indexed'}))
    monkeypatch.setattr(m.subprocess, 'run', dispatch)
    row, _ = m.start_proxy(m.db(), args())
    flow = Path(row['flow_path'])
    flow.write_bytes(b'nonempty')
    original = Path.stat
    verified = m.verify_task_capture
    phase = []
    def verify(row):
        verified(row)
        phase.append(True)
    def swap(path, *a, **kw):
        if path == flow and phase:
            saved = flow.with_name('saved')
            flow.rename(saved)
            flow.touch(mode=0o600)
            try:
                return original(path, *a, **kw)
            finally:
                flow.unlink()
                saved.rename(flow)
        return original(path, *a, **kw)
    monkeypatch.setattr(m, 'verify_task_capture', verify)
    monkeypatch.setattr(Path, 'stat', swap)
    with pytest.raises(SystemExit) as out:
        m.finish_proxy(args())
    assert out.value.code == 0
    assert any('index-lane' in command for command in calls)


def test_real_index_reads_original_during_swap_and_records_logical_path(monkeypatch, tmp_path, capsys):
    import sqlite3
    import subprocess
    import sys
    from mitmproxy import http, connection
    from mitmproxy.io import FlowWriter

    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    real_run = subprocess.run
    with monkeypatch.context() as fake:
        fake.setattr(m.subprocess, 'run', lambda *a, **kw: argparse.Namespace(returncode=0))
        row, _ = m.start_proxy(m.db(), args())
    flow = Path(row['flow_path'])
    def write_request(path, url):
        record = http.HTTPFlow(connection.Client(peername=('127.0.0.1', 1234), sockname=('127.0.0.1', 8080), timestamp_start=1), connection.Server(address=('example.test', 80)))
        record.request = http.Request.make('GET', url)
        with path.open('wb') as handle:
            FlowWriter(handle).add(record)
    write_request(flow, 'http://example.test/original')
    def dispatch(cmd, **kw):
        if 'index-lane' not in cmd:
            return real_run(cmd, **kw)
        saved = flow.with_name('saved')
        flow.rename(saved)
        write_request(flow, 'http://example.test/wrong')
        try:
            return real_run(cmd, **kw)
        finally:
            flow.unlink()
            saved.rename(flow)
    monkeypatch.setattr(m.subprocess, 'run', dispatch)
    monkeypatch.setattr(m, 'mitm_runtime', lambda: ('/fixture/mitmdump', sys.executable))
    with pytest.raises(SystemExit) as out:
        m.finish_proxy(args())
    assert out.value.code == 0
    assert json.loads(capsys.readouterr().out)['indexed']
    db = Path.home() / '.local/share/ghost/proxy-store/proxy_store.sqlite'
    assert db.is_relative_to(tmp_path)
    with sqlite3.connect(db) as conn:
        paths = conn.execute('select path, raw_flow_file from requests').fetchall()
        lane_file = conn.execute('select flow_file from lanes').fetchone()[0]
    assert paths == [('/original', str(flow))]
    assert lane_file == str(flow)


def test_preallocation_failure_does_not_strand_pending(monkeypatch, tmp_path):
    m, _, _ = setup(monkeypatch, tmp_path)
    monkeypatch.setattr(m, '_capture_local_private_path', lambda _: False)
    with pytest.raises(m.ProxyStartupError):
        m.start_proxy(m.db(), args())
    assert m.proxy_row(m.db(), args()) is None


def test_interrupted_before_allocation_can_recover(monkeypatch, tmp_path, capsys):
    m, _, _ = setup(monkeypatch, tmp_path)
    original = m._capture_local_private_path
    def interrupt(_):
        raise KeyboardInterrupt()
    monkeypatch.setattr(m, '_capture_local_private_path', interrupt)
    with pytest.raises(KeyboardInterrupt):
        m.start_proxy(m.db(), args())
    monkeypatch.setattr(m, '_capture_local_private_path', original)
    row = m.proxy_row(m.db(), args())
    assert row['capture_identity'] == 'allocation-not-started'
    with pytest.raises(SystemExit) as out:
        m.finish_proxy(args(), recovery=True)
    assert out.value.code == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'aborted'
    assert m.proxy_row(m.db(), args()) is None


def test_interrupted_during_mount_inspection_is_not_allocation_pending(monkeypatch, tmp_path):
    m, profiles, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    monkeypatch.setattr(profiles, 'default_mount_available', lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        m.start_proxy(m.db(), args())
    assert m.proxy_row(m.db(), args())['capture_identity'] == 'allocation-not-started'


def test_replacement_after_final_verifier_retains_reservation(monkeypatch, tmp_path, capsys):
    m, _, mount = setup(monkeypatch, tmp_path)
    (mount / 'Example Program').mkdir()
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: argparse.Namespace(returncode=0))
    row, _ = m.start_proxy(m.db(), args())
    flow = Path(row['flow_path'])
    real_verify = m.verify_task_capture
    calls = []
    def verify(row):
        real_verify(row)
        calls.append(None)
        if len(calls) == 2:
            flow.rename(flow.with_name('saved'))
    monkeypatch.setattr(m, 'verify_task_capture', verify)
    with pytest.raises(SystemExit) as out:
        m.finish_proxy(args())
    assert out.value.code == 2
    assert json.loads(capsys.readouterr().out)['reservation'] == 'retained'
    assert m.proxy_row(m.db(), args()) is not None
