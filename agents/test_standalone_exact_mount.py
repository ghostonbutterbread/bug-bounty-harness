from __future__ import annotations

import argparse
import importlib.util
import json
import sqlite3
from pathlib import Path
import subprocess
import sys

import pytest


def load(name):
    path = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def args(tmp, program='Exact Name'):
    return argparse.Namespace(root=str(tmp / 'state'), lane='lane', port=8081, mitmdump='fake',
        listen_host='127.0.0.1', proxy_host='127.0.0.1', program=program, task='fixture',
        account=None, account_label=None, profile_dir=None, run_id='run', agent_id='agent',
        runtime_host='fixture', transport='browser', browser_profile_id=None, session_source=None)


def setup(monkeypatch, tmp_path):
    m = load('mitm_lane')
    root = tmp_path / 'mount'
    root.mkdir()
    monkeypatch.setenv('BOUNTY_ARTIFACT_ROOT', str(root))
    monkeypatch.setattr(m.os.path, 'ismount', lambda p: Path(p) == root)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda _: True)
    monkeypatch.setattr(m, 'pid_alive', lambda _: False)
    def launch(command, **kwargs):
        state = m.read_state(tmp_path / 'state', 'lane')
        assert command[-1].startswith('/proc/self/fd/')
        assert int(command[-1].rsplit('/', 1)[1]) in kwargs['pass_fds']
        assert state['index_lane'].startswith('capture-')
        assert Path(command[-1]).stat().st_mode & 0o777 == 0o600
        Path(command[-1]).write_bytes(b'private synthetic data')
        return argparse.Namespace(pid=123)
    monkeypatch.setattr(m.subprocess, 'Popen', launch)
    return m, root


def test_exact_mount_sticky_identity_and_receipt(monkeypatch, tmp_path):
    m, root = setup(monkeypatch, tmp_path)
    (root / 'Exact Name/web').mkdir(parents=True)
    (root / 'exact-name/web').mkdir(parents=True)
    a = args(tmp_path)
    first = m.start_lane(a)
    assert Path(first['flow_file']).is_relative_to(root / 'Exact Name/web')
    assert first['capture_mount'] == str(root)
    assert Path(first['flow_file']).parent.stat().st_mode & 0o777 == 0o700
    assert m.start_lane(a)['status'] == 'capture-recovery-required'
    assert m.stop_lane(a)['status'] == 'stopped'
    monkeypatch.setenv('BOUNTY_ARTIFACT_ROOT', str(tmp_path / 'missing'))
    second = m.start_lane(a)
    assert Path(second['flow_file']).is_relative_to(tmp_path / 'state')
    assert second['index_lane'] != first['index_lane']
    assert Path(first['flow_file']).read_bytes() == b'private synthetic data'
    receipts = list((tmp_path / 'state/lane').glob('receipt-*/state.json'))
    assert len(receipts) == 1
    assert json.loads(receipts[0].read_text())['index_lane'] == first['index_lane']


@pytest.mark.parametrize('program', [None, 'general', '../Exact Name', 'exact name', '', 'Exact/Name'])
def test_missing_invalid_or_general_is_private_local(monkeypatch, tmp_path, program):
    m, root = setup(monkeypatch, tmp_path)
    (root / 'Exact Name/web').mkdir(parents=True)
    state = m.start_lane(args(tmp_path, program))
    assert Path(state['flow_file']).is_relative_to(tmp_path / 'state')
    assert state['program'] == program
    assert state['capture_mount'] is None


def test_plain_directory_and_shared_symlink_fall_back(monkeypatch, tmp_path):
    m, root = setup(monkeypatch, tmp_path)
    (root / 'Exact Name/web').mkdir(parents=True)
    monkeypatch.setattr(m.os.path, 'ismount', lambda _: False)
    assert m.capture_destination(tmp_path / 'state', 'a', 'Exact Name')[1] is None
    monkeypatch.setattr(m.os.path, 'ismount', lambda p: Path(p) == root)
    shared = tmp_path / 'shared'
    shared.mkdir()
    monkeypatch.setenv('HARNESS_SHARED_BASE', str(shared))
    (root / 'Other').symlink_to(shared, target_is_directory=True)
    assert m.capture_destination(tmp_path / 'state', 'b', 'Other')[1] is None


def test_recorded_mount_loss_and_replacement_fail_closed(monkeypatch, tmp_path):
    m, root = setup(monkeypatch, tmp_path)
    (root / 'Exact Name/web').mkdir(parents=True)
    a = args(tmp_path)
    state = m.start_lane(a)
    monkeypatch.setattr(m.os.path, 'ismount', lambda _: False)
    assert m.verify_recorded_capture(state)['status'] == 'capture-unavailable'
    replay = argparse.Namespace(root=a.root, lane=a.lane, flow_file=None, mitmdump='fake', timeout=1)
    assert m.replay_flows(replay)['status'] == 'capture-unavailable'
    monkeypatch.setattr(m.shutil, 'which', lambda _: '/usr/bin/mitmdump')
    index = argparse.Namespace(root=a.root, lane=a.lane, flow_file=None, mitmdump='fake', db=str(tmp_path / 'db'), store_full_requests=True)
    assert m.index_store(index)['status'] == 'capture-unavailable'
    monkeypatch.setattr(m.os.path, 'ismount', lambda p: Path(p) == root)
    flow = Path(state['flow_file'])
    flow.rename(flow.with_suffix('.old'))
    flow.write_bytes(b'replaced')
    assert m.verify_recorded_capture(state)['status'] == 'capture-unavailable'


def test_legacy_state_uses_old_lane_and_flow(monkeypatch, tmp_path):
    m, root = setup(monkeypatch, tmp_path)
    old_flow = tmp_path / 'legacy.mitm'
    old_flow.write_bytes(b'old')
    m.write_state(tmp_path / 'state', 'lane', {'status':'stopped', 'flow_file':str(old_flow), 'program':'old'})
    exe = tmp_path / 'mitmdump'
    exe.write_text(f'#!{sys.executable}\n')
    monkeypatch.setattr(m.shutil, 'which', lambda _: str(exe))
    calls = []
    monkeypatch.setattr(m.subprocess, 'run', lambda command, **kw: calls.append(command) or subprocess.CompletedProcess(command, 0, '{"status":"indexed"}', ''))
    a = argparse.Namespace(mitmdump='fake', db=str(tmp_path / 'db'), lane='lane', root=str(tmp_path / 'state'), flow_file=None, store_full_requests=True)
    assert m.index_store(a)['status'] == 'indexed'
    assert calls[0][calls[0].index('--lane') + 1] == 'lane'
    assert calls[0][calls[0].index('--flow-file') + 1] == str(old_flow)


def test_real_index_preserves_both_generations(monkeypatch, tmp_path):
    from mitmproxy import connection, http
    from mitmproxy.io import FlowWriter
    real_popen = subprocess.Popen
    m, root = setup(monkeypatch, tmp_path)
    a = args(tmp_path)
    db_dir = tmp_path / 'private-db'
    db_dir.mkdir(mode=0o700)
    db = db_dir / 'index.sqlite'
    index_args = argparse.Namespace(root=a.root, lane=a.lane, mitmdump='/usr/bin/mitmdump',
                                    db=str(db), flow_file=None, store_full_requests=True)
    real_run = subprocess.run
    def checked_run(*args, **kwargs):
        result = real_run(*args, **kwargs)
        assert result.returncode == 0, (result.stdout, result.stderr)
        return result
    monkeypatch.setattr(m.subprocess, 'run', checked_run)
    states = []
    for number in (1, 2):
        monkeypatch.setattr(m.subprocess, 'Popen', lambda *x, **kw: argparse.Namespace(pid=123))
        state = m.start_lane(a)
        states.append(state)
        client = connection.Client(peername=('127.0.0.1', 1), sockname=('127.0.0.1', 2), timestamp_start=1)
        item = http.HTTPFlow(client, connection.Server(address=('example.test', 80)))
        item.request = http.Request.make('GET', f'http://example.test/fixture-{number}')
        with Path(state['flow_file']).open('wb') as handle:
            FlowWriter(handle).add(item)
        m.stop_lane(a)
        monkeypatch.setattr(m.subprocess, 'Popen', real_popen)
        result = m.index_store(index_args)
        assert result['status'] == 'indexed', result
        assert m.index_store(index_args)['status'] == 'indexed'
    index_args.flow_file = states[0]['flow_file']
    assert m.index_store(index_args)['status'] == 'indexed'
    index_args.flow_file = str(tmp_path / 'unknown.mitm')
    assert m.index_store(index_args)['status'] == 'capture-conflict'
    with sqlite3.connect(db) as connection_db:
        rows = connection_db.execute('select lane, path_key, raw_flow_file from requests order by path_key').fetchall()
    assert rows == [(states[i]['index_lane'], f'/fixture-{i+1}', states[i]['flow_file']) for i in range(2)]
    store = load('proxy_store')
    query = argparse.Namespace(db=str(db), program=None, lane=a.lane, run_id=None, agent_id=None,
        account_label=None, host=None, method=None, path=None, param=None, no_background=False, limit=25)
    assert store.query_requests(query)['count'] == 2
    query.lane = states[0]['index_lane']
    assert store.query_requests(query)['count'] == 1
    query.lane = states[1]['index_lane']
    assert store.query_requests(query)['count'] == 1


def test_failed_launch_keeps_generation_for_recovery(monkeypatch, tmp_path):
    m, root = setup(monkeypatch, tmp_path)
    a = args(tmp_path)
    def fail(*_args, **_kwargs):
        raise OSError('synthetic launch failure')
    monkeypatch.setattr(m.subprocess, 'Popen', fail)
    with pytest.raises(OSError, match='synthetic'):
        m.start_lane(a)
    saved = m.read_state(tmp_path / 'state', 'lane')
    assert saved['status'] == 'start-failed'
    assert Path(saved['flow_file']).exists()
    retry = m.start_lane(a)
    assert retry['status'] == 'capture-recovery-required'
    assert retry['flow_file'] == saved['flow_file']


def test_hoster_does_not_release_when_stop_unverified(monkeypatch):
    m = load('hoster_mitm_lane')
    calls = []
    monkeypatch.setattr(m, 'run_remote_legacy', lambda a, cmd: calls.append(cmd) or {'status':'stop-failed', 'alive':True})
    assert m.index_stop_release(argparse.Namespace(lane='lane'))['status'] == 'stop-failed'
    assert len(calls) == 1


def test_shared_bind_alias_must_fall_back(monkeypatch, tmp_path):
    m, mount = setup(monkeypatch, tmp_path)
    web = mount / 'Exact Name/web'
    web.mkdir(parents=True)
    shared = tmp_path / 'shared'
    shared.mkdir()
    monkeypatch.setenv('HARNESS_SHARED_BASE', str(shared))
    read_text = Path.read_text
    mountinfo = (f'1 0 8:1 / / rw - ext4 /dev/fixture rw\n'
                 f'2 1 8:1 {shared} {mount} rw - ext4 /dev/fixture rw\n')
    monkeypatch.setattr(Path, 'read_text', lambda path, *a, **kw:
                        mountinfo if str(path) == '/proc/self/mountinfo' else read_text(path, *a, **kw))
    flow, selected = m.capture_destination(tmp_path / 'state', 'lane', 'Exact Name')
    assert selected is None and not flow.is_relative_to(web)


def test_hoster_reports_index_failure(monkeypatch):
    m = load('hoster_mitm_lane')
    calls = []
    def remote(a, cmd):
        calls.append(cmd)
        return {'status': 'stopped' if 'stop' in cmd else 'capture-unavailable' if 'index-store' in cmd else 'released'}
    monkeypatch.setattr(m, 'run_remote_legacy', remote)
    a = argparse.Namespace(lane='lane', agent_id=None, run_id=None, account_label=None, runtime_host=None,
        proxy_host=None, proxy_port=None, transport=None, browser_profile_id=None, session_source=None, note=None)
    assert m.index_stop_release(a)['status'] == 'index-failed'
    assert len(calls) == 3
