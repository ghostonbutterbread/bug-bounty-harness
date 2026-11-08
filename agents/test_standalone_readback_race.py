import argparse
import fcntl
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from agents.test_standalone_index_review import flow, ix, load, setup_lane


def test_index_reads_verified_capture_not_substituted_path(monkeypatch, tmp_path):
    real_popen, real_run = subprocess.Popen, subprocess.run
    m, args = setup_lane(monkeypatch, tmp_path)
    (tmp_path / 'private').mkdir(mode=0o700)
    state = m.start_lane(args)
    original = Path(state['flow_file'])
    flow(original)
    replacement = tmp_path / 'replacement.mitm'
    flow(replacement)
    from mitmproxy.io import FlowReader, FlowWriter
    with replacement.open('rb') as h:
        item = next(FlowReader(h).stream())
    item.request.path = '/substituted'
    with replacement.open('wb') as h:
        FlowWriter(h).add(item)
    monkeypatch.setattr(m.subprocess, 'Popen', real_popen)
    def swap_then_run(command, **kwargs):
        fd, = kwargs['pass_fds']
        assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        assert fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        original.rename(original.with_suffix('.saved'))
        replacement.rename(original)
        return real_run(command, **kwargs)
    monkeypatch.setattr(m.subprocess, 'run', swap_then_run)
    result = m.index_store(ix(args, tmp_path))
    assert result['status'] == 'indexed', result
    with sqlite3.connect(ix(args, tmp_path).db) as db:
        rows = db.execute('select path,raw_flow_file from requests').fetchall()
        lane_path = db.execute('select flow_file from lanes').fetchone()[0]
    assert rows == [('/owned-fixture', str(original))]
    assert lane_path == str(original)
    assert result['flow_file'] == str(original)
    store = load('proxy_store')
    query = argparse.Namespace(db=ix(args, tmp_path).db, program=None, lane=args.lane,
                               run_id=None, agent_id=None, account_label=None, host=None,
                               method=None, path=None, param=None, no_background=False, limit=25)
    found = store.query_requests(query)
    assert found['count'] == 1
    output = tmp_path / 'packet.json'
    exported = store.export_request_packet(argparse.Namespace(db=query.db, id=found['rows'][0]['id'],
                                            flow_uid=None, output=str(output), allow_sensitive_stdout=False))
    assert exported['status'] == 'capture-unavailable'
    assert not output.exists()
    original.unlink()
    original.with_suffix('.saved').rename(original)
    exported = store.export_request_packet(argparse.Namespace(db=query.db, id=found['rows'][0]['id'],
                                            flow_uid=None, output=str(output), allow_sensitive_stdout=False))
    assert exported['status'] == 'exported'
    assert '/owned-fixture' in output.read_text()
    assert '/substituted' not in output.read_text()


def test_replay_consumer_reads_verified_capture_not_substituted_path(monkeypatch, tmp_path):
    real_popen, real_run = subprocess.Popen, subprocess.run
    m, args = setup_lane(monkeypatch, tmp_path)
    state = m.start_lane(args)
    original = Path(state['flow_file'])
    flow(original)
    monkeypatch.setattr(m.subprocess, 'Popen', real_popen)
    observed = []
    def swap_then_run(command, **kwargs):
        original.rename(original.with_suffix('.saved'))
        original.write_bytes(b'substituted')
        selected = command[command.index('-C') + 1]
        # This is the same adapter used by the local clientplayback addon.
        code = 'from mitmproxy.io import read_flows_from_paths; import sys; print(read_flows_from_paths([sys.argv[1]])[0].request.path)'
        proc = real_run([sys.executable, '-c', code, selected],
                        pass_fds=kwargs.get('pass_fds', ()), capture_output=True, text=True, check=False)
        observed.append(proc.stdout.strip())
        return proc
    monkeypatch.setattr(m.subprocess, 'run', swap_then_run)
    result = m.replay_flows(argparse.Namespace(root=args.root, lane=args.lane, flow_file=None, mitmdump='fixture', timeout=5))
    assert result['status'] == 'replayed', result
    assert result['flow_file'] == str(original)
    assert observed == ['/owned-fixture']


@pytest.mark.parametrize('operation', ['index', 'replay'])
@pytest.mark.parametrize('change', ['replace', 'remove'])
def test_missing_or_replaced_after_verification_is_rejected(monkeypatch, tmp_path, operation, change):
    m, args = setup_lane(monkeypatch, tmp_path)
    state = m.start_lane(args)
    path = Path(state['flow_file'])
    flow(path)
    verify = m.verify_recorded_capture
    def change_after_verify(saved):
        result = verify(saved)
        assert result is None
        path.rename(path.with_suffix('.saved'))
        if change == 'replace':
            path.write_bytes(b'replacement')
        return result
    monkeypatch.setattr(m, 'verify_recorded_capture', change_after_verify)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: pytest.fail('consumer launched'))
    if operation == 'index':
        result = m.index_store(ix(args, tmp_path))
    else:
        result = m.replay_flows(argparse.Namespace(root=args.root, lane=args.lane, flow_file=None, mitmdump='fixture', timeout=5))
    assert result['status'] == 'capture-unavailable'


@pytest.mark.parametrize('operation', ['index', 'replay'])
def test_readback_fd_closed_when_child_raises(monkeypatch, tmp_path, operation):
    m, args = setup_lane(monkeypatch, tmp_path)
    state = m.start_lane(args)
    flow(Path(state['flow_file']))
    received = []
    def fail(command, **kwargs):
        received.extend(kwargs['pass_fds'])
        raise OSError('fixture failure')
    monkeypatch.setattr(m.subprocess, 'run', fail)
    with pytest.raises(OSError, match='fixture failure'):
        if operation == 'index':
            m.index_store(ix(args, tmp_path))
        else:
            m.replay_flows(argparse.Namespace(root=args.root, lane=args.lane, flow_file=None, mitmdump='fixture', timeout=5))
    assert len(received) == 1
    with pytest.raises(OSError):
        os.fstat(received[0])


def test_legacy_explicit_symlink_can_be_indexed(monkeypatch, tmp_path):
    real_popen = subprocess.Popen
    m, args = setup_lane(monkeypatch, tmp_path)
    (tmp_path / 'private').mkdir(mode=0o700)
    target = tmp_path / 'legacy.mitm'
    flow(target)
    link = tmp_path / 'legacy-link.mitm'
    link.symlink_to(target)
    m.write_state(Path(args.root), args.lane, {'flow_file': str(link), 'program': 'Old'})
    monkeypatch.setattr(m.subprocess, 'Popen', real_popen)
    result = m.index_store(ix(args, tmp_path, str(link)))
    assert result['status'] == 'indexed', result
    with sqlite3.connect(ix(args, tmp_path).db) as db:
        assert db.execute('select path from requests').fetchone() == ('/owned-fixture',)
        request_id = db.execute('select id from requests').fetchone()[0]
    result = load('proxy_store').export_request_packet(argparse.Namespace(
        db=ix(args, tmp_path).db, id=request_id, flow_uid=None,
        output=str(tmp_path / 'legacy-packet.json'), allow_sensitive_stdout=False))
    assert result['status'] == 'exported'
