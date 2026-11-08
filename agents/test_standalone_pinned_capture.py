from pathlib import Path
import argparse
import subprocess
import sys
from agents.test_standalone_exact_mount import setup, args


def test_child_opens_reserved_inode_even_when_path_replaced(monkeypatch, tmp_path):
    m, root = setup(monkeypatch, tmp_path)
    (root / 'Exact Name/web').mkdir(parents=True)
    seen = []
    def child(command, **kwargs):
        state = m.read_state(tmp_path / 'state', 'lane')
        path = Path(state['flow_file'])
        original = path.with_suffix('.original')
        path.rename(original)
        path.write_bytes(b'replacement')
        assert command[-1].startswith('/proc/self/fd/')
        assert int(command[-1].rsplit('/', 1)[1]) in kwargs['pass_fds']
        Path(command[-1]).write_bytes(b'captured')
        seen.append((original.read_bytes(), path.read_bytes()))
        return argparse.Namespace(pid=123)
    monkeypatch.setattr(m.subprocess, 'Popen', child)
    m.start_lane(args(tmp_path))
    assert seen == [(b'captured', b'replacement')]


def test_real_child_inherits_pinned_descriptor(monkeypatch, tmp_path):
    real_popen = subprocess.Popen
    m, root = setup(monkeypatch, tmp_path)
    (root / 'Exact Name/web').mkdir(parents=True)
    def child(command, **kwargs):
        proc = real_popen([sys.executable, '-c',
                           'import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b"child-flow")',
                           command[-1]], pass_fds=kwargs['pass_fds'])
        assert proc.wait(timeout=5) == 0
        return argparse.Namespace(pid=123)
    monkeypatch.setattr(m.subprocess, 'Popen', child)
    state = m.start_lane(args(tmp_path))
    assert Path(state['flow_file']).read_bytes() == b'child-flow'


def test_real_mitmproxy_save_addon_opens_inherited_descriptor(monkeypatch, tmp_path):
    from mitmproxy.io import FlowReader
    real_popen = subprocess.Popen
    m, root = setup(monkeypatch, tmp_path)
    (root / 'Exact Name/web').mkdir(parents=True)
    code = '''
import sys
from types import SimpleNamespace
from mitmproxy import connection, http
from mitmproxy.addons import save
save.ctx.options = SimpleNamespace(save_stream_file=sys.argv[1])
s = save.Save()
s.maybe_rotate_to_new_file()
f = http.HTTPFlow(connection.Client(peername=('127.0.0.1', 1), sockname=('127.0.0.1', 2), timestamp_start=1), connection.Server(address=('example.test', 80)))
f.request = http.Request.make('GET', 'http://example.test/offline')
s.save_flow(f)
s.done()
'''
    def child(command, **kwargs):
        proc = real_popen([sys.executable, '-c', code, command[-1]], pass_fds=kwargs['pass_fds'])
        assert proc.wait(timeout=15) == 0
        return argparse.Namespace(pid=123)
    monkeypatch.setattr(m.subprocess, 'Popen', child)
    state = m.start_lane(args(tmp_path))
    with Path(state['flow_file']).open('rb') as handle:
        flows = list(FlowReader(handle).stream())
    assert len(flows) == 1 and flows[0].request.path == '/offline'


def test_changed_mount_id_fails_before_launch(monkeypatch, tmp_path):
    m, root = setup(monkeypatch, tmp_path)
    (root / 'Exact Name/web').mkdir(parents=True)
    observed = iter((1, 2))
    monkeypatch.setattr(m, '_mount_id', lambda fd: next(observed))
    monkeypatch.setattr(m.subprocess, 'Popen', lambda *a, **kw: (_ for _ in ()).throw(AssertionError('launched')))
    result = m.start_lane(args(tmp_path))
    assert result['status'] == 'capture-unavailable'
