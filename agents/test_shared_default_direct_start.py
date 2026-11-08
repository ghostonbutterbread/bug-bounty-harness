"""Direct CLI starts against synthetic supervisor/proc; launcher fences all TCP/exec."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import time
import subprocess
import sys

import pytest

from agents.test_shared_default_absence import TCP_HEADER, TCP6_HEADER

SCRIPT = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/mitm_lane.py'
# Child calls the real parser and main, with only OS-facing evidence synthetic.
CHILD = r'''
import hashlib, importlib.util, io, json, os, ssl, subprocess, sys, time
from pathlib import Path
s = importlib.util.spec_from_file_location('lane', sys.argv.pop(1))
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
base = Path(os.environ['CASE'])
m.DEFAULT_ROOT = base / 'lanes'; m.PROC_ROOT = base / 'proc'; m.CGROUP_ROOT = base / 'cgroups'
m.can_bind_localhost = lambda port: True
m.wait_for_port = lambda *a: True
m.wait_for_ca = lambda *a: True
def fingerprint(path):
    if os.environ.get('BAD_CA'): return None
    if os.environ.get('REAL_DIGEST'):
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(path.read_text())).hexdigest()
    return 'a' * 64
m.signer_fingerprint = fingerprint
def which(name):
    if name == os.environ.get('MISSING'): return None
    if name == 'mitmdump': return os.environ.get('SELECTED', '/usr/bin/mitmdump')
    if name.startswith('/'): return name
    return '/fixture/' + name
m.shutil.which = which
original_open = Path.open
def fixture_open(path, *a, **kw):
    if str(path) == '/usr/bin/mitmdump':
        if os.environ.get('UNREADABLE_RUNTIME'): raise PermissionError('private runtime path')
        return io.BytesIO(os.environ.get('SHEBANG', '#!/usr/bin/python3').encode() + b'\n')
    return original_open(path, *a, **kw)
Path.open = fixture_open
original_flock = m.fcntl.flock
def flock(fd, operation):
    if operation == m.fcntl.LOCK_EX:
        (base / 'waiting').touch()
    return original_flock(fd, operation)
m.fcntl.flock = flock
original_read_text = Path.read_text
def read_text(path, *a, **kw):
    if os.environ.get('DENIED') and path == m.PROC_ROOT / 'net/tcp6':
        raise PermissionError('private fixture error')
    return original_read_text(path, *a, **kw)
Path.read_text = read_text
uid = os.getuid()
def command(cmd, env):
    with (base / 'calls').open('a') as f: f.write(json.dumps(cmd) + '\n')
    if cmd[0] == 'loginctl':
        return subprocess.CompletedProcess(cmd, 1 if os.environ.get('LINGER_FAIL') else 0, 'yes\n', '')
    if os.environ.get('MANAGER_FAIL') and cmd[0] == 'systemctl':
        return subprocess.CompletedProcess(cmd, 1, '', 'private supervisor error')
    if cmd[0] == 'systemd-run':
        if os.environ.get('CONTINUITY'):
            unit = next(x.split('=', 1)[1] for x in cmd if x.startswith('--unit='))
            argv = cmd[cmd.index('--') + 1:]
            group = f'/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/{unit}'
            proc = m.PROC_ROOT / '4321'
            for part in ('fd', 'net', 'ns'): (proc / part).mkdir(parents=True)
            (proc / 'ns/net').symlink_to('net:[1234]')
            (proc / 'exe').symlink_to('/usr/bin/python3')
            (proc / 'stat').write_text('4321 (mitmdump) S ' + '0 ' * 18 + '555 0\n')
            (proc / 'cgroup').write_text('0::' + group + '\n')
            (proc / 'cmdline').write_bytes(b'\0'.join(x.encode() for x in ['/usr/bin/python3', *argv]) + b'\0')
            address = '00000000' if argv[argv.index('--listen-host') + 1] == '0.0.0.0' else '0100007F'
            (proc / 'net/tcp').write_text('header\n 0: ' + address + ':1F90 00000000:0000 0A 0:0 0:0 0 1000 0 9001\n')
            (proc / 'net/tcp6').write_text('header\n')
            (proc / 'fd/6').symlink_to(argv[-1])
            (proc / 'fd/7').symlink_to('socket:[9002]' if os.environ.get('COMPETING') else 'socket:[9001]')
            (base / 'runtime.json').write_text(json.dumps({'unit': unit, 'group': group, 'argv': argv}))
        time.sleep(.15)
        return subprocess.CompletedProcess(cmd, 1 if os.environ.get('LOST') else 0, '', '')
    if 'list-units' in cmd: return subprocess.CompletedProcess(cmd, 0, '', '')
    unit = cmd[cmd.index('show') + 1]
    if unit == 'init.scope':
        value = f'Id=init.scope\nLoadState=loaded\nActiveState=active\nSubState=running\nControlGroup=/user.slice/user-{uid}.slice/user@{uid}.service/init.scope\n'
    elif '--all' in cmd:
        active = (os.environ.get('ACTIVE') == '1' or (base / 'active').exists()) and unit == m.LEGACY_UNIT
        value = f'Id={unit}\nLoadState={"loaded" if active else "not-found"}\nActiveState={"active" if active else "inactive"}\nSubState={"running" if active else "dead"}\nMainPID={"7" if active else "0"}\nControlGroup=\nSlice={"app.slice" if active else ""}\n'
    elif os.environ.get('CONTINUITY') and (base / 'runtime.json').exists():
        runtime = json.loads((base / 'runtime.json').read_text())
        assert unit == runtime['unit']
        value = (f'Id={unit}\nActiveState=active\nSubState=running\nMainPID=4321\n'
                 f'ControlGroup={runtime["group"]}\nInvocationID={"1" * 32}\n'
                 f'ExecStart={{ path=/usr/bin/mitmdump ; argv[]={" ".join(runtime["argv"])} ; }}\n')
    else:
        value = 'ActiveState=active\nMainPID=4321\nControlGroup=/user.slice/fixture\n'
    return subprocess.CompletedProcess(cmd, 0, value, '')
m.unit_command = command
if os.environ.get('OP') == 'attest-default':
    def tls(cmd, **kwargs):
        assert cmd[:2] == ['openssl', 's_client']
        return subprocess.CompletedProcess(cmd, 0, b'Verify return code: 0 (ok)\n', b'')
    m.subprocess.run = tls
sys.argv = ['mitm_lane.py', '--json', '--lane', m.DEFAULT_SHARED_LANE, '--mitmdump', os.environ.get('REQUESTED', 'mitmdump')]
op = os.environ.get('OP', 'start')
sys.argv += [op] + (['--port', '8080', '--listen-host', os.environ.get('LISTEN', '127.0.0.1')] if op == 'start' else [])
if op == 'start': sys.argv += json.loads(os.environ.get('EXTRA', '[]'))
raise SystemExit(m.main())
'''

@pytest.fixture
def case(tmp_path):
    assert os.environ.get('SHARED_DEFAULT_KERNEL_FENCE') == '1'
    root = tmp_path / 'lanes'
    lane = root / 'hoster-default-8080'
    (lane / 'mitmproxy').mkdir(parents=True)
    (lane / 'flows.mitm').write_bytes(b'old flow')
    (lane / 'mitmproxy/mitmproxy-ca.pem').write_bytes(b'old signer')
    proc = tmp_path / 'proc'
    (proc / 'net').mkdir(parents=True)
    (proc / 'net/tcp').write_text(TCP_HEADER)
    (proc / 'net/tcp6').write_text(TCP6_HEADER)
    for n in ('self', '42'):
        (proc / n / 'ns').mkdir(parents=True)
        (proc / n / 'ns/net').symlink_to('net:[1234]')
    uid = os.getuid()
    group = f'/user.slice/user-{uid}.slice/user@{uid}.service'
    (proc / '42/cgroup').write_text('0::' + group + '/init.scope\n')
    manager = tmp_path / 'cgroups' / group.lstrip('/')
    (manager / 'app.slice').mkdir(parents=True)
    (manager / 'init.scope').mkdir()
    (manager / 'init.scope/cgroup.procs').write_text('42\n')
    return tmp_path, lane

def launch(case, **extra):
    base, _ = case
    env = dict(os.environ, CASE=str(base), **extra)
    return subprocess.Popen([sys.executable, '-c', CHILD, str(SCRIPT)], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def finish(p):
    out, err = p.communicate(timeout=20)
    assert not err
    return p.returncode, json.loads(out)

def calls(case):
    path = case[0] / 'calls'
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

def assert_history(lane):
    assert (lane / 'flows.mitm').read_bytes() == b'old flow'
    assert (lane / 'mitmproxy/mitmproxy-ca.pem').read_bytes() == b'old signer'

def test_active_legacy_with_stopped_record_refuses_without_mutation(case):
    _, lane = case
    raw = b'{"status":"stopped","port":8080}\n'
    (lane / 'state.json').write_bytes(raw)
    rc, body = finish(launch(case, ACTIVE='1'))
    assert rc != 0 and body['status'] == 'unknown-state'
    assert (lane / 'state.json').read_bytes() == raw
    assert not any(c[0] == 'systemd-run' or 'stop' in c for c in calls(case))
    assert not list(lane.glob('flows-*.mitm'))
    assert_history(lane)

@pytest.mark.parametrize('stopped', [False, True])
def test_clean_start_dispatches_once_with_fresh_generation(case, stopped):
    _, lane = case
    if stopped:
        (lane / 'state.json').write_text('{"status":"stopped","port":8080}')
    rc, body = finish(launch(case, CONTINUITY='1'))
    assert rc == 0 and body['status'] == 'running'
    assert len([c for c in calls(case) if c[0] == 'systemd-run']) == 1
    assert body['unit'].startswith('ghost-mitm-default-8080-')
    assert Path(body['flow_file']).name.startswith('flows-')
    assert_history(lane)

def test_competing_listener_after_submission_is_uncertain_and_retained(case):
    _, lane = case
    rc, body = finish(launch(case, CONTINUITY='1', COMPETING='1'))
    assert rc == 2 and body['status'] == 'start-outcome-unknown'
    state = json.loads((lane / 'state.json').read_text())
    assert state['status'] == 'starting' and state['unit'] == body['unit']
    assert Path(state['flow_file']).exists()
    assert len([c for c in calls(case) if c[0] == 'systemd-run']) == 1
    assert not any('stop' in c for c in calls(case))
    assert_history(lane)

@pytest.mark.parametrize('kind', ['running', 'malformed', 'missing-proc', 'denied'])
def test_unknown_never_dispatches_or_changes_state(case, kind):
    base, lane = case
    raw = {'running': b'{"status":"running","pid":2147483647,"port":8080,"listen_host":"0.0.0.0","ca_cert":"x"}',
           'malformed': b'{private broken', 'missing-proc': b'{"status":"stopped"}',
           'denied': b'{"status":"stopped"}'}[kind]
    (lane / 'state.json').write_bytes(raw)
    if kind == 'missing-proc': (base / 'proc/net/tcp6').unlink()
    flags = {'DENIED': '1'} if kind == 'denied' else ({'ACTIVE': '1'} if kind == 'running' else {})
    rc, body = finish(launch(case, **flags))
    assert rc != 0 and body['status'] in ('unknown-state', 'corrupt-state')
    assert (lane / 'state.json').read_bytes() == raw
    assert not any(c[0] == 'systemd-run' or 'stop' in c for c in calls(case))
    assert not list(lane.glob('flows-*.mitm'))
    assert_history(lane)

@pytest.mark.parametrize('dependency', ['systemd-run', 'mitmdump', 'openssl'])
def test_missing_dependencies_do_not_reserve_or_change_state(case, dependency):
    _, lane = case
    raw = b'{"status":"stopped"}\n'
    (lane / 'state.json').write_bytes(raw)
    rc, body = finish(launch(case, MISSING=dependency))
    assert rc != 0 and body['status'] in ('supervisor-unavailable', 'start-failed')
    assert (lane / 'state.json').read_bytes() == raw
    assert not list(lane.glob('flows-*.mitm'))
    assert not any(c[0] == 'systemd-run' or 'stop' in c for c in calls(case))
    assert_history(lane)

@pytest.mark.parametrize('flags', [
    {'REQUESTED': '/opt/custom/mitmdump'},
    {'SELECTED': '/opt/custom/mitmdump'},
    {'SHEBANG': '#!/opt/python/bin/python3'},
    {'UNREADABLE_RUNTIME': '1'},
])
def test_incompatible_executable_refused_before_mutation(case, flags):
    _, lane = case
    raw = b'{"status":"stopped"}\n'
    (lane / 'state.json').write_bytes(raw)
    rc, body = finish(launch(case, **flags))
    assert rc == 2 and body['status'] == 'unsupported-runtime'
    assert '/usr/bin/mitmdump' in body['detail'] and '/usr/bin/python3' in body['detail']
    assert 'private runtime path' not in json.dumps(body)
    assert (lane / 'state.json').read_bytes() == raw
    assert not list(lane.glob('flows-*.mitm'))
    assert not any(c[0] == 'systemd-run' or 'stop' in c for c in calls(case))
    assert_history(lane)


@pytest.mark.parametrize('requested', ['mitmdump', '/usr/bin/mitmdump'])
def test_public_direct_start_observe_and_attest_same_generation(case, requested):
    base, lane = case
    ca = lane / 'mitmproxy/mitmproxy-ca-cert.pem'
    ca.write_bytes((SCRIPT.parents[3] / 'agents/fixtures/shared_default_supervision/a.crt').read_bytes())
    rc, started = finish(launch(case, CONTINUITY='1', REQUESTED=requested))
    assert rc == 0 and started['status'] == 'running'
    runtime = json.loads((base / 'runtime.json').read_text())
    assert runtime['unit'] == started['unit'] and runtime['argv'] == started['command']
    assert runtime['group'].endswith('/app.slice/' + started['unit'])
    assert runtime['argv'][0] == '/usr/bin/mitmdump'
    state = (lane / 'state.json').read_bytes()
    rc, observed = finish(launch(case, CONTINUITY='1', OP='observe-default'))
    assert rc == 0 and observed['status'] == 'observed-fresh'
    assert observed['unit'] == started['unit'] and observed['pid'] == started['pid']
    rc, attested = finish(launch(case, CONTINUITY='1', OP='attest-default'))
    assert rc == 0 and attested['status'] == 'attested'
    flow = Path(started['flow_file'])
    st = flow.stat()
    identity = (started['unit'], '127.0.0.1', str(flow),
                (4321, 555, '1' * 32, runtime['group'], 'net:[1234]', (9001,), (st.st_dev, st.st_ino)))
    expected_token = hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()
    assert attested['observation'] == 'observed-fresh' and attested['generation_sha256'] == expected_token
    assert (lane / 'state.json').read_bytes() == state
    assert len([c for c in calls(case) if c[0] == 'systemd-run']) == 1
    assert_history(lane)


@pytest.mark.parametrize('stopped', [False, True])
def test_public_wrapper_runs_real_direct_children_through_attestation(case, monkeypatch, capsys, stopped):
    from agents.test_shared_default_supervision import load
    from agents.test_shared_default_ca_readiness import wrapper_args
    base, lane = case
    ca = lane / 'mitmproxy/mitmproxy-ca-cert.pem'
    ca.write_bytes((SCRIPT.parents[3] / 'agents/fixtures/shared_default_supervision/a.crt').read_bytes())
    if stopped:
        (lane / 'state.json').write_text('{"status":"stopped","port":8080}')
    w = load('hoster_mitm_lane')
    seen = []
    def dispatch(_, argv):
        op = next(x for x in ('observe-default', 'classify-default-absence', 'start', 'attest-default') if x in argv)
        seen.append(op)
        rc, result = finish(launch(case, CONTINUITY='1', REAL_DIGEST='1', LISTEN='0.0.0.0', OP=op))
        if rc != 0:
            return {'status': 'local-failed', 'local_returncode': rc, 'remote_status': result.get('status')}
        return {**result, 'local_returncode': rc}
    monkeypatch.setattr(w, 'run_remote', dispatch)
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: True)
    args = wrapper_args(base / 'client')
    args.json = True
    args.func = w.ensure_default
    monkeypatch.setattr(w, 'parse_args', lambda: args)
    assert w.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'running'
    assert Path(result['local_ca_cert']).read_bytes() == ca.read_bytes()
    assert seen == ['observe-default', 'classify-default-absence', 'start', 'observe-default', 'attest-default', 'attest-default']
    assert len([c for c in calls(case) if c[0] == 'systemd-run']) == 1
    assert_history(lane)


@pytest.mark.parametrize('empty_values', [False, True])
def test_wrapper_cli_metadata_reaches_real_state_and_index(case, monkeypatch, capsys, empty_values):
    import sqlite3
    import types
    from agents.test_shared_default_supervision import load
    base, lane = case
    ca = lane / 'mitmproxy/mitmproxy-ca-cert.pem'
    ca.write_bytes((SCRIPT.parents[3] / 'agents/fixtures/shared_default_supervision/a.crt').read_bytes())
    values = {'program': 'program demo', 'task': 'task;demo', 'agent_id': 'agent demo',
              'run_id': 'run-1', 'account_label': 'account demo', 'runtime_host': 'host demo',
              'transport': 'tool', 'session_source': 'synthetic session'}
    if empty_values:
        values = dict.fromkeys(values, '')
    w = load('hoster_mitm_lane')
    def dispatch(_, argv):
        op = next(x for x in ('observe-default', 'classify-default-absence', 'start', 'attest-default') if x in argv)
        extra = [x for x in argv if any(x.startswith('--' + key.replace('_', '-') + '=') for key in values)]
        rc, result = finish(launch(case, CONTINUITY='1', REAL_DIGEST='1', LISTEN='0.0.0.0', OP=op, EXTRA=json.dumps(extra)))
        if rc:
            return {'status': 'local-failed', 'local_returncode': rc, 'remote_status': result.get('status')}
        return {**result, 'local_returncode': rc}
    monkeypatch.setattr(w, 'run_remote', dispatch)
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: True)
    options = [f'--{key.replace("_", "-")}={value}' for key, value in values.items()]
    monkeypatch.setattr(sys, 'argv', ['hoster_mitm_lane.py', '--json', 'ensure-default', *options])
    assert w.main() == 0
    output = capsys.readouterr().out
    assert json.loads(output)['status'] == 'running'
    if not empty_values:
        assert 'account demo' not in output and 'synthetic session' not in output
    state = json.loads((lane / 'state.json').read_text())
    assert {k: state[k] for k in values} == values
    fake_io = types.ModuleType('mitmproxy.io')
    class EmptyReader:
        def __init__(self, handle): self.handle = handle
        def stream(self): return iter(())
    fake_io.FlowReader = EmptyReader
    fake_package = types.ModuleType('mitmproxy')
    fake_package.io = fake_io
    monkeypatch.setitem(sys.modules, 'mitmproxy', fake_package)
    monkeypatch.setitem(sys.modules, 'mitmproxy.io', fake_io)
    store = load('proxy_store')
    db = base / 'index.sqlite'
    monkeypatch.setattr(sys, 'argv', ['proxy_store.py', '--json', '--db', str(db), 'index-lane',
                                    '--lane', 'hoster-default-8080', '--lane-root', str(base / 'lanes')])
    assert store.main() == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'indexed'
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute('SELECT * FROM lanes').fetchone()
    assert {key: row[key] for key in values} == values
    assert_history(lane)


def test_public_wrapper_retries_real_pending_child_attestation(case, monkeypatch, capsys):
    from agents.test_shared_default_supervision import load
    from agents.test_shared_default_ca_readiness import wrapper_args
    base, lane = case
    ca = lane / 'mitmproxy/mitmproxy-ca-cert.pem'
    public = (SCRIPT.parents[3] / 'agents/fixtures/shared_default_supervision/a.crt').read_bytes()
    ca.write_bytes(public)
    w = load('hoster_mitm_lane')
    seen = []
    def run(command, **kwargs):
        op = next(x for x in ('observe-default', 'classify-default-absence', 'start', 'attest-default') if x in command)
        seen.append(op)
        rc, result = finish(launch(case, CONTINUITY='1', REAL_DIGEST='1', LISTEN='0.0.0.0', OP=op))
        if op == 'start':
            assert rc == 0 and result['status'] == 'running'
            ca.unlink()
        elif result.get('status') == 'ca-pending':
            assert rc == 2 and not ca.exists()
            ca.write_bytes(public)
        return subprocess.CompletedProcess(command, rc, json.dumps(result), '')
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: True)
    monkeypatch.setattr(w.subprocess, 'run', run)
    a = wrapper_args(base / 'client')
    a.json, a.func = True, w.ensure_default
    monkeypatch.setattr(w, 'parse_args', lambda: a)
    assert w.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'running'
    assert Path(result['local_ca_cert']).read_bytes() == public
    assert seen == ['observe-default', 'classify-default-absence', 'start', 'observe-default',
                    'attest-default', 'attest-default', 'attest-default']
    assert len([c for c in calls(case) if c[0] == 'systemd-run']) == 1
    assert not any('stop' in c for c in calls(case))
    assert_history(lane)


@pytest.mark.parametrize('failure', ['MANAGER_FAIL', 'LINGER_FAIL'])
def test_unavailable_user_supervisor_does_not_reserve(case, failure):
    _, lane = case
    raw = b'{"status":"stopped"}\n'
    (lane / 'state.json').write_bytes(raw)
    rc, body = finish(launch(case, **{failure: '1'}))
    assert rc != 0 and body['status'] in ('unknown-state', 'supervisor-unavailable')
    assert 'private supervisor error' not in json.dumps(body)
    assert (lane / 'state.json').read_bytes() == raw
    assert not list(lane.glob('flows-*.mitm'))
    assert not any(c[0] == 'systemd-run' for c in calls(case))
    assert_history(lane)


def test_unusable_historical_signer_is_preserved_before_dispatch(case):
    _, lane = case
    raw = b'{"status":"stopped"}\n'
    (lane / 'state.json').write_bytes(raw)
    rc, body = finish(launch(case, BAD_CA='1'))
    assert rc != 0 and body['status'] == 'start-failed'
    assert (lane / 'state.json').read_bytes() == raw
    assert not list(lane.glob('flows-*.mitm'))
    assert not any(c[0] == 'systemd-run' for c in calls(case))
    assert_history(lane)


def test_rechecks_state_after_waiting_for_lock(case):
    base, lane = case
    state = lane / 'state.json'
    state.write_bytes(b'{"status":"stopped"}')
    with (lane / '.start.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        child = launch(case)
        try:
            deadline = time.monotonic() + 5
            while not (base / 'waiting').exists() and time.monotonic() < deadline:
                time.sleep(.01)
            assert (base / 'waiting').exists()
            raw = b'{"status":"starting","unit":"pending"}'
            state.write_bytes(raw)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
        rc, body = finish(child)
    assert rc != 0 and body['status'] == 'start-cleanup-failed'
    assert state.read_bytes() == raw
    assert not any(c[0] == 'systemd-run' or 'stop' in c for c in calls(case))
    assert_history(lane)


def test_rechecks_supervisor_after_waiting_for_lock(case):
    base, lane = case
    raw = b'{"status":"stopped"}\n'
    (lane / 'state.json').write_bytes(raw)
    with (lane / '.start.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        child = launch(case)
        try:
            deadline = time.monotonic() + 5
            while not (base / 'waiting').exists() and time.monotonic() < deadline:
                time.sleep(.01)
            assert (base / 'waiting').exists()
            (base / 'active').touch()
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
        rc, body = finish(child)
    assert rc != 0 and body['status'] == 'unknown-state'
    assert (lane / 'state.json').read_bytes() == raw
    assert not any(c[0] == 'systemd-run' or 'stop' in c for c in calls(case))
    assert not list(lane.glob('flows-*.mitm'))
    assert_history(lane)


def test_sequential_retry_after_unknown_never_redispatches(case):
    first = finish(launch(case, LOST='1'))
    saved = (case[1] / 'state.json').read_bytes()
    second = finish(launch(case, LOST='1'))
    assert first[0] != 0 and first[1]['status'] == 'start-outcome-unknown'
    assert second[0] != 0 and second[1]['status'] == 'start-cleanup-failed'
    assert (case[1] / 'state.json').read_bytes() == saved
    assert len([c for c in calls(case) if c[0] == 'systemd-run']) == 1
    assert not any('stop' in c for c in calls(case))
    assert_history(case[1])


def test_concurrent_starts_dispatch_at_most_once(case):
    first, second = launch(case, LOST='1'), launch(case, LOST='1')
    results = [finish(first), finish(second)]
    assert all(rc != 0 for rc, _ in results)
    assert {body['status'] for _, body in results} == {'start-outcome-unknown', 'start-cleanup-failed'}
    assert len([c for c in calls(case) if c[0] == 'systemd-run']) == 1
    assert_history(case[1])
