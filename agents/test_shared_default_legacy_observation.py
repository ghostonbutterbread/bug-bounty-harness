"""Kernel-fenced synthetic evidence for the legacy shared listener."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from agents.test_shared_default_supervision import args, load


@pytest.fixture
def legacy(tmp_path, monkeypatch):
    m = load('mitm_lane')
    root = tmp_path / 'lanes'
    lane = root / 'hoster-default-8080'
    conf = lane / 'mitmproxy'
    conf.mkdir(parents=True)
    flow = lane / 'flows.mitm'
    flow.write_bytes(b'fixture capture')
    state = lane / 'state.json'
    original = b'{"status":"running","pid":101,"port":8080,"listen_host":"0.0.0.0","ca_cert":"fixture"}'
    state.write_bytes(original)
    proc = tmp_path / 'proc'
    p = proc / '202'
    (p / 'fd').mkdir(parents=True)
    (p / 'net').mkdir()
    (p / 'ns').mkdir()
    (proc / 'self' / 'ns').mkdir(parents=True)
    (p / 'ns/net').symlink_to('net:[42]')
    (p / 'exe').symlink_to('/usr/bin/python3')
    (proc / 'self/ns/net').symlink_to('net:[42]')
    (p / 'stat').write_text('202 (mitmdump) S ' + '0 ' * 18 + '555 0\n')
    cgroup = f'/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service/app.slice/hoster-mitm-default-8080.service'
    (p / 'cgroup').write_text('0::' + cgroup + '\n')
    argv = ['/usr/bin/python3', '/usr/bin/mitmdump', '--listen-host', '0.0.0.0', '--listen-port', '8080', '--set', f'confdir={conf}', '--set', 'flow_detail=0', '-w', str(flow)]
    (p / 'cmdline').write_bytes(b'\0'.join(x.encode() for x in argv) + b'\0')
    (p / 'net/tcp').write_text('header\n 0: 00000000:1F90 00000000:0000 0A 0:0 0:0 0 1000 0 9001\n')
    (p / 'net/tcp6').write_text('header\n')
    (p / 'fd/6').symlink_to(flow)
    (p / 'fd/7').symlink_to('socket:[9001]')
    invocation = '1' * 32
    fields = {'Id':'hoster-mitm-default-8080.service','ActiveState':'active','SubState':'running','MainPID':'202','ControlGroup':cgroup,'InvocationID':invocation,
              'ExecStart':'{ path=/usr/bin/mitmdump ; argv[]=' + ' '.join(argv[1:]) + ' ; }'}
    calls = []
    def run(cmd, env):
        calls.append(cmd)
        assert cmd[:3] == ['systemctl', '--user', 'show']
        return subprocess.CompletedProcess(cmd, 0, ''.join(f'{k}={v}\n' for k,v in fields.items()), '')
    monkeypatch.setattr(m, 'DEFAULT_ROOT', root)
    monkeypatch.setattr(m, 'PROC_ROOT', proc, raising=False)
    monkeypatch.setattr(m, 'unit_command', run)
    monkeypatch.setattr(m, 'pid_alive', lambda _: pytest.fail('recorded PID must not be probed'))
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: pytest.fail('socket operation not allowed'))
    return m, root, lane, p, state, original, fields, calls


def test_stale_state_yields_readonly_limited_observation(legacy):
    m, root, lane, p, state, original, fields, calls = legacy
    result = m.observe_default(args(root))
    assert result['status'] == 'observed-legacy'
    assert result['signer'] == 'unverified'
    assert result['pid'] == 202 and result['port'] == 8080
    assert state.read_bytes() == original and (lane / 'flows.mitm').read_bytes() == b'fixture capture'
    assert len(calls) >= 2
    assert 'PRIVATE' not in json.dumps(result)


@pytest.mark.parametrize('change', ['pid','invocation','cgroup','argv','address','socket','flow','unit','inactive','race','namespace','exe','multiple-exec'])
def test_unproven_or_changed_observation_fails_closed(legacy, monkeypatch, change):
    m, root, lane, p, state, original, fields, calls = legacy
    if change == 'pid': fields['MainPID'] = '999'
    if change == 'invocation': fields['InvocationID'] = ''
    if change == 'cgroup': fields['ControlGroup'] += '-other'
    if change == 'argv': (p / 'cmdline').write_bytes(b'/usr/bin/python3\0--secret-should-not-leak\0')
    if change == 'address': (p / 'net/tcp').write_text((p / 'net/tcp').read_text().replace('00000000:1F90','0100007F:1F90'))
    if change == 'socket': (p / 'fd/7').unlink()
    if change == 'flow': (p / 'fd/6').unlink()
    if change == 'unit': fields['Id'] = 'other.service'
    if change == 'inactive': fields['ActiveState'] = 'inactive'
    if change == 'exe':
        (p / 'exe').unlink()
        (p / 'exe').symlink_to('/usr/bin/true')
    if change == 'multiple-exec': fields['ExecStart'] += ' { path=/usr/bin/true ; argv[]=/usr/bin/true ; }'
    if change == 'namespace':
        (p / 'ns/net').unlink()
        (p / 'ns/net').symlink_to('net:[43]')
    if change == 'race':
        base = m.unit_command
        def changed(cmd, env):
            result = base(cmd, env)
            if len(calls) == 1: fields['InvocationID'] = '2' * 32
            return result
        monkeypatch.setattr(m, 'unit_command', changed)
    result = m.status_lane(args(root))
    assert result['status'] == 'unknown-state'
    assert 'secret-should-not-leak' not in json.dumps(result)
    assert state.read_bytes() == original and (lane / 'flows.mitm').read_bytes() == b'fixture capture'


@pytest.mark.parametrize('change', ['ticks', 'socket', 'flow', 'pid'])
def test_changed_generation_between_snapshots_is_unknown(legacy, monkeypatch, change):
    m, root, lane, p, state, original, fields, calls = legacy
    base = m.unit_command
    def changed(cmd, env):
        if len(calls) == 1:
            if change == 'ticks': (p / 'stat').write_text('202 (mitmdump) S ' + '0 ' * 18 + '556 0\n')
            if change == 'socket': (p / 'fd/7').unlink()
            if change == 'flow': (p / 'fd/6').unlink()
            if change == 'pid': fields['MainPID'] = '203'
        return base(cmd, env)
    monkeypatch.setattr(m, 'unit_command', changed)
    result = m.status_lane(args(root))
    assert result['status'] == 'unknown-state'
    assert state.read_bytes() == original and (lane / 'flows.mitm').read_bytes() == b'fixture capture'


def test_wrapper_status_exposes_observation_without_ready_or_ca(tmp_path, monkeypatch):
    from agents.test_shared_default_ca_readiness import wrapper_args
    w = load('hoster_mitm_lane')
    calls = []
    monkeypatch.setattr(w, 'run_remote', lambda _, cmd: calls.append(cmd) or {
        'status': 'observed-legacy', 'lane': 'hoster-default-8080', 'unit': 'hoster-mitm-default-8080.service',
        'pid': 202, 'port': 8080, 'listen_host': '0.0.0.0', 'signer': 'unverified',
        'detail': 'limited observation'})
    monkeypatch.setattr(w, 'sync_lane_ca_until_ready', lambda *_: pytest.fail('unexpected CA sync'))
    result = w.status_default(wrapper_args(tmp_path))
    assert result['status'] == 'observed-legacy' and result['signer'] == 'unverified'
    assert 'ca_sync' not in result and 'proxy_server' not in result
    assert len(calls) == 1 and calls[0][-1] == 'observe-default'
    assert not list(tmp_path.iterdir())


def test_other_root_or_lane_never_observes(legacy):
    m, root, lane, p, state, original, fields, calls = legacy
    result = m.status_lane(args(root / 'other'))
    assert result['status'] == 'not-found' and calls == []
    result = m.status_lane(args(root, lane='other'))
    assert result['status'] == 'not-found' and calls == []
