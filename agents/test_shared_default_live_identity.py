"""Offline regressions for shared 8080 identity, races and dispatch."""
import json
import io
import os
from pathlib import Path
import pwd
import subprocess
import sys

import pytest

from agents.test_shared_default_supervision import FakeSystemd, args, load
from agents.test_shared_default_ca_readiness import wrapper_args
from agents.test_shared_default_signer_dispatch import signer_fixture, certs
from agents.test_shared_default_absence import TCP_HEADER, TCP6_HEADER


def prepare_direct_preflight(m, tmp_path, monkeypatch, *, assume_observed=False):
    """Use real absence classification over synthetic proc and supervisor state."""
    proc = tmp_path / 'proc'
    (proc / 'net').mkdir(parents=True)
    (proc / 'net/tcp').write_text(TCP_HEADER)
    (proc / 'net/tcp6').write_text(TCP6_HEADER)
    uid = os.getuid()
    group = f'/user.slice/user-{uid}.slice/user@{uid}.service'
    for pid in ('self', '42'):
        (proc / pid / 'ns').mkdir(parents=True)
        (proc / pid / 'ns/net').symlink_to('net:[1234]')
    (proc / '42/cgroup').write_text('0::' + group + '/init.scope\n')
    cgroups = tmp_path / 'cgroups'
    manager = cgroups / group.lstrip('/')
    (manager / 'app.slice').mkdir(parents=True)
    (manager / 'init.scope').mkdir()
    (manager / 'init.scope/cgroup.procs').write_text('42\n')
    monkeypatch.setattr(m, 'DEFAULT_ROOT', tmp_path)
    monkeypatch.setattr(m, 'PROC_ROOT', proc)
    monkeypatch.setattr(m, 'CGROUP_ROOT', cgroups)
    original_command = m.unit_command
    calls = []
    def command(cmd, env):
        calls.append(cmd)
        if 'list-units' in cmd:
            return subprocess.CompletedProcess(cmd, 0, '', '')
        if 'show' in cmd and 'init.scope' in cmd:
            data = f'Id=init.scope\nLoadState=loaded\nActiveState=active\nSubState=running\nControlGroup={group}/init.scope\n'
            return subprocess.CompletedProcess(cmd, 0, data, '')
        if 'show' in cmd and '--all' in cmd:
            unit = cmd[cmd.index('show') + 1]
            data = f'Id={unit}\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlGroup=\nSlice=\n'
            return subprocess.CompletedProcess(cmd, 0, data, '')
        return original_command(cmd, env)
    monkeypatch.setattr(m, 'unit_command', command)
    monkeypatch.setattr(m.shutil, 'which', lambda name: '/usr/bin/mitmdump' if name == 'mitmdump' else '/fixture/' + name)
    original_open = Path.open
    def fixture_open(path, *args, **kwargs):
        if str(path) == '/usr/bin/mitmdump':
            return io.BytesIO(b'#!/usr/bin/python3\n')
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', fixture_open)
    if assume_observed:
        # These callers exercise other boundaries with a synthetic supervisor,
        # not proc ownership; the direct CLI suite tests the real observer.
        def observed(root, state):
            assert root == tmp_path and Path(state['flow_file']).is_file()
            return {'status': 'observed-fresh', 'unit': state['unit'], 'pid': state['pid']}
        monkeypatch.setattr(m, 'default_generation_observation', observed)
    return calls


def test_combined_certificate_must_have_matching_private_key(tmp_path, signer_fixture):
    m = load('mitm_lane')
    fixture, public, combined = certs(tmp_path, signer_fixture)
    combined.write_bytes(public.read_bytes())
    assert m.signer_fingerprint(public) is None
    combined.write_bytes((fixture / 'b.key').read_bytes() + public.read_bytes())
    assert m.signer_fingerprint(public) is None
    combined.write_bytes((fixture / 'a.key').read_bytes() + public.read_bytes())
    assert m.signer_fingerprint(public)


def test_new_start_never_overwrites_historical_public_ca_without_signer(tmp_path, monkeypatch, signer_fixture):
    m = load('mitm_lane')
    ca = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    original = (signer_fixture / 'a.crt').read_bytes()
    ca.write_bytes(original)
    fake = FakeSystemd()
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch)
    monkeypatch.setattr(m.subprocess, 'run', fake.run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda _: True)
    result = m.start_lane(args(tmp_path))
    assert result['status'] == 'start-failed'
    assert any(c[0] == 'loginctl' for c in calls)
    assert not any(c[0] == 'systemd-run' for c in fake.calls)
    assert ca.read_bytes() == original


def test_started_identity_detects_replaced_files(tmp_path, monkeypatch, signer_fixture):
    m = load('mitm_lane')
    actual_observer = m.default_generation_observation
    ca = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    ca.write_bytes((signer_fixture / 'a.crt').read_bytes())
    combined = ca.with_name('mitmproxy-ca.pem')
    combined.write_bytes((signer_fixture / 'a.key').read_bytes() + ca.read_bytes())
    fake = FakeSystemd()
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch, assume_observed=True)
    monkeypatch.setattr(m.subprocess, 'run', fake.run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda _: True)
    started = m.start_lane(args(tmp_path))
    assert started['status'] == 'running'
    monkeypatch.setattr(m, 'default_generation_observation', actual_observer)
    assert len([c for c in calls if c[0] == 'systemd-run']) == 1
    assert started['ca_started_sha256'] == m.signer_fingerprint(ca)
    ca.write_bytes((signer_fixture / 'b.crt').read_bytes())
    combined.write_bytes((signer_fixture / 'b.key').read_bytes() + ca.read_bytes())
    monkeypatch.setattr(m, 'pid_alive', lambda _: True)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: False)
    # The exact shared root now requires generation observation; retain the
    # original general-status identity assertion on an alternate-root view.
    assert m.status_lane(args(tmp_path))['status'] == 'unknown-state'
    monkeypatch.setattr(m, 'DEFAULT_ROOT', tmp_path / 'configured-default')
    status = m.status_lane(args(tmp_path))
    assert status['ca_identity'] == 'changed'
    assert status['ca_signer_sha256'] is None
    assert not any(c[:3] == ['systemctl', '--user', 'stop'] for c in fake.calls)
    assert 'PRIVATE KEY' not in json.dumps(status)


def test_existing_legacy_identity_explicitly_unverified(tmp_path, monkeypatch, signer_fixture):
    m = load('mitm_lane')
    _, public, _ = certs(tmp_path, signer_fixture)
    m.write_state(tmp_path, 'hoster-default-8080', {'status':'running','pid':123, 'port':8080,'listen_host':'0.0.0.0','ca_cert':str(public)})
    monkeypatch.setattr(m, 'pid_alive', lambda _: True)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: False)
    result = m.status_lane(args(tmp_path))
    assert result['ca_identity'] == 'legacy-unverified'
    assert result['ca_signer_sha256']


def test_replaced_identity_never_copies_or_stops(tmp_path, monkeypatch, signer_fixture):
    m = load('hoster_mitm_lane')
    mitm = load('mitm_lane')
    fixture, public, combined = certs(tmp_path, signer_fixture)
    old = mitm.signer_fingerprint(public)
    public.write_bytes((fixture / 'b.crt').read_bytes())
    combined.write_bytes((fixture / 'b.key').read_bytes() + public.read_bytes())
    state = {'status': 'running', 'pid': 123, 'port': 8080, 'proxy_port': 8080,
             'listen_host': '0.0.0.0', 'ca_cert': str(public), 'ca_started_sha256': old}
    mitm.write_state(tmp_path, 'hoster-default-8080', state)
    monkeypatch.setattr(mitm, 'pid_alive', lambda _: True)
    monkeypatch.setattr(mitm, 'can_bind_localhost', lambda _: False)
    assert mitm.status_lane(args(tmp_path))['ca_identity'] == 'changed'
    monkeypatch.setattr(mitm, 'DEFAULT_ROOT', tmp_path)
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: True)
    calls = []
    def remote(_, cmd):
        calls.append(cmd)
        assert cmd[-1] == 'observe-default'
        return mitm.observe_default(args(tmp_path))
    monkeypatch.setattr(m, 'run_remote', remote)
    monkeypatch.setattr(m, 'copy_remote_file', lambda *_: pytest.fail('must not copy'))
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed'
    assert result['start']['status'] == 'unknown-state'
    assert 'ca_sync' not in result
    assert all('start' not in c and 'stop' not in c for c in calls)


def test_legacy_sync_propagates_unverified_warning(tmp_path, monkeypatch, signer_fixture):
    m = load('hoster_mitm_lane')
    mitm = load('mitm_lane')
    _, public, _ = certs(tmp_path, signer_fixture)
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: True)
    monkeypatch.setattr(m, 'run_remote', lambda *_: {'status':'running', 'alive':True, 'port_open':True,
                        'ca_cert':str(public), 'ca_signer_sha256':mitm.signer_fingerprint(public),
                        'ca_identity':'legacy-unverified'})
    result = m.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert':str(public)})
    assert result['status'] == 'copied' and result['ca_identity'] == 'legacy-unverified'


def test_legacy_identity_warning_in_plain_cli(monkeypatch, capsys):
    m = load('hoster_mitm_lane')
    a = wrapper_args('/unused')
    a.json = False
    a.func = lambda _: {'status': 'running', 'proxy_server': 'http://hoster:8080',
                        'ca_sync': {'ca_identity': 'legacy-unverified'}}
    monkeypatch.setattr(m, 'parse_args', lambda: a)
    assert m.main() == 0
    assert 'legacy-unverified' in capsys.readouterr().out


def test_running_without_alive_never_starts(tmp_path, monkeypatch):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    calls = []
    def remote(_, cmd):
        calls.append(cmd)
        return {'status':'running'}
    monkeypatch.setattr(m, 'run_remote', remote)
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed'
    assert 'unknown' in result['detail'].lower()
    assert len(calls) == 1


@pytest.mark.parametrize(('alive','port_open'), [(False,True),(True,False),(None,True),(True,None)])
def test_recheck_requires_live_listener_before_ca_copy(tmp_path, monkeypatch, alive, port_open):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'run_remote', lambda *_: {'status':'running','alive':alive,'port_open':port_open,
                         'ca_cert':'/remote/ca','ca_signer_sha256':'a'*64})
    monkeypatch.setattr(m, 'copy_remote_file', lambda *_: pytest.fail('stale CA copied'))
    result = m.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert':'/remote/ca'})
    assert result['status'] == 'copy-failed'


@pytest.mark.parametrize('fd', [1, 2])
def test_systemd_invalid_output_is_sanitized(tmp_path, monkeypatch, fd):
    m = load('mitm_lane')
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    original_run = subprocess.run
    def bad(command, **kwargs):
        assert command[0] == 'loginctl'
        # Exercise decoding of the selected stream by a real isolated child;
        # it is Python, not loginctl or another service-manager executable.
        return original_run([sys.executable, '-c',
                             f'import os; os.write({fd}, bytes([255]) + b"SECRET")'], **kwargs)
    monkeypatch.setattr(m.subprocess, 'run', bad)
    result = m.start_lane(args(tmp_path))
    assert result['status'] == 'supervisor-unavailable'
    assert [c[0] for c in calls if c[0] == 'loginctl'] == ['loginctl']
    assert not any(c[0] == 'systemd-run' for c in calls)
    assert 'SECRET' not in json.dumps(result)


@pytest.mark.parametrize('which', ['stdout','stderr'])
def test_non_utf8_dispatch_is_structured_and_never_starts(tmp_path, monkeypatch, which):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    calls = []
    def fail(*a, **kw):
        calls.append(a)
        raise UnicodeDecodeError('utf-8', b'\xffSECRET', 0, 1, which)
    monkeypatch.setattr(m.subprocess, 'run', fail)
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and len(calls) == 1
    assert 'SECRET' not in json.dumps(result)


@pytest.mark.parametrize('fd', [1, 2])
def test_real_non_utf8_subprocess_output(tmp_path, monkeypatch, fd):
    m = load('hoster_mitm_lane')
    original = subprocess.run
    calls = []
    def synthetic(cmd, **kw):
        calls.append(cmd)
        return original([sys.executable, '-c', f'import os; os.write({fd}, bytes([255]))'], **kw)
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(m.subprocess, 'run', synthetic)
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and len(calls) == 1
    assert result['start']['status'] == 'unknown-state'


def test_local_dispatch_requires_exact_host_and_effective_user(tmp_path, monkeypatch):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m.socket, 'gethostname', lambda: 'hoster')
    monkeypatch.setattr(m.socket, 'getfqdn', lambda: 'hoster.example.test')
    user = pwd.getpwuid(os.geteuid()).pw_name
    for host in ('hoster', 'hoster.example.test', 'localhost'):
        assert m.running_on_requested_hoster(wrapper_args(tmp_path, ssh_host=host, ssh_user=user))
    for host, name in [('hoster.evil.test', user), ('hoster.example.test', user+'-other')]:
        a = wrapper_args(tmp_path, ssh_host=host, ssh_user=name)
        a.dry_run = True
        result = m.run_remote(a, ['bbh', 'status'])
        assert result['ssh_command'][0] == 'ssh'
        assert f'{name}@{host}' in result['ssh_command']
