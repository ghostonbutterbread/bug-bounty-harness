"""Offline regressions for shared-default signer and dispatch boundaries."""
import json

import subprocess
from pathlib import Path

import pytest

from agents.test_shared_default_supervision import load, args, signer_fixture
from agents.test_shared_default_ca_readiness import wrapper_args



def certs(tmp_path, fixture):
    conf = tmp_path / 'remote'
    conf.mkdir()
    public = conf / 'mitmproxy-ca-cert.pem'
    combined = conf / 'mitmproxy-ca.pem'
    public.write_bytes((fixture / 'a.crt').read_bytes())
    combined.write_bytes((fixture / 'a.key').read_bytes() + public.read_bytes())
    return fixture, public, combined


def test_signer_mismatch_never_replaces_client_ca(tmp_path, monkeypatch, signer_fixture):
    m = load('mitm_lane')
    fixture, public, combined = certs(tmp_path, signer_fixture)
    assert m.readable_ca(public)
    combined.write_bytes((fixture / 'b.key').read_bytes() + (fixture / 'b.crt').read_bytes())
    assert not m.wait_for_ca(public, m.time.monotonic())
    wrapper = load('hoster_mitm_lane')
    monkeypatch.setattr(wrapper, 'running_on_requested_hoster', lambda _: True)
    monkeypatch.setattr(wrapper, 'run_remote', lambda *_: {'status': 'running', 'alive': True, 'port_open': True, 'ca_cert': str(public),
                                                           'ca_signer_sha256': m.signer_fingerprint(public)})
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    local.write_bytes(b'old client CA')
    result = wrapper.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert': str(public)})
    assert result['status'] == 'copy-failed'
    assert local.read_bytes() == b'old client CA'
    assert 'PRIVATE KEY' not in json.dumps(result)


def test_new_start_waits_for_valid_signer(tmp_path, monkeypatch, signer_fixture):
    from agents.test_shared_default_supervision import FakeSystemd
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    m = load('mitm_lane')
    fixture = signer_fixture
    ca = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    combined = ca.with_name('mitmproxy-ca.pem')
    fake = FakeSystemd()
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch, assume_observed=True)
    def run(command, **kwargs):
        result = fake.run(command, **kwargs)
        if command[0] == 'systemd-run':
            ca.write_bytes((fixture / 'a.crt').read_bytes())
            combined.write_bytes(b'partial')
        return result
    monkeypatch.setattr(m.subprocess, 'run', run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda _: True)
    slept = []
    def finish(_):
        slept.append(1)
        combined.write_bytes((fixture / 'a.key').read_bytes() + ca.read_bytes())
    monkeypatch.setattr(m.time, 'sleep', finish)
    result = m.start_lane(args(tmp_path))
    assert result['status'] == 'running' and slept == [1]
    assert len([c for c in calls if c[0] == 'systemd-run']) == 1
    assert 'PRIVATE KEY' not in json.dumps(result)


def test_matching_signer_copies_only_public_certificate(tmp_path, monkeypatch, signer_fixture):
    mitm = load('mitm_lane')
    wrapper = load('hoster_mitm_lane')
    _, public, combined = certs(tmp_path, signer_fixture)
    monkeypatch.setattr(wrapper, 'running_on_requested_hoster', lambda _: True)
    monkeypatch.setattr(wrapper, 'run_remote', lambda *_: {'status': 'running', 'alive': True, 'port_open': True, 'ca_cert': str(public),
                                                           'ca_signer_sha256': mitm.signer_fingerprint(public)})
    result = wrapper.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert': str(public)})
    assert result['status'] == 'copied'
    assert Path(result['local_path']).read_bytes() == public.read_bytes()
    assert b'PRIVATE KEY' not in Path(result['local_path']).read_bytes()
    assert 'PRIVATE KEY' not in json.dumps(result)
    assert b'PRIVATE KEY' in combined.read_bytes()


def test_public_ca_with_key_is_rejected_before_copy(tmp_path, monkeypatch, signer_fixture):
    mitm = load('mitm_lane')
    wrapper = load('hoster_mitm_lane')
    fixture, public, _ = certs(tmp_path, signer_fixture)
    public.write_bytes(public.read_bytes() + (fixture / 'a.key').read_bytes())
    assert mitm.signer_fingerprint(public) is None
    monkeypatch.setattr(wrapper, 'run_remote', lambda *_: {'status': 'running', 'alive': True, 'port_open': True, 'ca_cert': str(public),
                                                           'ca_signer_sha256': mitm.signer_fingerprint(public)})
    monkeypatch.setattr(wrapper, 'copy_remote_file', lambda *_: pytest.fail('must not copy key'))
    result = wrapper.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert': str(public)})
    assert result['status'] == 'copy-failed' and 'PRIVATE KEY' not in json.dumps(result)


def test_partial_signer_generation_retried_until_matching(tmp_path, monkeypatch, signer_fixture):
    mitm = load('mitm_lane')
    wrapper = load('hoster_mitm_lane')
    _, public, combined = certs(tmp_path, signer_fixture)
    full = combined.read_bytes()
    combined.write_bytes(full[:50])
    monkeypatch.setattr(wrapper, 'running_on_requested_hoster', lambda _: True)
    monkeypatch.setattr(wrapper, 'run_remote', lambda *_: {'status': 'running', 'alive': True, 'port_open': True, 'ca_cert': str(public),
                                                           'ca_signer_sha256': mitm.signer_fingerprint(public)})
    clock = [0.0]
    def sleep(seconds):
        clock[0] += seconds
        combined.write_bytes(full)
    monkeypatch.setattr(wrapper.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(wrapper.time, 'sleep', sleep)
    result = wrapper.sync_lane_ca_until_ready(wrapper_args(tmp_path), {'ca_cert': str(public)})
    assert result['status'] == 'copied' and clock[0] > 0
    assert Path(result['local_path']).read_bytes() == public.read_bytes()


def test_matching_and_partial_combined_ca(tmp_path, signer_fixture):
    m = load('mitm_lane')
    _, public, combined = certs(tmp_path, signer_fixture)
    full = combined.read_bytes()
    combined.write_bytes(full[:30])
    assert not m.wait_for_ca(public, m.time.monotonic())
    combined.write_bytes(full)
    assert m.wait_for_ca(public, m.time.monotonic())


@pytest.mark.parametrize('local', [False, True])
@pytest.mark.parametrize(('rc', 'body'), [(1, '{"status":"running","alive":true}'), (255, '{"status":"not-found"}'), (-9, '{"status":"running","alive":true}'), (1, '{"status":[]}'), (0, '[]'), (0, '{broken'), (0, '')])
def test_status_dispatch_failure_never_starts(tmp_path, monkeypatch, rc, body, local):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: local)
    calls = []
    def run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, rc, body, 'SECRET')
    monkeypatch.setattr(m.subprocess, 'run', run)
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed'
    assert len(calls) == 1
    assert 'SECRET' not in json.dumps(result)


def test_start_disconnect_is_unknown_without_retry(tmp_path, monkeypatch):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    calls = []
    def run(cmd, **kw):
        calls.append(cmd)
        if len(calls) == 1:
            assert 'observe-default' in cmd[-1]
            return subprocess.CompletedProcess(cmd, 2, '{"status":"unknown-state"}', '')
        if len(calls) == 2:
            assert 'classify-default-absence' in cmd[-1]
            return subprocess.CompletedProcess(cmd, 0, '{"status":"not-found","lane":"hoster-default-8080"}', '')
        assert ' start ' in cmd[-1] and '--require-user-systemd' in cmd[-1]
        return subprocess.CompletedProcess(cmd, 255, '{"status":"running"}', 'SECRET')
    monkeypatch.setattr(m.subprocess, 'run', run)
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-outcome-unknown' and 'may be running' in result['detail']
    assert 'without retrying' in result['detail'] and 'stopping' in result['detail']
    assert len(calls) == 3 and 'SECRET' not in json.dumps(result)


def test_live_failure_not_coerced_to_running(tmp_path, monkeypatch):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    calls = []
    def remote(_, cmd):
        calls.append(cmd)
        assert 'observe-default' in cmd
        return {'status': 'ssh-failed', 'ssh_returncode': 2, 'remote_status': 'start-timeout'}
    monkeypatch.setattr(m, 'run_remote', remote)
    monkeypatch.setattr(m, 'copy_remote_file', lambda *_: pytest.fail('must not copy'))
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and result['start']['status'] == 'unknown-state'
    assert result['start']['remote_status'] == 'start-timeout'
    assert len(calls) == 1 and all('start' not in c and 'stop' not in c for c in calls)


def test_legacy_failure_from_nonzero_status_is_retained(tmp_path, monkeypatch):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    calls = []
    monkeypatch.setattr(m.subprocess, 'run', lambda cmd, **kw:
                        calls.append(cmd) or subprocess.CompletedProcess(cmd, 2, '{"status":"start-timeout","alive":true}', 'SECRET'))
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed'
    assert result['start']['remote_status'] == 'start-timeout'
    assert len(calls) == 1 and 'observe-default' in calls[0][-1]
    assert 'SECRET' not in json.dumps(result)


def test_live_legacy_timeout_is_preserved_by_local_start(tmp_path, monkeypatch):
    m = load('mitm_lane')
    state = {'status': 'start-timeout', 'pid': 123, 'port': 8080, 'lane': 'hoster-default-8080'}
    m.write_state(tmp_path, state['lane'], state)
    monkeypatch.setattr(m, 'pid_alive', lambda _: True)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: pytest.fail('must not stop or launch'))
    result = m.start_lane(args(tmp_path))
    assert result['status'] == 'unknown-state'
    assert m.read_state(tmp_path, state['lane']) == state


@pytest.mark.parametrize(('host', 'target'), [('2001:db8::1', '[2001:db8::1]'), ('example.test', 'example.test'), ('192.0.2.1', '192.0.2.1')])
def test_ipv6_scp_brackets(tmp_path, monkeypatch, host, target):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    a = wrapper_args(tmp_path, ssh_host=host)
    a.dry_run = True
    command = m.copy_remote_file(a, '/remote/ca', tmp_path / 'ca')['scp_command']
    assert command[-2] == f'{a.ssh_user}@{target}:/remote/ca'
