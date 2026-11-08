from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import pytest

from agents.test_shared_default_supervision import FakeSystemd, args, load, signer_fixture, install_signer


def test_readiness_probes_loopback_without_opening_a_socket(monkeypatch):
    m = load('mitm_lane')
    addresses = []
    class Socket:
        def __enter__(self): return self
        def __exit__(self, *_args): pass
        def settimeout(self, _value): pass
        def connect_ex(self, address):
            addresses.append(address)
            return 0
    monkeypatch.setattr(m.socket, 'socket', lambda *_args: Socket())
    assert m.wait_for_port(8080)
    assert addresses == [('127.0.0.1', 8080)]


@pytest.mark.parametrize('listen_host', ['127.0.0.1', '0.0.0.0'])
def test_supported_listen_hosts_are_probed_through_loopback(tmp_path, monkeypatch, listen_host, signer_fixture):
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    m = load('mitm_lane')
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch, assume_observed=True)
    ca = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    install_signer(ca, signer_fixture)
    fake = FakeSystemd()
    monkeypatch.setattr(m.subprocess, 'run', fake.run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda port: True)
    probes = []
    monkeypatch.setattr(m, 'wait_for_port', lambda port: probes.append(port) or True)
    result = m.start_lane(args(tmp_path, listen_host=listen_host))
    assert result['status'] == 'running'
    assert result['listen_host'] == listen_host and probes == [8080]
    assert len([c for c in calls if c[0] == 'systemd-run']) == 1


def test_uncertain_start_keeps_generation_blocked_without_stop(tmp_path, monkeypatch):
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    m = load('mitm_lane')
    preflight_calls = prepare_direct_preflight(m, tmp_path, monkeypatch)
    fake = FakeSystemd()
    def run(command, **kwargs):
        if command[:3] == ['systemctl', '--user', 'stop']:
            return subprocess.CompletedProcess(command, 1, '', 'failure')
        return fake.run(command, **kwargs)
    monkeypatch.setattr(m.subprocess, 'run', run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda port: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda port: False)
    first = m.start_lane(args(tmp_path))
    assert first['status'] == 'start-outcome-unknown' and fake.active
    assert not any(c[:3] == ['systemctl', '--user', 'stop'] for c in fake.calls)
    calls = len(fake.calls)
    second = m.start_lane(args(tmp_path))
    assert second['status'] == 'start-cleanup-failed'
    assert second['unit'] == fake.unit and len(fake.calls) == calls
    assert len([c for c in preflight_calls if c[0] == 'systemd-run']) == 1


def test_disabled_linger_refuses_before_unit_launch(tmp_path, monkeypatch):
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    m = load('mitm_lane')
    preflight_calls = prepare_direct_preflight(m, tmp_path, monkeypatch)
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, 'no\n', '')
    monkeypatch.setattr(m.subprocess, 'run', run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda port: True)
    result = m.start_lane(args(tmp_path))
    assert result['status'] == 'supervisor-unavailable'
    assert len(calls) == 1 and calls[0][0] == 'loginctl'
    assert not any(c[0] == 'systemd-run' for c in preflight_calls)


def test_wrong_cgroup_is_not_signalled(tmp_path, monkeypatch):
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    m = load('mitm_lane')
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch)
    fake = FakeSystemd()
    monkeypatch.setattr(m.subprocess, 'run', fake.run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda port: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda port: True)
    real_status = m.unit_status
    def wrong_group(unit, env):
        status = real_status(unit, env)
        if status['ActiveState'] == 'active':
            status['ControlGroup'] = '/system.slice/ssh.service'
        return status
    monkeypatch.setattr(m, 'unit_status', wrong_group)
    result = m.start_lane(args(tmp_path))
    assert result['status'] == 'start-outcome-unknown' and fake.active
    assert m.read_state(tmp_path, 'hoster-default-8080')['status'] == 'starting'
    assert len([c for c in calls if c[0] == 'systemd-run']) == 1
    assert not any(c[:3] == ['systemctl', '--user', 'stop'] for c in fake.calls)


def test_guidance_distinguishes_shared_default_from_task_fallback():
    root = Path(__file__).resolve().parents[1]
    for path in ['skills/chromium-test/SKILL.md', 'skills/chromium-test/scripts/README.md', 'prompts/chromium-test-playbook.md']:
        text = (root / path).read_text()
        assert 'ensure-default' in text
        assert 'user-systemd' in text or 'user systemd' in text
        assert 'cannot start a missing' not in text
