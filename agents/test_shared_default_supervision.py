from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import os
import shutil
from pathlib import Path
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope='session')
def signer_fixture(tmp_path_factory):
    """Copy disposable, explicitly test-only CA material; never invoke OpenSSL."""
    directory = tmp_path_factory.mktemp('synthetic-signers')
    fixtures = ROOT / 'agents/fixtures/shared_default_supervision'
    for name in ('a', 'b'):
        shutil.copyfile(fixtures / f'{name}.crt', directory / f'{name}.crt')
        shutil.copyfile(fixtures / f'{name}-test-key.pem.fixture', directory / f'{name}.key')
    return directory


def install_signer(public, fixture):
    public.write_bytes((fixture / 'a.crt').read_bytes())
    public.with_name('mitmproxy-ca.pem').write_bytes((fixture / 'a.key').read_bytes() + public.read_bytes())


def signer_status(public, fixture):
    import hashlib
    import ssl
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert((fixture / 'a.crt').read_text())).hexdigest()
    return {'status': 'running', 'alive': True, 'port_open': True,
            'ca_cert': str(public), 'ca_signer_sha256': digest}


def observed_dispatch(public, fixture, *, kind='observed-legacy', listen_host='0.0.0.0'):
    """Return distinct read-only observation and generation-bound attestation replies."""
    import hashlib
    import ssl
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert((fixture / 'a.crt').read_text())).hexdigest()
    unit = ('hoster-mitm-default-8080.service' if kind == 'observed-legacy'
            else 'ghost-mitm-default-8080-' + 'a' * 32 + '.service')
    observation = {'status': kind, 'lane': 'hoster-default-8080', 'unit': unit,
                   'pid': 123, 'port': 8080, 'listen_host': listen_host, 'signer': 'unverified',
                   'generation_sha256': 'a' * 64}
    attestation = {'status': 'attested', 'lane': 'hoster-default-8080', 'signer': 'verified',
                   'generation_sha256': 'a' * 64, 'ca_sha256': digest, 'ca_cert': str(public),
                   'observation': kind, 'listen_host': listen_host}
    def dispatch(_, command):
        if command[-1] == 'observe-default':
            return dict(observation)
        if command[-1] == 'attest-default':
            return dict(attestation)
        pytest.fail('unexpected lifecycle or other dispatch')
    return dispatch


def fresh_dispatch(public, fixture):
    """Model the current absence/start/observation/attestation protocol."""
    import hashlib
    dispatch = observed_dispatch(public, fixture, kind='observed-fresh')
    flow = '/remote/hoster-default-8080/flows-test.mitm'
    observation = dispatch(None, ['observe-default'])
    attestation = dispatch(None, ['attest-default'])
    seen = []
    def remote(args, command):
        op = next(op for op in ('observe-default', 'classify-default-absence', 'start', 'attest-default') if op in command)
        seen.append(op)
        if op == 'observe-default':
            if seen.count(op) == 1:
                return {'status': 'ssh-failed', 'remote_status': 'unknown-state', 'ssh_returncode': 2}
            return {**observation, 'flow_path_sha256': hashlib.sha256(flow.encode()).hexdigest(), 'ssh_returncode': 0}
        if op == 'classify-default-absence':
            return {'status': 'not-found', 'lane': 'hoster-default-8080', 'ssh_returncode': 0}
        if op == 'start':
            return {'status': 'running', 'lane': 'hoster-default-8080', 'unit': observation['unit'],
                    'pid': observation['pid'], 'port': 8080, 'listen_host': observation['listen_host'],
                    'ca_cert': str(public), 'ca_started_sha256': attestation['ca_sha256'],
                    'flow_file': flow, 'ssh_returncode': 0}
        return {**attestation, 'ssh_returncode': 0}
    return remote, seen


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'skills/chromium-test/scripts' / (name + '.py'))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def args(root, **changes):
    values = dict(root=str(root), lane='hoster-default-8080', port=8080,
                  mitmdump='mitmdump', listen_host='0.0.0.0', proxy_host='hoster',
                  program='general', task='default-capture', account_label=None,
                  account=None, profile_dir=None, run_id=None, agent_id=None,
                  runtime_host=None, transport='mixed', browser_profile_id=None,
                  session_source=None)
    values.update(changes)
    return argparse.Namespace(**values)


class FakeSystemd:
    def __init__(self):
        self.calls = []
        self.active = False
        self.unit = None

    def run(self, command, **kwargs):
        self.calls.append(command)
        if command[0] == 'loginctl':
            return subprocess.CompletedProcess(command, 0, 'yes\n', '')
        if command[0] == 'systemd-run':
            self.unit = next(x.split('=', 1)[1] for x in command if x.startswith('--unit='))
            self.active = True
            return subprocess.CompletedProcess(command, 0, '', '')
        if command[:3] == ['systemctl', '--user', 'show']:
            return subprocess.CompletedProcess(command, 0,
                ('ActiveState=active\nMainPID=4321\nControlGroup=/user.slice/user-1000.slice/user@1000.service/app.slice/fake.service\n' if self.active else
                 'ActiveState=inactive\nMainPID=0\nControlGroup=\n'), '')
        if command[:3] == ['systemctl', '--user', 'stop']:
            assert command[-1] == self.unit
            self.active = False
            return subprocess.CompletedProcess(command, 0, '', '')
        raise AssertionError(command)


def test_default_new_generation_runs_in_user_unit_preserving_history(tmp_path, monkeypatch, signer_fixture):
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    m = load('mitm_lane')
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch, assume_observed=True)
    directory = tmp_path / 'hoster-default-8080'
    confdir = directory / 'mitmproxy'
    confdir.mkdir(parents=True)
    (directory / 'flows.mitm').write_bytes(b'history')
    install_signer(confdir / 'mitmproxy-ca-cert.pem', signer_fixture)
    fake = FakeSystemd()
    monkeypatch.setattr(m.subprocess, 'run', fake.run)
    monkeypatch.setattr(m.subprocess, 'Popen', lambda *a, **kw: (_ for _ in ()).throw(AssertionError('Popen proxy')))
    monkeypatch.setattr(m, 'can_bind_localhost', lambda port: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda *a, **kw: True)
    result = m.start_lane(args(tmp_path))
    assert result['status'] == 'running', result
    assert result['pid'] == 4321 and result['unit'] == fake.unit
    start = next(c for c in fake.calls if c[0] == 'systemd-run')
    assert '--user' in start and '--' in start and '/usr/bin/mitmdump' in start
    assert len([c for c in calls if c[0] == 'systemd-run']) == 1
    assert 'Type=exec' in ' '.join(start)
    assert (directory / 'flows.mitm').read_bytes() == b'history'
    assert (confdir / 'mitmproxy-ca-cert.pem').read_bytes() == (signer_fixture / 'a.crt').read_bytes()
    assert Path(result['flow_file']) != directory / 'flows.mitm'
    assert m.read_state(tmp_path, 'hoster-default-8080')['unit'] == fake.unit


@pytest.mark.parametrize('failure', ['timeout', 'nonzero'])
def test_ambiguous_systemd_submission_preserves_generation_without_stop(tmp_path, monkeypatch, failure):
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    m = load('mitm_lane')
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch)
    fake = FakeSystemd()
    def run(command, **kwargs):
        if command[0] == 'systemd-run':
            fake.run(command, **kwargs)  # The manager accepted it before the reply was lost.
            if failure == 'timeout':
                raise subprocess.TimeoutExpired(command, 12)
            return subprocess.CompletedProcess(command, 1, '', 'sensitive output')
        return fake.run(command, **kwargs)
    monkeypatch.setattr(m.subprocess, 'run', run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    result = m.start_lane(args(tmp_path))
    state = m.read_state(tmp_path, 'hoster-default-8080')
    assert result['status'] == 'start-outcome-unknown'
    assert state['status'] == 'starting' and state['unit'] == fake.unit
    assert fake.active
    assert not any(c[:3] == ['systemctl', '--user', 'stop'] for c in fake.calls)
    assert m.start_lane(args(tmp_path))['status'] == 'start-cleanup-failed'
    assert len([c for c in fake.calls if c[0] == 'systemd-run']) == 1
    assert len([c for c in calls if c[0] == 'systemd-run']) == 1
    assert 'sensitive output' not in json.dumps(result)
    a = args(tmp_path)
    a.json = True
    a.func = lambda _: result
    monkeypatch.setattr(m, 'parse_args', lambda: a)
    assert m.main() != 0


def test_timeout_preserves_unproven_unit_without_stop(tmp_path, monkeypatch):
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    m = load('mitm_lane')
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch)
    fake = FakeSystemd()
    monkeypatch.setattr(m.subprocess, 'run', fake.run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda port: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda *a, **kw: False)
    result = m.start_lane(args(tmp_path))
    assert result['status'] == 'start-outcome-unknown', result
    assert fake.active and m.read_state(tmp_path, 'hoster-default-8080')['unit'] == fake.unit
    assert len([c for c in calls if c[0] == 'systemd-run']) == 1
    assert not [c for c in fake.calls if c[:3] == ['systemctl', '--user', 'stop']]


def test_unsupported_bind_address_refuses_before_spawning(tmp_path, monkeypatch):
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    m = load('mitm_lane')
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: (_ for _ in ()).throw(AssertionError('spawned')))
    result = m.start_lane(args(tmp_path, listen_host='192.0.2.1'))
    assert result['status'] == 'unsupported-listen-host'
    assert '127.0.0.1' in result['detail'] and '0.0.0.0' in result['detail']
    assert not any(c[0] in ('loginctl', 'systemd-run') for c in calls)


def test_wrapper_requires_new_supervision_capability(monkeypatch):
    m = load('hoster_mitm_lane')
    calls = []
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    def remote(_args, argv):
        calls.append(argv)
        if 'observe-default' in argv:
            return {'status': 'ssh-failed', 'remote_status': 'unknown-state', 'ssh_returncode': 2}
        if 'classify-default-absence' in argv:
            return {'status': 'not-found', 'lane': 'hoster-default-8080', 'ssh_returncode': 0}
        assert 'start' in argv and '--require-user-systemd' in argv
        return {'status': 'ssh-failed', 'ssh_returncode': 2}
    monkeypatch.setattr(m, 'run_remote', remote)
    a = argparse.Namespace(lane='hoster-default-8080', port=8080, listen_host='0.0.0.0',
        proxy_host='hoster', ssh_host='hoster', program=None, task=None, agent_id=None, run_id=None,
        account_label=None, runtime_host=None, transport='mixed', session_source=None, dry_run=False, timeout=30)
    assert m.ensure_default(a)['status'] == 'start-outcome-unknown'
    assert len(calls) == 3 and '--require-user-systemd' in calls[-1]
    assert all('stop' not in call for call in calls)
