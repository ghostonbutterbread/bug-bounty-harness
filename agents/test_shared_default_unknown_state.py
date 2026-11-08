"""Fenced regressions for shared default state, address family and diagnostics."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agents.test_shared_default_supervision import FakeSystemd, args, load
from agents.test_shared_default_ca_readiness import wrapper_args
from agents.test_shared_default_signer_dispatch import signer_fixture


def allow_synthetic_start(m, monkeypatch, *, assume_observed=False):
    # These tests exercise post-submission behavior only; classifier evidence is
    # separately exercised through the direct CLI's full synthetic fixture.
    monkeypatch.setattr(m, 'classify_default_absence', lambda _: {'status': 'not-found'})
    if assume_observed:
        monkeypatch.setattr(m, 'default_generation_observation',
                            lambda root, state: {'status': 'observed-fresh', 'unit': state['unit'], 'pid': state['pid']})
    monkeypatch.setattr(m.shutil, 'which', lambda name: '/usr/bin/mitmdump' if name == 'mitmdump' else '/fixture/' + name)
    import io
    original_open = Path.open
    def fixture_open(path, *args, **kwargs):
        if str(path) == '/usr/bin/mitmdump':
            return io.BytesIO(b'#!/usr/bin/python3\n')
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', fixture_open)


@pytest.mark.parametrize('failure', ['port-timeout', 'ca-timeout', 'unit-unknown', 'save-error'])
def test_post_submission_failure_preserves_starting_generation(tmp_path, monkeypatch, failure):
    m = load('mitm_lane')
    fake = FakeSystemd()
    allow_synthetic_start(m, monkeypatch)
    monkeypatch.setattr(m.subprocess, 'run', fake.run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda *_: failure != 'port-timeout')
    monkeypatch.setattr(m, 'wait_for_ca', lambda *_: failure != 'ca-timeout')
    monkeypatch.setattr(m, 'signer_fingerprint', lambda *_: 'a' * 64)
    if failure == 'unit-unknown':
        monkeypatch.setattr(m, 'unit_status', lambda *_: {'ActiveState': 'active', 'MainPID': '123', 'ControlGroup': ''})
    if failure == 'save-error':
        def save(root, lane, state):
            raise OSError('sensitive save error')
        monkeypatch.setattr(m, 'publish_running_state', save)
    result = m.start_lane(args(tmp_path))
    state = m.read_state(tmp_path, 'hoster-default-8080')
    assert result['status'] == 'start-outcome-unknown'
    assert state['status'] == 'starting' and state['unit'] == fake.unit
    assert fake.active and not any(c[:3] == ['systemctl', '--user', 'stop'] for c in fake.calls)
    assert m.start_lane(args(tmp_path))['status'] == 'start-cleanup-failed'
    assert len([c for c in fake.calls if c[0] == 'systemd-run']) == 1
    assert 'sensitive save error' not in json.dumps(result)


def test_running_record_failed_atomic_replace_preserves_starting_record(tmp_path, monkeypatch):
    m = load('mitm_lane')
    fake = FakeSystemd()
    allow_synthetic_start(m, monkeypatch, assume_observed=True)
    monkeypatch.setattr(m.subprocess, 'run', fake.run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda *_: True)
    monkeypatch.setattr(m, 'wait_for_ca', lambda *_: True)
    monkeypatch.setattr(m, 'signer_fingerprint', lambda *_: 'a' * 64)
    attempts = []
    def fail_replace(source, target):
        attempts.append((source, target))
        raise OSError('private error')
    monkeypatch.setattr(m.os, 'replace', fail_replace)
    result = m.start_lane(args(tmp_path))
    state = m.read_state(tmp_path, 'hoster-default-8080')
    assert len(attempts) == 1
    assert result['status'] == 'start-outcome-unknown'
    assert state['status'] == 'starting' and state['unit'] == fake.unit
    assert not list((tmp_path / 'hoster-default-8080').glob('.state-*'))
    assert fake.active and not any(c[:3] == ['systemctl', '--user', 'stop'] for c in fake.calls)


@pytest.mark.parametrize('raw', [b'{}\n', b'{"status":"running","port":8080}\n', b'[]', b'{broken', b'{"status":"running","pid":null,"port":8080}', b'{"status":"running","pid":123,"port":8080}', b'{"status":[],"pid":123}', b'{"status":"stopped","port":[]}'])
def test_existing_unknown_state_is_preserved_without_dispatch(tmp_path, monkeypatch, raw):
    m = load('mitm_lane')
    w = load('hoster_mitm_lane')
    path = m.state_path(tmp_path, 'hoster-default-8080')
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: pytest.fail('unexpected service dispatch'))
    status = m.status_lane(args(tmp_path))
    assert status['status'] in ('unknown-state', 'corrupt-state')
    before = set(path.parent.iterdir())
    assert m.start_lane(args(tmp_path))['status'] in ('unknown-state', 'corrupt-state')
    assert set(path.parent.iterdir()) == before and path.read_bytes() == raw
    calls = []
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(w, 'run_remote', lambda _, cmd: calls.append(cmd) or status)
    assert w.ensure_default(wrapper_args(tmp_path))['status'] == 'start-failed'
    assert len(calls) == 1 and calls[0][-1] == 'observe-default'
    assert path.read_bytes() == raw


def test_missing_state_is_not_found_but_wrapper_does_not_start(tmp_path, monkeypatch):
    m = load('mitm_lane')
    w = load('hoster_mitm_lane')
    assert m.status_lane(args(tmp_path))['status'] == 'not-found'
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    calls = []
    monkeypatch.setattr(w, 'run_remote', lambda _, cmd: calls.append(cmd) or ({'status':'not-found'} if len(calls) == 1 else {'status':'start-failed'}))
    assert w.ensure_default(wrapper_args(tmp_path))['status'] == 'start-failed'
    assert len(calls) == 1 and calls[0][-1] == 'observe-default'


def test_direct_remote_ipv6_rejected_before_dispatch_or_writes(tmp_path, monkeypatch, capsys):
    w = load('hoster_mitm_lane')
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(w, 'run_remote', lambda *_: pytest.fail('unexpected dispatch'))
    a = wrapper_args(tmp_path, proxy_host='2001:db8::1')
    a.json, a.func = True, w.ensure_default
    monkeypatch.setattr(w, 'parse_args', lambda: a)
    assert w.main() != 0
    captured = capsys.readouterr()
    assert 'IPv6' in json.loads(captured.out)['detail'] and not captured.err
    assert not list(tmp_path.iterdir())


def test_ipv4_and_same_host_advertisements(tmp_path, monkeypatch):
    w = load('hoster_mitm_lane')
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    assert w.advertised_proxy(wrapper_args(tmp_path, proxy_host='192.0.2.1')) == 'http://192.0.2.1:8080'
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: True)
    assert w.advertised_proxy(wrapper_args(tmp_path, proxy_host='2001:db8::1')) == 'http://127.0.0.1:8080'


def test_ipv6_real_cli_refuses_before_any_state_write(tmp_path):
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/hoster_mitm_lane.py'
    result = subprocess.run([sys.executable, str(script), '--json', '--ssh-host', 'remote.example.test',
                             '--local-lane-root', str(tmp_path), 'ensure-default', '--proxy-host', '2001:db8::1'],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 2 and 'IPv6' in json.loads(result.stdout)['detail']
    assert not result.stderr and not list(tmp_path.iterdir())


def test_direct_mitm_start_rejects_ipv6_before_state_write(tmp_path, monkeypatch):
    m = load('mitm_lane')
    monkeypatch.setattr(m.subprocess, 'run', lambda *_a, **_kw: pytest.fail('unexpected dispatch'))
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    result = m.start_lane(args(tmp_path, proxy_host='2001:db8::1'))
    assert result['status'] == 'unsupported-proxy-host' and 'IPv6' in result['detail']
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('state', [{'status':'stopped'}, {'status':'start-failed','cleanup':'stopped'},
                                   {'status':'start-timeout','cleanup':'stopped'}])
def test_terminal_state_direct_start_and_wrapper_refusal(tmp_path, monkeypatch, state):
    m = load('mitm_lane')
    w = load('hoster_mitm_lane')
    m.write_state(tmp_path, 'hoster-default-8080', state)
    status = m.status_lane(args(tmp_path))
    assert status['status'] == 'stopped' and status['alive'] is False
    monkeypatch.setattr(m, 'legacy_start_lane', lambda _: pytest.fail('unproven terminal start'))
    assert m.start_lane(args(tmp_path))['status'] == 'unknown-state'
    calls = []
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(w, 'run_remote', lambda _, cmd: calls.append(cmd) or (status if len(calls) == 1 else {'status':'start-failed'}))
    assert w.ensure_default(wrapper_args(tmp_path))['status'] == 'start-failed'
    assert len(calls) == 1 and calls[0][-1] == 'observe-default'


def test_stopped_state_with_reused_pid_is_not_reported_as_start_success(tmp_path, monkeypatch, capsys):
    m = load('mitm_lane')
    state_path = m.state_path(tmp_path, 'hoster-default-8080')
    state_path.parent.mkdir(parents=True)
    original = b'{"status":"stopped","pid":123,"port":8080}'
    state_path.write_bytes(original)
    monkeypatch.setattr(m, 'pid_alive', lambda _pid: True)
    monkeypatch.setattr(m, 'legacy_start_lane', lambda _args: pytest.fail('unexpected listener start'))
    a = args(tmp_path)
    a.json = True
    a.func = m.start_lane
    monkeypatch.setattr(m, 'parse_args', lambda: a)
    assert m.main() != 0
    output = capsys.readouterr()
    assert json.loads(output.out)['status'] == 'unknown-state'
    assert not output.err
    assert state_path.read_bytes() == original


def test_existing_live_default_is_not_reused_by_direct_start(tmp_path, monkeypatch, signer_fixture):
    m = load('mitm_lane')
    ca = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    ca.write_bytes((signer_fixture / 'a.crt').read_bytes())
    ca.with_name('mitmproxy-ca.pem').write_bytes((signer_fixture / 'a.key').read_bytes() + ca.read_bytes())
    state = {'status':'running', 'pid':123, 'port':8080, 'listen_host':'0.0.0.0', 'ca_cert':str(ca)}
    m.write_state(tmp_path, 'hoster-default-8080', state)
    before = m.state_path(tmp_path, 'hoster-default-8080').read_bytes()
    monkeypatch.setattr(m, 'pid_alive', lambda _: True)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: False)
    monkeypatch.setattr(m.subprocess, 'run', lambda *_a, **_kw: pytest.fail('unexpected service dispatch'))
    assert m.start_lane(args(tmp_path))['status'] == 'unknown-state'
    assert m.state_path(tmp_path, 'hoster-default-8080').read_bytes() == before


def test_unattested_existing_listener_must_not_sync_or_report_ready(tmp_path, monkeypatch):
    w = load('hoster_mitm_lane')
    calls = []
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(w, 'run_remote', lambda _, cmd: calls.append(cmd) or {
        'status': 'running', 'alive': True, 'port_open': True, 'port': 8080,
        'listen_host': '0.0.0.0', 'pid': 123, 'ca_cert': '/fixture/ca',
        'ca_identity': 'observed-at-readiness', 'ca_signer_sha256': 'a' * 64})
    sync = []
    monkeypatch.setattr(w, 'sync_lane_ca_until_ready', lambda *_: sync.append(True) or {
        'status': 'copied', 'local_path': '/fixture/ca'})
    result = w.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed'
    assert not sync
    assert len(calls) == 1 and calls[0][-1] == 'observe-default'
    assert not list(tmp_path.iterdir())


def test_new_listener_without_attestation_must_not_sync_or_report_ready(tmp_path, monkeypatch):
    w = load('hoster_mitm_lane')
    calls = []
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    def dispatch(_, cmd):
        calls.append(cmd)
        if len(calls) == 1:
            return {'status': 'not-found'}
        return {'status': 'running', 'port': 8080, 'listen_host': '0.0.0.0',
                'ca_cert': '/fixture/ca', 'ca_identity': 'observed-at-readiness'}
    monkeypatch.setattr(w, 'run_remote', dispatch)
    sync = []
    monkeypatch.setattr(w, 'sync_lane_ca_until_ready', lambda *_: sync.append(True) or {
        'status': 'copied', 'local_path': '/fixture/ca'})
    result = w.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed'
    assert not sync
    assert len(calls) == 1 and calls[0][-1] == 'observe-default'
    assert not list(tmp_path.iterdir())


def test_nonzero_unknown_status_is_preserved_without_start(tmp_path, monkeypatch):
    w = load('hoster_mitm_lane')
    calls = []
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(w.subprocess, 'run', lambda cmd, **kw: calls.append(cmd) or
                        subprocess.CompletedProcess(cmd, 2, '{"status":"unknown-state"}', 'SECRET'))
    result = w.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and result['start']['status'] == 'unknown-state'
    assert len(calls) == 2 and 'classify-default-absence' in calls[1][-1]
    assert 'SECRET' not in json.dumps(result)


def test_systemd_failure_redacts_stderr_in_cli_and_state(tmp_path, monkeypatch, capsys):
    m = load('mitm_lane')
    fake = FakeSystemd()
    allow_synthetic_start(m, monkeypatch)
    def run(command, **kw):
        if command[0] == 'systemd-run':
            fake.unit = next(x.split('=', 1)[1] for x in command if x.startswith('--unit='))
            fake.calls.append(command)
            return subprocess.CompletedProcess(command, 1, '', 'SECRET-DIAGNOSTIC')
        return fake.run(command, **kw)
    monkeypatch.setattr(m.subprocess, 'run', run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    a = args(tmp_path)
    a.json, a.func = True, m.start_lane
    monkeypatch.setattr(m, 'parse_args', lambda: a)
    assert m.main() != 0
    output = capsys.readouterr()
    state = m.state_path(tmp_path, a.lane).read_text()
    body = json.loads(output.out)
    assert body['status'] == 'start-outcome-unknown' and body['unit'] == fake.unit
    saved = json.loads(state)
    assert saved['status'] == 'starting' and saved['unit'] == fake.unit and saved['flow_file']
    assert not any(c[:3] == ['systemctl', '--user', 'stop'] for c in fake.calls)
    assert 'SECRET-DIAGNOSTIC' not in state + output.out + output.err
    assert 'Traceback' not in state + output.out + output.err


def test_certificate_identity_is_readiness_observation(tmp_path, monkeypatch, signer_fixture):
    m = load('mitm_lane')
    ca = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    ca.write_bytes((signer_fixture / 'a.crt').read_bytes())
    ca.with_name('mitmproxy-ca.pem').write_bytes((signer_fixture / 'a.key').read_bytes() + ca.read_bytes())
    fake = FakeSystemd()
    allow_synthetic_start(m, monkeypatch, assume_observed=True)
    monkeypatch.setattr(m.subprocess, 'run', fake.run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda _: True)
    assert m.start_lane(args(tmp_path))['status'] == 'running'
    monkeypatch.setattr(m, 'pid_alive', lambda _: True)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: False)
    assert m.status_lane(args(tmp_path))['ca_identity'] == 'observed-at-readiness'


@pytest.mark.parametrize('label', ['running', 'already-running'])
def test_dead_nonterminal_state_remains_unknown_and_never_restarts(tmp_path, monkeypatch, label):
    m, w = load('mitm_lane'), load('hoster_mitm_lane')
    path = m.state_path(tmp_path, 'hoster-default-8080')
    path.parent.mkdir(parents=True)
    raw = json.dumps({'status': label, 'pid': 123, 'port': 8080,
                      'listen_host': '0.0.0.0', 'ca_cert': str(tmp_path / 'ca')}).encode()
    path.write_bytes(raw)
    monkeypatch.setattr(m, 'pid_alive', lambda _: False)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(m, 'legacy_start_lane', lambda _: pytest.fail('unexpected start'))
    before = set(path.parent.iterdir())
    status = m.status_lane(args(tmp_path))
    assert status['status'] == 'unknown-state'
    assert m.start_lane(args(tmp_path))['status'] == 'unknown-state'
    assert path.read_bytes() == raw and set(path.parent.iterdir()) == before
    calls = []
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(w, 'run_remote', lambda _, cmd: calls.append(cmd) or status)
    assert w.ensure_default(wrapper_args(tmp_path))['status'] == 'start-failed'
    assert len(calls) == 1 and calls[0][-1] == 'observe-default'


@pytest.mark.parametrize('host', ['2001:db8::1', '[2001:db8::1]'])
def test_ipv6_literals_rejected_direct_and_remote_before_side_effects(tmp_path, monkeypatch, host):
    m, w = load('mitm_lane'), load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'legacy_start_lane', lambda _: pytest.fail('unexpected start'))
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(w, 'run_remote', lambda *_: pytest.fail('unexpected dispatch'))
    assert m.start_lane(args(tmp_path, proxy_host=host))['status'] == 'unsupported-proxy-host'
    assert w.ensure_default(wrapper_args(tmp_path, proxy_host=host))['status'] == 'start-failed'
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('json_output', [True, False])
def test_legacy_detail_is_not_exposed_or_changed(tmp_path, monkeypatch, capsys, json_output):
    m = load('mitm_lane')
    path = m.state_path(tmp_path, 'hoster-default-8080')
    path.parent.mkdir(parents=True)
    raw = b'{"status":"start-failed","cleanup":"stopped","detail":"SECRET-OLD-STDERR"}'
    path.write_bytes(raw)
    a = args(tmp_path)
    a.json, a.func = json_output, m.status_lane
    monkeypatch.setattr(m, 'parse_args', lambda: a)
    assert m.main() == 0
    output = capsys.readouterr()
    assert 'SECRET-OLD-STDERR' not in output.out + output.err
    assert 'detail' in output.out and path.read_bytes() == raw


@pytest.mark.parametrize('raw', [
    b'{"status":"running","pid":' + b'9' * 5000 + b'}',
    b'[' * 20000 + b'0' + b']' * 20000,
    b'{"status":"running","pid":2147483648,"port":8080,"listen_host":"0.0.0.0","ca_cert":"x"}',
], ids=['large-integer', 'deep-nesting', 'pid-overflow'])
def test_corrupt_extremes_are_unknown_without_kill_or_mutation(tmp_path, monkeypatch, raw):
    m = load('mitm_lane')
    path = m.state_path(tmp_path, 'hoster-default-8080')
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    monkeypatch.setattr(m.os, 'kill', lambda *_: pytest.fail('unexpected kill'))
    monkeypatch.setattr(m, 'legacy_start_lane', lambda _: pytest.fail('unexpected start'))
    result = m.status_lane(args(tmp_path))
    assert result['status'] in {'unknown-state', 'corrupt-state'} and result['detail']
    assert m.start_lane(args(tmp_path))['status'] in {'unknown-state', 'corrupt-state'}
    assert path.read_bytes() == raw


def test_wrapper_rejects_older_dead_running_response_without_retry(tmp_path, monkeypatch):
    w = load('hoster_mitm_lane')
    calls = []
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(w, 'run_remote', lambda _, cmd: calls.append(cmd) or {'status': 'running', 'alive': False})
    assert w.ensure_default(wrapper_args(tmp_path))['status'] == 'start-failed'
    assert len(calls) == 1 and calls[0][-1] == 'observe-default'


@pytest.mark.parametrize('host', ['2001:db8::1', '[2001:db8::1]'])
def test_direct_ipv6_real_cli_fails_without_writing(tmp_path, host):
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/mitm_lane.py'
    result = subprocess.run([sys.executable, str(script), '--json', '--root', str(tmp_path),
                             '--lane', 'hoster-default-8080', 'start', '--port', '8080',
                             '--proxy-host', host], capture_output=True, text=True, check=False)
    assert result.returncode == 2 and json.loads(result.stdout)['status'] == 'unsupported-proxy-host'
    assert not result.stderr and not list(tmp_path.iterdir())


def test_terminal_state_really_starts_fake_supervisor(tmp_path, monkeypatch, signer_fixture):
    m = load('mitm_lane')
    ca = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    ca.write_bytes((signer_fixture / 'a.crt').read_bytes())
    ca.with_name('mitmproxy-ca.pem').write_bytes((signer_fixture / 'a.key').read_bytes() + ca.read_bytes())
    m.write_state(tmp_path, 'hoster-default-8080', {'status': 'stopped'})
    fake = FakeSystemd()
    allow_synthetic_start(m, monkeypatch, assume_observed=True)
    monkeypatch.setattr(m.subprocess, 'run', fake.run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda _: True)
    assert m.start_lane(args(tmp_path))['status'] == 'running'
    assert any(call[0] == 'systemd-run' for call in fake.calls)


def test_dying_between_precheck_and_locked_check_is_preserved(tmp_path, monkeypatch):
    m = load('mitm_lane')
    path = m.state_path(tmp_path, 'hoster-default-8080')
    path.parent.mkdir(parents=True)
    raw = json.dumps({'status': 'running', 'pid': 123, 'port': 8080,
                      'listen_host': '0.0.0.0', 'ca_cert': 'fixture-ca'}).encode()
    path.write_bytes(raw)
    checks = iter([True, False])
    monkeypatch.setattr(m, 'pid_alive', lambda _: next(checks))
    monkeypatch.setattr(m, 'legacy_start_lane', lambda _: pytest.fail('unexpected start'))
    assert m.start_lane(args(tmp_path))['status'] == 'unknown-state'
    assert path.read_bytes() == raw


@pytest.mark.parametrize('host', ['2001:db8::1', '[2001:db8::1]'])
def test_remote_ipv6_real_cli_fails_without_writing(tmp_path, host):
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/hoster_mitm_lane.py'
    result = subprocess.run([sys.executable, str(script), '--json', '--ssh-host', 'remote.example.test',
                             '--local-lane-root', str(tmp_path), 'ensure-default', '--proxy-host', host],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 2 and json.loads(result.stdout)['status'] == 'start-failed'
    assert not result.stderr and not list(tmp_path.iterdir())


@pytest.mark.parametrize('raw', [b'{"n":' + b'9' * 5000 + b'}',
                                  b'[' * 20000 + b'0' + b']' * 20000,
                                  b'{"status":"running","pid":2147483648}'],
                         ids=['large-integer', 'deep-nesting', 'pid-overflow'])
def test_malformed_state_real_cli_is_nonzero_and_unchanged(tmp_path, raw):
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/mitm_lane.py'
    path = tmp_path / 'hoster-default-8080' / 'state.json'
    path.parent.mkdir()
    path.write_bytes(raw)
    for operation in ('status', 'start'):
        command = [sys.executable, str(script), '--json', '--root', str(tmp_path),
                   '--lane', 'hoster-default-8080', operation]
        if operation == 'start':
            command += ['--port', '8080']
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        payload = json.loads(result.stdout)
        assert result.returncode == 2 and payload['status'] in {'corrupt-state', 'unknown-state'}
        assert payload['detail'] and not result.stderr and path.read_bytes() == raw
