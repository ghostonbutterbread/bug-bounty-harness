"""Wrapper attestation and CA publication; run only in the fenced fixture."""
import hashlib
import json
import ssl
from pathlib import Path

import pytest

from agents.test_shared_default_supervision import load, signer_fixture
from agents.test_shared_default_ca_readiness import wrapper_args


def observed(kind='observed-legacy'):
    unit = ('hoster-mitm-default-8080.service' if kind == 'observed-legacy'
            else 'ghost-mitm-default-8080-' + 'a' * 32 + '.service')
    return {'status': kind, 'lane': 'hoster-default-8080', 'listen_host': '0.0.0.0',
            'unit': unit, 'pid': 123, 'port': 8080, 'signer': 'unverified',
            'generation_sha256': 'a' * 64}


@pytest.mark.parametrize('mode', ['ready', 'deadline', 'changed', 'unknown', 'legacy',
                                  'pending-token', 'pending-code', 'pending-lane', 'second-pending', 'digest-change'])
def test_pending_ca_retries_only_fresh_started_generation(tmp_path, monkeypatch, signer_fixture, mode):
    m = load('hoster_mitm_lane')
    ca = tmp_path / 'remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    ca.write_bytes((signer_fixture / 'a.crt').read_bytes())
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.read_text())).hexdigest()
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    local.write_bytes(b'previous CA')
    flow = '/fixture/flows-one.mitm'
    clock = [0.0]
    calls = []
    def remote(_, argv):
        op = next(x for x in ('observe-default', 'classify-default-absence', 'start', 'attest-default') if x in argv)
        calls.append(op)
        if op == 'observe-default':
            if mode == 'legacy':
                return observed('observed-legacy')
            if calls.count(op) == 1:
                return {'status': 'ssh-failed', 'remote_status': 'unknown-state', 'ssh_returncode': 2}
            return {**observed('observed-fresh'), 'flow_path_sha256': hashlib.sha256(flow.encode()).hexdigest()}
        if op == 'classify-default-absence':
            return {'status': 'not-found', 'lane': 'hoster-default-8080', 'ssh_returncode': 0}
        if op == 'start':
            return {'status': 'running', 'lane': 'hoster-default-8080', 'unit': observed('observed-fresh')['unit'],
                    'pid': 123, 'port': 8080, 'listen_host': '0.0.0.0', 'ca_cert': str(ca),
                    'ca_started_sha256': digest, 'flow_file': flow, 'ssh_returncode': 0}
        count = calls.count('attest-default')
        if mode == 'unknown':
            return {'status': 'unknown-state'}
        if mode in ('deadline', 'legacy') or count == 1 or (mode == 'second-pending' and count == 3):
            return {'status': 'ssh-failed', 'remote_status': 'ca-pending',
                    'lane': 'other' if mode == 'pending-lane' else 'hoster-default-8080',
                    'generation_sha256': ('b' if mode == 'pending-token' else 'a') * 64,
                    'ssh_returncode': 255 if mode == 'pending-code' else 2}
        return {'status': 'attested', 'lane': 'hoster-default-8080', 'signer': 'verified',
                'generation_sha256': ('b' if mode == 'changed' else 'a') * 64,
                'ca_sha256': 'b' * 64 if mode == 'digest-change' else digest,
                'ca_cert': str(ca), 'observation': 'observed-fresh',
                'listen_host': '0.0.0.0', 'ssh_returncode': 0}
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(m, 'run_remote', remote)
    monkeypatch.setattr(m, 'copy_remote_file', lambda _, src, dst: (dst.write_bytes(Path(src).read_bytes()) and {'status': 'copied'}))
    monkeypatch.setattr(m.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(m.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    result = m.ensure_default(wrapper_args(tmp_path))
    assert calls.count('start') == (0 if mode == 'legacy' else 1)
    assert 'stop' not in calls
    if mode == 'ready':
        assert result['status'] == 'running' and local.read_bytes() == ca.read_bytes()
        assert calls.count('attest-default') == 3 and clock[0] > 0
    else:
        assert result['status'] == 'start-failed' and local.read_bytes() == b'previous CA'
        if mode == 'deadline':
            assert 1 <= clock[0] <= 8.01 and calls.count('attest-default') > 1
        else:
            expected = 3 if mode == 'second-pending' else 2 if mode in ('changed', 'digest-change') else 1
            assert calls.count('attest-default') == expected


@pytest.mark.parametrize('absence', ['not-found', 'stopped'])
@pytest.mark.parametrize('local', [True, False])
def test_fresh_start_is_observed_attested_and_published(tmp_path, monkeypatch, signer_fixture, absence, local):
    m = load('hoster_mitm_lane')
    ca = tmp_path / 'remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    ca.write_bytes((signer_fixture / 'a.crt').read_bytes())
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.read_text())).hexdigest()
    flow = '/fixture/flows-one.mitm'
    seen = []
    def remote(_, argv):
        op = next(x for x in ('observe-default', 'classify-default-absence', 'start', 'attest-default') if x in argv)
        seen.append(op)
        code = {'local_returncode' if local else 'ssh_returncode': 0}
        if op == 'observe-default':
            if seen.count(op) == 1:
                return {'status': 'local-failed' if local else 'ssh-failed', 'remote_status': 'unknown-state',
                        'local_returncode' if local else 'ssh_returncode': 2}
            return {**observed('observed-fresh'), 'generation_sha256': 'a' * 64,
                    'flow_path_sha256': hashlib.sha256(flow.encode()).hexdigest()} | code
        if op == 'classify-default-absence':
            return {'status': absence, 'lane': 'hoster-default-8080'} | code
        if op == 'start':
            return {'status': 'running', 'lane': 'hoster-default-8080',
                    'unit': observed('observed-fresh')['unit'], 'pid': 123, 'port': 8080,
                    'listen_host': '0.0.0.0', 'ca_cert': str(ca), 'ca_started_sha256': digest, 'flow_file': flow} | code
        return {'status': 'attested', 'lane': 'hoster-default-8080', 'signer': 'verified',
                'generation_sha256': 'a' * 64, 'ca_sha256': digest, 'ca_cert': str(ca),
                'observation': 'observed-fresh', 'listen_host': '0.0.0.0'} | code
    monkeypatch.setattr(m, 'run_remote', remote)
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: local)
    monkeypatch.setattr(m, 'copy_remote_file', lambda _, src, dst: (dst.write_bytes(Path(src).read_bytes()) and {'status': 'copied'}))
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'running', result
    assert Path(result['local_ca_cert']).read_bytes() == ca.read_bytes()
    assert seen == ['observe-default', 'classify-default-absence', 'start', 'observe-default', 'attest-default', 'attest-default']


@pytest.mark.parametrize('failure', ['classify-unknown', 'classify-nonzero', 'start-timeout', 'start-nonzero',
                                    'start-malformed', 'changed-under-lock', 'unit-mismatch', 'token-mismatch',
                                    'flow-mismatch', 'ca-mismatch', 'tls-failure', 'copy-mismatch'])
def test_fresh_failures_preserve_ca_without_retry_or_cleanup(tmp_path, monkeypatch, signer_fixture, failure):
    m = load('hoster_mitm_lane')
    ca = tmp_path / 'remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    ca.write_bytes((signer_fixture / 'a.crt').read_bytes())
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.read_text())).hexdigest()
    flow = '/fixture/flows-one.mitm'
    old = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    old.parent.mkdir(parents=True)
    old.write_bytes(b'old ca')
    calls = []
    def remote(_, argv):
        op = next(x for x in ('observe-default', 'classify-default-absence', 'start', 'attest-default') if x in argv)
        calls.append(op)
        if op == 'observe-default':
            if calls.count(op) == 1:
                return {'status': 'ssh-failed', 'remote_status': 'unknown-state', 'ssh_returncode': 2}
            data = {**observed('observed-fresh'), 'generation_sha256': 'a' * 64,
                    'flow_path_sha256': hashlib.sha256(('different' if failure == 'flow-mismatch' else flow).encode()).hexdigest()}
            if failure == 'unit-mismatch': data['unit'] = 'ghost-mitm-default-8080-' + 'b' * 32 + '.service'
            return data
        if op == 'classify-default-absence':
            return {'status': 'unknown-state' if failure == 'classify-unknown' else 'not-found',
                    'lane': 'hoster-default-8080', 'ssh_returncode': 2 if failure == 'classify-nonzero' else 0}
        if op == 'start':
            if failure == 'start-timeout': return {'status': 'dispatch-timeout', 'detail': 'SECRET'}
            if failure in ('start-nonzero', 'changed-under-lock'): return {'status': 'ssh-failed', 'ssh_returncode': 2, 'remote_status': 'unknown-state', 'detail': 'SECRET'}
            if failure == 'start-malformed': return {'status': 'running', 'ssh_returncode': 0, 'detail': 'SECRET'}
            return {'status': 'running', 'lane': 'hoster-default-8080', 'unit': observed('observed-fresh')['unit'],
                    'pid': 123, 'port': 8080, 'listen_host': '0.0.0.0', 'ca_cert': str(ca),
                    'ca_started_sha256': digest, 'flow_file': flow, 'ssh_returncode': 0}
        if failure == 'tls-failure': return {'status': 'tls-verification-failed', 'detail': 'SECRET'}
        return {'status': 'attested', 'lane': 'hoster-default-8080', 'signer': 'verified',
                'generation_sha256': ('b' if failure == 'token-mismatch' else 'a') * 64,
                'ca_sha256': ('b' * 64 if failure == 'ca-mismatch' else digest), 'ca_cert': str(ca),
                'observation': 'observed-fresh', 'listen_host': '0.0.0.0'}
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(m, 'run_remote', remote)
    def copy(_, src, dst):
        dst.write_bytes((signer_fixture / ('b.crt' if failure == 'copy-mismatch' else 'a.crt')).read_bytes())
        return {'status': 'copied'}
    monkeypatch.setattr(m, 'copy_remote_file', copy)
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] in {'start-failed', 'start-outcome-unknown'}
    if failure in ('start-timeout', 'start-nonzero', 'start-malformed', 'changed-under-lock'):
        assert result['status'] == 'start-outcome-unknown' and 'may be running' in result['detail']
    assert calls.count('start') == (0 if failure.startswith('classify-') else 1)
    assert old.read_bytes() == b'old ca' and 'SECRET' not in json.dumps(result)


@pytest.mark.parametrize('local', [True, False])
@pytest.mark.parametrize('observation', ['observed-legacy', 'observed-fresh'])
def test_observed_listener_attested_and_ca_published(tmp_path, monkeypatch, signer_fixture, local, observation):
    m = load('hoster_mitm_lane')
    source = tmp_path / 'remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    source.parent.mkdir(parents=True)
    source.write_bytes((signer_fixture / 'a.crt').read_bytes())
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(source.read_text())).hexdigest()
    calls = []
    def remote(_, argv):
        calls.append(argv[-1])
        if argv[-1] == 'observe-default':
            return observed(observation)
        if argv[-1] == 'attest-default':
            return {'status': 'attested', 'lane': 'hoster-default-8080', 'signer': 'verified',
                    'generation_sha256': 'a' * 64, 'ca_sha256': digest, 'ca_cert': str(source),
                    'observation': observation, 'listen_host': '0.0.0.0'}
        pytest.fail('unexpected dispatch')
    monkeypatch.setattr(m, 'run_remote', remote)
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: local)
    if not local:
        monkeypatch.setattr(m, 'copy_remote_file', lambda _, src, dst: (dst.write_bytes(Path(src).read_bytes()) and {'status': 'copied'}))
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'running', result
    assert Path(result['local_ca_cert']).read_bytes() == source.read_bytes()
    assert calls == ['observe-default', 'attest-default', 'attest-default']


@pytest.mark.parametrize('kind', ['observed-legacy', 'observed-fresh'])
@pytest.mark.parametrize('token', [None, 'b' * 64])
def test_initial_observation_must_match_attestation(tmp_path, monkeypatch, signer_fixture, kind, token):
    m = load('hoster_mitm_lane')
    source = tmp_path / 'remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    source.parent.mkdir(parents=True)
    source.write_bytes((signer_fixture / 'a.crt').read_bytes())
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(source.read_text())).hexdigest()
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    local.write_bytes(b'old ca')
    calls = []
    def remote(_, argv):
        calls.append(argv[-1])
        if argv[-1] == 'observe-default':
            reply = observed(kind)
            if token is None:
                reply.pop('generation_sha256')
            else:
                reply['generation_sha256'] = token
            return reply
        assert argv[-1] == 'attest-default'
        return {'status': 'attested', 'lane': 'hoster-default-8080', 'signer': 'verified',
                'generation_sha256': 'a' * 64, 'ca_sha256': digest, 'ca_cert': str(source),
                'observation': kind, 'listen_host': '0.0.0.0'}
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: True)
    monkeypatch.setattr(m, 'run_remote', remote)
    monkeypatch.setattr(m, 'copy_remote_file', lambda *_: pytest.fail('mismatched generation copied'))
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed'
    assert calls[0] == 'observe-default' and 'start' not in calls and 'stop' not in calls
    assert local.read_bytes() == b'old ca'


@pytest.mark.parametrize('failure', ['mismatch', 'generation', 'missing', 'tls-error', 'ssh-error', 'extra-key'])
def test_attestation_or_copy_failure_preserves_old_ca(tmp_path, monkeypatch, signer_fixture, failure):
    m = load('hoster_mitm_lane')
    source = tmp_path / 'remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    source.parent.mkdir(parents=True)
    source.write_bytes((signer_fixture / ('b.crt' if failure == 'mismatch' else 'a.crt')).read_bytes())
    if failure == 'extra-key':
        source.write_bytes(source.read_bytes() + (signer_fixture / 'a.key').read_bytes())
    if failure == 'missing':
        source.unlink()
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert((signer_fixture / 'a.crt').read_text())).hexdigest()
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    local.write_bytes(b'old ca')
    attests = []
    def remote(_, argv):
        if argv[-1] == 'observe-default':
            return observed()
        attests.append(1)
        if failure in ('tls-error', 'ssh-error'):
            return {'status': 'ssh-failed', 'detail': 'SECRET'}
        return {'status': 'attested', 'lane': 'hoster-default-8080', 'signer': 'verified',
                'generation_sha256': ('b' if failure == 'generation' and len(attests) == 2 else 'a') * 64,
                'ca_sha256': digest, 'ca_cert': str(source), 'observation': 'observed-legacy', 'listen_host': '0.0.0.0'}
    monkeypatch.setattr(m, 'run_remote', remote)
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: True)
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed'
    assert local.read_bytes() == b'old ca'
    assert 'SECRET' not in json.dumps(result)
    if failure == 'generation':
        assert len(attests) == 2


@pytest.mark.parametrize('status', ['not-found', 'stopped', 'unknown-state', 'dispatch-timeout'])
def test_unverified_absence_never_dispatches_start(tmp_path, monkeypatch, status):
    m = load('hoster_mitm_lane')
    calls = []
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(m, 'run_remote', lambda _, argv: calls.append(argv[-1]) or {'status': status})
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and 'no start was attempted' in result['detail']
    assert calls == ['observe-default']


@pytest.mark.parametrize('local', [False, True])
def test_real_wrapper_transport_dispatch_and_copy(tmp_path, monkeypatch, signer_fixture, local):
    import subprocess
    m = load('hoster_mitm_lane')
    source = tmp_path / 'remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    source.parent.mkdir(parents=True)
    source.write_bytes((signer_fixture / 'a.crt').read_bytes())
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(source.read_text())).hexdigest()
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if command[0] == 'scp':
            Path(command[-1]).write_bytes(source.read_bytes())
            return subprocess.CompletedProcess(command, 0, '', 'SECRET')
        if 'attest-default' in command[-1]:
            result = {'status': 'attested', 'lane': 'hoster-default-8080', 'signer': 'verified',
                      'generation_sha256': 'a'*64, 'ca_sha256': digest, 'ca_cert': str(source),
                      'observation': 'observed-legacy', 'listen_host': '0.0.0.0'}
        else:
            result = observed()
        return subprocess.CompletedProcess(command, 0, json.dumps(result), 'SECRET')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: local)
    monkeypatch.setattr(m.subprocess, 'run', run)
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'running' and 'SECRET' not in json.dumps(result)
    assert Path(result['local_ca_cert']).read_bytes() == source.read_bytes()
    assert len(calls) == (3 if local else 4)
    assert all(command[0] == 'ssh' for command in calls if not local and command[0] != 'scp')
    assert all(command[0] == m.sys.executable for command in calls if local)


@pytest.mark.parametrize('state', ['stopped', 'starting'])
def test_public_ensure_observes_without_private_open_bind_or_start(tmp_path, monkeypatch, state):
    import builtins
    import socket
    m, w = load('mitm_lane'), load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'DEFAULT_ROOT', tmp_path)
    private = tmp_path / 'private-signer.pem'
    private.write_text('PRIVATE-SENTINEL')
    m.write_state(tmp_path, 'hoster-default-8080', {
        'status': state, 'port': 8080, 'ca_cert': str(private)})
    original_builtin, original_path = builtins.open, Path.open
    def guard(path):
        if Path(path) == private:
            pytest.fail('private signer opened')
    def open_builtin(path, *a, **kw):
        if isinstance(path, (str, Path)):
            guard(path)
        return original_builtin(path, *a, **kw)
    def open_path(path, *a, **kw):
        guard(path)
        return original_path(path, *a, **kw)
    monkeypatch.setattr(builtins, 'open', open_builtin)
    monkeypatch.setattr(Path, 'open', open_path)
    monkeypatch.setattr(socket.socket, 'bind', lambda *_: pytest.fail('socket bind'))
    monkeypatch.setattr(m, 'signer_fingerprint', lambda *_: pytest.fail('private signer'))
    monkeypatch.setattr(m, 'legacy_start_lane', lambda *_: pytest.fail('lifecycle start'))
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    calls = []
    def dispatch(_, command):
        calls.append(command[-1])
        from agents.test_shared_default_supervision import args
        if command[-1] == 'observe-default':
            assert m.observe_default(args(tmp_path))['status'] == 'unknown-state'
            return {'status': 'ssh-failed', 'ssh_returncode': 2, 'remote_status': 'unknown-state'}
        assert command[-1] == 'classify-default-absence'
        return {'status': 'unknown-state', 'ssh_returncode': 2}
    monkeypatch.setattr(w, 'run_remote', dispatch)
    result = w.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and result['start']['status'] == 'unknown-state'
    assert calls == ['observe-default', 'classify-default-absence']


@pytest.mark.parametrize('stage', [1, 2])
@pytest.mark.parametrize('bad', [
    '{"n":' + '9' * 5000 + '}', '[' * 2000 + '0' + ']' * 2000,
    '[]', '{broken', '\ud800', '{"status":"' + 'x' * 65536 + '"}',
    '{"status":"' + 'é' * 33000 + '"}',
], ids=['integer', 'nesting', 'array', 'json', 'unicode', 'chars', 'bytes'])
def test_bad_attestation_response_preserves_ca(tmp_path, monkeypatch, signer_fixture, stage, bad):
    import subprocess
    w = load('hoster_mitm_lane')
    source = tmp_path / 'remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    source.parent.mkdir(parents=True)
    source.write_bytes((signer_fixture / 'a.crt').read_bytes())
    destination = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b'old ca')
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(source.read_text())).hexdigest()
    attested = {'status': 'attested', 'lane': 'hoster-default-8080', 'signer': 'verified',
                'generation_sha256': 'a' * 64, 'ca_sha256': digest, 'ca_cert': str(source),
                'observation': 'observed-legacy', 'listen_host': '0.0.0.0'}
    calls = []
    def run(command, **kwargs):
        assert command[0] != 'scp'
        if 'observe-default' in command[-1]:
            output = json.dumps(observed())
        else:
            calls.append('attest')
            output = bad if len(calls) == stage else json.dumps(attested)
        return subprocess.CompletedProcess(command, 0, output, 'SECRET')
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: True)
    monkeypatch.setattr(w.subprocess, 'run', run)
    result = w.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and result['ca_sync']['status'] == 'copy-failed'
    assert destination.read_bytes() == b'old ca' and len(calls) == stage
    assert 'SECRET' not in json.dumps(result)


@pytest.mark.parametrize('same', [True, False])
def test_same_source_and_cleanup_after_publication(tmp_path, monkeypatch, signer_fixture, same):
    w = load('hoster_mitm_lane')
    destination = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    destination.parent.mkdir(parents=True)
    source = destination if same else tmp_path / 'remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes((signer_fixture / 'a.crt').read_bytes())
    if not same:
        destination.write_bytes(b'old ca')
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(source.read_text())).hexdigest()
    calls = []
    def remote(_, argv):
        calls.append(argv[-1])
        if argv[-1] == 'observe-default':
            return observed()
        return {'status': 'attested', 'lane': 'hoster-default-8080', 'signer': 'verified',
                'generation_sha256': 'a' * 64, 'ca_sha256': digest, 'ca_cert': str(source),
                'observation': 'observed-legacy', 'listen_host': '0.0.0.0'}
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: True)
    monkeypatch.setattr(w, 'run_remote', remote)
    original_copy = w.copy_remote_file
    def copy(args, src, dst):
        assert dst.stat().st_mode & 0o777 == 0o600
        return original_copy(args, src, dst)
    monkeypatch.setattr(w, 'copy_remote_file', copy)
    if not same:
        original_unlink = Path.unlink
        def unlink(path, *args, **kwargs):
            if path.name.startswith('.ca-sync-'):
                raise OSError('SECRET cleanup')
            return original_unlink(path, *args, **kwargs)
        monkeypatch.setattr(Path, 'unlink', unlink)
    before = destination.stat().st_ino
    result = w.ensure_default(wrapper_args(tmp_path))
    assert calls == ['observe-default', 'attest-default', 'attest-default']
    assert destination.read_bytes() == source.read_bytes()
    if same:
        assert result['status'] == 'running' and result['ca_sync']['status'] == 'already-local'
        assert destination.stat().st_ino == before
    else:
        assert result['status'] == 'start-failed' and result['ca_sync']['status'] == 'post-publication-unknown'
        assert destination.stat().st_ino != before and 'SECRET' not in json.dumps(result)


@pytest.mark.parametrize('body', ['{"n":' + '9' * 5000 + '}', '[' * 2000 + '0' + ']' * 2000, '[]', '\ud800'])
@pytest.mark.parametrize('rc', [0, 2])
def test_invalid_dispatch_response_is_sanitized(tmp_path, monkeypatch, body, rc):
    import subprocess
    w = load('hoster_mitm_lane')
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(w.subprocess, 'run', lambda cmd, **kw: subprocess.CompletedProcess(cmd, rc, body, 'SECRET'))
    result = w.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and result['start']['status'] == 'unknown-state'
    assert 'SECRET' not in json.dumps(result) and not list(tmp_path.iterdir())


def test_invalid_utf8_dispatch_is_sanitized(tmp_path, monkeypatch):
    w = load('hoster_mitm_lane')
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    def invalid(*args, **kwargs):
        raise UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'bad byte')
    monkeypatch.setattr(w.subprocess, 'run', invalid)
    result = w.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and result['start']['status'] == 'unknown-state'
    assert not list(tmp_path.iterdir())
