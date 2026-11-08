"""Generation-bound TLS probe tests, run only under the offline fixture fence."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agents.test_shared_default_supervision import args, signer_fixture
from agents.test_shared_default_legacy_observation import legacy
from agents.test_shared_default_fresh_observation import fresh


@pytest.fixture
def prepared(legacy, signer_fixture):
    m, root, lane, proc, state, original, fields, calls = legacy
    ca = lane / 'mitmproxy/mitmproxy-ca-cert.pem'
    ca.write_bytes((signer_fixture / 'a.crt').read_bytes())
    data = json.loads(state.read_text())
    data['ca_cert'] = str(ca)
    state.write_text(json.dumps(data))
    return m, root, lane, proc, state, fields, calls, ca


def test_stable_attestation_uses_fixed_verified_tls_argv(prepared, monkeypatch):
    m, root, lane, proc, state, fields, calls, ca = prepared
    commands = []
    def run(cmd, **kw):
        commands.append((cmd, kw))
        return subprocess.CompletedProcess(cmd, 0, b'Verify return code: 0 (ok)\n', b'SECRET')
    monkeypatch.setattr(m.subprocess, 'run', run)
    result = m.attest_default(args(root))
    assert result['status'] == 'attested'
    assert result['signer'] == 'verified'
    cmd, kw = commands[0]
    assert cmd == ['openssl', 's_client', '-proxy', '127.0.0.1:8080', '-connect', 'example.com:443',
                   '-servername', 'example.com', '-verify_hostname', 'example.com', '-CAfile', str(ca),
                   '-no-CApath', '-no-CAstore', '-verify_return_error']
    assert kw['timeout'] > 0 and kw['stdin'] == subprocess.DEVNULL
    assert kw['stderr'] == subprocess.DEVNULL
    assert 'SECRET' not in json.dumps(result)


@pytest.mark.parametrize(('rc', 'output'), [(1, b'Verify return code: 0 (ok)\n'),
    (0, b''), (0, b'Verify return code: 20 (unable to get issuer certificate)\n'),
    (0, b'junk\xff'), (0, 'Verify return code: 0 (ok)')])
def test_unverified_or_invalid_tls_output_fails_safely(prepared, monkeypatch, rc, output):
    m, root, *_ = prepared
    monkeypatch.setattr(m.subprocess, 'run', lambda cmd, **kw: subprocess.CompletedProcess(cmd, rc, output, b'PRIVATE'))
    result = m.attest_default(args(root))
    assert result['status'] == 'tls-verification-failed'
    assert 'PRIVATE' not in json.dumps(result) and 'junk' not in json.dumps(result)


@pytest.mark.parametrize(('error', 'expected'), [(subprocess.TimeoutExpired('SECRET', 12), 'tls-timeout'),
    (OSError('SECRET'), 'tls-unavailable')])
def test_tls_errors_are_sanitized(prepared, monkeypatch, error, expected):
    m, root, *_ = prepared
    def fail(*a, **kw):
        raise error
    monkeypatch.setattr(m.subprocess, 'run', fail)
    result = m.attest_default(args(root))
    assert result['status'] == expected and 'SECRET' not in json.dumps(result)


@pytest.mark.parametrize('change', ['invocation', 'pid', 'ticks', 'socket', 'flow', 'state', 'ca'])
def test_changed_generation_or_ca_is_unknown(prepared, signer_fixture, monkeypatch, change):
    m, root, lane, proc, state, fields, calls, ca = prepared
    def run(cmd, **kw):
        if change == 'invocation': fields['InvocationID'] = '2' * 32
        if change == 'pid': fields['MainPID'] = '203'
        if change == 'ticks': (proc / 'stat').write_text('202 (mitmdump) S ' + '0 ' * 18 + '556 0\n')
        if change == 'socket':
            (proc / 'fd/7').unlink()
            (proc / 'fd/7').symlink_to('socket:[9002]')
            table = proc / 'net/tcp'
            table.write_text(table.read_text().replace('9001', '9002'))
        if change == 'flow':
            (proc / 'fd/6').unlink()
            (lane / 'flows.mitm').rename(lane / 'previous-capture.mitm')
            (lane / 'flows.mitm').write_bytes(b'new capture')
            (proc / 'fd/6').symlink_to(lane / 'flows.mitm')
        if change == 'state': state.write_text(state.read_text().replace('"pid": 101', '"pid": 102'))
        if change == 'ca': ca.write_bytes((signer_fixture / 'b.crt').read_bytes())
        return subprocess.CompletedProcess(cmd, 0, b'Verify return code: 0 (ok)\n', b'')
    monkeypatch.setattr(m.subprocess, 'run', run)
    assert m.attest_default(args(root))['status'] == 'unknown-state'


def test_unexpected_ca_or_private_material_is_rejected(prepared, signer_fixture, monkeypatch):
    m, root, lane, proc, state, fields, calls, ca = prepared
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: pytest.fail('unexpected TLS probe'))
    ca.write_bytes(ca.read_bytes() + (signer_fixture / 'a.key').read_bytes())
    assert m.attest_default(args(root))['status'] == 'unknown-state'
    data = json.loads(state.read_text())
    data['ca_cert'] = '/unexpected;SECRET'
    state.write_text(json.dumps(data))
    assert m.attest_default(args(root))['status'] == 'unknown-state'


def test_invalid_observer_result_fails_closed(prepared, monkeypatch):
    m, root, *_ = prepared
    monkeypatch.setattr(m, 'default_generation_observation', lambda *a, **kw: {'status': 'observed-legacy', 'secret': 'SECRET'})
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: pytest.fail('unexpected TLS probe'))
    result = m.attest_default(args(root))
    assert result['status'] == 'unknown-state' and 'SECRET' not in json.dumps(result)


def test_fresh_generation_succeeds_and_identity_is_not_exposed(fresh, signer_fixture, monkeypatch):
    m, root, lane, proc, state, fields, calls, data = fresh
    ca = lane / 'mitmproxy/mitmproxy-ca-cert.pem'
    ca.write_bytes((signer_fixture / 'a.crt').read_bytes())
    monkeypatch.setattr(m.subprocess, 'run', lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, b'Verify return code: 0 (ok)\n', b''))
    result = m.attest_default(args(root))
    assert result['status'] == 'attested'
    assert set(result) == {'status', 'lane', 'signer', 'generation_sha256', 'ca_sha256', 'ca_cert', 'observation', 'listen_host', 'detail'}
    assert result['ca_cert'] == str(ca)
    assert len(result['generation_sha256']) == len(result['ca_sha256']) == 64
    assert '_identity' not in result and 'pid' not in result


def test_missing_fresh_ca_is_pending_only_for_stable_generation(fresh, monkeypatch):
    m, root, lane, proc, state, fields, calls, data = fresh
    ca = lane / 'mitmproxy/mitmproxy-ca-cert.pem'
    ca.unlink(missing_ok=True)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: pytest.fail('no TLS without CA'))
    result = m.attest_default(args(root))
    assert result['status'] == 'ca-pending' and len(result['generation_sha256']) == 64
    assert 'signer' not in result
    real_observe = m.default_generation_observation
    count = []
    def changed(*a, **kw):
        count.append(1)
        result = real_observe(*a, **kw)
        if len(count) == 2 and result is not None:
            result['_identity'] = ('changed',) * 4
        return result
    monkeypatch.setattr(m, 'default_generation_observation', changed)
    assert m.attest_default(args(root))['status'] == 'unknown-state'


def test_missing_fresh_ca_cli_and_transport_are_nonzero(fresh, monkeypatch, capsys):
    from agents.test_shared_default_supervision import load
    m, root, lane, proc, state, fields, calls, data = fresh
    ca = lane / 'mitmproxy/mitmproxy-ca-cert.pem'
    ca.unlink(missing_ok=True)
    a = args(root)
    a.json, a.func = True, m.attest_default
    monkeypatch.setattr(m, 'parse_args', lambda: a)
    assert m.main() == 2
    output = capsys.readouterr()
    pending = json.loads(output.out)
    assert pending['status'] == 'ca-pending' and not output.err
    wrapper = load('hoster_mitm_lane')
    monkeypatch.setattr(wrapper, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(wrapper.subprocess, 'run', lambda command, **kw:
                        subprocess.CompletedProcess(command, 2, output.out, 'SECRET'))
    from agents.test_shared_default_ca_readiness import wrapper_args
    response = wrapper.run_remote(wrapper_args(root), ['bbh', 'attest-default'])
    assert response['remote_status'] == 'ca-pending'
    assert response['generation_sha256'] == pending['generation_sha256'] and response['ssh_returncode'] == 2
    assert 'SECRET' not in json.dumps(response)


def test_missing_legacy_ca_is_not_pending(prepared, monkeypatch):
    m, root, lane, proc, state, fields, calls, ca = prepared
    ca.unlink()
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **kw: pytest.fail('no TLS without CA'))
    assert m.attest_default(args(root))['status'] == 'unknown-state'


def test_cli_fails_closed_without_generation(tmp_path):
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/mitm_lane.py'
    completed = subprocess.run([sys.executable, str(script), '--json', '--lane', 'hoster-default-8080',
                                'attest-default'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=10, check=False)
    assert completed.returncode == 2
    assert json.loads(completed.stdout)['status'] == 'unknown-state'
    assert completed.stderr == b''
