import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from agents.test_shared_default_supervision import FakeSystemd, args, load, signer_fixture, install_signer, signer_status, observed_dispatch
from agents.test_hoster_mitm_lane import base_args


def wrapper_args(tmp_path, **kw):
    return base_args(lane='hoster-default-8080', port=8080, local_lane_root=str(tmp_path), **kw)


@pytest.mark.parametrize('reuse', [True, False])
def test_copy_failure_never_reports_stale_ca_or_stops_listener(tmp_path, monkeypatch, reuse, signer_fixture):
    from agents.test_shared_default_supervision import fresh_dispatch
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    ca = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    ca.write_bytes(b'stale')
    calls = []
    public = '/remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    dispatch = observed_dispatch(public, signer_fixture) if reuse else fresh_dispatch(public, signer_fixture)[0]
    def remote(_args, argv):
        calls.append(argv)
        return dispatch(_args, argv)
    monkeypatch.setattr(m, 'run_remote', remote)
    copies = []
    monkeypatch.setattr(m, 'copy_remote_file', lambda *a: copies.append(a) or {'status': 'copy-failed', 'copy_error': 'denied'})
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed'
    assert not result.get('local_ca_cert') and ca.read_bytes() == b'stale'
    assert copies and result['ca_sync']['status'] == 'copy-failed'
    assert 'denied' not in json.dumps(result)
    assert all('stop' not in call for call in calls)
    assert sum('start' in call for call in calls) == (0 if reuse else 1)
    assert sum('attest-default' in call for call in calls) == 1


def test_local_start_rejects_ipv6_proxy_url(tmp_path):
    m = load('mitm_lane')
    result = m.start_lane(args(tmp_path, proxy_host='2001:db8::1'))
    assert result['status'] == 'unsupported-proxy-host'
    assert not list(tmp_path.iterdir())


def test_remote_wildcard_does_not_advertise_stored_loopback(tmp_path, monkeypatch, signer_fixture):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    remote_ca = '/remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    calls = []
    dispatch = observed_dispatch(remote_ca, signer_fixture)
    def remote(args, argv):
        calls.append(argv[-1])
        response = dispatch(args, argv)
        response['proxy_server'] = 'http://127.0.0.1:8080'
        return response
    monkeypatch.setattr(m, 'run_remote', remote)
    def copy(_, source, dest):
        assert source == remote_ca
        dest.write_bytes((signer_fixture / 'a.crt').read_bytes())
        return {'status': 'copied'}
    monkeypatch.setattr(m, 'copy_remote_file', copy)
    result = m.ensure_default(wrapper_args(tmp_path, proxy_host='proxy.example.test'))
    assert result['status'] == 'running'
    assert result['proxy_server'] == 'http://proxy.example.test:8080'
    assert calls == ['observe-default', 'attest-default', 'attest-default']


def test_remote_loopback_rejected_before_dispatch(tmp_path, monkeypatch):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(m, 'run_remote', lambda *a: pytest.fail('remote dispatch'))
    result = m.ensure_default(wrapper_args(tmp_path, listen_host='127.0.0.1'))
    assert result['status'] == 'start-failed' and 'loopback' in result['detail']


def test_malformed_ca_is_not_ready_or_installed(tmp_path, monkeypatch, signer_fixture):
    mitm = load('mitm_lane')
    wrapper = load('hoster_mitm_lane')
    monkeypatch.setattr(wrapper, 'running_on_requested_hoster', lambda _: True)
    source = tmp_path / 'source-ca'
    source.write_bytes(b'-----BEGIN CERTIFICATE-----\npartial')
    monkeypatch.setattr(wrapper, 'run_remote', lambda *_: signer_status(source, signer_fixture))
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    original = (Path(__file__).parent / 'fixtures/shared_default_supervision/test-ca.crt').read_bytes()
    local.write_bytes(original)
    assert not mitm.readable_ca(source)
    assert wrapper.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert': str(source)})['status'] == 'copy-failed'
    assert local.read_bytes() == original


def test_missing_ca_new_start_is_not_ready(tmp_path, monkeypatch):
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    m = load('mitm_lane')
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch)
    fake = FakeSystemd()
    monkeypatch.setattr(m.subprocess, 'run', fake.run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda p: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda *a, **kw: True)
    monkeypatch.setattr(m.time, 'sleep', lambda _: None)
    clock = iter([0, 0, 9, 9, 9, 9])
    monkeypatch.setattr(m.time, 'monotonic', lambda: next(clock, 9))
    result = m.start_lane(args(tmp_path))
    assert result['status'] == 'start-outcome-unknown'
    assert fake.active and m.read_state(tmp_path, 'hoster-default-8080')['status'] == 'starting'
    assert len([c for c in calls if c[0] == 'systemd-run']) == 1
    assert not any(c[:3] == ['systemctl', '--user', 'stop'] for c in fake.calls)


def test_reused_listener_without_ca_is_not_stopped(tmp_path, monkeypatch):
    m = load('mitm_lane')
    state = {'status': 'running', 'pid': 123, 'port': 8080, 'lane': 'hoster-default-8080',
             'listen_host': '0.0.0.0', 'ca_cert': str(tmp_path / 'missing')}
    m.write_state(tmp_path, state['lane'], state)
    monkeypatch.setattr(m, 'pid_alive', lambda _: True)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: False)
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: pytest.fail('must not stop or launch'))
    monkeypatch.setattr(m, 'wait_for_ca', lambda *_: False)
    result = m.start_lane(args(tmp_path))
    assert result['status'] == 'unknown-state'
    assert m.read_state(tmp_path, state['lane']) == state
    from agents.test_shared_default_wrapper_attestation import observed
    wrapper = load('hoster_mitm_lane')
    monkeypatch.setattr(wrapper, 'running_on_requested_hoster', lambda _: False)
    calls = []
    def remote(_, command):
        calls.append(command[-1])
        return observed() if command[-1] == 'observe-default' else {'status': 'unknown-state'}
    monkeypatch.setattr(wrapper, 'run_remote', remote)
    monkeypatch.setattr(wrapper, 'copy_remote_file', lambda *_: pytest.fail('must not copy unverified CA'))
    result = wrapper.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and not result.get('local_ca_cert')
    assert calls == ['observe-default', 'attest-default']
    assert m.read_state(tmp_path, state['lane']) == state


def test_missing_ca_cli_exit_is_nonzero(tmp_path):
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/hoster_mitm_lane.py'
    result = subprocess.run([sys.executable, str(script), '--json', '--ssh-host', 'not-this-host.invalid',
                             'ensure-default', '--listen-host', '127.0.0.1'],
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert json.loads(result.stdout)['status'] == 'start-failed'


def test_delayed_ca_within_deadline_preserves_history(tmp_path, monkeypatch, signer_fixture):
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    m = load('mitm_lane')
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch, assume_observed=True)
    fake = FakeSystemd()
    monkeypatch.setattr(m.subprocess, 'run', fake.run)
    monkeypatch.setattr(m, 'can_bind_localhost', lambda _: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda _: True)
    ca = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    sleeps = []
    def create_ca(_):
        sleeps.append(1)
        install_signer(ca, signer_fixture)
    monkeypatch.setattr(m.time, 'sleep', create_ca)
    result = m.start_lane(args(tmp_path))
    assert result['status'] == 'running' and sleeps == [1]
    assert ca.read_bytes() == (signer_fixture / 'a.crt').read_bytes() and fake.active
    assert len([c for c in calls if c[0] == 'systemd-run']) == 1


def test_reused_listener_delayed_ca_is_copied(tmp_path, monkeypatch, signer_fixture):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    source = tmp_path / 'remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    source.parent.mkdir(parents=True)
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    local.write_bytes(b'old ca')
    dispatch = observed_dispatch(source, signer_fixture)
    calls = []
    def remote(args, argv):
        calls.append(argv[-1])
        if argv[-1] == 'attest-default' and not source.exists():
            return {'status': 'unknown-state'}
        return dispatch(args, argv)
    monkeypatch.setattr(m, 'run_remote', remote)
    monkeypatch.setattr(m, 'copy_remote_file', lambda _, src, dst: (dst.write_bytes(Path(src).read_bytes()) and {'status': 'copied'}))
    first = m.ensure_default(wrapper_args(tmp_path))
    assert first['status'] == 'start-failed' and local.read_bytes() == b'old ca'
    assert calls == ['observe-default', 'attest-default']
    install_signer(source, signer_fixture)
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'running'
    assert Path(result['local_ca_cert']).read_bytes() == (signer_fixture / 'a.crt').read_bytes()
    assert calls == ['observe-default', 'attest-default', 'observe-default', 'attest-default', 'attest-default']


@pytest.mark.parametrize('reuse', [True, False])
def test_missing_remote_ca_fails_without_stopping(tmp_path, monkeypatch, reuse, signer_fixture):
    from agents.test_shared_default_supervision import fresh_dispatch
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    calls = []
    public = '/remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    dispatch = observed_dispatch(public, signer_fixture) if reuse else fresh_dispatch(public, signer_fixture)[0]
    start_calls = []
    def remote(_, argv):
        calls.append(argv[-1])
        if 'start' in argv:
            start_calls.append(argv)
        if argv[-1] == 'attest-default':
            return {'status': 'unknown-state'}  # no validated public CA
        return dispatch(_, argv)
    monkeypatch.setattr(m, 'run_remote', remote)
    monkeypatch.setattr(m, 'copy_remote_file', lambda *_: pytest.fail('copy without CA attestation'))
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and not result.get('local_ca_cert')
    assert result['ca_sync']['status'] == 'copy-failed'
    assert 'attest-default' in calls
    assert all('stop' not in call for call in calls)
    assert len(start_calls) == (0 if reuse else 1)


def test_local_copy_failure_preserves_old_ca(tmp_path, monkeypatch, signer_fixture):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: True)
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    local.write_bytes(b'old CA')
    monkeypatch.setattr(m, 'run_remote', lambda *_: signer_status(tmp_path / 'missing', signer_fixture))
    result = m.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert': str(tmp_path / 'missing')})
    assert result['status'] == 'copy-failed'
    assert local.read_bytes() == b'old CA'


def test_successful_sync_replaces_stale_ca(tmp_path, monkeypatch, signer_fixture):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: True)
    source = tmp_path / 'source-ca'
    install_signer(source, signer_fixture)
    monkeypatch.setattr(m, 'run_remote', lambda *_: signer_status(source, signer_fixture))
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    local.write_bytes(b'stale CA')
    result = m.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert': str(source)})
    assert result['status'] == 'copied' and result['local_path'] == str(local)
    assert local.read_bytes() == (signer_fixture / 'a.crt').read_bytes() and source.read_bytes() == (signer_fixture / 'a.crt').read_bytes()


def test_already_local_ca_and_loopback_endpoint(tmp_path, monkeypatch, signer_fixture):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: True)
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    install_signer(local, signer_fixture)
    calls = []
    dispatch = observed_dispatch(local, signer_fixture, kind='observed-fresh', listen_host='127.0.0.1')
    def remote(args, argv):
        calls.append(argv[-1])
        return dispatch(args, argv)
    monkeypatch.setattr(m, 'run_remote', remote)
    inode = local.stat().st_ino
    result = m.ensure_default(wrapper_args(tmp_path, listen_host='127.0.0.1'))
    assert result['status'] == 'running' and result['proxy_server'] == 'http://127.0.0.1:8080'
    assert result['ca_sync']['status'] == 'already-local' and local.read_bytes() == (signer_fixture / 'a.crt').read_bytes()
    assert local.stat().st_ino == inode
    assert calls == ['observe-default', 'attest-default', 'attest-default']


def test_existing_remote_loopback_is_rejected(tmp_path, monkeypatch, signer_fixture):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    calls = []
    dispatch = observed_dispatch('/remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem',
                                 signer_fixture, kind='observed-fresh', listen_host='127.0.0.1')
    def remote(args, argv):
        calls.append(argv[-1])
        return dispatch(args, argv)
    monkeypatch.setattr(m, 'run_remote', remote)
    monkeypatch.setattr(m, 'copy_remote_file', lambda *_: pytest.fail('unexpected copy'))
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and 'remote loopback' in result['detail'].lower()
    assert calls == ['observe-default']


def test_missing_ssh_cli_is_structured(tmp_path):
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/hoster_mitm_lane.py'
    result = subprocess.run([sys.executable, str(script), '--json', '--ssh-host', 'remote.example.test',
                             'ensure-default'], env={**os.environ, 'PATH': str(tmp_path)},
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert json.loads(result.stdout)['status'] == 'start-failed'
    assert not result.stderr


def test_missing_ca_actual_cli_returns_nonzero(tmp_path, signer_fixture):
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/hoster_mitm_lane.py'
    ssh = tmp_path / 'ssh'
    dispatch = observed_dispatch('/remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem', signer_fixture)
    observation = dispatch(None, ['observe-default'])
    marker = tmp_path / 'ssh-calls'
    ssh.write_text(f'#!{sys.executable}\nimport json, sys\nfrom pathlib import Path\n'
                   f'p = Path({str(marker)!r})\np.write_text(p.read_text() + sys.argv[-1] + "\\n" if p.exists() else sys.argv[-1] + "\\n")\n'
                   f'command = sys.argv[-1].split()[-1]\n'
                   f'replies = {{"observe-default": {observation!r}, "attest-default": {{"status": "unknown-state"}}}}\n'
                   f'print(json.dumps(replies[command]))\n')
    ssh.chmod(0o700)
    result = subprocess.run([sys.executable, str(script), '--json', '--ssh-host', 'not-this-host.invalid',
                             '--local-lane-root', str(tmp_path), 'ensure-default'],
                            env={**os.environ, 'PATH': str(tmp_path)}, capture_output=True, text=True, check=False)
    assert result.returncode == 2
    body = json.loads(result.stdout)
    assert body['status'] == 'start-failed' and body['ca_sync']['status'] == 'copy-failed'
    assert [line.split()[-1] for line in marker.read_text().splitlines()] == ['observe-default', 'attest-default']
    assert not body.get('local_ca_cert')


def test_copy_failure_actual_cli_returns_nonzero_and_preserves_stale_ca(tmp_path, signer_fixture):
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/hoster_mitm_lane.py'
    ssh = tmp_path / 'ssh'
    remote_ca = '/remote/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    dispatch = observed_dispatch(remote_ca, signer_fixture)
    observation = dispatch(None, ['observe-default'])
    attestation = dispatch(None, ['attest-default'])
    marker_ssh = tmp_path / 'ssh-calls'
    ssh.write_text(f'#!{sys.executable}\nimport json, sys\nfrom pathlib import Path\n'
                   f'p = Path({str(marker_ssh)!r})\np.write_text(p.read_text() + sys.argv[-1] + "\\n" if p.exists() else sys.argv[-1] + "\\n")\n'
                   f'replies = {{"observe-default": {observation!r}, "attest-default": {attestation!r}}}\n'
                   f'command = sys.argv[-1].split()[-1]\nprint(json.dumps(replies[command]))\n')
    ssh.chmod(0o700)
    scp = tmp_path / 'scp'
    marker = tmp_path / 'scp-called'
    scp.write_text(f'#!{sys.executable}\nimport sys\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\nsys.stderr.write("denied")\nsys.exit(1)\n')
    scp.chmod(0o700)
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    local.write_bytes(b'stale CA')
    result = subprocess.run([sys.executable, str(script), '--json', '--ssh-host', 'not-this-host.invalid',
                             '--local-lane-root', str(tmp_path), 'ensure-default'],
                            env={**os.environ, 'PATH': str(tmp_path)}, capture_output=True, text=True, check=False)
    assert result.returncode == 2
    body = json.loads(result.stdout)
    assert body['status'] == 'start-failed' and body['ca_sync']['status'] == 'copy-failed'
    assert marker.exists()
    assert [line.split()[-1] for line in marker_ssh.read_text().splitlines()] == ['observe-default', 'attest-default']
    assert 'denied' not in result.stdout and not result.stderr
    assert not body.get('local_ca_cert') and local.read_bytes() == b'stale CA'


@pytest.mark.parametrize('kind', ['missing', 'directory', 'empty'])
def test_already_local_ca_must_be_nonempty_regular_file(tmp_path, monkeypatch, kind, signer_fixture):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: True)
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    monkeypatch.setattr(m, 'run_remote', lambda *_: signer_status(local, signer_fixture))
    if kind == 'directory':
        local.mkdir()
    elif kind == 'empty':
        local.touch()
    result = m.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert': str(local)})
    assert result['status'] == 'copy-failed'


@pytest.mark.parametrize('host', ['', '0.0.0.0', '127.12.1.2', '::', '::1',
                                  '::ffff:127.0.0.1', 'localhost', 'bad/host', 'bad:8080'])
def test_invalid_remote_advertisement_fails_before_dispatch(tmp_path, monkeypatch, host):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(m, 'run_remote', lambda *_: pytest.fail('unexpected dispatch'))
    assert m.ensure_default(wrapper_args(tmp_path, proxy_host=host))['status'] == 'start-failed'


@pytest.mark.parametrize(('host', 'url'), [('proxy.example.test', 'http://proxy.example.test:8080'),
                                          ('192.0.2.1', 'http://192.0.2.1:8080')])
def test_remote_advertisement_url_formats(tmp_path, monkeypatch, host, url):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    assert m.advertised_proxy(wrapper_args(tmp_path, proxy_host=host)) == url
    assert m.advertised_proxy(wrapper_args(tmp_path, proxy_host=None, ssh_host=host)) == url


def test_local_wildcard_uses_loopback(tmp_path, monkeypatch):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: True)
    assert m.advertised_proxy(wrapper_args(tmp_path)) == 'http://127.0.0.1:8080'


@pytest.mark.parametrize('content', [b'garbage', b'-----BEGIN PRIVATE KEY-----\nno\n-----END PRIVATE KEY-----\n',
                                    b'-----BEGIN CERTIFICATE-----\ntruncated'])
def test_invalid_certificate_does_not_replace_good_ca(tmp_path, monkeypatch, content, signer_fixture):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: True)
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    valid = (Path(__file__).parent / 'fixtures/shared_default_supervision/test-ca.crt').read_bytes()
    local.write_bytes(valid)
    source = tmp_path / 'source'
    source.write_bytes(content)
    monkeypatch.setattr(m, 'run_remote', lambda *_: signer_status(source, signer_fixture))
    assert m.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert': str(source)})['status'] == 'copy-failed'
    assert local.read_bytes() == valid


def test_non_ca_x509_does_not_replace_good_ca(tmp_path, monkeypatch, signer_fixture):
    import hashlib
    import ssl
    m = load('hoster_mitm_lane')
    mitm = load('mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: True)
    fixture = Path(__file__).parent / 'fixtures/shared_default_supervision'
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    valid = (fixture / 'test-ca.crt').read_bytes()
    local.write_bytes(valid)
    source = fixture / 'test-leaf.crt'
    status = signer_status(source, signer_fixture)
    status['ca_signer_sha256'] = hashlib.sha256(ssl.PEM_cert_to_DER_cert(source.read_text())).hexdigest()
    monkeypatch.setattr(m, 'run_remote', lambda *_: status)
    copies = []
    copy = m.copy_remote_file
    def record_copy(*args):
        copies.append(args)
        return copy(*args)
    monkeypatch.setattr(m, 'copy_remote_file', record_copy)
    assert not mitm.readable_ca(source)
    assert m.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert': str(source)})['status'] == 'copy-failed'
    assert len(copies) == 1
    assert local.read_bytes() == valid


@pytest.mark.parametrize('field,value', [('alive', None), ('alive', False),
                                         ('port_open', None), ('port_open', False)])
def test_ca_sync_rejects_missing_or_dead_signer_status(tmp_path, monkeypatch, signer_fixture, field, value):
    m = load('hoster_mitm_lane')
    source = signer_fixture / 'a.crt'
    status = signer_status(source, signer_fixture)
    if value is None:
        status.pop(field)
    else:
        status[field] = value
    monkeypatch.setattr(m, 'run_remote', lambda *_: status)
    monkeypatch.setattr(m, 'copy_remote_file', lambda *_: pytest.fail('unverified signer must not be copied'))
    result = m.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert': str(source)})
    assert result['status'] == 'copy-failed'


def test_partial_ca_becomes_valid_without_exposing_partial(tmp_path, monkeypatch, signer_fixture):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: True)
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    valid = (signer_fixture / 'a.crt').read_bytes()
    local.write_bytes(valid)
    source = tmp_path / 'source'
    source.write_bytes(valid[:100])
    monkeypatch.setattr(m, 'run_remote', lambda *_: signer_status(source, signer_fixture))
    clock = [0.0]
    def finish_writing(seconds):
        assert local.read_bytes() == valid
        clock[0] += seconds
        source.write_bytes(valid)
    monkeypatch.setattr(m, 'time', SimpleNamespace(monotonic=lambda: clock[0], sleep=finish_writing))
    assert m.sync_lane_ca_until_ready(wrapper_args(tmp_path), {'ca_cert': str(source)})['status'] == 'copied'
    assert clock[0] > 0 and local.read_bytes() == valid


def test_start_timeout_reports_unknown_without_retry_or_stop(tmp_path, monkeypatch):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    calls = []
    generation = tmp_path / 'remote-state.json'
    exact_state = {'status': 'starting', 'unit': 'ghost-mitm-default-8080-test-generation.service'}
    def run(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            assert 'observe-default' in command[-1]
            return subprocess.CompletedProcess(command, 2, '{"status":"unknown-state"}', '')
        if len(calls) == 2:
            assert 'classify-default-absence' in command[-1]
            return subprocess.CompletedProcess(command, 0, '{"status":"not-found","lane":"hoster-default-8080"}', '')
        assert ' start ' in command[-1]
        generation.write_text(json.dumps(exact_state))
        raise subprocess.TimeoutExpired('secret-command', 1, output='secret-output')
    monkeypatch.setattr(m.subprocess, 'run', run)
    result = m.ensure_default(wrapper_args(tmp_path))
    assert json.loads(generation.read_text()) == exact_state
    assert result['status'] == 'start-outcome-unknown'
    assert 'may be running' in result['detail'] and 'without retrying' in result['detail']
    assert len(calls) == 3 and all(' stop' not in ' '.join(c) for c in calls)
    assert 'secret-' not in json.dumps(result)


@pytest.mark.parametrize('exc', [FileNotFoundError('secret-path'), subprocess.TimeoutExpired('secret-command', 1)])
def test_copy_dispatch_failure_is_sanitized_and_preserves_old_ca(tmp_path, monkeypatch, exc, signer_fixture):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    calls = []
    def fail(*args, **kwargs):
        calls.append(args)
        raise exc
    monkeypatch.setattr(m.subprocess, 'run', fail)
    monkeypatch.setattr(m, 'run_remote', lambda *_: signer_status('/remote/ca', signer_fixture))
    local = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    local.parent.mkdir(parents=True)
    valid = (Path(__file__).parent / 'fixtures/shared_default_supervision/test-ca.crt').read_bytes()
    local.write_bytes(valid)
    result = m.sync_lane_ca(wrapper_args(tmp_path), {'ca_cert': '/remote/ca'})
    assert result['status'] == 'copy-failed' and 'secret-' not in json.dumps(result)
    assert calls and calls[0][0][0] == 'scp'
    assert local.read_bytes() == valid


def test_failed_ssh_and_scp_stderr_are_not_exposed(tmp_path, monkeypatch):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(m.subprocess, 'run', lambda command, **kw:
                        subprocess.CompletedProcess(command, 1, '', 'secret-diagnostic'))
    a = wrapper_args(tmp_path)
    ssh = m.run_remote(a, ['bbh', 'status'])
    scp = m.copy_remote_file(a, '/remote/ca', tmp_path / 'copy')
    assert ssh['status'] == 'ssh-failed' and scp['status'] == 'copy-failed'
    assert 'secret-diagnostic' not in json.dumps([ssh, scp])


def test_timeout_main_emits_json_and_exits_nonzero(tmp_path, monkeypatch, capsys):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    a = wrapper_args(tmp_path)
    a.json, a.func = True, m.ensure_default
    monkeypatch.setattr(m, 'parse_args', lambda: a)
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            assert 'observe-default' in command[-1]
            return subprocess.CompletedProcess(command, 2, '{"status":"unknown-state"}', '')
        if len(calls) == 2:
            assert 'classify-default-absence' in command[-1]
            return subprocess.CompletedProcess(command, 0, '{"status":"not-found","lane":"hoster-default-8080"}', '')
        assert ' start ' in command[-1]
        raise subprocess.TimeoutExpired('secret-command', 1)
    monkeypatch.setattr(m.subprocess, 'run', run)
    assert m.main() == 2
    output = capsys.readouterr()
    body = json.loads(output.out)
    assert body['status'] == 'start-outcome-unknown' and 'may be running' in body['detail'] and not output.err
    assert len(calls) == 3 and all(' stop' not in ' '.join(c) for c in calls)


def test_missing_bind_information_fails_without_start_or_copy(tmp_path, monkeypatch):
    m = load('hoster_mitm_lane')
    monkeypatch.setattr(m, 'running_on_requested_hoster', lambda _: False)
    calls = []
    from agents.test_shared_default_wrapper_attestation import observed
    reply = observed()
    del reply['listen_host']
    monkeypatch.setattr(m, 'run_remote', lambda *a: calls.append(a) or reply)
    monkeypatch.setattr(m, 'copy_remote_file', lambda *_: pytest.fail('unexpected CA copy'))
    result = m.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed' and 'bind address' in result['detail']
    assert len(calls) == 1
