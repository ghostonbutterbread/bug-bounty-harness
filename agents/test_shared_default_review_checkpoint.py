"""Focused safety regressions while actual signer attestation is unavailable."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agents.test_shared_default_supervision import args, load
from agents.test_shared_default_ca_readiness import wrapper_args


@pytest.mark.parametrize('status', ['stopped', 'starting', 'start-failed'])
def test_observation_never_opens_sockets_or_private_ca(tmp_path, monkeypatch, status):
    m = load('mitm_lane')
    monkeypatch.setattr(m, 'DEFAULT_ROOT', tmp_path)
    m.write_state(tmp_path, 'hoster-default-8080', {
        'status': status, 'port': 8080, 'ca_cert': str(tmp_path / 'secret-ca'),
        'cleanup': 'stopped', 'sensitive': 'SECRET-STATE'})
    monkeypatch.setattr(m, 'can_bind_localhost', lambda *_: pytest.fail('bound socket'))
    monkeypatch.setattr(m, 'signer_fingerprint', lambda *_: pytest.fail('read private key'))
    result = m.observe_default(args(tmp_path))
    assert result['status'] == 'unknown-state'
    assert 'SECRET-STATE' not in json.dumps(result)


def test_observation_real_cli_handles_stopped_state_without_socket_or_secret(tmp_path):
    home = tmp_path / 'home'
    lane = home / '.local/state/ghost/mitm-lanes/hoster-default-8080'
    lane.mkdir(parents=True)
    state = lane / 'state.json'
    raw = '{"status":"stopped","port":8080,"ca_cert":"/fixture/key","secret":"SECRET-STATE"}'
    state.write_text(raw)
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/mitm_lane.py'
    proc = subprocess.run([sys.executable, str(script), '--json', '--lane', 'hoster-default-8080',
                           'observe-default'], env={**os.environ, 'HOME': str(home)},
                          text=True, capture_output=True, check=False)
    assert proc.returncode == 2 and json.loads(proc.stdout)['status'] == 'unknown-state'
    assert not proc.stderr and 'SECRET-STATE' not in proc.stdout and state.read_text() == raw


def test_wrapper_uses_dedicated_observation_command(tmp_path, monkeypatch):
    w = load('hoster_mitm_lane')
    seen = []
    monkeypatch.setattr(w, 'run_remote', lambda _, cmd: seen.append(cmd) or {'status': 'unknown-state'})
    assert w.status_default(wrapper_args(tmp_path))['status'] == 'unknown-state'
    assert seen[0][-1] == 'observe-default'


@pytest.mark.parametrize('initial', ['not-found', 'stopped'])
def test_unavailable_attestation_never_dispatches_fresh_start(tmp_path, monkeypatch, initial):
    w = load('hoster_mitm_lane')
    seen = []
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(w, 'run_remote', lambda _, cmd: seen.append(cmd) or {'status': initial})
    result = w.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed'
    assert len(seen) == 1 and seen[0][-1] == 'observe-default'


def test_wrapper_omits_untrusted_nested_status_fields(tmp_path, monkeypatch):
    w = load('hoster_mitm_lane')
    monkeypatch.setattr(w, 'running_on_requested_hoster', lambda _: False)
    monkeypatch.setattr(w, 'run_remote', lambda *_: {
        'status': 'unknown-state', 'nested': {'secret': 'SECRET-STATE'}})
    result = w.ensure_default(wrapper_args(tmp_path))
    assert result['status'] == 'start-failed'
    assert 'SECRET-STATE' not in json.dumps(result)
