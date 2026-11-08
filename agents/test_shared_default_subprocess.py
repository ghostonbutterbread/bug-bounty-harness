"""Actual subprocess boundary against fake user-systemd, under launch.py's fence."""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys

import pytest

from agents.test_shared_default_supervision import args, load, signer_fixture, install_signer

FAKE = '''#!{python}
import json, os, signal, subprocess, sys
from pathlib import Path
state = Path(os.environ['FAKE_UNIT_STATE'])
name = Path(sys.argv[0]).name
if name == 'loginctl':
    print('yes'); raise SystemExit(0)
if name == 'systemd-run':
    unit = next(a.split('=', 1)[1] for a in sys.argv if a.startswith('--unit='))
    proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    state.write_text(json.dumps({{'pid': proc.pid, 'unit': unit, 'active': True}}))
    raise SystemExit(0)
obj = json.loads(state.read_text())
if name != 'systemctl' or obj['unit'] not in sys.argv: raise SystemExit(4)
if 'stop' in sys.argv:
    fd = os.pidfd_open(obj['pid'])
    signal.pidfd_send_signal(fd, signal.SIGTERM)
    os.close(fd)
    obj['active'] = False
    state.write_text(json.dumps(obj))
if 'show' in sys.argv:
    print('ActiveState=' + ('active' if obj['active'] else 'inactive'))
    print('MainPID=' + str(obj['pid'] if obj['active'] else 0))
    print('ControlGroup=' + ('/user.slice/fake.service' if obj['active'] else ''))
'''


@pytest.mark.skipif(os.environ.get('SHARED_DEFAULT_KERNEL_FENCE') != '1', reason='run via fenced fixture launcher')
def test_older_real_cli_rejects_supervision_flag_before_start(tmp_path, monkeypatch):
    m = load('hoster_mitm_lane')
    calls = []
    def remote(_args, argv):
        if 'status' in argv:
            return {'status': 'not-found'}
        result = subprocess.run([sys.executable, os.environ['OLD_MITM_LANE_FILE'],
                                 '--root', str(tmp_path), *argv[2:]],
                                capture_output=True, text=True, check=False)
        calls.append(result)
        return {'status': 'ssh-failed', 'ssh_stderr': result.stderr}
    monkeypatch.setattr(m, 'run_remote', remote)
    a = argparse.Namespace(lane='hoster-default-8080', port=8080, listen_host='0.0.0.0',
        proxy_host='hoster', ssh_host='hoster', program=None, task=None, agent_id=None, run_id=None,
        account_label=None, runtime_host=None, transport='mixed', session_source=None,
        dry_run=False, timeout=30)
    result = m.ensure_default(a)
    assert result['status'] == 'start-failed'
    assert len(calls) == 1 and calls[0].returncode == 2
    assert "invalid choice: 'observe-default'" in calls[0].stderr
    assert not (tmp_path / 'hoster-default-8080').exists()


@pytest.mark.skipif(os.environ.get('SHARED_DEFAULT_KERNEL_FENCE') != '1', reason='run via fenced fixture launcher')
def test_fake_user_systemd_subprocess_survives_dispatch_and_stops_exact_unit(tmp_path, monkeypatch, signer_fixture):
    m = load('mitm_lane')
    ca = tmp_path / 'hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem'
    ca.parent.mkdir(parents=True)
    install_signer(ca, signer_fixture)
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    for name in ('loginctl', 'systemd-run', 'systemctl'):
        path = bindir / name
        path.write_text(FAKE.format(python=sys.executable))
        path.chmod(0o700)
    store = tmp_path / 'unit.json'
    monkeypatch.setenv('PATH', str(bindir))
    monkeypatch.setenv('FAKE_UNIT_STATE', str(store))
    monkeypatch.setattr(m, 'can_bind_localhost', lambda port: True)
    monkeypatch.setattr(m, 'wait_for_port', lambda port: True)
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch, assume_observed=True)
    pidfd = None
    try:
        result = m.start_lane(args(tmp_path))
        assert result['status'] == 'running', result
        record = json.loads(store.read_text())
        assert record['unit'] == result['unit'] and record['pid'] == result['pid']
        assert len([c for c in calls if c[0] == 'systemd-run']) == 1
        pidfd = os.pidfd_open(record['pid'])
        assert not select.select([pidfd], [], [], 0)[0]  # child survived dispatch exit
        assert m.stop_started_unit(record['unit'], m.user_systemd_env())
        assert select.select([pidfd], [], [], 5)[0]  # exact child exited
        assert not json.loads(store.read_text())['active']
    finally:
        if pidfd is not None:
            if not select.select([pidfd], [], [], 0)[0]:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            os.close(pidfd)


@pytest.mark.skipif(os.environ.get('SHARED_DEFAULT_KERNEL_FENCE') != '1', reason='run via fenced fixture launcher')
def test_fake_user_systemd_timeout_preserves_spawned_process(tmp_path, monkeypatch):
    m = load('mitm_lane')
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    for name in ('loginctl', 'systemd-run', 'systemctl'):
        path = bindir / name
        path.write_text(FAKE.format(python=sys.executable))
        path.chmod(0o700)
    store = tmp_path / 'unit.json'
    monkeypatch.setenv('PATH', str(bindir))
    monkeypatch.setenv('FAKE_UNIT_STATE', str(store))
    monkeypatch.setattr(m, 'can_bind_localhost', lambda port: True)
    from agents.test_shared_default_live_identity import prepare_direct_preflight
    calls = prepare_direct_preflight(m, tmp_path, monkeypatch)
    pidfds = []
    def not_ready(_port):
        pidfds.append(os.pidfd_open(json.loads(store.read_text())['pid']))
        return False
    monkeypatch.setattr(m, 'wait_for_port', not_ready)
    try:
        result = m.start_lane(args(tmp_path))
        assert result['status'] == 'start-outcome-unknown', result
        assert json.loads(store.read_text())['active']
        assert len([c for c in calls if c[0] == 'systemd-run']) == 1
        assert not any('stop' in c for c in calls)
        assert not select.select(pidfds, [], [], 0)[0]
        assert m.read_state(tmp_path, 'hoster-default-8080')['status'] == 'starting'
    finally:
        for fd in pidfds:
            if not select.select([fd], [], [], 0)[0]:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            os.close(fd)
