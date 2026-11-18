"""Browser CLI integration with disposable local SSH and fake user systemd."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys

import pytest

from test_nebula_disconnect_lock import wait_until

from test_nebula_abandoned_lock_regression import invoke, start
from test_nebula_disconnect_lock import fixture_env, line_with_timeout, stop


def test_busy_remote_port_refuses_browser_start(tmp_path):
    env = setup_fake_systemd(tmp_path)
    with socket.socket() as occupied:
        occupied.bind(('127.0.0.1', 0))
        occupied.listen()
        env['FIXTURE_PORT'] = str(occupied.getsockname()[1])
        receipt = tmp_path / 'lease.json'
        owner = start(env, receipt, '30')
        try:
            assert line_with_timeout(owner).startswith('nebula lane lock held')
            result = invoke(env, 'browser-start', '--receipt', str(receipt))
            assert result.returncode != 0
            assert 'busy' in result.stderr.lower() and 'cleanup' in result.stderr.lower(), result.stderr
            assert not (tmp_path / 'units').exists()
            assert not (Path(env['XDG_STATE_HOME']) / 'nebula-lane/browser-start.json').exists(), (
                'confirmed busy port performed no startup and must not block cleanup of the old owner'
            )
        finally:
            stop(owner)


def setup_fake_systemd(tmp_path):
    env = fixture_env(tmp_path)
    ssh = tmp_path / 'bin/ssh'
    original = ssh.read_text()
    needle = 'remote = subprocess.Popen'
    assert original.count(needle) == 1
    ssh.write_text(original.replace(
        needle,
        "command = command.replace('PORT = 9333', 'PORT = ' + os.environ['FIXTURE_PORT'])\nif '-L' not in sys.argv:\n    os.execv('/bin/sh', ['/bin/sh', '-c', command])\nremote = subprocess.Popen"))
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        env['FIXTURE_PORT'] = str(probe.getsockname()[1])
    fake = tmp_path / 'bin/systemd-run'
    fake.write_text('''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
unit = next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--unit='))
root = pathlib.Path(os.environ['HOME']) / 'units'
root.mkdir(exist_ok=True)
args = sys.argv[1:]
(root / (unit + '.args')).write_text(json.dumps(args))
listener = "import socket,os,time; s=socket.socket(); s.bind(('127.0.0.1', int(os.environ['FIXTURE_PORT']))); s.listen(); time.sleep(60)"
p = subprocess.Popen([sys.executable, '-c', listener], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
(root / unit).write_text(str(p.pid))
''')
    fake.chmod(0o755)
    fake = tmp_path / 'bin/systemctl'
    fake.write_text('''#!/usr/bin/env python3
import os, pathlib, signal, sys, time
root = pathlib.Path(os.environ['HOME']) / 'units'
op, unit = sys.argv[2:4]
path = root / unit
if op == 'stop':
    if path.exists():
        os.kill(int(path.read_text()), signal.SIGTERM)
        path.unlink()
        time.sleep(.1)
elif op == 'show':
    if '--property=LoadState' in sys.argv:
        print('loaded' if path.exists() else 'not-found')
    else:
        print('active' if path.exists() else 'inactive')
else:
    sys.exit(2)
''')
    fake.chmod(0o755)
    return env


def test_expired_generation_cleanup_never_stops_successor(tmp_path):
    env = setup_fake_systemd(tmp_path)
    old = tmp_path / 'old.json'
    new = tmp_path / 'new.json'
    owner = start(env, old, '6')
    successor = None
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        first = invoke(env, 'browser-start', '--receipt', str(old))
        assert first.returncode == 0, first.stderr
        old_data = json.loads(old.read_text())
        owner.wait(timeout=10)
        successor = start(env, new, '30')
        assert line_with_timeout(successor).startswith('nebula lane lock held')
        new_data = json.loads(new.read_text())
        assert old_data['browser_id'] != new_data['browser_id']
        assert old_data['browser_id'] != old_data['generation']
        blocked = invoke(env, 'browser-start', '--receipt', str(new))
        assert blocked.returncode != 0 and 'busy' in blocked.stderr.lower()
        # A confirmed busy port never started this generation, so the old
        # owner's exact cleanup can proceed without discarding the new lease.
        assert invoke(env, 'browser-start', '--receipt', str(old)).returncode != 0
        assert invoke(env, 'browser-stop', '--receipt', str(old)).returncode == 0
        launched = invoke(env, 'browser-start', '--receipt', str(new))
        assert launched.returncode == 0, launched.stderr
        unit = 'nebula-lane-' + new_data['browser_id'] + '.service'
        state = tmp_path / 'units' / unit
        args = json.loads((tmp_path / 'units' / (unit + '.args')).read_text())
        profile = tmp_path / 'AI/nebula-lane/runs' / new_data['browser_id'] / 'chrome-profile'
        assert '--user-data-dir=' + str(profile) in args and profile.is_dir()
        assert new_data['generation'] not in ' '.join(args)
        assert invoke(env, 'browser-stop', '--receipt', str(old)).returncode == 0
        assert state.exists()
        assert invoke(env, 'browser-stop', '--receipt', str(new)).returncode == 0
        assert not state.exists() and profile.exists()
    finally:
        for receipt in (old, new):
            if receipt.exists():
                invoke(env, 'browser-stop', '--receipt', str(receipt))
        if successor is not None:
            stop(successor)
        stop(owner)


def test_legacy_and_malformed_browser_id_fail_before_ssh(tmp_path):
    env = setup_fake_systemd(tmp_path)
    receipt = tmp_path / 'bad.json'
    for browser_id in (None, '../other', 'a' * 31, 'a' * 32 + ';touch x'):
        receipt.write_text(json.dumps({'generation': 'old', 'socket': 'old', 'browser_id': browser_id}))
        for action in ('browser-start', 'browser-stop'):
            result = invoke(env, action, '--receipt', str(receipt))
            assert result.returncode != 0 and 'browser_id' in result.stderr
        assert not (tmp_path / 'units').exists()


def test_browser_stop_preserves_durable_human_handoff(tmp_path):
    env = setup_fake_systemd(tmp_path)
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '30')
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        assert invoke(env, 'browser-start', '--receipt', str(receipt)).returncode == 0
        assert invoke(env, 'begin-handoff', '--receipt', str(receipt)).returncode == 0
        blocked = invoke(env, 'browser-stop', '--receipt', str(receipt))
        assert blocked.returncode != 0 and 'handoff' in blocked.stderr
        owner.kill()
        owner.wait(timeout=5)
        blocked = invoke(env, 'browser-stop', '--receipt', str(receipt))
        assert blocked.returncode != 0 and 'handoff' in blocked.stderr
        assert invoke(env, 'complete-handoff', '--receipt', str(receipt)).returncode == 0
        assert invoke(env, 'browser-stop', '--receipt', str(receipt)).returncode == 0
    finally:
        if owner.poll() is None:
            invoke(env, 'complete-handoff', '--receipt', str(receipt))
        if receipt.exists():
            invoke(env, 'browser-stop', '--receipt', str(receipt))
        stop(owner)


def delayed_stop_fixture(tmp_path):
    env = setup_fake_systemd(tmp_path)
    fake = tmp_path / 'bin/systemctl'
    text = fake.read_text().replace("if op == 'stop':", """if op == 'stop':
    (root / 'stop-entered').touch()
    while not (root / 'allow-stop').exists():
        time.sleep(.02)""")
    fake.write_text(text)
    return env


def async_action(env, action, receipt):
    launcher = Path(env['HOME']) / 'checkout/scripts/bbh'
    return subprocess.Popen([sys.executable, str(launcher),
                             'skills/nebula-browser-lane/scripts/hold_lane.py',
                             action, '--receipt', str(receipt)], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_handoff_is_busy_while_browser_cleanup_is_in_flight(tmp_path):
    env = delayed_stop_fixture(tmp_path)
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '30')
    cleanup = None
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        assert invoke(env, 'browser-start', '--receipt', str(receipt)).returncode == 0
        cleanup = async_action(env, 'browser-stop', receipt)
        wait_until(lambda: (tmp_path / 'units/stop-entered').exists())
        handoff = invoke(env, 'begin-handoff', '--receipt', str(receipt))
        assert handoff.returncode != 0 and 'busy' in handoff.stderr.lower()
        (tmp_path / 'units/allow-stop').touch()
        _, err = cleanup.communicate(timeout=5)
        assert cleanup.returncode == 0, err
        assert invoke(env, 'begin-handoff', '--receipt', str(receipt)).returncode == 0
    finally:
        (tmp_path / 'units/allow-stop').touch(exist_ok=True)
        if cleanup is not None:
            cleanup.communicate(timeout=5)
        invoke(env, 'complete-handoff', '--receipt', str(receipt))
        stop(owner)


@pytest.mark.parametrize('interruption', ['signal', 'timeout'])
def test_delayed_interrupted_start_cannot_launch_after_stop_and_handoff(tmp_path, interruption):
    env = setup_fake_systemd(tmp_path)
    ssh = tmp_path / 'bin/ssh'
    ssh.write_text(ssh.read_text().replace(
        "    os.execv('/bin/sh', ['/bin/sh', '-c', command])",
        """    import pathlib, shlex
    if shlex.split(command)[-3] == 'start':
        pathlib.Path(os.environ['HOME'], 'delayed-start').write_text(command)
        os.execv('/bin/sleep', ['/bin/sleep', '60'])
    os.execv('/bin/sh', ['/bin/sh', '-c', command])"""))
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '30')
    operation = None
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        operation = async_action(env, 'browser-start', receipt)
        wait_until(lambda: (tmp_path / 'delayed-start').exists())
        if interruption == 'signal':
            operation.send_signal(signal.SIGTERM)
        _, err = operation.communicate(timeout=22)
        assert operation.returncode != 0
        if interruption == 'timeout':
            assert 'timed out' in err
        blocked = invoke(env, 'begin-handoff', '--receipt', str(receipt))
        if blocked.returncode == 0:
            assert invoke(env, 'complete-handoff', '--receipt', str(receipt)).returncode == 0
        cleanup = invoke(env, 'browser-stop', '--receipt', str(receipt))
        assert cleanup.returncode == 0, cleanup.stderr
        assert invoke(env, 'begin-handoff', '--receipt', str(receipt)).returncode == 0
        late = subprocess.run(['/bin/sh', '-c', (tmp_path / 'delayed-start').read_text()],
                              env=env, capture_output=True, text=True, timeout=8)
        unit = tmp_path / 'units' / ('nebula-lane-' + json.loads(receipt.read_text())['browser_id'] + '.service')
        assert blocked.returncode != 0, 'uncertain start allowed human handoff'
        assert late.returncode != 0 and not unit.exists(), 'late remote start launched after cleanup and handoff'
    finally:
        invoke(env, 'complete-handoff', '--receipt', str(receipt))
        if receipt.exists():
            invoke(env, 'browser-stop', '--receipt', str(receipt))
        if operation is not None and operation.poll() is None:
            operation.kill()
            operation.communicate(timeout=5)
        stop(owner)


def test_stop_waits_for_already_running_remote_start(tmp_path):
    env = setup_fake_systemd(tmp_path)
    fake = tmp_path / 'bin/systemd-run'
    text = fake.read_text()
    needle = 'unit = next('
    assert text.count(needle) == 1
    fake.write_text(text.replace(needle, """import time
(pathlib.Path(os.environ['HOME']) / 'start-entered').touch()
while not (pathlib.Path(os.environ['HOME']) / 'allow-start').exists():
    time.sleep(.02)
unit = next("""))
    ssh = tmp_path / 'bin/ssh'
    text = ssh.read_text()
    needle = "    os.execv('/bin/sh', ['/bin/sh', '-c', command])"
    assert text.count(needle) == 1
    ssh.write_text(text.replace(needle, """    import shlex
    if shlex.split(command)[-3] == 'start':
        subprocess.Popen(['/bin/sh', '-c', command], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        os.execv('/bin/sleep', ['/bin/sleep', '60'])
    os.execv('/bin/sh', ['/bin/sh', '-c', command])"""))
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '30')
    operation = cleanup = None
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        operation = async_action(env, 'browser-start', receipt)
        wait_until(lambda: (tmp_path / 'start-entered').exists())
        operation.send_signal(signal.SIGTERM)
        operation.communicate(timeout=5)
        assert operation.returncode != 0
        generation = json.loads(receipt.read_text())['browser_id']
        lock = tmp_path / 'AI/nebula-lane/browser-generations' / (generation + '.lock')
        assert subprocess.run(['flock', '-n', str(lock), 'true'], env=env).returncode != 0
        cleanup = async_action(env, 'browser-stop', receipt)
        wait_until(lambda: (Path(env['XDG_STATE_HOME']) / 'nebula-lane/browser-stop.json').exists())
        assert cleanup.poll() is None
        assert invoke(env, 'begin-handoff', '--receipt', str(receipt)).returncode != 0
        (tmp_path / 'allow-start').touch()
        _, err = cleanup.communicate(timeout=10)
        assert cleanup.returncode == 0, err
        unit = tmp_path / 'units' / ('nebula-lane-' + json.loads(receipt.read_text())['browser_id'] + '.service')
        assert not unit.exists()
        assert invoke(env, 'begin-handoff', '--receipt', str(receipt)).returncode == 0
    finally:
        (tmp_path / 'allow-start').touch(exist_ok=True)
        if cleanup is not None and cleanup.poll() is None:
            cleanup.communicate(timeout=15)
        invoke(env, 'complete-handoff', '--receipt', str(receipt))
        if receipt.exists():
            invoke(env, 'browser-stop', '--receipt', str(receipt))
        if operation is not None and operation.poll() is None:
            operation.kill()
            operation.communicate(timeout=5)
        stop(owner)


def test_uncertain_start_blocks_acquisition_until_exact_receipt_cleanup(tmp_path):
    env = setup_fake_systemd(tmp_path)
    ssh = tmp_path / 'bin/ssh'
    text = ssh.read_text()
    needle = "    os.execv('/bin/sh', ['/bin/sh', '-c', command])"
    assert text.count(needle) == 1
    ssh.write_text(text.replace(needle, """    import pathlib, shlex
    if shlex.split(command)[-3] == 'start':
        pathlib.Path(os.environ['HOME'], 'start-entered').touch()
        os.execv('/bin/sleep', ['/bin/sleep', '60'])
    os.execv('/bin/sh', ['/bin/sh', '-c', command])"""))
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '30')
    operation = contender = successor = None
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        operation = async_action(env, 'browser-start', receipt)
        wait_until(lambda: (tmp_path / 'start-entered').exists())
        operation.send_signal(signal.SIGTERM)
        operation.communicate(timeout=5)
        owner.kill()
        owner.wait(timeout=5)
        contender = start(env, tmp_path / 'contender.json')
        _, err = contender.communicate(timeout=5)
        assert contender.returncode != 0 and 'unknown' in err
        bad = json.loads(receipt.read_text())
        bad['browser_id'] = 'b' * 32
        wrong = tmp_path / 'wrong.json'
        wrong.write_text(json.dumps(bad))
        assert invoke(env, 'browser-stop', '--receipt', str(wrong)).returncode != 0
        assert invoke(env, 'browser-stop', '--receipt', str(receipt)).returncode == 0
        successor = start(env, tmp_path / 'successor.json', '30')
        assert line_with_timeout(successor).startswith('nebula lane lock held')
    finally:
        for process in (operation, contender, successor, owner):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        stop(owner)
        if successor is not None:
            stop(successor)


def test_start_that_outlives_lease_remains_reserved_until_cleanup(tmp_path):
    env = setup_fake_systemd(tmp_path)
    fake = tmp_path / 'bin/systemd-run'
    text = fake.read_text()
    needle = 'unit = next('
    assert text.count(needle) == 1
    fake.write_text(text.replace(needle, 'import time\ntime.sleep(5)\nunit = next('))
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '3')
    operation = None
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        operation = async_action(env, 'browser-start', receipt)
        _, err = operation.communicate(timeout=14)
        assert operation.returncode != 0 and 'lease lost' in err
        assert (Path(env['XDG_STATE_HOME']) / 'nebula-lane/browser-start.json').exists()
        contender = start(env, tmp_path / 'contender.json')
        try:
            _, err = contender.communicate(timeout=5)
            assert contender.returncode != 0 and 'unknown' in err
        finally:
            stop(contender)
        assert invoke(env, 'browser-stop', '--receipt', str(receipt)).returncode == 0
    finally:
        if operation is not None and operation.poll() is None:
            operation.kill()
            operation.wait(timeout=5)
        if receipt.exists():
            invoke(env, 'browser-stop', '--receipt', str(receipt))
        stop(owner)


def test_interrupted_browser_start_is_not_success(tmp_path):
    env = setup_fake_systemd(tmp_path)
    fake = tmp_path / 'bin/systemd-run'
    fake.write_text('#!/bin/sh\ntouch "$HOME/start-entered"\nsleep 3\n')
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '30')
    operation = None
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        operation = async_action(env, 'browser-start', receipt)
        wait_until(lambda: (tmp_path / 'start-entered').exists())
        operation.send_signal(signal.SIGTERM)
        operation.wait(timeout=6)
        assert operation.returncode != 0
    finally:
        if operation is not None and operation.poll() is None:
            operation.kill()
            operation.communicate(timeout=5)
        stop(owner)


def test_uncertain_stop_blocks_handoff_and_acquire_until_exact_retry(tmp_path):
    env = delayed_stop_fixture(tmp_path)
    receipt = tmp_path / 'lease.json'
    wrong = tmp_path / 'wrong.json'
    owner = start(env, receipt, '30')
    cleanup = None
    contender = None
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        assert invoke(env, 'browser-start', '--receipt', str(receipt)).returncode == 0
        cleanup = async_action(env, 'browser-stop', receipt)
        wait_until(lambda: (tmp_path / 'units/stop-entered').exists())
        cleanup.kill()
        cleanup.wait(timeout=5)
        handoff = invoke(env, 'begin-handoff', '--receipt', str(receipt))
        assert handoff.returncode != 0 and 'unknown' in handoff.stderr.lower()
        other = json.loads(receipt.read_text())
        other['browser_id'] = 'b' * 32
        wrong.write_text(json.dumps(other))
        assert invoke(env, 'browser-stop', '--receipt', str(wrong)).returncode != 0
        ssh = tmp_path / 'bin/ssh'
        original_ssh = ssh.read_text()
        ssh.write_text('#!/no/such/interpreter\n')
        assert invoke(env, 'browser-stop', '--receipt', str(receipt)).returncode != 0
        assert invoke(env, 'begin-handoff', '--receipt', str(receipt)).returncode != 0
        ssh.write_text(original_ssh)
        stop(owner)
        contender = start(env, tmp_path / 'contender.json', '30')
        _, err = contender.communicate(timeout=5)
        assert contender.returncode != 0 and 'unknown' in err.lower()
        (tmp_path / 'units/allow-stop').touch()
        retry = invoke(env, 'browser-stop', '--receipt', str(receipt))
        assert retry.returncode == 0, retry.stderr
        successor = start(env, tmp_path / 'successor.json', '30')
        try:
            assert line_with_timeout(successor).startswith('nebula lane lock held')
        finally:
            stop(successor)
    finally:
        (tmp_path / 'units/allow-stop').touch(exist_ok=True)
        if cleanup is not None and cleanup.poll() is None:
            cleanup.kill()
            cleanup.wait(timeout=5)
        if contender is not None and contender.poll() is None:
            stop(contender)
        if owner.poll() is None:
            stop(owner)


def test_interrupted_stop_preserves_marker_and_reaps_local_ssh(tmp_path):
    env = delayed_stop_fixture(tmp_path)
    ssh = tmp_path / 'bin/ssh'
    ssh.write_text(ssh.read_text().replace(
        "    os.execv('/bin/sh', ['/bin/sh', '-c', command])",
        "    open(os.path.join(os.environ['HOME'], 'browser-ssh-pid'), 'w').write(str(os.getpid()))\n    os.execv('/bin/sh', ['/bin/sh', '-c', command])"))
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '30')
    cleanup = None
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        assert invoke(env, 'browser-start', '--receipt', str(receipt)).returncode == 0
        cleanup = async_action(env, 'browser-stop', receipt)
        wait_until(lambda: (tmp_path / 'units/stop-entered').exists())
        ssh_pid = int((tmp_path / 'browser-ssh-pid').read_text())
        cleanup.send_signal(signal.SIGTERM)
        cleanup.wait(timeout=5)
        assert cleanup.returncode != 0
        try:
            os.kill(ssh_pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError('interrupted action did not reap its SSH child')
        blocked = invoke(env, 'begin-handoff', '--receipt', str(receipt))
        assert blocked.returncode != 0 and 'unknown' in blocked.stderr
        (tmp_path / 'units/allow-stop').touch()
        assert invoke(env, 'browser-stop', '--receipt', str(receipt)).returncode == 0
        assert invoke(env, 'begin-handoff', '--receipt', str(receipt)).returncode == 0
        assert invoke(env, 'complete-handoff', '--receipt', str(receipt)).returncode == 0
    finally:
        (tmp_path / 'units/allow-stop').touch(exist_ok=True)
        if cleanup is not None and cleanup.poll() is None:
            cleanup.kill()
            cleanup.wait(timeout=5)
        stop(owner)


def test_interrupted_control_returns_failure(tmp_path):
    env = setup_fake_systemd(tmp_path)
    receipt = tmp_path / 'lease.json'
    name = 'test-nebula-control-' + os.urandom(16).hex()
    receipt.write_text(json.dumps({'generation': 'fixture', 'socket': name}))
    with socket.socket(socket.AF_UNIX) as server:
        server.bind('\0' + name)
        server.listen()
        operation = async_action(env, 'renew', receipt)
        try:
            server.settimeout(5)
            conn, _ = server.accept()
            with conn:
                assert conn.recv(4096)
                operation.send_signal(signal.SIGHUP)
                _, err = operation.communicate(timeout=5)
                assert operation.returncode != 0 and 'unknown' in err
        finally:
            if operation.poll() is None:
                operation.kill()
                operation.wait(timeout=5)


def test_failed_ssh_exec_does_not_reserve_start(tmp_path):
    env = setup_fake_systemd(tmp_path)
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '30')
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        (tmp_path / 'bin/ssh').write_text('#!/no/such/interpreter\n')
        result = invoke(env, 'browser-start', '--receipt', str(receipt))
        assert result.returncode != 0
        assert not (Path(env['XDG_STATE_HOME']) / 'nebula-lane/browser-start.json').exists()
        assert invoke(env, 'begin-handoff', '--receipt', str(receipt)).returncode == 0
        assert invoke(env, 'complete-handoff', '--receipt', str(receipt)).returncode == 0
    finally:
        stop(owner)


def test_failed_ssh_exec_is_definitive_and_does_not_reserve_stop(tmp_path):
    env = setup_fake_systemd(tmp_path)
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '30')
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        (tmp_path / 'bin/ssh').write_text('#!/no/such/interpreter\n')
        # A missing interpreter makes execvp search the next PATH entry; do not
        # allow this negative fixture to fall through to the machine's real SSH.
        env['PATH'] = str(tmp_path / 'bin')
        result = invoke(env, 'browser-stop', '--receipt', str(receipt))
        assert result.returncode != 0
        handoff = invoke(env, 'begin-handoff', '--receipt', str(receipt))
        assert handoff.returncode == 0, handoff.stderr
        assert invoke(env, 'complete-handoff', '--receipt', str(receipt)).returncode == 0
    finally:
        stop(owner)


def test_lost_stop_reply_retry_fences_late_duplicate(tmp_path):
    env = setup_fake_systemd(tmp_path)
    ssh = tmp_path / 'bin/ssh'
    ssh.write_text(ssh.read_text().replace(
        "    os.execv('/bin/sh', ['/bin/sh', '-c', command])",
        """    import pathlib, shlex
    if shlex.split(command)[-3] == 'stop':
        pathlib.Path(os.environ['HOME'], 'captured-stop').write_text(command)
        lost = pathlib.Path(os.environ['HOME'], 'lose-reply')
        if lost.exists():
            subprocess.run(['/bin/sh', '-c', command], check=True)
            lost.unlink()
            sys.exit(255)
    os.execv('/bin/sh', ['/bin/sh', '-c', command])"""))
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '30')
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        assert invoke(env, 'browser-start', '--receipt', str(receipt)).returncode == 0
        (tmp_path / 'lose-reply').touch()
        lost = invoke(env, 'browser-stop', '--receipt', str(receipt))
        assert lost.returncode != 0 and 'unknown' in lost.stderr
        command = (tmp_path / 'captured-stop').read_text()
        assert invoke(env, 'begin-handoff', '--receipt', str(receipt)).returncode != 0
        retry = invoke(env, 'browser-stop', '--receipt', str(receipt))
        assert retry.returncode == 0, retry.stderr
        refused = invoke(env, 'browser-start', '--receipt', str(receipt))
        assert refused.returncode != 0 and 'generation stopped' in refused.stderr
        assert invoke(env, 'browser-stop', '--receipt', str(receipt)).returncode == 0
        assert invoke(env, 'release', '--receipt', str(receipt)).returncode == 0
        owner.wait(timeout=5)
        successor_receipt = tmp_path / 'successor.json'
        successor = start(env, successor_receipt, '30')
        try:
            assert line_with_timeout(successor).startswith('nebula lane lock held')
            assert invoke(env, 'browser-start', '--receipt', str(successor_receipt)).returncode == 0
            unit = tmp_path / 'units' / ('nebula-lane-' + json.loads(successor_receipt.read_text())['browser_id'] + '.service')
            assert unit.exists()
            late = subprocess.run(['/bin/sh', '-c', command], env=env, capture_output=True, text=True)
            assert late.returncode == 0, late.stderr
            assert unit.exists(), 'late duplicate stopped the successor unit'
            assert invoke(env, 'browser-stop', '--receipt', str(successor_receipt)).returncode == 0
        finally:
            stop(successor)
    finally:
        stop(owner)


def test_systemd_start_failure_does_not_report_browser_ready(tmp_path):
    env = setup_fake_systemd(tmp_path)
    fake = tmp_path / 'bin/systemd-run'
    fake.write_text('#!/bin/sh\nprintf "fixture start failed\\n" >&2\nexit 1\n')
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '30')
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        result = invoke(env, 'browser-start', '--receipt', str(receipt))
        assert result.returncode != 0
        assert 'start failed' in result.stderr and 'cleanup' in result.stderr
        assert 'CDP available' not in result.stdout
    finally:
        stop(owner)


def test_missing_unit_requires_verified_load_state_before_success(tmp_path):
    env = setup_fake_systemd(tmp_path)
    fake = tmp_path / 'bin/systemctl'
    original = fake.read_text()
    fake.write_text('#!/bin/sh\nprintf "systemd unavailable\\n" >&2\nexit 1\n')
    receipt = tmp_path / 'lease.json'
    receipt.write_text(json.dumps({'generation': 'old', 'socket': 'old', 'browser_id': 'a' * 32}))
    failed = invoke(env, 'browser-stop', '--receipt', str(receipt))
    assert failed.returncode != 0 and 'cannot inspect' in failed.stderr
    assert (Path(env['XDG_STATE_HOME']) / 'nebula-lane/browser-stop.json').exists()
    fake.write_text(original)
    retried = invoke(env, 'browser-stop', '--receipt', str(receipt))
    assert retried.returncode == 0, retried.stderr
    assert (tmp_path / 'AI/nebula-lane/browser-generations' / ('a' * 32 + '.stopped')).exists()


def test_systemd_unverified_stop_fails_closed(tmp_path):
    env = setup_fake_systemd(tmp_path)
    fake = tmp_path / 'bin/systemctl'
    fake.write_text('#!/bin/sh\nif [ "$2" = show ]; then case "$4" in --property=LoadState) printf "loaded\\n";; *) printf "active\\n";; esac; fi\nexit 0\n')
    receipt = tmp_path / 'lease.json'
    receipt.write_text(json.dumps({'generation': 'old', 'socket': 'old', 'browser_id': 'a' * 32}))
    result = invoke(env, 'browser-stop', '--receipt', str(receipt))
    assert result.returncode != 0 and 'not inactive' in result.stderr
