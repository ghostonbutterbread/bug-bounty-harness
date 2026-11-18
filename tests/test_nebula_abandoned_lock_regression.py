"""Exercise the public holder CLI against a disposable local SSH/flock fixture."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from test_nebula_disconnect_lock import available, fixture_env, line_with_timeout, stop, wait_until


def invoke(env, *args):
    launcher = Path(env['HOME']) / 'checkout/scripts/bbh'
    return subprocess.run([sys.executable, str(launcher),
                           'skills/nebula-browser-lane/scripts/hold_lane.py', *args],
                          env=env, capture_output=True, text=True, timeout=5)


def start(env, receipt, timeout='0.7'):
    launcher = Path(env['HOME']) / 'checkout/scripts/bbh'
    return subprocess.Popen([sys.executable, str(launcher),
                             'skills/nebula-browser-lane/scripts/hold_lane.py',
                             '--receipt', str(receipt), '--timeout', timeout],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)


def test_documented_entry_releases_after_observed_idle(tmp_path):
    env = fixture_env(tmp_path)
    receipt = tmp_path / 'lease.json'
    holder = start(env, receipt)
    try:
        assert line_with_timeout(holder).startswith('nebula lane lock held')
        assert receipt.is_file() and not available(env)
        assert receipt.stat().st_mode & 0o777 == 0o600
        holder.wait(timeout=5)
        wait_until(lambda: available(env))
        result = invoke(env, 'renew', '--receipt', str(receipt))
        assert result.returncode != 0 and 're-acquire' in result.stderr
    finally:
        stop(holder)


def test_renewal_extends_only_current_generation_and_reacquire(tmp_path):
    env = fixture_env(tmp_path)
    old = tmp_path / 'old.json'
    new = tmp_path / 'new.json'
    sentinel = tmp_path / 'personal-data'
    sentinel.write_text('preserve')
    owner = start(env, old, '4')
    unrelated = subprocess.Popen(['/bin/sleep', '30'], env=env)
    successor = None
    try:
        ready = line_with_timeout(owner)
        assert ready.startswith('nebula lane lock held')
        ssh_pid = int(ready.split('ssh pid ')[1].split(')')[0])
        inode = Path(env['FIXTURE_LOCK']).stat().st_ino
        time.sleep(2.2)
        assert invoke(env, 'renew', '--receipt', str(old)).returncode == 0
        time.sleep(2.2)
        assert owner.poll() is None and not available(env)
        owner.wait(timeout=6)
        wait_until(lambda: available(env))
        assert Path(env['FIXTURE_LOCK']).stat().st_ino == inode
        assert sentinel.read_text() == 'preserve'
        assert unrelated.poll() is None
        try:
            os.kill(ssh_pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError('expired holder did not reap exact SSH child')
        successor = start(env, new, '3')
        assert line_with_timeout(successor).startswith('nebula lane lock held')
        stale = invoke(env, 'renew', '--receipt', str(old))
        assert stale.returncode != 0 and 're-acquire' in stale.stderr
        forged = tmp_path / 'stale-on-new.json'
        old_data = json.loads(old.read_text())
        old_data['socket'] = json.loads(new.read_text())['socket']
        forged.write_text(json.dumps(old_data))
        result = invoke(env, 'renew', '--receipt', str(forged))
        assert result.returncode != 0 and 'stale generation' in result.stderr
        assert successor.poll() is None and not available(env)
    finally:
        if successor is not None:
            stop(successor)
        stop(owner)
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_handoff_survives_timeout_and_holder_death_until_explicit_completion(tmp_path):
    env = fixture_env(tmp_path)
    receipt = tmp_path / 'owner.json'
    owner = start(env, receipt, '0.8')
    contender = None
    successor = None
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        handoff = invoke(env, 'begin-handoff', '--receipt', str(receipt))
        assert handoff.returncode == 0, handoff.stderr
        time.sleep(1.1)
        assert owner.poll() is None and not available(env)
        assert invoke(env, 'release', '--receipt', str(receipt)).returncode != 0
        owner.kill()
        owner.wait(timeout=5)
        wait_until(lambda: available(env))
        contender = start(env, tmp_path / 'contender.json')
        _, err = contender.communicate(timeout=5)
        assert contender.returncode != 0 and 'handoff' in err
        assert available(env)
        assert invoke(env, 'renew', '--receipt', str(receipt)).returncode != 0
        other = tmp_path / 'wrong.json'
        bad = json.loads(receipt.read_text())
        bad['generation'] = 'wrong'
        other.write_text(json.dumps(bad))
        assert invoke(env, 'complete-handoff', '--receipt', str(other)).returncode != 0
        rejected = start(env, tmp_path / 'rejected.json')
        try:
            _, rejected_err = rejected.communicate(timeout=5)
            assert rejected.returncode != 0 and 'handoff' in rejected_err
        finally:
            stop(rejected)
        done = invoke(env, 'complete-handoff', '--receipt', str(receipt))
        assert done.returncode == 0 and 're-acquire' in done.stdout
        successor = start(env, tmp_path / 'successor.json')
        assert line_with_timeout(successor).startswith('nebula lane lock held')
    finally:
        if contender is not None:
            stop(contender)
        if successor is not None:
            stop(successor)
        stop(owner)


def test_release_cli_closes_exact_lease_and_old_receipt_fails(tmp_path):
    env = fixture_env(tmp_path)
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '5')
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        result = invoke(env, 'release', '--receipt', str(receipt))
        assert result.returncode == 0, result.stderr
        assert owner.wait(timeout=5) == 0
        wait_until(lambda: available(env))
        assert invoke(env, 'release', '--receipt', str(receipt)).returncode != 0
    finally:
        stop(owner)


def test_handoff_completion_live_resumes_timer(tmp_path):
    env = fixture_env(tmp_path)
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '0.8')
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        assert invoke(env, 'begin-handoff', '--receipt', str(receipt)).returncode == 0
        time.sleep(1)
        assert owner.poll() is None
        assert invoke(env, 'complete-handoff', '--receipt', str(receipt)).returncode == 0
        owner.wait(timeout=4)
        wait_until(lambda: available(env))
    finally:
        stop(owner)


def test_renewal_accepted_before_expiry_cannot_complete_after_deadline(tmp_path):
    env = fixture_env(tmp_path)
    receipt = tmp_path / 'lease.json'
    owner = start(env, receipt, '0.8')
    try:
        assert line_with_timeout(owner).startswith('nebula lane lock held')
        credentials = json.loads(receipt.read_text())
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(2)
            client.connect('\0' + credentials['socket'])
            time.sleep(0.9)
            try:
                client.sendall((json.dumps({'generation': credentials['generation'],
                                            'action': 'renew'}) + '\n').encode())
                reply = client.recv(4096)
            except (BrokenPipeError, ConnectionResetError):
                reply = b''
            assert not reply or not json.loads(reply)['ok']
        owner.wait(timeout=4)
        wait_until(lambda: available(env))
    finally:
        stop(owner)


def test_competing_cli_acquisitions_have_one_winner(tmp_path):
    env = fixture_env(tmp_path)
    contenders = [start(env, tmp_path / f'{i}.json', '30') for i in range(2)]
    try:
        wait_until(lambda: any(p.poll() is not None for p in contenders))
        alive = [p for p in contenders if p.poll() is None]
        assert len(alive) == 1
        loser = next(p for p in contenders if p.poll() is not None)
        assert loser.returncode != 0 and 'locked' in loser.stderr.read()
        assert line_with_timeout(alive[0]).startswith('nebula lane lock held')
        assert not available(env)
    finally:
        for p in contenders:
            stop(p)
