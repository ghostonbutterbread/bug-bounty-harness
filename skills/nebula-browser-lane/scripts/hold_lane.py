#!/usr/bin/env python3
"""Hold the Nebula lock/tunnel with an explicitly renewed lease."""
import argparse
import fcntl
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import shlex
import signal
import socket
import subprocess
import sys
import time


class Stopped(Exception):
    pass


def stop_signal(_signum, _frame):
    raise Stopped()


def state_dir():
    root = Path(os.environ.get('XDG_STATE_HOME') or Path.home() / '.local/state')
    directory = root / 'nebula-lane'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return directory


def lock_state(directory):
    fd = os.open(directory / 'coordination.lock', os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    return fd


def lock_operation(directory):
    fd = os.open(directory / 'operation.lock', os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    return fd


def sync_dir(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(data, out)
        out.flush()
        os.fsync(out.fileno())
    sync_dir(path.parent)


def read_receipt(path):
    with open(path, encoding='utf-8') as src:
        data = json.load(src)
    if not isinstance(data, dict) or not isinstance(data.get('generation'), str) or not isinstance(data.get('socket'), str):
        raise ValueError('invalid lease receipt')
    return data


def control(action, receipt_path, directory):
    receipt = read_receipt(receipt_path)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect('\0' + receipt['socket'])
            client.sendall((json.dumps({'generation': receipt['generation'], 'action': action}) + '\n').encode())
            response = json.loads(client.makefile('rb').readline(4096))
        print(response['message'], file=sys.stdout if response['ok'] else sys.stderr)
        return 0 if response['ok'] else 1
    except (OSError, ValueError, KeyError):
        # A durable reservation survives the supervisor. Only explicit completion
        # by the receipt owner may clear it, under the same coordination lock.
        if action == 'complete-handoff':
            try:
                fd = lock_state(directory)
            except BlockingIOError:
                print('lane owner state is ambiguous; defer', file=sys.stderr)
                return 1
            try:
                marker = directory / 'handoff.json'
                try:
                    reservation = read_receipt(marker)
                except (OSError, ValueError, json.JSONDecodeError):
                    print('no matching recoverable handoff; re-acquire after reconciliation', file=sys.stderr)
                    return 1
                if reservation != receipt:
                    print('handoff generation mismatch; defer', file=sys.stderr)
                    return 1
                marker.unlink()
                sync_dir(directory)
                print('handoff completed after holder loss; re-acquire before lane work')
                return 0
            finally:
                os.close(fd)
        print('lease unavailable or expired; stop lane work and re-acquire', file=sys.stderr)
        return 1


REMOTE_BROWSER = r'''
import errno, fcntl, os, socket, subprocess, sys, time
from pathlib import Path

PORT = 9333
action, browser_id, operation_id = sys.argv[1:]
unit = 'nebula-lane-' + browser_id + '.service'
runtime = '/run/user/' + str(os.getuid())
env = dict(os.environ, DISPLAY=':0', XDG_RUNTIME_DIR=runtime,
           DBUS_SESSION_BUS_ADDRESS='unix:path=' + runtime + '/bus')

def systemctl(*args):
    return subprocess.run(['systemctl', '--user', *args], env=env,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def property_value(name):
    result = systemctl('show', unit, '--property=' + name, '--value')
    if result.returncode:
        raise RuntimeError('cannot inspect exact user unit: ' + result.stderr.strip())
    return result.stdout.strip()

def active():
    return property_value('ActiveState')

# The generation lock orders every start against every stop, including delayed
# SSH continuations. Never remove these locks or tombstones while a command can
# arrive. A stopped browser ID cannot be restarted; acquire a fresh receipt.
lanes = Path.home() / 'AI' / 'nebula-lane'
locks = lanes / 'browser-generations'
locks.mkdir(mode=0o700, parents=True, exist_ok=True)
for parent in (locks.parent, locks.parent.parent, Path.home()):
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
generation_lock = open(locks / (browser_id + '.lock'), 'a')
fcntl.flock(generation_lock, fcntl.LOCK_EX)
tombstone = locks / (browser_id + '.stopped')
if action == 'start' and tombstone.exists():
    raise RuntimeError('browser generation stopped; acquire a new lease')

if action == 'stop':
    # Fence a start even when no systemd unit has yet been created.
    with open(tombstone, 'a') as fence:
        fence.flush()
        os.fsync(fence.fileno())
    directory_fd = os.open(locks, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    # A delayed duplicate must never stop a browser after a retry has succeeded.
    # Keep the per-operation completion receipt permanently, under the lane tree.
    operations = Path.home() / 'AI' / 'nebula-lane' / 'stop-operations'
    operations.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Persist any newly created lane directories before acknowledging a stop.
    for parent in (operations.parent, operations.parent.parent, Path.home()):
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    with open(operations / (operation_id + '.lock'), 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        done = operations / (operation_id + '.done')
        if not done.exists():
            load = property_value('LoadState')
            if load != 'not-found':
                if load != 'loaded':
                    raise RuntimeError('cannot verify exact unit load state: ' + load)
                result = systemctl('stop', unit)
                if result.returncode:
                    # A transient unit can disappear between inspection and stop.
                    if property_value('LoadState') != 'not-found':
                        raise RuntimeError('cannot stop exact user unit: ' + result.stderr.strip())
                else:
                    state = active()
                    if state not in ('inactive', 'failed'):
                        raise RuntimeError('unit still not inactive: ' + state)
            with open(done, 'x') as receipt:
                receipt.write(browser_id + '\n')
                receipt.flush()
                os.fsync(receipt.fileno())
        # A prior attempt may have died after creating the receipt but before
        # syncing it. Re-sync on every successful reply, including duplicates.
        with open(done, 'rb') as receipt:
            os.fsync(receipt.fileno())
        directory_fd = os.open(operations, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    print('exact browser unit stopped; profile retained')
    sys.exit(0)

with socket.socket() as probe:
    try:
        probe.bind(('127.0.0.1', PORT))
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            raise RuntimeError('remote CDP port busy; stale cleanup or owner reconciliation required') from exc
        raise RuntimeError('remote CDP bind check failed: ' + str(exc)) from exc
profile = Path.home() / 'AI' / 'nebula-lane' / 'runs' / browser_id / 'chrome-profile'
profile.mkdir(parents=True, exist_ok=True)
command = ['systemd-run', '--user', '--unit=' + unit,
           '--setenv=DISPLAY=:0', '--setenv=XDG_RUNTIME_DIR=' + runtime,
           '--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=' + runtime + '/bus',
           '--', '/usr/bin/google-chrome-stable', '--user-data-dir=' + str(profile),
           '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=' + str(PORT),
           '--remote-allow-origins=*', '--no-first-run', '--no-default-browser-check',
           '--start-maximized', 'about:blank']
result = subprocess.run(command, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
if result.returncode:
    raise RuntimeError('browser unit start failed; exact cleanup may be required: ' + result.stderr.strip())
for _ in range(50):
    if active() == 'active':
        with socket.socket() as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(('127.0.0.1', PORT)) == 0:
                print('browser unit active and CDP available; profile retained at ' + str(profile))
                sys.exit(0)
    time.sleep(0.1)
raise RuntimeError('browser startup not verified; exact browser-stop cleanup required')
'''


def browser(action, receipt_path, directory):
    receipt = read_receipt(receipt_path)
    browser_id = receipt.get('browser_id')
    if not isinstance(browser_id, str) or not re.fullmatch(r'[0-9a-f]{32}', browser_id):
        raise ValueError('receipt lacks valid browser_id; legacy browser requires owner reconciliation')
    try:
        operation_gate = lock_operation(directory)
    except BlockingIOError:
        print('browser operation busy; wait and retry', file=sys.stderr)
        return 1
    marker = directory / 'browser-stop.json'
    start_marker = directory / 'browser-start.json'
    try:
        if (directory / 'handoff.json').exists():
            print('human handoff reserved; complete it before browser operations', file=sys.stderr)
            return 1
        if start_marker.exists():
            try:
                pending_start = json.loads(start_marker.read_text())
                if pending_start != receipt:
                    raise ValueError('different receipt')
            except (OSError, ValueError, TypeError):
                print('browser start outcome unknown; original receipt and owner reconciliation required', file=sys.stderr)
                return 1
            if action != 'browser-stop':
                print('browser start outcome unknown; retry exact-receipt browser-stop first', file=sys.stderr)
                return 1
        operation_id = '-'
        new_marker = False
        if marker.exists():
            try:
                pending = json.loads(marker.read_text())
                operation_id = pending['operation_id']
                if pending['receipt'] != receipt or not re.fullmatch(r'[0-9a-f]{32}', operation_id):
                    raise ValueError('different receipt')
            except (OSError, ValueError, KeyError, TypeError):
                print('browser stop outcome unknown; original receipt and owner reconciliation required', file=sys.stderr)
                return 1
            if action != 'browser-stop':
                print('browser stop outcome unknown; retry exact-receipt browser-stop first', file=sys.stderr)
                return 1
        elif action == 'browser-stop':
            operation_id = secrets.token_hex(16)
            write_private(marker, {'receipt': receipt, 'operation_id': operation_id})
            new_marker = True
        if action == 'browser-start':
            if control('renew', receipt_path, directory):
                return 1
            write_private(start_marker, receipt)
        remote = shlex.join(['python3', '-c', REMOTE_BROWSER,
                             'start' if action == 'browser-start' else 'stop', browser_id, operation_id])
        try:
            ssh = subprocess.Popen(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                                    'nebula', remote])
        except OSError:
            # No SSH process was created. A pre-existing uncertain operation,
            # however, still needs its original retry and must remain reserved.
            if new_marker:
                marker.unlink()
                sync_dir(directory)
            if action == 'browser-start':
                start_marker.unlink()
                sync_dir(directory)
            raise
        try:
            try:
                code = ssh.wait(timeout=15)
            except subprocess.TimeoutExpired:
                print('browser SSH timed out; outcome unknown; exact browser-stop cleanup required', file=sys.stderr)
                return 1
        finally:
            if ssh.poll() is None:
                ssh.terminate()
                try:
                    ssh.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    ssh.kill()
                    ssh.wait()
        if code:
            print('browser operation failed; outcome unknown; reconcile exact cleanup', file=sys.stderr)
            return 1
        if action == 'browser-stop':
            if start_marker.exists():
                start_marker.unlink()
                sync_dir(directory)
            marker.unlink()
            sync_dir(directory)
        else:
            if control('renew', receipt_path, directory):
                print('lease lost during browser start; do not attach; exact browser-stop cleanup required', file=sys.stderr)
                return 1
            start_marker.unlink()
            sync_dir(directory)
        return 0
    finally:
        os.close(operation_gate)


def serve(child, listener, receipt, directory, timeout):
    deadline = time.monotonic() + timeout
    handoff = False
    marker = directory / 'handoff.json'
    with selectors.DefaultSelector() as selector:
        selector.register(listener, selectors.EVENT_READ, 'control')
        selector.register(child.stdout, selectors.EVENT_READ, 'ssh')
        while True:
            remaining = None if handoff else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                print('nebula lane lease expired; stop lane work and re-acquire', file=sys.stderr)
                return 0
            for key, _ in selector.select(remaining):
                if key.data == 'ssh':
                    data = os.read(child.stdout.fileno(), 4096)
                    if not data:
                        print('nebula lane SSH ended; stop lane work and re-acquire', file=sys.stderr)
                        return 1
                    continue
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(0.25)
                    try:
                        request = json.loads(conn.makefile('rb').readline(4096))
                        now = time.monotonic()
                        if not handoff and now >= deadline:
                            ok, message = False, 'lease expired; re-acquire'
                        elif request.get('generation') != receipt['generation']:
                            ok, message = False, 'stale generation; re-acquire'
                        elif request.get('action') == 'renew' and not handoff:
                            deadline = now + timeout
                            ok, message = True, 'lease renewed'
                        elif request.get('action') == 'begin-handoff' and not handoff:
                            try:
                                op_gate = lock_operation(directory)
                            except BlockingIOError:
                                ok, message = False, 'browser operation busy; retry handoff after cleanup'
                            else:
                                try:
                                    if any((directory / name).exists() for name in ('browser-start.json', 'browser-stop.json')):
                                        ok, message = False, 'browser operation outcome unknown; retry exact-receipt browser-stop before handoff'
                                    else:
                                        write_private(marker, receipt)
                                        handoff = True
                                        ok, message = True, 'handoff reserved; ask the human now'
                                finally:
                                    os.close(op_gate)
                        elif request.get('action') == 'complete-handoff' and handoff:
                            marker.unlink()
                            sync_dir(directory)
                            handoff = False
                            deadline = time.monotonic() + timeout
                            ok, message = True, 'handoff completed; lease renewed'
                        elif request.get('action') == 'release' and not handoff:
                            conn.sendall(b'{"ok":true,"message":"lease released"}\n')
                            return 0
                        else:
                            ok, message = False, 'operation unavailable in current state; complete handoff or re-acquire'
                        conn.sendall((json.dumps({'ok': ok, 'message': message}) + '\n').encode())
                    except (OSError, ValueError, AttributeError):
                        # A disconnected client must not terminate the holder.
                        continue


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=['hold', 'renew', 'begin-handoff', 'complete-handoff', 'release', 'browser-start', 'browser-stop'], default='hold')
    parser.add_argument('--receipt', type=Path, help='private run-specific receipt; required for control commands')
    parser.add_argument('--timeout', type=float, default=900, help='seconds since explicit renewal (default: 900)')
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('--timeout must be positive and finite')
    if args.action != 'hold' and args.receipt is None:
        parser.error('--receipt is required for control commands')
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, stop_signal)
    child = None
    listener = None
    gate = None
    operation_gate = None
    try:
        directory = state_dir()
        if args.action in ('browser-start', 'browser-stop'):
            return browser(args.action, args.receipt, directory)
        if args.action != 'hold':
            return control(args.action, args.receipt, directory)
        try:
            gate = lock_state(directory)
        except BlockingIOError:
            print('nebula lane locked; defer', file=sys.stderr)
            return 1
        try:
            operation_gate = lock_operation(directory)
        except BlockingIOError:
            print('browser operation busy; retry acquisition after cleanup', file=sys.stderr)
            return 1
        if any((directory / name).exists() for name in ('browser-start.json', 'browser-stop.json')):
            print('browser operation outcome unknown; retry exact-receipt browser-stop before acquisition', file=sys.stderr)
            return 1
        if (directory / 'handoff.json').exists():
            print('nebula lane has an unresolved human handoff; defer', file=sys.stderr)
            return 1
        receipt = {'generation': secrets.token_hex(32), 'socket': 'nebula-lane-' + secrets.token_hex(24),
                   'browser_id': secrets.token_hex(16)}
        receipt_path = args.receipt or directory / ('lease-' + secrets.token_hex(16) + '.json')
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind('\0' + receipt['socket'])
        listener.listen(8)
        token = 'nebula-lane-ready-' + secrets.token_hex(16)
        inner = f"printf '%s\\n' {shlex.quote(token)}; exec cat >/dev/null"
        remote = 'flock -n -E 73 /tmp/nebula-lane.lock sh -c ' + shlex.quote(inner)
        command = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ExitOnForwardFailure=yes',
                   '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3',
                   '-L', '9333:127.0.0.1:9333', 'nebula', remote]
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        assert child.stdout is not None
        deadline = time.monotonic() + 15
        buffer = b''
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if not selector.select(deadline - time.monotonic()):
                    break
                data = os.read(child.stdout.fileno(), 4096)
                if not data:
                    try:
                        code = child.wait(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        print('nebula lane SSH closed readiness output; defer', file=sys.stderr)
                        return 1
                    if code == 73:
                        print('nebula lane locked; defer', file=sys.stderr)
                    else:
                        print(f'nebula lane SSH failed before readiness (exit {code}); connection or local forwarding port 9333 may have failed; defer', file=sys.stderr)
                    return 1
                buffer += data
                if len(buffer) > 65536:
                    print('nebula lane unexpected SSH output; defer', file=sys.stderr)
                    return 1
                if token.encode() in buffer.splitlines():
                    write_private(receipt_path, receipt)
                    os.close(operation_gate)
                    operation_gate = None
                    print(f'nebula lane lock held (ssh pid {child.pid}); receipt {receipt_path}', flush=True)
                    return serve(child, listener, receipt, directory, args.timeout)
        print('nebula lane readiness timed out; defer', file=sys.stderr)
        return 1
    except Stopped:
        if args.action == 'hold':
            return 0
        print('operation interrupted; outcome unknown; inspect state and reconcile before continuing', file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f'nebula lane operation failed: {exc}; defer', file=sys.stderr)
        return 1
    finally:
        if child is not None:
            if child.stdin is not None:
                child.stdin.close()
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            if child.stdout is not None:
                child.stdout.close()
        if listener is not None:
            listener.close()
        if operation_gate is not None:
            os.close(operation_gate)
        if gate is not None:
            os.close(gate)


if __name__ == '__main__':
    sys.exit(main())