#!/usr/bin/env python3
"""Task-proxy incident comparison prototype; live admission is closed."""
import argparse
import ctypes
import errno
import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import select
import signal
import socket
import sqlite3
import subprocess
import ssl
import stat
import sys
import time

ENDPOINT = 'api.ipify.org'

class Blocked(Exception):
    pass


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally repeats arbitrary invalid user input on stderr.
        print(json.dumps({'status': 'blocked', 'reason': 'invalid-arguments'}))
        raise SystemExit(2)


def live_gate():
    # Deliberately no environment or CLI override. The provider must establish
    # policy, Mullvad, namespace, listener ownership, and upstream route proof.
    raise Blocked('live task-proxy observation contract is not established')


def _safe_environment():
    return {key: os.environ[key] for key in
            ('PATH', 'HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS',
             'BROWSER_PROVISIONER_STATE') if key in os.environ}


# pidfd_open(2) is syscall 434 on the Linux architectures that provide it.
# Keep an explicit allowlist: on an unknown machine, 434 may be an unrelated
# syscall, so fail closed rather than guess.
_PIDFD_OPEN_NR = {'x86_64': 434, 'aarch64': 434}


def _pidfd_open(pid):
    """Return a pidfd bound to pid, or raise Blocked if one cannot be obtained.

    os.pidfd_open is absent from interpreters built without it (notably some
    python-build-standalone/uv CPythons) even when the running kernel supports
    the syscall. Fall back to the raw syscall so the caller fence stays active:
    whether this process can be fenced must not depend on how the interpreter
    was compiled. A kernel that genuinely lacks the syscall still fails closed.
    """
    if hasattr(os, 'pidfd_open'):
        return os.pidfd_open(pid)
    number = _PIDFD_OPEN_NR.get(os.uname().machine) if sys.platform == 'linux' else None
    if number is None:
        raise Blocked('caller identity unavailable')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_int
    libc.syscall.argtypes = (ctypes.c_long, ctypes.c_int, ctypes.c_uint)
    ctypes.set_errno(0)
    fd = libc.syscall(number, pid, 0)
    if fd < 0:
        raise Blocked('caller identity unavailable')
    return fd


def bounded_observation(state, args, timeout=15):
    """Run the observation in an exec-isolated, supervised process group.

    The supervisor monitors a pidfd for the exact caller and its control pipe,
    and kills the worker's process group on caller death or deadline. This does
    not protect against the supervisor itself being killed, detached descendants, or
    uncooperative writers. Live admission remains closed.
    """
    if not 0 < timeout <= 15:
        raise Blocked('invalid observation deadline')
    env = _safe_environment()
    deadline = time.monotonic() + timeout
    payload = json.dumps({'state': str(state), 'args': vars(args), 'deadline': deadline}).encode() + b'\n'
    # Bound both pipe writes to PIPE_BUF so caller death cannot strand a
    # supervisor blocked while forwarding an oversized request.
    if len(payload) > 4096:
        raise Blocked('observation request too large')
    # A pidfd remains bound to this exact caller even if a later fork keeps a
    # duplicate of the control pipe open.
    parent_fd = _pidfd_open(os.getpid())
    try:
        proc = subprocess.Popen([sys.executable, '-I', str(Path(__file__).resolve()), '--_supervise', str(parent_fd)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, close_fds=True,
                                pass_fds=(parent_fd,), env=env)
    finally:
        os.close(parent_fd)
    assert proc.stdin is not None and proc.stdout is not None
    try:
        proc.stdin.write(payload)
        proc.stdin.flush()
        output = select.poll()
        output.register(proc.stdout.fileno(), select.POLLIN)
        ready = dict(output.poll(math.ceil((max(0, deadline - time.monotonic()) + 1) * 1000)))
        events = ready.get(proc.stdout.fileno(), 0)
        # HUP can accompany unread data; ERR/NVAL cannot establish a response.
        if events and not events & (select.POLLERR | select.POLLNVAL):
            result = os.read(proc.stdout.fileno(), 32)
        else:
            result = b''
        if result not in (b'recorded', b'changed', b'unchanged'):
            raise Blocked('observation deadline or worker failure')
        if proc.wait(timeout=2):
            raise Blocked('observation worker failed')
        return result.decode('ascii')
    finally:
        proc.stdin.close()  # EOF instructs supervisor to kill its worker group.
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            # Do not kill the supervisor: it owns cleanup of the worker group.
            pass
        proc.stdout.close()


def _supervise(parent_fd):
    """Monitor the exact caller while holding an unreaped group leader."""
    monitor = select.poll()
    monitor.register(parent_fd, select.POLLIN)
    monitor.register(sys.stdin.fileno(), select.POLLIN)
    ready = dict(monitor.poll(15000))
    stdin_events = ready.get(sys.stdin.fileno(), 0)
    if parent_fd in ready or not stdin_events or stdin_events & (select.POLLERR | select.POLLNVAL):
        return
    payload = sys.stdin.buffer.readline(4097)
    if len(payload) > 4096 or not payload.endswith(b'\n'):
        return
    data = json.loads(payload)
    deadline = data['deadline']
    if not 0 < deadline - time.monotonic() <= 15:
        return
    # SIG_IGN survives exec and would auto-reap the leader, defeating the PID
    # ownership fence used when killing the group.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    worker = subprocess.Popen([sys.executable, '-I', str(Path(__file__).resolve()), '--_worker'],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, close_fds=True,
                              start_new_session=True, env=dict(os.environ))
    assert worker.stdin is not None and worker.stdout is not None
    completed = False
    try:
        worker.stdin.write(payload)
        worker.stdin.close()
        while time.monotonic() < deadline:
            # WNOWAIT keeps the leader's PID reserved until group cleanup.
            exited = os.waitid(os.P_PID, worker.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if exited is not None:
                completed = True
                break
            ready = monitor.poll(math.ceil(min(.02, max(0, deadline - time.monotonic())) * 1000))
            if ready:
                break  # Caller exited or closed the control pipe.
    finally:
        try:
            os.killpg(worker.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        code = worker.wait()
        os.set_blocking(worker.stdout.fileno(), False)
        try:
            result = os.read(worker.stdout.fileno(), 32)
        except BlockingIOError:
            result = b''
        worker.stdout.close()
    if completed and code == 0 and time.monotonic() < deadline and result in (b'recorded', b'changed', b'unchanged'):
        os.write(sys.stdout.fileno(), result)


def _worker():
    from browser_lifecycle import node_lock
    payload = sys.stdin.buffer.readline(4097)
    if len(payload) > 4096 or not payload.endswith(b'\n'):
        return
    data = json.loads(payload)
    args = argparse.Namespace(**data['args'])
    with node_lock(Path(data['state'])):
        result = observe(args)
    if result in ('recorded', 'changed', 'unchanged'):
        os.write(sys.stdout.fileno(), result.encode('ascii'))


def systemd_identity(unit):
    result = subprocess.run(['systemctl', '--user', 'show', unit,
                             '--property=ActiveState', '--property=InvocationID',
                             '--property=MainPID'], capture_output=True, text=True, timeout=5)
    if result.returncode:
        raise Blocked('service state unavailable')
    fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if fields.get('ActiveState') != 'active' or not fields.get('InvocationID'):
        raise Blocked('service inactive')
    return fields['InvocationID'], int(fields['MainPID'])


def lane_snapshot(args):
    state = Path(os.environ.get('BROWSER_PROVISIONER_STATE',
        '~/.local/state/ghost/browser-profile-leases/browser_provisioner.sqlite')).expanduser().resolve()
    with sqlite3.connect(state.as_uri() + '?mode=ro', uri=True) as c:
        c.row_factory = sqlite3.Row
        c.execute('BEGIN')
        row = c.execute('SELECT * FROM task_proxies WHERE agent_id=? AND run_id=?',
                        (args.agent_id, args.run_id)).fetchone()
        attempt = c.execute('SELECT lane,outcome FROM proxy_attempts WHERE agent_id=? AND run_id=?',
                            (args.agent_id, args.run_id)).fetchone()
    if (not row or row['lane'] != args.expected_lane or row['state'] != 'running'
            or row['admitted'] != 1 or not attempt or attempt['lane'] != row['lane']
            or attempt['outcome'] != 'running'):
        raise Blocked('task proxy generation unavailable')
    if row['unit'] != 'task-mitm-' + row['lane'] or not row['invocation']:
        raise Blocked('task proxy unit unavailable')
    invocation, pid = systemd_identity(row['unit'])
    if invocation != row['invocation'] or pid <= 0:
        raise Blocked('task proxy invocation changed')
    proc = Path('/proc') / str(pid)
    start = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    namespace = os.readlink(proc / 'ns/net')
    if namespace != os.readlink('/proc/self/ns/net'):
        raise Blocked('remote task proxy namespace unsupported')
    port = row['port']
    if type(port) is not int or not 1 <= port <= 65535:
        raise Blocked('invalid port')
    # Match only an IPv4 loopback LISTEN inode actually held by MainPID.
    inodes = set()
    for line in (proc / 'net/tcp').read_text().splitlines()[1:]:
        parts = line.split()
        if parts[1] == '0100007F:%04X' % port and parts[3] == '0A':
            inodes.add(parts[9])
    held = set()
    for path in (proc / 'fd').iterdir():
        try:
            held.add(os.readlink(path))
        except FileNotFoundError:
            continue  # A transient descriptor closed during enumeration.
    matching = sorted(inode for inode in inodes if 'socket:[' + inode + ']' in held)
    if len(inodes) != 1 or len(matching) != 1:
        raise Blocked('listener ownership unavailable')
    ca = Path(row['run_dir']) / 'mitmproxy' / 'mitmproxy-ca-cert.pem'
    ca_data = ca.read_bytes()
    if not ca_data or len(ca_data) > 1024 * 1024:
        raise Blocked('task proxy CA unavailable')
    return {'host': socket.gethostname(), 'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'namespace': namespace, 'agent': args.agent_id, 'run': args.run_id,
            'lane': row['lane'], 'unit': row['unit'], 'invocation': invocation,
            'pid': pid, 'start': start, 'port': port, 'listener_inode': matching[0], 'ca': str(ca),
            'ca_sha256': hashlib.sha256(ca_data).hexdigest(), 'manager': str(state),
            '_ca_data': ca_data}


def verify_capture(row, pid):
    """Verify the provisioner's recorded private capture and its live writer.

    This checks a current snapshot, not exclusion of same-UID replacement or a
    guarantee about later writes. Legacy rows without a pinned identity fail.
    """
    from browser_provisioner import verify_task_capture
    if not row['flow_path'] or not row['capture_identity']:
        raise Blocked('capture identity unavailable')
    expected = json.loads(row['capture_identity'])
    if not isinstance(expected, dict) or not isinstance(expected.get('file'), list):
        raise Blocked('capture identity unavailable')
    verify_task_capture(row)
    flow = Path(row['flow_path'])
    if (stat.S_IMODE(flow.lstat().st_mode) != 0o600 or
            stat.S_IMODE(flow.parent.lstat().st_mode) != 0o700):
        raise Blocked('capture permissions unavailable')
    proc = Path('/proc') / str(pid)
    writers = 0
    for entry in (proc / 'fd').iterdir():
        try:
            info = entry.stat()
            if [info.st_dev, info.st_ino] != expected['file']:
                continue
            fields = (proc / 'fdinfo' / entry.name).read_text().splitlines()
            flags = next(int(line.split()[1], 8) for line in fields if line.startswith('flags:'))
            if flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR):
                writers += 1
        except FileNotFoundError:
            continue
    if not writers:
        raise Blocked('capture writer unavailable')
    return {'path': row['flow_path'], 'identity': expected}


def capture_snapshot(args, snapshot):
    state = Path(snapshot['manager'])
    with sqlite3.connect(state.as_uri() + '?mode=ro', uri=True) as c:
        c.row_factory = sqlite3.Row
        row = c.execute('SELECT flow_path,capture_identity FROM task_proxies '
                        'WHERE agent_id=? AND run_id=? AND lane=? AND state=?',
                        (args.agent_id, args.run_id, args.expected_lane, 'running')).fetchone()
    if row is None:
        raise Blocked('capture generation unavailable')
    return verify_capture(row, snapshot['pid'])


def sample(snapshot):
    port = snapshot['port']
    if type(port) is not int or not 1 <= port <= 65535:
        raise Blocked('invalid listener')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    ca_text = snapshot['_ca_data'].decode('ascii')
    if not re.fullmatch(r'\s*-----BEGIN CERTIFICATE-----\s*[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*', ca_text):
        raise Blocked('expected exactly one CA certificate')
    context.load_verify_locations(cadata=ca_text)
    if context.cert_store_stats()['x509_ca'] != 1 or context.cert_store_stats()['x509'] != 1:
        raise Blocked('expected exactly one trusted CA')
    conn = http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=5)
    conn.set_tunnel(ENDPOINT, 443)
    try:
        conn.request('GET', '/', headers={'Host': ENDPOINT, 'Connection': 'close'})
        response = conn.getresponse()
        if response.status != 200:
            raise Blocked('IP endpoint returned a non-success status')
        body = response.read(129)
        if len(body) > 128:
            raise Blocked('invalid IP response')
        address = ipaddress.ip_address(body.decode('ascii').strip())
        if (not address.is_global or
                (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None) or
                (isinstance(address, ipaddress.IPv4Address) and address in ipaddress.ip_network('192.88.99.0/24'))):
            raise Blocked('response is not a public address')
        return str(address)
    finally:
        conn.close()


def private_directory(path):
    # The caller selects an existing trusted parent; do not silently create a
    # hierarchy through symlinks or repair an existing, possibly shared dir.
    path = Path(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        s = os.fstat(parent)
        if s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o700:
            raise Blocked('incident parent is not private')
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
            os.chmod(path.name, 0o700, dir_fd=parent, follow_symlinks=False)
        except FileExistsError:
            pass
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    s = os.fstat(fd)
    if s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o700:
        os.close(fd)
        raise Blocked('incident directory is not private')
    return fd


def digest(salt, address):
    return hmac.new(bytes.fromhex(salt), address.encode('ascii'), hashlib.sha256).hexdigest()


def read_record(fd, name):
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        st = os.fstat(child)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1 or st.st_size > 8192:
            raise Blocked('incident record is not private')
        with os.fdopen(child, 'r') as f:
            child = -1
            return json.load(f)
    finally:
        if child != -1:
            os.close(child)


def publish(fd, directory, name, record):
    # Linux renameat2 makes the only visible final name single-linked from its
    # first instant and refuses replacement. No hard-link crash/read gap.
    temporary = '.incident-' + secrets.token_hex(16)
    tempfd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.fchmod(tempfd, 0o600)
        with os.fdopen(tempfd, 'w') as f:
            tempfd = -1
            json.dump(record, f, sort_keys=True)
            f.flush(); os.fsync(f.fileno())
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            rename = libc.renameat2
        except AttributeError as exc:
            raise Blocked('atomic no-replace publication unavailable') from exc
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(fd, os.fsencode(temporary), fd, os.fsencode(name), 1) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        os.fsync(fd)
    finally:
        if tempfd != -1:
            os.close(tempfd)
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass


def observe(args):
    before = lane_snapshot(args)
    if (before.get('agent') != args.agent_id or before.get('run') != args.run_id or before.get('lane') != args.expected_lane):
        raise Blocked('task proxy generation mismatch')
    capture = capture_snapshot(args, before)
    # Remaining runtime, DNS and egress admission is intentionally closed.
    live_gate()
    identity = {key: value for key, value in before.items() if key != '_ca_data'}
    identity['capture'] = capture
    fd = private_directory(args.state_dir)
    try:
        name = args.incident_id + '.json'
        old = None
        if args.action == 'record':
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Blocked('incident record already exists')
        else:
            old = read_record(fd, name)
            if (not isinstance(old, dict) or type(old.get('version')) is not int
                    or old['version'] != 1 or old.get('identity') != identity
                    or not isinstance(old.get('salt'), str)
                    or not re.fullmatch(r'[0-9a-f]{64}', old['salt'])
                    or not isinstance(old.get('digest'), str)
                    or not re.fullmatch(r'[0-9a-f]{64}', old['digest'])):
                raise Blocked('incident record invalid or generation mismatch')
        address = sample(before)
        if lane_snapshot(args) != before:
            raise Blocked('task proxy identity changed during observation')
        if capture_snapshot(args, before) != capture:
            raise Blocked('capture identity changed during observation')
        if args.action == 'record':
            salt = secrets.token_hex(32)
            publish(fd, args.state_dir, name, {'version': 1, 'identity': identity, 'salt': salt, 'digest': digest(salt, address)})
            return 'recorded'
        assert old is not None
        return 'unchanged' if hmac.compare_digest(old['digest'], digest(old['salt'], address)) else 'changed'
    finally:
        os.close(fd)


def main():
    parser = PrivateArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['record', 'compare'])
    for option in ('agent-id', 'run-id', 'expected-lane', 'incident-id', 'state-dir'):
        parser.add_argument('--' + option, required=True)
    args = parser.parse_args()
    try:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.incident_id):
            raise Blocked('invalid incident identifier')
        # Preserve the exact path used by browser_provisioner.STATE: resolving a
        # symlink here could select a different .lock than the provisioner.
        state = Path(os.environ.get('BROWSER_PROVISIONER_STATE',
            '~/.local/state/ghost/browser-profile-leases/browser_provisioner.sqlite')).expanduser()
        status = bounded_observation(state, args)
        print(json.dumps({'status': status, 'source': 'task-proxy', 'route': 'unverified'}))
    except (Blocked, OSError, ValueError, KeyError, TypeError, IndexError, UnicodeError,
            sqlite3.Error, subprocess.SubprocessError, http.client.HTTPException):
        # Never echo exceptions: they can contain addresses or response data.
        print(json.dumps({'status': 'blocked', 'reason': 'observation-unavailable'}))
        raise SystemExit(2)

if __name__ == '__main__':
    supervisor_mode = len(sys.argv) == 3 and sys.argv[1] == '--_supervise'
    worker_mode = sys.argv[1:] == ['--_worker']
    if supervisor_mode or worker_mode:
        # -I excludes this script's directory; add only its own trusted modules.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        try:
            env = _safe_environment()
            # Clearing os.environ does not scrub the kernel's initial environ
            # visible via /proc; re-exec direct internal invocations that
            # arrived with extra variables, before doing any observation.
            inherited = Path('/proc/self/environ').read_bytes().split(b'\0')
            allowed = {os.fsencode(key) for key in env}
            parent_fd = int(sys.argv[2]) if supervisor_mode else None
            if parent_fd is not None:
                if parent_fd < 3 or os.readlink('/proc/self/fd/' + str(parent_fd)) != 'anon_inode:[pidfd]':
                    raise Blocked('caller identity unavailable')
            # The soft RLIMIT_NOFILE may have been lowered after a high-numbered
            # fd was opened. Enumerate the actual table, not SC_OPEN_MAX. This
            # entrypoint is single-threaded; failure to inspect /proc is fatal.
            for entry in os.listdir('/proc/self/fd'):
                fd = int(entry)
                if fd >= 3 and fd != parent_fd:
                    try:
                        os.close(fd)
                    except OSError as exc:
                        if exc.errno != errno.EBADF:  # listdir's own fd is gone
                            raise
            if any(item and item.partition(b'=')[0] not in allowed for item in inherited):
                os.execve(sys.executable, [sys.executable, '-I', str(Path(__file__).resolve()), *sys.argv[1:]], env)
            os.environ.clear()
            os.environ.update(env)
            if parent_fd is not None:
                os.set_inheritable(parent_fd, False)
                _supervise(parent_fd)
            else:
                _worker()
        except BaseException:
            raise SystemExit(2) from None
    else:
        main()
