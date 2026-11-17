"""Offline process-level tests; the SSH boundary is a local pipe transport."""
import os
from pathlib import Path
import select
import shutil
import socket
import signal
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "skills/nebula-browser-lane/scripts/hold_lane.py"


def fixture_env(tmp_path):
    checkout = tmp_path / "checkout"
    (checkout / "scripts").mkdir(parents=True)
    (checkout / "skills/nebula-browser-lane/scripts").mkdir(parents=True)
    (checkout / ".venv/bin").mkdir(parents=True)
    for name in ("bbh", "bbh.py"):
        shutil.copy2(ROOT / "scripts" / name, checkout / "scripts" / name)
    shutil.copy2(HELPER, checkout / "skills/nebula-browser-lane/scripts/hold_lane.py")
    (checkout / ".venv/bin/python").symlink_to(sys.executable)
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    ssh = bindir / "ssh"
    ssh.write_text('''#!/usr/bin/env python3
import os, selectors, subprocess, sys
command = sys.argv[-1].replace('/tmp/nebula-lane.lock', os.environ['FIXTURE_LOCK'])
remote = subprocess.Popen(['/bin/sh', '-c', command], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
sel = selectors.DefaultSelector()
sel.register(sys.stdin.buffer, selectors.EVENT_READ, 'input')
sel.register(remote.stdout, selectors.EVENT_READ, 'output')
while sel.get_map():
    for key, _ in sel.select():
        data = os.read(key.fileobj.fileno(), 4096)
        if not data:
            sel.unregister(key.fileobj)
            if key.data == 'input':
                remote.stdin.close()
            continue
        if key.data == 'input':
            os.write(remote.stdin.fileno(), data)
        else:
            os.write(1, data)
    if remote.poll() is not None:
        break
sys.exit(remote.wait())
''')
    ssh.chmod(0o755)
    env = {"PATH": f"{bindir}:{Path(sys.executable).parent}:/usr/bin:/bin", "HOME": str(tmp_path),
           "XDG_CONFIG_HOME": str(tmp_path / "config"),
           "XDG_DATA_HOME": str(tmp_path / "data"),
           "XDG_CACHE_HOME": str(tmp_path / "cache"),
           "TMPDIR": str(tmp_path), "FIXTURE_LOCK": str(tmp_path / "lock")}
    return env


def start(env):
    assert HELPER.is_file(), "SSH-disconnect-safe lane holder is not implemented"
    launcher = Path(env["HOME"]) / "checkout/scripts/bbh"
    return subprocess.Popen([sys.executable, str(launcher),
                             "skills/nebula-browser-lane/scripts/hold_lane.py"], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)


def line_with_timeout(process):
    assert select.select([process.stdout], [], [], 5)[0], "holder did not report readiness"
    return process.stdout.readline()


def available(env):
    return subprocess.run(["flock", "-n", env["FIXTURE_LOCK"], "true"],
                          env=env, check=False).returncode == 0


def wait_until(predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    assert predicate(), "timed out waiting for fixture state"


def stop(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def test_ssh_disconnect_releases_lock_while_caller_stays_alive(tmp_path):
    env = fixture_env(tmp_path)
    holder = start(env)
    try:
        ready = line_with_timeout(holder)
        assert ready.startswith("nebula lane lock held"), ready
        ssh_pid = int(ready.split("ssh pid ")[1].split(")")[0])
        assert not available(env)
        os.kill(ssh_pid, signal.SIGKILL)
        holder.wait(timeout=5)
        wait_until(lambda: available(env))
        assert holder.returncode != 0
    finally:
        stop(holder)


def test_conflict_does_not_disturb_existing_owner(tmp_path):
    env = fixture_env(tmp_path)
    owner = start(env)
    contender = None
    try:
        assert line_with_timeout(owner).startswith("nebula lane lock held")
        contender = start(env)
        stdout, stderr = contender.communicate(timeout=5)
        assert contender.returncode != 0
        assert not stdout
        assert "nebula lane locked; defer" in stderr
        assert owner.poll() is None
        assert not available(env)
    finally:
        if contender is not None:
            stop(contender)
        stop(owner)


def test_legacy_flock_holder_blocks_new_holder(tmp_path):
    env = fixture_env(tmp_path)
    legacy = subprocess.Popen(["flock", "-n", env["FIXTURE_LOCK"], "sh", "-c",
                               "printf 'ready\\n'; exec sleep infinity"],
                              stdout=subprocess.PIPE,
                              text=True, env=env, start_new_session=True)
    contender = None
    try:
        assert line_with_timeout(legacy) == "ready\n"
        contender = start(env)
        stdout, stderr = contender.communicate(timeout=5)
        assert contender.returncode != 0 and not stdout
        assert "nebula lane locked; defer" in stderr
        assert legacy.poll() is None and not available(env)
    finally:
        if contender is not None:
            stop(contender)
        stop(legacy)


def test_new_holder_blocks_legacy_flock_holder(tmp_path):
    env = fixture_env(tmp_path)
    owner = start(env)
    try:
        assert line_with_timeout(owner).startswith("nebula lane lock held")
        legacy = subprocess.run(["flock", "-n", env["FIXTURE_LOCK"], "true"], env=env)
        assert legacy.returncode != 0
        assert owner.poll() is None and not available(env)
    finally:
        stop(owner)


def test_occupied_forward_port_reports_ambiguous_failure(tmp_path):
    env = fixture_env(tmp_path)
    ssh = tmp_path / "bin/ssh"
    ssh.write_text('''#!/usr/bin/env python3
import os, socket, sys
# The fixture redirects the requested forward to an isolated occupied port.
forward = sys.argv[sys.argv.index('-L') + 1]
if forward != '9333:127.0.0.1:9333':
    print('unexpected forward: ' + forward, file=sys.stderr)
    sys.exit(98)
s = socket.socket()
try:
    s.bind(('127.0.0.1', int(os.environ['FIXTURE_PORT'])))
except OSError as exc:
    print('local forwarding bind failed: ' + str(exc), file=sys.stderr)
    sys.exit(255)
sys.exit(99)
''')
    with socket.socket() as occupied:
        occupied.bind(('127.0.0.1', 0))
        occupied.listen()
        env['FIXTURE_PORT'] = str(occupied.getsockname()[1])
        holder = start(env)
        try:
            stdout, stderr = holder.communicate(timeout=5)
            assert holder.returncode != 0 and not stdout
            assert 'forward' in stderr.lower() and 'port' in stderr.lower()
            assert 'locked' not in stderr.lower()
            assert not Path(env['FIXTURE_LOCK']).exists()
        finally:
            stop(holder)


def test_closed_ssh_stdout_before_readiness_does_not_hang(tmp_path):
    env = fixture_env(tmp_path)
    ssh = tmp_path / "bin/ssh"
    ssh.write_text("#!/bin/sh\necho $$ > \"$HOME/ssh-pid\"\nexec 1>&-\nexec sleep 60\n")
    holder = start(env)
    try:
        try:
            result = holder.wait(timeout=3)
        except subprocess.TimeoutExpired:
            raise AssertionError("holder hung after SSH closed readiness output") from None
        assert result != 0
        ssh_pid = int((tmp_path / "ssh-pid").read_text())
        try:
            os.kill(ssh_pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError("holder left its failed SSH child alive")
    finally:
        stop(holder)


def test_terminated_helper_does_not_leave_pipe_holder(tmp_path):
    env = fixture_env(tmp_path)
    holder = start(env)
    try:
        ready = line_with_timeout(holder)
        assert ready.startswith("nebula lane lock held"), ready
        holder.kill()
        holder.wait(timeout=5)
        wait_until(lambda: available(env))
    finally:
        stop(holder)


def test_stopping_helper_reaps_its_ssh_and_releases_lock(tmp_path):
    env = fixture_env(tmp_path)
    holder = start(env)
    try:
        ready = line_with_timeout(holder)
        assert ready.startswith("nebula lane lock held"), ready
        ssh_pid = int(ready.split("ssh pid ")[1].split(")")[0])
        holder.terminate()
        assert holder.wait(timeout=5) == 0
        wait_until(lambda: available(env))
        try:
            os.kill(ssh_pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError("helper left its SSH child alive")
    finally:
        stop(holder)
