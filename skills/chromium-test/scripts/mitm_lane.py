#!/usr/bin/env python3
"""Manage a local mitmproxy lane for agent browser testing."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress


from contextlib import ExitStack
import fcntl
import json
import os
import re
import stat
import shutil
import shlex
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


DEFAULT_ROOT = Path("~/.local/state/ghost/mitm-lanes").expanduser()
DEFAULT_MITMDUMP = "mitmdump"
HOSTER_BOUNTY_ROOT = Path('/mnt/bounty')
DEFAULT_SHARED_LANE = "hoster-default-8080"
PROC_ROOT = Path('/proc')
CGROUP_ROOT = Path('/sys/fs/cgroup')
LEGACY_UNIT = 'hoster-mitm-default-8080.service'


LOCAL_FILESYSTEMS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs", "tmpfs", "overlay"}


def _outside_shared(path: Path) -> bool:
    shared = (Path.home() / "Shared", Path(os.environ.get("HARNESS_SHARED_BASE", "~/Shared/web_bounty")).expanduser())
    lexical = Path(os.path.abspath(path))
    try:
        resolved = path.resolve()
        resolved_shared = tuple(p.resolve() for p in shared)
        if any(candidate.is_relative_to(base)
               for candidate, bases in ((lexical, shared), (resolved, resolved_shared))
               for base in bases):
            return False
        mounts = []
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            left, _ = line.split(' - ', 1)
            fields = left.split()
            def unescape(value):
                return Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), value))
            mounts.append((unescape(fields[4]), fields[2], unescape(fields[3])))
        def backing(candidate):
            matches = [entry for entry in mounts if candidate.is_relative_to(entry[0])]
            depth = max(len(entry[0].parts) for entry in matches)
            choices = [entry for entry in matches if len(entry[0].parts) == depth]
            if len(choices) != 1:
                raise ValueError('ambiguous mount')
            target, device, root = choices[0]
            return device, root / candidate.relative_to(target)
        device, underlying = backing(resolved)
        for base in resolved_shared:
            shared_device, shared_underlying = backing(base)
            if device == shared_device and underlying.is_relative_to(shared_underlying):
                return False
        return True
    except (OSError, RuntimeError, ValueError, IndexError):
        return False


def _local_filesystem(path: Path) -> bool:
    """Inspect the deepest mount, including a nested network mount below the root."""
    path = path.resolve()
    matches = []
    try:
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            left, right = line.split(' - ', 1)
            mount = Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), left.split()[4]))
            if path.is_relative_to(mount):
                matches.append((len(mount.parts), right.split()[0]))
        deepest = max(depth for depth, _ in matches)
        return {kind for depth, kind in matches if depth == deepest} <= LOCAL_FILESYSTEMS
    except (OSError, ValueError, IndexError):
        return False


def _safe_existing_directories(path: Path) -> bool:
    """Reject symlinks and replaceable ancestors, including extended ACLs."""
    current = Path('/')
    private_fence = False
    try:
        for component in path.absolute().parts[1:]:
            current /= component
            info = current.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or (info.st_mode & 0o022 and not private_fence)):
                return False
            try:
                os.getxattr(current, 'system.posix_acl_access', follow_symlinks=False)
                if not private_fence:
                    return False  # conservatively refuse nontrivial access ACLs
            except OSError as exc:
                import errno
                if exc.errno not in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
                    return False
            if info.st_uid == os.geteuid() and not info.st_mode & 0o077:
                private_fence = True
        return True
    except OSError:
        return False


def _safe_mounted_directories(path: Path) -> bool:
    """Apply the managed capture path's owner-approved ACL trust policy."""
    scripts = str(Path(__file__).resolve().parent)
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    from browser_provisioner import _capture_open_dir
    try:
        fd = _capture_open_dir(path)
        os.close(fd)
        return True
    except (OSError, ValueError):
        return False


def capture_destination(root: Path, lane: str, program: str | None) -> tuple[Path, str | None]:
    """Reserve a private generation, using only an exact existing mounted lane.

    This local API can be replaced at integration by the managed route's shared
    selector: it returns (reserved flow path, selected mount or None).
    """
    if not lane or lane in ('.', '..') or '/' in lane or '\0' in lane:
        raise ValueError('lane must be one path component')
    directory = lane_dir(root, lane)
    if not _outside_shared(directory) or not _local_filesystem(directory):
        raise ValueError('lane state must be on a local filesystem outside Shared')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not _safe_existing_directories(directory):
        raise ValueError('lane state directory is not owner-controlled')
    raw = os.environ.get('BOUNTY_ARTIFACT_ROOT', '/mnt/bounty')
    artifact = Path(raw).expanduser()
    exact = (program and program != 'general' and program not in ('.', '..')
             and '/' not in program and '\0' not in program)
    if exact and artifact.is_absolute():
        safe_directories = (_safe_mounted_directories if artifact == HOSTER_BOUNTY_ROOT
                            else _safe_existing_directories)
        web = artifact / program / 'web'
        try:
            if (os.path.ismount(artifact) and _outside_shared(web) and _local_filesystem(web)
                    and safe_directories(web) and os.access(web, os.W_OK | os.X_OK)):
                parent = web
                for name in ('proxy', 'flows'):
                    child = parent / name
                    child.mkdir(mode=0o700, exist_ok=True)
                    if not safe_directories(child) or not _local_filesystem(child):
                        raise PermissionError('unsafe capture directory')
                    parent = child
                capture = Path(tempfile.mkdtemp(prefix='standalone-', dir=parent))
                return capture / 'flows.mitm', str(artifact)
        except OSError:
            pass  # An unusable mounted destination falls back, never to Shared.
    return Path(tempfile.mkdtemp(prefix='capture-', dir=directory)) / 'flows.mitm', None


def _mount_id(fd: int) -> int:
    """Linux mount identity for an open descriptor, including bind mounts."""
    for line in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines():
        if line.startswith('mnt_id:'):
            return int(line.split(':', 1)[1].strip())
    raise OSError('mount ID unavailable')


def verify_recorded_capture(state: dict[str, Any]) -> dict[str, Any] | None:
    mount = state.get('capture_mount')
    try:
        if mount:
            info = Path(mount).stat()
            if (not os.path.ismount(mount) or [info.st_dev, info.st_ino] != state.get('mount_identity')
                    or not _local_filesystem(Path(state['flow_file']))):
                raise OSError('recorded mount unavailable')
        if state.get('capture_identity'):
            info = Path(state['flow_file']).lstat()
            if (not stat.S_ISREG(info.st_mode) or [info.st_dev, info.st_ino] != state['capture_identity']):
                raise OSError('recorded capture replaced')
    except (OSError, KeyError):
        return {'status': 'capture-unavailable', 'flow_file': state.get('flow_file')}
    return None


def open_readback(state: dict[str, Any], flow_file: Path, verify: bool) -> tuple[int | None, dict[str, Any] | None]:
    """Open once and bind the read to the recorded inode, not a later path lookup."""
    if verify:
        failure = verify_recorded_capture(state)
        if failure:
            return None, failure
    fd = None
    try:
        recorded_identity = state.get('capture_identity') if verify else None
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
        # Historical/explicit paths may be symlinks; recorded generations may not.
        if recorded_identity:
            flags |= os.O_NOFOLLOW
        fd = os.open(flow_file, flags)
        opened = os.fstat(fd)
        named = flow_file.stat()
        identity = [opened.st_dev, opened.st_ino]
        if (not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode)
                or identity != [named.st_dev, named.st_ino]
                or (recorded_identity and identity != recorded_identity)):
            raise OSError('capture identity changed')
        return fd, None
    except OSError:
        if fd is not None:
            os.close(fd)
        status = 'capture-unavailable' if verify and state.get('capture_identity') else 'missing-flow-file'
        return None, {'status': status, 'flow_file': str(flow_file)}


def lane_dir(root: Path, lane: str) -> Path:
    return root / lane


def state_path(root: Path, lane: str) -> Path:
    return lane_dir(root, lane) / "state.json"


def read_state(root: Path, lane: str) -> dict[str, Any]:
    if lane != DEFAULT_SHARED_LANE:
        return legacy_read_state(root, lane)
    path = state_path(root, lane)
    try:
        state = json.loads(path.read_text())
    except FileNotFoundError:
        if not os.path.lexists(path):
            return {}
        return {"status": "corrupt-state", "state_path": str(path)}
    except (OSError, UnicodeError, ValueError, RecursionError):
        return {"status": "corrupt-state", "state_path": str(path),
                "detail": "state is unreadable or malformed; inspect it without restarting"}
    if not isinstance(state, dict) or not state:
        return {"status": "unknown-state", "state_path": str(path)}
    if lane != DEFAULT_SHARED_LANE:
        return state
    if 'detail' in state:
        state['detail'] = 'stored diagnostic omitted; inspect the supervisor and lane state'
    status = state.get('status')
    if not isinstance(status, str) or not status:
        return {"status": "unknown-state", "state_path": str(path)}
    port = state.get('port')
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        return {"status": "unknown-state", "state_path": str(path)}
    ca = state.get('ca_cert')
    if ca is not None and (not isinstance(ca, str) or not ca):
        return {"status": "unknown-state", "state_path": str(path)}
    if status in {'starting', 'start-cleanup-failed'}:
        pid = state.get('pid')
        if pid is not None and (type(pid) is not int or not 0 < pid <= 2147483647):
            return {"status": "unknown-state", "state_path": str(path), "detail": "invalid recorded PID; inspect state without restarting"}
        return state
    terminal = status == 'stopped' or (status in {'start-failed', 'start-timeout'} and state.get('cleanup') == 'stopped')
    pid = state.get('pid')
    if not terminal and (type(pid) is not int or not 0 < pid <= 2147483647):
        return {"status": "unknown-state", "state_path": str(path), "detail": "invalid recorded PID; inspect state without restarting"}
    if terminal and pid is not None and (type(pid) is not int or not 0 < pid <= 2147483647):
        return {"status": "unknown-state", "state_path": str(path), "detail": "invalid recorded PID; inspect state without restarting"}
    if status in {'running', 'already-running'} and (
            state.get('port') != 8080 or state.get('listen_host') not in ('127.0.0.1', '0.0.0.0')
            or not isinstance(state.get('ca_cert'), str) or not state['ca_cert']):
        return {"status": "unknown-state", "state_path": str(path)}
    return state


def state_for_flow(root: Path, lane: str, override: str | None) -> dict[str, Any] | None:
    """Resolve an explicitly named older generation without changing its identity."""
    state = read_state(root, lane)
    if not override or not state.get('index_lane'):
        return state
    requested = str(Path(override).expanduser().absolute())
    if requested == state.get('flow_file'):
        return state
    for receipt in lane_dir(root, lane).glob('receipt-*/state.json'):
        try:
            saved = json.loads(receipt.read_text())
            if isinstance(saved, dict) and saved.get('flow_file') == requested:
                return saved
        except (OSError, ValueError):
            continue
    return None


def write_state(root: Path, lane: str, state: dict[str, Any]) -> None:
    path = state_path(root, lane)
    path.parent.mkdir(parents=True, exist_ok=True)
    if lane == DEFAULT_SHARED_LANE:
        # Preserve the shared supervisor's pre-submission publication protocol.
        path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        return
    fd, temporary = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def publish_running_state(root: Path, lane: str, state: dict[str, Any]) -> None:
    """Publish without truncating the pre-submission starting record on failure."""
    path = state_path(root, lane)
    fd, name = tempfile.mkstemp(prefix='.state-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(state, output, indent=2, sort_keys=True)
            output.write('\n')
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def can_bind_localhost(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def wait_for_port(port: int, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.1)
    return False


def readable_ca(path: Path) -> bool:
    try:
        if not path.is_file():
            return False
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=path.read_text(encoding='ascii'))
        return context.cert_store_stats()['x509_ca'] > 0
    except (OSError, UnicodeError, ValueError, ssl.SSLError):
        return False


def signer_fingerprint(path: Path) -> str | None:
    """Return the public CA digest only when it matches mitmproxy's signer."""
    try:
        if not readable_ca(path):
            return None
        public = path.read_text(encoding='ascii')
        combined = path.with_name('mitmproxy-ca.pem').read_text(encoding='ascii')
        begin, end = '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'
        def der(text: str) -> bytes:
            start = text.index(begin)
            stop = text.index(end, start) + len(end)
            return ssl.PEM_cert_to_DER_cert(text[start:stop])
        cert = der(public)
        start = public.index(begin)
        stop = public.index(end, start) + len(end)
        if public[:start].strip() or public[stop:].strip():
            return None  # Never copy a public file that contains other PEM material.
        if cert != der(combined):
            return None
        # OpenSSL validates both the presence of a private key and that it
        # matches the certificate, without exposing either in a subprocess log.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.set_ciphers('DEFAULT:@SECLEVEL=0')  # Validate legacy keys without imposing TLS policy.
        context.load_cert_chain(str(path.with_name('mitmproxy-ca.pem')), password=lambda: '')
        return hashlib.sha256(cert).hexdigest()
    except (OSError, UnicodeError, ValueError, ssl.SSLError):
        return None


def wait_for_ca(path: Path, deadline: float) -> bool:
    while True:
        if signer_fingerprint(path):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.1, remaining))


def mitm_env() -> dict[str, str]:
    env = os.environ.copy()
    # Ubuntu's mitmproxy 8.x expects distro blinker. User-site blinker 1.9
    # shadows it and removes blinker._saferef.
    env["PYTHONNOUSERSITE"] = "1"
    return env


def start_lane(args: argparse.Namespace) -> dict[str, Any]:
    if args.lane == DEFAULT_SHARED_LANE and args.port == 8080:
        try:
            host = args.proxy_host
            address = ipaddress.ip_address(host[1:-1] if host.startswith('[') and host.endswith(']') else host)
        except ValueError:
            address = None  # Hostname resolution and routing require a live canary.
        if address is not None and address.version == 6:
            return {"status": "unsupported-proxy-host", "lane": args.lane,
                    "detail": "IPv6 proxy address is incompatible with the IPv4-only listener"}
        root = Path(args.root).expanduser()
        directory = lane_dir(root, args.lane)
        # Do not even create a lock file when existing metadata is unknown.
        current = read_state(root, args.lane)
        if current.get("status") in {"unknown-state", "corrupt-state"}:
            return current
        if current.get('status') in {'running', 'already-running'}:
            return {"status": "unknown-state", "lane": args.lane,
                    "detail": "recorded running generation requires observation; do not start another listener"}
        if current.get("status") in {"starting", "start-cleanup-failed"}:
            return {"status": "start-cleanup-failed", "lane": args.lane,
                    "unit": current.get("unit"), "detail": "previous startup needs exact-unit recovery; do not start another listener"}
        directory.mkdir(parents=True, exist_ok=True)
        # Cooperating starts share this lock; it is not process ownership proof.
        with (directory / ".start.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            current = read_state(root, args.lane)
            if current.get("status") in {"unknown-state", "corrupt-state"}:
                return current
            if current.get("status") in {"starting", "start-cleanup-failed"}:
                return {"status": "start-cleanup-failed", "lane": args.lane,
                        "unit": current.get("unit"), "detail": "previous startup needs exact-unit recovery; do not start another listener"}
            # The lock coordinates all direct starts, not arbitrary same-UID
            # writers. Reclassify here, not at a wrapper or before this lock.
            absence = classify_default_absence(args)
            if absence.get('status') not in {'not-found', 'stopped'}:
                return absence
            for executable in ('systemd-run', args.mitmdump, 'openssl'):
                if not shutil.which(executable):
                    return {"status": "start-failed", "lane": args.lane,
                            "detail": "Required start or attestation executable unavailable; inspect dependencies before starting."}
            # The observer recognizes only this script/interpreter and argv.
            # Resolve the requested executable, never substitute another one.
            selected = shutil.which(args.mitmdump)
            try:
                with Path('/usr/bin/mitmdump').open('rb') as script:
                    shebang = script.readline(128).rstrip(b'\n')
            except OSError:
                shebang = b''
            if selected != '/usr/bin/mitmdump' or shebang != b'#!/usr/bin/python3':
                return {"status": "unsupported-runtime", "lane": args.lane,
                        "detail": "Shared default observation requires /usr/bin/mitmdump with #!/usr/bin/python3; install or explicitly select that runtime before starting."}
            args.mitmdump = selected
            return legacy_start_lane(args)
    if args.lane == DEFAULT_SHARED_LANE:
        return {"status": "unmanaged-start-unsupported", "lane": args.lane}
    return task_start_lane(args)


def user_systemd_env() -> dict[str, str]:
    env = mitm_env()
    runtime = f"/run/user/{os.getuid()}"
    env.setdefault("XDG_RUNTIME_DIR", runtime)
    env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={env['XDG_RUNTIME_DIR']}/bus")
    return env


def unit_command(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, env=env, capture_output=True, text=True, check=False, timeout=12)
    except UnicodeError:
        raise RuntimeError('user supervisor returned invalid output; inspect its status') from None


def unit_status(unit: str, env: dict[str, str]) -> dict[str, str]:
    result = unit_command(["systemctl", "--user", "show", unit,
                           "--property=ActiveState,MainPID,ControlGroup"], env)
    if result.returncode:
        raise RuntimeError("cannot inspect shared proxy user unit")
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def stop_started_unit(unit: str, env: dict[str, str]) -> bool:
    try:
        result = unit_command(["systemctl", "--user", "stop", unit], env)
        status = unit_status(unit, env)
        return result.returncode == 0 and status.get("ActiveState") in {"inactive", "failed"} and status.get("MainPID") == "0"
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return False


def legacy_start_lane(args: argparse.Namespace) -> dict[str, Any]:
    if args.lane != DEFAULT_SHARED_LANE or args.port != 8080:
        return {"status": "unmanaged-start-unsupported", "lane": args.lane}
    if args.listen_host not in {"127.0.0.1", "0.0.0.0"}:
        return {"status": "unsupported-listen-host", "lane": args.lane,
                "detail": "shared default supports only 127.0.0.1 or 0.0.0.0; choose one before starting"}
    root = Path(args.root).expanduser()
    # The locked read-only classifier already checked both socket tables; do
    # not make a bind/connect probe or treat a successful bind as authority.
    env = user_systemd_env()
    try:
        linger = unit_command(["loginctl", "show-user", str(os.getuid()), "--property=Linger", "--value"], env)
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return {"status": "supervisor-unavailable", "lane": args.lane,
                "detail": "cannot check user linger; inspect the user supervisor"}
    if linger.returncode or linger.stdout.strip() != "yes":
        return {"status": "supervisor-unavailable", "lane": args.lane,
                "detail": "enable user linger and a working user systemd manager before starting"}

    directory = lane_dir(root, args.lane)
    confdir = directory / "mitmproxy"
    confdir.mkdir(parents=True, exist_ok=True)
    combined_ca = confdir / 'mitmproxy-ca.pem'
    if not combined_ca.exists() and any(confdir.glob('mitmproxy-ca*')):
        return {"status": "start-failed", "lane": args.lane,
                "detail": "historical CA exists without its signer; restore the signer before starting; no CA was replaced"}
    prior_fingerprint = signer_fingerprint(confdir / "mitmproxy-ca-cert.pem")
    if combined_ca.exists() and not prior_fingerprint:
        return {"status": "start-failed", "lane": args.lane,
                "detail": "historical signer or public CA is unreadable or inconsistent; no CA was replaced"}
    # mitmdump -w truncates; reserve a fresh output without touching history.
    flow_fd, flow_name = tempfile.mkstemp(prefix="flows-", suffix=".mitm", dir=directory)
    os.close(flow_fd)
    flow_file = Path(flow_name)
    log_file = directory / "mitmdump.log"
    unit = f"ghost-mitm-default-8080-{uuid.uuid4().hex}.service"

    command = [
        args.mitmdump,
        "--listen-host",
        args.listen_host,
        "--listen-port",
        str(args.port),
        "--set",
        f"confdir={confdir}",
        "--set",
        "flow_detail=0",
        "-w",
        str(flow_file),
    ]
    state = {"status": "starting", "lane": args.lane, "unit": unit,
             "port": args.port, "flow_file": str(flow_file)}
    # Persist the generation before submission: an interrupted dispatcher must
    # not start a second proxy while the transient unit may still be alive.
    write_state(root, args.lane, state)
    try:
        launch = unit_command(["systemd-run", "--user", f"--unit={unit}",
                               "--property=Type=exec", f"--property=StandardOutput=append:{log_file}",
                               "--property=StandardError=inherit", "--setenv=PYTHONNOUSERSITE=1",
                               "--", *command], env)
    except (OSError, subprocess.SubprocessError, RuntimeError):
        # A submission can reach the manager even when its reply is lost. Keep
        # the pre-submission starting record and never stop or retry this unit.
        return {"status": "start-outcome-unknown", "lane": args.lane, "unit": unit,
                "detail": "Submission outcome unknown; inspect the recorded unit and capture without stopping or retrying."}
    if launch.returncode:
        return {"status": "start-outcome-unknown", "lane": args.lane, "unit": unit,
                "detail": "Submission outcome unknown; inspect the recorded unit and capture without stopping or retrying."}
    try:
        deadline = time.monotonic() + 8.0
        started = wait_for_port(args.port)
        status = unit_status(unit, env)
        if not started:
            raise TimeoutError("shared proxy listener did not become ready")
        if (status.get("ActiveState") != "active" or not status.get("MainPID", "").isdigit()
                or int(status["MainPID"]) <= 0 or not status.get("ControlGroup", "").startswith("/user.slice/")):
            raise RuntimeError("shared proxy unit is not active under the user manager")
        if not wait_for_ca(confdir / "mitmproxy-ca-cert.pem", deadline):
            raise TimeoutError("shared proxy CA not readable before startup deadline; inspect the unit log and CA directory")
        fingerprint = signer_fingerprint(confdir / "mitmproxy-ca-cert.pem")
        if not fingerprint:
            raise RuntimeError("shared proxy signer changed during startup; inspect its CA directory")
        if prior_fingerprint and fingerprint != prior_fingerprint:
            raise RuntimeError("shared proxy CA changed during startup; inspect its CA directory")
        initial_pid = status['MainPID']
        status = unit_status(unit, env)
        if (status.get("ActiveState") != "active" or not status.get("MainPID", "").isdigit()
                or int(status["MainPID"]) <= 0 or status["MainPID"] != initial_pid
                or not status.get("ControlGroup", "").startswith("/user.slice/")):
            raise RuntimeError("shared proxy unit stopped or lost user-manager ownership while waiting for CA")
        pid = int(status["MainPID"])
    except (OSError, subprocess.SubprocessError, RuntimeError, TimeoutError):
        # A unit name alone does not prove that this is the submitted process.
        # Keep the starting record; never signal or retry an uncertain generation.
        return {"status": "start-outcome-unknown", "lane": args.lane, "unit": unit,
                "detail": "Post-submission readiness is unknown; inspect without stopping or retrying."}
    state = {
        "status": "running",
        "lane": args.lane,
        "program": args.program,
        "task": args.task,
        "account": args.account_label if args.account_label is not None else args.account,
        "account_label": args.account_label if args.account_label is not None else args.account,
        "profile_dir": args.profile_dir,
        "run_id": args.run_id,
        "agent_id": args.agent_id,
        "runtime_host": args.runtime_host,
        "proxy_host": args.proxy_host,
        "proxy_port": args.port,
        "transport": args.transport,
        "browser_profile_id": args.browser_profile_id or args.profile_dir,
        "session_source": args.session_source,
        "pid": pid,
        "unit": unit,
        "control_group": status["ControlGroup"],
        "port": args.port,
        "listen_host": args.listen_host,
        "proxy_server": f"http://[{args.proxy_host}]:{args.port}" if ':' in args.proxy_host and not args.proxy_host.startswith('[') else f"http://{args.proxy_host}:{args.port}",
        "root": str(root),
        "confdir": str(confdir),
        "ca_cert": str(confdir / "mitmproxy-ca-cert.pem"),
        "ca_started_sha256": fingerprint,
        "flow_file": str(flow_file),
        "log_file": str(log_file),
        "command": command,
    }
    # A ready port and active unit can belong to different processes. Before
    # publishing running, observe the submitted unit's exact process, listener
    # and reserved capture twice, while the starting record remains unchanged.
    starting = {"status": "starting", "lane": args.lane, "unit": unit,
                "port": args.port, "flow_file": str(flow_file)}
    observed = default_generation_observation(root, state)
    if (observed is None or observed.get('status') != 'observed-fresh'
            or observed.get('unit') != unit or observed.get('pid') != pid
            or read_state(root, args.lane) != starting):
        return {"status": "start-outcome-unknown", "lane": args.lane, "unit": unit,
                "detail": "Submitted generation could not be confirmed; inspect without stopping or retrying."}
    try:
        publish_running_state(root, args.lane, state)
    except OSError:
        return {"status": "start-outcome-unknown", "lane": args.lane, "unit": unit,
                "detail": "Post-submission state save is unknown; inspect without stopping or retrying."}
    return state


def default_generation_observation(root: Path, state: dict[str, Any] | None = None, *,
                                   include_identity: bool = False) -> dict[str, Any] | None:
    """Observe a recorded default generation; never grant lifecycle or CA trust."""
    directory = root / DEFAULT_SHARED_LANE
    state = state or {}
    recorded_unit = state.get('unit')
    fresh = False
    if isinstance(recorded_unit, str) and re.fullmatch(
            r'ghost-mitm-default-8080-[0-9a-f]{32}\.service', recorded_unit):
        fresh = True
        unit = recorded_unit
        flow_name = state.get('flow_file')
        if not isinstance(flow_name, str):
            return None
        flow = Path(flow_name)
        if flow.parent != directory or not re.fullmatch(r'flows-[A-Za-z0-9_-]+\.mitm', flow.name):
            return None
        host = state.get('listen_host')
        if host not in ('0.0.0.0', '127.0.0.1'):
            return None
    else:
        unit = LEGACY_UNIT
        flow = directory / 'flows.mitm'
        host = '0.0.0.0'
        if recorded_unit not in (None, LEGACY_UNIT) or state.get('flow_file') not in (None, str(flow)):
            return None
    conf = directory / 'mitmproxy'
    expected = ['/usr/bin/mitmdump', '--listen-host', host, '--listen-port', '8080',
                '--set', f'confdir={conf}', '--set', 'flow_detail=0', '-w', str(flow)]
    uid = os.getuid()
    cgroup = f'/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/{unit}'

    def snapshot() -> tuple[Any, ...]:
        result = unit_command(['systemctl', '--user', 'show', unit,
                               '--property=Id,ActiveState,SubState,MainPID,ControlGroup,InvocationID,ExecStart'],
                              user_systemd_env())
        if result.returncode:
            raise ValueError('unit unavailable')
        fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if (fields.get('Id') != unit or fields.get('ActiveState') != 'active'
                or fields.get('SubState') != 'running' or fields.get('ControlGroup') != cgroup
                or not re.fullmatch('[0-9a-f]{32}', fields.get('InvocationID', ''))
                or fields['InvocationID'] == '0' * 32):
            raise ValueError('unit identity mismatch')
        pid = int(fields.get('MainPID', '0'))
        if not 0 < pid <= 2147483647:
            raise ValueError('invalid pid')
        if fresh and pid != state.get('pid'):
            raise ValueError('recorded pid differs')
        exec_start = fields.get('ExecStart', '')
        if exec_start.count('argv[]=') != 1 or 'path=/usr/bin/mitmdump ; argv[]=' not in exec_start:
            raise ValueError('unexpected exec')
        command = exec_start.split('argv[]=', 1)[1].split(' ;', 1)[0]
        if shlex.split(command) != expected:
            raise ValueError('unexpected exec argv')
        proc = PROC_ROOT / str(pid)
        if not os.path.samefile(proc / 'exe', '/usr/bin/python3'):
            raise ValueError('unexpected process executable')
        namespace = os.readlink(proc / 'ns/net')
        if not re.fullmatch(r'net:\[[0-9]+\]', namespace) or namespace != os.readlink(PROC_ROOT / 'self/ns/net'):
            raise ValueError('network namespace mismatch')
        argv = (proc / 'cmdline').read_bytes().split(b'\0')
        if argv != [x.encode() for x in ['/usr/bin/python3', *expected]] + [b'']:
            raise ValueError('unexpected process argv')
        stat = (proc / 'stat').read_text()
        ticks = int(stat[stat.rindex(')') + 2:].split()[19])
        if ticks <= 0 or ('0::' + cgroup) not in (proc / 'cgroup').read_text().splitlines():
            raise ValueError('process identity mismatch')
        sockets = set()
        for table in ('tcp', 'tcp6'):
            for line in (proc / 'net' / table).read_text().splitlines()[1:]:
                cols = line.split()
                if len(cols) < 10:
                    raise ValueError('invalid socket table')
                addr, port = cols[1].split(':')
                if int(port, 16) == 8080 and cols[3] == '0A':
                    if table != 'tcp' or addr != ('00000000' if host == '0.0.0.0' else '0100007F'):
                        raise ValueError('unexpected listener')
                    sockets.add(int(cols[9]))
        path_stat = flow.stat()
        capture = (path_stat.st_dev, path_stat.st_ino)
        opened_sockets = set()
        opened_capture = False
        for fd in (proc / 'fd').iterdir():
            target = os.readlink(fd)
            match = re.fullmatch(r'socket:\[([0-9]+)\]', target)
            if match:
                opened_sockets.add(int(match.group(1)))
            elif target == str(flow):
                st = fd.stat()
                opened_capture |= (st.st_dev, st.st_ino) == capture
        matching = sockets & opened_sockets
        if len(sockets) != 1 or matching != sockets or not opened_capture:
            raise ValueError('listener or capture identity mismatch')
        return (pid, ticks, fields['InvocationID'], cgroup, namespace, tuple(sorted(matching)), capture)

    try:
        first = snapshot()
        if first != snapshot():
            return None
    except (OSError, ValueError, IndexError, KeyError, UnicodeError, subprocess.SubprocessError, RuntimeError):
        return None
    result = {'status': 'observed-fresh' if fresh else 'observed-legacy', 'lane': DEFAULT_SHARED_LANE, 'unit': unit,
              'pid': first[0], 'port': 8080, 'listen_host': host,
              'signer': 'unverified',
              'detail': 'Read-only listener and capture observation; signer, readiness, and lifecycle ownership are unverified.'}
    if include_identity:
        result['_identity'] = (unit, host, str(flow), first)
    return result


def observe_default(args: argparse.Namespace) -> dict[str, Any]:
    """Read-only observation without probing ports, CA files, or lifecycle."""
    root = Path(args.root).expanduser()
    if args.lane == DEFAULT_SHARED_LANE and root == DEFAULT_ROOT:
        state = read_state(root, args.lane)
        if state.get('status') in {'running', 'already-running'}:
            observed = default_generation_observation(root, state, include_identity=True)
            if observed is not None and read_state(root, args.lane) == state:
                identity = observed.pop('_identity')
                observed['generation_sha256'] = hashlib.sha256(
                    json.dumps(identity, separators=(',', ':')).encode()).hexdigest()
                if observed['status'] == 'observed-fresh':
                    observed['flow_path_sha256'] = hashlib.sha256(identity[2].encode()).hexdigest()
                return observed
    return {'status': 'unknown-state', 'lane': DEFAULT_SHARED_LANE,
            'detail': 'Shared listener observation unavailable; inspect without starting or stopping.'}


def classify_default_absence(args: argparse.Namespace) -> dict[str, Any]:
    """Classify only a clean absent/stopped default, without lifecycle actions."""
    unknown = {'status': 'unknown-state', 'lane': DEFAULT_SHARED_LANE,
               'detail': 'Clean absence is unproven; inspect without starting or stopping.'}
    root = Path(args.root).expanduser()
    if args.lane != DEFAULT_SHARED_LANE or root != DEFAULT_ROOT:
        return unknown
    fresh_pattern = r'ghost-mitm-default-8080-[0-9a-f]{32}\.service'
    path = state_path(root, DEFAULT_SHARED_LANE)

    class NamespaceUnproven(ValueError):
        pass

    def snapshot() -> tuple[Any, ...]:
        state = read_state(root, DEFAULT_SHARED_LANE)
        if not state:
            # read_state's absent result is valid only when the path is truly absent.
            try:
                path.lstat()
            except FileNotFoundError:
                pass
            else:
                raise ValueError('state exists')
            classification = 'not-found'
        else:
            if (state.get('status') != 'stopped'
                    or state.get('lane', DEFAULT_SHARED_LANE) != DEFAULT_SHARED_LANE
                    or state.get('port', 8080) != 8080):
                raise ValueError('not a stopped default')
            classification = 'stopped'
        recorded = state.get('unit')
        if recorded is not None and (not isinstance(recorded, str) or
                (recorded != LEGACY_UNIT and not re.fullmatch(fresh_pattern, recorded))):
            raise ValueError('unrecognized unit')
        pid = state.get('pid')
        if pid is not None:
            # A present PID may be reused; never decide it belongs to the lane.
            try:
                (PROC_ROOT / str(pid)).stat()
            except FileNotFoundError:
                # hidepid can make a live, reused PID invisible in procfs.
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    raise ValueError('recorded pid exists')
            else:
                raise ValueError('recorded pid exists')
        env = user_systemd_env()
        uid = os.getuid()
        manager_group = f'/user.slice/user-{uid}.slice/user@{uid}.service'
        manager = CGROUP_ROOT / manager_group.lstrip('/')
        # Prefer direct manager namespace evidence. If ptrace restrictions hide
        # it, a verified unisolated user-bus service is a practical witness.
        # This assumes cooperative same-UID services do not unshare or redirect
        # networking outside their declared systemd configuration.
        init = unit_command(['systemctl', '--user', 'show', 'init.scope', '--all', '--no-pager',
                             '--property=Id,LoadState,ActiveState,SubState,ControlGroup'], env)
        try:
            entries = [line.partition('=') for line in init.stdout.splitlines()]
            if (init.returncode or any(not sep for _, sep, _ in entries)
                    or len({key for key, _, _ in entries}) != len(entries)):
                raise ValueError('invalid init.scope')
            init_fields = {key: value for key, _, value in entries}
            if init_fields != {'Id': 'init.scope', 'LoadState': 'loaded', 'ActiveState': 'active',
                               'SubState': 'running', 'ControlGroup': manager_group + '/init.scope'}:
                raise ValueError('unverified manager scope')
            pids = (manager / 'init.scope' / 'cgroup.procs').read_text().splitlines()
            if not pids or len(set(pids)) != len(pids) or any(not re.fullmatch(r'[1-9][0-9]*', p) for p in pids):
                raise ValueError('invalid manager process list')
            namespace = os.readlink(PROC_ROOT / 'self/ns/net')
            if not re.fullmatch(r'net:\[[0-9]+\]', namespace):
                raise ValueError('invalid caller namespace')
            hidden = False
            for manager_pid in pids:
                process = PROC_ROOT / manager_pid
                groups = (process / 'cgroup').read_text().splitlines()
                if groups.count('0::' + manager_group + '/init.scope') != 1:
                    raise ValueError('manager process moved')
                try:
                    manager_ns = os.readlink(process / 'ns/net')
                except PermissionError:
                    hidden = True
                else:
                    if manager_ns != namespace:
                        raise ValueError('network namespace mismatch')
            witness = None
            if hidden:
                result = unit_command(['systemctl', '--user', 'show', 'dbus.service', '--all', '--no-pager',
                                       '--property=Id,LoadState,ActiveState,SubState,MainPID,InvocationID,ControlGroup,Slice,PrivateNetwork,NetworkNamespacePath,JoinsNamespaceOf'], env)
                entries = [line.partition('=') for line in result.stdout.splitlines()]
                if (result.returncode or any(not sep for _, sep, _ in entries)
                        or len({key for key, _, _ in entries}) != len(entries)):
                    raise ValueError('invalid witness fields')
                fields = {key: value for key, _, value in entries}
                if (set(fields) != {'Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'InvocationID',
                                    'ControlGroup', 'Slice', 'PrivateNetwork', 'NetworkNamespacePath', 'JoinsNamespaceOf'}
                        or fields['Id'] != 'dbus.service' or fields['LoadState'] != 'loaded'
                        or fields['ActiveState'] != 'active' or fields['SubState'] != 'running'
                        or fields['PrivateNetwork'] != 'no' or fields['NetworkNamespacePath']
                        or fields['JoinsNamespaceOf']
                        or not re.fullmatch(r'[a-zA-Z0-9_.-]+\.slice', fields['Slice'])
                        or fields['ControlGroup'] != manager_group + '/' + fields['Slice'] + '/dbus.service'
                        or not re.fullmatch(r'[1-9][0-9]*', fields['MainPID'])
                        or not re.fullmatch(r'[0-9a-f]{32}', fields['InvocationID'])
                        or fields['InvocationID'] == '0' * 32):
                    raise ValueError('unverified witness unit')
                process = PROC_ROOT / fields['MainPID']
                def process_identity():
                    stat = (process / 'stat').read_text()
                    prefix, sep, rest = stat.rpartition(') ')
                    parts = rest.split()
                    if (not sep or not prefix.startswith(fields['MainPID'] + ' (') or len(parts) < 20
                            or not re.fullmatch(r'[0-9]+', parts[19])):
                        raise ValueError('invalid witness process')
                    return parts[19]
                start = process_identity()
                if ((process / 'cgroup').read_text().splitlines().count('0::' + fields['ControlGroup']) != 1
                        or os.readlink(process / 'ns/net') != namespace or process_identity() != start):
                    raise ValueError('witness process changed or namespace mismatch')
                witness = (fields['MainPID'], fields['InvocationID'], fields['ControlGroup'], start)
        except (OSError, ValueError, UnicodeError) as exc:
            raise NamespaceUnproven('manager namespace unavailable') from exc
        listed = unit_command(['systemctl', '--user', '--no-pager', '--full', 'list-units', '--all', '--plain',
                               '--no-legend', 'ghost-mitm-default-8080-*.service'], env)
        if listed.returncode:
            raise ValueError('unit list unavailable')
        units = {LEGACY_UNIT}
        if recorded:
            units.add(recorded)
        seen_listed = set()
        for line in listed.stdout.splitlines():
            columns = line.split(None, 4)
            if (len(columns) != 5 or not re.fullmatch(fresh_pattern, columns[0])
                    or columns[1:4] != ['loaded', 'inactive', 'dead']
                    or not columns[4].strip() or any(ord(ch) < 32 for ch in columns[4])):
                raise ValueError('unrecognized unit list')
            if columns[0] in seen_listed:
                raise ValueError('duplicate unit list')
            seen_listed.add(columns[0])
            units.add(columns[0])
        # A collected transient unit may leave a populated cgroup even when it
        # no longer appears in list-units. Inspect only exact managed names.
        parent = manager / 'app.slice'
        try:
            names = list(parent.iterdir())
            app_exists = True
        except FileNotFoundError:
            manager.stat()
            names = []
            app_exists = False
            slice_list = unit_command(['systemctl', '--user', '--no-pager', '--full', 'list-units',
                                       '--all', '--plain', '--no-legend', 'app.slice'], env)
            slice_lines = slice_list.stdout.splitlines()
            if slice_list.returncode or len(slice_lines) > 1:
                raise ValueError('application slice list unavailable')
            if slice_lines:
                columns = slice_lines[0].split(None, 4)
                if (len(columns) != 5 or columns[:4] != ['app.slice', 'loaded', 'inactive', 'dead']
                        or not columns[4].strip() or any(ord(ch) < 32 for ch in columns[4])):
                    raise ValueError('application slice not inactive')
        units.update(entry.name for entry in names if re.fullmatch(fresh_pattern, entry.name))
        for unit in sorted(units):
            result = unit_command(['systemctl', '--user', 'show', unit, '--all', '--no-pager',
                                   '--property=Id,LoadState,ActiveState,SubState,MainPID,ControlGroup,Slice'], env)
            if result.returncode:
                raise ValueError('unit unavailable')
            fields = {}
            for line in result.stdout.splitlines():
                key, sep, value = line.partition('=')
                if not sep or key in fields:
                    raise ValueError('invalid unit fields')
                fields[key] = value
            if (set(fields) != {'Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlGroup', 'Slice'}
                    or fields.get('Id') != unit or fields.get('LoadState') not in ('loaded', 'not-found')
                    or fields.get('ActiveState') != 'inactive' or fields.get('SubState') != 'dead'
                    or fields.get('MainPID') != '0' or fields.get('ControlGroup') != ''
                    or fields.get('Slice') not in (('app.slice',) if fields.get('LoadState') == 'loaded'
                                                   else ('', 'app.slice'))):
                raise ValueError('unit not cleanly inactive')
            if unit in seen_listed and fields['LoadState'] != 'loaded':
                raise ValueError('unit changed since listing')
            # An inactive unit can leave children in its cgroup. Check the
            # exact expected cgroup even if systemd no longer reports it.
            if not app_exists:
                continue
            parent.stat()
            try:
                events = (parent / unit / 'cgroup.events').read_text()
            except FileNotFoundError:
                # A missing events file inside an existing cgroup is ambiguous.
                try:
                    (parent / unit).stat()
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError('cgroup events missing')
            else:
                rows = [line.split() for line in events.splitlines()]
                if [row for row in rows if row and row[0] == 'populated'] != [['populated', '0']]:
                    raise ValueError('cgroup populated or unobservable')
        # Both tables must be readable and parseable. Treat every local 8080
        # socket as a conflict, including non-LISTEN states, not just loopback.
        for table in ('tcp', 'tcp6'):
            lines = (PROC_ROOT / 'net' / table).read_text().splitlines()
            remote_column = 'rem_address' if table == 'tcp' else 'remote_address'
            if not lines or lines[0].split() != ['sl', 'local_address', remote_column, 'st', 'tx_queue',
                                                  'rx_queue', 'tr', 'tm->when', 'retrnsmt', 'uid', 'timeout', 'inode']:
                raise ValueError('invalid socket table')
            for line in lines[1:]:
                columns = line.split()
                if len(columns) < 12:
                    raise ValueError('invalid socket entry')
                # Time-wait and request sockets use the kernel's shorter
                # 12-column representation; ordinary sockets have 17 fields.
                if len(columns) != 17 and not (len(columns) == 12 and columns[3] in ('03', '06')):
                    raise ValueError('incomplete socket entry')
                address, port = columns[1].split(':')
                width = 8 if table == 'tcp' else 32
                if (not re.fullmatch(r'[0-9]+:', columns[0])
                        or len(address) != width
                        or not re.fullmatch(r'[0-9A-Fa-f]+', address)
                        or not re.fullmatch(r'[0-9A-Fa-f]{4}', port)
                        or not re.fullmatch(rf'[0-9A-Fa-f]{{{width}}}:[0-9A-Fa-f]{{4}}', columns[2])
                        or not re.fullmatch(r'[0-9A-Fa-f]{2}', columns[3])
                        or not re.fullmatch(r'[0-9A-Fa-f]{8}:[0-9A-Fa-f]{8}', columns[4])
                        or not re.fullmatch(r'[0-9A-Fa-f]{2}:[0-9A-Fa-f]{8}', columns[5])
                        or not re.fullmatch(r'[0-9A-Fa-f]{8}', columns[6])
                        or any(not re.fullmatch(r'[0-9]+', col) for col in columns[7:11])
                        or not re.fullmatch(r'[0-9A-Fa-f]+', columns[11])
                        or any(not re.fullmatch(r'-?[0-9]+', col) for col in columns[12:])):
                    raise ValueError('invalid socket entry')
                if int(port, 16) == 8080:
                    raise ValueError('port occupied')
        return classification, state, namespace, tuple(sorted(pids)), witness

    try:
        first = snapshot()
        if first != snapshot():
            return unknown
    except NamespaceUnproven:
        return {'status': 'unknown-state', 'lane': DEFAULT_SHARED_LANE,
                'detail': 'User-manager network namespace could not be verified; inspect manager and caller namespaces with suitable procfs access.'}
    except (OSError, ValueError, TypeError, UnicodeError, subprocess.SubprocessError, RuntimeError):
        return unknown
    return {'status': first[0], 'lane': DEFAULT_SHARED_LANE,
            'detail': 'Point-in-time read-only classification; recheck under the start lock before dispatch.'}


def public_ca_digest(path: Path) -> str | None:
    """Digest a single public CA certificate, never the combined signer file."""
    try:
        with path.open('rb') as source:
            data = source.read(65537)
        if len(data) > 65536:
            return None
        text = data.decode('ascii')
        if not re.fullmatch(r'\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*', text):
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=text)
        if context.cert_store_stats()['x509_ca'] != 1:
            return None
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(text.strip())).hexdigest()
    except (OSError, UnicodeError, ValueError, ssl.SSLError):
        return None


def attest_default(args: argparse.Namespace) -> dict[str, Any]:
    """Attest one observed generation with a bounded, fixed-target TLS probe."""
    unknown = {'status': 'unknown-state', 'lane': DEFAULT_SHARED_LANE,
               'detail': 'Generation or public CA could not be proven stable; inspect without restarting.'}
    root = Path(args.root).expanduser()
    if args.lane != DEFAULT_SHARED_LANE or root != DEFAULT_ROOT:
        return unknown
    state = read_state(root, args.lane)
    ca = root / DEFAULT_SHARED_LANE / 'mitmproxy' / 'mitmproxy-ca-cert.pem'
    if state.get('status') not in {'running', 'already-running'} or state.get('ca_cert') != str(ca):
        return unknown
    before = default_generation_observation(root, state, include_identity=True)
    if (not isinstance(before, dict) or not isinstance(before.get('_identity'), tuple)
            or len(before['_identity']) != 4 or read_state(root, args.lane) != state):
        return unknown
    digest = public_ca_digest(ca)
    if not digest:
        # A missing public file is the only retryable readiness condition.  Do
        # not conflate malformed, unreadable, or changed CA data with absence.
        try:
            ca.lstat()
        except FileNotFoundError:
            after = default_generation_observation(root, state, include_identity=True)
            if (before.get('status') == 'observed-fresh' and isinstance(after, dict)
                    and after.get('_identity') == before['_identity']
                    and read_state(root, args.lane) == state):
                token = hashlib.sha256(json.dumps(before['_identity'], separators=(',', ':')).encode()).hexdigest()
                return {'status': 'ca-pending', 'lane': DEFAULT_SHARED_LANE,
                        'generation_sha256': token, 'detail': 'Public CA is not yet present; signer is unverified.'}
        except OSError:
            pass
        return unknown
    command = ['openssl', 's_client', '-proxy', '127.0.0.1:8080', '-connect', 'example.com:443',
               '-servername', 'example.com', '-verify_hostname', 'example.com', '-CAfile', str(ca),
               '-no-CApath', '-no-CAstore', '-verify_return_error']
    failure = None
    try:
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=12, check=False)
        if (completed.returncode != 0 or not isinstance(completed.stdout, bytes)
                or not re.search(rb'(?m)^\s*Verify return code: 0 \(ok\)\s*$', completed.stdout)):
            failure = 'tls-verification-failed'
    except subprocess.TimeoutExpired:
        failure = 'tls-timeout'
    except (OSError, subprocess.SubprocessError):
        failure = 'tls-unavailable'
    after = default_generation_observation(root, state, include_identity=True)
    if (not isinstance(after, dict) or after.get('_identity') != before['_identity']
            or public_ca_digest(ca) != digest or read_state(root, args.lane) != state):
        return unknown
    if failure:
        return {'status': failure, 'lane': DEFAULT_SHARED_LANE,
                'detail': 'TLS probe did not verify the shared proxy signer.'}
    token = hashlib.sha256(json.dumps(before['_identity'], separators=(',', ':')).encode()).hexdigest()
    return {'status': 'attested', 'lane': DEFAULT_SHARED_LANE, 'signer': 'verified',
            'generation_sha256': token, 'ca_sha256': digest, 'ca_cert': str(ca),
            'observation': before['status'], 'listen_host': before['listen_host'],
            'detail': 'Point-in-time signer observation, assuming no local redirection; not lifecycle ownership or future readiness.'}


def status_lane(args: argparse.Namespace) -> dict[str, Any]:
    if args.lane != DEFAULT_SHARED_LANE:
        return task_status_lane(args)
    root = Path(args.root).expanduser()
    state = read_state(root, args.lane)
    if not state:
        return {"status": "not-found", "lane": args.lane}
    if (args.lane == DEFAULT_SHARED_LANE and root == DEFAULT_ROOT
            and state.get('status') in {'running', 'already-running'}):
        observed = default_generation_observation(root, state)
        if observed is not None and read_state(root, args.lane) == state:
            return observed
        return {"status": "unknown-state", "lane": args.lane,
                "detail": "shared unit identity is unproven; inspect without starting or stopping"}
    state["alive"] = pid_alive(state.get("pid"))
    if args.lane == DEFAULT_SHARED_LANE and state.get('status') in {'running', 'already-running'} and not state['alive']:
        return {"status": "unknown-state", "lane": args.lane,
                "detail": "recorded running process is absent; inspect before starting"}
    if (not state['alive'] and state.get('status') in {'start-failed', 'start-timeout'}
            and state.get('cleanup') == 'stopped'):
        state['previous_status'] = state['status']
        state['status'] = 'stopped'
    if args.lane == DEFAULT_SHARED_LANE and state.get('ca_cert'):
        fingerprint = signer_fingerprint(Path(state['ca_cert']).expanduser())
        expected = state.get('ca_started_sha256')
        state['ca_identity'] = ('legacy-unverified' if not expected else
                                'observed-at-readiness' if fingerprint == expected else 'changed')
        state['ca_signer_sha256'] = fingerprint if not expected or fingerprint == expected else None
    if state.get("port"):
        state["port_open"] = not can_bind_localhost(int(state["port"]))
    return state


def stop_lane(args: argparse.Namespace) -> dict[str, Any]:
    if args.lane != DEFAULT_SHARED_LANE:
        return task_stop_lane(args)
    # A PID in legacy state does not establish process or generation ownership.
    # Leave both the process and capture untouched; the manager can only finish
    # a listener whose exact binding it owns.
    return {"status": "unmanaged-stop-unsupported", "lane": args.lane,
            "detail": "legacy PID is not generation-bound; inspect and recover without signalling it"}


def replay_flows(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).expanduser()
    state = state_for_flow(root, args.lane, args.flow_file)
    if state is None:
        return {'status': 'capture-conflict', 'lane': args.lane}
    flow_file = Path(args.flow_file or state.get("flow_file", "")).expanduser()
    capture_fd, failure = open_readback(state, flow_file, not args.flow_file or bool(state.get('index_lane')))
    if failure:
        return failure
    assert capture_fd is not None
    with os.fdopen(capture_fd, 'rb') as capture:
        return _replay_open_capture(args, root, flow_file, capture.fileno())


def _replay_open_capture(args: argparse.Namespace, root: Path, flow_file: Path, capture_fd: int) -> dict[str, Any]:
    directory = lane_dir(root, args.lane)
    # Each replay owns a new private directory, so older artifacts, including
    # links or files with permissive modes, are never reused or truncated.
    replay_dir = Path(tempfile.mkdtemp(prefix="replay-", dir=directory))
    replay_file = replay_dir / "replay.mitm"
    replay_log = replay_dir / "replay.log"
    # mitmdump opens the output path itself; reserve it privately before launch.
    fd = os.open(replay_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    command = [
        args.mitmdump,
        "-n",
        "-C",
        str(flow_file),
        "-w",
        str(replay_file),
        "--set",
        "flow_detail=0",
    ]
    command[command.index('-C') + 1] = f'/proc/self/fd/{capture_fd}'
    proc = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=mitm_env(),
        timeout=args.timeout,
        pass_fds=(capture_fd,),
    )
    fd = os.open(replay_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as log:
        log.write(proc.stdout)
    return {
        "status": "replayed" if proc.returncode == 0 else "replay-failed",
        "returncode": proc.returncode,
        "flow_file": str(flow_file),
        "replay_file": str(replay_file),
        "replay_log": str(replay_log),
    }


def index_store(args: argparse.Namespace) -> dict[str, Any]:
    script = Path(__file__).resolve().parent / "proxy_store.py"
    if not script.is_file():
        return {"status": "missing-proxy-store", "script": str(script)}
    executable = shutil.which(args.mitmdump)
    if not executable:
        return {"status": "mitmdump-interpreter-unavailable"}
    shebang = Path(executable).resolve().open("rb").readline(256).decode("utf-8", errors="replace").strip()
    python = shebang[2:] if shebang.startswith("#!/") else ""
    if not Path(python).is_file():
        return {"status": "mitmdump-interpreter-unavailable"}
    system_reader = (Path(executable).resolve() == Path('/usr/bin/mitmdump'))
    if Path(python).resolve().name in {'sh', 'bash', 'dash', 'zsh', 'ksh', 'fish'}:
        if not Path('/usr/bin/mitmdump').is_file() or not Path('/usr/bin/python3').is_file():
            return {"status": "mitmdump-interpreter-unavailable"}
        python = '/usr/bin/python3'
        system_reader = True
    state = state_for_flow(Path(args.root).expanduser(), args.lane, getattr(args, 'flow_file', None))
    if state is None:
        return {'status': 'capture-conflict', 'lane': args.lane}
    index_lane = state.get("index_lane") or args.lane
    selected_flow = getattr(args, "flow_file", None) or state.get("flow_file")
    command = [python, *(['-s'] if system_reader else []), str(script), "--json", "--db", args.db,
               "index-lane", "--lane", index_lane]
    for name in ("program", "task", "run_id", "agent_id",
                 "account_label", "runtime_host", "proxy_host", "proxy_port",
                 "proxy_server", "transport", "browser_profile_id", "session_source", "note"):
        value = getattr(args, name, None)
        if value is None:
            value = state.get(name)
        if value is not None:
            command.extend(("--" + name.replace("_", "-"), str(value)))
    if not args.store_full_requests:
        command.append("--no-full-requests")
    # Give the indexer precisely the selected generation's recorded state.
    # Reading the logical lane directory here would borrow the current owner's
    # metadata when retrying an older, especially legacy, capture.
    with tempfile.TemporaryDirectory(prefix='mitm-index-state-') as temporary:
        write_state(Path(temporary), index_lane, state)
        command.extend(("--lane-root", temporary, "--receipt-metadata"))
        if not selected_flow:
            return {'status': 'missing-flow-file', 'flow_file': '', 'lane': index_lane}
        capture_fd, failure = open_readback(state, Path(selected_flow).expanduser(),
                                           not getattr(args, 'flow_file', None) or bool(state.get('index_lane')))
        if failure:
            return failure
        assert capture_fd is not None
        try:
            # Resolve provenance from the open file, never from a prior symlink
            # lookup. Verify the descriptor's name still names that inode; an
            # unlinked or renamed-away capture cannot supply reliable metadata.
            try:
                resolved_flow = os.readlink(f'/proc/self/fd/{capture_fd}')
                opened = os.fstat(capture_fd)
                named = os.stat(resolved_flow)
                if not os.path.isabs(resolved_flow) or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                    raise OSError('capture path no longer identifies open file')
            except OSError:
                return {'status': 'capture-unavailable', 'flow_file': str(selected_flow)}
            command.extend(('--flow-file', resolved_flow, '--flow-fd', str(capture_fd),
                            '--flow-resolved', resolved_flow))
            result = subprocess.run(command, capture_output=True, text=True, env=mitm_env(),
                                    check=False, pass_fds=(capture_fd,))
        finally:
            os.close(capture_fd)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = None
    if result.returncode:
        if isinstance(payload, dict) and payload.get("status") == "missing-flow-file":
            return payload
        return {"status": "index-failed", "returncode": result.returncode}
    return payload if isinstance(payload, dict) else {"status": "index-failed", "detail": "proxy store returned no JSON"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start, stop, and replay a mitmproxy lane.")
    parser.add_argument("--root", default=str(DEFAULT_ROOT), help="Lane state root.")
    parser.add_argument("--lane", default="default", help="Lane name.")
    parser.add_argument("--mitmdump", help="mitmdump executable.")
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="Start mitmdump for this lane.")
    start.add_argument("--port", type=int, default=8081)
    start.add_argument("--preserve-default-flow", action="store_true", help="Require the history-preserving shared-default implementation.")
    start.add_argument("--require-user-systemd", action="store_true", help="Require durable user-systemd supervision for the shared default.")
    start.add_argument("--listen-host", default="127.0.0.1")
    start.add_argument("--proxy-host", default="127.0.0.1", help="Advertised host agents will use in the proxy URL.")
    start.add_argument("--program", help="Optional program/target slug for later indexing.")
    start.add_argument("--task", help="Optional task label for later indexing.")
    start.add_argument("--account", help="Optional account/profile alias for later indexing.")
    start.add_argument("--account-label", help="Optional stable account label for later indexing.")
    start.add_argument("--run-id", help="Optional agent run id for later indexing.")
    start.add_argument("--agent-id", help="Optional agent id for later indexing.")
    start.add_argument("--runtime-host", help="Optional runtime hostname for later indexing.")
    start.add_argument("--transport", default="browser", help="Traffic source, e.g. browser, curl, httpx, tool.")
    start.add_argument("--browser-profile-id", help="Optional disposable browser profile id/path for later indexing.")
    start.add_argument("--session-source", help="Optional auth/session source label for later indexing.")
    start.add_argument("--profile-dir", help="Optional Chromium profile path for later indexing.")
    start.set_defaults(func=start_lane)

    status = sub.add_parser("status", help="Show lane state.")
    status.set_defaults(func=status_lane)

    observation = sub.add_parser("observe-default", help="Observe the shared default without socket or CA probes.")
    observation.set_defaults(func=observe_default)

    classification = sub.add_parser("classify-default-absence", help="Classify a clean absent or stopped shared default without lifecycle actions.")
    classification.set_defaults(func=classify_default_absence)

    attestation = sub.add_parser("attest-default", help="Attest the observed shared-default signer with a bounded TLS probe.")
    attestation.set_defaults(func=attest_default)

    stop = sub.add_parser("stop", help="Stop the lane.")
    stop.set_defaults(func=stop_lane)

    replay = sub.add_parser("replay-flows", help="Replay captured client flows.")
    replay.add_argument("--flow-file", help="Override flow file. Defaults to lane state.")
    replay.add_argument("--timeout", type=int, default=30)
    replay.set_defaults(func=replay_flows)

    index = sub.add_parser("index-store", help="Index this lane into the sanitized proxy SQLite store.")
    index.add_argument("--db", default=str(Path("~/.local/share/ghost/proxy-store/proxy_store.sqlite").expanduser()))
    index.add_argument("--flow-file", help="Override flow file. Defaults to lane state.")
    index.add_argument("--program")
    index.add_argument("--task")
    index.add_argument("--run-id")
    index.add_argument("--agent-id")
    index.add_argument("--account-label")
    index.add_argument("--runtime-host")
    index.add_argument("--proxy-host")
    index.add_argument("--proxy-port", type=int)
    index.add_argument("--proxy-server")
    index.add_argument("--transport")
    index.add_argument("--browser-profile-id")
    index.add_argument("--session-source")
    index.add_argument("--note")
    index.add_argument(
        "--no-full-requests",
        dest="store_full_requests",
        action="store_false",
        help="Only index sanitized metadata; do not store replay packets.",
    )
    index.set_defaults(func=index_store, store_full_requests=True)

    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()
    if args.mitmdump is None:
        args.mitmdump = DEFAULT_MITMDUMP
        if args.lane == DEFAULT_SHARED_LANE and args.command == 'start' and args.port == 8080:
            selected = shutil.which(DEFAULT_MITMDUMP)
            checkout_bin = Path(__file__).resolve().parents[3] / '.venv/bin/mitmdump'
            if selected and Path(selected).resolve() == checkout_bin.resolve():
                args.mitmdump = '/usr/bin/mitmdump'
    return args


def legacy_read_state(root: Path, lane: str) -> dict[str, Any]:
    path = state_path(root, lane)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"status": "corrupt-state", "state_path": str(path)}


def legacy_wait_for_port(port: int, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.1)
    return False


def task_start_lane(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).expanduser().absolute()
    if not args.lane or args.lane in ('.', '..') or '/' in args.lane or '\0' in args.lane:
        return {'status': 'capture-unavailable', 'lane': args.lane}
    directory = lane_dir(root, args.lane)
    if not _outside_shared(directory) or not _local_filesystem(directory):
        return {'status': 'capture-unavailable', 'lane': args.lane}
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not _safe_existing_directories(directory):
        return {'status': 'capture-unavailable', 'lane': args.lane}
    fd = os.open(directory / '.start.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return _start_lane_locked(args, root)
    finally:
        os.close(fd)


def task_status_lane(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).expanduser()
    state = legacy_read_state(root, args.lane)
    if not state:
        return {"status": "not-found", "lane": args.lane}
    state["alive"] = pid_alive(state.get("pid"))
    if state.get("port"):
        state["port_open"] = not can_bind_localhost(int(state["port"]))
    return state


def task_stop_lane(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).expanduser().absolute()
    if not args.lane or args.lane in ('.', '..') or '/' in args.lane or '\0' in args.lane:
        return {'status': 'capture-unavailable', 'lane': args.lane}
    directory = lane_dir(root, args.lane)
    if not directory.exists():
        return {'status': 'not-found', 'lane': args.lane}
    if not _outside_shared(directory) or not _local_filesystem(directory) or not _safe_existing_directories(directory):
        return {'status': 'capture-unavailable', 'lane': args.lane}
    fd = os.open(directory / '.start.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return _stop_lane_locked(args, root)
    finally:
        os.close(fd)



def _start_lane_locked(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    with ExitStack() as resources:
        return _start_lane_with_resources(args, root, resources)


def _start_lane_with_resources(args: argparse.Namespace, root: Path, resources: ExitStack) -> dict[str, Any]:
    current = read_state(root, args.lane)
    if current.get("status") in ("starting", "corrupt-state") and not current.get("pid"):
        return {"status": "state-unavailable", "lane": args.lane}
    if pid_alive(current.get("pid")):
        current["status"] = "already-running"
        return current
    if current.get('index_lane') and current.get('status') != 'stopped':
        return {'status': 'capture-recovery-required', 'lane': args.lane,
                'flow_file': current.get('flow_file')}
    if not can_bind_localhost(args.port):
        return {"status": "port-unavailable", "lane": args.lane, "port": args.port}

    directory = lane_dir(root, args.lane)
    confdir = directory / "mitmproxy"
    log_file = directory / "mitmdump.log"
    if any(not _outside_shared(p) or not _local_filesystem(p) for p in (confdir, log_file)):
        return {'status': 'capture-unavailable', 'lane': args.lane}
    confdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Pin the prospective mount before choosing or reserving a destination.
    # A missing root may still use the normal local fallback.
    mount_fd = None
    try:
        artifact = Path(os.environ.get('BOUNTY_ARTIFACT_ROOT', '/mnt/bounty')).expanduser()
        if artifact.is_absolute():
            mount_fd = os.open(artifact, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
            resources.callback(os.close, mount_fd)
    except OSError:
        pass
    try:
        flow_file, capture_mount = capture_destination(root, args.lane, args.program)
        capture_fd = os.open(flow_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        resources.callback(os.close, capture_fd)
        if capture_mount and (mount_fd is None or _mount_id(mount_fd) != _mount_id(capture_fd)):
            raise OSError('capture destination does not belong to pinned mount')
        capture_info = os.fstat(capture_fd)
        mount_info = os.fstat(mount_fd) if mount_fd is not None and capture_mount else None
    except (OSError, ValueError) as exc:
        return {'status': 'capture-unavailable', 'lane': args.lane, 'detail': str(exc)}
    index_lane = "capture-" + uuid.uuid4().hex
    log_file = directory / "mitmdump.log"

    command = [
        args.mitmdump,
        "--listen-host",
        args.listen_host,
        "--listen-port",
        str(args.port),
        "--set",
        f"confdir={confdir}",
        "--set",
        "flow_detail=0",
        "-w",
        str(flow_file),
    ]
    state = {
        "status": "starting",
        "lane": args.lane,
        "program": args.program,
        "task": args.task,
        "account": args.account_label or args.account,
        "account_label": args.account_label or args.account,
        "profile_dir": args.profile_dir,
        "run_id": args.run_id,
        "agent_id": args.agent_id,
        "runtime_host": args.runtime_host,
        "proxy_host": args.proxy_host,
        "proxy_port": args.port,
        "transport": args.transport,
        "browser_profile_id": args.browser_profile_id or args.profile_dir,
        "session_source": args.session_source,
        "pid": None,
        "index_lane": index_lane,
        "capture_mount": capture_mount,
        "capture_identity": [capture_info.st_dev, capture_info.st_ino],
        "mount_identity": ([mount_info.st_dev, mount_info.st_ino] if mount_info else None),
        "port": args.port,
        "listen_host": args.listen_host,
        "proxy_server": f"http://{args.proxy_host}:{args.port}",
        "root": str(root),
        "confdir": str(confdir),
        "ca_cert": str(confdir / "mitmproxy-ca-cert.pem"),
        "flow_file": str(flow_file),
        "log_file": str(log_file),
        "command": command,
    }
    if current:
        # Retain the previous generation, including legacy state, before reuse.
        receipt_dir = Path(tempfile.mkdtemp(prefix='receipt-', dir=directory))
        receipt = receipt_dir / 'state.json'
        fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as handle:
            json.dump(current, handle, indent=2, sort_keys=True)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
    write_state(root, args.lane, state)
    failure = verify_recorded_capture(state)
    if capture_mount and not failure:
        try:
            check_fd = os.open(capture_mount, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                if (mount_fd is None or _mount_id(check_fd) != _mount_id(mount_fd)
                        or not _outside_shared(flow_file)):
                    failure = {'status': 'capture-unavailable'}
            finally:
                os.close(check_fd)
        except (OSError, ValueError):
            failure = {'status': 'capture-unavailable'}
    if failure:
        state['status'] = 'capture-unavailable'
        write_state(root, args.lane, state)
        return state
    # The subprocess reopens this inherited descriptor, never the mutable mount
    # pathname. Even lazy unmount/replacement cannot redirect capture writes.
    launch_command = command[:-1] + [f'/proc/self/fd/{capture_fd}']
    try:
        with log_file.open("ab") as log_handle:
            proc = subprocess.Popen(launch_command, stdout=log_handle, stderr=subprocess.STDOUT,
                                    env=mitm_env(), start_new_session=True, pass_fds=(capture_fd,))
    except OSError:
        state["status"] = "start-failed"
        write_state(root, args.lane, state)
        raise
    state["pid"] = proc.pid
    write_state(root, args.lane, state)
    state["status"] = "running" if wait_for_port(args.port) else "start-timeout"
    write_state(root, args.lane, state)
    return state


def _stop_lane_locked(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    state = read_state(root, args.lane)
    pid = state.get("pid")
    if pid_alive(pid):
        os.killpg(pid, signal.SIGTERM)
        for _ in range(30):
            if not pid_alive(pid):
                break
            time.sleep(0.1)
        if pid_alive(pid):
            os.killpg(pid, signal.SIGKILL)
    state["alive"] = pid_alive(pid)
    state["status"] = "stop-failed" if state["alive"] else "stopped"
    write_state(root, args.lane, state)
    return state

def main() -> int:
    args = parse_args()
    result = args.func(args)
    if getattr(args, 'lane', None) != DEFAULT_SHARED_LANE and getattr(args, 'command', None) in {'start', 'status', 'stop', 'replay-flows', 'index-store'}:
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"{result.get('status')}: {result.get('lane', '')}")
            for key in ("proxy_server", "ca_cert", "flow_file", "log_file", "pid"):
                if result.get(key) is not None:
                    print(f"{key}: {result[key]}")
        if result.get('index_lane') and result.get('status') in {'start-timeout', 'start-failed'}:
            return 2
        return 0 if result.get("status") not in {"port-unavailable", "missing-flow-file", "replay-failed", "mitmdump-interpreter-unavailable", "index-failed", "missing-proxy-store", "state-unavailable", "corrupt-state", "capture-conflict", "capture-unavailable", "capture-recovery-required", "stop-failed"} else 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{result.get('status')}: {result.get('lane', '')}")
        for key in ("detail", "unit", "cleanup", "proxy_server", "ca_cert", "flow_file", "log_file", "pid"):
            if result.get(key) is not None:
                print(f"{key}: {result[key]}")
    return 0 if result.get('status') not in {'port-unavailable', 'ca-pending', 'start-outcome-unknown', 'start-timeout', 'start-failed', 'start-cleanup-failed', 'unsupported-runtime', 'unsupported-listen-host', 'unsupported-proxy-host', 'supervisor-unavailable', 'unknown-state', 'corrupt-state', 'missing-flow-file', 'missing-proxy-store', 'replay-failed', 'mitmdump-interpreter-unavailable', 'index-failed', 'unmanaged-start-unsupported', 'unmanaged-stop-unsupported', 'tls-verification-failed', 'tls-timeout', 'tls-unavailable', 'state-unavailable', 'capture-conflict', 'capture-unavailable', 'capture-recovery-required', 'stop-failed'} else 2


if __name__ == "__main__":
    raise SystemExit(main())
