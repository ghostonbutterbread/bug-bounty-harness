#!/usr/bin/env python3
"""Lease and manage Hoster-backed mitmproxy lanes through one-shot SSH."""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import re
import os
import pwd
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


DEFAULT_HOST = "hoster"
DEFAULT_USER = "ryushe"
DEFAULT_KEY = Path("/home/ryushe/.ssh/hoster")
DEFAULT_LOCAL_LANE_ROOT = Path("~/.local/state/ghost/mitm-lanes").expanduser()
DEFAULT_PROXY_HOST = "hoster"
DEFAULT_GENERAL_LANE = "hoster-default-8080"
DEFAULT_GENERAL_PORT = 8080
DEFAULT_PORT_MIN = 8081
DEFAULT_PORT_MAX = 8090


def ssh_base(args: argparse.Namespace) -> list[str]:
    return [
        "ssh",
        "-i",
        str(Path(args.ssh_key).expanduser()),
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={args.connect_timeout}",
        "-o",
        "ControlMaster=no",
        "-T",
        f"{args.ssh_user}@{args.ssh_host}",
    ]


def remote_command(args: argparse.Namespace, argv: list[str]) -> str:
    """Run the lane-installed dispatcher; remote source roots are never guessed."""
    return 'PATH="$HOME/.local/bin:/usr/bin:/bin"; export PATH; ' + " ".join(shlex.quote(part) for part in argv)


def running_on_requested_hoster(args: argparse.Namespace) -> bool:
    """Avoid SSH-to-self; the current checkout remains the lane authority."""
    try:
        if args.ssh_user != pwd.getpwuid(os.geteuid()).pw_name:
            return False
    except (AttributeError, KeyError):
        return False
    requested = args.ssh_host.strip().lower().rstrip(".")
    local_names = {
        socket.gethostname().lower().rstrip("."),
        socket.getfqdn().lower().rstrip("."),
        "localhost", "127.0.0.1", "::1",
    }
    return requested in local_names


def local_bbh_command(argv: list[str]) -> list[str]:
    """Run the dispatcher from this checkout rather than relying on PATH."""
    if not argv or argv[0] != "bbh":
        raise ValueError("local Hoster dispatch requires a BBH command")
    root = Path(__file__).resolve().parents[3]
    return [sys.executable, str(root / "scripts" / "bbh.py"), *argv[1:]]


def parse_dispatch_json(output: Any) -> dict[str, Any] | None:
    """Bound JSON parsing and reject malformed or non-UTF-8 responses."""
    try:
        if not isinstance(output, str) or len(output) > 65536 or len(output.encode('utf-8')) > 65536:
            return None
        value = json.loads(output)
    except (ValueError, RecursionError, UnicodeError):
        return None
    return value if isinstance(value, dict) else None


def run_remote(args: argparse.Namespace, argv: list[str]) -> dict[str, Any]:
    local = running_on_requested_hoster(args)
    command = local_bbh_command(argv) if local else ssh_base(args) + [remote_command(args, argv)]
    if args.dry_run:
        return {"status": "dry-run", "local_command" if local else "ssh_command": command}
    try:
        proc = subprocess.run(command, check=False, text=True, encoding='utf-8', stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        return {"status": "dispatch-timeout", "detail": "Dispatch timed out; outcome unknown. Inspect lane status before retrying."}
    except UnicodeError:
        return {"status": "dispatch-invalid", "detail": "Dispatcher output was not UTF-8; outcome unknown. Inspect lane status before retrying."}
    except OSError:
        return {"status": "local-failed" if local else "ssh-failed", "detail": "Cannot execute dispatcher; check installation and permissions."}
    code_key = "local_returncode" if local else "ssh_returncode"
    if proc.returncode:
        failure = parse_dispatch_json(proc.stdout)
        result = {"status": "local-failed" if local else "ssh-failed", code_key: proc.returncode,
                  "detail": "Dispatch failed; check connectivity and dispatcher status."}
        if (isinstance(failure, dict) and isinstance(failure.get('status'), str)
                and failure['status'] in {'start-timeout', 'start-failed', 'start-cleanup-failed', 'corrupt-state', 'unknown-state', 'ca-pending'}):
            result['remote_status'] = failure['status']
            token = failure.get('generation_sha256')
            if (failure['status'] == 'ca-pending' and failure.get('lane') == DEFAULT_GENERAL_LANE
                    and isinstance(token, str) and re.fullmatch('[0-9a-f]{64}', token)):
                result['generation_sha256'] = token
                result['lane'] = DEFAULT_GENERAL_LANE
        return result
    parsed = parse_dispatch_json(proc.stdout)
    if not isinstance(parsed, dict) or not isinstance(parsed.get('status'), str) or not parsed['status']:
        return {"status": "dispatch-invalid", code_key: proc.returncode,
                "detail": "Dispatcher returned invalid status; inspect the lane before retrying."}
    parsed[code_key] = proc.returncode
    return parsed


def copy_remote_file(args: argparse.Namespace, remote_path: str, local_path: Path) -> dict[str, Any]:
    local_path.parent.mkdir(parents=True, exist_ok=True)
    if running_on_requested_hoster(args):
        source = Path(remote_path).expanduser()
        try:
            if source.resolve() == local_path.resolve():
                return {"status": "already-local", "local_path": str(local_path), "remote_path": str(source)}
            shutil.copyfile(source, local_path)
        except OSError:
            return {"status": "copy-failed", "copy_error": "Cannot copy CA; check source and destination permissions."}
        return {"status": "copied", "local_path": str(local_path), "remote_path": str(source)}
    try:
        scp_host = f"[{args.ssh_host}]" if ipaddress.ip_address(args.ssh_host).version == 6 else args.ssh_host
    except ValueError:
        scp_host = args.ssh_host
    command = [
        "scp",
        "-i",
        str(Path(args.ssh_key).expanduser()),
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={args.connect_timeout}",
        "-q",
        f"{args.ssh_user}@{scp_host}:{remote_path}",
        str(local_path),
    ]
    if args.dry_run:
        return {"status": "dry-run", "scp_command": command, "local_path": str(local_path)}
    try:
        proc = subprocess.run(
            command, check=False, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=args.timeout,
        )
    except subprocess.TimeoutExpired:
        return {"status": "copy-failed", "copy_error": "CA copy timed out; check SSH connectivity and retry."}
    except UnicodeError:
        return {"status": "copy-failed", "copy_error": "CA copy output was invalid; inspect the lane before retrying."}
    except OSError:
        return {"status": "copy-failed", "copy_error": "Cannot execute SCP; check its installation and permissions."}
    return {
        "status": "copied" if proc.returncode == 0 else "copy-failed",
        "local_path": str(local_path),
        "remote_path": remote_path,
        "scp_returncode": proc.returncode,
        "scp_stderr": "CA copy failed; check connectivity and remote file permissions." if proc.returncode else "",
    }


def value_args(mapping: dict[str, Any]) -> list[str]:
    parts: list[str] = []
    for key, value in mapping.items():
        if value is None:
            continue
        parts.extend([f"--{key.replace('_', '-')}", str(value)])
    return parts


def acquire_start(args: argparse.Namespace) -> dict[str, Any]:
    lease = run_remote_legacy(
        args,
        [
            "bbh",
            "skills/chromium-test/scripts/proxy_store.py",
            "--json",
            "lease-acquire",
            *value_args(
                {
                    "agent_id": args.agent_id,
                    "run_id": args.run_id,
                    "program": args.program,
                    "task": args.task,
                    "account_label": args.account_label,
                    "runtime_host": args.runtime_host,
                    "proxy_host": args.proxy_host,
                    "port_min": args.port_min,
                    "port_max": args.port_max,
                    "ttl_seconds": args.ttl_seconds,
                    "note": args.note,
                }
            ),
        ],
    )
    if lease.get("status") not in {"leased", "dry-run"}:
        return {"status": "lease-failed", "lease": lease}
    if args.dry_run:
        return {"status": "dry-run", "lease": lease}

    lease_row = lease.get("lease") or {}
    lane = str(lease_row.get("lane") or args.lane)
    port = int(lease_row.get("proxy_port"))
    start = run_remote_legacy(
        args,
        [
            "bbh",
            "skills/chromium-test/scripts/mitm_lane.py",
            "--json",
            "--lane",
            lane,
            "start",
            *value_args(
                {
                    "listen_host": args.listen_host,
                    "proxy_host": args.proxy_host,
                    "port": port,
                    "program": args.program,
                    "task": args.task,
                    "agent_id": args.agent_id,
                    "run_id": args.run_id,
                    "account_label": args.account_label,
                    "runtime_host": args.runtime_host,
                    "transport": args.transport,
                    "browser_profile_id": args.browser_profile_id,
                    "session_source": args.session_source,
                    "profile_dir": args.profile_dir,
                }
            ),
        ],
    )
    if start.get("status") not in {"running", "already-running"}:
        run_remote_legacy(
            args,
            [
                "bbh",
                "skills/chromium-test/scripts/proxy_store.py",
                "--json",
                "lease-release",
                "--lane",
                lane,
            ],
        )
        return {"status": "start-failed", "lease": lease, "start": start}
    return {
        "status": "running",
        "lease": lease_row,
        "start": start,
        "lane": lane,
        "proxy_server": lease_row.get("proxy_server") or f"http://{args.proxy_host}:{port}",
        "proxy_port": port,
    }


def index_stop_release(args: argparse.Namespace) -> dict[str, Any]:
    stop = run_remote_legacy(
        args,
        [
            "bbh",
            "skills/chromium-test/scripts/mitm_lane.py",
            "--json",
            "--lane",
            args.lane,
            "stop",
        ],
    )
    index = run_remote_legacy(
        args,
        [
            "bbh",
            "skills/chromium-test/scripts/mitm_lane.py",
            "--json",
            "--lane",
            args.lane,
            "index-store",
            *value_args(
                {
                    "agent_id": args.agent_id,
                    "run_id": args.run_id,
                    "account_label": args.account_label,
                    "runtime_host": args.runtime_host,
                    "proxy_host": args.proxy_host,
                    "proxy_port": args.proxy_port,
                    "transport": args.transport,
                    "browser_profile_id": args.browser_profile_id,
                    "session_source": args.session_source,
                    "note": args.note,
                }
            ),
        ],
    )
    release = run_remote_legacy(
        args,
        [
            "bbh",
            "skills/chromium-test/scripts/proxy_store.py",
            "--json",
            "lease-release",
            "--lane",
            args.lane,
        ],
    )
    status = "released" if release.get("status") == "released" else "release-failed"
    return {"status": status, "stop": stop, "index": index, "release": release}


def advertised_proxy(args: argparse.Namespace) -> str:
    """Choose a caller-side endpoint; DNS and routing still require a smoke test."""
    if running_on_requested_hoster(args):
        return "http://127.0.0.1:8080"
    host = args.proxy_host if args.proxy_host is not None else args.ssh_host
    if not isinstance(host, str) or not host or host != host.strip():
        raise ValueError("configure a non-loopback --proxy-host or SSH host")
    if '%' in host:
        raise ValueError("configure a valid non-loopback --proxy-host or SSH host")
    try:
        address = ipaddress.ip_address(host[1:-1] if host.startswith('[') and host.endswith(']') else host)
    except ValueError:
        labels = host.rstrip('.').split('.')
        if (len(host) > 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in labels)
                or 'localhost' in (label.lower() for label in labels) or all(c.isdigit() or c == '.' for c in host)):
            raise ValueError("configure a valid non-loopback --proxy-host or SSH host")
        return f"http://{host}:8080"
    classified = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address
    if classified.is_loopback or classified.is_unspecified or classified.is_link_local or classified.is_multicast:
        raise ValueError("configure a non-loopback --proxy-host or SSH host")
    if address.version == 6:
        raise ValueError("direct IPv6 proxy address is incompatible with the IPv4-only listener; use an IPv4 address or hostname")
    return f"http://{host}:8080"


def status_default(args: argparse.Namespace, *, classify: bool = False) -> dict[str, Any]:
    """Read-only diagnostic; this does not establish proxy or CA readiness."""
    if args.lane != DEFAULT_GENERAL_LANE:
        return {'status': 'unknown-state', 'detail': 'Only the configured shared default can be observed.'}
    result = run_remote(args, ['bbh', 'skills/chromium-test/scripts/mitm_lane.py',
                               '--json', '--lane', DEFAULT_GENERAL_LANE, 'observe-default'])
    status = result.get('status')
    unit = result.get('unit')
    valid_unit = ((status == 'observed-legacy' and unit == 'hoster-mitm-default-8080.service')
                  or (status == 'observed-fresh' and isinstance(unit, str)
                      and re.fullmatch(r'ghost-mitm-default-8080-[0-9a-f]{32}\.service', unit)))
    if (valid_unit and result.get('lane') == DEFAULT_GENERAL_LANE
            and type(result.get('pid')) is int and 0 < result['pid'] <= 2147483647
            and result.get('port') == 8080 and result.get('listen_host') in ('0.0.0.0', '127.0.0.1')
            and (status != 'observed-legacy' or result['listen_host'] == '0.0.0.0')
            and result.get('signer') == 'unverified'):
        observation = {'status': status, 'lane': DEFAULT_GENERAL_LANE,
                'unit': unit, 'pid': result['pid'],
                'port': 8080, 'listen_host': result['listen_host'], 'signer': 'unverified',
                'detail': 'Read-only observation; signer and proxy readiness are unverified.'}
        token = result.get('generation_sha256')
        if isinstance(token, str) and re.fullmatch('[0-9a-f]{64}', token):
            observation['generation_sha256'] = token
        flow_token = result.get('flow_path_sha256')
        if isinstance(flow_token, str) and re.fullmatch('[0-9a-f]{64}', flow_token):
            observation['flow_path_sha256'] = flow_token
        return observation
    unavailable: dict[str, Any] = {'status': 'unknown-state', 'lane': DEFAULT_GENERAL_LANE,
                   'detail': 'Shared listener observation unavailable; inspect without starting or stopping.'}
    # Do not turn transport errors or malformed/older replies into permission
    # to start: only the observer's structured unknown enables classification.
    code_key = 'local_returncode' if running_on_requested_hoster(args) else 'ssh_returncode'
    if (classify and result.get('status') in ('local-failed', 'ssh-failed') and result.get(code_key) == 2
            and result.get('remote_status') in {'start-timeout', 'start-failed', 'start-cleanup-failed', 'corrupt-state'}):
        unavailable['_remote_status'] = result['remote_status']
    if (classify and result.get('status') in ('local-failed', 'ssh-failed')
            and type(result.get(code_key)) is int and result[code_key] == 2
            and result.get('remote_status') == 'unknown-state'):
        unavailable['_classify'] = True
    return unavailable


def ensure_default(args: argparse.Namespace) -> dict[str, Any]:
    if args.lane != DEFAULT_GENERAL_LANE or args.port != DEFAULT_GENERAL_PORT:
        return {"status": "start-failed", "lane": args.lane,
                "detail": "ensure-default supports only hoster-default-8080 on port 8080; use the manager for task proxies"}
    try:
        proxy_server = advertised_proxy(args)
    except ValueError as exc:
        return {"status": "start-failed", "lane": args.lane, "detail": str(exc)}
    if args.listen_host == "127.0.0.1" and not running_on_requested_hoster(args):
        return {"status": "start-failed", "lane": args.lane,
                "detail": "remote loopback listener is unreachable; use --listen-host 0.0.0.0 or run locally on Hoster"}
    if args.listen_host not in ('127.0.0.1', '0.0.0.0'):
        return {'status': 'start-failed', 'lane': args.lane, 'detail': 'Unsupported listener bind address; no start was attempted.'}
    start_command = ['bbh', 'skills/chromium-test/scripts/mitm_lane.py', '--json',
                     '--lane', DEFAULT_GENERAL_LANE, 'start', '--port', '8080',
                     '--listen-host', args.listen_host, '--proxy-host', '127.0.0.1',
                     '--preserve-default-flow', '--require-user-systemd']
    for field in ('program', 'task', 'agent_id', 'run_id', 'account_label',
                  'runtime_host', 'transport', 'session_source'):
        value = getattr(args, field, None)
        if value is not None:
            start_command.append(f"--{field.replace('_', '-')}={value}")
    if args.dry_run:
        return {'status': 'dry-run', 'lane': args.lane, 'proxy_server': proxy_server,
                'start': run_remote(args, start_command),
                'detail': 'Would observe and classify before a single locked start; no service was dispatched.'}
    status = status_default(args, classify=True)
    started = None
    status_name = status.get('status')
    if not isinstance(status_name, str) or status_name not in {'observed-legacy', 'observed-fresh'} or status.get('lane') != args.lane:
        if not status.get('_classify'):
            failure = {'status': 'unknown-state'}
            if status.get('_remote_status'):
                failure['remote_status'] = status['_remote_status']
            return {'status': 'start-failed', 'lane': args.lane, 'start': failure,
                    'detail': 'Listener state, port 8080 or bind address is unknown; no start was attempted. Inspect the listener without stopping it.'}
        absence = run_remote(args, ['bbh', 'skills/chromium-test/scripts/mitm_lane.py',
                                    '--json', '--lane', DEFAULT_GENERAL_LANE, 'classify-default-absence'])
        code_key = 'local_returncode' if running_on_requested_hoster(args) else 'ssh_returncode'
        if (type(absence.get(code_key)) is not int or absence[code_key] != 0
                or absence.get('lane') != args.lane or absence.get('status') not in {'not-found', 'stopped'}):
            return {'status': 'start-failed', 'lane': args.lane, 'start': {'status': 'unknown-state'},
                    'detail': 'Absence was not confirmed; no start was attempted. Inspect the listener without stopping it.'}
        started = run_remote(args, start_command)
        unit, pid, ca, digest, flow = (started.get('unit'), started.get('pid'), started.get('ca_cert'),
                                       started.get('ca_started_sha256'), started.get('flow_file'))
        if (type(started.get(code_key)) is not int or started[code_key] != 0 or started.get('status') != 'running'
                or started.get('lane') != args.lane or not isinstance(unit, str)
                or not re.fullmatch(r'ghost-mitm-default-8080-[0-9a-f]{32}\.service', unit)
                or type(pid) is not int or not 0 < pid <= 2147483647
                or started.get('port') != 8080 or started.get('listen_host') != args.listen_host
                or not isinstance(ca, str) or not isinstance(flow, str) or not flow
                or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
            return {'status': 'start-outcome-unknown', 'lane': args.lane,
                    'detail': 'The listener may be running. Inspect the lane and capture without retrying, stopping, or cleaning up.'}
        try:
            flow_digest = hashlib.sha256(flow.encode('utf-8')).hexdigest()
        except UnicodeError:
            return {'status': 'start-outcome-unknown', 'lane': args.lane,
                    'detail': 'The listener may be running. Inspect the lane and capture without retrying, stopping, or cleaning up.'}
        status = status_default(args)
        if (status.get('status') != 'observed-fresh' or status.get('unit') != unit or status.get('pid') != pid
                or status.get('listen_host') != args.listen_host or not status.get('generation_sha256')
                or status.get('flow_path_sha256') != flow_digest):
            return {'status': 'start-failed', 'lane': args.lane,
                    'detail': 'Start returned success but the submitted generation could not be observed; it may be running. Inspect without retrying or stopping.'}
    if status.get('listen_host') not in ('127.0.0.1', '0.0.0.0'):
        return {'status': 'start-failed', 'lane': args.lane, 'detail': 'Listener bind address is unverified.'}
    if status['listen_host'] == '127.0.0.1' and not running_on_requested_hoster(args):
        return {'status': 'start-failed', 'lane': args.lane, 'detail': 'Existing remote loopback listener is unreachable.'}
    deadline = None
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            ca_sync = {'status': 'copy-failed', 'copy_error': 'Public CA remained unavailable before the readiness deadline; existing CA was preserved.'}
            break
        ca_sync = sync_attested_default_ca(args, status, started, deadline=deadline)
        if ca_sync.get('status') != 'ca-pending' or not started:
            break
        if deadline is None:
            deadline = time.monotonic() + 8.0
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            ca_sync = {'status': 'copy-failed', 'copy_error': 'Public CA remained unavailable before the readiness deadline; existing CA was preserved.'}
            break
        time.sleep(min(0.1, remaining))
    if ca_sync.get('status') not in {'copied', 'already-local'}:
        if ca_sync.get('status') == 'post-publication-unknown':
            return {'status': 'start-failed', 'lane': args.lane, 'ca_sync': ca_sync,
                    'detail': 'CA was published but cleanup is uncertain; inspect the destination and listener without stopping or retrying.'}
        return {'status': 'start-failed', 'lane': args.lane, 'ca_sync': ca_sync,
                'detail': ('Start returned success; signer observation or CA staging failed. Inspect the running generation without retrying or stopping.'
                           if started else 'Signer observation or CA staging failed; no service action was attempted.')}
    return {'status': 'running', 'lane': args.lane, 'proxy_server': proxy_server, 'proxy_port': 8080,
            'local_ca_cert': ca_sync['local_path'], 'ca_sync': ca_sync,
            'detail': 'Point-in-time signer observation, assuming no local redirection; remote routing and future readiness are unverified.'}


def sync_attested_default_ca(args: argparse.Namespace, observation: dict[str, Any], started: dict[str, Any] | None = None, *, deadline: float | None = None) -> dict[str, Any]:
    """Stage a public CA only between matching generation-bound observations."""
    def bounded_args() -> argparse.Namespace | None:
        if deadline is None:
            return args
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        attempt = copy.copy(args)
        attempt.timeout = min(args.timeout, remaining)
        attempt.connect_timeout = min(args.connect_timeout, max(1, int(remaining)))
        return attempt

    def attest() -> tuple[str, str, str] | str | None:
        attempt = bounded_args()
        if attempt is None:
            return None
        result = run_remote(attempt, ['bbh', 'skills/chromium-test/scripts/mitm_lane.py',
                                   '--json', '--lane', args.lane, 'attest-default'])
        code_key = 'local_returncode' if running_on_requested_hoster(args) else 'ssh_returncode'
        if (started and result.get('status') in ('local-failed', 'ssh-failed')
                and result.get('remote_status') == 'ca-pending' and result.get('lane') == args.lane
                and type(result.get(code_key)) is int and result[code_key] == 2
                and result.get('generation_sha256') == observation.get('generation_sha256')):
            return 'ca-pending'
        generation, digest, path = (result.get('generation_sha256'), result.get('ca_sha256'), result.get('ca_cert'))
        if (result.get('status') != 'attested' or result.get('lane') != args.lane
                or result.get('signer') != 'verified'
                or result.get('observation') != observation.get('status')
                or result.get('listen_host') != observation.get('listen_host')
                or not isinstance(generation, str) or not re.fullmatch('[0-9a-f]{64}', generation)
                or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)
                or not isinstance(path, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', path)
                or '..' in Path(path).parts
                or not path.endswith('/hoster-default-8080/mitmproxy/mitmproxy-ca-cert.pem')):
            return None
        if generation != observation.get('generation_sha256'):
            return None
        if started and (digest != started.get('ca_started_sha256') or path != started.get('ca_cert')):
            return None
        return generation, digest, path

    failure = {'status': 'copy-failed', 'copy_error': 'Attestation or public CA validation failed; existing CA was preserved.'}
    initial = attest()
    if initial == 'ca-pending':
        return {'status': 'ca-pending'}
    if not isinstance(initial, tuple):
        return failure
    _, digest, remote_ca = initial
    local_path = Path(args.local_lane_root).expanduser() / args.lane / 'mitmproxy' / 'mitmproxy-ca-cert.pem'
    published = False
    try:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix='.ca-sync-', dir=local_path.parent)
        os.close(fd)
        temp = Path(name)
        try:
            attempt = bounded_args()
            if attempt is None or copy_remote_file(attempt, remote_ca, temp).get('status') != 'copied':
                return failure
            with temp.open('rb') as source:
                data = source.read(65537)
            if len(data) > 65536:
                return failure
            text = data.decode('ascii')
            if not re.fullmatch(r'\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*', text):
                return failure
            validate_ca(temp)
            if hashlib.sha256(ssl.PEM_cert_to_DER_cert(text.strip())).hexdigest() != digest:
                return failure
            if attest() != initial or (deadline is not None and time.monotonic() >= deadline):
                return failure
            if running_on_requested_hoster(args) and Path(remote_ca).resolve() == local_path.resolve():
                return {'status': 'already-local', 'local_path': str(local_path)}
            os.replace(temp, local_path)
            published = True
            return {'status': 'copied', 'local_path': str(local_path)}
        finally:
            temp.unlink(missing_ok=True)
    except (OSError, UnicodeError, ValueError, ssl.SSLError, subprocess.SubprocessError):
        if published:
            return {'status': 'post-publication-unknown', 'copy_error': 'CA was published but cleanup failed; inspect the destination.'}
        return failure


def sync_lane_ca_until_ready(args: argparse.Namespace, state: dict[str, Any]) -> dict[str, Any]:
    deadline = time.monotonic() + 8.0
    while True:
        remaining = max(0.01, deadline - time.monotonic())
        attempt = copy.copy(args)
        attempt.timeout = min(args.timeout, remaining)
        attempt.connect_timeout = min(args.connect_timeout, max(1, int(remaining)))
        result = sync_lane_ca(attempt, state)
        remaining = deadline - time.monotonic()
        if result.get('status') != 'copy-failed' or remaining <= 0:
            return result
        time.sleep(min(0.1, remaining))


def validate_ca(path: Path) -> None:
    if not path.is_file():
        raise ValueError('CA is not a regular file')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=path.read_text(encoding='ascii'))
    if not context.cert_store_stats()['x509_ca']:
        raise ValueError('certificate is not a CA')


def sync_lane_ca(args: argparse.Namespace, state: dict[str, Any]) -> dict[str, Any]:
    remote_ca = state.get("ca_cert")
    if not remote_ca:
        return {"status": "missing-remote-ca"}
    local_path = Path(args.local_lane_root).expanduser() / args.lane / "mitmproxy" / "mitmproxy-ca-cert.pem"
    try:
        verification = run_remote(args, ['bbh', 'skills/chromium-test/scripts/mitm_lane.py', '--json',
                                         '--lane', args.lane, 'status'])
        digest = verification.get('ca_signer_sha256')
        if verification.get('ca_identity') == 'changed':
            return {'status': 'identity-changed', 'copy_error': 'CA changed since listener start; inspect the running listener and CA without stopping it'}
        if (verification.get('status') not in {'running', 'already-running'}
                or verification.get('alive') is not True or verification.get('port_open') is not True
                or (state.get('pid') is not None and verification.get('pid') != state['pid'])
                or verification.get('ca_cert') != remote_ca
                or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)):
            return {'status': 'copy-failed', 'copy_error': 'CA signer unavailable or mismatched; inspect both CA files without stopping the listener'}
        local_path.parent.mkdir(parents=True, exist_ok=True)
        def validate_match(path: Path) -> None:
            validate_ca(path)
            text = path.read_text(encoding='ascii')
            begin, end = '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'
            start = text.index(begin)
            stop = text.index(end, start) + len(end)
            if text[:start].strip() or text[stop:].strip():
                raise ValueError('unexpected CA file content')
            if hashlib.sha256(ssl.PEM_cert_to_DER_cert(text[start:stop])).hexdigest() != digest:
                raise ValueError('CA signer mismatch')
        if running_on_requested_hoster(args) and Path(remote_ca).expanduser().resolve() == local_path.resolve():
            validate_match(local_path)
            return {"status": "already-local", "local_path": str(local_path), "remote_path": str(remote_ca),
                    "ca_identity": verification.get('ca_identity', 'legacy-unverified')}
        fd, name = tempfile.mkstemp(prefix='.ca-sync-', dir=local_path.parent)
        os.close(fd)
        try:
            temp = Path(name)
            result = copy_remote_file(args, str(remote_ca), temp)
            if result.get('status') != 'copied':
                return result
            validate_match(temp)
            os.replace(temp, local_path)
            return {**result, 'local_path': str(local_path),
                    'ca_identity': verification.get('ca_identity', 'legacy-unverified')}
        finally:
            Path(name).unlink(missing_ok=True)
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        return {'status': 'copy-failed', 'copy_error': 'CA copy failed or certificate is invalid; inspect source and retry'}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage Hoster mitmproxy lanes through SSH.")
    parser.add_argument("--ssh-host", default=DEFAULT_HOST)
    parser.add_argument("--ssh-user", default=DEFAULT_USER)
    parser.add_argument("--ssh-key", default=str(DEFAULT_KEY))
    parser.add_argument("--local-lane-root", default=str(DEFAULT_LOCAL_LANE_ROOT))
    parser.add_argument("--connect-timeout", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--dry-run", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("acquire-start", help="Acquire a Hoster lease and start mitmproxy.")
    start.add_argument("--lane")
    start.add_argument("--agent-id")
    start.add_argument("--run-id")
    start.add_argument("--program")
    start.add_argument("--task")
    start.add_argument("--account-label")
    start.add_argument("--runtime-host")
    start.add_argument("--proxy-host", default=DEFAULT_PROXY_HOST)
    start.add_argument("--listen-host", default="0.0.0.0")
    start.add_argument("--port-min", type=int, default=DEFAULT_PORT_MIN)
    start.add_argument("--port-max", type=int, default=DEFAULT_PORT_MAX)
    start.add_argument("--ttl-seconds", type=int, default=6 * 60 * 60)
    start.add_argument("--transport", default="browser")
    start.add_argument("--browser-profile-id")
    start.add_argument("--session-source")
    start.add_argument("--profile-dir")
    start.add_argument("--note")
    start.set_defaults(func=acquire_start)

    finish = sub.add_parser("index-stop-release", help="Index, stop, and release a Hoster lane.")
    finish.add_argument("--lane", required=True)
    finish.add_argument("--agent-id")
    finish.add_argument("--run-id")
    finish.add_argument("--account-label")
    finish.add_argument("--runtime-host")
    finish.add_argument("--proxy-host", default=DEFAULT_PROXY_HOST)
    finish.add_argument("--proxy-port", type=int)
    finish.add_argument("--transport", default="browser")
    finish.add_argument("--browser-profile-id")
    finish.add_argument("--session-source")
    finish.add_argument("--note")
    finish.set_defaults(func=index_stop_release)

    status = sub.add_parser("status-default", help="Observe the shared default without establishing readiness.")
    status.add_argument("--lane", default=DEFAULT_GENERAL_LANE)
    status.set_defaults(func=status_default)

    default = sub.add_parser("ensure-default", help="Ensure the shared default Hoster MITM proxy on 8080.")
    default.add_argument("--lane", default=DEFAULT_GENERAL_LANE)
    default.add_argument("--port", type=int, default=DEFAULT_GENERAL_PORT)
    default.add_argument("--listen-host", default="0.0.0.0")
    default.add_argument("--proxy-host", default=None, help="Advertised host; defaults to the SSH host")
    default.add_argument("--program", default="general")
    default.add_argument("--task", default="default-capture")
    default.add_argument("--agent-id", default="default-proxy")
    default.add_argument("--run-id")
    default.add_argument("--account-label")
    default.add_argument("--runtime-host")
    default.add_argument("--transport", default="mixed")
    default.add_argument("--session-source", default="default-mitm")
    default.set_defaults(func=ensure_default)

    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def ssh_base_legacy(args: argparse.Namespace) -> list[str]:
    return [
        "ssh",
        "-i",
        str(Path(args.ssh_key).expanduser()),
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={args.connect_timeout}",
        "-o",
        "ControlMaster=no",
        "-T",
        f"{args.ssh_user}@{args.ssh_host}",
    ]


def remote_command_legacy(args: argparse.Namespace, argv: list[str]) -> str:
    """Run the lane-installed dispatcher; remote source roots are never guessed."""
    return " ".join(shlex.quote(part) for part in argv)


def running_on_requested_hoster_legacy(args: argparse.Namespace) -> bool:
    """Avoid SSH-to-self; the current checkout remains the lane authority."""
    requested = args.ssh_host.strip().lower().rstrip(".")
    local_names = {
        socket.gethostname().lower().rstrip("."),
        socket.getfqdn().lower().rstrip("."),
    }
    return requested in local_names or requested.split(".", 1)[0] in {
        name.split(".", 1)[0] for name in local_names
    }


def local_bbh_command_legacy(argv: list[str]) -> list[str]:
    """Run the dispatcher from this checkout rather than relying on PATH."""
    if not argv or argv[0] != "bbh":
        raise ValueError("local Hoster dispatch requires a BBH command")
    root = Path(__file__).resolve().parents[3]
    return [sys.executable, str(root / "scripts" / "bbh.py"), *argv[1:]]


def run_remote_legacy(args: argparse.Namespace, argv: list[str]) -> dict[str, Any]:
    if running_on_requested_hoster_legacy(args):
        command = local_bbh_command_legacy(argv)
        if args.dry_run:
            return {"status": "dry-run", "local_command": command}
        proc = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.timeout,
        )
        try:
            parsed: dict[str, Any] = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError:
            parsed = {"raw_stdout": proc.stdout}
        parsed.update({"local_returncode": proc.returncode, "local_stderr": proc.stderr.strip()})
        if proc.returncode != 0:
            parsed.setdefault("status", "local-failed")
        return parsed
    command = ssh_base_legacy(args) + [remote_command_legacy(args, argv)]
    if args.dry_run:
        return {"status": "dry-run", "ssh_command": command}
    proc = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=args.timeout,
    )
    parsed: dict[str, Any]
    try:
        parsed = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        parsed = {"raw_stdout": proc.stdout}
    parsed.update(
        {
            "ssh_returncode": proc.returncode,
            "ssh_stderr": proc.stderr.strip(),
        }
    )
    if proc.returncode != 0:
        parsed.setdefault("status", "ssh-failed")
    return parsed


def main() -> int:
    args = parse_args()
    result = args.func(args)
    if getattr(args, 'command', None) in {'acquire-start', 'index-stop-release'}:
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"{result.get('status')}: {result.get('proxy_server', '')}")
        return 0 if result.get("status") not in {"lease-failed", "start-failed", "release-failed", "ssh-failed", "local-failed"} else 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{result.get('status')}: {result.get('proxy_server') or result.get('detail', '')}")
        if result.get('ca_sync', {}).get('ca_identity') == 'legacy-unverified':
            print('CA identity: legacy-unverified; the running listener has not been cryptographically verified')
    return 0 if result.get("status") not in {"lease-failed", "start-failed", "start-outcome-unknown", "release-failed", "ssh-failed", "local-failed", "unknown-state"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
