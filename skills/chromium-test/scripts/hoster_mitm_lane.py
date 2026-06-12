#!/usr/bin/env python3
"""Lease and manage Hoster-backed mitmproxy lanes through one-shot SSH."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any


DEFAULT_HOST = "hoster"
DEFAULT_USER = "ryushe"
DEFAULT_KEY = Path("/home/ryushe/.ssh/hoster")
DEFAULT_REMOTE_ROOT = Path("/home/ryushe/projects/bug_bounty_harness")
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
    quoted = " ".join(shlex.quote(part) for part in argv)
    return f"cd {shlex.quote(str(args.remote_root))} && {quoted}"


def run_remote(args: argparse.Namespace, argv: list[str]) -> dict[str, Any]:
    command = ssh_base(args) + [remote_command(args, argv)]
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


def copy_remote_file(args: argparse.Namespace, remote_path: str, local_path: Path) -> dict[str, Any]:
    local_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "scp",
        "-i",
        str(Path(args.ssh_key).expanduser()),
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={args.connect_timeout}",
        "-q",
        f"{args.ssh_user}@{args.ssh_host}:{remote_path}",
        str(local_path),
    ]
    if args.dry_run:
        return {"status": "dry-run", "scp_command": command, "local_path": str(local_path)}
    proc = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=args.timeout,
    )
    return {
        "status": "copied" if proc.returncode == 0 else "copy-failed",
        "local_path": str(local_path),
        "remote_path": remote_path,
        "scp_returncode": proc.returncode,
        "scp_stderr": proc.stderr.strip(),
    }


def value_args(mapping: dict[str, Any]) -> list[str]:
    parts: list[str] = []
    for key, value in mapping.items():
        if value is None:
            continue
        parts.extend([f"--{key.replace('_', '-')}", str(value)])
    return parts


def acquire_start(args: argparse.Namespace) -> dict[str, Any]:
    lease = run_remote(
        args,
        [
            "python3",
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
    start = run_remote(
        args,
        [
            "python3",
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
        run_remote(
            args,
            [
                "python3",
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
    stop = run_remote(
        args,
        [
            "python3",
            "skills/chromium-test/scripts/mitm_lane.py",
            "--json",
            "--lane",
            args.lane,
            "stop",
        ],
    )
    index = run_remote(
        args,
        [
            "python3",
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
    release = run_remote(
        args,
        [
            "python3",
            "skills/chromium-test/scripts/proxy_store.py",
            "--json",
            "lease-release",
            "--lane",
            args.lane,
        ],
    )
    status = "released" if release.get("status") == "released" else "release-failed"
    return {"status": status, "stop": stop, "index": index, "release": release}


def ensure_default(args: argparse.Namespace) -> dict[str, Any]:
    status = run_remote(
        args,
        [
            "python3",
            "skills/chromium-test/scripts/mitm_lane.py",
            "--json",
            "--lane",
            args.lane,
            "status",
        ],
    )
    if status.get("alive") and status.get("proxy_server"):
        ca_sync = sync_lane_ca(args, status)
        return {
            "status": "running",
            "lane": args.lane,
            "proxy_server": status["proxy_server"],
            "proxy_port": status.get("proxy_port") or status.get("port"),
            "start": status,
            "ca_sync": ca_sync,
            "local_ca_cert": ca_sync.get("local_path"),
        }

    start = run_remote(
        args,
        [
            "python3",
            "skills/chromium-test/scripts/mitm_lane.py",
            "--json",
            "--lane",
            args.lane,
            "start",
            *value_args(
                {
                    "listen_host": args.listen_host,
                    "proxy_host": args.proxy_host,
                    "port": args.port,
                    "program": args.program,
                    "task": args.task,
                    "agent_id": args.agent_id,
                    "run_id": args.run_id,
                    "account_label": args.account_label,
                    "runtime_host": args.runtime_host,
                    "transport": args.transport,
                    "session_source": args.session_source,
                }
            ),
        ],
    )
    if start.get("status") not in {"running", "already-running"}:
        return {"status": "start-failed", "lane": args.lane, "start": start}
    ca_sync = sync_lane_ca(args, start)
    return {
        "status": "running",
        "lane": args.lane,
        "proxy_server": start.get("proxy_server") or f"http://{args.proxy_host}:{args.port}",
        "proxy_port": args.port,
        "start": start,
        "ca_sync": ca_sync,
        "local_ca_cert": ca_sync.get("local_path"),
    }


def sync_lane_ca(args: argparse.Namespace, state: dict[str, Any]) -> dict[str, Any]:
    remote_ca = state.get("ca_cert")
    if not remote_ca:
        return {"status": "missing-remote-ca"}
    local_path = Path(args.local_lane_root).expanduser() / args.lane / "mitmproxy" / "mitmproxy-ca-cert.pem"
    return copy_remote_file(args, str(remote_ca), local_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage Hoster mitmproxy lanes through SSH.")
    parser.add_argument("--ssh-host", default=DEFAULT_HOST)
    parser.add_argument("--ssh-user", default=DEFAULT_USER)
    parser.add_argument("--ssh-key", default=str(DEFAULT_KEY))
    parser.add_argument("--remote-root", default=str(DEFAULT_REMOTE_ROOT))
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

    default = sub.add_parser("ensure-default", help="Ensure the default Hoster MITM proxy is listening on 8080.")
    default.add_argument("--lane", default=DEFAULT_GENERAL_LANE)
    default.add_argument("--port", type=int, default=DEFAULT_GENERAL_PORT)
    default.add_argument("--listen-host", default="0.0.0.0")
    default.add_argument("--proxy-host", default=DEFAULT_PROXY_HOST)
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


def main() -> int:
    args = parse_args()
    result = args.func(args)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{result.get('status')}: {result.get('proxy_server', '')}")
    return 0 if result.get("status") not in {"lease-failed", "start-failed", "release-failed", "ssh-failed"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
