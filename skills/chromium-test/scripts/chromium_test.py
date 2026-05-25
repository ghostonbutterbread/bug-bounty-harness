#!/usr/bin/env python3
"""Launch an isolated Chromium/Chrome instance for scoped testing."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Iterable


PORT_MIN = 9223
PORT_MAX = 9500
DEFAULT_MCP_URL = "http://127.0.0.1:3333/mcp"
CHROME_BINARIES = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
)


def sanitize_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")
    return slug or "default"


def listening_ports() -> set[int]:
    try:
        proc = subprocess.run(
            ["ss", "-ltn"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return set()

    ports: set[int] = set()
    for line in proc.stdout.splitlines():
        for match in re.finditer(r":(\d+)\s", line):
            ports.add(int(match.group(1)))
    return ports


def can_bind_localhost(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def iter_candidate_ports(requested: int | None) -> Iterable[int]:
    if requested is not None:
        yield requested
        return
    yield from range(PORT_MIN, PORT_MAX + 1)


def pick_port(requested: int | None = None) -> int:
    if requested is not None and not PORT_MIN <= requested <= PORT_MAX:
        raise SystemExit(f"--port must be in {PORT_MIN}-{PORT_MAX}")

    used = listening_ports()
    for port in iter_candidate_ports(requested):
        if port in used:
            continue
        if can_bind_localhost(port):
            return port

    if requested is not None:
        raise SystemExit(f"requested port {requested} is not available")
    raise SystemExit(f"no free port found in {PORT_MIN}-{PORT_MAX}")


def find_chrome_binary(explicit: str | None = None) -> str:
    if explicit:
        path = shutil.which(explicit) if os.path.sep not in explicit else explicit
        if path and Path(path).exists():
            return str(path)
        raise SystemExit(f"Chrome binary not found: {explicit}")

    env_binary = os.environ.get("CHROMIUM_TEST_CHROME")
    if env_binary:
        return find_chrome_binary(env_binary)

    for binary in CHROME_BINARIES:
        path = shutil.which(binary)
        if path:
            return path
    raise SystemExit("No Chromium/Chrome binary found")


def default_profile_dir(program: str, account: str) -> Path:
    shared_base = Path(
        os.environ.get("HARNESS_SHARED_BASE", "~/Shared/bounty_recon")
    ).expanduser()
    return (
        shared_base
        / sanitize_slug(program)
        / "ghost"
        / "chromium-test"
        / "profiles"
        / sanitize_slug(account)
    )


def build_command(args: argparse.Namespace, port: int, profile_dir: Path) -> list[str]:
    chrome = find_chrome_binary(args.chrome_binary)
    command = [
        chrome,
        f"--remote-debugging-port={port}",
        "--remote-debugging-address=127.0.0.1",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-sync",
        "--new-window",
    ]

    proxy_server = args.proxy_server or os.environ.get("CHROMIUM_TEST_PROXY_SERVER")
    if proxy_server:
        command.append(f"--proxy-server={proxy_server}")

    command.append(args.url or "about:blank")
    return command


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Launch an isolated Chromium/Chrome instance on a free CDP port."
    )
    parser.add_argument("program", help="Program or target slug.")
    parser.add_argument("task_arg", nargs="?", help="Requested test task label.")
    parser.add_argument("--task", dest="task_opt", help="Requested test task label.")
    parser.add_argument("--account", help="Account alias to use for this profile.")
    parser.add_argument("--url", help="Initial URL to open. Defaults to about:blank.")
    parser.add_argument("--port", type=int, help=f"CDP port in {PORT_MIN}-{PORT_MAX}.")
    parser.add_argument("--profile-dir", help="Override Chrome user-data-dir.")
    parser.add_argument("--proxy-server", help="Actual browser HTTP/SOCKS proxy listener.")
    parser.add_argument(
        "--mcp-url",
        default=os.environ.get("KAIDO_MCP_PROXY_URL", DEFAULT_MCP_URL),
    )
    parser.add_argument("--chrome-binary", help="Override Chromium/Chrome executable.")
    parser.add_argument("--dry-run", action="store_true", help="Print launch plan only.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    account = args.account or f"{sanitize_slug(args.program)}-context"
    port = pick_port(args.port)
    task = args.task_opt or args.task_arg or "manual"
    profile_dir = (
        Path(args.profile_dir).expanduser()
        if args.profile_dir
        else default_profile_dir(args.program, account)
    )
    if not args.dry_run:
        profile_dir.mkdir(parents=True, exist_ok=True)

    command = build_command(args, port, profile_dir)
    result = {
        "program": args.program,
        "task": task,
        "account": account,
        "port": port,
        "cdp_url": f"http://127.0.0.1:{port}",
        "cdp_version_url": f"http://127.0.0.1:{port}/json/version",
        "profile_dir": str(profile_dir),
        "mcp_url": args.mcp_url,
        "proxy_server": args.proxy_server or os.environ.get("CHROMIUM_TEST_PROXY_SERVER"),
        "command": command,
        "dry_run": args.dry_run,
    }

    if not args.dry_run:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(1)
        result["pid"] = proc.pid

    if args.json or args.dry_run:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Started Chromium PID {result['pid']} on {result['cdp_url']}")
        print(f"Profile: {profile_dir}")
        print(f"MCP: {args.mcp_url}")
        if result["proxy_server"]:
            print(f"Browser proxy: {result['proxy_server']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
