#!/usr/bin/env python3
"""Manage a local mitmproxy lane for agent browser testing."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Any


DEFAULT_ROOT = Path("~/.local/state/ghost/mitm-lanes").expanduser()
DEFAULT_MITMDUMP = "mitmdump"


def lane_dir(root: Path, lane: str) -> Path:
    return root / lane


def state_path(root: Path, lane: str) -> Path:
    return lane_dir(root, lane) / "state.json"


def read_state(root: Path, lane: str) -> dict[str, Any]:
    path = state_path(root, lane)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"status": "corrupt-state", "state_path": str(path)}


def write_state(root: Path, lane: str, state: dict[str, Any]) -> None:
    path = state_path(root, lane)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


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
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.1)
    return False


def mitm_env() -> dict[str, str]:
    env = os.environ.copy()
    # Ubuntu's mitmproxy 8.x expects distro blinker. User-site blinker 1.9
    # shadows it and removes blinker._saferef.
    env["PYTHONNOUSERSITE"] = "1"
    return env


def start_lane(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).expanduser()
    current = read_state(root, args.lane)
    if pid_alive(current.get("pid")):
        current["status"] = "already-running"
        return current
    if not can_bind_localhost(args.port):
        return {"status": "port-unavailable", "lane": args.lane, "port": args.port}

    directory = lane_dir(root, args.lane)
    directory.mkdir(parents=True, exist_ok=True)
    confdir = directory / "mitmproxy"
    confdir.mkdir(parents=True, exist_ok=True)
    flow_file = directory / "flows.mitm"
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
    log_handle = log_file.open("ab")
    proc = subprocess.Popen(
        command,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        env=mitm_env(),
        start_new_session=True,
    )
    started = wait_for_port(args.port)
    state = {
        "status": "running" if started else "start-timeout",
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
        "pid": proc.pid,
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
    write_state(root, args.lane, state)
    return state


def status_lane(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).expanduser()
    state = read_state(root, args.lane)
    if not state:
        return {"status": "not-found", "lane": args.lane}
    state["alive"] = pid_alive(state.get("pid"))
    if state.get("port"):
        state["port_open"] = not can_bind_localhost(int(state["port"]))
    return state


def stop_lane(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).expanduser()
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
    state["status"] = "stopped"
    state["alive"] = pid_alive(pid)
    write_state(root, args.lane, state)
    return state


def replay_flows(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).expanduser()
    state = read_state(root, args.lane)
    flow_file = Path(args.flow_file or state.get("flow_file", "")).expanduser()
    if not flow_file.exists():
        return {"status": "missing-flow-file", "flow_file": str(flow_file)}

    directory = lane_dir(root, args.lane)
    replay_file = directory / f"replay-{int(time.time())}.mitm"
    replay_log = directory / f"replay-{int(time.time())}.log"
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
    proc = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=mitm_env(),
        timeout=args.timeout,
    )
    replay_log.write_text(proc.stdout)
    return {
        "status": "replayed" if proc.returncode == 0 else "replay-failed",
        "returncode": proc.returncode,
        "flow_file": str(flow_file),
        "replay_file": str(replay_file),
        "replay_log": str(replay_log),
    }


def index_store(args: argparse.Namespace) -> dict[str, Any]:
    import importlib.util

    script = Path(__file__).resolve().parent / "proxy_store.py"
    spec = importlib.util.spec_from_file_location("proxy_store", script)
    if not spec or not spec.loader:
        return {"status": "missing-proxy-store", "script": str(script)}
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    store_args = argparse.Namespace(
        db=args.db,
        lane=args.lane,
        lane_root=args.root,
        flow_file=args.flow_file,
        program=args.program,
        task=args.task,
        run_id=getattr(args, "run_id", None),
        agent_id=getattr(args, "agent_id", None),
        account_label=getattr(args, "account_label", None),
        runtime_host=getattr(args, "runtime_host", None),
        proxy_host=getattr(args, "proxy_host", None),
        proxy_port=getattr(args, "proxy_port", None),
        proxy_server=getattr(args, "proxy_server", None),
        transport=getattr(args, "transport", None),
        browser_profile_id=getattr(args, "browser_profile_id", None),
        session_source=getattr(args, "session_source", None),
        note=args.note,
        store_full_requests=args.store_full_requests,
    )
    return module.index_lane(store_args)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start, stop, and replay a mitmproxy lane.")
    parser.add_argument("--root", default=str(DEFAULT_ROOT), help="Lane state root.")
    parser.add_argument("--lane", default="default", help="Lane name.")
    parser.add_argument("--mitmdump", default=DEFAULT_MITMDUMP, help="mitmdump executable.")
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="Start mitmdump for this lane.")
    start.add_argument("--port", type=int, default=8081)
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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = args.func(args)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"{result.get('status')}: {result.get('lane', '')}")
        for key in ("proxy_server", "ca_cert", "flow_file", "log_file", "pid"):
            if result.get(key) is not None:
                print(f"{key}: {result[key]}")
    return 0 if result.get("status") not in {"port-unavailable", "missing-flow-file", "replay-failed"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
