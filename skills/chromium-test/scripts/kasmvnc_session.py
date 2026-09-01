#!/usr/bin/env python3
"""Manage a task-owned, loopback-only KasmVNC display for Chromium handoff.

The helper deliberately never configures a public listener: the KasmVNC HTTP
endpoint is always reported as a 127.0.0.1 URL. Tailscale Serve, when used,
terminates HTTPS in front of this local HTTP service.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

LISTENER_HOST = "127.0.0.1"
DEFAULT_DISPLAY = 20
DEFAULT_WEB_PORT_MIN = 8463
DEFAULT_WEB_PORT_MAX = 8499
DEFAULT_GEOMETRY = "1400x900"
DEFAULT_DEPTH = 24
CLIPBOARD_MAX_BYTES = 1_048_576
DEFAULT_STATE_DIR = Path("~/.local/state/ghost/kasmvnc-sessions").expanduser()


class KasmVNCSessionError(RuntimeError):
    """Raised when a KasmVNC session cannot be safely started."""


def validate_display(display: int) -> int:
    if not 1 <= display <= 999:
        raise KasmVNCSessionError("display must be in 1-999")
    return display


def validate_web_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise KasmVNCSessionError("web port must be in 1-65535")
    return port


def can_bind_localhost(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((LISTENER_HOST, port))
        except OSError:
            return False
    return True


def candidate_web_ports(requested: int | None) -> Iterable[int]:
    if requested is not None:
        yield validate_web_port(requested)
        return
    yield from range(DEFAULT_WEB_PORT_MIN, DEFAULT_WEB_PORT_MAX + 1)


def pick_web_port(requested: int | None = None) -> int:
    for port in candidate_web_ports(requested):
        if can_bind_localhost(port):
            return port
    if requested is not None:
        raise KasmVNCSessionError(f"requested web port {requested} is not available on {LISTENER_HOST}")
    raise KasmVNCSessionError(
        f"no free loopback web port found in {DEFAULT_WEB_PORT_MIN}-{DEFAULT_WEB_PORT_MAX}"
    )


def display_name(display: int) -> str:
    return f":{validate_display(display)}"


def state_path(display: int, state_dir: Path = DEFAULT_STATE_DIR) -> Path:
    return state_dir.expanduser() / f"display-{validate_display(display)}.json"


def can_connect_localhost(port: int) -> bool:
    try:
        with socket.create_connection((LISTENER_HOST, port), timeout=0.25):
            return True
    except OSError:
        return False


def wait_for_web_listener(port: int, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if can_connect_localhost(port):
            return True
        time.sleep(0.2)
    return False


def build_start_command(display: int, web_port: int) -> list[str]:
    """Build the supported KasmVNC server invocation without exposing its listener."""
    return [
        "vncserver",
        display_name(display),
        "-geometry",
        DEFAULT_GEOMETRY,
        "-depth",
        str(DEFAULT_DEPTH),
        "-noxstartup",
        # Keep the Xvnc root in the task-owned systemd cgroup. The daemonized
        # default exits its launcher immediately and is killed with --collect.
        "-fg",
        "-interface",
        LISTENER_HOST,
        "-websocketPort",
        str(validate_web_port(web_port)),
        # KasmVNC's clipboard panel is the reliable text-box fallback when a
        # browser intercepts Ctrl/Cmd+V.  Keep both directions explicit and
        # bounded so task handoffs do not inherit an ambient server policy.
        "-AcceptCutText",
        "1",
        "-SendCutText",
        "1",
        "-DLP_ClipAcceptMax",
        str(CLIPBOARD_MAX_BYTES),
        "-DLP_ClipSendMax",
        str(CLIPBOARD_MAX_BYTES),
    ]


def _session_record(display: int, web_port: int, status: str) -> dict[str, Any]:
    return {
        "display": display_name(display),
        "listener_host": LISTENER_HOST,
        "status": status,
        "web_port": web_port,
        "web_url": f"http://{LISTENER_HOST}:{web_port}/",
    }


def _write_state(display: int, web_port: int, state_dir: Path) -> None:
    path = state_path(display, state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"display": display, "web_port": web_port}, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _read_state(display: int, state_dir: Path) -> dict[str, int] | None:
    path = state_path(display, state_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        stored_display = validate_display(int(data["display"]))
        web_port = validate_web_port(int(data["web_port"]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, KasmVNCSessionError):
        return None
    if stored_display != display:
        return None
    return {"display": stored_display, "web_port": web_port}


def session_status(display: int, state_dir: Path = DEFAULT_STATE_DIR) -> dict[str, Any]:
    display = validate_display(display)
    record = _read_state(display, state_dir)
    if not record:
        return {"display": display_name(display), "listener_host": LISTENER_HOST, "status": "not-found"}
    status = "ready" if can_connect_localhost(record["web_port"]) else "not-listening"
    return _session_record(display, record["web_port"], status)


def start_session(
    *,
    display: int = DEFAULT_DISPLAY,
    web_port: int | None = None,
    state_dir: Path = DEFAULT_STATE_DIR,
) -> dict[str, Any]:
    """Start a dedicated KasmVNC display and wait for its local HTTP endpoint."""
    display = validate_display(display)
    existing = session_status(display, state_dir)
    if existing["status"] == "ready":
        raise KasmVNCSessionError(f"KasmVNC display {display_name(display)} is already ready")

    selected_port = pick_web_port(web_port)
    try:
        proc = subprocess.Popen(
            build_start_command(display, selected_port),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise KasmVNCSessionError("vncserver executable was not found") from exc

    # `-fg` keeps Xvnc in the task-owned cgroup. Fail early and clean up only
    # the display this call created if its local web listener never appears.
    if not wait_for_web_listener(selected_port):
        if proc.poll() is None:
            proc.terminate()
        subprocess.run(
            ["vncserver", "-kill", display_name(display)],
            check=False,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        raise KasmVNCSessionError(
            f"KasmVNC display {display_name(display)} did not open {LISTENER_HOST}:{selected_port}"
        )
    _write_state(display, selected_port, state_dir)
    return _session_record(display, selected_port, "ready")


def stop_session(display: int, state_dir: Path = DEFAULT_STATE_DIR) -> dict[str, Any]:
    """Stop only the specified task display and remove its local state record."""
    display = validate_display(display)
    record = _read_state(display, state_dir)
    proc = subprocess.run(
        ["vncserver", "-kill", display_name(display)],
        check=False,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        return {"display": display_name(display), "status": "stop-failed"}
    state_path(display, state_dir).unlink(missing_ok=True)
    result: dict[str, Any] = {"display": display_name(display), "status": "stopped"}
    if record:
        result["web_port"] = record["web_port"]
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage a task-owned, loopback-only KasmVNC session.")
    parser.add_argument("action", choices=("start", "stop", "status"))
    parser.add_argument("--display", type=int, default=DEFAULT_DISPLAY)
    parser.add_argument("--web-port", type=int, help="KasmVNC HTTP port; omit to select a free loopback port.")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.action == "start":
            result = start_session(display=args.display, web_port=args.web_port, state_dir=args.state_dir)
        elif args.action == "stop":
            result = stop_session(args.display, args.state_dir)
        else:
            result = session_status(args.display, args.state_dir)
    except KasmVNCSessionError as exc:
        result = {"display": display_name(args.display), "status": "error", "error": str(exc)}
        print(json.dumps(result, sort_keys=True) if args.json else result["error"])
        return 2
    print(json.dumps(result, sort_keys=True) if args.json else result["status"])
    return 0 if result["status"] in {"ready", "stopped", "not-found", "not-listening"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
