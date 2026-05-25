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
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable


PORT_MIN = 9223
PORT_MAX = 9500
DEFAULT_MCP_URL = "http://127.0.0.1:3333/mcp"
CHROME_BINARIES = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
)
CAIDO_PROFILE_TOOL_HINTS = ("profile", "browser", "proxy", "context")


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


def parse_mcp_response(raw: str) -> dict[str, Any]:
    raw = raw.strip()
    if not raw:
        return {}
    if raw.startswith("data:"):
        data_lines = []
        for line in raw.splitlines():
            if line.startswith("data:"):
                data_lines.append(line.removeprefix("data:").strip())
        raw = "\n".join(data_lines).strip()
    return json.loads(raw)


def mcp_json_rpc(mcp_url: str, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": int(time.time() * 1000) % 1_000_000,
            "method": method,
            "params": params or {},
        }
    ).encode()
    request = urllib.request.Request(
        mcp_url,
        data=body,
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        return parse_mcp_response(response.read().decode("utf-8", errors="replace"))


def initialize_mcp(mcp_url: str) -> dict[str, Any]:
    return mcp_json_rpc(
        mcp_url,
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "chromium-test", "version": "1.0.0"},
        },
    )


def list_mcp_tools(mcp_url: str) -> list[dict[str, Any]]:
    response = mcp_json_rpc(mcp_url, "tools/list")
    result = response.get("result", response)
    tools = result.get("tools", []) if isinstance(result, dict) else []
    return tools if isinstance(tools, list) else []


def choose_profile_tool(tools: list[dict[str, Any]]) -> str | None:
    for tool in tools:
        name = str(tool.get("name", ""))
        haystack = " ".join(
            [
                name,
                str(tool.get("description", "")),
                json.dumps(tool.get("inputSchema", {}), sort_keys=True),
            ]
        ).lower()
        if "profile" in haystack and any(hint in haystack for hint in CAIDO_PROFILE_TOOL_HINTS):
            return name
    return None


def call_mcp_tool(mcp_url: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = mcp_json_rpc(
        mcp_url,
        "tools/call",
        {"name": tool_name, "arguments": arguments},
    )
    result = response.get("result", response)
    if not isinstance(result, dict):
        return {}

    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            text = item.get("text")
            if isinstance(text, str):
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    return parsed
    return result


def normalize_caido_profile(payload: dict[str, Any]) -> dict[str, Any]:
    profile = dict(payload)
    for key in ("profile", "browserProfile", "caidoProfile", "context"):
        nested = profile.get(key)
        if isinstance(nested, dict):
            profile.update({k: v for k, v in nested.items() if k not in profile})

    fields = {
        "account": ("account", "account_alias", "accountAlias", "label", "name"),
        "profile_dir": ("profile_dir", "profileDir", "user_data_dir", "userDataDir"),
        "proxy_server": ("proxy_server", "proxyServer", "browser_proxy", "browserProxy"),
        "url": ("url", "start_url", "startUrl", "target_url", "targetUrl"),
    }
    normalized: dict[str, Any] = {}
    for out_key, candidates in fields.items():
        for candidate in candidates:
            value = profile.get(candidate)
            if isinstance(value, str) and value.strip():
                normalized[out_key] = value.strip()
                break
    return normalized


def resolve_caido_profile(args: argparse.Namespace, task: str) -> dict[str, Any]:
    if args.caido_profile == "none":
        return {"status": "disabled"}

    try:
        initialize_mcp(args.mcp_url)
        tools = list_mcp_tools(args.mcp_url)
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        if args.require_caido_profile:
            raise SystemExit(f"Caido MCP profile resolution failed: {exc}") from exc
        return {"status": "unavailable", "error": str(exc)}

    tool_name = args.caido_profile_tool or choose_profile_tool(tools)
    if not tool_name:
        if args.require_caido_profile:
            tool_names = ", ".join(str(tool.get("name", "")) for tool in tools)
            raise SystemExit(f"No Caido profile tool found. Tools: {tool_names}")
        return {
            "status": "no-profile-tool",
            "tools": [tool.get("name") for tool in tools if isinstance(tool, dict)],
        }

    arguments = {
        "program": args.program,
        "task": task,
        "profile": args.caido_profile,
    }
    if args.account:
        arguments["account"] = args.account

    try:
        payload = call_mcp_tool(args.mcp_url, tool_name, arguments)
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        if args.require_caido_profile:
            raise SystemExit(f"Caido MCP profile tool failed: {exc}") from exc
        return {"status": "tool-error", "tool": tool_name, "error": str(exc)}

    normalized = normalize_caido_profile(payload)
    normalized.update({"status": "resolved", "tool": tool_name})
    return normalized


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Launch an isolated Chromium/Chrome instance on a free CDP port."
    )
    parser.add_argument("program", help="Program or target slug.")
    parser.add_argument("task_arg", nargs="?", help="Requested test task label.")
    parser.add_argument("--task", dest="task_opt", help="Requested test task label.")
    parser.add_argument("--account", help="Override account/profile alias.")
    parser.add_argument("--url", help="Initial URL to open. Defaults to about:blank.")
    parser.add_argument("--port", type=int, help=f"CDP port in {PORT_MIN}-{PORT_MAX}.")
    parser.add_argument("--profile-dir", help="Override Chrome user-data-dir.")
    parser.add_argument("--proxy-server", help="Actual browser HTTP/SOCKS proxy listener.")
    parser.add_argument(
        "--caido-profile",
        default=os.environ.get("CHROMIUM_TEST_CAIDO_PROFILE", "auto"),
        help="Caido profile selector: auto, none, or a named Caido profile.",
    )
    parser.add_argument("--caido-profile-tool", help="Explicit Caido MCP tool for profile lookup.")
    parser.add_argument(
        "--require-caido-profile",
        action="store_true",
        help="Fail if Caido profile lookup cannot resolve.",
    )
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
    port = pick_port(args.port)
    task = args.task_opt or args.task_arg or "manual"
    caido_profile = resolve_caido_profile(args, task)
    if args.account:
        account = args.account
    elif caido_profile.get("account"):
        account = caido_profile["account"]
    elif caido_profile.get("status") == "resolved":
        account = f"{sanitize_slug(args.program)}-caido"
    else:
        account = f"{sanitize_slug(args.program)}-context"
    profile_dir_override = args.profile_dir or caido_profile.get("profile_dir")
    profile_dir = (
        Path(profile_dir_override).expanduser()
        if profile_dir_override
        else default_profile_dir(args.program, account)
    )
    if not args.proxy_server and caido_profile.get("proxy_server"):
        args.proxy_server = caido_profile["proxy_server"]
    if not args.url and caido_profile.get("url"):
        args.url = caido_profile["url"]
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
        "caido_profile": caido_profile,
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
