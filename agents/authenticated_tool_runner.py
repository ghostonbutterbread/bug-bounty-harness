#!/usr/bin/env python3
"""Run FFUF or Arjun with local-only headers from an approved auth seed.

The seed path and tool name may be recorded in a run capsule, but header values
are deliberately never printed or written by this wrapper.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path


def load_headers(seed_path: Path) -> list[str]:
    mode = stat.S_IMODE(seed_path.stat().st_mode)
    if mode & 0o077:
        raise ValueError("auth seed permissions are too broad")
    payload = json.loads(seed_path.read_text(encoding="utf-8"))
    headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
    values = {str(key): str(value) for key, value in headers.items() if str(key).strip() and value is not None}
    cookies = payload.get("cookies") if isinstance(payload.get("cookies"), list) else []
    if "Cookie" not in values:
        pairs = [f"{item.get('name')}={item.get('value')}" for item in cookies if isinstance(item, dict) and item.get("name") is not None and item.get("value") is not None]
        if pairs:
            values["Cookie"] = "; ".join(pairs)
    return [f"{key}: {value}" for key, value in values.items()]


def build_command(tool: str, command: list[str], headers: list[str]) -> list[str]:
    if tool == "ffuf":
        result = list(command)
        for header in headers:
            result.extend(["-H", header])
        return result
    if tool == "arjun":
        return [*command, "--headers", "\n".join(headers)]
    raise ValueError(f"unsupported authenticated tool: {tool}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--auth-seed", required=True)
    parser.add_argument("--tool", choices=("ffuf", "arjun"), required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("tool command is required after --")
    try:
        command = build_command(args.tool, command, load_headers(Path(args.auth_seed)))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"authenticated tool handoff failed: {exc}", file=sys.stderr)
        return 2
    os.execvp(command[0], command)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
