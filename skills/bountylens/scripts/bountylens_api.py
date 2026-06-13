#!/usr/bin/env python3
"""Small BountyLens API helper that reads ~/.env without executing it."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_BASE_URL = "https://bountylens.com"


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def load_config(env_file: Path) -> tuple[str, str]:
    file_values = parse_env_file(env_file)
    api_key = os.environ.get("BOUNTYLENS_API_KEY") or file_values.get("BOUNTYLENS_API_KEY")
    base_url = (
        os.environ.get("BOUNTYLENS_URL")
        or file_values.get("BOUNTYLENS_URL")
        or DEFAULT_BASE_URL
    ).rstrip("/")

    if not api_key:
        raise SystemExit("Missing BOUNTYLENS_API_KEY in environment or ~/.env")
    return api_key, base_url


def parse_query(items: list[str]) -> str:
    params: list[tuple[str, str]] = []
    for item in items:
        if "=" not in item:
            raise SystemExit(f"Invalid --query value {item!r}; expected key=value")
        key, value = item.split("=", 1)
        params.append((key, value))
    return urllib.parse.urlencode(params)


def load_body(data_json: str | None, data_file: str | None) -> bytes | None:
    if data_json and data_file:
        raise SystemExit("Use only one of --data-json or --data-file")
    if data_file:
        raw = Path(data_file).read_text(encoding="utf-8")
    elif data_json:
        raw = data_json
    else:
        return None

    try:
        parsed: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON body: {exc}") from exc
    return json.dumps(parsed, separators=(",", ":")).encode("utf-8")


def build_url(base_url: str, path: str, query: list[str]) -> str:
    if not path.startswith("/"):
        path = f"/{path}"
    qs = parse_query(query)
    url = f"{base_url}/api/v1{path}"
    return f"{url}?{qs}" if qs else url


def request(args: argparse.Namespace) -> int:
    api_key, base_url = load_config(Path(args.env_file).expanduser())
    url = build_url(base_url, args.path, args.query)
    body = load_body(args.data_json, args.data_file)

    req = urllib.request.Request(
        url,
        data=body,
        method=args.method,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as response:
            payload = response.read().decode("utf-8")
            status = response.status
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        print(payload or f"HTTP {exc.code}", file=sys.stderr)
        return 1

    if args.raw:
        print(payload)
        return 0

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        print(payload)
    else:
        print(json.dumps(parsed, indent=2, sort_keys=True))
    return 0 if 200 <= status < 300 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Call the BountyLens API without exposing secrets.")
    parser.add_argument("method", nargs="?", choices=["GET", "POST", "PUT", "DELETE", "PATCH"])
    parser.add_argument("path", nargs="?")
    parser.add_argument("--env-file", default="~/.env")
    parser.add_argument("--query", action="append", default=[], help="Query parameter as key=value")
    parser.add_argument("--data-json", help="JSON request body")
    parser.add_argument("--data-file", help="Path to a JSON request body")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--raw", action="store_true", help="Print raw response instead of formatted JSON")
    parser.add_argument("--check", action="store_true", help="Verify config can be loaded without printing secrets")
    args = parser.parse_args()

    if args.check:
        _api_key, base_url = load_config(Path(args.env_file).expanduser())
        print(f"BountyLens config OK: base_url={base_url}")
        return 0

    if not args.method or not args.path:
        parser.error("method and path are required unless --check is used")
    return request(args)


if __name__ == "__main__":
    raise SystemExit(main())
