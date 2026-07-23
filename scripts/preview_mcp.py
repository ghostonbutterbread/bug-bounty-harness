#!/usr/bin/env python3
"""Query Preview's security-write-up retrieval API without exposing its API key.

The key is read from PREVIEW_API_KEY or a 0600 key/value file outside the repo:
~/.config/bug-bounty-harness/preview.env. The file is parsed as data, never
shell-sourced. Results are emitted as JSON so callers can retain cited research
without storing credentials in run artifacts.

Examples:
    python3 scripts/preview_mcp.py search --query "WAF bypass for reflected XSS"
    PREVIEW_API_KEY=... python3 scripts/preview_mcp.py search --query "DOM clobbering"
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_ENDPOINT = "https://api.preview.is/search"
DEFAULT_KEY_FILE = Path.home() / ".config" / "bug-bounty-harness" / "preview.env"


def load_key_file(path: Path) -> str | None:
    """Read PREVIEW_API_KEY from a simple key/value file without executing it."""
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        return None
    if mode & 0o077:
        raise ValueError(f"refusing key file with group/other permissions: {path}")
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").strip()
        name, separator, value = line.partition("=")
        if separator and name.strip() == "PREVIEW_API_KEY":
            value = value.strip().strip('"').strip("'")
            if value:
                return value
    return None


def resolve_api_key(key_file: Path) -> str:
    key = os.environ.get("PREVIEW_API_KEY") or load_key_file(key_file)
    if not key:
        raise ValueError(
            "Preview API key is not configured; set PREVIEW_API_KEY or create "
            f"{key_file} with mode 0600."
        )
    return key


def search(
    *, endpoint: str, api_key: str, query: str, k: int, min_score: float,
    candidates: int | None, full_content: bool, timeout: float,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"query": query, "k": k, "min_score": min_score}
    if candidates is not None:
        payload["candidates"] = candidates
    if full_content:
        payload["full_content"] = True
    request = Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"Preview request failed with HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Preview request failed: {exc.reason}") from exc


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    command = subcommands.add_parser("search", help="Search curated security write-ups")
    command.add_argument("--query", required=True)
    command.add_argument("--k", type=int, default=5, choices=range(1, 6))
    command.add_argument("--min-score", type=float, default=0.1)
    command.add_argument("--candidates", type=int)
    command.add_argument("--full-content", action="store_true")
    command.add_argument("--endpoint", default=os.environ.get("PREVIEW_API_URL", DEFAULT_ENDPOINT))
    command.add_argument(
        "--key-file", type=Path,
        default=Path(os.environ.get("PREVIEW_KEY_FILE", DEFAULT_KEY_FILE)).expanduser(),
    )
    command.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not 0 <= args.min_score <= 1:
        raise SystemExit("--min-score must be between 0 and 1")
    if args.candidates is not None and not 1 <= args.candidates <= 300:
        raise SystemExit("--candidates must be between 1 and 300")
    try:
        result = search(
            endpoint=args.endpoint,
            api_key=resolve_api_key(args.key_file),
            query=args.query,
            k=args.k,
            min_score=args.min_score,
            candidates=args.candidates,
            full_content=args.full_content,
            timeout=args.timeout,
        )
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
