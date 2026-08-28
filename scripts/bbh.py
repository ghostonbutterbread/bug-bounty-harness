#!/usr/bin/env python3
"""Lane-safe dispatcher for repository-owned BBH tools.

The command resolves this file's physical location, so a symlinked launcher
runs tools from the same checkout that supplied the launcher. It deliberately
does not read HARNESS_ROOT.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
TOOLS: Final[dict[str, Path]] = {
    "manual-hunter": Path("agents/manual_hunter.py"),
    "me-ledger": Path("agents/me_ledger.py"),
    "url-ingest": Path("agents/url_ingest.py"),
    "recon-bus": Path("scripts/recon_bus.py"),
    "tool-run": Path("scripts/tool_run.py"),
}


def tool_path(name: str) -> Path:
    try:
        relative = TOOLS[name]
    except KeyError as exc:
        available = ", ".join(sorted(TOOLS))
        raise ValueError(f"unknown BBH tool {name!r}; available: {available}") from exc
    path = REPO_ROOT / relative
    if not path.is_file():
        raise RuntimeError(f"BBH tool {name!r} is missing from this checkout: {path}")
    return path


def usage() -> str:
    return "Usage: bbh [--root | --list | --print-command TOOL | TOOL [ARG ...]]"


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        print(usage())
        return 0
    if args == ["--root"]:
        print(REPO_ROOT)
        return 0
    if args == ["--list"]:
        for name in sorted(TOOLS):
            print(name)
        return 0
    if args[0] == "--print-command":
        if len(args) != 2:
            print("--print-command requires exactly one tool name", file=sys.stderr)
            return 2
        try:
            print(tool_path(args[1]))
        except (ValueError, RuntimeError) as exc:
            print(f"bbh: {exc}", file=sys.stderr)
            return 2
        return 0
    if args[0].startswith("-"):
        print(f"bbh: unknown option {args[0]!r}", file=sys.stderr)
        print(usage(), file=sys.stderr)
        return 2

    try:
        path = tool_path(args[0])
    except (ValueError, RuntimeError) as exc:
        print(f"bbh: {exc}", file=sys.stderr)
        return 2
    os.execvpe(sys.executable, [sys.executable, str(path), *args[1:]], os.environ.copy())
    raise AssertionError("os.execvpe returned unexpectedly")


if __name__ == "__main__":
    raise SystemExit(main())
