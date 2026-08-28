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


def script_path(value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        raise ValueError("BBH script path must be relative to the repository root")
    path = (REPO_ROOT / candidate).resolve()
    if REPO_ROOT not in path.parents:
        raise ValueError("BBH script path escapes the repository root")
    if not path.is_file():
        raise RuntimeError(f"BBH script is missing from this checkout: {value}")
    return path


def runtime_python() -> Path:
    """Return this checkout's dependency interpreter or explain how to create it."""
    interpreter = REPO_ROOT / ".venv" / "bin" / "python"
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        raise RuntimeError(
            "BBH virtual environment is missing; run ./setup.sh --install-python-deps from this checkout"
        )
    return interpreter


def command_for(path: Path, args: list[str]) -> list[str]:
    if path.suffix == ".py":
        python = runtime_python()
        return [str(python), str(path), *args]
    if os.access(path, os.X_OK):
        return [str(path), *args]
    raise ValueError("BBH target must be a Python file or an executable script")


def usage() -> str:
    return "Usage: bbh [--root | --print-command PATH | REPO_RELATIVE_SCRIPT [ARG ...]]"


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        print(usage())
        return 0
    if args == ["--root"]:
        print(REPO_ROOT)
        return 0
    if args[0] == "--print-command":
        if len(args) != 2:
            print("--print-command requires exactly one repository-relative path", file=sys.stderr)
            return 2
        try:
            print(script_path(args[1]))
        except (ValueError, RuntimeError) as exc:
            print(f"bbh: {exc}", file=sys.stderr)
            return 2
        return 0
    if args[0].startswith("-"):
        print(f"bbh: unknown option {args[0]!r}", file=sys.stderr)
        print(usage(), file=sys.stderr)
        return 2

    try:
        path = script_path(args[0])
        command = command_for(path, args[1:])
    except (ValueError, RuntimeError) as exc:
        print(f"bbh: {exc}", file=sys.stderr)
        return 2
    environment = os.environ.copy()
    # Package-style BBH imports must resolve from the same physical checkout as
    # the selected launcher; inherited PYTHONPATH must not select another tree.
    environment["PYTHONPATH"] = str(REPO_ROOT)
    os.execvpe(command[0], command, environment)
    raise AssertionError("os.execvpe returned unexpectedly")


if __name__ == "__main__":
    raise SystemExit(main())
