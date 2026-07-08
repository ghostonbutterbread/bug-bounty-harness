#!/usr/bin/env python3
"""Minimal tool-run wrapper for recon tool artifacts."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


SHARED_BASE = Path.home() / "Shared" / "web_bounty"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_stamp() -> str:
    return utc_now().strftime("%Y%m%dT%H%M%S%fZ")


def safe_slug(value: str, *, default: str = "run") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()).strip("._-")
    return cleaned or default


def infer_tool(command: Sequence[str]) -> str:
    if not command:
        raise SystemExit("missing command; use: tool-run <program> -- <command>")
    first = Path(command[0]).name
    return safe_slug(first, default="tool")


def tool_root(shared_base: Path, program: str, tool: str) -> Path:
    return shared_base / program / "web" / "recon" / "tools" / tool


def allocate_run_dir(shared_base: Path, program: str, tool: str, run_id: str | None = None) -> tuple[str, Path]:
    day = utc_now().strftime("%Y-%m-%d")
    base = tool_root(shared_base, program, tool) / "runs" / day
    base.mkdir(parents=True, exist_ok=True)

    requested = safe_slug(run_id, default="") if run_id else ""
    stem = requested or f"{tool}-{utc_stamp()}"
    candidate = base / stem
    if not candidate.exists():
        candidate.mkdir()
        return stem, candidate

    for index in range(2, 1000):
        suffixed = f"{stem}-{index}"
        candidate = base / suffixed
        if not candidate.exists():
            candidate.mkdir()
            return suffixed, candidate
    raise SystemExit(f"unable to allocate unique run directory under {base}")


def write_command(path: Path, command: Sequence[str]) -> None:
    path.write_text(" ".join(subprocess.list2cmdline([part]) for part in command) + "\n", encoding="utf-8")


def discover_files(run_dir: Path, known: set[Path]) -> list[str]:
    files: list[str] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file() or path in known:
            continue
        files.append(str(path.relative_to(run_dir)))
    return files


def _coerce_path_list(value: object) -> list[str]:
    if not value:
        return []
    if isinstance(value, (str, Path)):
        return [str(value)]
    if isinstance(value, dict):
        paths: list[str] = []
        for item in value.values():
            paths.extend(_coerce_path_list(item))
        return paths
    if isinstance(value, Iterable):
        return [str(item) for item in value if item]
    return []


def promotion_counts(result: dict[str, object]) -> dict[str, object]:
    appends = result.get("appends")
    if not isinstance(appends, dict):
        return {}
    counts: dict[str, object] = {}
    for kind, append_result in appends.items():
        if not isinstance(append_result, dict):
            continue
        kind_counts = {
            key: value
            for key, value in append_result.items()
            if isinstance(value, dict) and key not in {"mirrors"}
        }
        if kind_counts:
            counts[str(kind)] = kind_counts
    return counts


def promotion_paths(result: dict[str, object]) -> list[str]:
    paths: list[str] = []
    appends = result.get("appends")
    if isinstance(appends, dict):
        for append_result in appends.values():
            if not isinstance(append_result, dict):
                continue
            for key in ("manifest", "incoming", "indexed", "mirrors"):
                paths.extend(_coerce_path_list(append_result.get(key)))
    return sorted(dict.fromkeys(paths))


def maybe_promote(
    program: str,
    run_dir: Path,
    *,
    enabled: bool,
    promote_bin: str | None = None,
    shared_base: Path | None = None,
    no_index: bool = False,
) -> dict[str, object]:
    if not enabled:
        return {"enabled": False, "status": "disabled"}
    if not promote_bin:
        from agents.recon.promote_run import promote_run

        promote_args = argparse.Namespace(
            program=program,
            run_root=str(run_dir),
            shared_base=str(shared_base) if shared_base else None,
            no_index=no_index,
        )
        result = promote_run(promote_args)
        return {"enabled": True, "status": "ok", "mode": "in-process", "result": result}

    result = subprocess.run(
        [
            promote_bin,
            "promote-run",
            program,
            "--run-root",
            str(run_dir),
            *(["--shared-base", str(shared_base)] if shared_base else []),
            *(["--no-index"] if no_index else []),
        ],
        cwd=str(run_dir),
        capture_output=True,
        check=False,
    )
    return {
        "enabled": True,
        "status": "ok" if result.returncode == 0 else "failed",
        "mode": "subprocess",
        "command": [
            promote_bin,
            "promote-run",
            program,
            "--run-root",
            str(run_dir),
            *(["--shared-base", str(shared_base)] if shared_base else []),
            *(["--no-index"] if no_index else []),
        ],
        "exit_code": result.returncode,
        "stdout": result.stdout.decode("utf-8", errors="replace"),
        "stderr": result.stderr.decode("utf-8", errors="replace"),
    }


def run_tool(args: argparse.Namespace) -> dict[str, object]:
    shared_base = Path(args.shared_base).expanduser() if args.shared_base else SHARED_BASE
    program = safe_slug(args.program, default="program")
    tool = safe_slug(args.tool, default="tool") if args.tool else infer_tool(args.command)
    run_id, run_dir = allocate_run_dir(shared_base, program, tool, args.run_id)

    command_path = run_dir / "command.txt"
    stdout_path = run_dir / "stdout.txt"
    stderr_path = run_dir / "stderr.txt"
    manifest_path = run_dir / "manifest.json"

    write_command(command_path, args.command)
    started_at = utc_now()
    result = subprocess.run(
        args.command,
        cwd=str(run_dir),
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )
    finished_at = utc_now()
    stdout_path.write_bytes(result.stdout)
    stderr_path.write_bytes(result.stderr)

    known_files = {command_path, stdout_path, stderr_path, manifest_path}
    manifest: dict[str, object] = {
        "program": program,
        "tool": tool,
        "run_id": run_id,
        "run_dir": str(run_dir),
        "command": list(args.command),
        "command_file": str(command_path),
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
        "exit_code": result.returncode,
        "status": "ok" if result.returncode == 0 else "failed",
        "started_at": started_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "finished_at": finished_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "generated_files": discover_files(run_dir, known_files),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest["promotion"] = maybe_promote(
        program,
        run_dir,
        enabled=not args.no_promote and result.returncode == 0,
        promote_bin=args.promote_bin,
        shared_base=shared_base,
        no_index=args.no_index,
    )
    if not args.no_promote and result.returncode != 0:
        manifest["promotion"] = {"enabled": True, "status": "skipped", "reason": "command-failed"}
    promotion = manifest.get("promotion")
    promotion_result = promotion.get("result") if isinstance(promotion, dict) else None
    if isinstance(promotion, dict) and promotion.get("status") == "ok" and isinstance(promotion_result, dict):
        manifest["promoted"] = True
        manifest["promoted_at"] = utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")
        manifest["promoted_counts"] = promotion_counts(promotion_result)
        manifest["promoted_paths_touched"] = promotion_paths(promotion_result)
    else:
        manifest["promoted"] = False
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest["manifest"] = str(manifest_path)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a recon tool into a canonical per-tool artifact directory.")
    parser.add_argument("program", help="Program slug, for example flourish.")
    parser.add_argument("--tool", help="Override inferred tool name. Defaults to the first command token basename.")
    parser.add_argument("--run-id", help="Optional run id. A unique suffix is added if it already exists.")
    parser.add_argument("--shared-base", help="Override ~/Shared/web_bounty for tests or controlled runs.")
    parser.add_argument("--no-promote", action="store_true", help="Do not call promote-run even if it is available.")
    parser.add_argument("--no-index", action="store_true", help="Pass --no-index to promote-run.")
    parser.add_argument("--promote-bin", help="Override promote-run binary path.")
    return parser


def split_argv(argv: Iterable[str] | None) -> tuple[list[str], list[str]]:
    values = list(sys.argv[1:] if argv is None else argv)
    if "--" not in values:
        raise SystemExit("missing command separator; use: tool-run <program> -- <command>")
    separator = values.index("--")
    return values[:separator], values[separator + 1 :]


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    wrapper_argv, command = split_argv(argv)
    args = parser.parse_args(wrapper_argv)
    args.command = command
    if not command:
        parser.error("missing command; use: tool-run <program> -- <command>")
    result = run_tool(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return int(result["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
