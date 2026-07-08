#!/usr/bin/env python3
"""Central append helper for lightweight recon aggregate stores.

Agents use this when they discover URL-like recon facts during exploration.
Tool wrappers can also use it as the first promotion primitive before richer
manifest-based promotion exists.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

_RECON_DIR = Path(__file__).resolve().parent
_AGENT_DIR = _RECON_DIR.parent
for _path in (_AGENT_DIR, _RECON_DIR):
    _path_str = str(_path)
    if _path_str not in sys.path:
        sys.path.insert(0, _path_str)

import url_ingest


SHARED_BASE = Path.home() / "Shared" / "web_bounty"

AGGREGATE_FILES = {
    "url": "urls.txt",
    "alive": "alive.txt",
    "param": "params_raw.txt",
    "js": "jsfiles.txt",
    "dir": "dirs.txt",
    "host": "wild.txt",
    "wild": "wild.txt",
}

URL_INDEX_FILES = {"urls.txt", "alive.txt", "params_raw.txt", "jsfiles.txt"}

MIRRORS = {
    "urls.txt": ("urls/urls.txt",),
    "alive.txt": ("urls/alive.txt",),
    "params_raw.txt": ("params/params_raw.txt",),
    "params.txt": ("urls/params.txt", "params/params.txt"),
    "jsfiles.txt": ("js/js_urls.txt", "js/jsfiles.txt"),
}


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def aggregate_root(program: str) -> Path:
    return SHARED_BASE / program / "web" / "recon" / "aggregated"


def recon_root(program: str) -> Path:
    return SHARED_BASE / program / "web" / "recon"


def safe_slug(value: str, *, default: str = "run") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()).strip("._-")
    return cleaned or default


def read_lines(paths: Iterable[str], values: Iterable[str], *, read_stdin: bool = False) -> list[str]:
    lines: list[str] = []
    for value in values:
        cleaned = normalize_line(value)
        if cleaned:
            lines.append(cleaned)
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw in handle:
                cleaned = normalize_line(raw)
                if cleaned:
                    lines.append(cleaned)
    if read_stdin:
        for raw in sys.stdin:
            cleaned = normalize_line(raw)
            if cleaned:
                lines.append(cleaned)
    return dedupe_preserve_order(lines)


def normalize_line(value: str) -> str:
    text = str(value or "").strip()
    if not text or text.startswith("#"):
        return ""
    return text


def dedupe_preserve_order(lines: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


def read_file_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]


@contextlib.contextmanager
def program_lock(root: Path):
    """Serialize aggregate writes for one program."""
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / ".recon_bus.lock"
    with lock_path.open("w", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def find_tool(name: str, explicit: str | None = None) -> str | None:
    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
        return explicit if shutil.which(explicit) else None
    return shutil.which(name)


def merge_with_anew(source_path: Path, target_path: Path, delta_path: Path) -> dict[str, object]:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    delta_path.parent.mkdir(parents=True, exist_ok=True)
    if not target_path.exists():
        target_path.touch()

    source_lines = read_file_lines(source_path)
    anew_bin = find_tool("anew")
    if anew_bin:
        result = subprocess.run(
            [anew_bin, str(target_path)],
            input="".join(f"{line}\n" for line in source_lines),
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            delta_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            write_lines(delta_path, delta_lines)
            return {"read": len(source_lines), "new": len(delta_lines), "mode": "anew"}

    existing = set(read_file_lines(target_path))
    delta_lines = [line for line in source_lines if line not in existing]
    if delta_lines:
        with target_path.open("a", encoding="utf-8") as handle:
            for line in delta_lines:
                handle.write(line + "\n")
    write_lines(delta_path, delta_lines)
    return {"read": len(source_lines), "new": len(delta_lines), "mode": "python"}


def run_uro(input_path: Path, output_path: Path, *, uro_bin: str | None = None) -> str:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    resolved = find_tool("uro", uro_bin)
    if resolved:
        tmp_output = output_path.with_name(f".{output_path.name}.{utc_stamp()}.tmp")
        result = subprocess.run(
            [resolved, "-o", str(tmp_output)],
            input=input_path.read_text(encoding="utf-8", errors="ignore"),
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0 and tmp_output.exists():
            tmp_output.replace(output_path)
            return "uro"
        if tmp_output.exists():
            tmp_output.unlink()
    write_lines(output_path, sorted(set(read_file_lines(input_path))))
    return "sort-unique"


def run_httpx(input_path: Path, output_path: Path, *, httpx_bin: str | None = None) -> dict[str, object]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not read_file_lines(input_path):
        write_lines(output_path, [])
        return {"ran": False, "reason": "empty-delta", "output": str(output_path), "count": 0}
    resolved = find_tool("httpx", httpx_bin)
    if not resolved:
        raise SystemExit("httpx not found; install it or pass --httpx-bin")
    result = subprocess.run(
        [resolved, "-silent", "-no-color", "-l", str(input_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"httpx failed: {result.stderr.strip()[-500:]}")
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    write_lines(output_path, dedupe_preserve_order(lines))
    return {"ran": True, "output": str(output_path), "count": len(lines)}


def mirror_aggregates(program: str) -> dict[str, str]:
    root = aggregate_root(program)
    base = recon_root(program)
    mirrored: dict[str, str] = {}
    for source_name, destinations in MIRRORS.items():
        source = root / source_name
        if not source.exists():
            continue
        for relative in destinations:
            destination = base / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            mirrored[relative] = str(destination)
    return mirrored


def index_delta(program: str, files: Iterable[Path], run_id: str, *, enabled: bool) -> list[str]:
    if not enabled:
        return []
    indexable_files = [path for path in files if path.name in URL_INDEX_FILES]
    if not indexable_files:
        return []
    indexed: list[str] = []
    original_base = url_ingest.SHARED_BASE
    url_ingest.SHARED_BASE = SHARED_BASE
    try:
        for path in indexable_files:
            if path.is_file() and path.stat().st_size > 0:
                url_ingest.ingest(
                    program,
                    source_file=str(path),
                    run_id=run_id,
                    scope_filter="off",
                    repull_scope=False,
                )
                indexed.append(str(path))
    finally:
        url_ingest.SHARED_BASE = original_base
    return indexed


def append(args: argparse.Namespace) -> dict[str, object]:
    global SHARED_BASE
    original_shared_base = SHARED_BASE
    original_url_ingest_base = url_ingest.SHARED_BASE
    if args.shared_base:
        SHARED_BASE = Path(args.shared_base).expanduser()
        url_ingest.SHARED_BASE = SHARED_BASE
    try:
        return _append(args)
    finally:
        SHARED_BASE = original_shared_base
        url_ingest.SHARED_BASE = original_url_ingest_base


def _append(args: argparse.Namespace) -> dict[str, object]:
    if args.kind not in AGGREGATE_FILES:
        raise SystemExit(f"unsupported kind: {args.kind}")
    if args.kind == "alive" and args.liveness == "probe":
        raise SystemExit("--kind alive already means liveness is known; use --liveness known or omit it")

    run_id = safe_slug(args.run_id or f"recon-bus-{utc_stamp()}")
    root = aggregate_root(args.program)
    with program_lock(root):
        run_dir = root / "runs" / run_id
        incoming = run_dir / "incoming" / f"{args.kind}.txt"
        delta_dir = run_dir / "delta"

        lines = read_lines(args.input or [], args.value or [], read_stdin=args.stdin)
        write_lines(incoming, lines)

        touched_files: list[Path] = []
        stats: dict[str, object] = {
            "program": args.program,
            "run_id": run_id,
            "kind": args.kind,
            "liveness": args.liveness,
            "incoming": str(incoming),
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "status": "ok",
        }

        target = root / AGGREGATE_FILES[args.kind]
        delta = delta_dir / AGGREGATE_FILES[args.kind]
        stats["primary"] = merge_with_anew(incoming, target, delta)
        touched_files.append(delta)

        if args.kind == "url" and args.liveness == "probe":
            httpx_output = run_dir / "normalized" / "httpx_alive.txt"
            stats["httpx"] = run_httpx(delta, httpx_output, httpx_bin=args.httpx_bin)
            alive_delta = delta_dir / "alive.txt"
            stats["alive"] = merge_with_anew(httpx_output, root / "alive.txt", alive_delta)
            touched_files.append(alive_delta)
        elif args.kind == "url" and args.liveness == "known":
            alive_delta = delta_dir / "alive.txt"
            stats["alive"] = merge_with_anew(delta, root / "alive.txt", alive_delta)
            touched_files.append(alive_delta)
        elif args.kind == "alive":
            urls_delta = delta_dir / "urls.txt"
            stats["urls"] = merge_with_anew(incoming, root / "urls.txt", urls_delta)
            touched_files.append(urls_delta)

        if args.kind == "param":
            mode = run_uro(root / "params_raw.txt", root / "params.txt", uro_bin=args.uro_bin)
            stats["params_normalization"] = {"mode": mode, "output": str(root / "params.txt")}

        stats["mirrors"] = mirror_aggregates(args.program)
        try:
            stats["indexed"] = index_delta(args.program, touched_files, run_id, enabled=not args.no_index)
        except Exception as exc:
            stats["indexed"] = []
            stats["index_error"] = str(exc)
            stats["status"] = "partial_index_failed"

        manifest = run_dir / "manifest.json"
        manifest.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        stats["manifest"] = str(manifest)
        return stats


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Append recon discoveries into canonical aggregate stores.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    append_parser = subparsers.add_parser("append", help="Append URL-like discoveries into aggregate stores.")
    append_parser.add_argument("program")
    append_parser.add_argument(
        "--kind",
        choices=sorted(AGGREGATE_FILES),
        required=True,
        help="Type of input being appended.",
    )
    append_parser.add_argument("--value", action="append", help="Single value to append. Repeatable.")
    append_parser.add_argument("--input", action="append", help="Input file. Repeatable.")
    append_parser.add_argument("--stdin", action="store_true", help="Read input values from stdin.")
    append_parser.add_argument("--run-id", help="Run id for the append operation.")
    append_parser.add_argument(
        "--liveness",
        choices=("unknown", "known", "probe"),
        default="unknown",
        help="For URL inputs: record only, known alive, or probe new delta with httpx.",
    )
    append_parser.add_argument("--httpx-bin", help="Override httpx binary path.")
    append_parser.add_argument("--uro-bin", help="Override uro binary path.")
    append_parser.add_argument("--shared-base", help="Override Shared web_bounty root for tests or controlled imports.")
    append_parser.add_argument("--no-index", action="store_true", help="Skip url_index SQLite ingest.")
    append_parser.set_defaults(func=append)

    promote_parser = subparsers.add_parser(
        "promote-run",
        help="Promote URL-like artifacts from a completed recon tool run.",
    )
    promote_parser.add_argument("program")
    promote_parser.add_argument("--run-root", required=True, help="Completed tool run directory to scan.")
    promote_parser.add_argument("--shared-base", help="Override Shared web_bounty root for tests or controlled imports.")
    promote_parser.add_argument("--no-index", action="store_true", help="Skip url_index SQLite ingest.")
    from agents.recon.promote_run import promote_run

    promote_parser.set_defaults(func=promote_run)

    from agents.recon.mirror import mirror

    mirror_parser = subparsers.add_parser("mirror", help="Rebuild legacy recon compatibility files from aggregates.")
    mirror_parser.add_argument("program")
    mirror_parser.add_argument("--shared-base", help="Override Shared web_bounty root for tests or controlled imports.")
    mirror_parser.set_defaults(func=mirror)

    from agents.recon import watch_runs

    watch_runs.add_parser(subparsers)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = args.func(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
