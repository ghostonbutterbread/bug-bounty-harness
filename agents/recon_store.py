#!/usr/bin/env python3
"""Shared recon artifact store helpers.

Recon tools should preserve raw output first, then import URL/host-shaped
artifacts into the per-program SQLite URL index. This module keeps that
discipline in one place so recon producers do not each reinvent ingestion.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

_AGENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _AGENT_DIR.parent
for _path in (_AGENT_DIR, _PROJECT_ROOT):
    _path_str = str(_path)
    if _path_str not in sys.path:
        sys.path.insert(0, _path_str)

from bounty_core_bootstrap import ensure_bounty_core_importable

ensure_bounty_core_importable("bounty_core.recon")

from bounty_core.recon import start_run, write_manifest

import url_ingest


URLISH_ARTIFACT_NAMES = {
    "alive.txt",
    "urls.txt",
    "params_raw.txt",
    "params.txt",
    "jsfiles.txt",
    "js_files.txt",
    "alive_subs.txt",
    "all_subs.txt",
}

RAW_ARTIFACT_EXTENSIONS = {".txt", ".json", ".jsonl", ".csv", ".md", ".log"}


@dataclass(frozen=True)
class ReconArtifact:
    source_path: Path
    raw_path: Path
    parsed_path: Path | None
    url_indexed: bool
    lines_read: int


def safe_slug(value: str, *, default: str = "target") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()).strip("._-")
    return cleaned or default


def line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        return sum(1 for line in handle if line.strip())


def looks_urlish(value: str) -> bool:
    text = value.strip()
    if not text or text.startswith("#"):
        return False
    if " " in text:
        return False
    if text.startswith(("http://", "https://")):
        return True
    if "/" in text.strip("/"):
        return False
    return bool(re.match(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?$", text))


def extract_urlish_lines(source: Path, destination: Path) -> int:
    """Write URL/host-shaped lines from source to destination."""
    count = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("r", encoding="utf-8", errors="ignore") as inp, destination.open(
        "w", encoding="utf-8"
    ) as out:
        for raw in inp:
            value = raw.strip()
            if looks_urlish(value):
                out.write(value + "\n")
                count += 1
    return count


def should_index_artifact(path: Path) -> bool:
    return path.name in URLISH_ARTIFACT_NAMES


def copy_artifact(source: Path, raw_dir: Path, parsed_dir: Path) -> ReconArtifact:
    """Copy one artifact into raw storage and optionally parsed URL-index input."""
    raw_path = raw_dir / source.name
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, raw_path)

    parsed_path: Path | None = None
    url_indexed = False
    if should_index_artifact(source):
        parsed_path = parsed_dir / source.name
        lines = extract_urlish_lines(source, parsed_path)
        url_indexed = lines > 0
    else:
        lines = line_count(source)

    return ReconArtifact(
        source_path=source,
        raw_path=raw_path,
        parsed_path=parsed_path,
        url_indexed=url_indexed,
        lines_read=lines,
    )


def import_url_artifacts(
    *,
    program: str,
    artifacts: Iterable[Path],
    run_id: str,
    scope_filter: str = "auto",
    repull_scope: bool = True,
) -> list[dict]:
    """Import URL-bearing artifacts into url_ingest and return import summaries."""
    imports: list[dict] = []
    for artifact in artifacts:
        path = Path(artifact)
        if not path.is_file() or line_count(path) == 0:
            continue
        before = _latest_import_id(program)
        url_ingest.ingest(
            program,
            source_file=str(path),
            run_id=run_id,
            scope_filter=scope_filter,
            repull_scope=repull_scope,
        )
        row = _latest_import_row(program, after_id=before)
        imports.append(row or {"source_file": str(path), "run_id": run_id})
    return imports


def record_recon_artifacts(
    *,
    program: str,
    target: str,
    tool: str,
    source_paths: Iterable[Path],
    family: str = "web_bounty",
    lane: str = "web",
    root_override: str | Path | None = None,
    run_id: str | None = None,
    command: str | None = None,
    scope_filter: str = "auto",
    repull_scope: bool = True,
    extra_manifest: dict | None = None,
) -> Path:
    """Create a canonical recon run, preserve raw files, and index URL artifacts."""
    run = start_run(
        tool=tool,
        target=safe_slug(target),
        program=program,
        family=family,
        lane=lane,
        run_id=run_id,
        root_override=root_override,
    )
    run.command_path.write_text((command or "").rstrip() + "\n", encoding="utf-8")
    run.stdout_path.write_text("", encoding="utf-8")
    run.stderr_path.write_text("", encoding="utf-8")

    copied: list[ReconArtifact] = []
    for source in source_paths:
        path = Path(source)
        if path.is_file() and path.suffix.lower() in RAW_ARTIFACT_EXTENSIONS:
            copied.append(copy_artifact(path, run.raw_dir, run.parsed_dir))

    index_inputs = [item.parsed_path for item in copied if item.url_indexed and item.parsed_path]
    url_index_imports = import_url_artifacts(
        program=program,
        artifacts=index_inputs,
        run_id=run.run_id,
        scope_filter=scope_filter,
        repull_scope=repull_scope,
    )
    url_index_summary = summarize_url_index(program)

    manifest = {
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "exit_code": 0,
        "mode": "record-artifacts",
        "source_files": [str(Path(path)) for path in source_paths],
        "raw_files": [str(item.raw_path) for item in copied],
        "parsed_files": [str(item.parsed_path) for item in copied if item.parsed_path],
        "url_index_imports": url_index_imports,
        "url_index_summary": url_index_summary,
        "counts": {
            "raw_records": sum(line_count(item.raw_path) for item in copied),
            "parsed_records": sum(item.lines_read for item in copied if item.url_indexed),
            "promotion_candidates": 0,
            "promoted_findings": 0,
            "url_indexed_artifacts": len(index_inputs),
            "url_index_imports": len(url_index_imports),
        },
        "promotion_policy": "No automatic ledger promotion. Recon artifacts are stored and URL-shaped records are indexed for later review.",
    }
    if extra_manifest:
        manifest.update(extra_manifest)
    return write_manifest(run, manifest)


def summarize_url_index(program: str, limit: int = 20) -> dict:
    """Return small DB summary for agents before loading large queues."""
    try:
        with url_ingest.get_conn(program) as conn:
            total = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
            hosts = conn.execute(
                "SELECT host, COUNT(*) AS count FROM urls GROUP BY host ORDER BY count DESC LIMIT ?",
                (limit,),
            ).fetchall()
            sources = conn.execute(
                "SELECT source, COUNT(*) AS count FROM urls GROUP BY source ORDER BY count DESC LIMIT ?",
                (limit,),
            ).fetchall()
            last_import = conn.execute(
                "SELECT imported_at, source_file, run_id, urls_imported, urls_read, urls_accepted, "
                "urls_rejected, scope_mode FROM imports ORDER BY imported_at DESC LIMIT 1"
            ).fetchone()
    except Exception as exc:
        return {"available": False, "error": str(exc)}
    return {
        "available": True,
        "total_urls": total,
        "top_hosts": [dict(row) for row in hosts],
        "top_sources": [dict(row) for row in sources],
        "last_import": dict(last_import) if last_import else None,
    }


def _latest_import_id(program: str) -> int:
    try:
        with url_ingest.get_conn(program) as conn:
            row = conn.execute("SELECT MAX(id) AS id FROM imports").fetchone()
            return int(row["id"] or 0)
    except Exception:
        return 0


def _latest_import_row(program: str, *, after_id: int) -> dict | None:
    with url_ingest.get_conn(program) as conn:
        row = conn.execute(
            "SELECT id, source_file, run_id, urls_imported, urls_read, urls_accepted, "
            "urls_rejected, scope_mode, scoped_temp_path, rejected_temp_path, imported_at "
            "FROM imports WHERE id > ? ORDER BY id DESC LIMIT 1",
            (after_id,),
        ).fetchone()
        return dict(row) if row else None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Record recon artifacts and index URL-shaped data.")
    parser.add_argument("program")
    parser.add_argument("--target", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--source", action="append", required=True, help="File artifact to preserve and optionally index. Repeatable.")
    parser.add_argument("--run-id")
    parser.add_argument("--family", default="web_bounty")
    parser.add_argument("--lane", default="web")
    parser.add_argument("--root")
    parser.add_argument("--scope-filter", choices=["off", "auto"], default="auto")
    parser.add_argument("--no-repull-scope", action="store_false", dest="repull_scope", default=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = record_recon_artifacts(
        program=args.program,
        target=args.target,
        tool=args.tool,
        source_paths=[Path(item).expanduser() for item in args.source],
        family=args.family,
        lane=args.lane,
        root_override=args.root,
        run_id=args.run_id,
        scope_filter=args.scope_filter,
        repull_scope=args.repull_scope,
    )
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
