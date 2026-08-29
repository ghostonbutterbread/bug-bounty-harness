#!/usr/bin/env python3
"""Normalize agent-collected product/developer documentation signals for recon.

Network retrieval is deliberately outside this helper.  A documentation agent
collects bounded source records, then this command validates, deduplicates, and
writes a source-attributed recon artifact for later `/docs` promotion.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bounty_core_bootstrap import ensure_bounty_core_importable

ensure_bounty_core_importable("bounty_core.recon")
from bounty_core.recon import start_run, write_manifest

VALID_KINDS = {"product", "developer", "api", "sdk", "integration", "webhook", "permission", "workflow"}


def normalized_record(raw: dict[str, Any], *, source_path: str) -> dict[str, Any] | None:
    url = str(raw.get("url") or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    kind = str(raw.get("kind") or "developer").strip().lower()
    if kind not in VALID_KINDS:
        kind = "developer"
    signals = raw.get("signals") or raw.get("tags") or []
    if isinstance(signals, str):
        signals = [part.strip() for part in signals.split(",") if part.strip()]
    if not isinstance(signals, list):
        signals = []
    title = str(raw.get("title") or "").strip()
    use_cases = raw.get("use_cases") or []
    if isinstance(use_cases, str):
        use_cases = [part.strip() for part in use_cases.split(",") if part.strip()]
    if not isinstance(use_cases, list):
        use_cases = []
    return {
        "id": "doc-" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:16],
        "url": url,
        "kind": kind,
        "title": title,
        "signals": sorted({str(value).strip().lower() for value in signals if str(value).strip()}),
        "use_cases": sorted({str(value).strip() for value in use_cases if str(value).strip()}),
        "source_artifact_path": source_path,
        "source_status": "collected-unverified",
        "promotion": "candidate-for-program-docs",
    }


def read_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        payload = json.loads(text)
        if isinstance(payload, dict):
            payload = payload.get("documents", [])
        if not isinstance(payload, list):
            raise ValueError("JSON input must be a list or contain documents[]")
        return [row for row in payload if isinstance(row, dict)]
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program")
    parser.add_argument("--input", required=True, type=Path, help="Agent-collected JSON/JSONL documentation source records.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--family", default="web_bounty")
    parser.add_argument("--lane", default="web")
    parser.add_argument("--root")
    parser.add_argument("--run-id")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source = args.input.expanduser().resolve(strict=True)
    normalized: dict[str, dict[str, Any]] = {}
    for raw in read_records(source):
        row = normalized_record(raw, source_path=str(source))
        if row:
            normalized[row["url"]] = row
    run = start_run(tool="recon-docs", target=args.target, program=args.program, family=args.family, lane=args.lane, run_id=args.run_id, root_override=args.root)
    output = run.parsed_dir / "developer_docs.jsonl"
    output.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in sorted(normalized.values(), key=lambda row: row["url"])), encoding="utf-8")
    run.command_path.write_text(f"recon-docs input={source}\n", encoding="utf-8")
    run.stdout_path.write_text("", encoding="utf-8")
    run.stderr_path.write_text("", encoding="utf-8")
    manifest = write_manifest(run, {
        "status": "ok",
        "exit_code": 0,
        "mode": "offline-normalization",
        "inputs": [str(source)],
        "artifact_files": [str(output)],
        "raw_files": [str(source)],
        "parsed_files": [str(output)],
        "counts": {"input_records": len(read_records(source)), "document_sources": len(normalized), "promotion_candidates": len(normalized)},
        "promotion_policy": "Collected documentation is source-backed context, not target proof. Promote only reviewed workflow models via /docs.",
    })
    if args.json:
        print(manifest.read_text(encoding="utf-8"), end="")
    else:
        print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
