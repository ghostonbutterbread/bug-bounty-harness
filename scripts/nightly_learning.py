#!/usr/bin/env python3
"""Run the safe, report-only beta of the AppSec nightly learning loop.

The source registry is Markdown-adjacent and synced at
``~/notes/appsec/research/sources/learning-sources.yaml``.  This runner fetches
only configured HTTPS source indexes through safe-fetch, writes auditable JSON
and Markdown reports, and prints a compact Discord-ready digest.  It never
writes ResearchMap cards, skills, prompts, or target facts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import yaml

DEFAULT_REGISTRY = Path.home() / "notes" / "appsec" / "research" / "sources" / "learning-sources.yaml"
DEFAULT_RUNTIME = Path.home() / ".hermes" / "learning" / "nightly"
DEFAULT_REPORTS = DEFAULT_RUNTIME / "reports"
DEFAULT_LEDGER = DEFAULT_RUNTIME / "seen.sqlite"
SAFE_FETCH = Path.home() / "safe-fetch" / "scripts" / "safe_fetch.py"
REQUIRED_FIELDS = ("id", "name", "url", "type", "tags", "enabled", "priority", "fetch_strategy")


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    url: str
    type: str
    tags: list[str]
    enabled: bool
    priority: int
    fetch_strategy: str


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def validate_registry(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict) or data.get("version") != 1:
        return ["registry version must be 1"]
    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        return ["sources must be a non-empty list"]
    seen: set[str] = set()
    for index, item in enumerate(sources, 1):
        prefix = f"source #{index}"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: must be a mapping")
            continue
        for field in REQUIRED_FIELDS:
            if field not in item:
                errors.append(f"{prefix}: missing {field}")
        source_id = item.get("id")
        if isinstance(source_id, str) and source_id:
            if source_id in seen:
                errors.append(f"{prefix}: duplicate id {source_id}")
            seen.add(source_id)
        else:
            errors.append(f"{prefix}: id must be a non-empty string")
        url = item.get("url")
        parsed = urlparse(url) if isinstance(url, str) else None
        if not parsed or parsed.scheme != "https" or not parsed.netloc:
            errors.append(f"{prefix}: url must be canonical HTTPS")
        if not isinstance(item.get("tags"), list) or not all(isinstance(tag, str) and tag for tag in item.get("tags", [])):
            errors.append(f"{prefix}: tags must be a non-empty string list")
        if not isinstance(item.get("enabled"), bool):
            errors.append(f"{prefix}: enabled must be boolean")
        if not isinstance(item.get("priority"), int):
            errors.append(f"{prefix}: priority must be integer")
    return errors


def load_registry(path: Path) -> list[Source]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    errors = validate_registry(data)
    if errors:
        raise ValueError("invalid source registry:\n" + "\n".join(errors))
    return [Source(**{key: item[key] for key in Source.__dataclass_fields__}) for item in data["sources"]]


def safe_fetch(source: Source, max_chars: int) -> dict[str, Any]:
    command = [sys.executable, str(SAFE_FETCH), source.url, "--json", "--max-chars", str(max_chars)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or f"safe-fetch exited {result.returncode}").strip())
    document = json.loads(result.stdout)
    if not isinstance(document, dict) or document.get("type") != "SanitizedDocument":
        raise ValueError("safe-fetch did not return a SanitizedDocument")
    return document


def stable_content_hash(document: dict[str, Any]) -> str:
    """Hash sanitized visible content, not a transport artifact with volatile markup."""
    content = document.get("content")
    if isinstance(content, str) and content.strip():
        normalized = " ".join(content.split())
        return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    source_hash = document.get("sha256")
    return str(source_hash) if source_hash else ""


def record_seen(ledger_path: Path, source_id: str, content_hash: str, observed_at: str) -> bool:
    """Record a source-index version and return whether it is new."""
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(ledger_path) as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS seen_source_versions (
            source_id TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            PRIMARY KEY (source_id, content_hash)
        )""")
        existing = connection.execute(
            "SELECT 1 FROM seen_source_versions WHERE source_id = ? AND content_hash = ?",
            (source_id, content_hash),
        ).fetchone()
        if existing:
            connection.execute(
                "UPDATE seen_source_versions SET last_seen_at = ? WHERE source_id = ? AND content_hash = ?",
                (observed_at, source_id, content_hash),
            )
            return False
        connection.execute(
            "INSERT INTO seen_source_versions VALUES (?, ?, ?, ?)",
            (source_id, content_hash, observed_at, observed_at),
        )
    return True


def run_beta(
    sources: list[Source],
    reports_dir: Path,
    *,
    ledger_path: Path | None = None,
    max_chars: int = 3000,
    fetch: Callable[[Source, int], dict[str, Any]] = safe_fetch,
    now: datetime | None = None,
) -> tuple[Path, dict[str, Any]]:
    now = now or utc_now()
    ledger_path = ledger_path or reports_dir.parent / "seen.sqlite"
    run_id = "nightly-learning-" + now.strftime("%Y%m%dT%H%M%SZ")
    records: list[dict[str, Any]] = []
    for source in sorted((item for item in sources if item.enabled), key=lambda item: (-item.priority, item.id)):
        record: dict[str, Any] = {"source_id": source.id, "source_name": source.name, "url": source.url, "status": "failed"}
        try:
            document = fetch(source, max_chars)
            observed_at = str(document.get("fetched_at") or now.isoformat())
            content_hash = stable_content_hash(document)
            status = "needs_review" if document.get("verdict") != "allow" else "new"
            if status == "new" and content_hash and not record_seen(ledger_path, source.id, content_hash, observed_at):
                status = "duplicate"
            record.update({
                "status": status,
                "fetched_at": observed_at,
                "sha256": document.get("sha256"),
                "artifact_dir": document.get("artifact_dir"),
                "raw_artifact": document.get("raw_artifact"),
                "risk_flags": document.get("risk_flags", []),
                "recommended_mode": document.get("recommended_mode"),
                "truncated": bool(document.get("truncated")),
            })
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            record["error"] = str(exc)
        records.append(record)
    counts = {status: sum(item["status"] == status for item in records) for status in ("new", "duplicate", "needs_review", "failed")}
    report = {"schema_version": 1, "mode": "beta-report-only", "run_id": run_id, "started_at": now.isoformat(), "registry": str(DEFAULT_REGISTRY), "ledger": str(ledger_path), "records": records, "counts": counts}
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"{now.strftime('%Y-%m-%d')}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path = reports_dir / f"{now.strftime('%Y-%m-%d')}.md"
    markdown_path.write_text(render_digest(report, include_paths=True) + "\n", encoding="utf-8")
    return report_path, report


def render_digest(report: dict[str, Any], *, include_paths: bool = False) -> str:
    counts = report["counts"]
    lines = [f"Nightly AppSec learning beta — {report['run_id']}", "", "Safe-fetch source-index review only; no cards, notes, skills, or target actions were created."]
    for record in report["records"]:
        suffix = ""
        if record["status"] == "failed":
            suffix = f": {record.get('error', 'unknown error')}"
        elif record["status"] == "needs_review":
            suffix = f": flagged {', '.join(record.get('risk_flags') or ['review required'])}"
        else:
            suffix = f": artifact {record.get('raw_artifact', 'recorded')}"
        lines.append(f"- [{record['status']}] {record['source_name']} — {record['url']}{suffix}")
    lines.extend(["", f"Counts: {counts['new']} new, {counts['duplicate']} duplicate, {counts['needs_review']} review, {counts['failed']} failed.", "Next: review the bounded source artifacts; promote only concrete reusable mechanisms into cited ResearchMap cards."])
    if include_paths:
        lines.append(f"Report: {report.get('report_path', 'written alongside this digest')}")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate", help="Validate the curated source whitelist")
    beta = commands.add_parser("beta", help="Fetch whitelisted source indexes and write a report-only digest")
    beta.add_argument("--max-chars", type=int, default=3000)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        sources = load_registry(args.registry.expanduser())
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if args.command == "validate":
        print(f"Learning source registry valid: {len(sources)} source(s)")
        return 0
    if args.max_chars < 500:
        print("--max-chars must be at least 500", file=sys.stderr)
        return 2
    report_path, report = run_beta(
        sources,
        args.reports_dir.expanduser(),
        ledger_path=args.ledger.expanduser(),
        max_chars=args.max_chars,
    )
    report["report_path"] = str(report_path)
    print(render_digest(report))
    return 0 if report["counts"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
