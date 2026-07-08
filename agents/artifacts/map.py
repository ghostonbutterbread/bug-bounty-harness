#!/usr/bin/env python3
"""Maintain Shared artifact maps for heavy bounty artifacts.

This helper is intentionally small and dependency-free. It lets agents update
machine-readable artifact maps without hand-editing the same Markdown file.
"""

from __future__ import annotations

import argparse
import fcntl
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_SHARED = Path.home() / "Shared"


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return {}


def map_path(shared_root: Path, program: str, surface: str, artifact_type: str) -> Path:
    if surface == "web":
        return shared_root / "web_bounty" / program / "web" / "recon" / "artifacts" / f"{artifact_type}-map.json"
    if surface == "apk":
        return shared_root / "bounty_recon" / program / "apk" / "recon" / "artifacts" / f"{artifact_type}-map.json"
    raise ValueError(f"unsupported surface: {surface}")


def normalize_entry(entry: dict[str, Any], program: str, surface: str, artifact_type: str) -> dict[str, Any]:
    normalized = dict(entry)
    normalized.setdefault("program", program)
    normalized.setdefault("surface", surface)
    normalized.setdefault("artifact_type", artifact_type)
    normalized.setdefault("updated_at", now_utc())
    normalized.setdefault("status", "active")
    return normalized


def refresh_health(entry: dict[str, Any]) -> dict[str, Any]:
    checked = dict(entry)
    candidates = [
        checked.get("target_artifact"),
        checked.get("stable_root"),
        checked.get("index_path"),
        checked.get("latest_run_path"),
    ]
    existing = [str(path) for value in candidates if value and (path := Path(str(value))).exists()]
    missing = [str(path) for value in candidates if value and not (path := Path(str(value))).exists()]
    checked["health_checked_at"] = now_utc()
    checked["observed_existing_paths"] = existing
    checked["observed_missing_paths"] = missing
    if checked.get("target_artifact") and not Path(str(checked["target_artifact"])).exists():
        checked["status"] = checked.get("missing_status", "regenerate")
        checked["health"] = "stale_pointer_missing_target"
        checked["observed_exists"] = False
    elif missing:
        checked.setdefault("health", "partial")
        checked["observed_exists"] = bool(existing)
    else:
        checked["health"] = "exists"
        checked["observed_exists"] = True
    return checked


def upsert_entry(path: Path, entry: dict[str, Any], *, check: bool = False) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        doc = load_json(path)
        doc.setdefault("program", entry["program"])
        doc.setdefault("surface", entry["surface"])
        doc.setdefault("artifact_type", entry["artifact_type"])
        doc.setdefault("entries", [])
        doc["updated_at"] = now_utc()
        doc["format"] = "bounty-artifact-map-v1"

        entry_id = entry.get("artifact_id") or entry.get("id")
        if not entry_id:
            raise ValueError("entry requires artifact_id or id")
        entry["artifact_id"] = entry_id
        if check:
            entry = refresh_health(entry)

        entries = [item for item in doc["entries"] if item.get("artifact_id") != entry_id]
        entries.append(entry)
        doc["entries"] = sorted(entries, key=lambda item: str(item.get("artifact_id", "")))
        path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        fcntl.flock(lock, fcntl.LOCK_UN)
    return doc


def main() -> int:
    parser = argparse.ArgumentParser(description="Upsert/check Shared bounty artifact map entries.")
    parser.add_argument("program")
    parser.add_argument("artifact_type", help="screenshots, javascript, proxy-flows, fuzzing, etc.")
    parser.add_argument("--surface", choices=["web", "apk"], default="web")
    parser.add_argument("--shared-root", type=Path, default=DEFAULT_SHARED)
    parser.add_argument("--entry-json", help="JSON object to upsert.")
    parser.add_argument("--entry-file", type=Path, help="Path to JSON object to upsert.")
    parser.add_argument("--check", action="store_true", help="Refresh health fields from target paths.")
    parser.add_argument("--path-only", action="store_true", help="Print map path and exit.")
    args = parser.parse_args()

    path = map_path(args.shared_root.expanduser(), args.program, args.surface, args.artifact_type)
    if args.path_only:
        print(path)
        return 0
    if args.entry_file:
        entry = json.loads(args.entry_file.read_text())
    elif args.entry_json:
        entry = json.loads(args.entry_json)
    else:
        raise SystemExit("--entry-json or --entry-file is required unless --path-only is used")
    entry = normalize_entry(entry, args.program, args.surface, args.artifact_type)
    doc = upsert_entry(path, entry, check=args.check)
    print(json.dumps({"map_path": str(path), "entry_count": len(doc.get("entries", []))}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
