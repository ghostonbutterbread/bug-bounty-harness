"""Read-only, bounded Coverage uptake watch for one resolved BBH lane.

A missing linkage is a reconciliation prompt, not proof the run was untested or
that every Attempt must have an assessment. This helper never writes Coverage.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from agents.storage_resolver import resolve_storage
from agents.surface_coverage import SurfaceCoverageStore

SOURCES = {
    "url_index": ("recon/url_index/url_index.sqlite", "recon/urls/url_index.sqlite"),
    "urls_aggregate": ("recon/aggregated/urls.txt",),
    "params_aggregate": ("recon/aggregated/params_raw.txt",),
    "js_aggregate": ("recon/aggregated/jsfiles.txt",),
}


def _run_id(value: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise ValueError("attempt run_id must be a non-empty path-safe identifier")
    return value


def watch_lane(program: str, *, family: str, lane: str, root: str | Path | None = None,
               attempt_run_id: str | None = None, run_limit: int = 50,
               max_attempt_rows: int = 5000) -> dict:
    """Summarize existing inventory and typed Attempt links without creating stores."""
    if not 1 <= run_limit <= 200 or not 1 <= max_attempt_rows <= 100000:
        raise ValueError("run_limit must be 1..200 and max_attempt_rows 1..100000")
    layout = resolve_storage(program, family=family, lane=lane, root_override=root, create=False)
    store = SurfaceCoverageStore(program, family=family, lane=lane, root_override=root)
    coverage = {"state": "missing", "questions": 0, "statuses": {}, "history_events": 0,
                "history_incomplete": False}
    refs_by_run: dict[str, set[str]] = {}
    events_by_run: dict[str, dict[str, set[int]]] = {}
    if store.path.is_file():
        try:
            brief = store.brief(limit=1)
            coverage.update(state="present", questions=brief["total"], statuses=brief["counts"])
            with store._read_connection() as db:
                for event in db.execute("SELECT event_id,evidence_json FROM assessment_history"):
                    coverage["history_events"] += 1
                    try:
                        refs = json.loads(event["evidence_json"])
                    except (ValueError, TypeError):
                        coverage["history_incomplete"] = True
                        continue
                    if not isinstance(refs, list):
                        coverage["history_incomplete"] = True
                        continue
                    for ref in refs:
                        if not isinstance(ref, str) or not ref.startswith("attempt:"):
                            continue
                        parts = ref.split(":", 2)
                        if len(parts) != 3 or not parts[1] or not parts[2]:
                            coverage["history_incomplete"] = True
                            continue
                        refs_by_run.setdefault(parts[1], set()).add(parts[2])
                        events_by_run.setdefault(parts[1], {}).setdefault(parts[2], set()).add(event["event_id"])
        except (sqlite3.DatabaseError, ValueError, KeyError) as exc:
            coverage.update(state="unreadable", history_incomplete=True, error_type=type(exc).__name__)
    runs_root = layout.lane_root / "attempts" / "_runs"
    if attempt_run_id is not None:
        files = [runs_root / _run_id(attempt_run_id) / "attempts.jsonl"]
        more_runs = False
    else:
        files = sorted(runs_root.glob("*/attempts.jsonl"), reverse=True) if runs_root.is_dir() else []
        more_runs = len(files) > run_limit
        files = files[:run_limit]
    runs = []
    for path in files:
        run_id = _run_id(path.parent.name)
        row = {"run_id": run_id, "attempt_rows": 0, "linked_events": 0,
               "truncated": False, "parse_errors": 0, "missing_ids": 0, "signal": "no_attempts"}
        if path.is_file():
            ids = set()
            with path.open(encoding="utf-8") as handle:
                for index, line in enumerate(handle):
                    if index >= max_attempt_rows:
                        row["truncated"] = True
                        break
                    try:
                        event = json.loads(line)
                    except ValueError:
                        row["parse_errors"] += 1
                        continue
                    if not isinstance(event, dict):
                        row["parse_errors"] += 1
                        continue
                    row["attempt_rows"] += 1
                    if isinstance(event.get("attempt_id"), str):
                        ids.add(event["attempt_id"])
                    else:
                        row["missing_ids"] += 1
            matched = ids & refs_by_run.get(run_id, set())
            row["linked_events"] = len(set().union(*(events_by_run.get(run_id, {}).get(key, set())
                                                      for key in matched))) if matched else 0
            if row["parse_errors"] or row["missing_ids"] or row["truncated"] or coverage["state"] == "unreadable" or coverage["history_incomplete"]:
                row["signal"] = "incomplete"
            elif row["attempt_rows"]:
                row["signal"] = "linked" if row["linked_events"] else "needs_reconciliation"
        runs.append(row)
    sources = {}
    for name, candidates in SOURCES.items():
        present = next((relative for relative in candidates if (layout.lane_root / relative).is_file()), None)
        sources[name] = {"relative_path": present or candidates[0], "available": present is not None,
                         "reviewed": False}
    return {"program": layout.program, "family": layout.family, "lane": layout.lane,
            "coverage": coverage, "runs": runs, "more_runs": more_runs,
            "sources": sources, "conclusion": "inventory-and-linkage-only; never a test or exhaustion verdict"}
