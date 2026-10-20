"""Evidence-linked live-surface/class coverage, distinct from static file coverage.

This index records the *denominator* that Attempts and MapStore cannot supply:
which mapped surfaces have an explicitly relevant vulnerability-class question.
It never interprets an Attempt or finding as automatic completion.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agents.storage_resolver import resolve_storage
from agents.coverage_evidence import verify_references

STATES = {"no_assessment", "in_progress", "blocked", "bounded_review"}
# Read old lane-local SQLite rows without rewriting history or changing XSS pressure.
LEGACY_STATUSES = {"untested": "no_assessment", "exhausted": "bounded_review"}


def _review_status(status: str) -> str:
    return LEGACY_STATUSES.get(status, status)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _plain(value: Any, label: str, *, required: bool = False) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise ValueError(f"{label} is required")
    if any(c in text for c in ("?", "#", "\n", "\r")):
        raise ValueError(f"{label} must be a stable, non-secret identifier, not a query, fragment, or raw request")
    if (re.search(r"\b(?:bearer|authorization|set-cookie|cookie)(?:\s+|\s*[:=]\s*)\S+", text, re.I)
            or re.search(r"\b(?:(?:access|refresh|client)[_-])?(?:token|secret)\s*[:=]\s*\S+", text, re.I)
            or re.search(r"\b(?:password|api[_-]?key)\s*[:=]\s*\S+", text, re.I)):
        raise ValueError(f"{label} must not contain authentication material; use an opaque evidence ID")
    return text


class SurfaceCoverageStore:
    """One lane-local SQLite index; class semantics remain with specialist agents."""

    def __init__(self, program: str, *, family: str, lane: str, root_override: str | Path | None = None) -> None:
        layout = resolve_storage(program, family=family, lane=lane, root_override=root_override, create=False)
        self.path = layout.ledgers_root / "surface_coverage.sqlite"
        self._evidence_scope = (layout.program, layout.family, layout.lane, root_override)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=15000")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS surfaces (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, host TEXT NOT NULL,
                surface_key TEXT NOT NULL, input_key TEXT NOT NULL, consumer TEXT NOT NULL,
                source_ref TEXT NOT NULL, run_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assessments (
                surface_id TEXT NOT NULL REFERENCES surfaces(id), class_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'no_assessment', pressure TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '', boundary TEXT NOT NULL DEFAULT '',
                axes_json TEXT NOT NULL DEFAULT '[]', evidence_json TEXT NOT NULL DEFAULT '[]',
                reopen_when TEXT NOT NULL DEFAULT '', assessed_fingerprint TEXT NOT NULL DEFAULT '',
                agent TEXT NOT NULL DEFAULT '', assessment_run_id TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL, PRIMARY KEY(surface_id, class_name)
            );
            CREATE INDEX IF NOT EXISTS coverage_by_class ON assessments(class_name, status);
            CREATE TABLE IF NOT EXISTS previous_fingerprints (
                surface_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                PRIMARY KEY(surface_id, fingerprint)
            );
            CREATE TABLE IF NOT EXISTS assessment_history (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT, surface_id TEXT NOT NULL,
                class_name TEXT NOT NULL, status TEXT NOT NULL, pressure TEXT NOT NULL,
                reason TEXT NOT NULL, boundary TEXT NOT NULL, axes_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL, reopen_when TEXT NOT NULL,
                fingerprint TEXT NOT NULL, agent TEXT NOT NULL, run_id TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS coverage_history_subject
                ON assessment_history(surface_id, class_name, event_id);
            CREATE TABLE IF NOT EXISTS surface_sources (
                surface_id TEXT NOT NULL REFERENCES surfaces(id),
                source_ref TEXT NOT NULL, run_id TEXT NOT NULL,
                added_at TEXT NOT NULL,
                PRIMARY KEY(surface_id, source_ref, run_id)
            );
        """)
        return db

    def _read_connection(self) -> sqlite3.Connection:
        """Open an existing index without running schema setup or migration."""
        db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=15000")
        return db

    def discover(self, *, kind: str, host: str, surface_key: str, source_ref: str, run_id: str,
                 class_name: str | None = None, input_key: str = "", consumer: str = "",
                 fingerprint: str = "") -> str:
        return self.discover_many([dict(kind=kind, host=host, surface_key=surface_key,
                                        source_ref=source_ref, run_id=run_id, class_name=class_name,
                                        input_key=input_key, consumer=consumer, fingerprint=fingerprint)])[0]

    def discover_many(self, rows: list[dict[str, Any]]) -> list[str]:
        """Import a mapper batch atomically; invalid later rows roll back earlier ones."""
        ids = []
        seen_ids: set[str] = set()
        with self._connect() as db:
            for line_number, row in enumerate(rows, 1):
                try:
                    identity = {
                        "kind": _plain(row.get("kind"), "kind", required=True),
                        "host": _plain(row.get("host"), "host", required=True).lower(),
                        "surface_key": _plain(row.get("surface_key"), "surface_key", required=True),
                        "input_key": _plain(row.get("input_key"), "input_key"),
                        "consumer": _plain(row.get("consumer"), "consumer"),
                    }
                    source_ref = _plain(row.get("source_ref"), "source_ref", required=True)
                    run_id = _plain(row.get("run_id"), "run_id", required=True)
                    fingerprint = _plain(row.get("fingerprint"), "fingerprint")
                    classes = row.get("class_names", [row.get("class_name")])
                    if not isinstance(classes, list) or any(value is not None and not isinstance(value, str) for value in classes):
                        raise ValueError("class_names must be a list of strings")
                    class_names = [_plain(value or "", "class_name").lower() for value in classes]
                    surface_id = "S-" + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24]
                    timestamp = _now()
                    previous = db.execute("SELECT fingerprint,source_ref,run_id,first_seen FROM surfaces WHERE id=?",
                                          (surface_id,)).fetchone()
                    if previous and not previous["fingerprint"] and not fingerprint and run_id != previous["run_id"]:
                        old_run = db.execute("""SELECT 1 FROM surface_sources
                                                WHERE surface_id=? AND run_id=?""",
                                             (surface_id, run_id)).fetchone()
                        if old_run:
                            raise ValueError("older mapper run cannot replace current unversioned inventory")
                    if previous:
                        db.execute("""INSERT OR IGNORE INTO surface_sources(surface_id,source_ref,run_id,added_at)
                                      VALUES(?,?,?,?)""",
                                   (surface_id, previous["source_ref"], previous["run_id"], previous["first_seen"]))
                        if not previous["fingerprint"]:
                            # Older unversioned decisions have no mapper baseline; capture it
                            # before replacing the current run, without altering their history.
                            db.execute("""UPDATE assessments SET assessed_fingerprint=?
                                          WHERE surface_id=? AND status NOT IN ('untested','no_assessment')
                                            AND assessed_fingerprint=''""",
                                       ("@mapper-run:" + previous["run_id"], surface_id))
                    if previous and fingerprint and fingerprint != previous["fingerprint"]:
                        seen = db.execute("SELECT 1 FROM previous_fingerprints WHERE surface_id=? AND fingerprint=?",
                                          (surface_id, fingerprint)).fetchone()
                        if seen:
                            raise ValueError("older fingerprint cannot replace current mapped version")
                        if previous["fingerprint"]:
                            db.execute("INSERT OR IGNORE INTO previous_fingerprints(surface_id,fingerprint) VALUES(?,?)",
                                       (surface_id, previous["fingerprint"]))
                    db.execute("""INSERT INTO surfaces(id,kind,host,surface_key,input_key,consumer,source_ref,run_id,fingerprint,first_seen,last_seen)
                                  VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                                  source_ref=excluded.source_ref,run_id=excluded.run_id,
                                  fingerprint=CASE WHEN excluded.fingerprint != '' THEN excluded.fingerprint ELSE surfaces.fingerprint END,
                                  last_seen=excluded.last_seen""",
                               (surface_id, *identity.values(), source_ref, run_id, fingerprint, timestamp, timestamp))
                    db.execute("""INSERT OR IGNORE INTO surface_sources(surface_id,source_ref,run_id,added_at)
                                  VALUES(?,?,?,?)""", (surface_id, source_ref, run_id, timestamp))
                    for class_name in class_names:
                        if class_name:
                            db.execute("""INSERT OR IGNORE INTO assessments(surface_id,class_name,status,updated_at)
                                          VALUES(?,?,?,?)""", (surface_id, class_name, "no_assessment", timestamp))
                    if surface_id not in seen_ids:
                        seen_ids.add(surface_id)
                        ids.append(surface_id)
                except ValueError as exc:
                    raise ValueError(f"inventory line {line_number}: {exc}") from exc
        return ids

    def assess(self, surface_id: str, *, class_name: str, status: str, expected_fingerprint: str,
               evidence_refs: list[str],
               reason: str, pressure: str = "", boundary: str = "", axes: list[str] | None = None,
               reopen_when: str = "", agent: str = "", run_id: str = "") -> dict[str, Any]:
        surface_id = _plain(surface_id, "surface_id", required=True)
        class_name = _plain(class_name, "class_name", required=True).lower()
        expected_fingerprint = _plain(expected_fingerprint, "expected_fingerprint")
        status = _review_status(status)  # Historical CLI writers remain accepted.
        if status not in STATES - {"no_assessment"}:
            raise ValueError("status must be in_progress, blocked, or bounded_review")
        reason = _plain(reason, "reason", required=True)
        refs = [_plain(ref, "evidence_ref", required=True) for ref in evidence_refs]
        if not refs:
            raise ValueError("assessment requires at least one evidence reference")
        pressure = _plain(pressure, "pressure")
        boundary = _plain(boundary, "boundary")
        axes = [_plain(axis, "axis", required=True) for axis in (axes or [])]
        reopen_when = _plain(reopen_when, "reopen_when")
        agent = _plain(agent, "agent")
        run_id = _plain(run_id, "run_id")
        if status == "blocked" and not reopen_when:
            raise ValueError("blocked assessment requires reopen_when")
        if status == "bounded_review" and (not boundary or not axes):
            raise ValueError("bounded_review assessment requires boundary and axes")
        if not self.path.exists():
            raise ValueError("surface not discovered")
        # New typed pointers must resolve *before* changing the assessment/history.
        # Legacy opaque references remain readable and writable for compatibility.
        typed = [ref for ref in refs if ref.startswith(("attempt:", "map:"))]
        if typed:
            program, family, lane, root = self._evidence_scope
            checked = verify_references(program, family=family, lane=lane,
                                        root_override=str(root) if root is not None else None, refs=typed)
            for number, result in enumerate(checked, 1):
                if result["status"] != "resolved":
                    kind = "Attempt" if typed[number - 1].startswith("attempt:") else "MapStore"
                    raise ValueError(f"evidence reference {number} ({kind}) is {result['status']}; "
                                     "use the returned attempt_id and exact stream or a retained indexed map path")
        with self._connect() as db:
            row = db.execute("SELECT fingerprint,run_id FROM surfaces WHERE id=?", (surface_id,)).fetchone()
            assessment = db.execute("SELECT 1 FROM assessments WHERE surface_id=? AND class_name=?",
                                    (surface_id, class_name)).fetchone()
            if row is None or assessment is None:
                raise ValueError("surface/class question not discovered")
            if row["fingerprint"] != expected_fingerprint:
                raise ValueError("mapped fingerprint changed; review the current surface before assessment")
            db.execute("""UPDATE assessments SET status=?,pressure=?,reason=?,boundary=?,axes_json=?,
                          evidence_json=?,reopen_when=?,assessed_fingerprint=?,agent=?,assessment_run_id=?,updated_at=?
                          WHERE surface_id=? AND class_name=?""",
                       (status, pressure, reason, boundary, json.dumps(axes), json.dumps(refs), reopen_when,
                        row["fingerprint"] or "@mapper-run:" + row["run_id"],
                        agent, run_id, _now(), surface_id, class_name))
            event = db.execute("""INSERT INTO assessment_history(surface_id,class_name,status,pressure,reason,boundary,
                          axes_json,evidence_json,reopen_when,fingerprint,agent,run_id,recorded_at)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (surface_id, class_name, status, pressure, reason, boundary, json.dumps(axes),
                        json.dumps(refs), reopen_when, row["fingerprint"], agent, run_id, _now()))
            event_id = event.lastrowid
        return {"surface_id": surface_id, "class_name": class_name, "status": status,
                "event_id": event_id}

    def history(self, surface_id: str, *, class_name: str, limit: int = 50,
                event_id: int | None = None) -> list[dict[str, Any]]:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        if event_id is not None and event_id < 1:
            raise ValueError("event_id must be positive")
        if not self.path.exists():
            return []
        with self._read_connection() as db:
            where = " AND event_id=?" if event_id is not None else ""
            rows = db.execute("""SELECT * FROM assessment_history WHERE surface_id=? AND class_name=?"""
                              + where + " ORDER BY event_id DESC LIMIT ?",
                              (_plain(surface_id, "surface_id", required=True),
                               _plain(class_name, "class_name", required=True).lower(),
                               *([event_id] if event_id is not None else []), limit)).fetchall()
        return [{**dict(row), "status": _review_status(row["status"]), "axes": json.loads(row["axes_json"]),
                 "evidence_refs": json.loads(row["evidence_json"])} for row in reversed(rows)]

    def brief(self, *, class_name: str | None = None, host: str | None = None,
              limit: int = 50, offset: int = 0) -> dict[str, Any]:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        if offset < 0:
            raise ValueError("offset must be nonnegative")
        if not self.path.exists():
            return {"counts": {}, "items": [], "total": 0, "unclassified_surfaces": 0,
                    "mapped_kinds": {}, "coverage_path": str(self.path),
                    "offset": offset, "next_offset": None}
        filters = []
        values = []
        if class_name:
            filters.append("a.class_name=?")
            values.append(_plain(class_name, "class_name").lower())
        if host:
            filters.append("s.host=?")
            values.append(_plain(host, "host").lower())
        where = " WHERE " + " AND ".join(filters) if filters else ""
        questions = """WITH questions AS (SELECT s.*,a.class_name,a.status,a.pressure,a.reason,a.boundary,
                       a.axes_json,a.evidence_json,a.reopen_when,a.assessed_fingerprint,a.agent,
                       a.assessment_run_id,a.updated_at,
                       CASE WHEN a.status NOT IN ('untested','no_assessment') AND a.assessed_fingerprint != ''
                                 AND a.assessed_fingerprint !=
                                     CASE WHEN s.fingerprint != '' THEN s.fingerprint
                                          ELSE '@mapper-run:' || s.run_id END THEN 'stale'
                            WHEN a.status = 'untested' THEN 'no_assessment'
                            WHEN a.status = 'exhausted' THEN 'bounded_review'
                            ELSE a.status END AS review_status
                       FROM assessments a JOIN surfaces s ON s.id=a.surface_id""" + where + ") "
        with self._read_connection() as db:
            counts = {row["review_status"]: row["n"] for row in db.execute(
                questions + "SELECT review_status, COUNT(*) AS n FROM questions GROUP BY review_status", values)}
            rows = db.execute(questions + """SELECT * FROM questions ORDER BY
                              CASE review_status WHEN 'blocked' THEN 0 WHEN 'stale' THEN 1
                              WHEN 'in_progress' THEN 2 WHEN 'no_assessment' THEN 3 ELSE 4 END,
                              host,surface_key,input_key,class_name,id LIMIT ? OFFSET ?""",
                              [*values, limit, offset]).fetchall()
            host_filter = " WHERE s.host=?" if host else ""
            host_values = [_plain(host, "host").lower()] if host else []
            kinds = db.execute("SELECT s.kind, COUNT(*) AS n FROM surfaces s" + host_filter +
                               " GROUP BY s.kind", host_values).fetchall()
            unclassified = db.execute("""SELECT COUNT(*) FROM surfaces s WHERE NOT EXISTS
                                      (SELECT 1 FROM assessments a WHERE a.surface_id=s.id)""" +
                                      (" AND s.host=?" if host else ""), host_values).fetchone()[0]
            sources_by_id = {}
            has_source_table = db.execute("""SELECT 1 FROM sqlite_master WHERE type='table'
                                             AND name='surface_sources'""").fetchone() is not None
            for row in rows:
                source_rows = db.execute("""SELECT source_ref,run_id FROM surface_sources
                                           WHERE surface_id=? ORDER BY added_at DESC,source_ref
                                           LIMIT 20""", (row["id"],)).fetchall() if has_source_table else []
                source_count = db.execute("SELECT COUNT(*) FROM surface_sources WHERE surface_id=?",
                                          (row["id"],)).fetchone()[0] if has_source_table else 0
                sources_by_id[row["id"]] = (
                    [dict(source) for source in source_rows] if source_count else
                    [{"source_ref": row["source_ref"], "run_id": row["run_id"]}],
                    source_count if source_count else 1,
                )
        items = []
        for row in rows:
            item = dict(row)
            if item["review_status"] == "stale":
                item["prior_status"] = _review_status(item["status"])
            item["status"] = item.pop("review_status")
            item["surface_id"] = item.pop("id")
            item["sources"], item["source_count"] = sources_by_id[item["surface_id"]]
            item["sources_truncated"] = item["source_count"] > len(item["sources"])
            item["axes"] = json.loads(item.pop("axes_json"))
            item["evidence_refs"] = json.loads(item.pop("evidence_json"))
            items.append(item)
        total = sum(counts.values())
        return {"counts": counts, "items": items, "total": total,
                "unclassified_surfaces": unclassified,
                "mapped_kinds": {row["kind"]: row["n"] for row in kinds},
                "coverage_path": str(self.path), "offset": offset,
                "next_offset": offset + len(items) if offset + len(items) < total else None}
