"""Evidence-linked live-surface/class coverage, distinct from static file coverage.

This index records the *denominator* that Attempts and MapStore cannot supply:
which mapped surfaces have an explicitly relevant vulnerability-class question.
It never interprets an Attempt or finding as automatic completion.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agents.storage_resolver import resolve_storage

STATES = {"untested", "in_progress", "blocked", "exhausted"}
ORDER = {"blocked": 0, "stale": 1, "in_progress": 2, "untested": 3, "exhausted": 4}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _plain(value: str, label: str, *, required: bool = False) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise ValueError(f"{label} is required")
    if any(c in text for c in ("?", "#", "\n", "\r")):
        raise ValueError(f"{label} must be a stable, non-secret identifier, not a query, fragment, or raw request")
    return text


class SurfaceCoverageStore:
    """One lane-local SQLite index; class semantics remain with specialist agents."""

    def __init__(self, program: str, *, family: str, lane: str, root_override: str | Path | None = None) -> None:
        layout = resolve_storage(program, family=family, lane=lane, root_override=root_override, create=False)
        self.path = layout.ledgers_root / "surface_coverage.sqlite"

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
                status TEXT NOT NULL DEFAULT 'untested', pressure TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '', boundary TEXT NOT NULL DEFAULT '',
                axes_json TEXT NOT NULL DEFAULT '[]', evidence_json TEXT NOT NULL DEFAULT '[]',
                reopen_when TEXT NOT NULL DEFAULT '', assessed_fingerprint TEXT NOT NULL DEFAULT '',
                agent TEXT NOT NULL DEFAULT '', assessment_run_id TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL, PRIMARY KEY(surface_id, class_name)
            );
            CREATE INDEX IF NOT EXISTS coverage_by_class ON assessments(class_name, status);
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
        """)
        return db

    def discover(self, *, kind: str, host: str, surface_key: str, source_ref: str, run_id: str,
                 class_name: str | None = None, input_key: str = "", consumer: str = "",
                 fingerprint: str = "") -> str:
        identity = {
            "kind": _plain(kind, "kind", required=True),
            "host": _plain(host, "host", required=True).lower(),
            "surface_key": _plain(surface_key, "surface_key", required=True),
            "input_key": _plain(input_key, "input_key"),
            "consumer": _plain(consumer, "consumer"),
        }
        source_ref = _plain(source_ref, "source_ref", required=True)
        run_id = _plain(run_id, "run_id", required=True)
        fingerprint = _plain(fingerprint, "fingerprint")
        class_name = _plain(class_name or "", "class_name").lower()
        surface_id = "S-" + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24]
        timestamp = _now()
        with self._connect() as db:
            db.execute("""INSERT INTO surfaces(id,kind,host,surface_key,input_key,consumer,source_ref,run_id,fingerprint,first_seen,last_seen)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                          source_ref=excluded.source_ref,run_id=excluded.run_id,
                          fingerprint=CASE WHEN excluded.fingerprint != '' THEN excluded.fingerprint ELSE surfaces.fingerprint END,
                          last_seen=excluded.last_seen""",
                       (surface_id, *identity.values(), source_ref, run_id, fingerprint, timestamp, timestamp))
            if class_name:
                db.execute("""INSERT OR IGNORE INTO assessments(surface_id,class_name,updated_at)
                              VALUES(?,?,?)""", (surface_id, class_name, timestamp))
        return surface_id

    def assess(self, surface_id: str, *, class_name: str, status: str, evidence_refs: list[str],
               reason: str, pressure: str = "", boundary: str = "", axes: list[str] | None = None,
               reopen_when: str = "", agent: str = "", run_id: str = "") -> dict[str, Any]:
        surface_id = _plain(surface_id, "surface_id", required=True)
        class_name = _plain(class_name, "class_name", required=True).lower()
        if status not in STATES - {"untested"}:
            raise ValueError("status must be in_progress, blocked, or exhausted")
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
        if status == "exhausted" and (not boundary or not axes):
            raise ValueError("exhausted assessment requires boundary and axes")
        if not self.path.exists():
            raise ValueError("surface not discovered")
        with self._connect() as db:
            row = db.execute("SELECT fingerprint FROM surfaces WHERE id=?", (surface_id,)).fetchone()
            assessment = db.execute("SELECT 1 FROM assessments WHERE surface_id=? AND class_name=?",
                                    (surface_id, class_name)).fetchone()
            if row is None or assessment is None:
                raise ValueError("surface/class question not discovered")
            db.execute("""UPDATE assessments SET status=?,pressure=?,reason=?,boundary=?,axes_json=?,
                          evidence_json=?,reopen_when=?,assessed_fingerprint=?,agent=?,assessment_run_id=?,updated_at=?
                          WHERE surface_id=? AND class_name=?""",
                       (status, pressure, reason, boundary, json.dumps(axes), json.dumps(refs), reopen_when,
                        row["fingerprint"], agent, run_id, _now(), surface_id, class_name))
            db.execute("""INSERT INTO assessment_history(surface_id,class_name,status,pressure,reason,boundary,
                          axes_json,evidence_json,reopen_when,fingerprint,agent,run_id,recorded_at)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (surface_id, class_name, status, pressure, reason, boundary, json.dumps(axes),
                        json.dumps(refs), reopen_when, row["fingerprint"], agent, run_id, _now()))
        return {"surface_id": surface_id, "class_name": class_name, "status": status}

    def history(self, surface_id: str, *, class_name: str, limit: int = 50) -> list[dict[str, Any]]:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        if not self.path.exists():
            return []
        with self._connect() as db:
            rows = db.execute("""SELECT * FROM assessment_history WHERE surface_id=? AND class_name=?
                              ORDER BY event_id DESC LIMIT ?""",
                              (_plain(surface_id, "surface_id", required=True),
                               _plain(class_name, "class_name", required=True).lower(), limit)).fetchall()
        return [{**dict(row), "axes": json.loads(row["axes_json"]),
                 "evidence_refs": json.loads(row["evidence_json"])} for row in reversed(rows)]

    def brief(self, *, class_name: str | None = None, host: str | None = None, limit: int = 50) -> dict[str, Any]:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        if not self.path.exists():
            return {"counts": {}, "items": [], "total": 0, "unclassified_surfaces": 0,
                    "mapped_kinds": {}, "coverage_path": str(self.path)}
        filters = []
        values = []
        if class_name:
            filters.append("a.class_name=?")
            values.append(_plain(class_name, "class_name").lower())
        if host:
            filters.append("s.host=?")
            values.append(_plain(host, "host").lower())
        where = " WHERE " + " AND ".join(filters) if filters else ""
        with self._connect() as db:
            rows = db.execute("""SELECT s.*,a.class_name,a.status,a.pressure,a.reason,a.boundary,
                              a.axes_json,a.evidence_json,a.reopen_when,a.assessed_fingerprint,a.agent,
                              a.assessment_run_id,a.updated_at
                              FROM assessments a JOIN surfaces s ON s.id=a.surface_id""" + where, values).fetchall()
            host_filter = " WHERE s.host=?" if host else ""
            host_values = [_plain(host, "host").lower()] if host else []
            kinds = db.execute("SELECT s.kind, COUNT(*) AS n FROM surfaces s" + host_filter +
                               " GROUP BY s.kind", host_values).fetchall()
            unclassified = db.execute("""SELECT COUNT(*) FROM surfaces s WHERE NOT EXISTS
                                      (SELECT 1 FROM assessments a WHERE a.surface_id=s.id)""" +
                                      (" AND s.host=?" if host else ""), host_values).fetchone()[0]
        counts: dict[str, int] = {}
        items = []
        for row in rows:
            item = dict(row)
            prior = item["status"]
            if prior != "untested" and item["fingerprint"] and item["assessed_fingerprint"] != item["fingerprint"]:
                item["status"] = "stale"
                item["prior_status"] = prior
            status = item["status"]
            counts[status] = counts.get(status, 0) + 1
            item["surface_id"] = item.pop("id")
            item["axes"] = json.loads(item.pop("axes_json"))
            item["evidence_refs"] = json.loads(item.pop("evidence_json"))
            items.append(item)
        items.sort(key=lambda item: (ORDER[item["status"]], item["host"], item["surface_key"], item["input_key"], item["class_name"]))
        return {"counts": counts, "items": items[:limit], "total": len(items),
                "unclassified_surfaces": unclassified,
                "mapped_kinds": {row["kind"]: row["n"] for row in kinds},
                "coverage_path": str(self.path)}
