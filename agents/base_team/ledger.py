"""Shared ledger loading and saving helpers for BaseTeam-backed teams."""

from __future__ import annotations

import fcntl
import json
import tempfile
from pathlib import Path
from typing import Any, Callable

from agents.ledger import create_team_ledger_from_storage, update_team_finding

from .findings import safe_int

TimestampFn = Callable[[], str]
NormalizeFindingFn = Callable[[Any], dict[str, Any] | None]
EnsureParentFn = Callable[[Path], None]
ReadLedgerFn = Callable[[], dict[str, Any]]
NormalizeLedgerFn = Callable[[dict[str, Any]], dict[str, Any]]
MergeLedgerFn = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
DefaultLedgerFn = Callable[[], dict[str, Any]]


def load_ledger(
    ledger_lock_path: Path,
    *,
    ensure_parent: EnsureParentFn,
    read_ledger_unchecked: ReadLedgerFn,
    set_last_loaded: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    """Load the team ledger or return an empty v2-compatible structure."""
    ensure_parent(ledger_lock_path)
    ledger_lock_path.touch(exist_ok=True)
    with ledger_lock_path.open("a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            payload = read_ledger_unchecked()
            set_last_loaded(payload)
            return payload
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def save_ledger(
    ledger: dict[str, Any],
    *,
    ledger_path: Path,
    ledger_lock_path: Path,
    ensure_parent: EnsureParentFn,
    read_ledger_unchecked: ReadLedgerFn,
    normalize_ledger_payload: NormalizeLedgerFn,
    merge_ledger: MergeLedgerFn,
    set_last_loaded: Callable[[dict[str, Any]], None],
) -> None:
    """Persist the ledger atomically under an exclusive lock."""
    payload = normalize_ledger_payload(ledger)
    ensure_parent(ledger_path)
    ensure_parent(ledger_lock_path)
    ledger_lock_path.touch(exist_ok=True)

    with ledger_lock_path.open("a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            current = read_ledger_unchecked()
            merged = merge_ledger(current, payload)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=ledger_path.parent,
                prefix=f".{ledger_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                json.dump(merged, handle, indent=2, sort_keys=False)
                handle.write("\n")
                temp_path = Path(handle.name)
            temp_path.replace(ledger_path)
            set_last_loaded(merged)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def reserve_findings(
    raw_findings: list[dict[str, Any]],
    *,
    program: str,
    storage: Any,
    target_path: Path,
    snapshot_identity: dict[str, Any],
    run_id: str,
    agent: str,
    normalize_finding: NormalizeFindingFn,
    timestamp_iso: TimestampFn,
    team_type: str,
) -> list[dict[str, Any]]:
    """Deduplicate raw candidates by reserving new identities in the canonical ledger."""
    ledger = create_team_ledger_from_storage(
        program,
        storage=storage,
        target_root=target_path,
        snapshot_identity=snapshot_identity,
        run_id=run_id,
        agent=agent,
    )
    reserved_findings: list[dict[str, Any]] = []
    now = timestamp_iso()

    for raw in raw_findings:
        finding = normalize_finding(raw)
        if finding is None:
            continue
        finding.setdefault("team_type", team_type)
        finding.setdefault("seen_at", now)

        is_duplicate, fid, reserved = ledger.check(finding)
        if is_duplicate:
            continue

        promoted = dict(finding)
        promoted.update({key: value for key, value in reserved.items() if value not in (None, "")})
        if fid:
            promoted["fid"] = fid
        promoted.setdefault("team_type", team_type)
        reserved_findings.append(promoted)

    return reserved_findings


def update_reviewed_findings(
    reviewed_findings: list[dict[str, Any]],
    *,
    program: str,
    storage: Any,
    target_path: Path,
    snapshot_identity: dict[str, Any],
    run_id: str,
    agent: str,
    team_type: str,
) -> list[dict[str, Any]]:
    """Persist reviewer results through the canonical ledger API."""
    updated: list[dict[str, Any]] = []
    for finding in reviewed_findings:
        payload = dict(finding)
        payload.setdefault("team_type", team_type)
        review_tier = str(payload.get("review_tier") or payload.get("tier") or "").strip().upper()
        if not str(payload.get("status") or "").strip():
            if review_tier == "CONFIRMED":
                payload["status"] = "confirmed"
            elif review_tier.startswith("DORMANT"):
                payload["status"] = "dormant"
            elif review_tier == "NOVEL" or str(payload.get("category") or "").strip().lower() == "novel":
                payload["status"] = "novel"
        updated.append(
            update_team_finding(
                program,
                payload,
                snapshot_id=str(snapshot_identity.get("snapshot_id") or ""),
                version_label=str(snapshot_identity.get("version_label") or ""),
                run_id=run_id,
                agent=agent,
                family=storage.family,
                lane=storage.lane,
                root_override=getattr(storage, "base_root", None) if getattr(storage, "root_mode", "") == "explicit-local" else None,
                write_report=True,
                refresh=True,
                update_current=True,
                update_sighting=True,
            )
        )
    return updated


def update_coverage_state(
    *,
    ledger_path: Path,
    ledger_lock_path: Path,
    ensure_parent: EnsureParentFn,
    read_default_ledger: DefaultLedgerFn,
    timestamp_iso: TimestampFn,
    agent_name: str,
    surface: str,
    finding_count: int,
    set_last_loaded: Callable[[dict[str, Any]], None],
) -> None:
    """Update BaseTeam coverage metadata while preserving canonical finding state."""
    ensure_parent(ledger_path)
    ensure_parent(ledger_lock_path)
    ledger_lock_path.touch(exist_ok=True)

    with ledger_lock_path.open("a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            payload = read_default_ledger()
            if ledger_path.exists():
                try:
                    loaded = json.loads(ledger_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    loaded = None
                if isinstance(loaded, dict):
                    payload = loaded

            coverage = payload.setdefault("coverage", {})
            if not isinstance(coverage, dict):
                coverage = {}
                payload["coverage"] = coverage

            agents_run = coverage.setdefault("agents_run", {})
            if not isinstance(agents_run, dict):
                agents_run = {}
                coverage["agents_run"] = agents_run
            agents_run[str(agent_name)] = timestamp_iso()

            surfaces_tested = coverage.setdefault("surfaces_tested", [])
            if not isinstance(surfaces_tested, list):
                surfaces_tested = []
                coverage["surfaces_tested"] = surfaces_tested
            normalized_surface = str(surface or "").strip()
            if normalized_surface and normalized_surface not in surfaces_tested:
                surfaces_tested.append(normalized_surface)
            coverage["surfaces_tested"] = sorted(str(item).strip() for item in surfaces_tested if str(item).strip())

            findings = payload.get("findings")
            finding_total = len(findings) if isinstance(findings, list) else 0
            coverage["total_findings"] = max(
                safe_int(coverage.get("total_findings")),
                finding_total,
                max(0, int(finding_count)),
            )
            payload["updated_at"] = timestamp_iso()

            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=ledger_path.parent,
                prefix=f".{ledger_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                json.dump(payload, handle, indent=2, sort_keys=False)
                handle.write("\n")
                temp_path = Path(handle.name)
            temp_path.replace(ledger_path)
            set_last_loaded(payload)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
