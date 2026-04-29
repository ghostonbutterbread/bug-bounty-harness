"""Shared ledger loading and saving helpers for BaseTeam-backed teams."""

from __future__ import annotations

import fcntl
import json
import tempfile
from pathlib import Path
from typing import Any, Callable

from agents.ledger import create_team_ledger_from_storage, update_team_coverage_state, update_team_finding

TimestampFn = Callable[[], str]
NormalizeFindingFn = Callable[[Any], dict[str, Any] | None]
EnsureParentFn = Callable[[Path], None]
ReadLedgerFn = Callable[[], dict[str, Any]]
NormalizeLedgerFn = Callable[[dict[str, Any]], dict[str, Any]]
MergeLedgerFn = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]


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
    """Compatibility-only whole-ledger save; active finding writes use canonical adapters."""
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
    program: str,
    storage: Any,
    agent_name: str,
    surface: str,
    finding_count: int,
    set_last_loaded: Callable[[dict[str, Any]], None],
) -> None:
    """Update BaseTeam coverage metadata through the canonical ledger adapter."""
    coverage = update_team_coverage_state(
        program,
        storage=storage,
        agent_name=agent_name,
        surface=surface,
        finding_count=finding_count,
    )
    set_last_loaded({"coverage": coverage})
