"""Shared ledger loading, saving, and finding dedup helpers for BaseTeam-backed teams."""

from __future__ import annotations

import fcntl
import json
import tempfile
from pathlib import Path
from typing import Any, Callable

from .findings import safe_int

TimestampFn = Callable[[], str]
NormalizeFindingFn = Callable[[Any], dict[str, Any] | None]
FindingIdentityFn = Callable[[dict[str, Any]], tuple[str, int, str, str]]
SnapshotIdFn = Callable[[], str | None]
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


def deduplicate_findings(
    raw_findings: list[dict[str, Any]],
    ledger: dict[str, Any],
    *,
    normalize_finding: NormalizeFindingFn,
    finding_identity: FindingIdentityFn,
    timestamp_iso: TimestampFn,
    snapshot_id: SnapshotIdFn,
    team_type: str,
) -> list[dict[str, Any]]:
    """Return new findings while updating sighting counts on existing entries."""
    findings = ledger.setdefault("findings", [])
    seen: dict[tuple[str, int, str, str], dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        seen[finding_identity(finding)] = finding

    new_findings: list[dict[str, Any]] = []
    now = timestamp_iso()
    for raw in raw_findings:
        finding = normalize_finding(raw)
        if finding is None:
            continue
        identity = finding_identity(finding)
        existing = seen.get(identity)
        if existing is not None:
            existing["last_seen"] = now
            existing["sighting_count"] = safe_int(existing.get("sighting_count"), 1) + 1
            sightings = existing.get("sightings")
            if not isinstance(sightings, list):
                sightings = []
                existing["sightings"] = sightings
            sightings.append(
                {
                    "seen_at": now,
                    "agent": str(finding.get("agent") or ""),
                    "team_type": team_type,
                }
            )
            continue

        finding["first_seen"] = now
        finding["last_seen"] = now
        finding["sighting_count"] = 1
        finding["snapshot_id"] = snapshot_id()
        seen[identity] = finding
        new_findings.append(finding)

    coverage = ledger.setdefault("coverage", {})
    coverage["total_findings"] = max(
        safe_int(coverage.get("total_findings")),
        len(findings) + len(new_findings),
    )
    return new_findings
