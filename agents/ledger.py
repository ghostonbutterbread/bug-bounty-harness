"""Shared connected-team ledger helpers.

This module is the canonical entrypoint for connected team modules that need to
read/write the shared version-aware ledger while preserving the existing
0day-team ledger shape and behavior.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from agents.storage_resolver import StorageLayout


from bounty_core.ledger import (  # noqa: E402
    VersionedFindingsLedger,
    ledger_add,
    ledger_check,
    ledger_get,
    ledger_list,
    ledger_path,
    patch_finding_by_fid,
    update_coverage_state as core_update_coverage_state,
)
from bounty_core.reports import EVIDENCE_ONLY

from agents.ledger_tombstones import (
    delete_finding_by_fid,
    skip_message,
    tombstone_guard,
    tombstone_guard_for_layout,
)


def _log_tombstone_skip(fid: str, source: str) -> None:
    print(f"[ledger] {skip_message(fid, source)}", file=sys.stderr)


class TombstoneAwareFindingsLedger(VersionedFindingsLedger):
    """Ledger wrapper that will not re-add a deleted (tombstoned) finding.

    Every BBH team, manual, and sync path gets its ledger object from
    ``create_team_ledger``; checking ``ledgers/deleted-findings.jsonl`` here
    covers sighting merges and report re-imports without touching Bounty Core.
    A tombstoned candidate is reported as a duplicate of its deleted FID with
    ``tombstoned=True`` so callers skip it instead of inserting it.
    """

    def _tombstone_match(self, candidate: dict[str, Any]) -> str | None:
        guard = tombstone_guard_for_layout(self.storage)
        return guard.match(candidate) if guard else None

    def _skipped(self, candidate: dict[str, Any], fid: str, source: str) -> tuple[bool, str, dict[str, Any]]:
        _log_tombstone_skip(fid, source)
        return True, fid, {**dict(candidate), "fid": fid, "tombstoned": True}

    def check(self, finding_dict: dict[str, Any]) -> tuple[bool, str | None, dict[str, Any]]:
        fid = self._tombstone_match(finding_dict)
        if fid:
            return self._skipped(finding_dict, fid, f"{self.agent} check")
        return super().check(finding_dict)

    def import_finding(self, candidate: dict[str, Any], *, packet_mode: str = EVIDENCE_ONLY) -> tuple[bool, str, dict[str, Any]]:
        fid = self._tombstone_match(candidate)
        if fid:
            return self._skipped(candidate, fid, f"{self.agent} import")
        return super().import_finding(candidate, packet_mode=packet_mode)

    def reserve_batch(self, candidates: list[dict[str, Any]]) -> list[tuple[bool, str | None, dict[str, Any]]]:
        if not isinstance(candidates, list):
            return super().reserve_batch(candidates)
        guard = tombstone_guard_for_layout(self.storage)
        matches = [guard.match(c) if guard and isinstance(c, dict) else None for c in candidates]
        allowed = [c for c, m in zip(candidates, matches) if not m]
        reserved = iter(super().reserve_batch(allowed) if allowed else [])
        return [self._skipped(c, m, f"{self.agent} batch") if m else next(reserved)
                for c, m in zip(candidates, matches)]

    def update(self, finding_with_fid: dict[str, Any]) -> dict[str, Any]:
        fid = self._tombstone_match(finding_with_fid)
        if fid:
            return self._skipped(finding_with_fid, fid, f"{self.agent} update")[2]
        return super().update(finding_with_fid)


def _explicit_root_from_storage(storage: StorageLayout) -> Path | None:
    if getattr(storage, "root_mode", "") != "explicit-local":
        return None
    return Path(storage.base_root).expanduser().resolve(strict=False)


def create_team_ledger(
    program: str,
    *,
    target_root: str | Path,
    version_label: str | None = None,
    snapshot_identity: dict[str, Any] | None = None,
    run_id: str | None = None,
    agent: str = "codex",
    lane: str,
    family: str,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> VersionedFindingsLedger:
    """Create the canonical connected-team ledger wrapper.

    Connected team modules should use this helper instead of instantiating
    VersionedFindingsLedger directly so future shared ledger logic stays
    centralized.
    """
    return TombstoneAwareFindingsLedger(
        program,
        target_root=target_root,
        version_label=version_label,
        snapshot_identity=snapshot_identity,
        run_id=run_id,
        agent=agent,
        lane=lane,
        family=family,
        root_override=root_override,
        storage_root=storage_root,
    )


def create_team_ledger_from_storage(
    program: str,
    *,
    storage: StorageLayout,
    target_root: str | Path,
    version_label: str | None = None,
    snapshot_identity: dict[str, Any] | None = None,
    run_id: str | None = None,
    agent: str = "codex",
) -> VersionedFindingsLedger:
    """Create a connected-team ledger directly from resolved storage context."""
    return create_team_ledger(
        program,
        target_root=target_root,
        version_label=version_label,
        snapshot_identity=snapshot_identity,
        run_id=run_id,
        agent=agent,
        lane=storage.lane,
        family=storage.family,
        root_override=_explicit_root_from_storage(storage),
    )



def read_team_findings(
    program: str,
    *,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
    snapshot_id: str | None = None,
    version_label: str | None = None,
) -> list[dict[str, Any]]:
    """Read canonical team findings through the harness ledger adapter.

    This is the read-only migration seam for callers that previously parsed
    `ledger.json` directly. It keeps path resolution, migration, and fixture
    normalization owned by `bounty_core.ledger`.
    """
    return ledger_list(
        program,
        snapshot_id=snapshot_id,
        version_label=version_label,
        family=family,
        lane=lane or "apk",
        root_override=root_override,
        storage_root=storage_root,
    )


def update_team_finding(
    program: str,
    finding: dict[str, Any],
    *,
    snapshot_id: str | None = None,
    version_label: str | None = None,
    run_id: str | None = None,
    agent: str = "codex",
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
    write_report: bool = False,
    refresh: bool = False,
    update_current: bool = False,
    update_sighting: bool = False,
) -> dict[str, Any]:
    """Update a team finding through the harness ledger adapter.

    FID-addressed validation updates patch the existing ledger entry in place
    so reviewer corrections cannot create a duplicate when file, line, class,
    or title changes. Snapshot and sighting metadata are intentionally left
    untouched. If the FID has not been reserved yet, fall back to the canonical
    v2 ledger reservation path, which writes only the ledger and does not
    refresh report indexes.
    """
    fid = str((finding or {}).get("fid") or "").strip()
    if not fid:
        raise ValueError("finding fid is required")

    resolved_lane = lane or "apk"
    patched = patch_finding_by_fid(
        program,
        fid,
        dict(finding),
        lane=resolved_lane,
        family=family,
        root_override=root_override,
        storage_root=storage_root,
        write_report=write_report,
        refresh=refresh,
        update_current=update_current,
        update_sighting=update_sighting,
        packet_mode=EVIDENCE_ONLY,
    )
    if patched is not None:
        return patched

    guard = tombstone_guard(program, family=family, lane=resolved_lane, root_override=root_override or storage_root)
    tombstoned = guard.match(finding) if guard else None
    if tombstoned:
        # The FID was deleted (patch found nothing); never let the ledger_add
        # fallback re-create it or its identity under a new FID.
        _log_tombstone_skip(tombstoned, f"{agent} update")
        return {**dict(finding), "fid": tombstoned, "tombstoned": True, "is_new": False}

    is_new, reserved_fid = ledger_add(
        program,
        dict(finding),
        str(snapshot_id or finding.get("snapshot_id") or finding.get("first_snapshot") or "report-checker"),
        str(version_label if version_label is not None else finding.get("version_label") or ""),
        str(run_id or finding.get("run_id") or "report-checker"),
        str(agent or finding.get("agent") or "codex"),
        lane=resolved_lane,
        family=family,
        root_override=root_override,
        storage_root=storage_root,
    )
    target_fid = str(reserved_fid or fid).strip()
    if write_report or refresh or update_current or update_sighting:
        patched = patch_finding_by_fid(
            program,
            target_fid,
            dict(finding),
            lane=resolved_lane,
            family=family,
            root_override=root_override,
            storage_root=storage_root,
            write_report=write_report,
            refresh=refresh,
            update_current=update_current,
            update_sighting=update_sighting,
            packet_mode=EVIDENCE_ONLY,
        )
        if patched is not None:
            return patched
    stored = ledger_get(
        program,
        target_fid,
        lane=resolved_lane,
        family=family,
        root_override=root_override,
        storage_root=storage_root,
    )
    if stored is None:
        result = dict(finding)
        result["fid"] = target_fid
        result["is_new"] = is_new
        return result
    return stored

def update_team_coverage_state(
    program: str,
    *,
    storage: StorageLayout,
    agent_name: str,
    surface: str,
    finding_count: int,
) -> dict[str, Any]:
    """Update team coverage metadata through the harness ledger adapter."""
    return core_update_coverage_state(
        program,
        agent_name=agent_name,
        surface=surface,
        finding_count=finding_count,
        lane=storage.lane,
        family=storage.family,
        root_override=_explicit_root_from_storage(storage),
    )


def team_ledger_path(*, storage: StorageLayout, program: str | None = None) -> Path:
    """Return the canonical ledger path for an already resolved storage context."""
    if program is None:
        return storage.ledgers_root / "ledger.json"
    return ledger_path(
        program,
        lane=storage.lane,
        family=storage.family,
        root_override=_explicit_root_from_storage(storage),
    )


__all__ = [
    "TombstoneAwareFindingsLedger",
    "VersionedFindingsLedger",
    "delete_finding_by_fid",
    "tombstone_guard",
    "create_team_ledger",
    "create_team_ledger_from_storage",
    "read_team_findings",
    "team_ledger_path",
    "update_team_coverage_state",
    "update_team_finding",
    "ledger_add",
    "ledger_check",
    "ledger_get",
    "ledger_list",
    "ledger_path",
    "patch_finding_by_fid",
]
