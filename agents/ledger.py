"""Shared connected-team ledger helpers.

This module is the canonical entrypoint for connected team modules that need to
read/write the shared version-aware ledger while preserving the existing
0day-team ledger shape and behavior.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agents.bounty_core_bootstrap import ensure_bounty_core_importable
from agents.storage_resolver import StorageLayout

ensure_bounty_core_importable()

from bounty_core.ledger import (  # noqa: E402
    VersionedFindingsLedger,
    ledger_add,
    ledger_check,
    ledger_get,
    ledger_list,
    ledger_path,
    patch_finding_by_fid,
)


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
    return VersionedFindingsLedger(
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
    )
    if patched is not None:
        return patched

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
    "VersionedFindingsLedger",
    "create_team_ledger",
    "create_team_ledger_from_storage",
    "read_team_findings",
    "team_ledger_path",
    "update_team_finding",
    "ledger_add",
    "ledger_check",
    "ledger_get",
    "ledger_list",
    "ledger_path",
    "patch_finding_by_fid",
]
