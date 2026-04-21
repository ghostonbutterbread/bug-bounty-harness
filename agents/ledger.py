"""Shared connected-team ledger helpers.

This module is the canonical entrypoint for connected team modules that need to
read/write the shared version-aware ledger while preserving the existing
0day-team ledger shape and behavior.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agents.ledger_v2 import VersionedFindingsLedger, ledger_add, ledger_check, ledger_get, ledger_list, ledger_path
from agents.storage_resolver import StorageLayout


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
    )


def team_ledger_path(*, storage: StorageLayout, program: str | None = None) -> Path:
    """Return the canonical ledger path for an already resolved storage context."""
    if program is None:
        return storage.ledgers_root / "ledger.json"
    return ledger_path(program, lane=storage.lane, family=storage.family)


__all__ = [
    "VersionedFindingsLedger",
    "create_team_ledger",
    "create_team_ledger_from_storage",
    "team_ledger_path",
    "ledger_add",
    "ledger_check",
    "ledger_get",
    "ledger_list",
    "ledger_path",
]
