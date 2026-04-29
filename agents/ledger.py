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

from bounty_core.ledger import VersionedFindingsLedger, ledger_add, ledger_check, ledger_get, ledger_list, ledger_path  # noqa: E402


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
    "ledger_add",
    "ledger_check",
    "ledger_get",
    "ledger_list",
    "ledger_path",
]
