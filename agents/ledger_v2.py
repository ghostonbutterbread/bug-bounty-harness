"""Compatibility shim for the Ledger V2 implementation in bounty_core.ledger."""

from __future__ import annotations

from agents.bounty_core_bootstrap import ensure_bounty_core_importable

ensure_bounty_core_importable()

from bounty_core.ledger import (  # noqa: E402
    LEDGER_VERSION,
    DEFAULT_REVIEW_TIER,
    DEFAULT_STATUS,
    VersionedFindingsLedger,
    get_snapshot_identity,
    ledger_add,
    ledger_check,
    ledger_get,
    ledger_list,
    ledger_path,
    ledger_sightings,
    migrate_ledger_payload,
    migrate_legacy_finding,
)

__all__ = [
    "LEDGER_VERSION",
    "DEFAULT_REVIEW_TIER",
    "DEFAULT_STATUS",
    "VersionedFindingsLedger",
    "get_snapshot_identity",
    "ledger_add",
    "ledger_check",
    "ledger_get",
    "ledger_list",
    "ledger_path",
    "ledger_sightings",
    "migrate_ledger_payload",
    "migrate_legacy_finding",
]
