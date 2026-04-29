"""Compatibility facade over :mod:`bounty_core.storage`."""

from __future__ import annotations

import json
from pathlib import Path

from agents.bounty_core_bootstrap import ensure_bounty_core_importable

ensure_bounty_core_importable()

from bounty_core.storage import (  # noqa: E402
    BINARIES_FAMILY,
    DEFAULT_LANES,
    NOTE_BUCKETS,
    REPORT_STATES,
    VALID_FAMILIES,
    WEB_FAMILY,
    StorageLayout,
    build_me_context,
    ensure_layout,
    infer_family_from_lane,
    normalize_family,
    normalize_lane,
    normalize_program,
    resolve_family_lane,
    resolve_storage,
)


def write_context_files(
    layout: StorageLayout,
    *,
    handoff_text: str | None = None,
    overwrite_handoff: bool = False,
) -> dict[str, Path]:
    """Preserve the harness helper while using bounty-core layout creation."""
    ensure_layout(layout)

    profile_path = layout.context_root / "target_profile.json"
    me_context_path = layout.context_root / "me_context.md"
    handoff_path = layout.context_root / "session_handoff.md"

    profile_path.write_text(json.dumps(layout.to_dict(), indent=2) + "\n", encoding="utf-8")
    me_context_path.write_text(build_me_context(layout), encoding="utf-8")

    if handoff_text:
        handoff_path.write_text(handoff_text.rstrip() + "\n", encoding="utf-8")
    elif overwrite_handoff or not handoff_path.exists():
        handoff_path.write_text(
            f"# Session Handoff\n\n"
            f"Program: {layout.program}\n"
            f"Family: {layout.family}\n"
            f"Lane: {layout.lane}\n\n"
            f"Canonical root: {layout.lane_root}\n",
            encoding="utf-8",
        )

    return {
        "target_profile": profile_path,
        "me_context": me_context_path,
        "session_handoff": handoff_path,
    }


__all__ = [
    "BINARIES_FAMILY",
    "DEFAULT_LANES",
    "NOTE_BUCKETS",
    "REPORT_STATES",
    "StorageLayout",
    "VALID_FAMILIES",
    "WEB_FAMILY",
    "build_me_context",
    "ensure_layout",
    "infer_family_from_lane",
    "normalize_family",
    "normalize_lane",
    "normalize_program",
    "resolve_family_lane",
    "resolve_storage",
    "write_context_files",
]
