"""Shared storage helpers for BaseTeam-backed hunting teams."""

from __future__ import annotations

from pathlib import Path

from agents.storage_resolver import resolve_family_lane, resolve_storage, write_context_files


def resolve_team_storage(
    program: str,
    *,
    team_type: str,
    output_root: str | Path | None = None,
):
    family, lane = resolve_family_lane(hunt_type=team_type)
    override_root = None
    if output_root is not None:
        output_text = str(output_root).strip()
        if output_text:
            override_root = Path(output_text).expanduser().resolve(strict=False)
    storage = resolve_storage(
        program,
        family=family,
        lane=lane,
        root_override=override_root,
        create=True,
    )
    write_context_files(storage)
    return storage
