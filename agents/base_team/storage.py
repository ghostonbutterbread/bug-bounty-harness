"""Shared storage helpers for BaseTeam-backed hunting teams."""

from __future__ import annotations

from pathlib import Path

from agents.storage_resolver import (
    TargetIdentity,
    resolve_family_lane,
    resolve_storage,
    resolve_target_identity,
    write_context_files,
)


def _normalize_output_root(output_root: str | Path | None) -> Path | None:
    if output_root is None:
        return None
    output_text = str(output_root).strip()
    if not output_text:
        return None
    return Path(output_text).expanduser().resolve(strict=False)


def _canonical_output_root_override(
    program: str,
    *,
    output_root: str | Path | None,
    team_type: str,
) -> Path | None:
    normalized = _normalize_output_root(output_root)
    if normalized is None:
        return None

    identity = resolve_target_identity(
        program=program,
        output_root=normalized,
        wrapper_hint=team_type,
        hunt_type=team_type,
    )
    if identity.evidence and identity.evidence[0].source == "canonical_path":
        return identity.storage_root
    return normalized


def resolve_team_storage(
    program: str,
    *,
    team_type: str,
    output_root: str | Path | None = None,
    family: str | None = None,
    lane: str | None = None,
    target_kind: str | None = None,
    intent_text: str | None = None,
    target_path: str | Path | None = None,
    target_identity: TargetIdentity | None = None,
):
    has_identity_context = any(
        value is not None
        for value in (family, lane, target_kind, intent_text, target_path, target_identity)
    )
    if has_identity_context:
        override_root = _canonical_output_root_override(
            program,
            output_root=output_root,
            team_type=team_type,
        )
    else:
        override_root = _normalize_output_root(output_root)

    if has_identity_context:
        identity = target_identity or resolve_target_identity(
            program=program,
            family=family,
            lane=lane,
            target_kind=target_kind,
            intent_text=intent_text,
            target_path=target_path,
            wrapper_hint=team_type,
            hunt_type=team_type,
        )
        resolved_family, resolved_lane = identity.family, identity.lane
        if override_root is None:
            override_root = identity.storage_root
    else:
        resolved_family, resolved_lane = resolve_family_lane(hunt_type=team_type)

    storage = resolve_storage(
        program,
        family=resolved_family,
        lane=resolved_lane,
        root_override=override_root,
        create=True,
    )
    write_context_files(storage)
    return storage
