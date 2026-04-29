"""Shared source-root precedence helpers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path

from agents.shared_brain import RepoIndex, load_index
from agents.storage_resolver import resolve_family_lane


PathLike = str | Path
FallbackFactory = Callable[[], PathLike | None]


def normalize_source_root(value: PathLike | None) -> Path | None:
    if value is None:
        return None
    return Path(value).expanduser().resolve(strict=False)


def shared_brain_target_root(
    program: str,
    *,
    hunt_type: str = "source",
    family: str | None = None,
    lane: str | None = None,
    root_override: PathLike | None = None,
    index: RepoIndex | None = None,
) -> Path | None:
    """Return the shared-brain target root for the resolved family/lane."""
    shared_brain = index
    if shared_brain is None:
        resolved_family, resolved_lane = resolve_family_lane(
            family=family,
            lane=lane,
            hunt_type=hunt_type,
        )
        shared_brain = load_index(
            program,
            family=resolved_family,
            lane=resolved_lane,
            root_override=root_override,
        )
    if shared_brain is None or not shared_brain.target_root:
        return None
    return normalize_source_root(shared_brain.target_root)


def resolve_source_root(
    program: str,
    *,
    explicit: PathLike | None = None,
    hunt_type: str = "source",
    family: str | None = None,
    lane: str | None = None,
    root_override: PathLike | None = None,
    shared_brain: RepoIndex | None = None,
    fallback: PathLike | FallbackFactory | None = None,
) -> Path | None:
    """Resolve source root as explicit override, shared-brain target, fallback."""
    explicit_root = normalize_source_root(explicit)
    if explicit_root is not None:
        return explicit_root

    target_root = shared_brain_target_root(
        program,
        hunt_type=hunt_type,
        family=family,
        lane=lane,
        root_override=root_override,
        index=shared_brain,
    )
    if target_root is not None:
        return target_root

    fallback_value = fallback() if callable(fallback) else fallback
    return normalize_source_root(fallback_value)


def source_root_candidates(
    program: str,
    *,
    explicit: PathLike | None = None,
    hunt_type: str = "source",
    family: str | None = None,
    lane: str | None = None,
    root_override: PathLike | None = None,
    shared_brain: RepoIndex | None = None,
    fallback_candidates: Iterable[PathLike | None] = (),
) -> list[Path]:
    """Return deduped candidates ordered by the shared source-root precedence."""
    candidates: list[Path | None] = [
        normalize_source_root(explicit),
        shared_brain_target_root(
            program,
            hunt_type=hunt_type,
            family=family,
            lane=lane,
            root_override=root_override,
            index=shared_brain,
        ),
    ]
    candidates.extend(normalize_source_root(candidate) for candidate in fallback_candidates)

    seen: set[str] = set()
    deduped: list[Path] = []
    for candidate in candidates:
        if candidate is None:
            continue
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped
