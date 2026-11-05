"""Resolve the shared bounty artifact root at invocation time."""

import os
from pathlib import Path


LEGACY_ARTIFACT_ROOT = Path("/mnt/bounty")


def resolve_artifact_root() -> Path:
    """Return the environment-selected root, or the legacy root if unset."""
    value = os.environ.get("BOUNTY_ARTIFACT_ROOT")
    if value is None:
        return LEGACY_ARTIFACT_ROOT
    if not value.strip():
        raise SystemExit("BOUNTY_ARTIFACT_ROOT is empty; unset it or specify an artifact root")
    return Path(value).expanduser()


def preflight_artifact_paths(*paths: Path) -> None:
    """Refuse writes beneath the legacy root unless it is a mount point.

    Check lexical and symlink-resolved paths, including paths not yet created.
    Call once on all write destinations before any filesystem or network work.
    """
    for path in paths:
        expanded = Path(path).expanduser()
        lexical = Path(os.path.abspath(expanded))
        actual = expanded.resolve()
        if any(p == LEGACY_ARTIFACT_ROOT or LEGACY_ARTIFACT_ROOT in p.parents
               for p in (lexical, actual)) and not os.path.ismount(LEGACY_ARTIFACT_ROOT):
            raise SystemExit(
                f"{LEGACY_ARTIFACT_ROOT} is not mounted; mount it or select a different artifact root (destination: {path})"
            )
