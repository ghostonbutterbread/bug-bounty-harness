"""Target snapshot identity helpers for version-aware hunting."""

from __future__ import annotations

import hashlib
import os
import platform as platform_lib
import subprocess
import sys
from pathlib import Path
from typing import Any


_CHANNELS = {"stable", "beta", "dev"}


def _normalize_version_label(version_label: str | None) -> str:
    explicit = str(version_label or "").strip()
    if explicit:
        return explicit
    return str(os.environ.get("SNAPSHOT_VERSION") or "").strip()


def _normalize_build_id() -> str | None:
    value = str(os.environ.get("SNAPSHOT_BUILD_ID") or "").strip()
    return value or None


def _normalize_platform() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform.startswith("win"):
        return "win32"
    if sys.platform == "darwin":
        return "darwin"
    return sys.platform


def _normalize_arch() -> str:
    machine = platform_lib.machine().strip().lower()
    if machine in {"x86_64", "amd64", "x64"}:
        return "x64"
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    return machine or "unknown"


def _infer_channel(version_label: str) -> str:
    explicit = str(os.environ.get("SNAPSHOT_CHANNEL") or "").strip().lower()
    if explicit in _CHANNELS:
        return explicit

    lowered = version_label.lower()
    if any(token in lowered for token in ("beta", "b.")):
        return "beta"
    if any(token in lowered for token in ("dev", "alpha", "canary", "nightly", "preview")):
        return "dev"
    return "stable"


def _git_head(target_root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(target_root),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None

    if result.returncode != 0:
        return None

    head = result.stdout.strip()
    return head or None


def _manifest_hash(target_root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(target_root.rglob("*")):
        if not path.is_file():
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        relpath = path.relative_to(target_root).as_posix()
        digest.update(f"{relpath}:{stat.st_size}\n".encode("utf-8"))
    return digest.hexdigest()


def get_snapshot_identity(target_root: Path, version_label: str | None = None) -> dict[str, Any]:
    """Return full structured identity dict."""
    resolved_root = Path(target_root).expanduser().resolve(strict=False)
    normalized_version = _normalize_version_label(version_label)
    git_head = _git_head(resolved_root)
    manifest_hash = None if git_head else _manifest_hash(resolved_root)
    snapshot_id = git_head or manifest_hash or ""

    return {
        "version_label": normalized_version,
        "build_id": _normalize_build_id(),
        "git_head": git_head,
        "manifest_hash": manifest_hash,
        "platform": _normalize_platform(),
        "arch": _normalize_arch(),
        "channel": _infer_channel(normalized_version),
        "snapshot_id": snapshot_id,
    }


def get_snapshot_id(target_root: Path, version_label: str | None = None) -> str:
    """Return the canonical snapshot_id string."""
    return str(get_snapshot_identity(target_root, version_label=version_label).get("snapshot_id") or "")


def is_same_snapshot(target_root: Path, snapshot_id: str) -> bool:
    """Check if the current target matches the given snapshot_id."""
    return get_snapshot_id(target_root) == str(snapshot_id or "").strip()
