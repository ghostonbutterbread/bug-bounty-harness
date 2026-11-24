"""Target snapshot identity helpers for version-aware hunting."""

from __future__ import annotations

import hashlib
import json
import os
import platform as platform_lib
import subprocess
import sys
import tempfile
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


def _manifest_entries(target_root: Path) -> list[tuple[Path, str, os.stat_result]]:
    """Return the sorted regular files the manifest hash covers, with their stat."""
    entries: list[tuple[Path, str, os.stat_result]] = []
    for path in sorted(target_root.rglob("*")):
        if not path.is_file():
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        entries.append((path, path.relative_to(target_root).as_posix(), stat))
    return entries


def _manifest_hash(target_root: Path, entries: list[tuple[Path, str, os.stat_result]] | None = None) -> str:
    """Content hash of every file under ``target_root`` (the snapshot_id of a non-git root)."""
    digest = hashlib.sha256()
    for path, relpath, stat in entries if entries is not None else _manifest_entries(target_root):
        digest.update(f"{relpath}:{stat.st_size}\n".encode("utf-8"))
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            continue
    return digest.hexdigest()


MANIFEST_CACHE_SCHEMA = "bbh-snapshot-manifest-cache/1"


def default_manifest_cache_dir() -> Path:
    """Host-local cache home for manifest hashes (never inside a lane or source tree)."""
    base = str(os.environ.get("XDG_CACHE_HOME") or "").strip()
    return (Path(base) if base else Path.home() / ".cache") / "bbh" / "snapshot-manifest"


def _tree_fingerprint(entries: list[tuple[Path, str, os.stat_result]]) -> dict[str, Any]:
    """Cheap stat-only fingerprint: every relpath, size and mtime_ns, plus summary counts."""
    digest = hashlib.sha256()
    total_size = 0
    max_mtime_ns = 0
    for _path, relpath, stat in entries:
        digest.update(f"{relpath}\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode("utf-8", "surrogateescape"))
        total_size += stat.st_size
        max_mtime_ns = max(max_mtime_ns, stat.st_mtime_ns)
    return {
        "fingerprint": digest.hexdigest(),
        "file_count": len(entries),
        "total_size": total_size,
        "max_mtime_ns": max_mtime_ns,
    }


def _cache_file(cache_dir: Path, target_root: Path) -> Path:
    key = hashlib.sha256(str(target_root).encode("utf-8", "surrogateescape")).hexdigest()
    return cache_dir / f"{key}.json"


def _read_cached_manifest(cache_path: Path, target_root: Path, fingerprint: dict[str, Any]) -> str | None:
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("schema") != MANIFEST_CACHE_SCHEMA:
        return None
    if payload.get("root") != str(target_root):
        return None
    if any(payload.get(key) != value for key, value in fingerprint.items()):
        return None
    manifest_hash = payload.get("manifest_hash")
    if not isinstance(manifest_hash, str) or len(manifest_hash) != 64:
        return None
    return manifest_hash


def _write_cached_manifest(cache_path: Path, target_root: Path, fingerprint: dict[str, Any], manifest_hash: str) -> None:
    payload = {"schema": MANIFEST_CACHE_SCHEMA, "root": str(target_root), **fingerprint, "manifest_hash": manifest_hash}
    temp_path: Path | None = None
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=cache_path.parent,
                                         prefix=f".{cache_path.name}.", suffix=".tmp", delete=False) as handle:
            temp_path = Path(handle.name)
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
        temp_path.replace(cache_path)
        temp_path = None
    except OSError:
        pass  # The cache is an optimization; an unwritable cache only costs a recompute next time.
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def cached_manifest_hash(target_root: Path, cache_dir: Path) -> str:
    """Return ``_manifest_hash(target_root)``, reusing a cached value while the tree is unchanged.

    One stat-only walk builds a fingerprint of every (relpath, size, mtime_ns);
    file contents are read and hashed only when that fingerprint differs from
    the cached one. The returned value is identical to an uncached
    ``_manifest_hash``. A content edit that keeps the same size and mtime is not
    detected (the same trade-off ``make`` and ``rsync`` defaults make).
    """
    resolved_root = Path(target_root).expanduser().resolve(strict=False)
    entries = _manifest_entries(resolved_root)
    fingerprint = _tree_fingerprint(entries)
    cache_path = _cache_file(Path(cache_dir), resolved_root)
    cached = _read_cached_manifest(cache_path, resolved_root, fingerprint)
    if cached is not None:
        return cached
    manifest_hash = _manifest_hash(resolved_root, entries)
    _write_cached_manifest(cache_path, resolved_root, fingerprint, manifest_hash)
    return manifest_hash


def get_snapshot_identity(
    target_root: Path,
    version_label: str | None = None,
    *,
    manifest_cache_dir: Path | None = None,
) -> dict[str, Any]:
    """Return full structured identity dict.

    ``manifest_cache_dir`` opts into :func:`cached_manifest_hash` for non-git
    roots; the identity values are the same with or without it.
    """
    resolved_root = Path(target_root).expanduser().resolve(strict=False)
    normalized_version = _normalize_version_label(version_label)
    git_head = _git_head(resolved_root)
    if git_head:
        manifest_hash = None
    elif manifest_cache_dir is not None:
        manifest_hash = cached_manifest_hash(resolved_root, manifest_cache_dir)
    else:
        manifest_hash = _manifest_hash(resolved_root)
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
