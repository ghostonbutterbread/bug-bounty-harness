from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from agents.hunt_pipeline.appmap_loader import load_appmap_run

MAP_CACHE_SCHEMA_VERSION = 1
DEFAULT_STALE_AFTER_DAYS = 14
MAP_CACHE_FILENAME = "map_cache.json"
MAP_DIFF_FILENAME = "map_diff.json"


@dataclass(frozen=True, slots=True)
class MapReuseDecision:
    action: str
    reason: str
    prior_map_path: str | None
    current_map_path: str | None
    app_version_changed: bool
    stale: bool
    forced: bool
    diff_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AppMapResolution:
    appmap_root: Path
    source_mode: str
    decision: MapReuseDecision
    metadata: dict[str, Any]
    previous_appmap_root: Path | None = None
    previous_metadata: dict[str, Any] | None = None


def resolve_appmap_run(
    *,
    appmap_run: str | Path | None,
    program: str,
    target_path: str | Path,
    target_kind: str | None,
    output_root: str | Path,
    run_id: str,
    cache_search_root: str | Path | None = None,
    force_remap: bool = False,
    stale_after_days: int = DEFAULT_STALE_AFTER_DAYS,
) -> AppMapResolution:
    target = Path(target_path).expanduser().resolve(strict=False)
    if appmap_run is not None:
        appmap_root = Path(appmap_run).expanduser().resolve(strict=False)
        metadata = ensure_map_cache_metadata(appmap_root, target_path=target, stale_after_days=stale_after_days)
        return AppMapResolution(
            appmap_root=appmap_root,
            source_mode="loaded-existing",
            decision=MapReuseDecision(
                action="reuse",
                reason="explicit appmap run supplied",
                prior_map_path=str(appmap_root),
                current_map_path=str(appmap_root),
                app_version_changed=False,
                stale=False,
                forced=False,
            ),
            metadata=metadata,
        )

    search_root = _resolve_cache_search_root(cache_search_root, output_root)
    prior = find_latest_prior_map(search_root, target_path=target, exclude_output_root=Path(output_root))
    if prior and not force_remap:
        metadata = prior["metadata"]
        stale = _is_stale(metadata, default_days=stale_after_days)
        current_fingerprint = fingerprint_target(target)
        previous_fingerprint = str(metadata.get("source_fingerprint") or "").strip()
        app_version_changed = bool(current_fingerprint and previous_fingerprint and current_fingerprint != previous_fingerprint)
        if not stale and not app_version_changed:
            return AppMapResolution(
                appmap_root=prior["appmap_root"],
                source_mode="reused-cache",
                decision=MapReuseDecision(
                    action="reuse",
                    reason="reused prior fresh map",
                    prior_map_path=str(prior["appmap_root"]),
                    current_map_path=str(prior["appmap_root"]),
                    app_version_changed=False,
                    stale=False,
                    forced=False,
                ),
                metadata=metadata,
                previous_appmap_root=prior["appmap_root"],
                previous_metadata=metadata,
            )
        reason = "stale map" if stale else "target fingerprint changed"
    else:
        stale = False
        app_version_changed = False
        reason = "forced remap" if force_remap else "no prior reusable map"

    appmap_root = Path(output_root).expanduser().resolve(strict=False) / "appmap" / run_id
    return AppMapResolution(
        appmap_root=appmap_root,
        source_mode="generated-neutral",
        decision=MapReuseDecision(
            action="remap",
            reason=reason,
            prior_map_path=str(prior["appmap_root"]) if prior else None,
            current_map_path=str(appmap_root),
            app_version_changed=app_version_changed,
            stale=stale,
            forced=bool(force_remap),
        ),
        metadata=build_map_cache_metadata(
            appmap_root,
            target_path=target,
            target_kind=target_kind,
            program=program,
            stale_after_days=stale_after_days,
            mapped_at=_timestamp_iso(),
        ),
        previous_appmap_root=prior["appmap_root"] if prior else None,
        previous_metadata=prior["metadata"] if prior else None,
    )


def ensure_map_cache_metadata(
    appmap_root: str | Path,
    *,
    target_path: str | Path | None = None,
    stale_after_days: int = DEFAULT_STALE_AFTER_DAYS,
) -> dict[str, Any]:
    root = Path(appmap_root).expanduser().resolve(strict=False)
    sidecar = root / MAP_CACHE_FILENAME
    if sidecar.exists():
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return payload
    manifest = _read_json(root / "manifest.json")
    profile = _read_json(root / "target_profile.json")
    resolved_target = Path(target_path or profile.get("target_path") or manifest.get("target_path") or root).expanduser().resolve(strict=False)
    metadata = build_map_cache_metadata(
        root,
        target_path=resolved_target,
        target_kind=str(profile.get("target_kind") or manifest.get("target_kind") or "").strip() or None,
        program=str(profile.get("program") or manifest.get("program") or "").strip(),
        stale_after_days=stale_after_days,
        mapped_at=str(manifest.get("created_at") or _timestamp_iso()),
        manifest=manifest,
    )
    write_map_cache_metadata(root, metadata)
    return metadata


def build_map_cache_metadata(
    appmap_root: str | Path,
    *,
    target_path: str | Path,
    target_kind: str | None,
    program: str,
    stale_after_days: int,
    mapped_at: str,
    manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    root = Path(appmap_root).expanduser().resolve(strict=False)
    resolved_target = Path(target_path).expanduser().resolve(strict=False)
    source_fingerprint = fingerprint_target(resolved_target)
    manifest_payload = dict(manifest or _read_json(root / "manifest.json"))
    artifacts = manifest_payload.get("artifacts") if isinstance(manifest_payload.get("artifacts"), Mapping) else {}
    return {
        "schema_version": MAP_CACHE_SCHEMA_VERSION,
        "map_version": MAP_CACHE_SCHEMA_VERSION,
        "mapped_at": str(mapped_at or _timestamp_iso()),
        "program": str(program or manifest_payload.get("program") or "").strip(),
        "target_kind": str(target_kind or manifest_payload.get("target_kind") or "").strip(),
        "target_path": str(resolved_target),
        "app_version": str(manifest_payload.get("app_version") or "").strip(),
        "build_id": str(manifest_payload.get("build_id") or "").strip(),
        "source_fingerprint": source_fingerprint,
        "stale_after_days": max(1, int(stale_after_days)),
        "artifact_paths": {
            "manifest": str(root / "manifest.json"),
            "target_profile": str(root / "target_profile.json"),
            "surfaces": str(root / str(artifacts.get("surfaces") or "surfaces.jsonl")),
            "flows": str(root / str(artifacts.get("flows") or "flows.jsonl")),
        },
    }


def write_map_cache_metadata(appmap_root: str | Path, metadata: Mapping[str, Any]) -> Path:
    root = Path(appmap_root).expanduser().resolve(strict=False)
    root.mkdir(parents=True, exist_ok=True)
    path = root / MAP_CACHE_FILENAME
    path.write_text(json.dumps(dict(metadata), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_map_diff(
    *,
    previous_appmap_root: str | Path,
    current_appmap_root: str | Path,
    output_path: str | Path,
    previous_metadata: Mapping[str, Any] | None = None,
    current_metadata: Mapping[str, Any] | None = None,
) -> Path:
    previous = load_appmap_run(previous_appmap_root)
    current = load_appmap_run(current_appmap_root)
    previous_index = {_surface_identity(item): item for item in previous.surfaces}
    current_index = {_surface_identity(item): item for item in current.surfaces}

    new_keys = sorted(set(current_index) - set(previous_index))
    removed_keys = sorted(set(previous_index) - set(current_index))
    shared_keys = sorted(set(previous_index) & set(current_index))
    changed_keys = [key for key in shared_keys if _normalized_surface(previous_index[key]) != _normalized_surface(current_index[key])]

    payload = {
        "schema_version": MAP_CACHE_SCHEMA_VERSION,
        "target": str((current_metadata or {}).get("program") or (current.manifest.get("program") if isinstance(current.manifest, Mapping) else "") or ""),
        "previous_map": {
            "mapped_at": str((previous_metadata or {}).get("mapped_at") or ""),
            "app_version": str((previous_metadata or {}).get("app_version") or ""),
            "source_fingerprint": str((previous_metadata or {}).get("source_fingerprint") or ""),
            "appmap_root": str(Path(previous_appmap_root).expanduser().resolve(strict=False)),
        },
        "current_map": {
            "mapped_at": str((current_metadata or {}).get("mapped_at") or ""),
            "app_version": str((current_metadata or {}).get("app_version") or ""),
            "source_fingerprint": str((current_metadata or {}).get("source_fingerprint") or ""),
            "appmap_root": str(Path(current_appmap_root).expanduser().resolve(strict=False)),
        },
        "counts": {
            "new": len(new_keys),
            "changed": len(changed_keys),
            "removed": len(removed_keys),
            "unchanged": len(shared_keys) - len(changed_keys),
        },
        "new_surfaces": [current_index[key] for key in new_keys],
        "changed_surfaces": [
            {
                "identity": key,
                "previous": previous_index[key],
                "current": current_index[key],
            }
            for key in changed_keys
        ],
        "removed_surfaces": [previous_index[key] for key in removed_keys],
    }
    resolved_output = Path(output_path).expanduser().resolve(strict=False)
    resolved_output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return resolved_output


def find_latest_prior_map(
    search_root: str | Path,
    *,
    target_path: str | Path,
    exclude_output_root: str | Path | None = None,
) -> dict[str, Any] | None:
    root = Path(search_root).expanduser().resolve(strict=False)
    if not root.exists():
        return None
    target = str(Path(target_path).expanduser().resolve(strict=False))
    excluded = Path(exclude_output_root).expanduser().resolve(strict=False) if exclude_output_root else None
    candidates: list[dict[str, Any]] = []
    for plan_path in root.rglob("pipeline_plan.json"):
        output_root = plan_path.parent
        if excluded and output_root == excluded:
            continue
        try:
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(plan, dict):
            continue
        if str(Path(plan.get("target_path") or "").expanduser().resolve(strict=False)) != target:
            continue
        appmap_source = plan.get("appmap_source") if isinstance(plan.get("appmap_source"), Mapping) else {}
        run_root = appmap_source.get("run_root")
        if not run_root:
            continue
        appmap_root = Path(str(run_root)).expanduser().resolve(strict=False)
        if not appmap_root.exists():
            continue
        metadata = appmap_source.get("map_cache_metadata") if isinstance(appmap_source.get("map_cache_metadata"), Mapping) else None
        if metadata is None:
            metadata = ensure_map_cache_metadata(appmap_root, target_path=target)
        candidates.append(
            {
                "plan_path": plan_path,
                "output_root": output_root,
                "appmap_root": appmap_root,
                "metadata": dict(metadata),
                "sort_key": str(metadata.get("mapped_at") or ""),
            }
        )
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item["sort_key"], item["plan_path"].stat().st_mtime), reverse=True)
    return candidates[0]


def fingerprint_target(target_path: str | Path) -> str:
    target = Path(target_path).expanduser().resolve(strict=False)
    if not target.exists():
        return ""
    if target.is_file():
        stat = target.stat()
        return _sha256_json({"path": target.name, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns})
    git_head = _git_head(target)
    if git_head:
        return f"git:{git_head}"
    manifest_candidates = [
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "pyproject.toml",
        "requirements.txt",
        "Cargo.toml",
        "Cargo.lock",
    ]
    snapshot: list[dict[str, Any]] = []
    for relative in manifest_candidates:
        path = target / relative
        if not path.exists() or not path.is_file():
            continue
        stat = path.stat()
        snapshot.append({"path": relative, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns})
    if snapshot:
        return _sha256_json(snapshot)
    stat = target.stat()
    return _sha256_json({"path": str(target), "mtime_ns": stat.st_mtime_ns})


def _resolve_cache_search_root(cache_search_root: str | Path | None, output_root: str | Path) -> Path:
    if cache_search_root is not None:
        return Path(cache_search_root).expanduser().resolve(strict=False)
    return Path(output_root).expanduser().resolve(strict=False).parent


def _is_stale(metadata: Mapping[str, Any], *, default_days: int) -> bool:
    mapped_at = str(metadata.get("mapped_at") or "").strip()
    if not mapped_at:
        return True
    try:
        mapped = _parse_iso8601(mapped_at)
    except ValueError:
        return True
    stale_after_days = int(metadata.get("stale_after_days") or default_days)
    age_seconds = (datetime.now(UTC) - mapped).total_seconds()
    return age_seconds > max(1, stale_after_days) * 86400


def _surface_identity(surface: Mapping[str, Any]) -> str:
    return "|".join(
        [
            str(surface.get("kind") or ""),
            str(surface.get("file") or ""),
            str(surface.get("line") or ""),
            str(surface.get("name") or surface.get("channel") or surface.get("route") or surface.get("sink") or ""),
        ]
    )


def _normalized_surface(surface: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(surface)
    payload.pop("id", None)
    return payload


def _git_head(target: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""
    return result.stdout.strip()


def _sha256_json(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _parse_iso8601(value: str) -> datetime:
    cleaned = str(value or "").strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    return datetime.fromisoformat(cleaned).astimezone(UTC)


def _timestamp_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}
