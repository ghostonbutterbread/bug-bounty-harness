from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def classify_target_kind(
    target_path: str | Path | None,
    *,
    requested_kind: str | None = "auto",
    appmap_profile: dict[str, Any] | None = None,
) -> str:
    requested = str(requested_kind or "auto").strip().lower()
    if requested and requested != "auto":
        return requested
    profile_kind = str((appmap_profile or {}).get("target_kind") or "").strip().lower()
    if profile_kind and profile_kind != "auto":
        return profile_kind
    if target_path and _has_electron_package(Path(target_path).expanduser()):
        return "electron"
    return "desktop"


def _has_electron_package(path: Path) -> bool:
    for candidate in (path / "package.json", path / "resources" / "app.asar" / "package.json"):
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if "electron" in json.dumps(payload, sort_keys=True).lower():
            return True
    return False
