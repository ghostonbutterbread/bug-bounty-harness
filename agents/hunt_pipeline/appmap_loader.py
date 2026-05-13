from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents.hunt_pipeline.models import NormalizedMapResult


def load_appmap_run(appmap_root: str | Path) -> NormalizedMapResult:
    root = Path(appmap_root).expanduser().resolve(strict=False)
    if not root.exists() or not root.is_dir():
        raise ValueError(f"AppMap run root must be an existing directory: {root}")

    manifest = _read_json(root / "manifest.json")
    target_profile = _read_json(root / "target_profile.json")
    surfaces = tuple(_read_jsonl(root / "surfaces.jsonl"))
    flows = tuple(_read_jsonl(root / "flows.jsonl"))
    candidates = tuple(_with_compat_context(row, "legacy_candidate") for row in _read_jsonl(root / "candidates.jsonl"))
    rejected = tuple(
        _with_compat_context(row, "legacy_rejected_candidate")
        for row in _read_jsonl(root / "rejected_candidates.jsonl")
    )
    legacy_policy_shaped = bool(candidates or rejected)
    legacy_policy_shaped = legacy_policy_shaped or any(key in manifest for key in ("hunting_policy", "hunting_policy_id"))

    source_files = [
        "manifest.json",
        "target_profile.json",
        "surfaces.jsonl",
        "flows.jsonl",
    ]
    if candidates:
        source_files.append("candidates.jsonl")
    if rejected:
        source_files.append("rejected_candidates.jsonl")

    return NormalizedMapResult(
        appmap_root=str(root),
        manifest=manifest,
        target_profile=target_profile,
        surfaces=surfaces,
        flows=flows,
        legacy_candidates=candidates,
        legacy_rejected_candidates=rejected,
        legacy_policy_shaped=legacy_policy_shaped,
        source_files=tuple(source_files),
    )


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError(f"expected JSON object at {path}:{line_number}")
        rows.append(payload)
    return rows


def _with_compat_context(row: dict[str, Any], context_type: str) -> dict[str, Any]:
    copy = dict(row)
    copy["pipeline_context"] = {
        "type": context_type,
        "legacy_compatibility_context": True,
        "legacy_policy_shaped": True,
        "neutral_truth": False,
    }
    return copy
