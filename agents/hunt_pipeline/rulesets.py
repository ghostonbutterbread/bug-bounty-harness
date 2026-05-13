from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents.hunt_pipeline.models import ResolvedRuleset
from agents.hunting_policy import HuntingPolicy, resolve_hunting_policy

RULESET_ROOT = Path(__file__).resolve().parent.parent / "rulesets"


def resolve_ruleset(
    ruleset_id: str | None = "auto",
    *,
    target_kind: str | None = None,
    target_path: str | Path | None = None,
    ruleset_root: str | Path | None = None,
) -> ResolvedRuleset:
    root = Path(ruleset_root).expanduser().resolve(strict=False) if ruleset_root else RULESET_ROOT
    requested = str(ruleset_id or "auto").strip() or "auto"
    aliases = _load_aliases(root)
    normalized = _normalize_id(requested)
    target_kind_norm = _normalize_id(target_kind or "")

    if normalized == "auto":
        selected = ["desktop-baseline"]
        if _looks_electron(target_kind=target_kind_norm, target_path=target_path):
            selected.append("electron-overlay")
        return _compose(selected, requested_id=requested, compatibility_alias=None, root=root)

    if normalized in aliases:
        alias = aliases[normalized]
        selected = _as_string_list(alias.get("rulesets"))
        if not selected:
            selected = [_normalize_id(alias.get("base") or "desktop-baseline"), *_as_string_list(alias.get("overlays"))]
        resolved = _compose(selected, requested_id=requested, compatibility_alias=normalized, root=root)
        return _with_policy_hints(resolved, alias.get("policy_hints"))

    payload, path = _load_ruleset_payload(normalized, root)
    if payload.get("kind") == "overlay":
        selected = [*_as_string_list(payload.get("extends") or ["desktop-baseline"]), normalized]
    else:
        selected = [normalized]
    return _compose(selected, requested_id=requested, compatibility_alias=None, root=root)


def hunting_policy_view(ruleset: ResolvedRuleset) -> HuntingPolicy:
    policy_id = str(ruleset.policy_hints.get("policy_id") or "").strip()
    if policy_id:
        return resolve_hunting_policy(policy_id)
    return HuntingPolicy(
        id=f"{ruleset.id}-ruleset-view",
        enabled=True,
        mode="ruleset-view",
        requested_id=ruleset.requested_id,
        hunt_posture=str(ruleset.policy_hints.get("hunt_posture") or ""),
        prioritize=[str(item) for item in ruleset.surface_taxonomy.get("prioritize") or []],
        deprioritize=[str(item) for item in ruleset.surface_taxonomy.get("deprioritize") or []],
        avoid=[str(item) for item in ruleset.surface_taxonomy.get("avoid") or []],
        allow_if_evidence=[str(item) for item in ruleset.hypothesis_guidance.get("required_evidence") or []],
        reporting_rules=dict(ruleset.review_guidance.get("reportability_rules") or {}),
        applies_to={"app_kinds": list(ruleset.app_kinds), "target_kinds": list(ruleset.target_kinds)},
    )


def _compose(
    selected: list[str],
    *,
    requested_id: str,
    compatibility_alias: str | None,
    root: Path,
) -> ResolvedRuleset:
    if not selected:
        raise ValueError("at least one ruleset must be selected")

    payloads: list[tuple[dict[str, Any], Path]] = [_load_ruleset_payload(_normalize_id(item), root) for item in selected]
    base_payload, base_path = payloads[0]
    merged: dict[str, Any] = {
        "id": str(base_payload.get("id") or selected[0]),
        "version": int(base_payload.get("version") or 1),
        "app_kinds": _as_string_list((base_payload.get("applies_to") or {}).get("app_kinds")),
        "target_kinds": _as_string_list((base_payload.get("applies_to") or {}).get("target_kinds")),
        "surface_taxonomy": dict(base_payload.get("surface_taxonomy") or {}),
        "hypothesis_guidance": dict(base_payload.get("hypothesis_guidance") or {}),
        "scheduler_guidance": dict(base_payload.get("scheduler_guidance") or {}),
        "review_guidance": dict(base_payload.get("review_guidance") or {}),
        "policy_hints": dict(base_payload.get("policy_hints") or {}),
        "notes": dict(base_payload.get("notes") or {}),
    }

    overlays: list[str] = []
    config_paths = [str(base_path)]
    for payload, path in payloads[1:]:
        overlay_id = str(payload.get("id") or path.stem)
        overlays.append(overlay_id)
        config_paths.append(str(path))
        applies_to = payload.get("applies_to") if isinstance(payload.get("applies_to"), dict) else {}
        merged["app_kinds"] = _unique([*merged["app_kinds"], *_as_string_list(applies_to.get("app_kinds"))])
        merged["target_kinds"] = _unique([*merged["target_kinds"], *_as_string_list(applies_to.get("target_kinds"))])
        for key in ("surface_taxonomy", "hypothesis_guidance", "scheduler_guidance", "review_guidance", "policy_hints", "notes"):
            merged[key] = _deep_merge(merged.get(key), payload.get(key))

    selected_ids = tuple(str(payload.get("id") or path.stem) for payload, path in payloads)
    resolved_id = compatibility_alias or ("+".join(selected_ids) if overlays else selected_ids[0])
    return ResolvedRuleset(
        id=resolved_id,
        version=max(int(payload.get("version") or 1) for payload, _path in payloads),
        requested_id=requested_id,
        base_id=str(base_payload.get("id") or selected[0]),
        overlays=tuple(overlays),
        selected_rulesets=selected_ids,
        compatibility_alias=compatibility_alias,
        app_kinds=tuple(merged["app_kinds"]),
        target_kinds=tuple(merged["target_kinds"]),
        surface_taxonomy=merged["surface_taxonomy"],
        hypothesis_guidance=merged["hypothesis_guidance"],
        scheduler_guidance=merged["scheduler_guidance"],
        review_guidance=merged["review_guidance"],
        policy_hints=merged["policy_hints"],
        notes=merged["notes"],
        config_paths=tuple(config_paths),
    )


def _with_policy_hints(ruleset: ResolvedRuleset, hints: Any) -> ResolvedRuleset:
    if not isinstance(hints, dict):
        return ruleset
    policy_hints = _deep_merge(ruleset.policy_hints, hints)
    return ResolvedRuleset(
        **{
            **ruleset.to_dict(),
            "policy_hints": policy_hints,
        }
    )


def _load_ruleset_payload(ruleset_id: str, root: Path) -> tuple[dict[str, Any], Path]:
    candidates = [
        root / "base" / f"{ruleset_id}.json",
        root / "overlays" / f"{ruleset_id}.json",
        root / f"{ruleset_id}.json",
    ]
    for path in candidates:
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"ruleset must be a JSON object: {path}")
        _validate_ruleset_payload(payload, path)
        return payload, path
    raise ValueError(f"unknown ruleset {ruleset_id!r} under {root}")


def _validate_ruleset_payload(payload: dict[str, Any], path: Path) -> None:
    for key in ("id", "version", "kind"):
        if key not in payload:
            raise ValueError(f"ruleset {path} missing required key: {key}")
    if payload["kind"] not in {"base", "overlay"}:
        raise ValueError(f"ruleset {path} has unsupported kind: {payload['kind']!r}")


def _load_aliases(root: Path) -> dict[str, dict[str, Any]]:
    path = root / "aliases.json"
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"aliases config must be a JSON object: {path}")
    aliases = payload.get("aliases", payload)
    if not isinstance(aliases, dict):
        raise ValueError(f"aliases config must contain an object: {path}")
    return {_normalize_id(key): dict(value) for key, value in aliases.items() if isinstance(value, dict)}


def _looks_electron(*, target_kind: str, target_path: str | Path | None) -> bool:
    if "electron" in target_kind or target_kind in {"app-asar", "app_asar", "electron-exe"}:
        return True
    if target_path is None:
        return False
    path = Path(target_path).expanduser()
    candidates = [path / "package.json", path / "resources" / "app.asar" / "package.json"]
    for candidate in candidates:
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        haystack = json.dumps(payload, sort_keys=True).lower()
        if "electron" in haystack:
            return True
    return False


def _deep_merge(left: Any, right: Any) -> Any:
    if right is None:
        return left if left is not None else {}
    if isinstance(left, dict) and isinstance(right, dict):
        merged = dict(left)
        for key, value in right.items():
            merged[key] = _deep_merge(merged.get(key), value)
        return merged
    if isinstance(left, list) or isinstance(right, list):
        return _unique([*_as_string_or_object_list(left), *_as_string_or_object_list(right)])
    return right


def _as_string_or_object_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _as_string_list(value: Any) -> list[str]:
    return [str(item).strip() for item in _as_string_or_object_list(value) if str(item).strip()]


def _unique(values: list[Any]) -> list[Any]:
    seen: set[str] = set()
    out: list[Any] = []
    for value in values:
        key = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def _normalize_id(value: Any) -> str:
    return str(value or "").strip().lower().replace("_", "-")
