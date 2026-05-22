from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from agents.agent_scheduler import family_role_for, infer_surface_family
from agents.hunt_pipeline.models import HypothesisAgentPacket, NormalizedMapResult, ResolvedRuleset


def build_hypothesis_packets(
    normalized: NormalizedMapResult,
    ruleset: ResolvedRuleset,
    *,
    target_kind: str,
    max_packets: int | None = None,
) -> list[HypothesisAgentPacket]:
    packets: list[HypothesisAgentPacket] = []
    for surface in sorted(normalized.surfaces, key=_surface_sort_key):
        packet = _packet_for_surface(surface, normalized=normalized, ruleset=ruleset, target_kind=target_kind)
        if packet is None:
            continue
        packets.append(packet)

    packets = _dedupe_packets(packets)
    if max_packets is not None:
        packets = packets[: max(0, int(max_packets))]
    return packets


def _packet_for_surface(
    surface: dict[str, Any],
    *,
    normalized: NormalizedMapResult,
    ruleset: ResolvedRuleset,
    target_kind: str,
) -> HypothesisAgentPacket | None:
    kind = _text(surface.get("kind") or surface.get("surface_kind") or surface.get("type"))
    if not kind:
        return None
    family = _surface_family(surface, ruleset)
    family_role = family_role_for(family)
    explicit_entry = bool(surface.get("app_entry_evidence") or surface.get("proven_app_entry"))
    standalone_sink = _is_standalone_sink_surface(surface, normalized)
    role = (
        "entry"
        if explicit_entry or (family_role == "application-entry" and not standalone_sink)
        else "amplifier"
        if family_role == "amplifier"
        else "notes_only"
    )
    priority = "high" if role == "entry" else "medium" if role == "amplifier" else "low"
    entry_status = "plausible" if role == "entry" else "missing" if role in {"amplifier", "chain"} else "not_required"
    reportability = "validate_entry" if role == "entry" else "hold_for_chain" if role in {"amplifier", "chain"} else "notes_only"
    surface_id = _text(surface.get("id")) or _stable_id("surface", surface)[:10]
    focus_files = _focus_files(surface)
    title = f"Investigate {family} surface {surface_id}"
    key = _key_for(family, surface_id)
    evidence = (_surface_evidence(surface),)
    requirements = tuple(_guidance_list(ruleset, "required_evidence"))
    chain_requirements = tuple(_guidance_list(ruleset, "chain_requirements") if role != "entry" else ())
    reasons = [
        f"neutral AppMap surface kind={kind}",
        f"ruleset mapped surface to {family}",
    ]
    if normalized.legacy_policy_shaped:
        reasons.append("legacy candidates were loaded as compatibility context only")

    tags = tuple(
        item
        for item in _unique(
            [
                "hunt-pipeline",
                ruleset.id,
                family,
                role,
                *_string_list(surface.get("tags")),
                *_string_list((ruleset.notes or {}).get("tags")),
            ]
        )
    )
    ingestion_path = _ingestion_path(surface, family, role)
    context_tags = tuple(_context_tags(surface, family, tags))
    required_entry_primitives = tuple(_required_entry_primitives(surface, family, role, chain_requirements))
    unlocked_amplifiers = tuple(_unlocked_amplifiers(surface, family, role))
    scores = _hypothesis_scores(surface, family, role, priority)
    metadata = {
        "hypothesis_id": "",
        "brainstorm_agent_key": key,
        "surface_family": family,
        "priority": priority,
        "appmap_run_root": normalized.appmap_root,
        "appmap_surface_id": surface_id,
        "ruleset_id": ruleset.id,
        "finding_role": role,
        "entry_status": entry_status,
        "ingestion_path": ingestion_path,
        "required_entry_primitives": list(required_entry_primitives),
        "context_tags": list(context_tags),
        "unlocked_amplifiers": list(unlocked_amplifiers),
        "reportability": reportability,
        **scores,
        "legacy_policy_shaped_context": normalized.legacy_policy_shaped,
        "expected_chain": _expected_chain(surface, family, role),
        "focus_files": focus_files,
        "brainstorm_tags": list(tags),
    }
    packet_id = _packet_id(ruleset.id, target_kind, surface)
    metadata["hypothesis_id"] = packet_id
    return HypothesisAgentPacket(
        id=packet_id,
        key=key,
        title=title,
        role=role,
        surface_family=family,
        secondary_families=tuple(_secondary_families(surface, family)),
        priority=priority,
        target_kind=target_kind,
        ruleset_id=ruleset.id,
        source_evidence=evidence,
        evidence_requirements=requirements,
        chain_requirements=chain_requirements,
        focus_files=tuple(focus_files),
        tags=tags,
        reasons=tuple(reasons),
        scheduler_metadata=metadata,
        entry_status=entry_status,
        attacker_influence_score=scores["attacker_influence_score"],
        context_privilege_score=scores["context_privilege_score"],
        incremental_impact_score=scores["incremental_impact_score"],
        entry_reportability_score=scores["entry_reportability_score"],
        chain_unlock_score=scores["chain_unlock_score"],
        ingestion_path=ingestion_path,
        required_entry_primitives=required_entry_primitives,
        context_tags=context_tags,
        unlocked_amplifiers=unlocked_amplifiers,
        reportability=reportability,
    )


def _surface_family(surface: dict[str, Any], ruleset: ResolvedRuleset) -> str:
    explicit = _text(surface.get("surface_family") or surface.get("scheduler_surface_family"))
    kind = _text(surface.get("kind") or surface.get("surface_kind") or surface.get("type")).lower()
    family_map = ruleset.hypothesis_guidance.get("surface_family_map")
    if isinstance(family_map, dict):
        mapped = _text(family_map.get(kind) or family_map.get(kind.replace("_", "-")))
        if mapped:
            return infer_surface_family(metadata={"surface_family": mapped})[0]
    if explicit:
        return infer_surface_family(metadata={"surface_family": explicit})[0]
    profile_text = " ".join(
        _text(value)
        for value in (
            kind,
            surface.get("name"),
            surface.get("description"),
            surface.get("file"),
            surface.get("code"),
        )
    )
    return infer_surface_family(profile=None, metadata={"brainstorm_tags": [kind], "expected_chain": profile_text})[0]


def _is_standalone_sink_surface(surface: dict[str, Any], normalized: NormalizedMapResult) -> bool:
    if _text(surface.get("role")).lower() != "sink":
        return False
    surface_id = _text(surface.get("id"))
    if not surface_id:
        return True
    for flow in normalized.flows:
        sink_refs = {
            _text(flow.get("sink_id")),
            *(_text(item) for item in _string_list(flow.get("sink_ids"))),
        }
        if surface_id in sink_refs:
            return False
    return True


def _secondary_families(surface: dict[str, Any], primary: str) -> list[str]:
    secondary = []
    for value in _string_list(surface.get("secondary_families") or surface.get("surface_families")):
        family = infer_surface_family(metadata={"surface_family": value})[0]
        if family != primary:
            secondary.append(family)
    return _unique(secondary)


def _surface_evidence(surface: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "role", "kind", "file", "line", "name", "description", "confidence", "trust_level", "attacker_control")
    return {key: surface[key] for key in keys if key in surface and surface[key] not in (None, "", [])}


def _focus_files(surface: dict[str, Any]) -> list[str]:
    values = [surface.get("file"), *_string_list(surface.get("focus_files"))]
    return _unique([_text(item) for item in values if _text(item)])


def _guidance_list(ruleset: ResolvedRuleset, key: str) -> list[str]:
    return _string_list(ruleset.hypothesis_guidance.get(key))


def _expected_chain(surface: dict[str, Any], family: str, role: str) -> str:
    file_name = _text(surface.get("file"))
    suffix = f" in {file_name}" if file_name else ""
    return f"{role} hypothesis for {family}{suffix}"


def _ingestion_path(surface: dict[str, Any], family: str, role: str) -> str:
    explicit = _text(surface.get("ingestion_path") or surface.get("entry_path"))
    if explicit:
        return explicit
    haystack = " ".join(
        _text(value).lower()
        for value in (
            surface.get("kind"),
            surface.get("name"),
            surface.get("description"),
            surface.get("file"),
            family,
        )
    )
    if "deeplink" in haystack or "protocol" in haystack:
        return "deeplink"
    if "import" in haystack or "file" in haystack:
        return "file import"
    if "comment" in haystack or "collab" in haystack or "sync" in haystack:
        return "collaboration sync"
    if "media" in haystack or "image" in haystack or "recording" in haystack:
        return "uploaded media"
    if "webview" in haystack or "navigation" in haystack or "url" in haystack:
        return "external URL"
    if role == "entry":
        return "attacker-influenceable app input"
    return "requires prior entry"


def _context_tags(surface: dict[str, Any], family: str, tags: tuple[str, ...]) -> list[str]:
    values = [
        family,
        *_string_list(surface.get("context_tags")),
        *_string_list(surface.get("renderer")),
        *_string_list(surface.get("window")),
        *_string_list(surface.get("bridge")),
        *_string_list(surface.get("protocol")),
        *tags,
    ]
    return _unique([_text(item) for item in values if _text(item)])


def _required_entry_primitives(
    surface: dict[str, Any],
    family: str,
    role: str,
    chain_requirements: tuple[str, ...],
) -> list[str]:
    explicit = _string_list(surface.get("required_entry_primitives"))
    if explicit:
        return _unique(explicit)
    if role == "entry":
        return []
    haystack = " ".join([family, *_string_list(surface.get("tags")), *chain_requirements]).lower()
    primitives = []
    if "webview" in haystack:
        primitives.append("webview_js")
    if "deeplink" in haystack or "protocol" in haystack:
        primitives.append("deeplink_control")
    if "file" in haystack or "import" in haystack:
        primitives.append("malicious_file_import")
    if "auth" in haystack or "oauth" in haystack:
        primitives.append("auth_callback_control")
    if not primitives:
        primitives.append("renderer_xss")
    return _unique(primitives)


def _unlocked_amplifiers(surface: dict[str, Any], family: str, role: str) -> list[str]:
    explicit = _string_list(surface.get("unlocked_amplifiers"))
    if explicit:
        return _unique(explicit)
    if role != "entry":
        return []
    if family in {"rendering-content-parser", "file-ingestion-import", "custom-protocol-deeplink"}:
        return ["ipc-bridge", "storage-cache-state"]
    return []


def _hypothesis_scores(surface: dict[str, Any], family: str, role: str, priority: str) -> dict[str, float]:
    confidence = _float(surface.get("confidence"), default=0.5)
    attacker_control = _float(surface.get("attacker_control"), default=0.7 if role == "entry" else 0.2)
    context_privilege = 0.8 if family in {"ipc-bridge", "storage-cache-state", "custom-protocol-deeplink"} else 0.5
    incremental = 0.8 if family in {"ipc-bridge", "storage-cache-state", "network-fetch-ssrf"} else 0.5
    priority_bonus = {"critical": 0.9, "high": 0.75, "medium": 0.45, "low": 0.2}.get(priority, 0.2)
    entry_reportability = (attacker_control + confidence + priority_bonus) / 3 if role == "entry" else 0.0
    chain_unlock = (context_privilege + incremental + confidence) / 3 if role in {"amplifier", "chain"} else incremental / 2
    return {
        "attacker_influence_score": round(attacker_control, 3),
        "context_privilege_score": round(context_privilege, 3),
        "incremental_impact_score": round(incremental, 3),
        "entry_reportability_score": round(entry_reportability, 3),
        "chain_unlock_score": round(chain_unlock, 3),
    }


def _float(value: Any, *, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _packet_id(ruleset_id: str, target_kind: str, surface: dict[str, Any]) -> str:
    digest = _stable_id(ruleset_id, {"target_kind": target_kind, "surface": surface})[:12].upper()
    return f"HP-{digest}"


def _key_for(family: str, surface_id: str) -> str:
    suffix = re.sub(r"[^a-z0-9-]+", "-", surface_id.lower()).strip("-") or "surface"
    return f"{family}-{suffix}"


def _stable_id(prefix: str, payload: Any) -> str:
    blob = json.dumps({"prefix": prefix, "payload": payload}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _dedupe_packets(packets: list[HypothesisAgentPacket]) -> list[HypothesisAgentPacket]:
    seen: set[tuple[str, str]] = set()
    out: list[HypothesisAgentPacket] = []
    for packet in packets:
        key = (packet.surface_family, json.dumps(packet.source_evidence, sort_keys=True))
        if key in seen:
            continue
        seen.add(key)
        out.append(packet)
    return out


def _surface_sort_key(surface: dict[str, Any]) -> tuple[str, str, str]:
    return (_text(surface.get("file")), _text(surface.get("line")).zfill(8), _text(surface.get("id")))


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [_text(item) for item in value if _text(item)]
    text = _text(value)
    return [text] if text else []


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _text(value: Any) -> str:
    return str(value or "").strip()
