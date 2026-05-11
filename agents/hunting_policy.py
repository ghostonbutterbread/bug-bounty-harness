"""Shared hunting policy resolver and prompt snippets."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator


POLICY_OFF_ALIASES = {"off", "none", "disabled", "disable", "false", "0", ""}
POLICY_AUTO_ALIASES = {"auto", "default"}
ELECTRON_POLICY_ID = "electron-application-first-loose"
DEFAULT_POLICY_CONFIG_DIR = Path(__file__).resolve().parent / "policies"
POLICY_ARTIFACT_KEYS = (
    "hunting_policy",
    "hunting_policy_id",
    "hunting_policy_mode",
    "hunting_policy_posture",
)
ELECTRON_POLICY_ALIASES = {
    ELECTRON_POLICY_ID,
    "electron-application-first",
    "electron-entry-first",
}
APPMAP_POLICY_REPORTABILITY_SUBMIT = "submit"
APPMAP_POLICY_REPORTABILITY_HOLD = "hold_for_chain"
APPMAP_POLICY_REPORTABILITY_NOTES = "notes_only"


@dataclass(slots=True)
class HuntingPolicy:
    id: str
    enabled: bool = True
    version: int = 1
    mode: str = "on"
    requested_id: str = "auto"
    hunt_posture: str = ""
    prioritize: list[str] = field(default_factory=list)
    deprioritize: list[str] = field(default_factory=list)
    avoid: list[str] = field(default_factory=list)
    allow_if_evidence: list[str] = field(default_factory=list)
    reporting_rules: dict[str, Any] = field(default_factory=dict)
    applies_to: dict[str, Any] = field(default_factory=dict)
    config_path: str = ""

    def __bool__(self) -> bool:
        return self.enabled

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def keys(self):
        return self.to_dict().keys()

    def items(self):
        return self.to_dict().items()

    def values(self):
        return self.to_dict().values()

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def snippet(self, stage: str = "agent") -> str:
        return policy_prompt_snippet(self, stage=stage)


def disabled_policy(requested_id: str = "off") -> HuntingPolicy:
    return HuntingPolicy(id="off", enabled=False, mode="off", requested_id=requested_id)


def _electron_application_first_policy(*, mode: str, requested_id: str) -> HuntingPolicy:
    return HuntingPolicy(
        id=ELECTRON_POLICY_ID,
        enabled=True,
        version=1,
        mode=mode,
        requested_id=requested_id,
        hunt_posture="application-first-loose",
        applies_to={
            "platforms": ["electron", "desktop"],
            "target_kinds": ["electron-exe", "desktop", "app_asar", "mac-desktop"],
        },
        prioritize=[
            "rendering",
            "navigation",
            "protocol-handlers",
            "auth-flows",
            "file-ingestion",
            "import-export",
            "local-file-manipulation",
            "plugin-template-systems",
            "custom-url-handlers",
            "parser-boundaries",
        ],
        deprioritize=[
            "ipc",
            "hostrpc",
            "preload",
            "native-bridge",
            "openExternal",
            "download-save-reveal",
            "media-access",
            "auth-session-helpers",
            "updater-relaunch",
            "native-parsers",
        ],
        avoid=[],
        allow_if_evidence=[
            "deprioritized surface is reached from a proven app-level entry",
            "deprioritized surface provides standalone critical impact",
            "program explicitly accepts this class",
        ],
        reporting_rules={
            "headline_entry_not_amplifier": True,
            "hold_amplifier_without_entry": True,
            "allow_standalone_critical_amplifier": True,
        },
    )


def normalize_policy_id(policy_id: str | None) -> str:
    """Normalize policy aliases without blocking future config-backed policy IDs."""

    normalized = str(policy_id if policy_id is not None else "auto").strip().lower().replace("_", "-")
    if normalized in POLICY_OFF_ALIASES:
        return "off"
    if normalized in POLICY_AUTO_ALIASES:
        return "auto"
    if normalized in ELECTRON_POLICY_ALIASES:
        return ELECTRON_POLICY_ID
    return normalized


def resolve_policy_selection(
    hunting_policy: str | None = "auto",
    *,
    triage_policy: str | None = None,
    no_triage_policy: bool = False,
) -> str:
    if no_triage_policy:
        return "off"
    if triage_policy is not None:
        return triage_policy
    return hunting_policy if hunting_policy is not None else "auto"


def resolve_hunting_policy(
    policy_id: str | None = "auto",
    *,
    target_kind: str | None = None,
    target_path: str | Path | None = None,
    policy_config: str | Path | None = None,
) -> HuntingPolicy:
    requested_id = str(policy_id if policy_id is not None else "auto").strip()
    if str(requested_id).strip().lower().replace("_", "-") in POLICY_OFF_ALIASES:
        return disabled_policy(requested_id=requested_id or "off")

    if policy_config:
        return _load_policy_config(policy_config, requested_id=requested_id or "config")

    normalized_id = normalize_policy_id(requested_id) if requested_id else "off"
    if normalized_id == "off":
        return disabled_policy(requested_id=requested_id or "off")

    if normalized_id == "auto":
        if _looks_like_electron_target(target_kind=target_kind, target_path=target_path):
            return _electron_application_first_policy(mode="auto", requested_id=requested_id or "auto")
        return disabled_policy(requested_id=requested_id or "auto")

    named_config = _policy_config_path(normalized_id)
    if named_config.exists():
        return _load_policy_config(named_config, requested_id=requested_id or normalized_id)
    if normalized_id == ELECTRON_POLICY_ID:
        return _electron_application_first_policy(mode="on", requested_id=requested_id or normalized_id)
    raise ValueError(
        f"unsupported hunting policy {policy_id!r}; expected auto, off, an Electron policy alias, "
        f"or a JSON config at {named_config}"
    )


def _policy_config_path(policy_id: str) -> Path:
    safe_id = str(policy_id).strip().lower().replace("_", "-")
    return DEFAULT_POLICY_CONFIG_DIR / f"{safe_id}.json"


def _load_policy_config(policy_config: str | Path, *, requested_id: str) -> HuntingPolicy:
    config_path = Path(policy_config).expanduser().resolve(strict=False)
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"policy config must be a JSON object: {config_path}")

    data = HuntingPolicy(
        id=str(payload.get("id") or config_path.stem or "custom-policy"),
        enabled=bool(payload.get("enabled", True)),
        mode=str(payload.get("mode") or "on"),
        requested_id=requested_id,
    ).to_dict()
    data.update(payload)
    data["enabled"] = bool(data.get("enabled", True))
    data["id"] = str(data.get("id") or config_path.stem or "custom-policy")
    data["requested_id"] = requested_id
    data["config_path"] = str(config_path)
    return HuntingPolicy(**{field_name: data.get(field_name) for field_name in HuntingPolicy.__dataclass_fields__})


def _looks_like_electron_target(
    *,
    target_kind: str | None,
    target_path: str | Path | None,
) -> bool:
    kind = str(target_kind or "").strip().lower()
    if any(token in kind for token in ("electron", "desktop", "app_asar", "mac-desktop")):
        return True

    if target_path is None:
        return False
    path = Path(target_path).expanduser()
    path_text = str(path).lower()
    package_candidates: list[Path] = []
    if path.name == "package.json":
        package_candidates.append(path)
    package_candidates.extend(
        [
            path / "package.json",
            path / "app_asar" / "resources" / "app.asar" / "package.json",
            path / "resources" / "app.asar" / "package.json",
        ]
    )
    if "app_asar/resources/app.asar/package.json" in path_text:
        package_candidates.append(path)

    return any(_package_has_electron_evidence(candidate) for candidate in package_candidates)


def _package_has_electron_evidence(package_json: Path) -> bool:
    try:
        payload = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    haystack = json.dumps(
        {
            "main": payload.get("main"),
            "dependencies": payload.get("dependencies"),
            "devDependencies": payload.get("devDependencies"),
            "optionalDependencies": payload.get("optionalDependencies"),
            "build": payload.get("build"),
        },
        sort_keys=True,
    ).lower()
    return any(token in haystack for token in ("electron", "electron-builder", "electron-packager"))


def policy_prompt_snippet(policy: HuntingPolicy | dict[str, Any] | None, *, stage: str = "agent") -> str:
    normalized = coerce_hunting_policy(policy)
    if not normalized.enabled:
        return ""

    prioritize = ", ".join(normalized.prioritize)
    deprioritize = ", ".join(normalized.deprioritize)
    allow = "; ".join(normalized.allow_if_evidence)
    stage_name = str(stage or "agent").strip().lower()
    metadata = (
        "When emitting or reviewing findings, include policy_id, finding_role, entry_status, "
        "entry_vector, impact_amplifiers, chain_requirements, reportability, and payout_confidence."
    )
    review_rule = (
        "Amplifier-only findings with missing entry should usually be held as chain material; "
        "standalone critical IPC/native impact is still allowed when the evidence proves it."
    )

    headings = {
        "map": "Hunting Policy For Mapping",
        "brainstorm": "Hunting Policy For Brainstorming",
        "agent": "Hunting Policy",
        "review": "Hunting Policy For Review",
    }
    heading = headings.get(stage_name, "Hunting Policy")
    lines = [
        f"## {heading}: {normalized.id}",
        "This policy guides priority and report framing. It is not a hard ban unless an avoid rule explicitly says so.",
        "Deprioritized surfaces are not forbidden. IPC, HostRpc, preload, and native bridge work is soft-deprioritized by default, not banned.",
        f"Prioritize: {prioritize or 'None configured.'}",
        f"Deprioritize: {deprioritize or 'None configured.'}",
        f"Allow following deprioritized lanes when: {allow or 'strong evidence justifies it.'}",
    ]
    if stage_name == "map":
        lines.append(
            "Promote application behavior lanes first; retain IPC/native methods as secondary impact context unless directly attacker-reachable."
        )
    elif stage_name == "brainstorm":
        lines.append(
            "Prefer hypotheses that start from rendering, navigation, import/export, protocol, auth, file, or parser boundaries, then attach IPC/native impact where relevant."
        )
    elif stage_name == "review":
        lines.extend([metadata, review_rule, "Headline the application entry path when one exists; use IPC/native behavior as impact expansion."])
    else:
        lines.extend([metadata, "Do not tunnel on raw IPC/native enumeration unless evidence connects it to attacker control or standalone critical impact."])
    return "\n".join(lines).rstrip()


def coerce_hunting_policy(policy: HuntingPolicy | dict[str, Any] | None) -> HuntingPolicy:
    if isinstance(policy, HuntingPolicy):
        return policy
    if not isinstance(policy, dict):
        return disabled_policy()
    data = disabled_policy().to_dict()
    data.update(policy)
    return HuntingPolicy(**{field_name: data.get(field_name) for field_name in HuntingPolicy.__dataclass_fields__})


def policy_config_path_for_artifacts(policy: HuntingPolicy | dict[str, Any] | None) -> str:
    normalized = coerce_hunting_policy(policy)
    if not normalized.enabled:
        return ""
    return str(normalized.config_path or "").strip()


def policy_artifact_metadata(policy: HuntingPolicy | dict[str, Any] | None) -> dict[str, Any]:
    source = policy
    if isinstance(policy, dict) and isinstance(policy.get("hunting_policy"), dict):
        source = policy["hunting_policy"]
    normalized = coerce_hunting_policy(source)
    if not normalized.enabled:
        return {}
    return {
        "hunting_policy": normalized.to_dict(),
        "hunting_policy_id": normalized.id,
        "hunting_policy_mode": normalized.mode,
        "hunting_policy_posture": normalized.hunt_posture,
    }


def merge_policy_artifact_metadata(
    payload: dict[str, Any],
    policy: HuntingPolicy | dict[str, Any] | None,
) -> dict[str, Any]:
    merged = dict(payload)
    merged.update(policy_artifact_metadata(policy))
    return merged


def extract_policy_artifact_metadata(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    if isinstance(payload.get("hunting_policy"), dict):
        return policy_artifact_metadata(payload["hunting_policy"])
    hunting_policy_id = str(payload.get("hunting_policy_id") or "").strip()
    if not hunting_policy_id:
        return {}
    extracted = {"hunting_policy_id": hunting_policy_id}
    for key in POLICY_ARTIFACT_KEYS[2:]:
        value = payload.get(key)
        if value not in (None, "", []):
            extracted[key] = value
    return extracted


def apply_appmap_promotion_policy(
    candidates: list[dict[str, Any]],
    rejected_candidates: list[dict[str, Any]],
    policy: HuntingPolicy | dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    normalized = coerce_hunting_policy(policy)
    if not normalized.enabled:
        return list(candidates), list(rejected_candidates)

    promoted: list[dict[str, Any]] = []
    held = [dict(item) for item in rejected_candidates]
    next_rejected_index = _next_rejected_index(held)
    for candidate in candidates:
        candidate_copy = dict(candidate)
        candidate_policy = appmap_candidate_policy_metadata(candidate_copy, normalized)
        candidate_copy["policy"] = candidate_policy
        candidate_copy["policy_id"] = candidate_policy["policy_id"]
        candidate_copy["reportability"] = candidate_policy["reportability"]
        if candidate_policy["decision"] == "hold":
            held.append(_held_appmap_candidate(candidate_copy, candidate_policy, index=next_rejected_index))
            next_rejected_index += 1
            continue
        promoted.append(candidate_copy)

    promoted.sort(
        key=lambda item: (
            int((item.get("policy") or {}).get("promotion_rank", 999)),
            -float(item.get("score", 0.0)),
            str(item.get("id", "")),
        )
    )
    return promoted, held


def appmap_candidate_policy_metadata(
    candidate: dict[str, Any],
    policy: HuntingPolicy | dict[str, Any] | None,
) -> dict[str, Any]:
    normalized = coerce_hunting_policy(policy)
    if not normalized.enabled:
        return {}

    source = candidate.get("source") if isinstance(candidate.get("source"), dict) else {}
    source_kind = _normalize_policy_kind(source.get("kind"))
    surface_kinds = sorted(_appmap_surface_kinds(candidate))
    deprioritized = _deprioritized_policy_kinds(normalized)
    suppressed_surface_kinds = sorted(kind for kind in surface_kinds if kind in deprioritized)
    app_entry_evidence = _candidate_has_app_entry_evidence(candidate, deprioritized)
    standalone_critical = _candidate_has_standalone_critical_evidence(candidate)
    source_is_deprioritized = source_kind in deprioritized
    hold = bool(source_is_deprioritized and not app_entry_evidence and not standalone_critical)

    if hold:
        finding_role = "chain"
        entry_status = "missing"
        entry_vector = None
        reportability = APPMAP_POLICY_REPORTABILITY_HOLD
        reason_code = "deprioritized-source-without-app-entry"
        reason = (
            "held by hunting policy because the candidate starts from a deprioritized "
            "surface without app-level entry evidence"
        )
        chain_requirements = [
            "prove an application-level entry that reaches this privileged lane",
            "or prove standalone critical impact that does not rely on a separate entry path",
        ]
        promotion_rank = 900
    else:
        finding_role = "entry" if app_entry_evidence else "amplifier"
        entry_status = "proven" if app_entry_evidence else ("not_required" if standalone_critical else "plausible")
        entry_vector = _candidate_entry_vector(candidate) if app_entry_evidence else None
        reportability = APPMAP_POLICY_REPORTABILITY_SUBMIT if (app_entry_evidence or standalone_critical) else APPMAP_POLICY_REPORTABILITY_NOTES
        if standalone_critical and source_is_deprioritized:
            reason_code = "standalone-critical-amplifier"
            reason = "promoted despite deprioritization because standalone critical impact evidence is present"
            promotion_rank = 50
        elif app_entry_evidence and source_is_deprioritized:
            reason_code = "deprioritized-source-with-app-entry"
            reason = "promoted because app-level entry evidence reaches the deprioritized surface"
            promotion_rank = 25
        elif app_entry_evidence:
            reason_code = "application-entry"
            reason = "promoted because the candidate is anchored in application behavior"
            promotion_rank = 0
        else:
            reason_code = "policy-allowed"
            reason = "promoted because the candidate is not blocked by the active hunting policy"
            promotion_rank = 100
        chain_requirements = []

    return {
        "policy_id": normalized.id,
        "policy_mode": normalized.mode,
        "policy_posture": normalized.hunt_posture,
        "decision": "hold" if hold else "promote",
        "promotion_rank": promotion_rank,
        "reason_code": reason_code,
        "reason": reason,
        "finding_role": finding_role,
        "entry_status": entry_status,
        "entry_vector": entry_vector,
        "impact_amplifiers": suppressed_surface_kinds,
        "chain_requirements": chain_requirements,
        "reportability": reportability,
        "hold_for_chain": hold,
        "suppressed_surface_kinds": suppressed_surface_kinds,
        "app_entry_evidence": app_entry_evidence,
        "standalone_critical": standalone_critical,
    }


def _held_appmap_candidate(
    candidate: dict[str, Any],
    candidate_policy: dict[str, Any],
    *,
    index: int,
) -> dict[str, Any]:
    source = candidate.get("source") if isinstance(candidate.get("source"), dict) else {}
    boundary = candidate.get("boundary") if isinstance(candidate.get("boundary"), dict) else {}
    transform = candidate.get("transform") if isinstance(candidate.get("transform"), dict) else None
    sink = candidate.get("sink") if isinstance(candidate.get("sink"), dict) else {}
    record = {
        "id": f"R{index:04d}",
        "candidate_id": candidate.get("id"),
        "flow_id": candidate.get("flow_id"),
        "surface_id": candidate.get("surface_id"),
        "file": source.get("file") or boundary.get("file") or sink.get("file"),
        "source_ids": [source["id"]] if source.get("id") else [],
        "boundary_ids": [boundary["id"]] if boundary.get("id") else [],
        "transform_ids": [transform["id"]] if transform and transform.get("id") else [],
        "sink_ids": [sink["id"]] if sink.get("id") else [],
        "source_kind": source.get("kind"),
        "boundary_kind": boundary.get("kind"),
        "sink_kind": sink.get("kind"),
        "score": candidate.get("score"),
        "priority": candidate.get("priority"),
        "question": candidate.get("question"),
        "reason": candidate_policy["reason"],
        "policy_id": candidate_policy["policy_id"],
        "finding_role": candidate_policy["finding_role"],
        "entry_status": candidate_policy["entry_status"],
        "reportability": candidate_policy["reportability"],
        "hold_for_chain": bool(candidate_policy.get("hold_for_chain")),
        "policy": candidate_policy,
    }
    return record


def _next_rejected_index(rejected_candidates: list[dict[str, Any]]) -> int:
    indexes = [
        int(match.group(1))
        for item in rejected_candidates
        if (match := re.match(r"^R(\d+)$", str(item.get("id") or "").strip()))
    ]
    return max(indexes, default=0) + 1


def _appmap_surface_kinds(candidate: dict[str, Any]) -> set[str]:
    kinds: set[str] = set()
    for key in ("source", "boundary", "transform", "sink"):
        surface = candidate.get(key)
        if not isinstance(surface, dict):
            continue
        normalized = _normalize_policy_kind(surface.get("kind"))
        if normalized:
            kinds.add(normalized)
    return kinds


def _deprioritized_policy_kinds(policy: HuntingPolicy) -> set[str]:
    kinds: set[str] = set()
    for value in policy.deprioritize:
        normalized = _normalize_policy_kind(value)
        if normalized:
            kinds.add(normalized)
    return kinds


def _normalize_policy_kind(value: Any) -> str:
    return str(value or "").strip().lower().replace("_", "-")


def _candidate_has_app_entry_evidence(candidate: dict[str, Any], deprioritized: set[str]) -> bool:
    explicit = candidate.get("app_entry_evidence")
    if explicit is not None:
        return bool(explicit)
    if candidate.get("app_entry_evidence_ids"):
        return True
    source = candidate.get("source") if isinstance(candidate.get("source"), dict) else {}
    source_kind = _normalize_policy_kind(source.get("kind"))
    return bool(source_kind and source_kind not in deprioritized)


def _candidate_has_standalone_critical_evidence(candidate: dict[str, Any]) -> bool:
    for key in ("standalone_critical_impact", "policy_standalone_critical", "standalone_critical"):
        value = candidate.get(key)
        if value is not None:
            return bool(value)
    return False


def _candidate_entry_vector(candidate: dict[str, Any]) -> str:
    source = candidate.get("source") if isinstance(candidate.get("source"), dict) else {}
    file_name = str(source.get("file") or "").strip()
    line = source.get("line")
    kind = str(source.get("kind") or "source").strip()
    if file_name and line:
        return f"{kind} at {file_name}:{line}"
    if file_name:
        return f"{kind} at {file_name}"
    return kind or "source"


def inject_policy_metadata_into_markdown(
    text: str,
    policy: HuntingPolicy | dict[str, Any] | None,
) -> str:
    metadata = policy_artifact_metadata(policy)
    if not metadata or "\n- Hunting policy:" in text:
        return text

    lines = [f"- Hunting policy: {metadata['hunting_policy_id']}"]
    posture = str(metadata.get("hunting_policy_posture") or "").strip()
    if posture:
        lines.append(f"- Hunting posture: {posture}")

    for marker in ("\n- AppMap run root:", "\n- AppMap run id:", "\n- Status:"):
        index = text.find(marker)
        if index < 0:
            continue
        line_end = text.find("\n", index + 1)
        if line_end < 0:
            return text.rstrip() + "\n" + "\n".join(lines) + "\n"
        return text[:line_end] + "\n" + "\n".join(lines) + text[line_end:]
    return text
