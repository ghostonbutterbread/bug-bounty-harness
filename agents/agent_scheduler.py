"""Policy-aware agent scheduling primitives for dynamic hunt runtimes.

This module is intentionally pure: it does not spawn agents, write coverage, or
import zero_day_team.  Runtime entrypoints can adapt their profile objects into
AgentAssignment instances, plan a wave, then emit scheduler decisions through
existing coverage/logging code.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Literal, Sequence

Decision = Literal["spawn", "defer", "skip"]
CoverageStatus = Literal[
    "untested",
    "queued",
    "running",
    "covered",
    "uncovered",
    "deferred",
    "skipped",
    "timeout",
    "crashed",
    "invalid_output",
    "review_rejected",
]
SchedulerMode = Literal["off", "legacy", "policy-aware"]

CANONICAL_SURFACE_FAMILIES: tuple[str, ...] = (
    "ipc-bridge",
    "hostrpc",
    "preload-native-bridge",
    "ui-dialog-window",
    "navigation-popup",
    "custom-protocol-deeplink",
    "file-ingestion-import",
    "download-export-filesystem",
    "rendering-content-parser",
    "auth-session-callback",
    "plugin-template-integration",
    "updater-installer-relaunch",
    "native-parser-addon",
    "network-fetch-ssrf",
    "storage-cache-state",
    "local-service-helper-bridge",
    "unknown",
)

APPLICATION_ENTRY_FAMILIES: set[str] = {
    "ui-dialog-window",
    "navigation-popup",
    "custom-protocol-deeplink",
    "file-ingestion-import",
    "download-export-filesystem",
    "rendering-content-parser",
    "auth-session-callback",
    "plugin-template-integration",
    "storage-cache-state",
    "network-fetch-ssrf",
    "local-service-helper-bridge",
}

AMPLIFIER_FAMILIES: set[str] = {
    "ipc-bridge",
    "hostrpc",
    "preload-native-bridge",
    "updater-installer-relaunch",
    "native-parser-addon",
}

TERMINAL_COVERED_STATUSES: set[str] = {"covered", "skipped"}

PRIORITY_SCORES: dict[str, float] = {
    "critical": 100.0,
    "crit": 100.0,
    "p0": 100.0,
    "high": 80.0,
    "p1": 80.0,
    "medium": 55.0,
    "med": 55.0,
    "p2": 55.0,
    "low": 30.0,
    "p3": 30.0,
    "info": 10.0,
    "informational": 10.0,
}

MASTER_AGENT_BY_FAMILY: dict[str, str] = {
    "ui-dialog-window": "ui-dialog-window-master",
    "file-ingestion-import": "file-ingestion-import-master",
    "navigation-popup": "navigation-popup-master",
    "custom-protocol-deeplink": "custom-protocol-deeplink-master",
    "download-export-filesystem": "download-export-filesystem-master",
    "auth-session-callback": "auth-session-callback-master",
    "rendering-content-parser": "rendering-content-parser-master",
    "storage-cache-state": "storage-cache-state-master",
    "ipc-bridge": "ipc-hostrpc-amplifier-master",
    "hostrpc": "ipc-hostrpc-amplifier-master",
    "preload-native-bridge": "ipc-hostrpc-amplifier-master",
    "native-parser-addon": "native-parser-device-master",
    "updater-installer-relaunch": "updater-installer-persistence-master",
    "local-service-helper-bridge": "local-service-helper-bridge-master",
    "network-fetch-ssrf": "network-sync-ssrf-master",
    "plugin-template-integration": "plugin-template-integration-master",
    "unknown": "unknown-surface-master",
}

# Ordered before substring inference.  Specific terms must beat broad ones.
FAMILY_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("hostrpc", ("hostrpc", "host-rpc", "host rpc", "executehostfunction", "host service")),
    ("preload-native-bridge", ("preload", "contextbridge", "native bridge", "native-bridge")),
    ("ipc-bridge", ("ipc", "ipcmain", "ipcrenderer", "messageport", "message port")),
    ("auth-session-callback", ("oauth", "oidc", "sso", "auth callback", "login callback", "session binding", "state nonce", "pkce", "token", "account", "tenant", "team switch")),
    ("custom-protocol-deeplink", ("deeplink", "deep link", "custom protocol", "url scheme", "://", "protocol handler", "startup arg", "command line", "file association")),
    ("navigation-popup", ("window.open", "popup", "opener", "openexternal", "shell.openexternal", "webview", "navigation", "redirect", "new-window", "browserview")),
    ("download-export-filesystem", ("download", "export", "save as", "save-dialog", "reveal", "content-disposition", "filesystem", "file system", "local file", "print-to-pdf")),
    ("file-ingestion-import", ("import", "drag", "drop", "attachment", "archive", "extract", "file open", "open file", "parser handoff", "clipboard file")),
    ("ui-dialog-window", ("dialog", "modal", "permission prompt", "prompt", "double-click", "share", "invite", "context menu", "notification", "open/reveal", "user intent")),
    ("rendering-content-parser", ("xss", "render", "html", "markdown", "template", "svg", "rich text", "preview", "sanitize", "dom", "content parser")),
    ("plugin-template-integration", ("plugin", "extension", "template integration", "addon system", "macro")),
    ("updater-installer-relaunch", ("updater", "installer", "update", "relaunch", "dll", "search order", "privileged helper", "package signature")),
    ("native-parser-addon", ("nativeimage", "native image", "native addon", "node addon", "jni", "codec", "ffmpeg", "media parser", "pdf", "camera", "microphone", "screen capture")),
    ("local-service-helper-bridge", ("localhost", "127.0.0.1", "named pipe", "unix socket", "websocket", "helper daemon", "native messaging", "dns rebinding", "debug port")),
    ("network-fetch-ssrf", ("ssrf", "fetch", "webhook", "url import", "link preview", "proxy", "credentialed request")),
    ("storage-cache-state", ("storage", "cache", "sqlite", "indexeddb", "localstorage", "secret", "keychain", "token store", "logs", "crash report", "logout residue")),
)

STATIC_PROFILE_FAMILY_HINTS: dict[str, str] = {
    "dom-xss": "rendering-content-parser",
    "path-traversal": "file-ingestion-import",
    "ssrf": "network-fetch-ssrf",
    "node-integration": "preload-native-bridge",
    "ipc-trust-boundary": "ipc-bridge",
    "ipc_rpc_handler": "ipc-bridge",
    "auth_authz_handler": "auth-session-callback",
    "file_io_handler": "file-ingestion-import",
    "input_handler": "ui-dialog-window",
    "exec-sink-reachability": "ipc-bridge",
    "native-module-abuse": "native-parser-addon",
    "memory-unsafe-parser": "native-parser-addon",
    "unsafe-deserialization": "rendering-content-parser",
}


@dataclass(frozen=True, slots=True)
class AgentAssignment:
    profile: Any
    key: str
    source: str = "dynamic"
    hypothesis_id: str | None = None
    source_spec_path: str | None = None
    priority: str | None = None
    priority_score: float = 0.0
    surface_family: str = "unknown"
    secondary_families: tuple[str, ...] = ()
    policy_id: str | None = None
    policy_rank: int = 0
    coverage_status: CoverageStatus = "untested"
    novelty_score: float = 0.0
    redundancy_penalty: float = 0.0
    final_score: float = 0.0
    decision: Decision | None = None
    decision_reason: str | None = None
    family_role: str = "unknown"
    assigned_hypotheses: tuple[dict[str, Any], ...] = ()
    scheduler_metadata: dict[str, Any] = field(default_factory=dict)
    input_index: int = 0

    def with_decision(self, decision: Decision, reason: str) -> "AgentAssignment":
        return replace(self, decision=decision, decision_reason=reason)


@dataclass(frozen=True, slots=True)
class SchedulerConfig:
    mode: SchedulerMode = "policy-aware"
    agent_wave_size: int | Literal["all"] = "all"
    max_agents: int | None = None
    concurrent_agents: int | None = None
    max_per_surface_family: int = 2
    max_amplifier_family_first_wave: int = 3
    max_hypotheses_per_master_agent: int = 6
    prefer_deferred: bool = True
    category_master_mode: bool = False
    fresh: bool = False


@dataclass(frozen=True, slots=True)
class SchedulerPlan:
    selected: tuple[AgentAssignment, ...]
    deferred: tuple[AgentAssignment, ...]
    skipped: tuple[AgentAssignment, ...]
    all_assignments: tuple[AgentAssignment, ...]
    mode: SchedulerMode

    def decisions(self) -> tuple[AgentAssignment, ...]:
        return self.selected + self.deferred + self.skipped

    def summary(self) -> dict[str, Any]:
        families = sorted({item.surface_family for item in self.selected})
        return {
            "mode": self.mode,
            "selected": len(self.selected),
            "deferred": len(self.deferred),
            "skipped": len(self.skipped),
            "families": families,
        }


def assignment_from_profile(profile: Any, *, source: str | None = None, policy: Any | None = None, input_index: int = 0) -> AgentAssignment:
    """Adapt a zero_day_team/BaseTeam-style profile object into an assignment."""

    metadata = _profile_metadata(profile)
    if metadata.get("brainstorm_cluster_assignments"):
        key = _string(getattr(profile, "key", ""))
    else:
        key = _string(metadata.get("brainstorm_agent_key") or metadata.get("agent_key") or getattr(profile, "key", ""))
    key = key or f"profile-{input_index}"
    hypothesis_id = _string(metadata.get("hypothesis_id")) or None
    source_spec_path = _string(metadata.get("source_spec_path") or metadata.get("brainstorm_spec")) or None
    inferred_source = source or _infer_source(metadata)
    priority = _string(metadata.get("priority") or metadata.get("severity")) or None
    family, secondary = infer_surface_family(profile, metadata=metadata)
    family_role = _assignment_family_role(family, metadata)
    priority_score = _priority_score(priority)
    policy_rank = _policy_rank_for(family, policy=policy)
    novelty_score = _float(metadata.get("novelty_score"), 0.0)
    redundancy_penalty = _float(metadata.get("redundancy_penalty"), 0.0)
    coverage_status = _coverage_status(metadata.get("coverage_status"))
    final_score = _score_assignment(
        priority_score=priority_score,
        policy_rank=policy_rank,
        novelty_score=novelty_score,
        redundancy_penalty=redundancy_penalty,
        family_role=family_role,
        metadata=metadata,
        coverage_status=coverage_status,
    )
    assigned_hypotheses = _assigned_hypothesis_records(profile, metadata, family)
    return AgentAssignment(
        profile=profile,
        key=key,
        source=inferred_source,
        hypothesis_id=hypothesis_id,
        source_spec_path=source_spec_path,
        priority=priority,
        priority_score=priority_score,
        surface_family=family,
        secondary_families=tuple(secondary),
        policy_id=_policy_id(policy) or _string(metadata.get("hunting_policy_id")) or None,
        policy_rank=policy_rank,
        coverage_status=coverage_status,
        novelty_score=novelty_score,
        redundancy_penalty=redundancy_penalty,
        final_score=final_score,
        family_role=family_role,
        assigned_hypotheses=assigned_hypotheses,
        scheduler_metadata={"inference_text": _profile_text(profile, metadata), "profile_metadata": metadata},
        input_index=input_index,
    )


def assignments_from_profiles(profiles: Sequence[Any], *, source: str | None = None, policy: Any | None = None) -> list[AgentAssignment]:
    return [assignment_from_profile(profile, source=source, policy=policy, input_index=index) for index, profile in enumerate(profiles)]


def infer_surface_family(profile: Any | None = None, *, metadata: dict[str, Any] | None = None) -> tuple[str, tuple[str, ...]]:
    metadata = dict(metadata or {})
    explicit = _canonical_family(
        metadata.get("brainstorm_surface_family")
        or metadata.get("surface_family")
        or metadata.get("scheduler_surface_family")
    )
    secondary = [_canonical_family(item) for item in _as_list(metadata.get("secondary_families") or metadata.get("surface_families"))]
    secondary = [item for item in secondary if item and item != explicit]
    if explicit:
        return explicit, tuple(dict.fromkeys(secondary))

    appmap_family = _family_from_appmap_metadata(metadata)
    if appmap_family:
        return appmap_family, tuple(dict.fromkeys(secondary))

    text = _profile_text(profile, metadata)
    matches = _family_matches(text)
    key = _string(metadata.get("brainstorm_agent_key") or metadata.get("agent_key") or getattr(profile, "key", "")).casefold()
    static_family = STATIC_PROFILE_FAMILY_HINTS.get(key.replace("-", "_")) or STATIC_PROFILE_FAMILY_HINTS.get(key)
    if static_family and static_family not in matches:
        matches.append(static_family)
    if matches:
        primary = _choose_primary_family(matches, metadata)
        return primary, tuple(dict.fromkeys([item for item in matches if item != primary]))
    return "unknown", tuple(dict.fromkeys(secondary))


def _assignment_family_role(surface_family: str, metadata: dict[str, Any]) -> str:
    finding_role = _normalize_token(metadata.get("finding_role"))
    if finding_role == "notes-only":
        return "notes_only"
    if finding_role == "entry":
        return "application-entry"
    if finding_role in {"chain", "hardening"}:
        return finding_role
    if finding_role == "amplifier":
        return "amplifier"
    return family_role_for(surface_family)


def family_role_for(surface_family: str) -> str:
    if surface_family in APPLICATION_ENTRY_FAMILIES:
        return "application-entry"
    if surface_family in AMPLIFIER_FAMILIES:
        return "amplifier"
    return "unknown"


def bundle_category_masters(
    assignments: Sequence[AgentAssignment],
    *,
    max_hypotheses_per_master_agent: int = 6,
    keep_standalone_critical: bool = True,
) -> list[AgentAssignment]:
    """Group related hypothesis assignments into broad category-master assignments.

    The returned assignment keeps the first profile as a runtime placeholder and
    records every covered hypothesis in assigned_hypotheses. Runtime wiring can
    later convert this into a merged prompt/profile object.
    """

    if max_hypotheses_per_master_agent <= 1:
        return list(assignments)

    grouped: dict[tuple[str, tuple[str, ...]], list[AgentAssignment]] = {}
    passthrough: list[AgentAssignment] = []
    for item in assignments:
        if keep_standalone_critical and _is_standalone_critical(item):
            passthrough.append(item)
            continue
        if not item.hypothesis_id:
            passthrough.append(item)
            continue
        focus_key = tuple(sorted(_focus_globs(item.profile)))
        grouped.setdefault((item.surface_family, focus_key), []).append(item)

    bundled: list[AgentAssignment] = []
    for (family, _focus_key), group in grouped.items():
        for offset in range(0, len(group), max_hypotheses_per_master_agent):
            chunk = group[offset : offset + max_hypotheses_per_master_agent]
            if len(chunk) == 1:
                bundled.append(chunk[0])
                continue
            first = chunk[0]
            hypotheses: list[dict[str, Any]] = []
            for assignment in chunk:
                if assignment.assigned_hypotheses:
                    hypotheses.extend(assignment.assigned_hypotheses)
                else:
                    hypotheses.append(_assignment_hypothesis_record(assignment))
            key = MASTER_AGENT_BY_FAMILY.get(family, f"{family}-master")
            priority_score = max(item.priority_score for item in chunk)
            final_score = max(item.final_score for item in chunk) + min(len(chunk), max_hypotheses_per_master_agent)
            bundled.append(
                replace(
                    first,
                    key=key,
                    hypothesis_id=None,
                    priority_score=priority_score,
                    final_score=final_score,
                    assigned_hypotheses=tuple(hypotheses),
                    scheduler_metadata={
                        **first.scheduler_metadata,
                        "category_master": True,
                        "member_agent_keys": [item.key for item in chunk],
                        "member_hypothesis_ids": [item.hypothesis_id for item in chunk if item.hypothesis_id],
                    },
                )
            )
    return sorted([*passthrough, *bundled], key=lambda item: item.input_index)


def plan_agent_wave(assignments: Sequence[AgentAssignment], config: SchedulerConfig | None = None) -> SchedulerPlan:
    config = config or SchedulerConfig()
    normalized = list(assignments)

    if config.category_master_mode:
        normalized = bundle_category_masters(
            normalized,
            max_hypotheses_per_master_agent=config.max_hypotheses_per_master_agent,
        )

    if config.mode in {"off", "legacy"}:
        selected = tuple(item.with_decision("spawn", "scheduler disabled; preserving legacy order") for item in normalized)
        if config.max_agents is not None:
            limit = max(0, int(config.max_agents))
            deferred = tuple(item.with_decision("defer", "max agents cap reached") for item in normalized[limit:])
            selected = selected[:limit]
            return SchedulerPlan(
                selected=selected,
                deferred=deferred,
                skipped=(),
                all_assignments=tuple(selected + deferred),
                mode=config.mode,
            )
        return SchedulerPlan(selected=selected, deferred=(), skipped=(), all_assignments=selected, mode=config.mode)

    skipped: list[AgentAssignment] = []
    eligible: list[AgentAssignment] = []
    for item in normalized:
        if not config.fresh and item.coverage_status in TERMINAL_COVERED_STATUSES:
            skipped.append(item.with_decision("skip", f"terminal coverage status: {item.coverage_status}"))
        else:
            eligible.append(item)

    wave_size = len(eligible) if config.agent_wave_size == "all" else max(0, int(config.agent_wave_size))
    max_agents = None if config.max_agents is None else max(0, int(config.max_agents))
    selection_limit = wave_size if max_agents is None else min(wave_size, max_agents)
    if selection_limit >= len(eligible):
        selected = [
            item.with_decision("spawn", _selection_reason(item, 1))
            for item in _ranked(eligible, prefer_deferred=config.prefer_deferred)
        ]
        return SchedulerPlan(
            selected=tuple(selected),
            deferred=(),
            skipped=tuple(skipped),
            all_assignments=tuple(selected + skipped),
            mode=config.mode,
        )

    selected: list[AgentAssignment] = []
    deferred: list[AgentAssignment] = []
    family_counts: dict[str, int] = {}
    amplifier_selected = 0
    remaining = _ranked(eligible, prefer_deferred=config.prefer_deferred)

    while remaining and len(selected) < selection_limit:
        choice_index = _next_selectable_index(
            remaining,
            family_counts=family_counts,
            amplifier_selected=amplifier_selected,
            config=config,
        )
        if choice_index is None:
            choice_index = 0  # all remaining are capped; fall back instead of returning empty
        item = remaining.pop(choice_index)
        family_counts[item.surface_family] = family_counts.get(item.surface_family, 0) + 1
        if item.family_role == "amplifier":
            amplifier_selected += 1
        selected.append(item.with_decision("spawn", _selection_reason(item, family_counts[item.surface_family])))

    for item in remaining:
        deferred.append(
            item.with_decision(
                "defer",
                _defer_reason(
                    item,
                    family_counts,
                    amplifier_selected,
                    config,
                    selected_count=len(selected),
                ),
            )
        )

    return SchedulerPlan(
        selected=tuple(selected),
        deferred=tuple(deferred),
        skipped=tuple(skipped),
        all_assignments=tuple(selected + deferred + skipped),
        mode=config.mode,
    )


def decision_events(plan: SchedulerPlan, *, scheduler_wave_id: str | None = None, run_id: str | None = None) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for item in plan.decisions():
        if len(item.assigned_hypotheses) > 1:
            for hypothesis in item.assigned_hypotheses:
                events.append(
                    _decision_event(
                        item,
                        plan=plan,
                        scheduler_wave_id=scheduler_wave_id,
                        run_id=run_id,
                        hypothesis=hypothesis,
                    )
                )
            continue
        events.append(_decision_event(item, plan=plan, scheduler_wave_id=scheduler_wave_id, run_id=run_id))
    return events


def _decision_event(
    item: AgentAssignment,
    *,
    plan: SchedulerPlan,
    scheduler_wave_id: str | None,
    run_id: str | None,
    hypothesis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    skip_event = "agent_skipped_covered" if item.coverage_status in TERMINAL_COVERED_STATUSES else "agent_skipped_policy_budget"
    event_name = {
        "spawn": "agent_selected",
        "defer": "agent_deferred",
        "skip": skip_event,
    }.get(item.decision or "", "agent_scheduled")
    hypothesis = dict(hypothesis or {})
    base = {
        "event": event_name,
        "agent_key": hypothesis.get("agent_key") or item.key,
        "scheduler_master_agent_key": item.key if hypothesis else None,
        "hypothesis_id": hypothesis.get("hypothesis_id") or item.hypothesis_id,
        "source_spec_path": hypothesis.get("source_spec_path") or item.source_spec_path,
        "surface_family": hypothesis.get("surface_family") or item.surface_family,
        "secondary_families": list(item.secondary_families),
        "family_role": item.family_role,
        "policy_id": item.policy_id,
        "coverage_status": item.coverage_status,
        "final_score": item.final_score,
        "decision_reason": item.decision_reason,
        "scheduler_mode": plan.mode,
        "scheduler_wave_id": scheduler_wave_id,
        "run_id": run_id,
    }
    for key in (
        "brainstorm_spec",
        "brainstorm_agent_key",
        "appmap_candidate_id",
        "candidate_id",
        "appmap_context_packet",
        "appmap_run_id",
        "snapshot_id",
        "snapshot_version",
        "evidence_refs",
        "tags",
    ):
        if hypothesis.get(key) not in (None, "", []):
            base[key] = hypothesis[key]
    metadata = item.scheduler_metadata.get("profile_metadata") if isinstance(item.scheduler_metadata, dict) else None
    if isinstance(metadata, dict):
        metadata_key_map = {
            "brainstorm_spec": "brainstorm_spec",
            "brainstorm_agent_key": "brainstorm_agent_key",
            "appmap_candidate_id": "appmap_candidate_id",
            "appmap_context_packet": "appmap_context_packet",
            "appmap_run_id": "appmap_run_id",
            "snapshot_id": "snapshot_id",
            "_snapshot_id": "snapshot_id",
            "snapshot_version": "snapshot_version",
            "_snapshot_version": "snapshot_version",
            "agent_metadata": "agent_metadata",
            "agent_spec": "agent_spec",
        }
        for metadata_key, event_key in metadata_key_map.items():
            if event_key not in base and metadata.get(metadata_key) not in (None, ""):
                base[event_key] = metadata[metadata_key]
    return {key: value for key, value in base.items() if value not in (None, "", [])}

def _next_selectable_index(
    remaining: Sequence[AgentAssignment],
    *,
    family_counts: dict[str, int],
    amplifier_selected: int,
    config: SchedulerConfig,
) -> int | None:
    enough_family_diversity = len({item.surface_family for item in remaining}) > 1
    enough_role_diversity = any(item.family_role != "amplifier" for item in remaining)
    for index, item in enumerate(remaining):
        family_count = family_counts.get(item.surface_family, 0)
        if family_count >= config.max_per_surface_family and enough_family_diversity and not _is_standalone_critical(item):
            continue
        if (
            item.family_role == "amplifier"
            and amplifier_selected >= config.max_amplifier_family_first_wave
            and enough_role_diversity
            and not _is_standalone_critical(item)
        ):
            continue
        return index
    return None


def _ranked(assignments: Sequence[AgentAssignment], *, prefer_deferred: bool) -> list[AgentAssignment]:
    return sorted(
        assignments,
        key=lambda item: (
            0 if prefer_deferred and item.coverage_status == "deferred" else 1,
            -item.final_score,
            0 if item.family_role == "application-entry" else 1,
            item.surface_family,
            item.input_index,
            item.key,
        ),
    )


def _selection_reason(item: AgentAssignment, family_count: int) -> str:
    parts = ["selected"]
    if item.family_role == "application-entry":
        parts.append("application-entry family")
    elif item.family_role == "amplifier":
        parts.append("amplifier allowed")
    if item.coverage_status == "deferred":
        parts.append("resumed from deferred")
    if family_count > 1:
        parts.append(f"family slot {family_count}")
    return "; ".join(parts)


def _defer_reason(
    item: AgentAssignment,
    family_counts: dict[str, int],
    amplifier_selected: int,
    config: SchedulerConfig,
    *,
    selected_count: int | None = None,
) -> str:
    max_agents = None if config.max_agents is None else max(0, int(config.max_agents))
    if max_agents is not None and selected_count is not None and selected_count >= max_agents:
        return "max agents cap reached"
    if item.family_role == "amplifier" and amplifier_selected >= config.max_amplifier_family_first_wave and not _is_standalone_critical(item):
        return "first-wave amplifier family cap reached"
    if family_counts.get(item.surface_family, 0) >= config.max_per_surface_family and not _is_standalone_critical(item):
        return "first-wave surface-family cap reached"
    return "outside configured agent wave size"


def _score_assignment(
    *,
    priority_score: float,
    policy_rank: int,
    novelty_score: float,
    redundancy_penalty: float,
    family_role: str,
    metadata: dict[str, Any],
    coverage_status: str,
) -> float:
    score = priority_score + novelty_score - redundancy_penalty + float(policy_rank)
    if family_role == "application-entry":
        score += 12.0
    elif family_role == "amplifier":
        score -= 8.0
    # Deferred preference is applied by _ranked(prefer_deferred=...), not by score,
    # so --no-prefer-deferred can fully disable resume bias.
    if _truthy(metadata.get("standalone_critical") or metadata.get("proven_app_entry") or metadata.get("app_entry_evidence")):
        score += 25.0
    return score


def _policy_rank_for(family: str, *, policy: Any | None) -> int:
    if policy is None:
        return 0
    enabled = _policy_get(policy, "enabled")
    if enabled is False:
        return 0
    if enabled is None and not bool(policy):
        return 0
    prioritize = [_normalize_token(item) for item in _as_list(_policy_get(policy, "prioritize"))]
    deprioritize = [_normalize_token(item) for item in _as_list(_policy_get(policy, "deprioritize"))]
    family_tokens = set(_family_policy_tokens(family))
    if family_tokens & set(prioritize):
        return 20
    if family_tokens & set(deprioritize):
        return -15
    return 0


def _family_policy_tokens(family: str) -> tuple[str, ...]:
    return {
        "ui-dialog-window": ("dialog", "window", "ui"),
        "navigation-popup": ("navigation", "openexternal", "popup"),
        "custom-protocol-deeplink": ("protocol-handlers", "custom-url-handlers", "deeplink"),
        "file-ingestion-import": ("file-ingestion", "parser-boundaries", "import"),
        "download-export-filesystem": ("import-export", "local-file-manipulation", "download-save-reveal"),
        "rendering-content-parser": ("rendering", "parser-boundaries"),
        "auth-session-callback": ("auth-flows", "auth-session-helpers"),
        "plugin-template-integration": ("plugin-template-systems",),
        "ipc-bridge": ("ipc",),
        "hostrpc": ("hostrpc",),
        "preload-native-bridge": ("preload", "native-bridge"),
        "native-parser-addon": ("native-parsers", "media-access"),
        "updater-installer-relaunch": ("updater-relaunch",),
        "network-fetch-ssrf": ("ssrf", "network"),
        "storage-cache-state": ("storage", "cache"),
    }.get(family, (family,))


def _family_matches(text: str) -> list[str]:
    lowered = text.casefold()
    matches: list[str] = []
    for family, keywords in FAMILY_KEYWORDS:
        if any(keyword.casefold() in lowered for keyword in keywords):
            matches.append(family)
    return matches


def _choose_primary_family(matches: list[str], metadata: dict[str, Any]) -> str:
    app_matches = [family for family in matches if family in APPLICATION_ENTRY_FAMILIES]
    if not app_matches:
        return matches[0]
    amplifier_matches = [family for family in matches if family in AMPLIFIER_FAMILIES]
    if not amplifier_matches:
        return app_matches[0]
    if any(_truthy(metadata.get(key)) for key in ("app_entry_evidence", "proven_app_entry", "has_app_entry")):
        return app_matches[0]
    for key in ("brainstorm_surface", "surface", "surface_type", "title", "hypothesis_title", "brainstorm_tags", "tags"):
        field_text = "\n".join(_string(item) for item in _as_list(metadata.get(key)))
        if any(family in APPLICATION_ENTRY_FAMILIES for family in _family_matches(field_text)):
            return app_matches[0]
    return matches[0]


def _family_from_appmap_metadata(metadata: dict[str, Any]) -> str:
    for key in ("appmap_surface_family", "appmap_family", "scheduler_surface_family"):
        family = _canonical_family(metadata.get(key))
        if family:
            return family
    packet = metadata.get("appmap_context_packet")
    if isinstance(packet, dict):
        candidate = packet.get("candidate") if isinstance(packet.get("candidate"), dict) else {}
        policy = candidate.get("policy") if isinstance(candidate.get("policy"), dict) else {}
        evidence = packet.get("evidence") if isinstance(packet.get("evidence"), dict) else {}
        if policy.get("finding_role") == "entry" or policy.get("app_entry_evidence"):
            for evidence_key in ("source", "boundary"):
                surface = evidence.get(evidence_key) if isinstance(evidence.get(evidence_key), dict) else {}
                family = _family_from_appmap_kind(surface.get("kind"))
                if family in APPLICATION_ENTRY_FAMILIES:
                    return family
        for evidence_key in ("source", "boundary", "sink"):
            surface = evidence.get(evidence_key) if isinstance(evidence.get(evidence_key), dict) else {}
            family = _family_from_appmap_kind(surface.get("kind"))
            if family:
                return family
    for key in ("source_kind", "boundary_kind", "sink_kind"):
        family = _family_from_appmap_kind(metadata.get(key))
        if family:
            return family
    return ""


def _family_from_appmap_kind(value: Any) -> str:
    raw = _normalize_token(value)
    mapping = {
        "renderer-ipc": "ipc-bridge",
        "ipc": "ipc-bridge",
        "ipc-main": "ipc-bridge",
        "hostrpc": "hostrpc",
        "preload": "preload-native-bridge",
        "contextbridge": "preload-native-bridge",
        "route": "navigation-popup",
        "navigation": "navigation-popup",
        "openexternal": "navigation-popup",
        "protocol": "custom-protocol-deeplink",
        "file-ingestion": "file-ingestion-import",
        "parser-boundary": "file-ingestion-import",
        "download": "download-export-filesystem",
        "export": "download-export-filesystem",
        "rendering": "rendering-content-parser",
        "dom-sink": "rendering-content-parser",
        "auth": "auth-session-callback",
        "oauth": "auth-session-callback",
        "storage": "storage-cache-state",
        "local-service": "local-service-helper-bridge",
        "ssrf": "network-fetch-ssrf",
    }
    return mapping.get(raw, _canonical_family(raw))


def _profile_text(profile: Any | None, metadata: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "brainstorm_surface",
        "surface",
        "surface_type",
        "expected_chain",
        "title",
        "description",
        "brainstorm_agent_key",
        "agent_key",
        "hunting_notes",
    ):
        parts.extend(_as_list(metadata.get(key)))
    for key in ("brainstorm_tags", "tags", "evidence", "appmap_refs", "appmap_surface_refs", "focus_files", "focus_files_glob"):
        parts.extend(_as_list(metadata.get(key)))
    if profile is not None:
        for attr in ("key", "display_name", "description", "reasoning", "prompt_addendum"):
            parts.append(_string(getattr(profile, attr, "")))
        for attr in ("entry_questions", "cross_questions", "sink_categories", "focus_globs"):
            parts.extend(_as_list(getattr(profile, attr, ())))
    return "\n".join(item for item in (_string(part) for part in parts) if item)


def _profile_metadata(profile: Any) -> dict[str, Any]:
    metadata = getattr(profile, "brainstorm_metadata", None)
    return dict(metadata or {}) if isinstance(metadata, dict) else {}


def _assigned_hypothesis_records(profile: Any, metadata: dict[str, Any], family: str) -> tuple[dict[str, Any], ...]:
    cluster_assignments = [item for item in _as_list(metadata.get("brainstorm_cluster_assignments")) if isinstance(item, dict)]
    if cluster_assignments:
        records: list[dict[str, Any]] = []
        for assignment in cluster_assignments:
            assignment_family, _secondary = infer_surface_family(profile, metadata=assignment)
            records.append(_hypothesis_record(profile, assignment, assignment_family or family))
        return tuple(records)
    if metadata.get("hypothesis_id"):
        return (_hypothesis_record(profile, metadata, family),)
    return ()


def _hypothesis_record(profile: Any, metadata: dict[str, Any], family: str) -> dict[str, Any]:
    record = {
        "hypothesis_id": _string(metadata.get("hypothesis_id")),
        "agent_key": _string(metadata.get("brainstorm_agent_key") or metadata.get("agent_key") or getattr(profile, "key", "")),
        "brainstorm_agent_key": _string(metadata.get("brainstorm_agent_key") or metadata.get("agent_key") or getattr(profile, "key", "")),
        "source_spec_path": _string(metadata.get("source_spec_path") or metadata.get("brainstorm_spec")),
        "brainstorm_spec": _string(metadata.get("brainstorm_spec") or metadata.get("source_spec_path")),
        "title": _string(metadata.get("hypothesis_title") or metadata.get("title") or getattr(profile, "display_name", "")),
        "priority": _string(metadata.get("priority") or metadata.get("severity")),
        "expected_chain": _string(metadata.get("expected_chain")),
        "surface_family": family,
        "appmap_candidate_id": _string(metadata.get("appmap_candidate_id") or metadata.get("candidate_id")),
        "candidate_id": _string(metadata.get("candidate_id") or metadata.get("appmap_candidate_id")),
        "appmap_context_packet": metadata.get("appmap_context_packet"),
        "appmap_run_id": _string(metadata.get("appmap_run_id")),
        "snapshot_id": _string(metadata.get("snapshot_id") or metadata.get("_snapshot_id")),
        "snapshot_version": _string(metadata.get("snapshot_version") or metadata.get("_snapshot_version")),
        "evidence_refs": tuple(_as_list(metadata.get("evidence_refs") or metadata.get("evidence"))),
        "tags": tuple(_as_list(metadata.get("brainstorm_tags") or metadata.get("tags"))),
        "focus_files_glob": _focus_globs(profile) or tuple(_as_list(metadata.get("focus_files_glob") or metadata.get("focus_files"))),
    }
    return {key: value for key, value in record.items() if value not in (None, "", (), [])}


def _assignment_hypothesis_record(assignment: AgentAssignment) -> dict[str, Any]:
    return {
        "hypothesis_id": assignment.hypothesis_id,
        "agent_key": assignment.key,
        "priority": assignment.priority,
        "surface_family": assignment.surface_family,
    }


def _is_standalone_critical(item: AgentAssignment) -> bool:
    metadata = item.scheduler_metadata or {}
    profile_metadata = metadata.get("profile_metadata") if isinstance(metadata, dict) else {}
    if isinstance(profile_metadata, dict) and any(
        _truthy(profile_metadata.get(key))
        for key in ("standalone_critical", "standalone_critical_impact", "policy_standalone_critical")
    ):
        return True
    text = _string(metadata.get("inference_text"))
    return item.priority_score >= PRIORITY_SCORES["critical"] or "standalone critical" in text.casefold()


def _focus_globs(profile: Any) -> tuple[str, ...]:
    return tuple(_string(item) for item in _as_list(getattr(profile, "focus_globs", ())) if _string(item))


def _canonical_family(value: Any) -> str:
    raw = _normalize_token(value)
    aliases = {
        "ipc": "ipc-bridge",
        "ipc-rpc": "ipc-bridge",
        "host-rpc": "hostrpc",
        "preload": "preload-native-bridge",
        "native-bridge": "preload-native-bridge",
        "ui-dialog": "ui-dialog-window",
        "dialog": "ui-dialog-window",
        "navigation": "navigation-popup",
        "popup": "navigation-popup",
        "protocol": "custom-protocol-deeplink",
        "deeplink": "custom-protocol-deeplink",
        "file-import": "file-ingestion-import",
        "download-export": "download-export-filesystem",
        "rendering": "rendering-content-parser",
        "auth": "auth-session-callback",
        "oauth": "auth-session-callback",
        "plugin": "plugin-template-integration",
        "updater": "updater-installer-relaunch",
        "native-parser": "native-parser-addon",
        "ssrf": "network-fetch-ssrf",
        "storage": "storage-cache-state",
        "local-service": "local-service-helper-bridge",
    }
    candidate = aliases.get(raw, raw)
    return candidate if candidate in CANONICAL_SURFACE_FAMILIES else ""


def _coverage_status(value: Any) -> CoverageStatus:
    normalized = _normalize_token(value) or "untested"
    if normalized in {
        "queued",
        "running",
        "covered",
        "uncovered",
        "deferred",
        "skipped",
        "timeout",
        "crashed",
        "invalid-output",
        "review-rejected",
    }:
        normalized = normalized.replace("-", "_")
        return normalized  # type: ignore[return-value]
    return "untested"


def _priority_score(priority: str | None) -> float:
    return PRIORITY_SCORES.get(_normalize_token(priority), 40.0 if priority else 35.0)


def _infer_source(metadata: dict[str, Any]) -> str:
    tags = {_normalize_token(item) for item in _as_list(metadata.get("brainstorm_tags") or metadata.get("tags"))}
    if "appmap" in tags or metadata.get("appmap_context_packet") or metadata.get("appmap_run_id"):
        return "appmap"
    if metadata.get("hypothesis_id"):
        return "brainstorm"
    return "dynamic"


def _policy_id(policy: Any | None) -> str:
    return _string(_policy_get(policy, "id")) if policy is not None else ""


def _policy_get(policy: Any | None, key: str) -> Any:
    if policy is None:
        return None
    if isinstance(policy, dict):
        return policy.get(key)
    return getattr(policy, key, None)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _string(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_token(value: Any) -> str:
    return _string(value).casefold().replace("_", "-").strip()


def _float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().casefold() in {"1", "true", "yes", "y", "on", "proven"}
    return bool(value)
