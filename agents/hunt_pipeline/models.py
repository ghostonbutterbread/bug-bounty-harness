from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

HypothesisRole = Literal["entry", "amplifier", "chain", "hardening", "notes_only"]


def _jsonable_path(value: str | Path | None) -> str:
    return str(value or "").strip()


@dataclass(frozen=True, slots=True)
class NormalizedMapResult:
    appmap_root: str
    manifest: dict[str, Any] = field(default_factory=dict)
    target_profile: dict[str, Any] = field(default_factory=dict)
    surfaces: tuple[dict[str, Any], ...] = ()
    flows: tuple[dict[str, Any], ...] = ()
    legacy_candidates: tuple[dict[str, Any], ...] = ()
    legacy_rejected_candidates: tuple[dict[str, Any], ...] = ()
    legacy_policy_shaped: bool = False
    source_files: tuple[str, ...] = ()

    def counts(self) -> dict[str, int]:
        return {
            "surfaces": len(self.surfaces),
            "flows": len(self.flows),
            "legacy_candidates": len(self.legacy_candidates),
            "legacy_rejected_candidates": len(self.legacy_rejected_candidates),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "appmap_root": self.appmap_root,
            "manifest": self.manifest,
            "target_profile": self.target_profile,
            "surfaces": list(self.surfaces),
            "flows": list(self.flows),
            "legacy_candidates": list(self.legacy_candidates),
            "legacy_rejected_candidates": list(self.legacy_rejected_candidates),
            "counts": self.counts(),
            "legacy_policy_shaped": self.legacy_policy_shaped,
            "source_files": list(self.source_files),
        }


@dataclass(frozen=True, slots=True)
class ResolvedRuleset:
    id: str
    version: int
    requested_id: str
    base_id: str
    overlays: tuple[str, ...] = ()
    selected_rulesets: tuple[str, ...] = ()
    compatibility_alias: str | None = None
    app_kinds: tuple[str, ...] = ()
    target_kinds: tuple[str, ...] = ()
    surface_taxonomy: dict[str, Any] = field(default_factory=dict)
    hypothesis_guidance: dict[str, Any] = field(default_factory=dict)
    scheduler_guidance: dict[str, Any] = field(default_factory=dict)
    review_guidance: dict[str, Any] = field(default_factory=dict)
    policy_hints: dict[str, Any] = field(default_factory=dict)
    notes: dict[str, Any] = field(default_factory=dict)
    config_paths: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class HypothesisAgentPacket:
    id: str
    key: str
    title: str
    role: HypothesisRole
    surface_family: str
    priority: str
    target_kind: str
    ruleset_id: str
    source_evidence: tuple[dict[str, Any], ...] = ()
    secondary_families: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    chain_requirements: tuple[str, ...] = ()
    focus_files: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    scheduler_metadata: dict[str, Any] = field(default_factory=dict)
    entry_status: str = "unknown"
    attacker_influence_score: float = 0.0
    context_privilege_score: float = 0.0
    incremental_impact_score: float = 0.0
    entry_reportability_score: float = 0.0
    chain_unlock_score: float = 0.0
    ingestion_path: str = "unknown"
    required_entry_primitives: tuple[str, ...] = ()
    context_tags: tuple[str, ...] = ()
    unlocked_amplifiers: tuple[str, ...] = ()
    reportability: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CategoryPack:
    pack_id: str
    vuln_class: str
    subclass: str
    surface_family: str
    context_cluster_id: str
    source_files: tuple[str, ...] = ()
    route_or_endpoint_keys: tuple[str, ...] = ()
    sink_types: tuple[str, ...] = ()
    entry_paths: tuple[str, ...] = ()
    policy_id: str | None = None
    hypothesis_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    priority_score: float = 0.0
    reason: str = ""
    expected_outputs: tuple[str, ...] = ()
    specialist_followup_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CategoryPackPlan:
    packs: tuple[CategoryPack, ...] = ()
    hypothesis_to_pack_id: dict[str, str] = field(default_factory=dict)
    pack_to_hypothesis_ids: dict[str, tuple[str, ...]] = field(default_factory=dict)
    mode: str = "auto"
    max_pack_size: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PipelineSchedulerPlan:
    mode: str
    selected: tuple[dict[str, Any], ...] = ()
    deferred: tuple[dict[str, Any], ...] = ()
    skipped: tuple[dict[str, Any], ...] = ()
    selected_batches: tuple[dict[str, Any], ...] = ()
    summary: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    decision_artifacts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PipelineDryRunArtifact:
    schema_version: int
    run_id: str
    program: str
    target_path: str
    target_kind: str
    selected_rulesets: dict[str, Any]
    appmap_source: dict[str, Any]
    normalized_map: dict[str, Any]
    hypotheses: tuple[dict[str, Any], ...]
    artifact_metadata: dict[str, Any]
    scheduler_plan: dict[str, Any]
    runtime_adapter_availability: dict[str, Any]
    runtime_handoff_boundary: dict[str, Any]
    runtime_handoff_contract: dict[str, Any]
    runtime_promotion_protocol: dict[str, Any]
    static_team_handoffs: dict[str, Any]
    dynamic_validation_queue: dict[str, Any]
    safety: dict[str, Any]
    live_testing_playbook: dict[str, Any] = field(default_factory=dict)
    runtime_environment_approval: dict[str, Any] = field(default_factory=dict)
    runtime_action_policy: dict[str, Any] = field(default_factory=dict)
    runtime_promotion_readiness: dict[str, Any] = field(default_factory=dict)
    runtime_operator_approval_schema: dict[str, Any] = field(default_factory=dict)
    runtime_promotion_request_packet: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalized_path(value: str | Path | None) -> str:
    return _jsonable_path(value)
