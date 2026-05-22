from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
import uuid

from agents.app_mapper import map_application, write_artifacts
from agents.hunt_pipeline.appmap_loader import load_appmap_run
from agents.hunt_pipeline.hypothesis_builder import build_hypothesis_packets
from agents.hunt_pipeline.live_testing import build_live_testing_playbook
from agents.hunt_pipeline.map_cache import (
    DEFAULT_STALE_AFTER_DAYS,
    MAP_DIFF_FILENAME,
    AppMapResolution,
    MapReuseDecision,
    resolve_appmap_run,
    write_map_cache_metadata,
    write_map_diff,
)
from agents.hunt_pipeline.models import PipelineDryRunArtifact
from agents.hunt_pipeline.operator_approval_schema import build_runtime_operator_approval_schema
from agents.hunt_pipeline.promotion_readiness import (
    build_runtime_promotion_readiness_checklist,
    non_live_readiness_stub,
)
from agents.hunt_pipeline.promotion_request_packet import build_runtime_promotion_request_packet
from agents.hunt_pipeline.runtime_action_policy import build_runtime_action_policy
from agents.hunt_pipeline.runtime_contract import build_runtime_handoff_contract, build_runtime_promotion_protocol
from agents.hunt_pipeline.runtime_environment_approval import build_runtime_environment_approval
from agents.hunt_pipeline.run_state import validate_run_id
from agents.hunt_pipeline.rulesets import resolve_ruleset
from agents.hunt_pipeline.scheduler import plan_hypothesis_packets, runtime_adapter_availability, runtime_handoff_boundary
from agents.hunt_pipeline.target_classifier import classify_target_kind
from agents.hunting_policy import disabled_policy

SCHEMA_VERSION = 1


def build_dry_run_plan(
    *,
    program: str,
    target_path: str | Path,
    target_kind: str | None = "auto",
    ruleset_id: str | None = "auto",
    appmap_run: str | Path | None = None,
    output_dir: str | Path,
    run_id: str | None = None,
    max_hypotheses: int | None = None,
    max_agents: int | None = None,
    concurrent_agents: int | None = None,
    write_hypotheses: bool = True,
    tmp_output: bool = False,
    remap: bool = False,
    diff: bool = False,
    cache_search_root: str | Path | None = None,
    stale_after_days: int = DEFAULT_STALE_AFTER_DAYS,
) -> tuple[PipelineDryRunArtifact, Path]:
    output_root = Path(output_dir).expanduser().resolve(strict=False)
    output_root.mkdir(parents=True, exist_ok=True)
    target = Path(target_path).expanduser().resolve(strict=False)
    resolved_run_id = validate_run_id(str(run_id or _default_run_id()))
    created_at = _timestamp_iso()

    appmap_resolution = resolve_appmap_run(
        appmap_run=appmap_run,
        program=program,
        target_path=target,
        target_kind=target_kind,
        output_root=output_root,
        run_id=resolved_run_id,
        cache_search_root=cache_search_root,
        force_remap=remap,
        stale_after_days=stale_after_days,
    )

    if appmap_resolution.source_mode == "generated-neutral":
        map_result = map_application(program, target, target_kind=target_kind or "auto")
        paths = write_artifacts(
            map_result,
            output_root=output_root,
            run_id=resolved_run_id,
            write_specs=False,
            hunting_policy=disabled_policy(),
            agent_granularity="category-master",
        )
        appmap_root = paths["run_root"]
        manifest = json.loads((appmap_root / "manifest.json").read_text(encoding="utf-8"))
        appmap_metadata = {**appmap_resolution.metadata, "mapped_at": str(manifest.get("created_at") or created_at)}
        write_map_cache_metadata(appmap_root, appmap_metadata)
    else:
        appmap_root = appmap_resolution.appmap_root
        appmap_metadata = appmap_resolution.metadata

    normalized = load_appmap_run(appmap_root)
    map_diff_path: Path | None = None
    appmap_resolution = _with_diff_path(appmap_resolution, None)
    if bool(diff) and bool(remap) and appmap_resolution.previous_appmap_root and appmap_resolution.source_mode == "generated-neutral":
        map_diff_path = write_map_diff(
            previous_appmap_root=appmap_resolution.previous_appmap_root,
            current_appmap_root=appmap_root,
            output_path=output_root / MAP_DIFF_FILENAME,
            previous_metadata=appmap_resolution.previous_metadata,
            current_metadata=appmap_metadata,
        )
        appmap_resolution = _with_diff_path(appmap_resolution, map_diff_path)

    appmap_source = {
        "mode": appmap_resolution.source_mode,
        "run_root": str(appmap_root),
        "map_cache_metadata": appmap_metadata,
        "map_reuse_decision": appmap_resolution.decision.to_dict(),
    }
    if appmap_resolution.previous_appmap_root is not None:
        appmap_source["previous_run_root"] = str(appmap_resolution.previous_appmap_root)
    if map_diff_path is not None:
        appmap_source["map_diff_path"] = str(map_diff_path)
    resolved_target_kind = classify_target_kind(
        target,
        requested_kind=target_kind,
        appmap_profile=normalized.target_profile,
    )
    ruleset = resolve_ruleset(ruleset_id, target_kind=resolved_target_kind, target_path=target)
    packets = build_hypothesis_packets(
        normalized,
        ruleset,
        target_kind=resolved_target_kind,
        max_packets=max_hypotheses,
    )
    scheduler_plan = plan_hypothesis_packets(
        packets,
        ruleset=ruleset,
        max_agents=max_agents,
        concurrent_agents=concurrent_agents,
    )
    scheduler_plan_payload = scheduler_plan.to_dict()
    decision_artifacts = _write_decision_artifacts(output_root, scheduler_plan_payload)
    scheduler_plan_payload["decision_artifacts"] = decision_artifacts
    hypotheses_payload = tuple(packet.to_dict() for packet in packets)
    artifact_metadata: dict[str, Any] = {
        "run": {
            "run_id": resolved_run_id,
            "created_at": created_at,
            "output_dir": str(output_root),
        }
    }
    if tmp_output:
        artifact_metadata["tmp_output"] = {
            "enabled": True,
            "root": str(output_root),
            "parent": str(output_root.parent),
        }
    if write_hypotheses:
        artifact_metadata["hypotheses"] = _write_jsonl_artifact(output_root / "hypotheses.jsonl", list(hypotheses_payload))
    amplifier_hypotheses = _amplifier_hypotheses(hypotheses_payload)
    artifact_metadata["amplifier_hypotheses"] = _write_jsonl_artifact(
        output_root / "amplifier_hypotheses.jsonl",
        amplifier_hypotheses,
    )
    chain_activation_index = _chain_activation_index(hypotheses_payload, amplifier_hypotheses)
    artifact_metadata["chain_activation_index"] = _write_json_artifact_with_metadata(
        output_root / "chain_activation_index.json",
        chain_activation_index,
    )
    artifact_metadata["amplifier_report"] = _write_amplifier_report_artifact(
        output_root / "reports" / "findings" / "amplifier.md",
        amplifier_hypotheses,
        program=str(program),
        target_kind=resolved_target_kind,
        run_id=resolved_run_id,
    )
    artifact_metadata["appmap"] = {
        "run_root": str(appmap_root),
        "map_cache_path": str(appmap_root / "map_cache.json"),
        "decision": appmap_resolution.decision.to_dict(),
        "diff_path": str(map_diff_path) if map_diff_path else "",
    }
    runtime_adapter = runtime_adapter_availability()
    handoff_boundary = runtime_handoff_boundary()
    static_team_handoffs = _static_team_handoffs(
        target_kind=resolved_target_kind,
        ruleset_id=ruleset.id,
        selected_rulesets=ruleset.selected_rulesets,
    )
    dynamic_validation_queue = {
        "enabled": False,
        "queued": [],
        "placeholder": "dynamic validation is not invoked in the dry-run slice",
    }
    safety = {
        "dry_run_only": True,
        "spawn_agents": False,
        "live_dynamic_validation": False,
        "ledger_writes": False,
    }
    live_testing_playbook = build_live_testing_playbook(
        target_kind=resolved_target_kind,
        ruleset_id=ruleset.id,
    ).to_dict()
    runtime_promotion_protocol = build_runtime_promotion_protocol().to_dict()
    plan_path = output_root / "pipeline_plan.json"
    plan_context = {
        "program": str(program),
        "target_path": str(target),
        "target_kind": resolved_target_kind,
        "selected_rulesets": ruleset.to_dict(),
        "appmap_source": appmap_source,
    }
    runtime_environment_approval = build_runtime_environment_approval(plan_path, plan=plan_context).to_dict()
    runtime_action_policy = build_runtime_action_policy(plan_path, plan=plan_context).to_dict()
    artifact_context = {
        **plan_context,
        "runtime_environment_approval": runtime_environment_approval,
        "runtime_action_policy": runtime_action_policy,
    }
    readiness_seed = non_live_readiness_stub()
    runtime_handoff_contract = build_runtime_handoff_contract(
        {
            **artifact_context,
            "runtime_handoff_contract": {"schema_version": 1},
            "runtime_promotion_protocol": runtime_promotion_protocol,
            "runtime_promotion_readiness": readiness_seed,
            "runtime_adapter_availability": runtime_adapter,
            "static_team_handoffs": static_team_handoffs,
            "dynamic_validation_queue": dynamic_validation_queue,
            "live_testing_playbook": live_testing_playbook,
            "runtime_environment_approval": runtime_environment_approval,
            "runtime_action_policy": runtime_action_policy,
            "safety": safety,
        }
    ).to_dict()
    runtime_promotion_readiness = build_runtime_promotion_readiness_checklist(
        plan_path,
        plan={
            **artifact_context,
            "runtime_handoff_contract": runtime_handoff_contract,
            "runtime_promotion_protocol": runtime_promotion_protocol,
            "runtime_promotion_readiness": readiness_seed,
            "runtime_adapter_availability": runtime_adapter,
            "static_team_handoffs": static_team_handoffs,
            "dynamic_validation_queue": dynamic_validation_queue,
            "live_testing_playbook": live_testing_playbook,
            "runtime_environment_approval": runtime_environment_approval,
            "runtime_action_policy": runtime_action_policy,
            "safety": safety,
        },
    ).to_dict()
    runtime_operator_approval_schema = build_runtime_operator_approval_schema(
        plan_path,
        plan={
            **artifact_context,
            "runtime_handoff_contract": runtime_handoff_contract,
            "runtime_promotion_protocol": runtime_promotion_protocol,
            "runtime_promotion_readiness": runtime_promotion_readiness,
            "runtime_adapter_availability": runtime_adapter,
            "static_team_handoffs": static_team_handoffs,
            "dynamic_validation_queue": dynamic_validation_queue,
            "runtime_environment_approval": runtime_environment_approval,
            "runtime_action_policy": runtime_action_policy,
            "safety": safety,
        },
    ).to_dict()
    runtime_handoff_contract = build_runtime_handoff_contract(
        {
            **artifact_context,
            "runtime_handoff_contract": {"schema_version": 1},
            "runtime_promotion_protocol": runtime_promotion_protocol,
            "runtime_promotion_readiness": runtime_promotion_readiness,
            "runtime_operator_approval_schema": runtime_operator_approval_schema,
            "runtime_adapter_availability": runtime_adapter,
            "static_team_handoffs": static_team_handoffs,
            "dynamic_validation_queue": dynamic_validation_queue,
            "live_testing_playbook": live_testing_playbook,
            "runtime_environment_approval": runtime_environment_approval,
            "runtime_action_policy": runtime_action_policy,
            "safety": safety,
        }
    ).to_dict()
    runtime_promotion_request_packet = build_runtime_promotion_request_packet(
        plan_path,
        plan={
            **artifact_context,
            "runtime_handoff_contract": runtime_handoff_contract,
            "runtime_promotion_protocol": runtime_promotion_protocol,
            "runtime_promotion_readiness": runtime_promotion_readiness,
            "runtime_operator_approval_schema": runtime_operator_approval_schema,
            "runtime_adapter_availability": runtime_adapter,
            "static_team_handoffs": static_team_handoffs,
            "dynamic_validation_queue": dynamic_validation_queue,
            "live_testing_playbook": live_testing_playbook,
            "runtime_environment_approval": runtime_environment_approval,
            "runtime_action_policy": runtime_action_policy,
            "safety": safety,
        },
    ).to_dict()
    artifact = PipelineDryRunArtifact(
        schema_version=SCHEMA_VERSION,
        run_id=resolved_run_id,
        program=str(program),
        target_path=str(target),
        target_kind=resolved_target_kind,
        selected_rulesets=ruleset.to_dict(),
        appmap_source={
            **appmap_source,
            "preferred_neutral_artifacts": ["surfaces.jsonl", "flows.jsonl"],
            "legacy_compatibility_artifacts": ["candidates.jsonl", "rejected_candidates.jsonl"],
        },
        normalized_map=normalized.to_dict(),
        hypotheses=hypotheses_payload,
        artifact_metadata=artifact_metadata,
        scheduler_plan=scheduler_plan_payload,
        runtime_adapter_availability=runtime_adapter,
        runtime_handoff_boundary=handoff_boundary,
        runtime_handoff_contract=runtime_handoff_contract,
        runtime_promotion_protocol=runtime_promotion_protocol,
        runtime_promotion_readiness=runtime_promotion_readiness,
        runtime_operator_approval_schema=runtime_operator_approval_schema,
        runtime_promotion_request_packet=runtime_promotion_request_packet,
        static_team_handoffs=static_team_handoffs,
        dynamic_validation_queue=dynamic_validation_queue,
        safety=safety,
        live_testing_playbook=live_testing_playbook,
        runtime_environment_approval=runtime_environment_approval,
        runtime_action_policy=runtime_action_policy,
    )
    _write_json_artifact(plan_path, artifact.to_dict())
    return artifact, plan_path


def _default_run_id() -> str:
    return f"hunt-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"


def _timestamp_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_plan(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"pipeline plan must be a JSON object: {path}")
    return payload


def _static_team_handoffs(*, target_kind: str, ruleset_id: str, selected_rulesets: tuple[str, ...]) -> dict[str, Any]:
    """Describe compatible static-team bundles without invoking them."""

    normalized_kind = str(target_kind or "").strip().lower()
    planned: list[dict[str, Any]] = []
    if "electron" in normalized_kind or "electron-overlay" in selected_rulesets:
        planned.append(
            {
                "team": "electron_team",
                "entrypoint": "agents/electron_team.py",
                "reason": "Electron overlay selected; use only as an explicit static coverage bundle after reviewing the dynamic plan.",
                "invocation_status": "planned-only",
            }
        )
    if normalized_kind in {"apk", "android", "mobile"}:
        planned.append(
            {
                "team": "apk_team",
                "entrypoint": "agents/apk_team.py",
                "reason": "Mobile/APK target kind selected; use only as an explicit static coverage bundle.",
                "invocation_status": "planned-only",
            }
        )
    if normalized_kind in {"desktop", "native-desktop", "source-tree", "electron", "electron-exe", "app_asar"}:
        planned.append(
            {
                "team": "zero_day_team",
                "entrypoint": "agents/zero_day_team.py",
                "reason": "Desktop/source baseline available as a legacy static bundle for coverage gaps.",
                "invocation_status": "planned-only",
            }
        )
    return {
        "enabled": False,
        "invocation_enabled": False,
        "ruleset_id": ruleset_id,
        "target_kind": target_kind,
        "planned": planned,
        "placeholder": "static team handoffs are metadata only in this slice; no static team is invoked",
    }


def _write_decision_artifacts(output_root: Path, scheduler_plan: dict[str, Any]) -> dict[str, Any]:
    selected = [_decision_log_record(item, "selected") for item in scheduler_plan.get("selected", ())]
    deferred = [_decision_log_record(item, "deferred") for item in scheduler_plan.get("deferred", ())]
    skipped = [_decision_log_record(item, "skipped") for item in scheduler_plan.get("skipped", ())]
    unrun = [*deferred, *skipped]
    artifacts = {
        "selected_agents": _write_jsonl_artifact(output_root / "selected_agents.jsonl", selected),
        "deferred_agents": _write_jsonl_artifact(output_root / "deferred_agents.jsonl", deferred),
        "skipped_agents": _write_jsonl_artifact(output_root / "skipped_agents.jsonl", skipped),
        "unrun_agents": _write_jsonl_artifact(output_root / "unrun_agents.jsonl", unrun),
    }
    summary = scheduler_plan.setdefault("summary", {})
    summary["selected"] = artifacts["selected_agents"]["count"]
    summary["deferred"] = artifacts["deferred_agents"]["count"]
    summary["skipped"] = artifacts["skipped_agents"]["count"]
    summary["unrun"] = artifacts["unrun_agents"]["count"]
    return artifacts


def _amplifier_hypotheses(hypotheses: tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for hypothesis in hypotheses:
        if str(hypothesis.get("role") or "").strip().lower() not in {"amplifier", "chain"}:
            continue
        scheduler_metadata = hypothesis.get("scheduler_metadata") if isinstance(hypothesis.get("scheduler_metadata"), dict) else {}
        rows.append(
            {
                "id": hypothesis.get("id"),
                "key": hypothesis.get("key"),
                "title": hypothesis.get("title"),
                "role": hypothesis.get("role"),
                "surface_family": hypothesis.get("surface_family"),
                "priority": hypothesis.get("priority"),
                "target_kind": hypothesis.get("target_kind"),
                "ruleset_id": hypothesis.get("ruleset_id"),
                "required_entry_primitives": list(
                    hypothesis.get("required_entry_primitives") or hypothesis.get("chain_requirements") or ()
                ),
                "context_tags": list(hypothesis.get("context_tags") or hypothesis.get("tags") or ()),
                "focus_files": list(hypothesis.get("focus_files") or ()),
                "source_evidence": list(hypothesis.get("source_evidence") or ()),
                "ingestion_path": hypothesis.get("ingestion_path") or "requires prior entry",
                "chain_unlock_score": float(hypothesis.get("chain_unlock_score") or 0.0),
                "unlocked_amplifiers": list(hypothesis.get("unlocked_amplifiers") or ()),
                "expected_chain": scheduler_metadata.get("expected_chain", ""),
                "reportability": hypothesis.get("reportability") or "hold_for_chain",
                "entry_status": hypothesis.get("entry_status") or "missing",
            }
        )
    return rows


def _chain_activation_index(
    hypotheses: tuple[dict[str, Any], ...],
    amplifier_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    entry_rows = [
        _entry_activation_row(hypothesis)
        for hypothesis in hypotheses
        if str(hypothesis.get("role") or "").strip().lower() == "entry"
    ]
    entries_by_id = {str(row["id"]): row for row in entry_rows if row.get("id")}
    matched_amplifier_ids: set[str] = set()
    activations: list[dict[str, Any]] = []

    for entry in entry_rows:
        unlocked = []
        for amplifier in amplifier_rows:
            reasons = _activation_match_reasons(entry, amplifier)
            if not reasons:
                continue
            amplifier_id = str(amplifier.get("id") or "").strip()
            if amplifier_id:
                matched_amplifier_ids.add(amplifier_id)
            unlocked.append(
                {
                    "id": amplifier.get("id"),
                    "key": amplifier.get("key"),
                    "title": amplifier.get("title"),
                    "role": amplifier.get("role"),
                    "surface_family": amplifier.get("surface_family"),
                    "priority": amplifier.get("priority"),
                    "match_reasons": reasons,
                    "required_entry_primitives": list(amplifier.get("required_entry_primitives") or ()),
                    "expected_chain": amplifier.get("expected_chain") or "",
                }
            )
        if unlocked:
            activations.append(
                {
                    **entry,
                    "unlocked_amplifiers": unlocked,
                }
            )

    return {
        "schema_version": 1,
        "activation_model": "entry_to_matching_amplifiers",
        "entry_count": len(entry_rows),
        "amplifier_count": len(amplifier_rows),
        "matched_entry_count": len(activations),
        "matched_amplifier_count": len(matched_amplifier_ids),
        "activations": activations,
        "unmatched_amplifiers": [
            row for row in amplifier_rows if str(row.get("id") or "").strip() not in matched_amplifier_ids
        ],
        "notes": [
            "This is a planning index only; it does not spawn chain validation agents.",
            "Use it after an entry is proven or promising to select a small second-wave amplifier validation set.",
        ],
        "entry_ids": list(entries_by_id),
    }


def _entry_activation_row(hypothesis: dict[str, Any]) -> dict[str, Any]:
    scheduler_metadata = hypothesis.get("scheduler_metadata") if isinstance(hypothesis.get("scheduler_metadata"), dict) else {}
    return {
        "id": hypothesis.get("id"),
        "key": hypothesis.get("key"),
        "title": hypothesis.get("title"),
        "role": hypothesis.get("role"),
        "surface_family": hypothesis.get("surface_family"),
        "priority": hypothesis.get("priority"),
        "focus_files": list(hypothesis.get("focus_files") or ()),
        "context_tags": list(hypothesis.get("context_tags") or hypothesis.get("tags") or ()),
        "source_evidence": list(hypothesis.get("source_evidence") or ()),
        "ingestion_path": hypothesis.get("ingestion_path") or "unknown",
        "entry_status": hypothesis.get("entry_status") or "plausible",
        "entry_reportability_score": float(hypothesis.get("entry_reportability_score") or 0.0),
        "unlocked_amplifiers": list(hypothesis.get("unlocked_amplifiers") or ()),
        "expected_entry": scheduler_metadata.get("expected_chain", ""),
    }


def _activation_match_reasons(entry: dict[str, Any], amplifier: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    entry_files = set(_string_set(entry.get("focus_files"))) | _evidence_files(entry.get("source_evidence"))
    amplifier_files = set(_string_set(amplifier.get("focus_files"))) | _evidence_files(amplifier.get("source_evidence"))
    shared_files = sorted(entry_files & amplifier_files)
    if shared_files:
        reasons.append(f"shared_focus_file:{shared_files[0]}")

    entry_family = str(entry.get("surface_family") or "").strip()
    unlocked_families = set(_string_set(entry.get("unlocked_amplifiers")))
    amplifier_family = str(amplifier.get("surface_family") or "").strip()
    if amplifier_family and amplifier_family in unlocked_families:
        reasons.append(f"entry_unlocks_family:{amplifier_family}")

    required = " ".join(_string_set(amplifier.get("required_entry_primitives"))).lower()
    if entry_family and entry_family.lower() in required:
        reasons.append(f"required_entry_mentions_family:{entry_family}")

    shared_tags = sorted(
        set(_meaningful_context_tags(entry.get("context_tags")))
        & set(_meaningful_context_tags(amplifier.get("context_tags")))
    )
    if shared_tags:
        reasons.append(f"shared_context_tag:{shared_tags[0]}")
    return reasons


def _meaningful_context_tags(value: Any) -> list[str]:
    noisy = {
        "hunt-pipeline",
        "entry",
        "amplifier",
        "chain",
        "hardening",
        "notes_only",
        "desktop",
        "electron",
        "electron-exe",
        "apk",
        "mobile",
    }
    return [
        item
        for item in _string_set(value)
        if item not in noisy
        and not item.startswith("ruleset-")
        and "electron" not in item
        and "desktop" not in item
    ]


def _evidence_files(value: Any) -> set[str]:
    files: set[str] = set()
    if not isinstance(value, (list, tuple)):
        return files
    for item in value:
        if not isinstance(item, dict):
            continue
        file_name = str(item.get("file") or "").strip()
        if file_name:
            files.add(file_name)
    return files


def _string_set(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return list(dict.fromkeys(str(item or "").strip() for item in value if str(item or "").strip()))


def _write_amplifier_report_artifact(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    program: str,
    target_kind: str,
    run_id: str,
) -> dict[str, Any]:
    text = _render_amplifier_report(rows, program=program, target_kind=target_kind, run_id=run_id)
    _atomic_write_text(path, text)
    return {
        "path": str(path),
        "count": len(rows),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def _render_amplifier_report(
    rows: list[dict[str, Any]],
    *,
    program: str,
    target_kind: str,
    run_id: str,
) -> str:
    lines = [
        "# Amplifier Hypotheses",
        "",
        f"- Program: `{_md_inline(program)}`",
        f"- Target kind: `{_md_inline(target_kind)}`",
        f"- Run ID: `{_md_inline(run_id)}`",
        f"- Count: {len(rows)}",
        "",
        "These are chain/amplifier hypotheses held for later validation. They should not be treated as standalone active findings until a realistic entry primitive is proven or they demonstrate major standalone incremental impact.",
        "",
    ]
    if not rows:
        lines.extend(["No amplifier hypotheses were generated for this plan.", ""])
        return "\n".join(lines)
    for index, row in enumerate(rows, start=1):
        lines.extend(
            [
                f"## {index}. {_md_text(str(row.get('title') or row.get('key') or row.get('id') or 'Untitled amplifier'))}",
                "",
                f"- ID: `{_md_inline(row.get('id'))}`",
                f"- Role: `{_md_inline(row.get('role'))}`",
                f"- Surface family: `{_md_inline(row.get('surface_family'))}`",
                f"- Priority: `{_md_inline(row.get('priority'))}`",
                f"- Reportability: `{_md_inline(row.get('reportability'))}`",
                f"- Entry status: `{_md_inline(row.get('entry_status'))}`",
                f"- Expected chain: {_md_text(str(row.get('expected_chain') or 'Not specified'))}",
                f"- Required entry primitives: {_md_list(row.get('required_entry_primitives'))}",
                f"- Context tags: {_md_list(row.get('context_tags'))}",
                f"- Focus files: {_md_list(row.get('focus_files'))}",
                "",
            ]
        )
    return "\n".join(lines)


def _md_list(value: Any) -> str:
    if not isinstance(value, (list, tuple)) or not value:
        return "none"
    return ", ".join(f"`{_md_inline(item)}`" for item in value if str(item or "").strip()) or "none"


def _md_inline(value: Any) -> str:
    return str(value or "").replace("`", "'").strip()


def _md_text(value: str) -> str:
    return value.replace("\r", " ").replace("\n", " ").strip()


def _decision_log_record(decision: dict[str, Any], status: str) -> dict[str, Any]:
    return {
        **decision,
        "status": status,
        "reason": decision.get("reason") or decision.get("event", {}).get("decision_reason"),
    }


def _write_jsonl_artifact(path: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    _atomic_write_text(path, text)
    return {
        "path": str(path),
        "count": len(rows),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def _write_json_artifact(path: Path, payload: dict[str, Any]) -> None:
    _atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _write_json_artifact_with_metadata(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    _atomic_write_text(path, text)
    return {
        "path": str(path),
        "count": int(payload.get("matched_entry_count") or 0),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp_path.write_text(text, encoding="utf-8")
    tmp_path.replace(path)


def _with_diff_path(resolution: AppMapResolution, diff_path: Path | None) -> AppMapResolution:
    return AppMapResolution(
        appmap_root=resolution.appmap_root,
        source_mode=resolution.source_mode,
        decision=MapReuseDecision(**{**resolution.decision.to_dict(), "diff_path": str(diff_path) if diff_path else None}),
        metadata=resolution.metadata,
        previous_appmap_root=resolution.previous_appmap_root,
        previous_metadata=resolution.previous_metadata,
    )
