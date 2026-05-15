from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from agents.base_team import AgentSpec

_EFFICIENCY_DIRNAME = "tmp_efficiency"
_TOOL_OUTPUT_SPIKE_THRESHOLD = 25_000
_ORIGINAL_TOKEN_RE = re.compile(r"Original token count:\s*(\d+)")
_PROCESS_SESSION_RE = re.compile(r"Process running with session ID\s+(\S+)")


def resolve_efficiency_dir(plan_path: str | Path, plan: Mapping[str, Any]) -> Path:
    resolved_plan = Path(plan_path).expanduser().resolve(strict=False)
    run_id = _run_id(plan, resolved_plan)
    metadata = plan.get("artifact_metadata") if isinstance(plan.get("artifact_metadata"), Mapping) else {}
    tmp_output = metadata.get("tmp_output") if isinstance(metadata.get("tmp_output"), Mapping) else {}
    if bool(tmp_output.get("enabled", False)):
        return Path("/tmp/bug_bounty_harness") / run_id / "efficiency"
    return resolved_plan.parent / _EFFICIENCY_DIRNAME


def initialize_efficiency_logging(
    plan_path: str | Path,
    plan: Mapping[str, Any],
    *,
    specs: Sequence[AgentSpec],
    wave: Sequence[Mapping[str, Any]],
    spec_metrics: Mapping[str, Any],
    execution_mode: str,
    selected_wave: int | None = None,
) -> Path:
    resolved_plan = Path(plan_path).expanduser().resolve(strict=False)
    run_id = _run_id(plan, resolved_plan)
    efficiency_dir = resolve_efficiency_dir(resolved_plan, plan)
    efficiency_dir.mkdir(parents=True, exist_ok=True)
    _append_jsonl(
        efficiency_dir / "pack_plan.jsonl",
        _pack_plan_rows(run_id, specs, spec_metrics),
    )
    _append_jsonl(
        efficiency_dir / "spawn_decisions.jsonl",
        _spawn_decision_rows(run_id, specs, wave, execution_mode=execution_mode, selected_wave=selected_wave),
    )
    _write_summary(
        efficiency_dir / "summary.json",
        build_efficiency_summary(
            run_id,
            specs=specs,
            agent_usage_rows=_read_jsonl(efficiency_dir / "agent_usage.jsonl"),
            tool_spike_rows=_read_jsonl(efficiency_dir / "tool_output_spikes.jsonl"),
            specialist_rows=_read_jsonl(efficiency_dir / "specialist_requests.jsonl"),
        ),
    )
    return efficiency_dir


def finalize_efficiency_logging(
    plan_path: str | Path,
    plan: Mapping[str, Any],
    *,
    specs: Sequence[AgentSpec],
    result: Mapping[str, str],
    execution_details: Mapping[str, Mapping[str, Any]] | None = None,
) -> Path:
    resolved_plan = Path(plan_path).expanduser().resolve(strict=False)
    run_id = _run_id(plan, resolved_plan)
    efficiency_dir = resolve_efficiency_dir(resolved_plan, plan)
    efficiency_dir.mkdir(parents=True, exist_ok=True)
    details_map = execution_details or {}
    agent_rows: list[dict[str, Any]] = []
    spike_rows: list[dict[str, Any]] = []
    specialist_rows: list[dict[str, Any]] = []
    for spec in specs:
        spec_details = details_map.get(spec.key, {})
        usage = build_agent_usage_row(run_id, spec, result.get(spec.key, "missing"), spec_details)
        agent_rows.append(usage)
        spike_rows.extend(build_tool_output_spike_rows(run_id, spec, spec_details, usage.get("codex_session_id")))
        specialist_rows.extend(build_specialist_request_rows(run_id, spec, spec_details))
    _append_jsonl(efficiency_dir / "agent_usage.jsonl", agent_rows)
    _append_jsonl(efficiency_dir / "tool_output_spikes.jsonl", spike_rows)
    _append_jsonl(efficiency_dir / "specialist_requests.jsonl", specialist_rows)
    _write_summary(
        efficiency_dir / "summary.json",
        build_efficiency_summary(
            run_id,
            specs=specs,
            agent_usage_rows=_read_jsonl(efficiency_dir / "agent_usage.jsonl"),
            tool_spike_rows=_read_jsonl(efficiency_dir / "tool_output_spikes.jsonl"),
            specialist_rows=_read_jsonl(efficiency_dir / "specialist_requests.jsonl"),
        ),
    )
    return efficiency_dir


def build_agent_usage_row(
    run_id: str,
    spec: AgentSpec,
    status: str,
    execution_details: Mapping[str, Any],
) -> dict[str, Any]:
    category_pack = spec.metadata.get("category_pack") if isinstance(spec.metadata, Mapping) else {}
    pack_id = str(spec.metadata.get("category_pack_id") or spec.key).strip()
    covered_hypothesis_count = len(spec.metadata.get("category_pack_hypothesis_ids") or spec.metadata.get("selected_hypothesis_ids") or [spec.key])
    log_path = _path_or_empty(execution_details.get("log_path"))
    prompt_path = _path_or_empty(execution_details.get("prompt_path"))
    artifact_dir = Path(str(execution_details.get("artifact_dir") or "")).expanduser().resolve(strict=False) if execution_details.get("artifact_dir") else None
    log_text = _read_text(log_path)
    codex_session_id = _extract_process_session_id(log_text)
    rollout = find_matching_rollout(
        marker=str(execution_details.get("prompt_marker") or "").strip(),
        session_id=codex_session_id,
        cwd=str(execution_details.get("cwd") or "").strip(),
    )
    usage = parse_rollout_usage(rollout) if rollout is not None else {}
    notes_count = 0
    finding_count = 0
    if artifact_dir and artifact_dir.exists():
        notes_count = len(list(artifact_dir.rglob("notes*.txt"))) + len(list(artifact_dir.rglob("README*")))
        finding_count = len(list(artifact_dir.rglob("finding*.jsonl")))
    tokens_total = _safe_int((usage.get("total_token_usage") or {}).get("total_tokens"))
    input_tokens = _safe_int((usage.get("total_token_usage") or {}).get("input_tokens"))
    cached_input_tokens = _safe_int((usage.get("total_token_usage") or {}).get("cached_input_tokens"))
    output_tokens = _safe_int((usage.get("total_token_usage") or {}).get("output_tokens"))
    reasoning_output_tokens = _safe_int((usage.get("total_token_usage") or {}).get("reasoning_output_tokens"))
    uncached_input_tokens = max(0, input_tokens - cached_input_tokens)
    max_tool_output_tokens = max([0, *usage.get("original_token_counts", [])])
    warnings: list[str] = []
    if max_tool_output_tokens >= _TOOL_OUTPUT_SPIKE_THRESHOLD:
        warnings.append("large-tool-output")
    if status != "completed":
        warnings.append(f"status-{status}")
    if rollout is None:
        warnings.append("usage-unmatched")
    row = {
        "run_id": run_id,
        "pack_id": pack_id,
        "agent_name": spec.key,
        "codex_session_id": str(usage.get("session_meta_id") or codex_session_id or ""),
        "prompt_path": prompt_path,
        "log_path": log_path,
        "status": "usage_unmatched" if rollout is None else status,
        "duration_ms": _safe_int(usage.get("duration_ms")),
        "tool_calls": _safe_int(usage.get("tool_calls")),
        "tokens_total": tokens_total,
        "input_tokens": input_tokens,
        "cached_input_tokens": cached_input_tokens,
        "uncached_input_tokens": uncached_input_tokens,
        "output_tokens": output_tokens,
        "reasoning_output_tokens": reasoning_output_tokens,
        "max_tool_output_tokens": max_tool_output_tokens,
        "finding_count": finding_count,
        "notes_count": notes_count,
        "covered_hypothesis_count": covered_hypothesis_count,
        "tokens_per_covered_hypothesis": round(tokens_total / covered_hypothesis_count, 2) if covered_hypothesis_count and tokens_total else 0,
        "tokens_per_finding": round(tokens_total / finding_count, 2) if finding_count and tokens_total else 0,
        "efficiency_warnings": warnings,
        "vuln_class": str(category_pack.get("vuln_class") or spec.vuln_class),
        "subclass": str(category_pack.get("subclass") or ""),
        "context_cluster_id": str(category_pack.get("context_cluster_id") or ""),
        "rollout_path": str(rollout or ""),
    }
    return row


def build_tool_output_spike_rows(
    run_id: str,
    spec: AgentSpec,
    execution_details: Mapping[str, Any],
    codex_session_id: str | None,
) -> list[dict[str, Any]]:
    rollout = find_matching_rollout(
        marker=str(execution_details.get("prompt_marker") or "").strip(),
        session_id=codex_session_id,
        cwd=str(execution_details.get("cwd") or "").strip(),
    )
    if rollout is None:
        return []
    usage = parse_rollout_usage(rollout)
    rows: list[dict[str, Any]] = []
    pack_id = str(spec.metadata.get("category_pack_id") or spec.key).strip()
    source_guess = ", ".join(spec.metadata.get("source_files") or spec.focus_globs[:2])
    for index, spike in enumerate(usage.get("tool_outputs", []), start=1):
        original_token_count = _safe_int(spike.get("original_token_count"))
        if original_token_count <= 0:
            continue
        warning = classify_tool_output_warning(str(spike.get("command_preview") or ""), original_token_count)
        if not warning and original_token_count < _TOOL_OUTPUT_SPIKE_THRESHOLD:
            continue
        rows.append(
            {
                "run_id": run_id,
                "pack_id": pack_id,
                "agent_name": spec.key,
                "tool_call_index": index,
                "original_token_count": original_token_count,
                "command_preview": str(spike.get("command_preview") or "")[:500],
                "source_file_guess": source_guess,
                "warning": warning or "large-tool-output",
            }
        )
    return rows


def build_specialist_request_rows(
    run_id: str,
    spec: AgentSpec,
    execution_details: Mapping[str, Any],
) -> list[dict[str, Any]]:
    artifact_dir = execution_details.get("artifact_dir")
    if not artifact_dir:
        return []
    path = Path(str(artifact_dir)).expanduser().resolve(strict=False) / "specialist_requests.jsonl"
    rows = _read_jsonl(path)
    for row in rows:
        row.setdefault("run_id", run_id)
        row.setdefault("pack_id", str(spec.metadata.get("category_pack_id") or spec.key).strip())
        row.setdefault("agent_name", spec.key)
    return rows


def build_efficiency_summary(
    run_id: str,
    *,
    specs: Sequence[AgentSpec],
    agent_usage_rows: Sequence[Mapping[str, Any]],
    tool_spike_rows: Sequence[Mapping[str, Any]],
    specialist_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    class_summary: dict[str, dict[str, Any]] = {}
    subclass_summary: dict[str, dict[str, Any]] = {}
    source_file_counts: dict[str, int] = {}
    for spec in specs:
        category_pack = spec.metadata.get("category_pack") if isinstance(spec.metadata, Mapping) else {}
        vuln_class = str(category_pack.get("vuln_class") or spec.vuln_class or "unknown")
        subclass = str(category_pack.get("subclass") or "unknown")
        pack_id = str(spec.metadata.get("category_pack_id") or spec.key).strip()
        class_summary.setdefault(vuln_class, {"tokens_total": 0, "finding_count": 0, "packs": []})["packs"].append(pack_id)
        subclass_summary.setdefault(subclass, {"tokens_total": 0, "finding_count": 0, "packs": []})["packs"].append(pack_id)
        for source_file in spec.metadata.get("source_files") or spec.focus_globs:
            cleaned = str(source_file).strip()
            if cleaned:
                source_file_counts[cleaned] = source_file_counts.get(cleaned, 0) + 1
    for row in agent_usage_rows:
        vuln_class = str(row.get("vuln_class") or "unknown")
        subclass = str(row.get("subclass") or "unknown")
        class_summary.setdefault(vuln_class, {"tokens_total": 0, "finding_count": 0, "packs": []})
        subclass_summary.setdefault(subclass, {"tokens_total": 0, "finding_count": 0, "packs": []})
        class_summary[vuln_class]["tokens_total"] += _safe_int(row.get("tokens_total"))
        class_summary[vuln_class]["finding_count"] += _safe_int(row.get("finding_count"))
        subclass_summary[subclass]["tokens_total"] += _safe_int(row.get("tokens_total"))
        subclass_summary[subclass]["finding_count"] += _safe_int(row.get("finding_count"))
    top_waste = sorted(
        (
            {
                "pack_id": str(row.get("pack_id") or ""),
                "tokens_total": _safe_int(row.get("tokens_total")),
                "finding_count": _safe_int(row.get("finding_count")),
                "tokens_per_finding": row.get("tokens_per_finding"),
            }
            for row in agent_usage_rows
        ),
        key=lambda item: (-int(item["tokens_total"]), item["pack_id"]),
    )[:5]
    duplicate_source_file_ingestion_count = sum(max(0, count - 1) for count in source_file_counts.values())
    return {
        "run_id": run_id,
        "tokens_by_class": class_summary,
        "tokens_by_subclass": subclass_summary,
        "top_waste_clusters": top_waste,
        "duplicate_source_file_ingestion_count": duplicate_source_file_ingestion_count,
        "tool_output_spike_count": len(tool_spike_rows),
        "specialist_request_count": len(specialist_rows),
        "suggested_future_pack_collapse_rules": _suggested_rules(tool_spike_rows, duplicate_source_file_ingestion_count),
    }


def parse_rollout_usage(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    resolved = Path(path).expanduser().resolve(strict=False)
    if not resolved.exists():
        return {}
    session_meta_id = ""
    started_at: int | None = None
    started_timestamp: str | None = None
    last_timestamp: str | None = None
    last_token_usage: dict[str, Any] = {}
    tool_calls = 0
    call_args: dict[str, str] = {}
    tool_outputs: list[dict[str, Any]] = []
    cwd = ""
    with resolved.open(encoding="utf-8") as handle:
        for line in handle:
            payload = json.loads(line)
            last_timestamp = str(payload.get("timestamp") or last_timestamp or "")
            record_type = payload.get("type")
            body = payload.get("payload") if isinstance(payload.get("payload"), Mapping) else {}
            if record_type == "session_meta":
                session_meta_id = str(body.get("id") or session_meta_id)
                cwd = str(body.get("cwd") or cwd)
                continue
            if record_type != "event_msg" and record_type != "response_item":
                continue
            event_type = body.get("type")
            if event_type == "task_started":
                started_at = _safe_int(body.get("started_at")) or started_at
                started_timestamp = str(payload.get("timestamp") or started_timestamp or "")
            elif event_type == "token_count":
                info = body.get("info") if isinstance(body.get("info"), Mapping) else {}
                if info.get("total_token_usage"):
                    last_token_usage = dict(info)
            elif event_type == "function_call":
                tool_calls += 1
                call_args[str(body.get("call_id") or "")] = str(body.get("arguments") or "")
            elif event_type == "function_call_output":
                output = str(body.get("output") or "")
                match = _ORIGINAL_TOKEN_RE.search(output)
                original = _safe_int(match.group(1)) if match else 0
                tool_outputs.append(
                    {
                        "call_id": str(body.get("call_id") or ""),
                        "original_token_count": original,
                        "command_preview": _command_preview(call_args.get(str(body.get("call_id") or ""), "")),
                    }
                )
    duration_ms = 0
    if started_timestamp and last_timestamp:
        try:
            start_dt = _parse_iso8601(started_timestamp)
            end_dt = _parse_iso8601(last_timestamp)
            duration_ms = max(0, int((end_dt - start_dt).total_seconds() * 1000))
        except ValueError:
            duration_ms = 0
    return {
        "session_meta_id": session_meta_id,
        "cwd": cwd,
        "started_at": started_at,
        "duration_ms": duration_ms,
        "total_token_usage": dict(last_token_usage.get("total_token_usage") or {}),
        "tool_calls": tool_calls,
        "tool_outputs": tool_outputs,
        "original_token_counts": [item["original_token_count"] for item in tool_outputs if item.get("original_token_count")],
    }


def find_matching_rollout(*, marker: str = "", session_id: str = "", cwd: str = "") -> Path | None:
    sessions_root = Path.home() / ".codex" / "sessions"
    if not sessions_root.exists():
        return None
    marker = marker.strip()
    session_id = str(session_id or "").strip()
    cwd = str(cwd or "").strip()
    candidates = sorted(sessions_root.rglob("rollout-*.jsonl"), key=lambda item: item.stat().st_mtime, reverse=True)
    for candidate in candidates:
        try:
            if _rollout_matches(candidate, marker=marker, session_id=session_id, cwd=cwd):
                return candidate
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
    return None


def classify_tool_output_warning(command_preview: str, original_token_count: int) -> str:
    command = str(command_preview or "").lower()
    if " rg " in f" {command} " and original_token_count >= _TOOL_OUTPUT_SPIKE_THRESHOLD:
        if ".min.js" in command or "dist/" in command or "bundle" in command:
            if "-m" not in command and "--max-count" not in command and "head" not in command and "sed -n" not in command:
                return "minified-broad-rg"
        if "-m" not in command and "--max-count" not in command and "head" not in command and "sed -n" not in command:
            return "uncapped-search"
    if any(token in command for token in ("cat ", "sed -n '1,", "python - <<")) and original_token_count >= _TOOL_OUTPUT_SPIKE_THRESHOLD:
        return "full-file-dump"
    return "large-tool-output" if original_token_count >= _TOOL_OUTPUT_SPIKE_THRESHOLD else ""


def _append_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    if not rows:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(dict(row), sort_keys=True))
            handle.write("\n")


def _write_summary(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _pack_plan_rows(run_id: str, specs: Sequence[AgentSpec], spec_metrics: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    estimated_context_risk = _safe_int(spec_metrics.get("collapsed_groups"))
    for spec in specs:
        category_pack = spec.metadata.get("category_pack") if isinstance(spec.metadata, Mapping) else {}
        if not isinstance(category_pack, Mapping):
            category_pack = {}
        rows.append(
            {
                "run_id": run_id,
                "pack_id": str(spec.metadata.get("category_pack_id") or spec.key).strip(),
                "vuln_class": str(category_pack.get("vuln_class") or spec.vuln_class),
                "subclass": str(category_pack.get("subclass") or ""),
                "surface_family": str(category_pack.get("surface_family") or spec.surface),
                "context_cluster_id": str(category_pack.get("context_cluster_id") or ""),
                "source_files": list(category_pack.get("source_files") or spec.metadata.get("source_files") or spec.focus_globs),
                "hypothesis_ids": list(category_pack.get("hypothesis_ids") or spec.metadata.get("selected_hypothesis_ids") or []),
                "evidence_ids": list(category_pack.get("evidence_ids") or spec.metadata.get("category_pack_evidence_ids") or []),
                "pack_size": len(category_pack.get("hypothesis_ids") or spec.metadata.get("selected_hypothesis_ids") or []),
                "estimated_context_risk": estimated_context_risk,
                "reason": str(category_pack.get("reason") or spec.metadata.get("source_group", {}).get("reason") or ""),
            }
        )
    return rows


def _spawn_decision_rows(
    run_id: str,
    specs: Sequence[AgentSpec],
    wave: Sequence[Mapping[str, Any]],
    *,
    execution_mode: str,
    selected_wave: int | None,
) -> list[dict[str, Any]]:
    spec_by_record_key: dict[str, str] = {}
    for spec in specs:
        source_group = spec.metadata.get("source_group") if isinstance(spec.metadata, Mapping) else {}
        decision_agent_keys = source_group.get("decision_agent_keys") if isinstance(source_group, Mapping) else []
        for agent_key in decision_agent_keys or ():
            spec_by_record_key[str(agent_key)] = spec.key
        spec_by_record_key.setdefault(spec.key, spec.key)
    rows: list[dict[str, Any]] = []
    for record in wave:
        agent_key = str(record.get("agent_key") or "").strip()
        rows.append(
            {
                "run_id": run_id,
                "pack_id": spec_by_record_key.get(agent_key, agent_key),
                "decision": str(record.get("decision", "spawn" if execution_mode != "blocked" else "skip")),
                "decision_reason": str(record.get("reason") or ""),
                "priority_score": record.get("final_score") if record.get("final_score") is not None else record.get("priority_score"),
                "budget_bucket": execution_mode,
                "selected_wave": selected_wave,
            }
        )
    return rows


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _read_text(path: str | Path | None) -> str:
    if not path:
        return ""
    resolved = Path(path).expanduser().resolve(strict=False)
    if not resolved.exists():
        return ""
    return resolved.read_text(encoding="utf-8", errors="replace")


def _extract_process_session_id(log_text: str) -> str:
    ids = _PROCESS_SESSION_RE.findall(log_text)
    return ids[-1] if ids else ""


def _path_or_empty(value: Any) -> str:
    return str(value or "").strip()


def _command_preview(arguments: str) -> str:
    try:
        payload = json.loads(arguments)
    except json.JSONDecodeError:
        return arguments[:500]
    if isinstance(payload, Mapping):
        command = payload.get("cmd") or payload.get("command") or payload.get("workdir") or ""
        return str(command)[:500]
    return str(arguments)[:500]


def _rollout_matches(path: Path, *, marker: str, session_id: str, cwd: str) -> bool:
    session_meta_id = ""
    session_cwd = ""
    saw_marker = not marker
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            payload = json.loads(line)
            body = payload.get("payload") if isinstance(payload.get("payload"), Mapping) else {}
            if payload.get("type") == "session_meta":
                session_meta_id = str(body.get("id") or session_meta_id)
                session_cwd = str(body.get("cwd") or session_cwd)
                continue
            if marker and marker in line:
                saw_marker = True
        if session_id and session_meta_id != session_id:
            return False
        if cwd and session_cwd and session_cwd != cwd:
            return False
        return saw_marker


def _run_id(plan: Mapping[str, Any], plan_path: Path) -> str:
    candidates = [
        plan.get("run_id"),
        ((plan.get("artifact_metadata") or {}).get("run") if isinstance(plan.get("artifact_metadata"), Mapping) else {}).get("run_id"),
        plan_path.parent.name,
    ]
    for candidate in candidates:
        cleaned = str(candidate or "").strip()
        if cleaned:
            return cleaned
    return plan_path.parent.name


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_iso8601(value: str) -> datetime:
    cleaned = str(value or "").strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    return datetime.fromisoformat(cleaned).astimezone(UTC)


def _suggested_rules(tool_spike_rows: Sequence[Mapping[str, Any]], duplicate_source_file_ingestion_count: int) -> list[str]:
    suggestions: list[str] = []
    if duplicate_source_file_ingestion_count > 0:
        suggestions.append("collapse repeated same-file packs or reuse precomputed context for shared source bundles")
    if any(str(row.get("warning") or "") == "minified-broad-rg" for row in tool_spike_rows):
        suggestions.append("add minified-bundle extractors or capped symbol lookups before broad rg on dist bundles")
    if any(str(row.get("warning") or "") == "uncapped-search" for row in tool_spike_rows):
        suggestions.append("enforce rg -m/--max-count or capped sed/head snippets in pack prompts")
    return suggestions
