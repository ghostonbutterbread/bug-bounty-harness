#!/usr/bin/env python3
"""PTE-informed harness efficiency audit."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agents.ledger_v2 import ledger_list


REWARD_TABLE = {
    "CONFIRMED_unique_class": 1.00,
    "CONFIRMED_unique_novel": 1.20,
    "DORMANT_ACTIVE": 0.45,
    "DORMANT_HYPOTHETICAL": 0.15,
    "REJECTED": -0.60,
    "duplicate": -0.35,
    "chain_enabler": 0.30,
}

REDUNDANCY_MATRIX = {
    ("ipc-trust-boundary", "node-integration"): 0.70,
    ("exec-sink-reachability", "native-module-abuse"): 0.60,
    ("exec-sink-reachability", "path-traversal"): 0.30,
    ("unsafe-deserialization", "exec-sink-reachability"): 0.40,
    ("xss_framework", "xss_hunter"): 0.75,
    ("fuzz_runner", "recon"): 0.65,
}

SOFT_CONTEXT_LIMIT_TOKENS = 32000
KNOWN_SPAN_TYPES = {"run", "spawn_decision", "model", "tool", "finding"}
REPORT_FILE_NAMES = ("confirmed.md", "dormant.md", "novel_findings.md")


def _normalize_program(program: str) -> str:
    return str(program or "").strip().replace(" ", "_")


def _normalize_agent_name(value: Any) -> str:
    return str(value or "").strip()


def _normalize_class_name(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "y"}


def _normalize_review_tier(value: Any) -> str:
    text = str(value or "").strip().replace("-", "_").upper()
    if not text:
        return ""
    if text == "DORMANT":
        return "DORMANT_ACTIVE"
    if text in {"PENDING_REVIEW", "PENDING"}:
        return ""
    return text


def _normalize_category(value: Any, class_name: str) -> str:
    category = str(value or "").strip().lower()
    if category in {"class", "novel"}:
        return category
    return "novel" if _normalize_class_name(class_name) == "novel" else "class"


def _coerce_dt(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _fmt_int(value: Any) -> str:
    numeric = _safe_int(value, 0)
    return f"{numeric:,}"


def _fmt_float(value: Any) -> str:
    return f"{_safe_float(value, 0.0):.2f}"


def _fmt_pct(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "0%"
    return f"{round((numerator / denominator) * 100)}%"


def _estimate_tokens(size_bytes: Any) -> int:
    numeric = _safe_int(size_bytes, 0)
    return max(0, math.ceil(numeric / 4))


def _compute_pte_lite(entry: dict[str, Any]) -> int:
    if entry.get("pte_lite") is not None:
        return _safe_int(entry.get("pte_lite"))
    context_after = _safe_int(entry.get("context_tokens_after"))
    context_overhang = entry.get("context_overhang_tokens")
    if context_overhang is None:
        context_overhang = max(0, context_after - SOFT_CONTEXT_LIMIT_TOKENS)
    return (
        _safe_int(entry.get("prompt_tokens"))
        + _safe_int(entry.get("completion_tokens"))
        + _safe_int(entry.get("tool_output_tokens"))
        + _safe_int(entry.get("spawn_prefill_tokens"))
        + _safe_int(context_overhang)
    )


def _reward_for(
    *,
    review_tier: str,
    category: str,
    duplicate: bool,
    chain_enabler: bool,
) -> float:
    if duplicate:
        reward = REWARD_TABLE["duplicate"]
    elif review_tier == "CONFIRMED":
        reward = REWARD_TABLE["CONFIRMED_unique_novel"] if category == "novel" else REWARD_TABLE["CONFIRMED_unique_class"]
    elif review_tier == "DORMANT_ACTIVE":
        reward = REWARD_TABLE["DORMANT_ACTIVE"]
    elif review_tier == "DORMANT_HYPOTHETICAL":
        reward = REWARD_TABLE["DORMANT_HYPOTHETICAL"]
    elif review_tier == "REJECTED":
        reward = REWARD_TABLE["REJECTED"]
    else:
        reward = 0.0
    if chain_enabler:
        reward += REWARD_TABLE["chain_enabler"]
    return reward


def _pair_overlap(agent_a: str, agent_b: str) -> float:
    key = (_normalize_class_name(agent_a), _normalize_class_name(agent_b))
    reverse = (key[1], key[0])
    return REDUNDANCY_MATRIX.get(key) or REDUNDANCY_MATRIX.get(reverse) or 0.0


@dataclass(slots=True)
class FindingOutcome:
    fid: str
    run_id: str
    agent_name: str
    class_name: str
    category: str
    review_tier: str
    duplicate: bool
    chain_enabler: bool
    reward: float
    allocated_pte_lite: int
    seen_at: datetime | None


class HarnessEfficiencyScorer:
    def __init__(self, program: str):
        self.program = _normalize_program(program)
        self.ghost_dir = Path.home() / "Shared" / "bounty_recon" / self.program / "ghost"
        self.traces_dir = self.ghost_dir / "traces"
        self.findings_dir = self.ghost_dir / "reports"
        self._trace_cache: list[dict[str, Any]] | None = None
        self._ledger_cache: list[dict[str, Any]] | None = None
        self._report_meta_cache: dict[tuple[str, str], dict[str, Any]] | None = None
        self._finding_cache: list[FindingOutcome] | None = None

    def _trace_files(self) -> list[Path]:
        if not self.traces_dir.exists():
            return []
        return sorted(
            [path for path in self.traces_dir.rglob("*") if path.is_file() and path.suffix in {".jsonl", ".logl"}],
            key=lambda item: item.stat().st_mtime,
        )

    def _load_trace_entries(self) -> list[dict[str, Any]]:
        if self._trace_cache is not None:
            return self._trace_cache

        entries: list[dict[str, Any]] = []
        for path in self._trace_files():
            try:
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    for raw_line in handle:
                        line = raw_line.strip()
                        if not line:
                            continue
                        try:
                            payload = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(payload, dict):
                            continue
                        payload["_path"] = str(path)
                        payload["_timestamp_dt"] = _coerce_dt(payload.get("timestamp"))
                        payload["run_id"] = str(payload.get("run_id") or "").strip()
                        payload["agent_name"] = _normalize_agent_name(
                            payload.get("agent_name") or payload.get("tool") or payload.get("tool_name")
                        )
                        payload["span_type"] = str(payload.get("span_type") or "").strip()
                        payload["pte_lite"] = _compute_pte_lite(payload)
                        entries.append(payload)
            except OSError:
                continue

        self._trace_cache = entries
        return entries

    def _load_ledger_findings(self) -> list[dict[str, Any]]:
        if self._ledger_cache is not None:
            return self._ledger_cache
        try:
            self._ledger_cache = ledger_list(self.program)
        except Exception:
            self._ledger_cache = []
        return self._ledger_cache

    def _report_roots(self) -> list[Path]:
        roots = [
            self.ghost_dir / "reports",
            self.ghost_dir / "reports_source",
            self.ghost_dir / "reports_web",
        ]
        return [root for root in roots if root.exists()]

    def _latest_report_files(self) -> list[Path]:
        files: list[Path] = []
        for root in self._report_roots():
            for filename in REPORT_FILE_NAMES:
                candidates = [path for path in root.glob(f"*/{filename}") if path.is_file()]
                if not candidates:
                    direct = root / filename
                    if direct.is_file():
                        candidates = [direct]
                if candidates:
                    files.append(max(candidates, key=lambda item: item.stat().st_mtime))
        return files

    def _load_report_meta(self) -> dict[tuple[str, str], dict[str, Any]]:
        if self._report_meta_cache is not None:
            return self._report_meta_cache

        meta: dict[tuple[str, str], dict[str, Any]] = {}
        for path in self._latest_report_files():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            blocks = text.split("\n## [")
            for block in blocks[1:]:
                header, _, remainder = block.partition("\n")
                if "]" not in header:
                    continue
                tier_text, _, title = header.partition("]")
                review_tier = _normalize_review_tier(tier_text)
                category = "novel" if "novel" in path.name.lower() else "class"
                class_name = ""
                file_value = ""
                agent_name = ""
                for line in remainder.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("**Class:**"):
                        class_name = stripped.split(":", 1)[1].strip()
                    elif stripped.startswith("**File:**"):
                        file_value = stripped.split(":", 1)[1].strip()
                    elif stripped.startswith("**Agent:**"):
                        agent_name = stripped.split(":", 1)[1].strip()
                key = (_normalize_class_name(class_name), str(file_value).strip().lower())
                if not key[0] and not key[1]:
                    continue
                meta[key] = {
                    "title": title.strip(),
                    "review_tier": review_tier,
                    "category": category,
                    "agent_name": agent_name,
                }

        self._report_meta_cache = meta
        return meta

    def _build_finding_outcomes(self) -> list[FindingOutcome]:
        if self._finding_cache is not None:
            return self._finding_cache

        report_meta = self._load_report_meta()
        outcomes: list[FindingOutcome] = []
        for finding in self._load_ledger_findings():
            if not isinstance(finding, dict):
                continue
            fid = str(finding.get("fid") or "").strip()
            class_name = _normalize_class_name(finding.get("class_name"))
            file_key = str(finding.get("file") or "").strip().lower()
            category = _normalize_category(finding.get("category"), class_name)
            entry_chain = _normalize_bool(finding.get("chain_enabler"))
            report_fallback = report_meta.get((class_name, file_key), {})

            sightings = finding.get("sightings", [])
            normalized_sightings = [item for item in sightings if isinstance(item, dict)]
            normalized_sightings.sort(key=lambda item: (_coerce_dt(item.get("seen_at")) or datetime.min.replace(tzinfo=timezone.utc), str(item.get("run_id") or "")))
            first_run_by_fid = str(normalized_sightings[0].get("run_id") or "").strip() if normalized_sightings else ""

            for sighting in normalized_sightings:
                run_id = str(sighting.get("run_id") or "").strip()
                if not run_id:
                    continue
                review_tier = _normalize_review_tier(
                    sighting.get("review_tier")
                    or sighting.get("tier")
                    or finding.get("current", {}).get("review_tier")
                    or report_fallback.get("review_tier")
                )
                agent_name = _normalize_agent_name(
                    sighting.get("agent")
                    or finding.get("agent")
                    or report_fallback.get("agent_name")
                    or class_name
                )
                chain_enabler = _normalize_bool(
                    sighting.get("chain_enabler")
                    or finding.get("chain_enabler")
                    or (
                        str(finding.get("chain_status") or "").strip().lower()
                        in {"ready-for-chainer", "ready_for_chainer"}
                    )
                ) or entry_chain
                duplicate = _normalize_bool(sighting.get("duplicate")) or (run_id != first_run_by_fid)
                reward = _safe_float(
                    sighting.get("finding_reward"),
                    _reward_for(
                        review_tier=review_tier,
                        category=category,
                        duplicate=duplicate,
                        chain_enabler=chain_enabler,
                    ),
                )
                outcomes.append(
                    FindingOutcome(
                        fid=fid,
                        run_id=run_id,
                        agent_name=agent_name,
                        class_name=class_name,
                        category=category,
                        review_tier=review_tier,
                        duplicate=duplicate,
                        chain_enabler=chain_enabler,
                        reward=reward,
                        allocated_pte_lite=_safe_int(sighting.get("allocated_pte_lite")),
                        seen_at=_coerce_dt(sighting.get("seen_at") or finding.get("last_seen")),
                    )
                )

        self._finding_cache = outcomes
        return outcomes

    def _runs_from_traces(self) -> dict[str, list[dict[str, Any]]]:
        by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for entry in self._load_trace_entries():
            run_id = str(entry.get("run_id") or "").strip()
            if run_id:
                by_run[run_id].append(entry)
        return dict(by_run)

    def _findings_by_run(self) -> dict[str, list[FindingOutcome]]:
        by_run: dict[str, list[FindingOutcome]] = defaultdict(list)
        for outcome in self._build_finding_outcomes():
            by_run[outcome.run_id].append(outcome)
        return dict(by_run)

    def _agent_for_run(self, run_id: str, trace_entries: list[dict[str, Any]], findings: list[FindingOutcome]) -> str:
        for entry in trace_entries:
            agent = _normalize_agent_name(entry.get("agent_name"))
            if agent:
                return agent
        for finding in findings:
            if finding.agent_name:
                return finding.agent_name
        return ""

    def _run_cost(self, trace_entries: list[dict[str, Any]]) -> int:
        model_cost = sum(_safe_int(entry.get("pte_lite")) for entry in trace_entries if entry.get("span_type") == "model")
        if model_cost > 0:
            return model_cost
        non_finding_cost = sum(
            _safe_int(entry.get("pte_lite"))
            for entry in trace_entries
            if entry.get("span_type") != "finding"
        )
        if non_finding_cost > 0:
            return non_finding_cost
        return 1000 if trace_entries else 0

    def _run_duration(self, trace_entries: list[dict[str, Any]]) -> int:
        finish_durations = [_safe_int(entry.get("duration_ms")) for entry in trace_entries if entry.get("level") == "FINISH"]
        finish_durations = [item for item in finish_durations if item > 0]
        if finish_durations:
            return max(finish_durations)
        timestamps = [entry.get("_timestamp_dt") for entry in trace_entries if entry.get("_timestamp_dt") is not None]
        if len(timestamps) >= 2:
            return int((max(timestamps) - min(timestamps)).total_seconds() * 1000)
        return 0

    def _run_tool_types(self, trace_entries: list[dict[str, Any]]) -> set[str]:
        tool_types: set[str] = set()
        for entry in trace_entries:
            if entry.get("span_type") != "tool":
                continue
            tool_type = str(entry.get("tool_category") or entry.get("tool_name") or entry.get("tool") or "").strip()
            if tool_type:
                tool_types.add(tool_type)
        return tool_types

    def compute_run_worth(self, run_id: str) -> dict[str, Any]:
        trace_entries = self._runs_from_traces().get(run_id, [])
        findings = self._findings_by_run().get(run_id, [])
        agent_name = self._agent_for_run(run_id, trace_entries, findings)
        total_pte_lite = self._run_cost(trace_entries)
        run_signal = sum(item.reward for item in findings)
        run_cost = max(total_pte_lite / 1000, 1.0)
        confirmed_unique = sum(1 for item in findings if item.review_tier == "CONFIRMED" and not item.duplicate)
        dormant_active = sum(1 for item in findings if item.review_tier == "DORMANT_ACTIVE")
        dormant_hypothetical = sum(1 for item in findings if item.review_tier == "DORMANT_HYPOTHETICAL")
        rejected = sum(1 for item in findings if item.review_tier == "REJECTED")
        duplicates = sum(1 for item in findings if item.duplicate)
        chain_enablers = sum(1 for item in findings if item.chain_enabler)
        tool_types = self._run_tool_types(trace_entries)

        return {
            "run_id": run_id,
            "agent_name": agent_name,
            "run_signal": round(run_signal, 4),
            "total_pte_lite": total_pte_lite,
            "run_cost": round(run_cost, 4),
            "run_worth": round(run_signal / run_cost, 4),
            "findings": len(findings),
            "confirmed_unique": confirmed_unique,
            "dormant_active": dormant_active,
            "dormant_hypothetical": dormant_hypothetical,
            "rejected": rejected,
            "duplicates": duplicates,
            "chain_enablers": chain_enablers,
            "model_call_count": sum(1 for item in trace_entries if item.get("span_type") == "model"),
            "tool_call_count": sum(1 for item in trace_entries if item.get("span_type") == "tool"),
            "distinct_tool_types": len(tool_types),
            "tool_types": sorted(tool_types),
            "duration_ms": self._run_duration(trace_entries),
            "trace_entries": len(trace_entries),
        }

    def _run_ids_for_agent(self, agent_name: str) -> list[str]:
        target = _normalize_agent_name(agent_name)
        run_ids: set[str] = set()
        for run_id, entries in self._runs_from_traces().items():
            if self._agent_for_run(run_id, entries, []) == target:
                run_ids.add(run_id)
        for outcome in self._build_finding_outcomes():
            if outcome.agent_name == target:
                run_ids.add(outcome.run_id)
        return sorted(run_ids)

    def score_agent_profile(self, agent_name: str) -> dict[str, Any]:
        target = _normalize_agent_name(agent_name)
        run_ids = self._run_ids_for_agent(target)
        runs = [self.compute_run_worth(run_id) for run_id in run_ids]
        findings = [item for item in self._build_finding_outcomes() if item.agent_name == target]
        reviewed = [item for item in findings if item.review_tier]
        unique_findings = [item for item in findings if not item.duplicate and item.review_tier != "REJECTED"]
        worth_by_run = [item["run_worth"] for item in runs]
        pte_values = [item["total_pte_lite"] for item in runs if item["total_pte_lite"] > 0]
        duration_values = [item["duration_ms"] for item in runs if item["duration_ms"] > 0]
        recent_30_cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        recent_7_cutoff = datetime.now(timezone.utc) - timedelta(days=7)

        worth_30 = [
            run["run_worth"]
            for run in runs
            if any((item.seen_at or recent_30_cutoff) >= recent_30_cutoff for item in self._findings_by_run().get(run["run_id"], []))
        ]
        worth_7 = [
            run["run_worth"]
            for run in runs
            if any((item.seen_at or recent_7_cutoff) >= recent_7_cutoff for item in self._findings_by_run().get(run["run_id"], []))
        ]
        rolling_30 = statistics.mean(worth_30) if worth_30 else (statistics.mean(worth_by_run) if worth_by_run else 0.0)
        rolling_7 = statistics.mean(worth_7) if worth_7 else rolling_30
        profile_worth = (0.7 * rolling_30) + (0.3 * rolling_7)

        return {
            "agent_name": target,
            "runs": len(runs),
            "run_ids": run_ids,
            "median_pte_lite": statistics.median(pte_values) if pte_values else 0,
            "confirmed_unique": sum(1 for item in findings if item.review_tier == "CONFIRMED" and not item.duplicate),
            "dormant_active": sum(1 for item in findings if item.review_tier == "DORMANT_ACTIVE"),
            "dormant_hypothetical": sum(1 for item in findings if item.review_tier == "DORMANT_HYPOTHETICAL"),
            "rejected": sum(1 for item in findings if item.review_tier == "REJECTED"),
            "duplicates": sum(1 for item in findings if item.duplicate),
            "reviewed": len(reviewed),
            "raw_findings": len(findings),
            "unique_findings": len(unique_findings),
            "chain_enablers": sum(1 for item in findings if item.chain_enabler),
            "fp_rate": (sum(1 for item in findings if item.review_tier == "REJECTED") / len(reviewed)) if reviewed else 0.0,
            "dup_rate": (sum(1 for item in findings if item.duplicate) / len(findings)) if findings else 0.0,
            "chain_rate": (sum(1 for item in findings if item.chain_enabler) / len(unique_findings)) if unique_findings else 0.0,
            "rolling_30d_mean": round(rolling_30, 4),
            "rolling_7d_mean": round(rolling_7, 4),
            "profile_worth": round(profile_worth, 4),
            "mean_run_worth": round(statistics.mean(worth_by_run), 4) if worth_by_run else 0.0,
            "mean_duration_ms": round(statistics.mean(duration_values), 2) if duration_values else 0.0,
            "mean_tool_types": round(statistics.mean([item["distinct_tool_types"] for item in runs]), 2) if runs else 0.0,
            "mean_tool_calls": round(statistics.mean([item["tool_call_count"] for item in runs]), 2) if runs else 0.0,
            "mean_model_calls": round(statistics.mean([item["model_call_count"] for item in runs]), 2) if runs else 0.0,
        }

    def get_inefficiency_patterns(self, agent_name: str) -> list[str]:
        profile = self.score_agent_profile(agent_name)
        runs = [self.compute_run_worth(run_id) for run_id in profile["run_ids"]]
        trace_entries = [
            entry
            for entry in self._load_trace_entries()
            if _normalize_agent_name(entry.get("agent_name")) == _normalize_agent_name(agent_name)
        ]
        patterns: list[str] = []

        if profile["dup_rate"] >= 0.40 and profile["confirmed_unique"] <= 1:
            patterns.append("Confirmatory Tool Usage")

        if profile["mean_tool_types"] >= 4 and profile["profile_worth"] < 0.75:
            patterns.append("Tool-Mixing")

        tool_calls = sum(run["tool_call_count"] for run in runs)
        if tool_calls >= 6 and profile["confirmed_unique"] == 0 and profile["dormant_active"] <= 1:
            patterns.append("Lack of Tool Priors")

        overhang_values = [_safe_int(entry.get("context_overhang_tokens")) for entry in trace_entries if _safe_int(entry.get("context_overhang_tokens")) > 0]
        if overhang_values and statistics.mean(overhang_values) >= 1000 and profile["profile_worth"] < 0.75:
            patterns.append("Tool Format Collapse")

        return patterns

    def _all_agents(self) -> list[str]:
        agents = {
            _normalize_agent_name(entry.get("agent_name"))
            for entry in self._load_trace_entries()
            if _normalize_agent_name(entry.get("agent_name"))
        }
        agents.update(
            outcome.agent_name
            for outcome in self._build_finding_outcomes()
            if outcome.agent_name
        )
        return sorted(agent for agent in agents if agent)

    def _recommendations(self, profiles: list[dict[str, Any]]) -> list[str]:
        recommendations: list[str] = []
        by_name = {item["agent_name"]: item for item in profiles}
        agents = sorted(by_name)

        for idx, agent_a in enumerate(agents):
            for agent_b in agents[idx + 1 :]:
                overlap = _pair_overlap(agent_a, agent_b)
                if overlap <= 0:
                    continue
                weaker, stronger = sorted(
                    [by_name[agent_a], by_name[agent_b]],
                    key=lambda item: (item["profile_worth"], -item["runs"]),
                )
                recommendations.append(
                    f"{weaker['agent_name']} overlaps {round(overlap * 100)}% with {stronger['agent_name']} "
                    f"and has lower worth ({_fmt_float(weaker['profile_worth'])} vs {_fmt_float(stronger['profile_worth'])}) "
                    f"so consider running only one by default."
                )

        for profile in profiles:
            patterns = self.get_inefficiency_patterns(profile["agent_name"])
            if "Tool-Mixing" in patterns:
                recommendations.append(
                    f"{profile['agent_name']} has high tool-mixing (mean {profile['mean_tool_types']:.1f} tool types/run); consider splitting discovery and verification phases."
                )
            if profile["profile_worth"] < 0.25 and profile["median_pte_lite"] > 0:
                recommendations.append(
                    f"{profile['agent_name']} has low historical worth ({_fmt_float(profile['profile_worth'])}); require stronger preflight signal before spawn."
                )
            if "Tool Format Collapse" in patterns:
                recommendations.append(
                    f"{profile['agent_name']} shows context overhang without matching value; cap replayed tool output and trim inherited context."
                )
            if "Confirmatory Tool Usage" in patterns:
                recommendations.append(
                    f"{profile['agent_name']} spends too much budget on duplicate confirmation; dedupe earlier and reward only chain uplift or unique findings."
                )

        deduped: list[str] = []
        seen: set[str] = set()
        for item in recommendations:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped

    def generate_audit_report(self) -> str:
        agents = self._all_agents()
        profiles = [self.score_agent_profile(agent) for agent in agents]
        profiles.sort(key=lambda item: (item["profile_worth"], item["confirmed_unique"]), reverse=True)

        lines = [f"# PTE Audit: {self.program}", ""]
        lines.append("| Agent | Runs | Median PTE | Confirmed | Dormant | Rejected | Dupes | FP Rate | Worth Score |")
        lines.append("|-------|------|------------|-----------|---------|----------|-------|---------|-------------|")
        for profile in profiles:
            dormant_total = profile["dormant_active"] + profile["dormant_hypothetical"]
            lines.append(
                "| {agent} | {runs} | {pte} | {confirmed} | {dormant} | {rejected} | {dupes} | {fp_rate} | {worth} |".format(
                    agent=profile["agent_name"],
                    runs=profile["runs"],
                    pte=_fmt_int(profile["median_pte_lite"]),
                    confirmed=profile["confirmed_unique"],
                    dormant=dormant_total,
                    rejected=profile["rejected"],
                    dupes=profile["duplicates"],
                    fp_rate=_fmt_pct(profile["rejected"], profile["reviewed"]),
                    worth=_fmt_float(profile["profile_worth"]),
                )
            )

        good = [item["agent_name"] for item in profiles if item["profile_worth"] >= 0.75][:3]
        wasteful = [item["agent_name"] for item in profiles if item["profile_worth"] < 0.25 or item["dup_rate"] >= 0.40][:3]
        lines.extend(["", "## Highlights", ""])
        lines.append(f"- Good performers: {', '.join(good) if good else 'none yet'}")
        lines.append(f"- Wasteful candidates: {', '.join(wasteful) if wasteful else 'none clearly flagged'}")

        recommendations = self._recommendations(profiles)
        lines.extend(["", "## Recommendations", ""])
        if recommendations:
            for item in recommendations:
                lines.append(f"- {item}")
        else:
            lines.append("- No strong recommendations yet; more traced runs are needed.")

        return "\n".join(lines)


def _format_profile(profile: dict[str, Any], patterns: list[str]) -> str:
    lines = [f"# Agent Profile: {profile['agent_name']}", ""]
    lines.append(f"- Runs: {profile['runs']}")
    lines.append(f"- Median PTE-lite: {_fmt_int(profile['median_pte_lite'])}")
    lines.append(f"- Confirmed unique: {profile['confirmed_unique']}")
    lines.append(f"- Dormant active: {profile['dormant_active']}")
    lines.append(f"- Dormant hypothetical: {profile['dormant_hypothetical']}")
    lines.append(f"- Rejected: {profile['rejected']}")
    lines.append(f"- Duplicates: {profile['duplicates']}")
    lines.append(f"- FP rate: {_fmt_pct(profile['rejected'], profile['reviewed'])}")
    lines.append(f"- Dup rate: {_fmt_pct(profile['duplicates'], profile['raw_findings'])}")
    lines.append(f"- Chain rate: {_fmt_pct(profile['chain_enablers'], profile['unique_findings'])}")
    lines.append(f"- Profile worth: {_fmt_float(profile['profile_worth'])}")
    lines.append(f"- Inefficiency patterns: {', '.join(patterns) if patterns else 'none flagged'}")
    return "\n".join(lines)


def _format_compare(left: dict[str, Any], right: dict[str, Any]) -> str:
    rows = [
        ("Runs", left["runs"], right["runs"]),
        ("Median PTE-lite", _fmt_int(left["median_pte_lite"]), _fmt_int(right["median_pte_lite"])),
        ("Confirmed unique", left["confirmed_unique"], right["confirmed_unique"]),
        ("Dormant active", left["dormant_active"], right["dormant_active"]),
        ("Rejected", left["rejected"], right["rejected"]),
        ("Duplicates", left["duplicates"], right["duplicates"]),
        ("FP rate", _fmt_pct(left["rejected"], left["reviewed"]), _fmt_pct(right["rejected"], right["reviewed"])),
        ("Worth", _fmt_float(left["profile_worth"]), _fmt_float(right["profile_worth"])),
    ]
    lines = [f"# Compare: {left['agent_name']} vs {right['agent_name']}", ""]
    lines.append(f"| Metric | {left['agent_name']} | {right['agent_name']} |")
    lines.append("|--------|-------------------|--------------------|")
    for metric, lhs, rhs in rows:
        lines.append(f"| {metric} | {lhs} | {rhs} |")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit harness efficiency using PTE-lite traces and ledger outcomes.")
    parser.add_argument("--program", required=True, help="Program slug")
    parser.add_argument("--agent", help="Agent name for focused profile output")
    parser.add_argument("--report", action="store_true", help="Generate a markdown report")
    parser.add_argument("--inefficiency", metavar="AGENT", help="Show inefficiency patterns for one agent")
    parser.add_argument("--compare", nargs=2, metavar=("AGENT1", "AGENT2"), help="Compare two agents")
    parser.add_argument("--recommend", action="store_true", help="Show recommendations only")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    scorer = HarnessEfficiencyScorer(args.program)

    if args.compare:
        left = scorer.score_agent_profile(args.compare[0])
        right = scorer.score_agent_profile(args.compare[1])
        print(_format_compare(left, right))
        return 0

    if args.inefficiency:
        patterns = scorer.get_inefficiency_patterns(args.inefficiency)
        print("\n".join(patterns) if patterns else "No inefficiency patterns flagged.")
        return 0

    if args.recommend:
        profiles = [scorer.score_agent_profile(agent) for agent in scorer._all_agents()]
        recommendations = scorer._recommendations(profiles)
        if recommendations:
            print("\n".join(f"- {item}" for item in recommendations))
        else:
            print("- No strong recommendations yet; more traced runs are needed.")
        return 0

    if args.report or not any((args.inefficiency, args.compare, args.recommend)):
        if args.agent:
            profile = scorer.score_agent_profile(args.agent)
            patterns = scorer.get_inefficiency_patterns(args.agent)
            print(_format_profile(profile, patterns))
        else:
            print(scorer.generate_audit_report())
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
