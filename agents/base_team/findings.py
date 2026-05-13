"""Shared finding parsing, normalization, and identity helpers for BaseTeam-backed teams."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents.base_team.reporting_compat import is_placeholder_finding

BRAINSTORM_METADATA_FIELDS = (
    "brainstorm_spec",
    "source_spec_path",
    "hypothesis_id",
    "hypothesis_title",
    "brainstorm_agent_key",
    "brainstorm_surface",
    "brainstorm_tags",
    "appmap_context_packet",
    "appmap_candidate_id",
    "appmap_flow_id",
    "appmap_run_id",
    "appmap_research_technique_ids",
    "appmap_research_source_ids",
    "appmap_research_citations",
)


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_relpath(value: Any) -> str:
    relpath = str(value or "").strip().replace("\\", "/")
    while relpath.startswith("./"):
        relpath = relpath[2:]
    return relpath


def read_findings_jsonl(findings_path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not findings_path.exists():
        return findings
    try:
        with findings_path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    findings.append(payload)
    except OSError:
        return []
    return findings


def normalize_finding(
    raw: Any,
    *,
    default_agent: str = "unknown",
    default_class: str = "unknown",
) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    file_path = normalize_relpath(raw.get("file"))
    if not file_path:
        return None

    category = str(raw.get("category") or "class").strip().lower()
    if category not in {"class", "novel"}:
        category = "class"

    class_name = str(raw.get("class_name") or raw.get("vuln_class") or default_class).strip().lower()
    if not class_name:
        class_name = default_class

    finding_type = str(raw.get("type") or raw.get("title") or "").strip()
    if not finding_type:
        return None

    normalized = {
        "agent": str(raw.get("agent") or default_agent).strip() or default_agent,
        "category": category,
        "class_name": class_name,
        "type": finding_type,
        "file": file_path,
        "line": safe_int(raw.get("line")),
        "description": str(raw.get("description") or "").strip(),
        "severity": str(raw.get("severity") or "UNKNOWN").strip().upper() or "UNKNOWN",
        "context": str(raw.get("context") or "").strip(),
        "source": str(raw.get("source") or "").strip(),
        "trust_boundary": str(raw.get("trust_boundary") or "").strip(),
        "flow_path": str(raw.get("flow_path") or "").strip(),
        "sink": str(raw.get("sink") or "").strip(),
        "exploitability": str(raw.get("exploitability") or "").strip(),
    }
    for key in BRAINSTORM_METADATA_FIELDS:
        if key in raw:
            normalized[key] = raw[key]
    if is_placeholder_finding(raw) or is_placeholder_finding(normalized):
        return None
    return normalized


def extract_findings_from_log(log_path: Path, *, default_agent: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not log_path.exists():
        return findings
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                normalized = normalize_finding(payload, default_agent=default_agent)
                if normalized is not None:
                    findings.append(normalized)
    except OSError:
        return []
    return findings


def finding_identity(finding: dict[str, Any]) -> tuple[str, int, str, str]:
    return (
        normalize_relpath(finding.get("file")),
        safe_int(finding.get("line")),
        str(finding.get("class_name") or "").strip().lower(),
        str(finding.get("type") or "").strip().lower(),
    )
