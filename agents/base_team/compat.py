"""Compatibility helpers extracted from older team modules for incremental migration."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence


@dataclass
class AgentSession:
    """Live or completed agent execution context."""

    profile: Any
    workspace: Path
    log_path: Path
    process: Optional[subprocess.Popen]
    skip_ledger: bool = False


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def reset_findings_store(path: Path) -> None:
    ensure_directory(path.parent)
    path.write_text("", encoding="utf-8")


def summarize_findings(findings: Sequence[dict[str, Any]]) -> dict[str, Any]:
    by_agent: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_class: dict[str, int] = {}

    for finding in findings:
        agent = str(finding.get("agent", "unknown"))
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        category = str(finding.get("category", "class")).lower()
        class_name = str(finding.get("class_name", "unknown")).lower()
        by_agent[agent] = by_agent.get(agent, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1
        by_class[class_name] = by_class.get(class_name, 0) + 1

    return {
        "total_findings": len(findings),
        "by_agent": dict(sorted(by_agent.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_class": dict(sorted(by_class.items())),
    }


def pretty_print_findings(
    findings: Sequence[dict[str, Any]],
    *,
    display_file_reference,
) -> None:
    summary = summarize_findings(findings)
    print("Zero-Day Team Findings")
    print("=" * 80)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("-" * 80)

    if not findings:
        print("No findings recorded.")
        return

    for index, finding in enumerate(findings, start=1):
        category = str(finding.get("category", "class")).lower()
        tier = str(finding.get("review_tier", "")).upper()
        if category == "novel":
            label = f"NOVEL/{tier or finding.get('severity', 'UNKNOWN')}"
        else:
            label = "DORMANT" if tier.startswith("DORMANT") else str(finding.get("severity", "UNKNOWN"))

        print(f"{index}. [{label}] {finding['type']} ({finding['agent']})")
        print(f"   File: {display_file_reference(finding)}")
        print(f"   Why: {finding['description']}")
        source = str(finding.get("source", "")).strip()
        sink = str(finding.get("sink", "")).strip()
        if source:
            print(f"   Source: {source}")
        if sink:
            print(f"   Sink: {sink}")
        review_reason = str(finding.get("review_reason", "")).strip()
        if review_reason:
            print(f"   Review: {review_reason}")
        print("-" * 80)


def write_chainable_findings_input(path: Path, findings: Sequence[dict[str, Any]]) -> Path:
    ensure_directory(path.parent)
    path.write_text(json.dumps(list(findings), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
