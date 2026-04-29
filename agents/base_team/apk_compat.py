"""Incremental compatibility helpers shared while removing APK -> zero-day sideways coupling."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Callable, Sequence

from .compat import AgentSession
from .findings import normalize_finding


NormalizeFindingFn = Callable[[Any, str], dict[str, Any] | None]


def load_findings(findings_path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not findings_path.exists():
        return findings

    with findings_path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            normalized = normalize_finding(parsed, default_agent="unknown", default_class="unknown")
            if normalized is not None:
                findings.append(normalized)
    return findings


def run_agent_session(
    session: AgentSession,
    findings_path: Path,
    ledger: Any,
    *,
    extract_findings_from_log: Callable[[Path, str], list[dict[str, Any]]],
    maybe_log_span: Callable[..., None] | None = None,
) -> int:
    if session.process is None:
        return 1

    exit_code = session.process.wait()
    session_findings = extract_findings_from_log(session.log_path, session.profile.key)
    if session_findings and not session.skip_ledger:
        for finding in session_findings:
            ledger.add_or_update(finding)

    try:
        findings_path.parent.mkdir(parents=True, exist_ok=True)
        with findings_path.open("a", encoding="utf-8") as handle:
            for finding in session_findings:
                handle.write(json.dumps(finding, sort_keys=True))
                handle.write("\n")
    except OSError:
        pass

    if maybe_log_span is not None:
        try:
            maybe_log_span(
                span_type="agent",
                level="RESULT",
                message=f"Agent finished: {session.profile.key}",
                tool_name="codex_exec",
                tool_category="subprocess",
                target=str(session.workspace),
                success=(exit_code == 0),
                output_bytes=session.log_path.stat().st_size if session.log_path.exists() else 0,
            )
        except Exception:
            pass

    try:
        shutil.rmtree(session.workspace, ignore_errors=True)
    except OSError:
        pass

    return exit_code
