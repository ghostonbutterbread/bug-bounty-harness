#!/usr/bin/env python3
"""Ingest manual findings into the shared Ghost pipeline."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.chain_matrix import build_chain_graph, get_chainable_findings
from agents.coverage_store import CoverageStore
from agents.findings_ledger import FindingsLedger
from agents.report_checker import (
    _load_ledger_findings,
    _load_markdown_findings,
    _merge_findings,
)
from agents.shared_brain import load_index


SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}
KNOWN_CLASSES = {
    "dom-xss",
    "exec-sink-reachability",
    "ipc-trust-boundary",
    "memory-unsafe-parser",
    "native-module-abuse",
    "node-integration",
    "path-traversal",
    "prototype-pollution",
    "ssrf",
    "unsafe-deserialization",
    "novel",
}
FIELD_ALIASES = {
    "title": "title",
    "finding": "title",
    "type": "type",
    "class": "class_name",
    "category": "category",
    "severity": "severity",
    "file": "file",
    "path": "file",
    "line": "line",
    "source": "source",
    "sink": "sink",
    "trust boundary": "trust_boundary",
    "trust_boundary": "trust_boundary",
    "flow": "flow_path",
    "flow path": "flow_path",
    "flow_path": "flow_path",
    "description": "description",
    "impact": "impact",
    "exploitability": "exploitability",
    "blocked reason": "blocked_reason",
    "blocked_reason": "blocked_reason",
    "chain requirements": "chain_requirements",
    "chain_requirements": "chain_requirements",
    "remediation": "remediation",
    "review notes": "review_notes",
    "review_notes": "review_notes",
    "poc": "poc",
    "tier": "review_tier",
    "review tier": "review_tier",
    "review_tier": "review_tier",
    "status": "review_tier",
}
MULTILINE_FIELDS = {
    "description",
    "impact",
    "exploitability",
    "blocked_reason",
    "chain_requirements",
    "remediation",
    "review_notes",
    "poc",
}
FIELD_RE = re.compile(
    r"^\s*(?:[-*]\s+)?(?:\*\*)?(?P<label>[A-Za-z][A-Za-z0-9 _-]*?)(?:\*\*)?\s*:\s*(?P<value>.*)$"
)
FILE_HINT_RE = re.compile(
    r"(?P<path>[\w./-]+\.(?:js|jsx|ts|tsx|py|rb|java|go|rs|php|c|cc|cpp|h|hpp|swift|kt|mjs|cjs|json|html|md))(?:[:#](?P<line>\d+))?"
)
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_$.]*\([^()\n]{0,160}\))")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _today_iso() -> str:
    return _utc_now().date().isoformat()


def _timestamp_iso() -> str:
    return _utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")


def _default_run_id() -> str:
    return _utc_now().strftime("%Y%m%dT%H%M%SZ")


def _sanitize_program_name(program: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(program).strip())
    return cleaned or "default_program"


def _default_source_root(program: str) -> Path:
    return (Path.home() / "source" / _sanitize_program_name(program)).resolve(strict=False)


def _display_path(path: Path) -> str:
    resolved = path.expanduser().resolve(strict=False)
    home = Path.home().resolve(strict=False)
    with contextlib.suppress(ValueError):
        return f"~/{resolved.relative_to(home).as_posix()}"
    return str(resolved)


def _finding_file_ref(finding: dict[str, Any]) -> str:
    file_ref = _normalize_text(finding.get("file"))
    line = _safe_int(finding.get("line"))
    if file_ref and line > 0:
        return f"{file_ref}:{line}"
    return file_ref or "?"


def _review_tier_label(value: Any) -> str:
    text = _normalize_text(value)
    if not text:
        return "UNKNOWN"
    return text.replace("-", "_").upper()


def _group_surface_entries(entries: list[dict[str, Any]]) -> list[tuple[str, list[str]]]:
    grouped: dict[str, set[str]] = {}
    for entry in entries:
        relpath = _normalize_text(entry.get("file"))
        class_name = _normalize_text(entry.get("class_name")).lower()
        if not relpath or not class_name:
            continue
        grouped.setdefault(relpath, set()).add(class_name)
    return [
        (relpath, sorted(class_names))
        for relpath, class_names in sorted(grouped.items())
    ]


def _append_grouped_surface_section(
    context_parts: list[str],
    heading: str,
    grouped_entries: list[tuple[str, list[str]]],
    *,
    trailing: str = "",
    max_items: int = 40,
) -> None:
    context_parts.append(heading)
    if not grouped_entries:
        context_parts.append("- None.")
        context_parts.append("")
        return

    for relpath, class_names in grouped_entries[:max_items]:
        classes = ", ".join(class_names)
        suffix = f" {trailing}".rstrip()
        context_parts.append(f"- {relpath} ({classes}){suffix}")
    if len(grouped_entries) > max_items:
        context_parts.append(
            f"- ... truncated {len(grouped_entries) - max_items} additional surface entries"
        )
    context_parts.append("")


def _coordination_briefing(program: str, reports_dir: Path) -> list[str]:
    ledger_script = (REPO_ROOT / "agents" / "me_ledger.py").resolve(strict=False)
    return [
        "## Coordination:",
        "Use the shared ledger to dedup findings and coordinate coverage in real time.",
        "Before adding a finding, check if it already exists:",
        f"  python3 {ledger_script} check --program {program} --file <file> --class-name <class>",
        "If it is not a duplicate, add it to the ledger:",
        f"  python3 {ledger_script} add --program {program} --file <file> --class-name <class> --type \"<type>\" --severity <SEVERITY>",
        "After reviewing a surface, mark it as explored:",
        f"  python3 {ledger_script} cover --program {program} --file <file> --class-name <class>",
        f"Write one markdown report per finding to {_display_path(reports_dir)}/<fid>_<title>.md.",
        "",
    ]


def _build_hunt_context(
    program: str,
    source_root: str | Path | None = None,
    *,
    fresh: bool = False,
) -> str:
    """Build the context prompt for Codex hunting."""
    program_slug = _sanitize_program_name(program)
    target_root = (
        Path(source_root).expanduser().resolve(strict=False)
        if source_root is not None
        else _default_source_root(program_slug)
    )
    reports_dir = (target_root / "reports").resolve(strict=False)
    ledger = FindingsLedger(program_slug, base_dir=target_root)
    findings = ledger.list_all()

    examined_rows: list[dict[str, Any]] = []
    unexplored_rows: list[dict[str, Any]] = []
    coverage_note = ""
    try:
        coverage = CoverageStore(program_slug, target_root)
        examined = coverage.get_all_examined()
        candidates = coverage.get_candidates()
        unexplored = {
            key: value
            for key, value in candidates.items()
            if key not in examined
        }
        examined_rows = list(examined.values())
        unexplored_rows = list(unexplored.values())
    except Exception as exc:
        coverage_note = f"Coverage unavailable: {exc}"

    context_parts = [
        f"Program: {program_slug}",
        f"Target: {_display_path(target_root)}",
        f"Output: {_display_path(reports_dir)}",
        "",
    ]

    if fresh:
        context_parts.extend(
            [
                "Fresh context — you don't know what other agents have found. Hunt freely, but findings will be coordinated with other agents via the shared ledger.",
                "",
            ]
        )
        context_parts.extend(_coordination_briefing(program_slug, reports_dir))
        return "\n".join(context_parts)

    context_parts.append("## Current findings (from ledger):")
    if findings:
        for finding in findings[:40]:
            fid = _normalize_text(finding.get("fid")) or "?"
            finding_type = _normalize_text(finding.get("title") or finding.get("type")) or "?"
            file_ref = _finding_file_ref(finding)
            class_name = _normalize_text(
                finding.get("vuln_class") or finding.get("class_name")
            ) or "?"
            tier = _review_tier_label(finding.get("status"))
            context_parts.append(
                f"- {fid}: {finding_type} — {file_ref} — {class_name} — {tier}"
            )
        if len(findings) > 40:
            context_parts.append(f"- ... truncated {len(findings) - 40} additional findings")
    else:
        context_parts.append("- None yet.")
    context_parts.append("")

    _append_grouped_surface_section(
        context_parts,
        "## Already examined surfaces:",
        _group_surface_entries(examined_rows),
        trailing="✅",
    )

    if coverage_note:
        context_parts.append("## Unexplored attack surface:")
        context_parts.append(f"- {coverage_note}")
        context_parts.append("")
    else:
        _append_grouped_surface_section(
            context_parts,
            "## Unexplored attack surface:",
            _group_surface_entries(unexplored_rows),
        )

    context_parts.extend(_coordination_briefing(program_slug, reports_dir))

    context_parts.extend(
        [
            "## Task:",
            "Hunt for vulnerabilities in this Electron desktop application.",
            "Focus on the unexplored surfaces above.",
            "Do NOT re-hunt surfaces already examined.",
            f"When you find a vulnerability, write a markdown report to {_display_path(reports_dir)}.",
            "Use this format for each report:",
            "  # [Vulnerability Title]",
            "  **Type:** [short type]",
            "  **Class:** [vuln class]",
            "  **Severity:** [severity]",
            "  **File:** [file:line]",
            "  ## Description",
            "  [what you found]",
            "After writing all reports, exit.",
        ]
    )
    return "\n".join(context_parts)


def _run_codex_hunt(context: str, workdir: Path, *, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    workdir.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [
            "codex",
            "exec",
            "-s",
            "danger-full-access",
            "-a",
            "never",
            "--skip-git-repo-check",
            "-C",
            str(workdir),
        ],
        cwd=str(workdir),
        input=context,
        text=True,
        timeout=timeout,
        check=False,
    )


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _split_file_reference(value: str) -> tuple[str, int]:
    raw = str(value or "").strip()
    if not raw:
        return "", 0
    match = re.match(r"^(?P<path>.+?)(?::(?P<line>\d+))(?::\d+)?$", raw)
    if not match:
        return raw, 0
    return match.group("path").strip(), _safe_int(match.group("line"))


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_severity(value: Any) -> str:
    text = _normalize_text(value).upper()
    return text if text in SEVERITIES else "UNKNOWN"


def _normalize_class(value: Any) -> str:
    text = _normalize_text(value).lower().replace("_", "-").replace(" ", "-")
    return text


def _bool_prompt(question: str) -> bool:
    try:
        answer = input(f"{question} [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def _read_multiline_input(prompt: str) -> str:
    print(prompt)
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip() and lines:
            break
        if not line.strip() and not lines:
            return ""
        lines.append(line)
    return "\n".join(lines).strip()


def _derive_title(description: str, fallback: str = "Untitled finding") -> str:
    text = " ".join(part.strip() for part in description.splitlines() if part.strip())
    if not text:
        return fallback
    sentence = re.split(r"(?<=[.!?])\s+", text, maxsplit=1)[0].strip()
    return sentence[:140] if sentence else fallback


def _infer_class(text_blob: str) -> str:
    text = text_blob.lower()
    if any(token in text for token in ("better-sqlite3", "sqlite", "native module", "preload bridge")):
        return "native-module-abuse"
    if any(token in text for token in ("contextbridge", "ipcrenderer", "ipcmain", "postmessage", "ipc port", "preload")):
        return "ipc-trust-boundary"
    if any(token in text for token in ("innerhtml", "outerhtml", "document.write", "dom xss", "xss")):
        return "dom-xss"
    if any(token in text for token in ("prototype pollution", "__proto__", "constructor.prototype")):
        return "prototype-pollution"
    if any(token in text for token in ("path traversal", "../", "..\\", "readfile", "writefile")):
        return "path-traversal"
    if any(token in text for token in ("ssrf", "fetch internal", "169.254.169.254")):
        return "ssrf"
    if any(token in text for token in ("deserialize", "pickle", "yaml.load", "marshal.load")):
        return "unsafe-deserialization"
    if any(token in text for token in ("nodeintegration", "contextisolation", "remote module")):
        return "node-integration"
    if any(token in text for token in ("child_process", "exec(", "spawn(", "shell", "rce")):
        return "exec-sink-reachability"
    if any(token in text for token in ("overflow", "use-after-free", "out-of-bounds", "unsafe.pointer")):
        return "memory-unsafe-parser"
    return "unknown"


def _infer_sink(note: dict[str, Any]) -> str:
    explicit = _normalize_text(note.get("sink"))
    if explicit:
        return explicit

    text = "\n".join(
        _normalize_text(note.get(key))
        for key in ("description", "type", "title", "exploitability", "review_notes")
    ).strip()
    call_match = CALL_RE.search(text)
    if call_match:
        return call_match.group(1).strip()

    title = _normalize_text(note.get("type")) or _normalize_text(note.get("title"))
    if title:
        return title
    return _derive_title(text, fallback="manual finding")


def _infer_review_tier(parsed: dict[str, Any]) -> str:
    explicit = _normalize_text(parsed.get("review_tier")).upper()
    if explicit in {"CONFIRMED", "DORMANT_ACTIVE", "DORMANT_HYPOTHETICAL"}:
        return explicit

    blob = " ".join(
        _normalize_text(parsed.get(key))
        for key in ("blocked_reason", "chain_requirements", "exploitability", "description", "review_notes")
    ).lower()
    vague = (
        "inconclusive",
        "not confirmed",
        "needs more research",
        "unclear",
        "possible",
        "potential",
        "might",
        "may",
        "theoretical",
    )
    blocked = (
        "needs prior",
        "requires prior",
        "depends on",
        "needs xss",
        "requires xss",
        "renderer compromise",
        "user interaction",
        "admin role",
        "authenticated access",
        "local foothold",
    )
    if any(marker in blob for marker in vague):
        return "DORMANT_HYPOTHETICAL"
    if any(marker in blob for marker in blocked) or _normalize_text(parsed.get("chain_requirements")):
        return "DORMANT_ACTIVE"
    if _normalize_text(parsed.get("blocked_reason")):
        return "DORMANT_HYPOTHETICAL"
    return "CONFIRMED"


def _report_bucket(finding: dict[str, Any]) -> str:
    if str(finding.get("category", "class")).strip().lower() == "novel":
        return "novel"
    if str(finding.get("review_tier", "")).strip().upper() == "CONFIRMED":
        return "confirmed"
    return "dormant"


def _report_header(bucket: str) -> str:
    if bucket == "confirmed":
        return "# Confirmed Findings\n\n"
    if bucket == "novel":
        return "# Novel Findings\n\n"
    return "# Dormant Findings\n\n"


def _display_file_reference(finding: dict[str, Any]) -> str:
    file_path, inline_line = _split_file_reference(_normalize_text(finding.get("file")))
    line = _safe_int(finding.get("line")) or inline_line
    if line > 0:
        return f"{file_path}:{line}"
    return file_path


def _render_confirmed_section(finding: dict[str, Any]) -> str:
    severity = _normalize_text(finding.get("severity_label") or finding.get("severity") or "UNKNOWN")
    return "\n".join(
        [
            f"## [{severity}] {finding['vulnerability_name']}",
            f"**Type:** {finding['type']}",
            f"**Class:** {finding.get('class_name', 'unknown')}",
            f"**File:** {_display_file_reference(finding)}",
            f"**Agent:** {finding['agent']}",
            "",
            "### Description",
            _normalize_text(finding.get("description")) or "None provided.",
            "",
            "### Source -> Sink",
            f"Source: {_normalize_text(finding.get('source')) or 'None provided.'}",
            f"Trust boundary: {_normalize_text(finding.get('trust_boundary')) or 'None provided.'}",
            f"Flow: {_normalize_text(finding.get('flow_path')) or 'None provided.'}",
            f"Sink: {_normalize_text(finding.get('sink')) or 'None provided.'}",
            "",
            "### Impact",
            _normalize_text(finding.get("impact")) or "None provided.",
            "",
            "### Review Notes",
            _normalize_text(finding.get("review_notes")) or "None provided.",
            "",
            "### PoC",
            _normalize_text(finding.get("poc")) or "None provided.",
            "",
            "### CVSS Estimate",
            f"{_normalize_text(finding.get('cvss_vector'))} -> {_normalize_text(finding.get('cvss_score'))} ({severity})",
            "",
            "### Remediation",
            _normalize_text(finding.get("remediation")) or "None provided.",
            "",
        ]
    )


def _render_dormant_section(finding: dict[str, Any]) -> str:
    tier = _normalize_text(finding.get("review_tier") or "DORMANT").upper()
    return "\n".join(
        [
            f"## [{tier}] {finding['vulnerability_name']}",
            f"**Type:** {finding['type']}",
            f"**Class:** {finding.get('class_name', 'unknown')}",
            f"**File:** {_display_file_reference(finding)}",
            f"**Agent:** {finding['agent']}",
            "",
            "### Why It's Dangerous (if triggered)",
            _normalize_text(finding.get("description")) or "None provided.",
            "",
            "### Source -> Sink",
            f"Source: {_normalize_text(finding.get('source')) or 'None provided.'}",
            f"Trust boundary: {_normalize_text(finding.get('trust_boundary')) or 'None provided.'}",
            f"Flow: {_normalize_text(finding.get('flow_path')) or 'None provided.'}",
            f"Sink: {_normalize_text(finding.get('sink')) or 'None provided.'}",
            "",
            "### Impact If Chained",
            _normalize_text(finding.get("impact")) or "None provided.",
            "",
            "### Review Notes",
            _normalize_text(finding.get("review_notes")) or "None provided.",
            "",
            "### Why It's Blocked Right Now",
            _normalize_text(finding.get("blocked_reason")) or "None provided.",
            "",
            "### What's Needed to Exploit",
            _normalize_text(finding.get("chain_requirements")) or "None provided.",
            "",
            "### Remediation",
            _normalize_text(finding.get("remediation")) or "None provided.",
            "",
        ]
    )


def _render_novel_section(finding: dict[str, Any]) -> str:
    tier = _normalize_text(finding.get("review_tier") or "DORMANT").upper()
    lines = [
        f"## [{tier}] {finding['vulnerability_name']}",
        f"**Type:** {finding['type']}",
        f"**Discovered During Class Pass:** {finding['agent']}",
        f"**File:** {_display_file_reference(finding)}",
        "",
        "### Why It Looks Novel",
        _normalize_text(finding.get("description")) or "None provided.",
        "",
        "### Source -> Sink",
        f"Source: {_normalize_text(finding.get('source')) or 'None provided.'}",
        f"Trust boundary: {_normalize_text(finding.get('trust_boundary')) or 'None provided.'}",
        f"Flow: {_normalize_text(finding.get('flow_path')) or 'None provided.'}",
        f"Sink: {_normalize_text(finding.get('sink')) or 'None provided.'}",
        "",
        "### Impact",
        _normalize_text(finding.get("impact")) or "None provided.",
        "",
        "### Review Notes",
        _normalize_text(finding.get("review_notes")) or "None provided.",
        "",
    ]
    if tier == "CONFIRMED":
        lines.extend(["### PoC", _normalize_text(finding.get("poc")) or "None provided.", ""])
    else:
        lines.extend(
            [
                "### Why It's Blocked Right Now",
                _normalize_text(finding.get("blocked_reason")) or "None provided.",
                "",
                "### What's Needed to Chain It",
                _normalize_text(finding.get("chain_requirements")) or "None provided.",
                "",
            ]
        )
    lines.extend(["### Remediation", _normalize_text(finding.get("remediation")) or "None provided.", ""])
    return "\n".join(lines)


def _ghost_report_paths(program: str, hunt_type: str) -> tuple[Path, Path, Path]:
    date_folder = time.strftime("%d-%m-%Y")
    reports_subdir = "reports_source" if hunt_type == "source" else "reports_web"
    reports_dir = (
        Path.home()
        / "Shared"
        / "bounty_recon"
        / _sanitize_program_name(program)
        / "ghost"
        / reports_subdir
        / date_folder
    )
    reports_dir.mkdir(parents=True, exist_ok=True)
    return (
        reports_dir / "confirmed.md",
        reports_dir / "dormant.md",
        reports_dir / "novel_findings.md",
    )


def _append_report_section(path: Path, bucket: str, finding: dict[str, Any]) -> None:
    if bucket == "confirmed":
        section = _render_confirmed_section(finding)
    elif bucket == "novel":
        section = _render_novel_section(finding)
    else:
        section = _render_dormant_section(finding)

    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    if not existing.strip():
        existing = _report_header(bucket)
    if not existing.endswith("\n"):
        existing += "\n"
    if not existing.endswith("\n\n"):
        existing += "\n"
    path.write_text(existing + section.rstrip() + "\n", encoding="utf-8")


@dataclass(slots=True)
class ParsedFinding:
    finding: dict[str, Any]
    raw_text: str
    source_label: str
    source_path: Path | None = None


class ManualStateStore:
    def __init__(self, program: str) -> None:
        self.path = (
            Path.home()
            / "Shared"
            / "bounty_recon"
            / _sanitize_program_name(program)
            / "ghost"
            / "manual_hunter_state.json"
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "files": {}}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {"version": 1, "files": {}}
        if not isinstance(payload, dict):
            return {"version": 1, "files": {}}
        payload.setdefault("files", {})
        return payload

    def save(self, payload: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class DuplicateCommentStore:
    def __init__(self, program: str) -> None:
        self.path = (
            Path.home()
            / "Shared"
            / "bounty_recon"
            / _sanitize_program_name(program)
            / "ghost"
            / "ledger"
            / "manual_comments.jsonl"
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        *,
        fid: str,
        source_label: str,
        source_path: Path | None,
        raw_text: str,
        parsed_finding: dict[str, Any],
    ) -> None:
        payload = {
            "fid": fid,
            "recorded_at": _timestamp_iso(),
            "source_label": source_label,
            "source_path": str(source_path) if source_path is not None else "",
            "raw_note": raw_text,
            "title": _normalize_text(parsed_finding.get("title") or parsed_finding.get("type")),
            "file": _normalize_text(parsed_finding.get("file")),
            "class_name": _normalize_text(parsed_finding.get("class_name")),
            "sink": _normalize_text(parsed_finding.get("sink")),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")


class ManualHunter:
    def __init__(
        self,
        program: str,
        *,
        hunt_type: str = "source",
        source_root: str | Path | None = None,
    ) -> None:
        self.program = _sanitize_program_name(program)
        self.hunt_type = hunt_type
        self.shared_brain = load_index(self.program)
        self.source_root = self._resolve_source_root(source_root)
        self.ledger = FindingsLedger(self.program, base_dir=self.source_root or Path.cwd())
        self.comment_store = DuplicateCommentStore(self.program)
        self.state_store = ManualStateStore(self.program)

    def _resolve_source_root(self, override: str | Path | None) -> Path | None:
        if override is not None:
            return Path(override).expanduser().resolve(strict=False)
        if self.shared_brain is not None and self.shared_brain.target_root:
            return Path(self.shared_brain.target_root).expanduser().resolve(strict=False)
        return None

    @property
    def drop_dir(self) -> Path:
        path = Path.home() / "Shared" / "bounty_recon" / self.program / "manual"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def parse_text(
        self,
        raw_text: str,
        *,
        source_label: str,
        source_path: Path | None = None,
    ) -> ParsedFinding:
        text = raw_text.replace("\r\n", "\n").strip()
        if not text:
            raise ValueError("finding note is empty")

        parsed: dict[str, str] = {}
        narrative_lines: list[str] = []
        current_key: str | None = None

        for raw_line in text.splitlines():
            line = raw_line.rstrip()
            match = FIELD_RE.match(line)
            if match:
                label = match.group("label").strip().lower().replace("-", " ")
                key = FIELD_ALIASES.get(label)
                if key:
                    value = match.group("value").strip()
                    parsed[key] = value
                    current_key = key if key in MULTILINE_FIELDS else None
                    continue
            if current_key and line.strip():
                parsed[current_key] = (parsed.get(current_key, "") + "\n" + line.strip()).strip()
                continue
            if line.strip():
                narrative_lines.append(line.strip())
            current_key = None

        narrative = "\n".join(narrative_lines).strip()
        if not parsed.get("description"):
            parsed["description"] = narrative
        elif narrative:
            parsed["review_notes"] = (
                (parsed.get("review_notes", "") + "\n" + narrative).strip()
            )

        if not parsed.get("file"):
            file_hint = FILE_HINT_RE.search(text)
            if file_hint:
                parsed["file"] = file_hint.group("path")
                if file_hint.group("line") and not parsed.get("line"):
                    parsed["line"] = file_hint.group("line")

        file_value = _normalize_text(parsed.get("file"))
        file_path, inline_line = _split_file_reference(file_value)
        line_number = _safe_int(parsed.get("line")) or inline_line

        class_name = _normalize_class(parsed.get("class_name"))
        if not class_name:
            class_name = _infer_class(text)

        category = _normalize_text(parsed.get("category")).lower() or ("novel" if class_name == "novel" else "class")
        if category not in {"class", "novel"}:
            category = "novel" if class_name == "novel" else "class"

        description = _normalize_text(parsed.get("description"))
        if not file_path:
            raise ValueError("finding note is missing File")
        if not description:
            raise ValueError("finding note is missing Description")

        title = _normalize_text(parsed.get("title")) or _normalize_text(parsed.get("type")) or _derive_title(description)
        finding_type = _normalize_text(parsed.get("type")) or title
        severity = _normalize_severity(parsed.get("severity"))
        sink = _infer_sink(parsed)
        exploitability = _normalize_text(parsed.get("exploitability"))
        blocked_reason = _normalize_text(parsed.get("blocked_reason"))
        chain_requirements = _normalize_text(parsed.get("chain_requirements"))
        review_tier = _infer_review_tier(parsed)
        vulnerability_name = title

        if review_tier.startswith("DORMANT") and not blocked_reason:
            blocked_reason = exploitability or "Manual finding requires additional preconditions."
        if review_tier == "DORMANT_ACTIVE" and not chain_requirements:
            chain_requirements = blocked_reason or exploitability

        if category == "novel" and not _normalize_text(parsed.get("source")):
            raise ValueError("novel finding is missing Source")

        review_notes = _normalize_text(parsed.get("review_notes"))
        if not review_notes:
            review_notes = f"Manual finding imported from {source_label}."

        impact = _normalize_text(parsed.get("impact")) or description
        remediation = _normalize_text(parsed.get("remediation")) or "Validate untrusted input and reduce trust-boundary exposure."

        finding = {
            "agent": "manual-hunter",
            "category": category,
            "class_name": class_name,
            "type": finding_type,
            "title": title,
            "vulnerability_name": vulnerability_name,
            "file": file_path,
            "line": line_number,
            "description": description,
            "severity": severity,
            "severity_label": severity,
            "context": review_notes,
            "source": _normalize_text(parsed.get("source")),
            "trust_boundary": _normalize_text(parsed.get("trust_boundary")),
            "flow_path": _normalize_text(parsed.get("flow_path")),
            "sink": sink,
            "exploitability": exploitability,
            "review_tier": review_tier,
            "tier": review_tier,
            "impact": impact,
            "blocked_reason": blocked_reason,
            "chain_requirements": chain_requirements,
            "review_notes": review_notes,
            "review_reason": review_notes,
            "remediation": remediation,
            "poc": _normalize_text(parsed.get("poc")),
            "cvss_vector": "",
            "cvss_score": "",
            "run_id": _default_run_id(),
            "manual_source_label": source_label,
        }
        return ParsedFinding(finding=finding, raw_text=text, source_label=source_label, source_path=source_path)

    def ingest(self, parsed: ParsedFinding, *, link_duplicate_comment: bool = False) -> int:
        is_duplicate, existing_fid, finding = self.ledger.check(parsed.finding)
        finding["fid"] = existing_fid or finding.get("fid", "")
        title = _normalize_text(finding.get("title") or finding.get("type"))

        if is_duplicate:
            print(f"Duplicate: {existing_fid} overlaps with {title}")
            if link_duplicate_comment or (
                sys.stdin.isatty() and not link_duplicate_comment and _bool_prompt(f"Link note to {existing_fid} as a comment")
            ):
                self.comment_store.append(
                    fid=str(existing_fid),
                    source_label=parsed.source_label,
                    source_path=parsed.source_path,
                    raw_text=parsed.raw_text,
                    parsed_finding=finding,
                )
                print(f"Linked duplicate note to {existing_fid}")
            else:
                print("Use --link-duplicate-comment to attach the note to the existing finding.")
            return 1

        self.ledger.update(finding)
        self._append_report(finding)
        self._mark_coverage(finding, parsed)
        self._print_chain_suggestions(finding)
        print(f"Added finding {finding['fid']}")
        return 0

    def _append_report(self, finding: dict[str, Any]) -> None:
        confirmed_path, dormant_path, novel_path = _ghost_report_paths(self.program, self.hunt_type)
        bucket = _report_bucket(finding)
        target_path = {
            "confirmed": confirmed_path,
            "dormant": dormant_path,
            "novel": novel_path,
        }[bucket]
        _append_report_section(target_path, bucket, finding)
        print(f"Updated report: {target_path}")

    def _coverage_relpath(self, file_value: str) -> str | None:
        if self.shared_brain is None or not self.shared_brain.files:
            return None
        raw_file = _normalize_text(file_value)
        if not raw_file:
            return None
        path_part, _ = _split_file_reference(raw_file)
        if path_part in self.shared_brain.files:
            return path_part

        candidate = Path(path_part).expanduser()
        if not candidate.is_absolute() and self.source_root is not None:
            candidate = (self.source_root / candidate).resolve(strict=False)
        if self.source_root is not None:
            with contextlib.suppress(ValueError):
                relpath = candidate.relative_to(self.source_root).as_posix()
                if relpath in self.shared_brain.files:
                    return relpath

        lowered = path_part.lower()
        for relpath in self.shared_brain.files:
            if relpath.lower() == lowered or relpath.lower().endswith("/" + lowered):
                return relpath
        return None

    def _mark_coverage(self, finding: dict[str, Any], parsed: ParsedFinding) -> None:
        vuln_class = _normalize_text(finding.get("class_name")).lower()
        if vuln_class in {"", "unknown", "novel"}:
            return
        if self.shared_brain is None or self.source_root is None:
            print("Coverage not updated: shared_brain index unavailable")
            return

        relpath = self._coverage_relpath(_normalize_text(parsed.finding.get("file")))
        if relpath is None:
            print("Coverage not updated: file not present in shared_brain")
            return

        try:
            store = CoverageStore(self.program, self.source_root)
            store.mark_examined(
                vuln_class=vuln_class,
                files=[relpath],
                method="manual-hunter",
                status="done",
                run_id=_normalize_text(finding.get("run_id")) or _default_run_id(),
                finding_fids=[_normalize_text(finding.get("fid"))],
                notes=f"Manual finding imported from {parsed.source_label}",
            )
            print(f"Coverage updated: {vuln_class} -> {relpath}")
        except Exception as exc:
            print(f"Coverage not updated: {exc}")

    def _print_chain_suggestions(self, new_finding: dict[str, Any]) -> None:
        existing = _merge_findings(
            _load_markdown_findings(self.program, self.hunt_type),
            _load_ledger_findings(self.program),
        )
        merged = [record.to_finding_dict() for record in existing]
        merged = [item for item in merged if item.get("fid") != new_finding.get("fid")] + [dict(new_finding)]

        chainable = {
            _normalize_text(item.get("fid"))
            for item in get_chainable_findings(merged)
            if _normalize_text(item.get("fid"))
        }
        if _normalize_text(new_finding.get("fid")) not in chainable:
            return

        graph = build_chain_graph(merged)
        related: set[str] = set()
        for node in graph.get("nodes", []):
            if _normalize_text(node.get("id")) != _normalize_text(new_finding.get("fid")):
                continue
            for edge in node.get("incoming", []):
                related.add(_normalize_text(edge.get("from")))
            for edge in node.get("outgoing", []):
                related.add(_normalize_text(edge.get("to")))
            break
        related.discard(_normalize_text(new_finding.get("fid")))
        if related:
            print(f"This could chain with: {', '.join(sorted(related))}")

    def ingest_file(self, note_path: Path, *, link_duplicate_comment: bool = False) -> int:
        raw_text = note_path.read_text(encoding="utf-8", errors="replace")
        parsed = self.parse_text(raw_text, source_label=str(note_path), source_path=note_path)
        return self.ingest(parsed, link_duplicate_comment=link_duplicate_comment)

    def interactive(self, *, link_duplicate_comment: bool = False) -> int:
        title = input("Title: ").strip()
        finding_type = input("Type: ").strip()
        class_name = input("Class: ").strip()
        severity = input("Severity [HIGH/MEDIUM/LOW/INFO]: ").strip()
        file_value = input("File: ").strip()
        source = input("Source: ").strip()
        sink = input("Sink: ").strip()
        trust_boundary = input("Trust Boundary: ").strip()
        flow = input("Flow: ").strip()
        exploitability = input("Exploitability: ").strip()
        description = _read_multiline_input("Description (finish with a blank line):")

        lines = [
            f"Title: {title}",
            f"Type: {finding_type}",
            f"Class: {class_name}",
            f"Severity: {severity}",
            f"File: {file_value}",
            f"Source: {source}",
            f"Sink: {sink}",
            f"Trust Boundary: {trust_boundary}",
            f"Flow: {flow}",
            f"Exploitability: {exploitability}",
            f"Description: {description}",
        ]
        parsed = self.parse_text("\n".join(lines), source_label="interactive")
        return self.ingest(parsed, link_duplicate_comment=link_duplicate_comment)

    def watch(self, *, poll_interval: float = 2.0, link_duplicate_comment: bool = False) -> int:
        state = self.state_store.load()
        print(f"Watching {self.drop_dir}")
        try:
            while True:
                files_state = dict(state.get("files", {}))
                for note_path in sorted(self.drop_dir.glob("*")):
                    if not note_path.is_file():
                        continue
                    fingerprint = f"{note_path.stat().st_mtime_ns}:{note_path.stat().st_size}"
                    if files_state.get(str(note_path)) == fingerprint:
                        continue
                    try:
                        self.ingest_file(note_path, link_duplicate_comment=link_duplicate_comment)
                    except Exception as exc:
                        print(f"Failed to ingest {note_path}: {exc}")
                    files_state[str(note_path)] = fingerprint
                state["files"] = files_state
                self.state_store.save(state)
                time.sleep(max(0.2, poll_interval))
        except KeyboardInterrupt:
            print("Stopped watching.")
            return 0

    def hunt(self, *, timeout: int = 1800, fresh: bool = False) -> int:
        target_root = self.source_root or _default_source_root(self.program)
        reports_dir = (target_root / "reports").resolve(strict=False)
        reports_dir.mkdir(parents=True, exist_ok=True)

        context = _build_hunt_context(self.program, source_root=target_root, fresh=fresh)
        if fresh:
            print(f"[/me] Fresh mode enabled for {self.program}; skipping ledger and coverage context...")
        else:
            print(f"[/me] Loading Ghost state for {self.program}...")
        print("[/me] Spawning Codex with context:")
        print(context)
        print("---")

        codex_rc = 1
        try:
            result = _run_codex_hunt(context, target_root, timeout=timeout)
            codex_rc = int(result.returncode)
        except FileNotFoundError:
            print("[/me] Codex executable not found in PATH")
        except subprocess.TimeoutExpired:
            print(f"[/me] Codex hunt timed out after {timeout} seconds")
        else:
            if codex_rc != 0:
                print(f"[/me] Codex exited with code {codex_rc}")

        print("[/me] Codex done. Running sync-reports to import findings...")
        from agents.sync_reports import sync_reports_main

        sync_rc = sync_reports_main(
            self.program,
            source_dir=str(reports_dir),
            verbose=True,
        )
        if sync_rc != 0:
            print(f"[/me] sync-reports exited with code {sync_rc}")
            return sync_rc

        print("[/me] Hunt complete!")
        return codex_rc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ingest manual findings into the Ghost pipeline or launch a Ghost-aware hunt."
    )
    parser.add_argument("program", help="Program slug under ~/Shared/bounty_recon/")
    parser.add_argument("--fresh", action="store_true", help="Run with a clean slate, ignoring prior findings.")
    mode = parser.add_mutually_exclusive_group(required=False)
    mode.add_argument("--watch", action="store_true", help="Watch the manual drop folder for notes to ingest.")
    mode.add_argument("--add", help="Paste a finding note directly.")
    mode.add_argument("--from-file", dest="from_file", help="Read a finding note from a markdown/text file.")
    mode.add_argument("--interactive", action="store_true", help="Prompt for finding fields interactively.")
    mode.add_argument(
        "--hunt",
        action="store_true",
        help="Hunt with Codex using current Ghost state as context. Loads ledger + coverage, "
        "spawns Codex with context, then runs sync-reports to import findings.",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="When hunting, skip loading ledger and coverage into the Codex prompt. Findings are still deduped "
        "and coverage is still coordinated through the shared ledger.",
    )
    parser.add_argument("--hunt-type", choices=("source", "web"), default="source", help="Report bucket root to update.")
    parser.add_argument("--source-root", help="Override the source root used for file resolution and coverage.")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Watch mode polling interval in seconds.")
    parser.add_argument(
        "--link-duplicate-comment",
        action="store_true",
        help="When a duplicate is found, attach the raw note to the existing finding comment ledger.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    hunter = ManualHunter(
        args.program,
        hunt_type=args.hunt_type,
        source_root=args.source_root,
    )

    if args.watch:
        return hunter.watch(
            poll_interval=args.poll_interval,
            link_duplicate_comment=args.link_duplicate_comment,
        )
    if args.add is not None:
        parsed = hunter.parse_text(args.add, source_label="--add")
        return hunter.ingest(parsed, link_duplicate_comment=args.link_duplicate_comment)
    if args.from_file:
        return hunter.ingest_file(Path(args.from_file).expanduser(), link_duplicate_comment=args.link_duplicate_comment)
    if args.interactive:
        return hunter.interactive(link_duplicate_comment=args.link_duplicate_comment)
    if args.hunt or not any((args.watch, args.add is not None, args.from_file, args.interactive)):
        return hunter.hunt(fresh=args.fresh)
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
