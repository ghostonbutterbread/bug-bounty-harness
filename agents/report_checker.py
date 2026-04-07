#!/usr/bin/env python3
"""Validate bug bounty findings against source code and expand nearby attack surface."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.findings_ledger import FindingsLedger


DEFAULT_CODEX_TIMEOUT = 600
CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
SEVERITY_ORDER = {"UNKNOWN": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
PLACEHOLDER_MARKERS = (
    "short vulnerability label",
    "short novel pattern label",
    "identified source",
    "dangerous sink category",
    "what boundary is crossed",
    "how the data moves",
    "relevant code context and reasoning",
    "why this path is dangerous",
    "why an attacker can or cannot trigger it",
    "boundary crossed or unresolved boundary question",
    "known or suspected flow",
)
JSON_RE = re.compile(r"\{.*\}", re.DOTALL)
FILE_LINE_RE = re.compile(r"^(?P<path>.+?)(?::(?P<line>\d+))(?::\d+)?$")
JS_FILE_RE = re.compile(r"[\w./-]+\.(?:js|jsx|ts|tsx|cjs|mjs)(?::\d+)?")
IPC_STRING_RE = re.compile(r"""(?:"|')([a-z0-9_.-]+:[a-z0-9_.-]+)(?:"|')""", re.IGNORECASE)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sanitize_program_name(program: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(program).strip())
    return cleaned or "default_program"


def _today_iso() -> str:
    return _utc_now().date().isoformat()


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _normalize_severity(value: Any) -> str:
    text = str(value or "").strip().upper()
    return text if text in SEVERITY_ORDER else "UNKNOWN"


def _normalize_confidence(value: Any) -> str:
    text = str(value or "").strip().upper()
    return text if text in CONFIDENCE_ORDER else "LOW"


def _is_meaningful_text(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text) and not _is_placeholder_text(text)


def _should_prefer_incoming(key: str, current: Any, incoming: Any) -> bool:
    if incoming in ("", None, [], {}):
        return False
    if current in ("", None, [], {}):
        return True

    if key == "severity":
        return _normalize_severity(current) == "UNKNOWN" and _normalize_severity(incoming) != "UNKNOWN"
    if key == "line":
        return _safe_int(current) <= 0 and _safe_int(incoming) > 0
    if key == "status":
        return str(current).strip() in {"", "pending-review"} and str(incoming).strip() not in {"", "pending-review"}
    if key == "chain_status":
        return str(current).strip() in {"", "unchained"} and str(incoming).strip() not in {"", "unchained"}
    if key in {
        "title",
        "type",
        "file",
        "sink",
        "description",
        "context",
        "source",
        "trust_boundary",
        "flow_path",
        "exploitability",
    }:
        return not _is_meaningful_text(current) and _is_meaningful_text(incoming)
    return False


def _split_file_reference(value: Any) -> tuple[str, int]:
    raw = str(value or "").strip()
    if not raw:
        return "", 0
    match = FILE_LINE_RE.match(raw)
    if not match:
        return raw, 0
    return match.group("path").strip(), _safe_int(match.group("line"))


@dataclass(slots=True)
class FindingRecord:
    fid: str
    title: str
    vuln_class: str
    category: str
    status: str
    chain_status: str
    file: str
    line: int
    severity: str
    description: str
    context: str
    source: str
    trust_boundary: str
    flow_path: str
    sink: str
    exploitability: str
    discovered_date: str
    last_seen: str
    agent: str
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "FindingRecord":
        file_value, inline_line = _split_file_reference(payload.get("file", ""))
        line = _safe_int(payload.get("line")) or inline_line
        title = str(
            payload.get("title")
            or payload.get("type")
            or payload.get("vulnerability_name")
            or "Untitled finding"
        ).strip()
        vuln_class = str(
            payload.get("vuln_class")
            or payload.get("class_name")
            or payload.get("agent")
            or "unknown"
        ).strip()
        category = str(payload.get("category") or "class").strip().lower() or "class"
        if vuln_class == "novel":
            category = "novel"
        return cls(
            fid=str(payload.get("fid", "")).strip(),
            title=title,
            vuln_class=vuln_class,
            category=category,
            status=str(payload.get("status", "")).strip() or "pending-review",
            chain_status=str(payload.get("chain_status", "")).strip() or "unchained",
            file=file_value,
            line=line,
            severity=_normalize_severity(payload.get("severity")),
            description=str(payload.get("description", "")).strip(),
            context=str(payload.get("context", "")).strip(),
            source=str(payload.get("source", "")).strip(),
            trust_boundary=str(payload.get("trust_boundary", "")).strip(),
            flow_path=str(payload.get("flow_path", "")).strip(),
            sink=str(payload.get("sink", "")).strip(),
            exploitability=str(
                payload.get("exploitability")
                or payload.get("blocked_reason")
                or payload.get("chain_requirements")
                or ""
            ).strip(),
            discovered_date=str(payload.get("discovered_date", "")).strip() or _today_iso(),
            last_seen=str(payload.get("last_seen", "")).strip() or _today_iso(),
            agent=str(payload.get("agent", "")).strip(),
            raw=dict(payload),
        )

    def key(self) -> tuple[str, str, int, str]:
        return (
            self.fid.upper(),
            self.title.strip().lower(),
            self.line,
            self.vuln_class.strip().lower(),
        )

    def logical_key(self) -> tuple[str, str, int, str]:
        return (
            self.title.strip().lower(),
            self.file.strip().lower(),
            self.line,
            self.vuln_class.strip().lower(),
        )

    def merge(self, other: "FindingRecord") -> "FindingRecord":
        base = dict(self.raw)
        for key, value in other.raw.items():
            if _should_prefer_incoming(key, base.get(key), value):
                base[key] = value
        merged = FindingRecord.from_dict(base)
        if not merged.fid:
            merged.fid = self.fid or other.fid
        return merged

    def to_finding_dict(self) -> dict[str, Any]:
        payload = dict(self.raw)
        payload.update(
            {
                "fid": self.fid,
                "title": self.title,
                "type": payload.get("type") or self.title,
                "vuln_class": self.vuln_class,
                "class_name": payload.get("class_name") or self.vuln_class,
                "category": self.category,
                "status": self.status,
                "chain_status": self.chain_status,
                "file": self.file,
                "line": self.line,
                "severity": self.severity,
                "description": self.description,
                "context": self.context,
                "source": self.source,
                "trust_boundary": self.trust_boundary,
                "flow_path": self.flow_path,
                "sink": self.sink,
                "exploitability": self.exploitability,
                "discovered_date": self.discovered_date,
                "last_seen": self.last_seen,
                "agent": self.agent,
            }
        )
        return payload


def _is_placeholder_text(text: str) -> bool:
    lowered = text.strip().lower()
    if not lowered:
        return True
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def is_placeholder_finding(finding: FindingRecord) -> bool:
    title = finding.title.strip().lower()
    if title in {"short vulnerability label", "short novel pattern label", "untitled finding"}:
        return True
    fields = [
        finding.title,
        finding.description,
        finding.source,
        finding.sink,
        finding.trust_boundary,
        finding.flow_path,
        finding.context,
    ]
    return sum(1 for value in fields if _is_placeholder_text(value)) >= 3


def _reports_root(program: str, hunt_type: str) -> Path:
    return Path.home() / "Shared" / "bounty_recon" / _sanitize_program_name(program) / "ghost" / f"reports_{hunt_type}"


def _validation_report_paths(program: str, hunt_type: str) -> tuple[Path, Path, Path]:
    reports_root = _reports_root(program, hunt_type)
    reports_root.mkdir(parents=True, exist_ok=True)
    date_stamp = _today_iso()
    artifacts_dir = reports_root / "validation_artifacts" / date_stamp
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    return (
        reports_root / f"validation_{date_stamp}.md",
        reports_root / f"validation_{date_stamp}.json",
        artifacts_dir,
    )


def _default_findings_json(program: str) -> Path:
    return Path.home() / "Shared" / "bounty_recon" / _sanitize_program_name(program) / "0day_team" / "findings.jsonl"


def _load_jsonl_findings(path: Path) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    if not path.exists():
        return findings
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                print(f"[report_checker] skipped invalid JSONL line {line_number}: {path}")
                continue
            if not isinstance(payload, dict):
                continue
            findings.append(FindingRecord.from_dict(payload))
    return findings


def _load_ledger_findings(program: str) -> list[FindingRecord]:
    ledger_path = (
        Path.home() / "Shared" / "bounty_recon" / _sanitize_program_name(program) / "ghost" / "ledger" / "findings_ledger.json"
    )
    if not ledger_path.exists():
        return []
    try:
        payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    raw_findings = payload.get("findings", [])
    if not isinstance(raw_findings, list):
        return []
    findings: list[FindingRecord] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        mapped = {
            "fid": item.get("fid"),
            "title": item.get("title"),
            "type": item.get("title"),
            "vuln_class": item.get("vuln_class"),
            "class_name": item.get("vuln_class"),
            "category": item.get("category"),
            "status": item.get("status"),
            "chain_status": item.get("chain_status"),
            "file": item.get("file"),
            "line": item.get("line"),
            "sink": item.get("sink"),
            "discovered_date": item.get("discovered_date"),
            "last_seen": item.get("last_seen"),
            "description": "",
            "context": "",
            "source": "",
            "trust_boundary": "",
            "flow_path": "",
            "exploitability": "",
            "severity": "UNKNOWN",
            "agent": item.get("vuln_class"),
        }
        findings.append(FindingRecord.from_dict(mapped))
    return findings


def _latest_report_path(reports_root: Path, filename: str) -> Path | None:
    dated_candidates = [path for path in reports_root.glob(f"*/{filename}") if path.is_file()]
    legacy_candidates = [path for path in reports_root.glob(f"{filename[:-3]}_*") if path.is_file()]
    candidates = dated_candidates + legacy_candidates
    if not candidates:
        return None
    return max(candidates, key=lambda item: item.stat().st_mtime)


def _extract_markdown_field(block: str, label: str) -> str:
    match = re.search(re.escape(label) + r"\s*(.+?)(?:\n|$)", block)
    return match.group(1).strip() if match else ""


def _extract_markdown_section(block: str, heading: str) -> str:
    match = re.search(re.escape(heading) + r"\n(.+?)(?=\n###\s|\n##\s|\Z)", block, re.DOTALL)
    return match.group(1).strip() if match else ""


def _extract_markdown_field_aliases(block: str, labels: Sequence[str]) -> str:
    for label in labels:
        value = _extract_markdown_field(block, label)
        if value:
            return value
    return ""


def _extract_markdown_section_aliases(block: str, headings: Sequence[str]) -> str:
    for heading in headings:
        value = _extract_markdown_section(block, heading)
        if value:
            return value
    return ""


def _finding_record_from_block(
    block: str,
    *,
    title: str,
    default_category: str,
    default_status: str,
    tier: str,
) -> FindingRecord:
    class_name = (
        _extract_markdown_field_aliases(
            block,
            ("**Class:**", "**Discovered During Class Pass:**", "Class:", "Discovered During Class Pass:"),
        )
        or "unknown"
    )
    return FindingRecord.from_dict(
        {
            "fid": "",
            "title": title,
            "type": _extract_markdown_field_aliases(block, ("**Type:**", "Type:")) or title,
            "class_name": class_name,
            "vuln_class": class_name,
            "category": default_category,
            "status": "confirmed" if tier == "CONFIRMED" else default_status,
            "chain_status": "unchained",
            "file": _extract_markdown_field_aliases(block, ("**File:**", "File:")),
            "description": _extract_markdown_section_aliases(
                block,
                (
                    "### Why It's Dangerous (if triggered)",
                    "### Why It Looks Novel",
                    "### Why It's Dangerous",
                    "## Description",
                    "### Description",
                ),
            ),
            "source": _extract_markdown_field_aliases(block, ("Source:", "**Source:**"))
            or _extract_markdown_section_aliases(block, ("## Source", "### Source")),
            "trust_boundary": _extract_markdown_field_aliases(
                block,
                ("Trust boundary:", "**Trust Boundary:**", "Trust Boundary:", "**Trust boundary:**"),
            )
            or _extract_markdown_section_aliases(block, ("## Trust Boundary", "### Trust Boundary")),
            "flow_path": _extract_markdown_field_aliases(block, ("Flow:", "**Flow:**"))
            or _extract_markdown_section_aliases(block, ("## Flow", "### Flow")),
            "sink": _extract_markdown_field_aliases(block, ("Sink:", "**Sink:**"))
            or _extract_markdown_section_aliases(block, ("## Sink", "### Sink")),
            "exploitability": _extract_markdown_section_aliases(
                block,
                (
                    "### Why It's Blocked Right Now",
                    "### What's Needed to Exploit",
                    "### What's Needed to Chain It",
                    "## Exploitability",
                    "### Exploitability",
                ),
            ),
            "context": _extract_markdown_section_aliases(block, ("### Review Notes", "## Review Notes")),
            "severity": _extract_markdown_field_aliases(block, ("**Severity:**", "Severity:")) or "UNKNOWN",
            "agent": _extract_markdown_field_aliases(block, ("**Agent:**", "Agent:")) or "report",
        }
    )


def _load_markdown_findings_from_text(
    text: str,
    *,
    default_category: str,
    default_status: str,
) -> list[FindingRecord]:
    stripped = text.strip()
    if not stripped:
        return []

    findings: list[FindingRecord] = []
    blocks = re.split(r"\n##\s+\[", text)
    if len(blocks) > 1:
        for block in blocks[1:]:
            match = re.match(r"([A-Z_]+)\]\s+(.+?)(?:\n|$)", block, re.DOTALL)
            if not match:
                continue
            tier = match.group(1).strip().upper()
            title = match.group(2).strip()
            findings.append(
                _finding_record_from_block(
                    block,
                    title=title,
                    default_category=default_category,
                    default_status=default_status,
                    tier=tier,
                )
            )
        if findings:
            return findings

    title_match = re.search(r"(?m)^#\s+(.+?)\s*$", stripped)
    title = title_match.group(1).strip() if title_match else stripped.splitlines()[0].strip()
    tier = _extract_markdown_field_aliases(stripped, ("**Tier:**", "Tier:", "**Review Tier:**", "Review Tier:")).upper()
    if tier not in {"CONFIRMED", "DORMANT_ACTIVE", "DORMANT_HYPOTHETICAL"}:
        tier = ""

    generic = _finding_record_from_block(
        stripped,
        title=title,
        default_category=default_category,
        default_status=default_status,
        tier=tier,
    )
    if any(
        (
            generic.title.strip(),
            generic.file.strip(),
            generic.description.strip(),
            generic.source.strip(),
            generic.sink.strip(),
        )
    ):
        return [generic]
    return []


def _report_defaults_for_path(path: Path) -> tuple[str, str]:
    lowered = path.name.lower()
    if "novel" in lowered:
        return "novel", "novel"
    if "confirmed" in lowered:
        return "class", "confirmed"
    return "class", "pending-review"


def _load_markdown_findings(
    program: str,
    hunt_type: str,
    report_paths: Sequence[str | Path] | None = None,
) -> list[FindingRecord]:
    findings: list[FindingRecord] = []

    if report_paths is None:
        reports_root = _reports_root(program, hunt_type)
        report_specs = [
            ("confirmed.md", "class", "confirmed"),
            ("dormant.md", "class", "pending-review"),
            ("novel_findings.md", "novel", "novel"),
        ]
        for filename, default_category, default_status in report_specs:
            path = _latest_report_path(reports_root, filename)
            if path is None:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            findings.extend(
                _load_markdown_findings_from_text(
                    text,
                    default_category=default_category,
                    default_status=default_status,
                )
            )
        return findings

    for raw_path in report_paths:
        path = Path(raw_path).expanduser()
        if not path.is_file():
            continue
        default_category, default_status = _report_defaults_for_path(path)
        text = path.read_text(encoding="utf-8", errors="replace")
        findings.extend(
            _load_markdown_findings_from_text(
                text,
                default_category=default_category,
                default_status=default_status,
            )
        )
    return findings


def _merge_findings(*sources: Iterable[FindingRecord]) -> list[FindingRecord]:
    merged: list[FindingRecord] = []
    by_fid: dict[str, int] = {}
    by_logical: dict[tuple[str, str, int, str], int] = {}
    for source in sources:
        for finding in source:
            target_index: int | None = None
            fid_key = finding.fid.upper()
            logical_key = finding.logical_key()
            if fid_key and fid_key in by_fid:
                target_index = by_fid[fid_key]
            elif logical_key in by_logical:
                target_index = by_logical[logical_key]

            if target_index is None:
                target_index = len(merged)
                merged.append(finding)
            else:
                merged[target_index] = merged[target_index].merge(finding)

            current = merged[target_index]
            if current.fid:
                by_fid[current.fid.upper()] = target_index
            by_logical[current.logical_key()] = target_index

    resolved = list(merged)
    for index, finding in enumerate(resolved, start=1):
        if not finding.fid:
            prefix = "N" if finding.category == "novel" else "R"
            finding.fid = f"{prefix}{index:02d}"
    return resolved


def _sort_findings(findings: list[FindingRecord]) -> list[FindingRecord]:
    def sort_key(item: FindingRecord) -> tuple[str, str, int]:
        return (item.last_seen or item.discovered_date or "", item.fid, item.line)
    return sorted(findings, key=sort_key)


def _select_findings(
    findings: list[FindingRecord],
    *,
    finding_id: str | None,
    vuln_class: str | None,
    select_all: bool,
) -> list[FindingRecord]:
    real_findings = [item for item in findings if not is_placeholder_finding(item)]
    if finding_id:
        needle = finding_id.strip().upper()
        return [item for item in real_findings if item.fid.upper() == needle]
    if vuln_class:
        needle = vuln_class.strip().lower()
        return [item for item in real_findings if item.vuln_class.strip().lower() == needle]
    if select_all:
        return _sort_findings(real_findings)
    if not real_findings:
        return []
    return [_sort_findings(real_findings)[-1]]


def _source_root_candidates(program: str, override: str | None) -> list[Path]:
    candidates: list[Path] = []
    if override:
        candidates.append(Path(override).expanduser().resolve(strict=False))
    env_source = os.environ.get("REPORT_CHECKER_SOURCE_ROOT")
    if env_source:
        candidates.append(Path(env_source).expanduser().resolve(strict=False))

    source_parent = Path.home() / "source"
    if source_parent.exists():
        for child in sorted(source_parent.iterdir()):
            if child.is_dir() and child.name.lower() == program.lower():
                candidates.append(child.resolve(strict=False))
        candidates.append(source_parent.resolve(strict=False))

    candidates.append((Path.home() / ".openclaw" / "workspace").resolve(strict=False))
    candidates.append(Path.cwd().resolve(strict=False))

    seen: set[str] = set()
    deduped: list[Path] = []
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _resolve_existing_path(candidates: Iterable[Path]) -> Path | None:
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.exists() and candidate.is_file():
            return candidate.resolve(strict=False)
    return None


def _resolve_source_file(file_value: str, source_roots: Sequence[Path]) -> Path | None:
    file_path, _ = _split_file_reference(file_value)
    if not file_path:
        return None

    raw = Path(file_path).expanduser()
    direct_candidates: list[Path] = []
    if raw.is_absolute():
        direct_candidates.append(raw)
    else:
        trimmed = file_path[2:] if file_path.startswith("./") else file_path
        relative = Path(trimmed)
        direct_candidates.extend(root / relative for root in source_roots)

    resolved = _resolve_existing_path(direct_candidates)
    if resolved is not None:
        return resolved

    parts = list(raw.parts if raw.is_absolute() else Path(file_path).parts)
    suffix_candidates: list[Path] = []
    for root in source_roots:
        for index in range(len(parts)):
            suffix = Path(*parts[index:])
            suffix_candidates.append(root / suffix)
    return _resolve_existing_path(suffix_candidates)


def _extract_support_file_refs(finding: FindingRecord) -> list[str]:
    refs: list[str] = []
    for text in (finding.context, finding.flow_path, finding.source, finding.sink, finding.description):
        refs.extend(JS_FILE_RE.findall(text))
    seen: set[str] = set()
    deduped: list[str] = []
    for ref in refs:
        clean = ref.strip("`")
        if clean in seen:
            continue
        seen.add(clean)
        deduped.append(clean)
    return deduped


def _collect_same_file_ipc_methods(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    methods = sorted({match.group(1) for match in IPC_STRING_RE.finditer(text)})
    return methods[:40]


def _collect_nearby_files(path: Path) -> list[str]:
    siblings: list[str] = []
    try:
        for child in sorted(path.parent.iterdir()):
            if child == path or not child.is_file():
                continue
            if child.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".json"}:
                continue
            siblings.append(str(child))
            if len(siblings) >= 12:
                break
    except OSError:
        return []
    return siblings


def _load_prompt_template() -> str:
    template_path = Path(__file__).resolve().parent.parent / "prompts" / "report-checker-prompt.md"
    return template_path.read_text(encoding="utf-8")


def _mode_instructions(expand_only: bool, validate_only: bool) -> str:
    if expand_only:
        return "- Expand attack surface only. Validation booleans should be conservative defaults with `performed=false`."
    if validate_only:
        return "- Validate the finding only. Expansion fields should be empty/default with `performed=false`."
    return "- Perform both validation and expansion."


def _render_prompt(
    template: str,
    finding: FindingRecord,
    *,
    primary_source: Path | None,
    supporting_files: list[Path],
    heuristic_hints: dict[str, Any],
    expand_only: bool,
    validate_only: bool,
) -> str:
    replacements = {
        "{{MODE_INSTRUCTIONS}}": _mode_instructions(expand_only, validate_only),
        "{{FINDING_JSON}}": json.dumps(finding.to_finding_dict(), indent=2, sort_keys=True),
        "{{PRIMARY_SOURCE}}": str(primary_source) if primary_source is not None else "UNRESOLVED",
        "{{SUPPORTING_FILES}}": json.dumps([str(path) for path in supporting_files], indent=2),
        "{{HEURISTIC_HINTS}}": json.dumps(heuristic_hints, indent=2, sort_keys=True),
    }
    rendered = template
    for needle, value in replacements.items():
        rendered = rendered.replace(needle, value)
    return rendered


def _extract_json_payload(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if not stripped:
        raise ValueError("empty codex output")
    try:
        payload = json.loads(stripped)
        if isinstance(payload, dict):
            return payload
    except json.JSONDecodeError:
        pass
    match = JSON_RE.search(stripped)
    if not match:
        raise ValueError("no JSON object found in codex output")
    payload = json.loads(match.group(0))
    if not isinstance(payload, dict):
        raise ValueError("codex output was not a JSON object")
    return payload


def _empty_validation(performed: bool) -> dict[str, Any]:
    return {
        "performed": performed,
        "function_name_correct": False,
        "flow_correct": False,
        "severity_justified": False,
        "blocked_reason_accurate": False,
        "corrections": [],
        "confidence": "LOW",
        "evidence": [],
    }


def _empty_expansion(performed: bool) -> dict[str, Any]:
    return {
        "performed": performed,
        "additional_ipc_methods": [],
        "related_attack_surface": [],
        "missing_prerequisites": [],
        "alternative_exploit_paths": [],
        "enrichment_notes": "",
    }


def _empty_brainstorm() -> dict[str, Any]:
    return {
        "potential_chains": [],
        "architectural_notes": [],
        "questions": [],
        "architecture_map": "",
    }


def _normalized_string_list(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    return [str(item).strip() for item in values if str(item).strip()]


def _derive_architecture_map(
    finding: FindingRecord,
    expansion: dict[str, Any],
    chained_findings: list[str],
    suggested_updates: dict[str, Any],
    supplied_map: str,
) -> str:
    supplied = str(supplied_map or "").strip()
    if supplied:
        return supplied

    resolved_file = str(suggested_updates.get("file") or finding.file).strip() or "UNRESOLVED"
    resolved_line = _safe_int(suggested_updates.get("line")) or finding.line
    source_label = f"{resolved_file}:{resolved_line}" if resolved_line else resolved_file
    map_lines = [
        "Finding Entry",
        "|",
        f"+- {source_label}  <- {finding.fid} (primary finding)",
    ]

    additional_ipc_methods = expansion.get("additional_ipc_methods", [])
    if additional_ipc_methods:
        map_lines.extend(
            [
                "|",
                "+- Same-file IPC methods",
            ]
        )
        for index, item in enumerate(additional_ipc_methods):
            branch = "\\-" if index == len(additional_ipc_methods) - 1 else "+-"
            map_lines.append(f"|  {branch} {item}")

    related_attack_surface = expansion.get("related_attack_surface", [])
    if related_attack_surface:
        map_lines.extend(
            [
                "|",
                "+- Related attack surface",
            ]
        )
        for index, item in enumerate(related_attack_surface):
            branch = "\\-" if index == len(related_attack_surface) - 1 else "+-"
            map_lines.append(f"|  {branch} {item}")

    alternative_exploit_paths = expansion.get("alternative_exploit_paths", [])
    if alternative_exploit_paths:
        map_lines.extend(
            [
                "|",
                "+- Alternative paths",
            ]
        )
        for index, item in enumerate(alternative_exploit_paths):
            branch = "\\-" if index == len(alternative_exploit_paths) - 1 else "+-"
            map_lines.append(f"|  {branch} {item}")

    if chained_findings:
        map_lines.extend(
            [
                "|",
                "\\- Potential chains",
            ]
        )
        for index, item in enumerate(chained_findings):
            branch = "\\-" if index == len(chained_findings) - 1 else "+-"
            map_lines.append(f"   {branch} {item}")

    return "\n".join(map_lines)


def _normalize_codex_result(
    finding: FindingRecord,
    payload: dict[str, Any],
    *,
    expand_only: bool,
    validate_only: bool,
) -> dict[str, Any]:
    validation = payload.get("validation")
    expansion = payload.get("expansion")
    brainstorm = payload.get("brainstorm")
    if not isinstance(validation, dict):
        validation = _empty_validation(not expand_only)
    if not isinstance(expansion, dict):
        expansion = _empty_expansion(not validate_only)
    if not isinstance(brainstorm, dict):
        brainstorm = _empty_brainstorm()

    suggested_updates = payload.get("suggested_finding_updates")
    if not isinstance(suggested_updates, dict):
        suggested_updates = {}

    normalized_expansion = {
        "performed": bool(expansion.get("performed", not validate_only)),
        "additional_ipc_methods": _normalized_string_list(expansion.get("additional_ipc_methods", [])),
        "related_attack_surface": _normalized_string_list(expansion.get("related_attack_surface", [])),
        "missing_prerequisites": _normalized_string_list(expansion.get("missing_prerequisites", [])),
        "alternative_exploit_paths": _normalized_string_list(expansion.get("alternative_exploit_paths", [])),
        "enrichment_notes": str(expansion.get("enrichment_notes", "")).strip(),
    }
    normalized_chained_findings = _normalized_string_list(payload.get("chained_findings", []))
    normalized_brainstorm = {
        "potential_chains": _normalized_string_list(brainstorm.get("potential_chains", [])),
        "architectural_notes": _normalized_string_list(brainstorm.get("architectural_notes", [])),
        "questions": _normalized_string_list(brainstorm.get("questions", [])),
        "architecture_map": _derive_architecture_map(
            finding,
            normalized_expansion,
            normalized_chained_findings,
            suggested_updates,
            str(brainstorm.get("architecture_map", "")).strip(),
        ),
    }

    normalized = {
        "finding_id": str(payload.get("finding_id") or finding.fid).strip() or finding.fid,
        "validation": {
            "performed": bool(validation.get("performed", not expand_only)),
            "function_name_correct": bool(validation.get("function_name_correct", False)),
            "flow_correct": bool(validation.get("flow_correct", False)),
            "severity_justified": bool(validation.get("severity_justified", False)),
            "blocked_reason_accurate": bool(validation.get("blocked_reason_accurate", False)),
            "corrections": _normalized_string_list(validation.get("corrections", [])),
            "confidence": _normalize_confidence(validation.get("confidence")),
            "evidence": _normalized_string_list(validation.get("evidence", [])),
        },
        "expansion": normalized_expansion,
        "brainstorm": normalized_brainstorm,
        "chained_findings": normalized_chained_findings,
        "confidence": _normalize_confidence(payload.get("confidence")),
        "further_investigation": _normalized_string_list(payload.get("further_investigation", [])),
        "suggested_finding_updates": suggested_updates,
    }
    if normalized["confidence"] == "LOW":
        normalized["confidence"] = max(
            normalized["validation"]["confidence"],
            "LOW",
            key=lambda item: CONFIDENCE_ORDER.get(item, 0),
        )
    return normalized


def _derive_status(result: dict[str, Any], expand_only: bool, validate_only: bool) -> tuple[str, str]:
    validation = result["validation"]
    expansion = result["expansion"]
    if expand_only:
        status = "validation-skipped"
    else:
        checks = [
            validation["function_name_correct"],
            validation["flow_correct"],
            validation["severity_justified"],
            validation["blocked_reason_accurate"],
        ]
        status = "validated-confirmed" if all(checks) else "validated-needs-work"

    expansion_lists = (
        expansion["additional_ipc_methods"]
        + expansion["related_attack_surface"]
        + expansion["alternative_exploit_paths"]
        + result["chained_findings"]
    )
    if validate_only:
        chain_status = "unchained"
    elif result["confidence"] == "HIGH" and expansion_lists:
        chain_status = "ready-for-chainer"
    elif expansion["missing_prerequisites"]:
        chain_status = "needs-prereq"
    else:
        chain_status = "unchained"
    return status, chain_status


def _apply_suggested_updates(finding: FindingRecord, result: dict[str, Any]) -> dict[str, Any]:
    updates = dict(finding.to_finding_dict())
    suggested = dict(result.get("suggested_finding_updates") or {})
    for key in ("title", "file", "sink", "status", "chain_status"):
        value = str(suggested.get(key, "")).strip()
        if value:
            updates[key] = value
    line = _safe_int(suggested.get("line"))
    if line > 0:
        updates["line"] = line
    severity = _normalize_severity(suggested.get("severity"))
    if severity != "UNKNOWN":
        updates["severity"] = severity
    return updates


def _run_codex_check(
    prompt: str,
    *,
    source_root: Path,
    artifact_dir: Path,
    artifact_stem: str,
    timeout: int,
    model: str | None,
) -> tuple[dict[str, Any], Path]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    raw_output_path = artifact_dir / f"{artifact_stem}_codex_output.txt"
    last_message_path = artifact_dir / f"{artifact_stem}_codex_last_message.txt"
    raw_prompt_path = artifact_dir / f"{artifact_stem}_prompt.txt"
    raw_prompt_path.write_text(prompt, encoding="utf-8")

    cmd = [
        "codex",
        "exec",
        "-s",
        "danger-full-access",
        "--skip-git-repo-check",
        "-C",
        str(source_root),
        "-o",
        str(last_message_path),
        "-",
    ]
    if model:
        cmd[2:2] = ["-m", model]

    result = subprocess.run(
        cmd,
        input=prompt,
        text=True,
        capture_output=True,
        timeout=timeout,
        cwd=str(source_root),
    )
    stdout_text = result.stdout or ""
    stderr_text = result.stderr or ""
    raw_output_path.write_text(
        stdout_text + ("\n[stderr]\n" + stderr_text if stderr_text else ""),
        encoding="utf-8",
    )
    message_text = last_message_path.read_text(encoding="utf-8", errors="replace") if last_message_path.exists() else stdout_text
    if result.returncode not in (0, 2):
        raise RuntimeError(f"codex exec failed (exit {result.returncode}): {stderr_text.strip()[:300]}")
    return _extract_json_payload(message_text), raw_output_path


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _render_markdown_report(
    program: str,
    hunt_type: str,
    source_root: Path | None,
    results: list[dict[str, Any]],
    summary: dict[str, Any],
) -> str:
    lines = [
        f"# Validation Report — {program}",
        "",
        f"- Generated: `{_utc_now().isoformat(timespec='seconds').replace('+00:00', 'Z')}`",
        f"- Hunt type: `{hunt_type}`",
        f"- Source root: `{source_root}`" if source_root is not None else "- Source root: `UNRESOLVED`",
        f"- Findings processed: `{summary['processed']}`",
        f"- Validated confirmed: `{summary['validated_confirmed']}`",
        f"- Needs work: `{summary['validated_needs_work']}`",
        f"- Chain candidates: `{summary['chain_candidates']}`",
        "",
    ]
    for result in results:
        finding = result["finding"]
        audit = result["audit"]
        validation = audit["validation"]
        expansion = audit["expansion"]
        brainstorm = audit.get("brainstorm") or _empty_brainstorm()
        updated = result["updated_finding"]
        reported_file = f"{finding.file}:{finding.line}" if finding.line else finding.file
        resolved_line = _safe_int(updated.get("line")) or finding.line
        resolved_file = str(updated.get("file") or finding.file).strip()
        lines.extend(
            [
                f"## {finding.fid} — {finding.title}",
                "",
                f"- Class: `{finding.vuln_class}`",
                f"- Reported file: `{reported_file}`",
                f"- Resolved file: `{resolved_file}:{resolved_line}`" if resolved_file else "- Resolved file: `UNRESOLVED`",
                f"- Severity: reported `{finding.severity}` / suggested `{updated.get('severity', finding.severity)}`",
                f"- Status: `{updated.get('status', finding.status)}`",
                f"- Chain status: `{updated.get('chain_status', finding.chain_status)}`",
                f"- Confidence: `{audit['confidence']}`",
                "",
                "### Validation",
                "",
                f"- Function name correct: `{validation['function_name_correct']}`",
                f"- Flow correct: `{validation['flow_correct']}`",
                f"- Severity justified: `{validation['severity_justified']}`",
                f"- Blocked reason accurate: `{validation['blocked_reason_accurate']}`",
            ]
        )
        lines.extend(["", "### Expansion", ""])
        if expansion["additional_ipc_methods"]:
            lines.append("- Additional IPC methods: " + "; ".join(expansion["additional_ipc_methods"]))
        else:
            lines.append("- Additional IPC methods: none noted")
        if expansion["related_attack_surface"]:
            lines.append("- Related attack surface: " + "; ".join(expansion["related_attack_surface"]))
        else:
            lines.append("- Related attack surface: none noted")
        if expansion["missing_prerequisites"]:
            lines.append("- Missing prerequisites: " + "; ".join(expansion["missing_prerequisites"]))
        else:
            lines.append("- Missing prerequisites: none noted")
        if expansion["alternative_exploit_paths"]:
            lines.append("- Alternative exploit paths: " + "; ".join(expansion["alternative_exploit_paths"]))
        else:
            lines.append("- Alternative exploit paths: none noted")
        if expansion["enrichment_notes"]:
            lines.append(f"- Enrichment notes: {expansion['enrichment_notes']}")
        if audit["chained_findings"]:
            lines.append("- Suggested chains: " + "; ".join(audit["chained_findings"]))
        if audit["further_investigation"]:
            lines.append("- Further investigation: " + "; ".join(audit["further_investigation"]))
        lines.extend(
            [
                "",
                "### Architecture Map",
                "",
                "```text",
                brainstorm["architecture_map"] or "No architecture map available.",
                "```",
            ]
        )
        if validation["corrections"]:
            lines.append("")
            lines.append("### Corrections")
            lines.append("")
            for item in validation["corrections"]:
                lines.append(f"- {item}")
        if validation["evidence"]:
            lines.append("")
            lines.append("### Evidence")
            lines.append("")
            for item in validation["evidence"]:
                lines.append(f"- {item}")
        lines.extend(
            [
                "",
                "### Structured Result",
                "",
                "```json",
                json.dumps(audit, indent=2, sort_keys=True),
                "```",
                "",
                "---",
                "",
                f"## 💭 Brainstorm — {finding.fid} (Speculative • NOT FOR PUBLICATION)",
                "",
            ]
        )
        if brainstorm["potential_chains"]:
            lines.append("**Chain possibilities:**")
            for item in brainstorm["potential_chains"]:
                lines.append(f"- {item}")
            lines.append("")
        if brainstorm["architectural_notes"]:
            lines.append("**Architectural notes:**")
            for item in brainstorm["architectural_notes"]:
                lines.append(f"- {item}")
            lines.append("")
        if brainstorm["questions"]:
            lines.append("**Questions to investigate:**")
            for item in brainstorm["questions"]:
                lines.append(f"- {item}")
            lines.append("")
        if not (
            brainstorm["potential_chains"]
            or brainstorm["architectural_notes"]
            or brainstorm["questions"]
        ):
            lines.append("_No brainstorm notes provided._")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _write_chainer_input(path: Path, findings: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _run_chainer(program: str, source_root: Path, findings_json: Path, hunt_type: str) -> int:
    cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent / "chainer.py"),
        program,
        "--source",
        str(source_root),
        "--findings-json",
        str(findings_json),
        "--hunt-type",
        hunt_type,
    ]
    result = subprocess.run(cmd, text=True, capture_output=True, cwd=str(Path(__file__).resolve().parent.parent))
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    return result.returncode


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate bug bounty findings against source and expand nearby attack surface.",
        epilog=(
            "Examples:\n"
            "  python3 agents/report_checker.py notion --finding D05 --source-root ~/source/Notion\n"
            "  python3 agents/report_checker.py notion --class ipc-trust-boundary --all\n"
            "  python3 agents/report_checker.py notion --all --run-chainer"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("program", help="Bug bounty program name.")
    parser.add_argument("--finding", help="Validate a specific finding ID, for example D05.")
    parser.add_argument("--class", dest="selected_class", help="Validate all findings of a class.")
    parser.add_argument("--all", action="store_true", help="Validate all matching findings.")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--expand-only", action="store_true", help="Skip validation and only expand attack surface.")
    mode_group.add_argument("--validate-only", action="store_true", help="Skip expansion and only validate claims.")
    parser.add_argument("--hunt-type", default="source", choices=("source", "web"), help="Report namespace. Default: source.")
    parser.add_argument("--findings-json", help="Optional findings.jsonl override.")
    parser.add_argument("--source-root", help="Optional application source root override.")
    parser.add_argument("--output-dir", help="Optional report output directory override.")
    parser.add_argument("--model", help="Optional codex model override.")
    parser.add_argument("--codex-timeout", type=int, default=DEFAULT_CODEX_TIMEOUT, help="Per-finding codex timeout in seconds. Default: 600.")
    parser.add_argument("--run-chainer", action="store_true", help="Run chainer for high-confidence expandable findings.")
    parser.add_argument("--skip-ledger-update", action="store_true", help="Do not persist validated status back into the ledger.")
    return parser.parse_args(list(argv) if argv is not None else sys.argv[1:])


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    program = _sanitize_program_name(args.program)
    findings_json_path = Path(args.findings_json).expanduser().resolve() if args.findings_json else _default_findings_json(program)

    findings = _merge_findings(
        _load_jsonl_findings(findings_json_path),
        _load_ledger_findings(program),
        _load_markdown_findings(program, args.hunt_type),
    )
    selected = _select_findings(
        findings,
        finding_id=args.finding,
        vuln_class=args.selected_class,
        select_all=args.all,
    )
    if not selected:
        print("[report_checker] no matching non-placeholder findings found", file=sys.stderr)
        return 1

    source_roots = _source_root_candidates(program, args.source_root)
    source_root = source_roots[0] if source_roots else None
    template = _load_prompt_template()
    markdown_path, json_path, artifact_dir = _validation_report_paths(program, args.hunt_type)
    if args.output_dir:
        custom_root = Path(args.output_dir).expanduser().resolve(strict=False)
        custom_root.mkdir(parents=True, exist_ok=True)
        markdown_path = custom_root / markdown_path.name
        json_path = custom_root / json_path.name
        artifact_dir = custom_root / artifact_dir.name
        artifact_dir.mkdir(parents=True, exist_ok=True)

    ledger = FindingsLedger(program) if not args.skip_ledger_update else None
    results: list[dict[str, Any]] = []
    chain_candidates: list[dict[str, Any]] = []

    print(f"[report_checker] program={program} findings={len(selected)} hunt_type={args.hunt_type}")
    if source_root is not None:
        print(f"[report_checker] source_root={source_root}")

    for index, finding in enumerate(selected, start=1):
        print(f"[report_checker] [{index}/{len(selected)}] {finding.fid} — {finding.title}")
        primary_source = _resolve_source_file(finding.file, source_roots)
        support_files: list[Path] = []
        for ref in _extract_support_file_refs(finding):
            resolved = _resolve_source_file(ref, source_roots)
            if resolved is not None and resolved != primary_source and resolved not in support_files:
                support_files.append(resolved)

        heuristic_hints: dict[str, Any] = {
            "same_file_ipc_methods": _collect_same_file_ipc_methods(primary_source) if primary_source is not None else [],
            "nearby_files": _collect_nearby_files(primary_source) if primary_source is not None else [],
        }
        prompt = _render_prompt(
            template,
            finding,
            primary_source=primary_source,
            supporting_files=support_files[:8],
            heuristic_hints=heuristic_hints,
            expand_only=args.expand_only,
            validate_only=args.validate_only,
        )
        artifact_stem = f"{finding.fid}_{re.sub(r'[^A-Za-z0-9._-]+', '_', finding.title)[:50]}"
        try:
            audit_payload, raw_output_path = _run_codex_check(
                prompt,
                source_root=source_root or (primary_source.parent if primary_source is not None else Path.cwd()),
                artifact_dir=artifact_dir,
                artifact_stem=artifact_stem,
                timeout=args.codex_timeout,
                model=args.model,
            )
            audit = _normalize_codex_result(
                finding,
                audit_payload,
                expand_only=args.expand_only,
                validate_only=args.validate_only,
            )
        except Exception as exc:
            raw_output_path = artifact_dir / f"{artifact_stem}_codex_output.txt"
            if not raw_output_path.exists():
                raw_output_path.write_text(str(exc) + "\n", encoding="utf-8")
            audit = {
                "finding_id": finding.fid,
                "validation": _empty_validation(not args.expand_only),
                "expansion": _empty_expansion(not args.validate_only),
                "brainstorm": _empty_brainstorm(),
                "chained_findings": [],
                "confidence": "LOW",
                "further_investigation": [f"codex execution failed: {exc}"],
                "suggested_finding_updates": {},
            }

        status, chain_status = _derive_status(audit, args.expand_only, args.validate_only)
        updated_finding = _apply_suggested_updates(finding, audit)
        updated_finding.setdefault("severity", finding.severity)
        current_status = str(updated_finding.get("status", "")).strip()
        current_chain_status = str(updated_finding.get("chain_status", "")).strip()
        if not current_status or current_status == finding.status:
            updated_finding["status"] = status
        if not current_chain_status or current_chain_status == finding.chain_status:
            updated_finding["chain_status"] = chain_status
        updated_finding["fid"] = finding.fid
        updated_finding["vuln_class"] = updated_finding.get("vuln_class") or finding.vuln_class
        updated_finding["class_name"] = updated_finding.get("class_name") or finding.vuln_class
        updated_finding["category"] = updated_finding.get("category") or finding.category
        updated_finding["title"] = updated_finding.get("title") or finding.title
        updated_finding["type"] = updated_finding.get("type") or updated_finding["title"]
        updated_finding["file"] = updated_finding.get("file") or finding.file
        updated_finding["line"] = _safe_int(updated_finding.get("line")) or finding.line
        updated_finding["sink"] = updated_finding.get("sink") or finding.sink
        updated_finding["raw_validation_artifact"] = str(raw_output_path)

        if ledger is not None and finding.fid:
            try:
                ledger.update(updated_finding)
            except Exception as exc:
                audit["further_investigation"].append(f"ledger update failed: {exc}")

        result_entry = {
            "finding": finding,
            "audit": audit,
            "updated_finding": updated_finding,
        }
        results.append(result_entry)

        if (
            not args.expand_only
            and not args.validate_only
            and updated_finding.get("chain_status") == "ready-for-chainer"
            and audit["confidence"] == "HIGH"
        ):
            chain_candidates.append(updated_finding)

    summary = {
        "program": program,
        "hunt_type": args.hunt_type,
        "generated_at": _utc_now().isoformat(timespec="seconds").replace("+00:00", "Z"),
        "processed": len(results),
        "validated_confirmed": sum(1 for item in results if item["updated_finding"].get("status") == "validated-confirmed"),
        "validated_needs_work": sum(1 for item in results if item["updated_finding"].get("status") == "validated-needs-work"),
        "chain_candidates": len(chain_candidates),
        "findings": [
            {
                "fid": item["finding"].fid,
                "title": item["finding"].title,
                "status": item["updated_finding"].get("status"),
                "chain_status": item["updated_finding"].get("chain_status"),
                "confidence": item["audit"]["confidence"],
                "severity": item["updated_finding"].get("severity", item["finding"].severity),
                "raw_validation_artifact": item["updated_finding"]["raw_validation_artifact"],
            }
            for item in results
        ],
    }

    json_payload = {
        "summary": summary,
        "results": [
            {
                "finding": item["finding"].to_finding_dict(),
                "updated_finding": item["updated_finding"],
                "audit": item["audit"],
            }
            for item in results
        ],
    }
    markdown_path.write_text(
        _render_markdown_report(program, args.hunt_type, source_root, results, summary),
        encoding="utf-8",
    )
    _write_json(json_path, json_payload)

    if args.run_chainer and chain_candidates and source_root is not None:
        chainer_input = _write_chainer_input(
            artifact_dir / f"chain_candidates_{_today_iso()}.json",
            chain_candidates,
        )
        chainer_exit = _run_chainer(program, source_root, chainer_input, args.hunt_type)
        print(f"[report_checker] chainer exit={chainer_exit}")

    print(f"[report_checker] markdown report: {markdown_path}")
    print(f"[report_checker] json report: {json_path}")
    print(
        "[report_checker] summary: "
        f"processed={summary['processed']} "
        f"validated_confirmed={summary['validated_confirmed']} "
        f"needs_work={summary['validated_needs_work']} "
        f"chain_candidates={summary['chain_candidates']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
