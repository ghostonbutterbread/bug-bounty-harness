#!/usr/bin/env python3
"""Import working report markdown into the Ghost pipeline."""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.chain_matrix import build_chain_graph, get_chainable_findings
from agents.coverage_store import CoverageStore
from agents.manual_hunter import (
    ManualHunter,
    ParsedFinding,
    _append_report_section,
    _default_run_id,
    _derive_title,
    _ghost_report_paths,
    _infer_class,
    _infer_review_tier,
    _normalize_text,
    _report_bucket,
)
from agents.report_checker import FindingRecord, _load_ledger_findings, _load_markdown_findings, _merge_findings


FILE_HINT_RE = (
    r"(?P<path>[\w./-]+\.(?:js|jsx|ts|tsx|py|rb|java|go|rs|php|c|cc|cpp|h|hpp|swift|kt|mjs|cjs|json|html|md))"
    r"(?:[:#](?P<line>\d+))?"
)


def _find_reports_dir(program: str, override: str | None) -> tuple[Path | None, str | None]:
    if override:
        return Path(override).expanduser().resolve(strict=False), "override"

    program_root = Path.home() / "source" / program
    candidates = [
        (program_root / "reports", "my_reports"),
        (program_root / "report", "report"),
    ]
    for candidate, mode in candidates:
        if candidate.is_dir():
            return candidate.resolve(strict=False), mode

    wildcard_matches = sorted(
        path.resolve(strict=False)
        for path in program_root.glob("*reports*")
        if path.is_dir()
    )
    if wildcard_matches:
        return wildcard_matches[0], "wildcard"
    return None, None


def _default_reports_dir(program: str) -> Path:
    return (Path.home() / "source" / program / "reports").resolve(strict=False)


def _program_root(program: str, source_dir: Path | None) -> Path:
    home_root = (Path.home() / "source" / program).resolve(strict=False)
    if home_root.exists():
        return home_root
    if source_dir is None:
        return home_root
    if source_dir.name in {"report", "reports"}:
        return source_dir.parent.resolve(strict=False)
    return source_dir.resolve(strict=False)


def _discover_report_files(source_dir: Path) -> list[Path]:
    return sorted(path for path in source_dir.rglob("*.md") if path.is_file())


def _loose_markdown_fallback(text: str, source_path: Path) -> dict[str, Any] | None:
    stripped = text.strip()
    if not stripped:
        return None

    heading_match = None
    for line in stripped.splitlines():
        if line.strip():
            heading_match = line.strip()
            break
    if heading_match is None:
        return None

    title = heading_match[2:].strip() if heading_match.startswith("# ") else heading_match
    file_match = re.search(FILE_HINT_RE, stripped)
    if not file_match:
        return None

    file_path = file_match.group("path").strip()
    line_number = int(file_match.group("line") or 0)
    description = _derive_title(stripped, fallback=title)
    blob = "\n".join((title, stripped))
    class_name = _infer_class(blob)
    review_tier = _infer_review_tier({"description": stripped, "review_notes": stripped})
    blocked_reason = stripped if review_tier.startswith("DORMANT") else ""
    chain_requirements = stripped if review_tier == "DORMANT_ACTIVE" else ""

    return {
        "title": title,
        "type": title,
        "vulnerability_name": title,
        "class_name": class_name,
        "vuln_class": class_name,
        "category": "novel" if class_name == "novel" else "class",
        "status": "confirmed" if review_tier == "CONFIRMED" else "pending-review",
        "review_tier": review_tier,
        "tier": review_tier,
        "file": file_path,
        "line": line_number,
        "description": description,
        "impact": description,
        "review_notes": f"Imported from {source_path}",
        "context": f"Imported from {source_path}",
        "blocked_reason": blocked_reason,
        "chain_requirements": chain_requirements,
        "source": "",
        "trust_boundary": "",
        "flow_path": "",
        "sink": title,
        "severity": "UNKNOWN",
        "severity_label": "UNKNOWN",
        "agent": "sync-reports",
    }


def _flexible_findings_for_file(hunter: ManualHunter, path: Path, text: str) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    try:
        parsed = hunter.parse_text(text, source_label=str(path), source_path=path)
    except ValueError:
        loose = _loose_markdown_fallback(text, path)
        if loose:
            findings.append(FindingRecord.from_dict(loose))
        return findings

    findings.append(FindingRecord.from_dict(parsed.finding))
    return findings


def _normalize_candidate(record: FindingRecord, raw_text: str, source_path: Path) -> dict[str, Any]:
    finding = record.to_finding_dict()
    title = _normalize_text(finding.get("title") or finding.get("type"))
    description = _normalize_text(finding.get("description"))
    blob = "\n".join(
        part
        for part in (
            title,
            _normalize_text(finding.get("type")),
            description,
            _normalize_text(finding.get("context")),
            _normalize_text(finding.get("exploitability")),
            _normalize_text(finding.get("source")),
            _normalize_text(finding.get("sink")),
            raw_text,
        )
        if part
    )

    if not title:
        title = _derive_title(description or raw_text, fallback=source_path.stem.replace("_", " "))
    if not description:
        description = _derive_title(raw_text, fallback=title)

    class_name = _normalize_text(finding.get("class_name") or finding.get("vuln_class")).lower()
    if not class_name or class_name == "unknown":
        class_name = _infer_class(blob)

    category = _normalize_text(finding.get("category")).lower() or ("novel" if class_name == "novel" else "class")
    if category not in {"class", "novel"}:
        category = "novel" if class_name == "novel" else "class"

    review_tier = _normalize_text(finding.get("review_tier") or finding.get("tier")).upper()
    if review_tier not in {"CONFIRMED", "DORMANT_ACTIVE", "DORMANT_HYPOTHETICAL"}:
        review_tier = _infer_review_tier(
            {
                "description": description,
                "exploitability": finding.get("exploitability"),
                "blocked_reason": finding.get("blocked_reason"),
                "chain_requirements": finding.get("chain_requirements"),
                "review_notes": finding.get("review_notes") or finding.get("context") or raw_text,
            }
        )

    status = _normalize_text(finding.get("status")).lower()
    if not status or status == "pending-review":
        if category == "novel":
            status = "novel"
        elif review_tier == "CONFIRMED":
            status = "confirmed"
        else:
            status = "pending-review"

    blocked_reason = _normalize_text(finding.get("blocked_reason"))
    chain_requirements = _normalize_text(finding.get("chain_requirements"))
    exploitability = _normalize_text(finding.get("exploitability"))
    if review_tier.startswith("DORMANT") and not blocked_reason:
        blocked_reason = exploitability or "Imported report requires additional preconditions."
    if review_tier == "DORMANT_ACTIVE" and not chain_requirements:
        chain_requirements = blocked_reason or exploitability

    review_notes = _normalize_text(finding.get("review_notes") or finding.get("context"))
    if not review_notes:
        review_notes = f"Imported from {source_path}"

    normalized = dict(finding)
    normalized.update(
        {
            "title": title,
            "type": _normalize_text(finding.get("type")) or title,
            "vulnerability_name": _normalize_text(finding.get("vulnerability_name")) or title,
            "class_name": class_name,
            "vuln_class": class_name,
            "category": category,
            "status": status,
            "review_tier": review_tier,
            "tier": review_tier,
            "description": description,
            "impact": _normalize_text(finding.get("impact")) or description,
            "context": review_notes,
            "review_notes": review_notes,
            "blocked_reason": blocked_reason,
            "chain_requirements": chain_requirements,
            "exploitability": exploitability,
            "severity": _normalize_text(finding.get("severity")).upper() or "UNKNOWN",
            "severity_label": _normalize_text(finding.get("severity_label") or finding.get("severity")).upper() or "UNKNOWN",
            "agent": _normalize_text(finding.get("agent")) or "sync-reports",
            "run_id": _normalize_text(finding.get("run_id")) or _default_run_id(),
            "manual_source_label": str(source_path),
        }
    )
    return normalized


def _is_present_value(value: Any) -> bool:
    if value in ("", None, [], {}):
        return False
    if isinstance(value, int):
        return value > 0
    return True


def _merge_single_record(structured: FindingRecord, flexible: FindingRecord) -> FindingRecord:
    merged_payload = structured.to_finding_dict()
    flexible_payload = flexible.to_finding_dict()

    weak_string_values = {"unknown", "report"}
    for key, value in flexible_payload.items():
        current = merged_payload.get(key)
        if key == "line":
            if int(current or 0) <= 0 and int(value or 0) > 0:
                merged_payload[key] = value
            continue
        if key in {"file", "description", "source", "sink", "exploitability", "context", "title", "type"}:
            if not _is_present_value(current) and _is_present_value(value):
                merged_payload[key] = value
            continue
        if key in {"severity", "severity_label"}:
            if str(current or "").strip().upper() in {"", "UNKNOWN"} and _is_present_value(value):
                merged_payload[key] = value
            continue
        if key in {"class_name", "vuln_class"}:
            if str(current or "").strip().lower() in weak_string_values and _is_present_value(value):
                merged_payload[key] = value
            continue
        if key == "agent":
            if str(current or "").strip().lower() in weak_string_values and _is_present_value(value):
                merged_payload[key] = value
            continue
        if not _is_present_value(current) and _is_present_value(value):
            merged_payload[key] = value

    return FindingRecord.from_dict(merged_payload)


def _candidates_for_file(
    program: str,
    hunt_type: str,
    hunter: ManualHunter,
    source_path: Path,
) -> list[dict[str, Any]]:
    raw_text = source_path.read_text(encoding="utf-8", errors="replace")
    structured = _load_markdown_findings(program, hunt_type, report_paths=[source_path])
    flexible = _flexible_findings_for_file(hunter, source_path, raw_text)
    if structured and flexible and len(structured) == 1 and len(flexible) == 1:
        merged = [_merge_single_record(structured[0], flexible[0])]
    elif structured:
        merged = structured
    else:
        merged = flexible

    candidates: list[dict[str, Any]] = []
    seen_fingerprints: set[str] = set()
    for record in merged:
        normalized = _normalize_candidate(record, raw_text, source_path)
        if not _normalize_text(normalized.get("file")):
            continue
        fingerprint = hunter.ledger.fingerprint_for(normalized)
        if fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(fingerprint)
        candidates.append(normalized)
    return candidates


def _append_ghost_report(program: str, hunt_type: str, finding: dict[str, Any]) -> Path:
    confirmed_path, dormant_path, novel_path = _ghost_report_paths(program, hunt_type)
    bucket = _report_bucket(finding)
    target_path = {
        "confirmed": confirmed_path,
        "dormant": dormant_path,
        "novel": novel_path,
    }[bucket]
    _append_report_section(target_path, bucket, finding)
    return target_path


def _mark_coverage(hunter: ManualHunter, finding: dict[str, Any], parsed: ParsedFinding) -> str | None:
    vuln_class = _normalize_text(finding.get("class_name")).lower()
    if vuln_class in {"", "unknown", "novel"}:
        return None
    if hunter.shared_brain is None or hunter.source_root is None:
        return None

    relpath = hunter._coverage_relpath(_normalize_text(parsed.finding.get("file")))
    if relpath is None:
        return None

    store = CoverageStore(hunter.program, hunter.source_root)
    store.mark_examined(
        vuln_class=vuln_class,
        files=[relpath],
        method="sync-reports",
        status="done",
        run_id=_normalize_text(finding.get("run_id")) or _default_run_id(),
        snapshot_id=hunter.snapshot_id,
        version_label=hunter.version_label,
        finding_fids=[_normalize_text(finding.get("fid"))],
        notes=f"Imported report from {parsed.source_label}",
    )
    return relpath


def _chain_suggestions(program: str, hunt_type: str, finding: dict[str, Any]) -> list[str]:
    existing = _merge_findings(
        _load_markdown_findings(program, hunt_type),
        _load_ledger_findings(program),
    )
    merged = [record.to_finding_dict() for record in existing]
    new_fid = _normalize_text(finding.get("fid"))
    merged = [item for item in merged if _normalize_text(item.get("fid")) != new_fid] + [dict(finding)]

    chainable = {
        _normalize_text(item.get("fid"))
        for item in get_chainable_findings(merged)
        if _normalize_text(item.get("fid"))
    }
    if new_fid not in chainable:
        return []

    graph = build_chain_graph(merged)
    related: set[str] = set()
    for node in graph.get("nodes", []):
        if _normalize_text(node.get("id")) != new_fid:
            continue
        for edge in node.get("incoming", []):
            related.add(_normalize_text(edge.get("from")))
        for edge in node.get("outgoing", []):
            related.add(_normalize_text(edge.get("to")))
        break
    related.discard(new_fid)
    return sorted(fid for fid in related if fid)


def _call_codex_exec(prompt: str, workdir: Path, timeout: int = 900) -> tuple[str, str, int]:
    workdir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".md", delete=False) as handle:
        handle.write(prompt)
        task_path = Path(handle.name)

    try:
        shell_cmd = (
            "codex exec -s danger-full-access -a never --skip-git-repo-check "
            f"-C {shlex.quote(str(workdir))} < {shlex.quote(str(task_path))}"
        )
        result = subprocess.run(
            ["bash", "-lc", shell_cmd],
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout or "", result.stderr or "", result.returncode
    finally:
        task_path.unlink(missing_ok=True)


def _memory_prompt(program: str, source_root: Path, reports_dir: Path, ledger_path: Path) -> str:
    return f"""You are preparing bug bounty source reports for the Ghost pipeline.

Program: {program}
Source root: {source_root}
Reports directory: {reports_dir}
Ledger path: {ledger_path}
Memory directory: {Path.home() / "memory"}

Task:
1. Read the ledger, recent memory entries, and recent notes under the source root.
2. Identify vulnerabilities already found for this program that do not yet have a markdown report in the reports directory.
3. Write one markdown report file per missing vulnerability directly into the reports directory.

Requirements:
- Use only evidence from the ledger, memory, and source-root notes. Do not invent findings.
- Prefer filenames like d01_sqlite_ipc.md or notion_ipc_sqlite.md.
- Use this report shape when possible:

# Finding title

**Type:** short vulnerability type
**Class:** vulnerability-class
**Severity:** HIGH
**File:** relative/path.js:123

## Description
Short clear explanation with the evidence you found.

## Source
Input or entry point.

## Sink
Dangerous sink or consequence.

## Trust Boundary
Boundary crossed, if known.

## Flow
Source to sink flow, if known.

## Exploitability
Why it is immediately exploitable or what preconditions are needed.

If nothing new can be written, print exactly NO_NEW_REPORTS and do not create files.
"""


def _write_reports_from_memory(program: str, source_root: Path, reports_dir: Path, ledger_path: Path) -> tuple[bool, str]:
    prompt = _memory_prompt(program, source_root, reports_dir, ledger_path)
    stdout_text, stderr_text, returncode = _call_codex_exec(prompt, source_root)
    ok = returncode == 0
    detail = (stdout_text or stderr_text).strip()
    return ok, detail


def _format_summary_count(label: str, count: int, noun: str, values: list[str]) -> str:
    base = f"  {label}: {count} {noun}"
    if not values:
        return base
    return f"{base} ({', '.join(values)})"


def sync_reports_main(
    program: str,
    *,
    source_dir: str | None = None,
    write_reports_from_memory: bool = False,
    verbose: bool = False,
) -> int:
    argv = [program]
    if source_dir:
        argv.extend(["--source-dir", source_dir])
    if write_reports_from_memory:
        argv.append("--write-reports-from-memory")
    if verbose:
        argv.append("--verbose")
    return main(argv)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import working report markdown into the Ghost pipeline.")
    parser.add_argument("program", help="Bug bounty program slug.")
    parser.add_argument("--source-dir", help="Optional reports directory override.")
    parser.add_argument(
        "--write-reports-from-memory",
        action="store_true",
        help="Ask Codex to write reports from memory and recent notes when no reports exist.",
    )
    parser.add_argument("--verbose", action="store_true", help="Print detailed progress.")
    args = parser.parse_args(argv)

    program = args.program
    source_dir, source_mode = _find_reports_dir(program, args.source_dir)
    source_root = _program_root(program, source_dir)
    hunt_type = "source"
    hunter = ManualHunter(program, hunt_type=hunt_type, source_root=source_root)

    if source_dir is None:
        source_dir = _default_reports_dir(program)
    report_files = _discover_report_files(source_dir) if source_dir.is_dir() else []

    if args.verbose:
        print(f"[sync_reports] source_dir={source_dir} mode={source_mode or 'missing'} files={len(report_files)}")

    memory_write_attempted = False
    memory_write_failed = False
    memory_write_detail = ""
    if not report_files and args.write_reports_from_memory:
        memory_write_attempted = True
        source_dir.mkdir(parents=True, exist_ok=True)
        ok, detail = _write_reports_from_memory(program, source_root, source_dir, hunter.ledger.path)
        memory_write_failed = not ok
        memory_write_detail = detail
        if args.verbose and detail:
            print(detail)
        report_files = _discover_report_files(source_dir)
        if args.verbose:
            print(f"[sync_reports] memory_write_ok={ok} files_after_write={len(report_files)}")

    if not report_files:
        print("sync_reports complete")
        print(f"  Found: 0 reports in {source_dir}")
        print("  Imported: 0 new findings")
        print("  Skipped: 0 duplicates")
        if memory_write_failed:
            if memory_write_detail:
                print(f"  Memory write failed: {memory_write_detail}")
            else:
                print("  Memory write failed: codex exec returned non-zero")
            return 1
        if memory_write_attempted:
            if memory_write_detail and memory_write_detail != "NO_NEW_REPORTS":
                print(f"  Memory write: {memory_write_detail}")
            else:
                print("  Memory write: no new reports created")
        return 0

    imported_fids: list[str] = []
    skipped_fids: list[str] = []
    chain_lines: list[str] = []

    for report_path in report_files:
        candidates = _candidates_for_file(program, hunt_type, hunter, report_path)
        if args.verbose:
            print(f"[sync_reports] parsed {len(candidates)} findings from {report_path}")

        for candidate in candidates:
            parsed = ParsedFinding(
                finding=dict(candidate),
                raw_text=report_path.read_text(encoding="utf-8", errors="replace"),
                source_label=str(report_path),
                source_path=report_path,
            )
            is_duplicate, existing_fid, finding = hunter.ledger.check(candidate)
            if is_duplicate:
                skipped_fids.append(existing_fid or "?")
                print(f"{existing_fid} already exists, skipped")
                continue

            finding = hunter.ledger.update(finding)
            report_output = _append_ghost_report(hunter.program, hunter.hunt_type, finding)
            coverage_relpath = None
            try:
                coverage_relpath = _mark_coverage(hunter, finding, parsed)
            except Exception as exc:
                if args.verbose:
                    print(f"[sync_reports] coverage update failed for {report_path}: {exc}")
            related = _chain_suggestions(program, hunt_type, finding)

            imported_fids.append(_normalize_text(finding.get("fid")))
            print(f"ADDED {finding['fid']}")
            if args.verbose:
                print(f"[sync_reports] report={report_output}")
                if coverage_relpath:
                    print(f"[sync_reports] coverage={coverage_relpath}")
            if related:
                chain_lines.append(f"{finding['fid']} could chain with {', '.join(related)}")

    print("sync_reports complete")
    print(f"  Found: {len(report_files)} reports in {source_dir}")
    print(_format_summary_count("Imported", len(imported_fids), "new findings", imported_fids))
    duplicate_summary = [f"{fid} already in ledger" for fid in skipped_fids]
    print(_format_summary_count("Skipped", len(skipped_fids), "duplicates", duplicate_summary))
    if chain_lines:
        print(f"  Chain suggestions: {'; '.join(chain_lines)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
