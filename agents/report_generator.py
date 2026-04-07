"""Generate zero-day vulnerability reports from JSONL findings."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable


SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}

IMPACT_BY_TYPE: dict[str, str] = {
    "auth-bypass": "Attackers may access protected functionality without valid authorization.",
    "command-injection": "Attackers may achieve arbitrary code execution as the affected user.",
    "csrf": "Attackers may force authenticated users to perform unwanted state-changing actions.",
    "deserialization": "Attackers may execute unintended code paths or gain remote code execution.",
    "idor": "Attackers may access or modify data that belongs to other users.",
    "lfi": "Attackers may read sensitive local files and expose secrets or source code.",
    "path-traversal": "Attackers may access files outside the intended directory boundary.",
    "rce": "Attackers may execute arbitrary code on the target system.",
    "sql-injection": "Attackers may read or modify database contents and potentially escalate to full compromise.",
    "ssrf": "Attackers may coerce the server into making unintended internal or external network requests.",
    "xss": "Attackers may execute arbitrary JavaScript in a victim's browser session.",
    "xxe": "Attackers may read local files or pivot to internal network resources through XML parsing.",
}

FIX_BY_TYPE: dict[str, str] = {
    "auth-bypass": "Enforce authorization checks server-side for every protected action and resource.",
    "command-injection": "Avoid invoking shells with untrusted input; use allowlists and structured APIs instead.",
    "csrf": "Require anti-CSRF tokens and verify Origin or Referer for state-changing requests.",
    "deserialization": "Reject untrusted serialized data or switch to a safe, schema-validated format.",
    "idor": "Bind object access to the authenticated principal and perform per-object authorization checks.",
    "lfi": "Restrict file access to approved directories and normalize paths before use.",
    "path-traversal": "Canonicalize paths and reject traversal sequences before filesystem access.",
    "rce": "Remove unsafe code execution primitives and strictly validate any user-controlled inputs.",
    "sql-injection": "Use parameterized queries everywhere and remove string-built SQL.",
    "ssrf": "Restrict outbound requests with allowlists and block access to internal address space.",
    "xss": "Apply contextual output encoding and sanitize untrusted HTML where rendering is required.",
    "xxe": "Disable external entity resolution and use hardened XML parser settings.",
}

POC_BY_TYPE: dict[str, list[str]] = {
    "auth-bypass": [
        "Authenticate as a low-privilege user or use an unauthenticated session.",
        "Send a request to the protected endpoint identified in the finding.",
        "Modify the request to remove or alter the access control assumption.",
        "Confirm the server returns protected data or performs the restricted action.",
    ],
    "command-injection": [
        "Identify the user-controlled parameter referenced in the finding.",
        "Submit a benign command separator payload to test command execution safely.",
        "Observe command output, side effects, or timing differences in the response.",
        "Replace the probe with a minimal proof payload that demonstrates code execution.",
    ],
    "csrf": [
        "Authenticate to the target application in a browser.",
        "Create an HTML form or script that issues the vulnerable state-changing request.",
        "Load the proof page from another origin while the victim session is active.",
        "Confirm the action succeeds without a valid anti-CSRF defense.",
    ],
    "idor": [
        "Authenticate as a normal user and capture a request that accesses an object.",
        "Replace the object identifier with another plausible identifier.",
        "Replay the request without changing privileges.",
        "Confirm unauthorized data access or modification occurs.",
    ],
    "lfi": [
        "Find the file path parameter identified in the finding.",
        "Submit a traversal payload that targets a benign local file.",
        "Review the response for file contents or error messages proving file access.",
        "Escalate to a more sensitive file only if permitted during validation.",
    ],
    "path-traversal": [
        "Locate the path-handling input described in the finding.",
        "Send traversal sequences that attempt to break out of the intended directory.",
        "Observe whether the application reads or writes outside the allowed path.",
        "Capture the response or side effect that proves unauthorized file access.",
    ],
    "rce": [
        "Identify the execution sink and the controllable input path.",
        "Submit a low-impact probe to confirm server-side command or code execution.",
        "Observe response content, timing, or outbound interaction that proves execution.",
        "Document the exact payload and resulting behavior.",
    ],
    "sql-injection": [
        "Identify the parameter that reaches the query logic.",
        "Submit a syntax probe or boolean condition to test query manipulation.",
        "Compare responses to true and false conditions.",
        "Capture the evidence showing attacker-controlled SQL behavior.",
    ],
    "ssrf": [
        "Identify the URL-fetching parameter or feature.",
        "Supply a controlled URL that points to an external listener or harmless internal target.",
        "Observe the server-side fetch in logs, callbacks, or response content.",
        "Confirm the application can reach destinations not intended by design.",
    ],
    "xss": [
        "Find the reflected or stored input referenced in the finding.",
        "Submit a minimal JavaScript payload appropriate to the rendering context.",
        "Load the vulnerable page and verify the payload executes.",
        "Capture the sink, context, and any security control bypass required.",
    ],
    "xxe": [
        "Identify the XML-parsing endpoint described in the finding.",
        "Submit a crafted XML document with a harmless external entity reference.",
        "Observe the response or outbound interaction that proves entity resolution.",
        "Confirm the parser accepts external entities without proper hardening.",
    ],
}


def generate_report(finding: dict, program: str, output_dir: Path | None = None) -> Path:
    """Generate a single markdown report for one finding."""
    reports_dir = output_dir or default_reports_dir(program)
    reports_dir.mkdir(parents=True, exist_ok=True)

    content = fill_template(load_template(), finding, program)
    filename = build_report_filename(finding)
    report_path = reports_dir / filename
    report_path.write_text(content, encoding="utf-8")
    return report_path


def generate_reports_for_program(
    program: str,
    findings_path: Path | None = None,
    output_dir: Path | None = None,
) -> tuple[list[Path], Path]:
    """Generate per-finding reports and a consolidated index for a program."""
    source_path = findings_path or default_findings_path(program)
    findings = load_findings(source_path)
    reports_dir = output_dir or default_reports_dir(program)
    reports_dir.mkdir(parents=True, exist_ok=True)

    generated_reports: list[Path] = []
    index_rows: list[dict[str, str]] = []

    for finding in findings:
        report_path = generate_report(finding, program, output_dir=reports_dir)
        generated_reports.append(report_path)
        index_rows.append(
            {
                "severity": normalized_severity(finding.get("severity")),
                "type": string_field(finding, "type"),
                "component": string_field(finding, "file"),
                "agent": string_field(finding, "agent"),
                "report_name": report_path.name,
            }
        )

    index_path = write_master_index(reports_dir, index_rows)
    return generated_reports, index_path


def default_findings_path(program: str) -> Path:
    """Return the expected findings.jsonl path for a program."""
    return Path.home() / "Shared" / "bounty_recon" / program / "0day_team" / "findings.jsonl"


def default_reports_dir(program: str) -> Path:
    """Return the default reports directory for a program."""
    return Path.home() / "Shared" / "bounty_recon" / program / "0day_team" / "reports"


def load_findings(findings_path: Path) -> list[dict]:
    """Load JSONL findings, skipping blank lines."""
    findings: list[dict] = []
    if not findings_path.exists():
        return findings

    with findings_path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number} of {findings_path}: {exc}"
                ) from exc
            if isinstance(parsed, dict):
                findings.append(parsed)
            else:
                raise ValueError(
                    f"Expected JSON object on line {line_number} of {findings_path}"
                )
    return findings


def load_template() -> str:
    """Load the markdown template, falling back to a built-in template if needed."""
    template_path = Path(__file__).resolve().parent.parent / "references" / "0day_report_template.md"
    if template_path.exists():
        return template_path.read_text(encoding="utf-8")
    return fallback_template()


def fill_template(template: str, finding: dict, program: str) -> str:
    """Fill the report template using finding data and generated sections."""
    summary = generate_summary(finding)
    root_cause = generate_root_cause(finding)
    impact = generate_impact(finding)
    poc = generate_poc(finding)
    fix = generate_recommended_fix(finding)
    bug_intro = generate_bug_introduction(finding, program)

    values: dict[str, str] = {
        "severity": normalized_severity(finding.get("severity")),
        "affected component": string_field(finding, "file"),
        "component": string_field(finding, "file"),
        "description": string_field(finding, "description"),
        "type": string_field(finding, "type"),
        "agent": string_field(finding, "agent"),
        "line": string_field(finding, "line"),
        "context": string_field(finding, "context"),
        "summary": summary,
        "root cause": root_cause,
        "impact": impact,
        "poc": poc,
        "recommended fix": fix,
        "fix": fix,
        "bug introduction": bug_intro,
        "program": program or "TODO: program",
    }

    rendered = template
    rendered = replace_placeholders(rendered, values)
    rendered = replace_section(rendered, "Summary", summary)
    rendered = replace_section(rendered, "Root Cause", root_cause)
    rendered = replace_section(rendered, "Impact", impact)
    rendered = replace_section(rendered, "Proof of Concept", poc)
    rendered = replace_section(rendered, "PoC", poc)
    rendered = replace_section(rendered, "Recommended Fix", fix)
    rendered = replace_section(rendered, "Bug Introduction", bug_intro)

    if rendered == template:
        rendered = fallback_template()
        rendered = replace_placeholders(rendered, values)
        rendered = replace_section(rendered, "Summary", summary)
        rendered = replace_section(rendered, "Root Cause", root_cause)
        rendered = replace_section(rendered, "Impact", impact)
        rendered = replace_section(rendered, "Proof of Concept", poc)
        rendered = replace_section(rendered, "Recommended Fix", fix)
        rendered = replace_section(rendered, "Bug Introduction", bug_intro)

    return rendered.rstrip() + "\n"


def replace_placeholders(template: str, values: dict[str, str]) -> str:
    """Replace several common placeholder styles in the template."""
    rendered = template
    for key, value in values.items():
        variants = placeholder_variants(key)
        for variant in variants:
            rendered = rendered.replace(variant, value)
    return rendered


def placeholder_variants(key: str) -> set[str]:
    """Return placeholder text variants for a logical field name."""
    base = key.strip()
    compact = normalize_key(base)
    title = " ".join(part.capitalize() for part in compact.split("_"))
    brace_key = compact
    return {
        f"{{{{{base}}}}}",
        f"{{{{ {base} }}}}",
        f"{{{base}}}",
        f"[[{base}]]",
        f"<{base}>",
        f"{{{{{title}}}}}",
        f"{{{{ {title} }}}}",
        f"{{{title}}}",
        f"[[{title}]]",
        f"<{title}>",
        f"{{{{{brace_key}}}}}",
        f"{{{{ {brace_key} }}}}",
        f"{{{brace_key}}}",
        f"[[{brace_key}]]",
        f"<{brace_key}>",
    }


def normalize_key(value: str) -> str:
    """Normalize a placeholder key into snake_case."""
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def replace_section(template: str, heading: str, body: str) -> str:
    """Replace the contents of a markdown section when the heading exists."""
    pattern = re.compile(
        rf"(^##\s+{re.escape(heading)}\s*\n)(.*?)(?=^##\s+|\Z)",
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(template)
    if not match:
        return template
    replacement = f"{match.group(1)}{body.strip()}\n\n"
    return template[: match.start()] + replacement + template[match.end() :]


def generate_summary(finding: dict) -> str:
    """Generate a short report summary from the finding."""
    vuln_type = string_field(finding, "type")
    description = string_field(finding, "description")
    component = string_field(finding, "file")
    return (
        f"The finding indicates a {vuln_type.lower()} issue in {component}. "
        f"{description}"
    )


def generate_root_cause(finding: dict) -> str:
    """Generate the root cause section from finding context."""
    component = string_field(finding, "file")
    line = string_field(finding, "line")
    context = string_field(finding, "context")
    return (
        f"The vulnerable behavior appears in `{component}` at or near line `{line}`.\n\n"
        "```text\n"
        f"{context}\n"
        "```"
    )


def generate_impact(finding: dict) -> str:
    """Infer impact text based on vulnerability type."""
    raw_type = string_field(finding, "type")
    vuln_type = raw_type.lower()
    for known_type, impact in IMPACT_BY_TYPE.items():
        if known_type in vuln_type:
            return impact
    return f"TODO: impact assessment for {raw_type}"


def generate_poc(finding: dict) -> str:
    """Generate proof-of-concept steps based on vulnerability type."""
    raw_type = string_field(finding, "type")
    vuln_type = raw_type.lower()
    steps = find_by_type(vuln_type, POC_BY_TYPE)
    if not steps:
        steps = [
            "Identify the exact request, input, or workflow that triggers the issue.",
            "Replay the vulnerable action with the minimum data needed to reproduce it.",
            "Capture the response, side effect, or behavioral difference that proves exploitation.",
            f"TODO: tailor the proof steps for {raw_type}.",
        ]
    return "\n".join(f"{index}. {step}" for index, step in enumerate(steps, start=1))


def generate_recommended_fix(finding: dict) -> str:
    """Generate a remediation placeholder or recommendation from the type."""
    raw_type = string_field(finding, "type")
    vuln_type = raw_type.lower()
    fix = find_by_type(vuln_type, FIX_BY_TYPE)
    if fix:
        return fix
    return f"TODO: recommended fix for {raw_type}"


def generate_bug_introduction(finding: dict, program: str) -> str:
    """Generate a placeholder bug introduction section with useful metadata."""
    metadata = {
        "program": program or "TODO: program",
        "agent": string_field(finding, "agent"),
        "type": string_field(finding, "type"),
        "component": string_field(finding, "file"),
        "line": string_field(finding, "line"),
        "timestamp": safe_text(finding.get("timestamp")) or "TODO: timestamp",
    }
    return (
        "TODO: determine when the bug was introduced.\n\n"
        f"- Program: {metadata['program']}\n"
        f"- Agent: {metadata['agent']}\n"
        f"- Type: {metadata['type']}\n"
        f"- Component: {metadata['component']}\n"
        f"- Line: {metadata['line']}\n"
        f"- Finding Timestamp: {metadata['timestamp']}\n"
    )


def find_by_type(vuln_type: str, mapping: dict[str, str] | dict[str, list[str]]) -> str | list[str] | None:
    """Return the first mapping value whose key appears in the vulnerability type."""
    for known_type, value in mapping.items():
        if known_type in vuln_type:
            return value
    return None


def build_report_filename(finding: dict) -> str:
    """Build the output report filename."""
    vuln_type = sanitize_filename_part(string_field(finding, "type"))
    agent = sanitize_filename_part(string_field(finding, "agent"))
    timestamp = sanitize_filename_part(resolve_timestamp(finding))
    return f"{vuln_type}_{agent}_{timestamp}.md"


def resolve_timestamp(finding: dict) -> str:
    """Resolve a stable report timestamp from finding metadata or current time."""
    raw_timestamp = safe_text(finding.get("timestamp"))
    if raw_timestamp:
        digits = re.sub(r"[^0-9]", "", raw_timestamp)
        if len(digits) >= 14:
            return digits[:14]
        if digits:
            return digits
    return datetime.now().strftime("%Y%m%d%H%M%S")


def sanitize_filename_part(value: str) -> str:
    """Sanitize a string for use in a filename."""
    cleaned = re.sub(r"[^a-z0-9]+", "_", value.strip().lower())
    cleaned = cleaned.strip("_")
    return cleaned or "unknown"


def normalized_severity(value: object) -> str:
    """Normalize severity strings to uppercase."""
    text = safe_text(value)
    if not text:
        return "UNKNOWN"
    return text.upper()


def string_field(finding: dict, field_name: str) -> str:
    """Return a string field or a TODO marker when missing."""
    value = safe_text(finding.get(field_name))
    if value:
        return value
    return f"TODO: {field_name}"


def safe_text(value: object) -> str:
    """Convert supported values to trimmed text."""
    if value is None:
        return ""
    return str(value).strip()


def write_master_index(reports_dir: Path, rows: Iterable[dict[str, str]]) -> Path:
    """Write a markdown index of all generated reports."""
    sorted_rows = sorted(
        rows,
        key=lambda row: (
            SEVERITY_ORDER.get(row["severity"], SEVERITY_ORDER["UNKNOWN"]),
            row["type"].lower(),
            row["component"].lower(),
            row["agent"].lower(),
        ),
    )
    lines = [
        "# Zero-Day Report Index",
        "",
        "| Severity | Type | Component | Agent | Report |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in sorted_rows:
        lines.append(
            f"| {row['severity']} | {row['type']} | {row['component']} | "
            f"{row['agent']} | [{row['report_name']}]({row['report_name']}) |"
        )
    lines.append("")

    index_path = reports_dir / "index.md"
    index_path.write_text("\n".join(lines), encoding="utf-8")
    return index_path


def fallback_template() -> str:
    """Return a minimal built-in template when the repository template is unavailable."""
    return """# {{Type}} in {{Affected Component}}

## Metadata

- Severity: {{Severity}}
- Type: {{Type}}
- Agent: {{Agent}}
- Affected Component: {{Affected Component}}
- Line: {{Line}}
- Program: {{Program}}

## Summary

{{Summary}}

## Description

{{Description}}

## Root Cause

{{Root Cause}}

## Impact

{{Impact}}

## Proof of Concept

{{PoC}}

## Recommended Fix

{{Recommended Fix}}

## Bug Introduction

{{Bug Introduction}}

## Research Notes

{{Context}}
"""
