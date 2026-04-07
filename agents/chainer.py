#!/usr/bin/env python3
"""Chain vulnerabilities into exploitable attack paths.

Reads dormant and novel findings from zero_day_team reports, filters out
placeholder/template entries, and uses codex to develop concrete exploit chains.

Outputs two reports:
  - chained_report_*.md         — ONLY actively exploitable findings (real PoC exists)
  - hypothetical_chains_*.md    — findings whose impact is entirely contingent on a
                                  prior exploit (e.g. "SSRF if we get XSS first").
                                  These are idea generators for agents, NOT for publishing.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ChainFinding:
    fid: str
    title: str
    vuln_class: str
    file_ref: str
    description: str
    source: str
    sink: str
    trust_boundary: str
    flow_path: str
    blocked_reason: str
    chain_requirements: str
    impact: str
    remediation: str
    is_novel: bool = False


# ---------------------------------------------------------------------------
# Finding parsers
# ---------------------------------------------------------------------------

def _load_dormant_findings(path: Path) -> list[ChainFinding]:
    if not path.exists():
        return []

    text = path.read_text(encoding="utf-8", errors="replace")
    findings: list[ChainFinding] = []

    blocks = re.split(r"\n##\s+\[", text)
    for block in blocks[1:]:
        m = re.match(r"DORMANT\]\s+(.+?)(?:\n|$)", block, re.DOTALL)
        if not m:
            continue
        title = m.group(1).strip()
        if _is_placeholder(block):
            continue

        fid = _assign_fid(findings, "D")
        findings.append(ChainFinding(
            fid=fid,
            title=title,
            vuln_class=_extract_field(block, "**Class:**") or "unknown",
            file_ref=_extract_field(block, "**File:**"),
            description=_extract_section(block, "### Why It's Dangerous"),
            source=_extract_field(block, "Source:") or "",
            sink=_extract_field(block, "Sink:") or "",
            trust_boundary=_extract_field(block, "Trust boundary:") or "",
            flow_path=_extract_field(block, "Flow:") or "",
            blocked_reason=_extract_section(block, "### Why It's Blocked Right Now") or "",
            chain_requirements=_extract_section(block, "### What's Needed to Exploit") or "",
            impact=_extract_section(block, "### Impact If Chained") or "",
            remediation=_extract_section(block, "### Remediation") or "",
            is_novel=False,
        ))

    return findings


def _load_novel_findings(path: Path) -> list[ChainFinding]:
    if not path.exists():
        return []

    text = path.read_text(encoding="utf-8", errors="replace")
    findings: list[ChainFinding] = []

    blocks = re.split(r"\n##\s+\[", text)
    for block in blocks[1:]:
        m = re.match(r"(CONFIRMED|DORMANT(?:_[A-Z]+)?)\]\s+(.+?)(?:\n|$)", block, re.DOTALL)
        if not m:
            continue
        title = m.group(2).strip()
        if _is_placeholder(block):
            continue

        fid = _assign_fid(findings, "N")
        findings.append(ChainFinding(
            fid=fid,
            title=title,
            vuln_class=_extract_field(block, "**Discovered During Class Pass:**") or "unknown",
            file_ref=_extract_field(block, "**File:**"),
            description=_extract_section(block, "### Why It Looks Novel") or _extract_section(block, "### Why It's Dangerous"),
            source=_extract_field(block, "Source:") or "",
            sink=_extract_field(block, "Sink:") or "",
            trust_boundary=_extract_field(block, "Trust boundary:") or "",
            flow_path=_extract_field(block, "Flow:") or "",
            blocked_reason=_extract_section(block, "### Why It's Blocked Right Now") or "",
            chain_requirements=_extract_section(block, "### What's Needed to Chain It") or "",
            impact=_extract_section(block, "### Impact") or "",
            remediation=_extract_section(block, "### Remediation") or "",
            is_novel=True,
        ))

    return findings


def _load_json_findings(path: Path) -> list[ChainFinding]:
    if not path.exists():
        return []

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        return []

    findings: list[ChainFinding] = []
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            continue
        fid = str(item.get("fid", "")).strip() or _assign_fid(findings, "J")
        findings.append(
            ChainFinding(
                fid=fid,
                title=str(item.get("vulnerability_name") or item.get("type") or f"Finding {index}").strip(),
                vuln_class=str(item.get("class_name") or item.get("agent") or "unknown").strip(),
                file_ref=str(item.get("file", "")).strip(),
                description=str(item.get("description", "")).strip(),
                source=str(item.get("source", "")).strip(),
                sink=str(item.get("sink", "")).strip(),
                trust_boundary=str(item.get("trust_boundary", "")).strip(),
                flow_path=str(item.get("flow_path", "")).strip(),
                blocked_reason=str(item.get("blocked_reason", "")).strip(),
                chain_requirements=str(item.get("chain_requirements", "")).strip(),
                impact=str(item.get("impact", "")).strip(),
                remediation=str(item.get("remediation", "")).strip(),
                is_novel=str(item.get("category", "class")).strip().lower() == "novel",
            )
        )
    return findings


def _is_placeholder(block: str) -> bool:
    markers = (
        "path:123", "identified source", "dangerous sink category",
        "what boundary is crossed", "how the data moves", "UNRESOLVED",
        "UNAVAILABLE", "None provided.", "why this path is dangerous",
    )
    return sum(1 for m in markers if m in block) >= 3


def _extract_field(block: str, label: str) -> str:
    m = re.search(re.escape(label) + r"\s*(.+?)(?:\n|$)", block)
    return m.group(1).strip() if m else ""


def _extract_section(block: str, heading: str) -> str:
    m = re.search(re.escape(heading) + r"\n(.+?)(?=\n###\s|\n##\s|\Z)", block, re.DOTALL)
    return m.group(1).strip() if m else ""


def _assign_fid(findings: list[ChainFinding], prefix: str) -> str:
    n = len([f for f in findings if f.fid.startswith(prefix)]) + 1
    return f"{prefix}{n:02d}"


def _is_real_finding(finding: ChainFinding) -> bool:
    title = (finding.title or "").strip()
    file_ref = (finding.file_ref or "").strip()
    description = (finding.description or "").strip()
    title_lc = title.lower()
    file_ref_lc = file_ref.lower()
    combined = " ".join(
        part for part in (title, description, finding.source, finding.sink, finding.blocked_reason) if part
    ).lower()
    # Placeholder markers (old, to be deprecated)
    placeholder_markers = (
        "identified source",
        "dangerous sink category",
        "what boundary is crossed",
        "how the data moves",
        "none provided.",
        "placeholder",
    )

    # Strong requirement markers — if any, mark as real finding
    requirement_verbs = (
        "needs", "requires", "must", "after", "once", "with",
    )
    has_requirement = any(v in combined for v in requirement_verbs)

    if not title:
        return False
    if title_lc in {"short vulnerability label", "short novel pattern label", "placeholder"}:
        return False
    if not file_ref or re.fullmatch(r"path:\d+", file_ref_lc):
        return False
    if not description or description == "...":
        return False
    if any(marker in combined for marker in placeholder_markers):
        return False
    return has_requirement


# ---------------------------------------------------------------------------
# Codex interaction
# ---------------------------------------------------------------------------

_COX_HEADER_PREFIXES = (
    "OpenAI Codex", "--------", "workdir:", "model:", "provider:",
    "approval:", "sandbox:", "reasoning", "session", "mcp", "tokens used", "user",
)


def _resolve_source_file(source_root: Path, file_ref: str) -> Path | None:
    raw = str(file_ref or "").strip()
    if not raw:
        return None

    relpath = raw.rsplit(":", 1)[0] if ":" in raw else raw
    if not relpath:
        return None

    candidate = Path(relpath).expanduser()
    candidates: list[Path] = []
    if candidate.is_absolute():
        candidates.append(candidate)
    else:
        trimmed = relpath[2:] if relpath.startswith("./") else relpath
        relative = Path(trimmed)
        candidates.append((source_root / relative).resolve())
        if relative.parts and relative.parts[0] == source_root.name:
            candidates.append((source_root.parent / relative).resolve())

    for path in candidates:
        if path.exists() and path.is_file():
            return path
    return None


def _codex_develop_chain(finding: ChainFinding, source_path: Path, output_dir: Path) -> dict:
    """Develop an exploit chain and write a human-readable markdown report."""
    try:
        slug_title = slug(finding.title)
        report_path = output_dir / f"{finding.fid}_{slug_title}_report.md"
        resolved_source = _resolve_source_file(source_path, finding.file_ref)
        source_ref_for_prompt = str(resolved_source) if resolved_source is not None else finding.file_ref

        prompt = f'''TASK: Write a human-readable security report for this dormant finding.

VULNERABILITY:
  Title: {finding.title}
  Class: {finding.vuln_class}
  File: {finding.file_ref}
  Resolved Source File: {source_ref_for_prompt}
  Description: {finding.description[:500]}
  Source: {finding.source[:200]}
  Sink: {finding.sink[:200]}
  Trust Boundary: {finding.trust_boundary[:200]}
  Flow: {finding.flow_path[:200]}
  Blocked Because: {finding.blocked_reason[:300]}
  What's Needed: {finding.chain_requirements[:300]}
  Impact If Chained: {finding.impact[:200]}

STEPS:
1. Read the source file at: {source_ref_for_prompt}
2. Understand the actual code and data flow
3. Determine if the vulnerability is real and exploitable
4. Design a concrete exploit chain that overcomes the blocking reason
5. Write a fully working PoC — real, runnable code

OUTPUT: Write a human-readable markdown report directly to this file:
{report_path}

Use this exact format for the report (fill in all fields):

# {finding.fid} — {finding.title}

**Severity:** HIGH / MEDIUM / LOW / UNKNOWN
**Class:** {finding.vuln_class}
**File:** `{finding.file_ref}`

## Verdict
CONFIRMED / NOT EXPLOITABLE / NEEDS MORE RESEARCH

## Why It's Dangerous
[A clear 2-3 sentence explanation of the vulnerability and why it matters]

## Exploit Scenario
[Step-by-step plain-text explanation of how an attacker would exploit this.
Be specific — name the functions, the data flow, what the attacker controls vs what the app does.
If this needs a prior exploit (e.g. XSS first), say so explicitly here.]

## PoC Code
```code
[Fully working PoC — real code that demonstrates the vulnerability.
If no real PoC can be built because the finding needs a prior exploit,
write "Requires prior [XSS / arbitrary file write / etc.] to trigger."
If the file doesn't exist or the vulnerability is theoretical, say so.]
```

## What's Still Missing
[What blocks this from being a working exploit right now.
If nothing is missing and this IS the exploit, write "Nothing missing — this IS the exploit."]

## Estimated CVSS
[CVSS 3.1 vector string, e.g. CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — or "N/A" if unknown]

## Technical Notes
[Any additional technical context, nuances, or observations from reading the source]

---

CRITICAL:
- If the vulnerability requires a prior exploit (e.g. XSS, arbitrary JS), write the PoC section as "Requires prior [XSS / file write / etc.]" and set Verdict to "NEEDS MORE RESEARCH"
- NEVER write placeholder PoC like "<insert payload here>" — either write real working code or honestly say what missing
- Be specific: name functions, APIs, file paths, data flows — not abstract hand-waving
- Output must be written to the file path above using the write tool — do NOT output to stdout
'''.replace("    ", "", 1)

        result = subprocess.run(
            ["codex", "exec", "-s", "danger-full-access", "--skip-git-repo-check", prompt],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(source_path),
        )

        if result.returncode != 0 and result.returncode != 2:  # 2 = write used, not error
            return _empty_chain(f"codex exec failed (exit {result.returncode}): {result.stderr.strip()[:200]}")

        # Read what codex wrote
        if report_path.exists():
            report_text = report_path.read_text(encoding="utf-8", errors="replace")
            # Fall back to stdout if report file is empty
            if len(report_text.strip()) < 50:
                report_text = (result.stdout or "").strip()
        else:
            report_text = (result.stdout or "").strip()

        # Save raw response too
        (output_dir / f"{finding.fid}_chain_response.txt").write_text(report_text, encoding="utf-8")

        # Parse the markdown report to extract structured fields
        try:
            return _parse_markdown_report(report_text, finding)
        except Exception as e:
            print(f"[chainer] markdown parse failed for {finding.fid}: {e}")
            try:
                return _parse_text_fallback(report_text, finding)
            except Exception as fallback_exc:
                print(f"[chainer] text fallback failed for {finding.fid}: {fallback_exc}")
                return _empty_chain("Failed to parse Codex output")

    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return _empty_chain(str(exc))
    except Exception as exc:
        print(f"[chainer] unexpected chain failure for {finding.fid}: {exc}")
        return _empty_chain(str(exc))


def _parse_markdown_report(report_text: str, finding: ChainFinding) -> dict:
    """Extract structured fields from a human-readable markdown report."""
    lc = report_text.lower()
    lines = report_text.splitlines()

    # Extract verdict and severity — scan all lines, handle header + next-line value
    verdict = "UNKNOWN"
    verdict_next = False
    severity = "UNKNOWN"
    for i, line in enumerate(lines):
        stripped = line.strip().lower()

        # Verdict: found header, next non-empty line is the value
        if stripped.startswith("## verdict") or stripped == "**verdict**":
            verdict_next = True
            continue
        if verdict_next and stripped and stripped not in ("---", ""):
            if "confirmed" in stripped:
                verdict = "CONFIRMED"
            elif "not exploitable" in stripped:
                verdict = "NOT EXPLOITABLE"
            elif "needs more research" in stripped or "needs research" in stripped:
                verdict = "NEEDS MORE RESEARCH"
            verdict_next = False

        # Severity: check for **Severity:** or **severity** patterns
        stripped_clean = stripped.lstrip("[@")  # [@ for codex list-item prefix
        if severity == "UNKNOWN":
            lower_line = stripped_clean.lower()
            if "**severity" in lower_line or "severity:**" in lower_line:
                sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "unknown": "UNKNOWN"}
                for k, v in sev_map.items():
                    if k in lower_line:
                        severity = v
                        break

    # Extract CVSS
    cvss = ""
    m = re.search(r'CVSS[:.\s]*3\.1/[\w/\s]+', report_text, re.IGNORECASE)
    if m:
        cvss = m.group(0).strip()
    m2 = re.search(r'CVSS[:.\s]*([\d.]+[/][\w/\.]+)', report_text, re.IGNORECASE)
    if m2 and not cvss:
        cvss = m2.group(1).strip()

    # Extract PoC section
    poc_code = ""
    in_poc = False
    poc_lines = []
    for line in lines:
        if "## poc code" in line.lower() or "## poc:" in line.lower():
            in_poc = True
            continue
        if in_poc:
            if line.startswith("## ") or line.startswith("# "):
                break
            poc_lines.append(line)

    # Clean PoC — remove markdown code fences
    poc_raw = "\n".join(poc_lines).strip()
    poc_code = re.sub(r'^```code\s*$', "", poc_raw, flags=re.MULTILINE)
    poc_code = re.sub(r'^```$', "", poc_code, flags=re.MULTILINE).strip()

    # Extract exploit scenario (text between headers)
    exploit_scenario = ""
    in_exploit = False
    exploit_lines = []
    for line in lines:
        if "## exploit scenario" in line.lower():
            in_exploit = True
            continue
        if in_exploit:
            if line.startswith("## ") or line.startswith("# "):
                break
            exploit_lines.append(line)
    exploit_scenario = "\n".join(exploit_lines).strip()

    # Extract what's missing
    missing_link = ""
    in_missing = False
    missing_lines = []
    for line in lines:
        if "## what's still missing" in line.lower() or "## what's missing" in line.lower():
            in_missing = True
            continue
        if in_missing:
            if line.startswith("## ") or line.startswith("# "):
                break
            missing_lines.append(line)
    missing_link = "\n".join(missing_lines).strip()

    # Determine hypothetical_prereq from content
    hypothetical_prereq = ""
    hypoth_markers = ["requires prior", "needs prior", "xss first", "javascript execution first",
                      "depends on a separate", "separate exploit", "if we get xss"]
    if any(m in lc for m in hypoth_markers) and not poc_code.strip():
        hypothetical_prereq = missing_link or "XSS or equivalent renderer JS execution (unconfirmed)"

    # chain_viable: has PoC and no missing link dependency
    chain_viable = bool(poc_code.strip()) and not hypothetical_prereq

    # Build notes from technical notes section
    notes = ""
    in_notes = False
    notes_lines = []
    for line in lines:
        if "## technical notes" in line.lower():
            in_notes = True
            continue
        if in_notes:
            if line.startswith("## ") or line.startswith("# "):
                break
            notes_lines.append(line)
    notes = "\n".join(notes_lines).strip()[:500]

    result = {
        "chain_viable": chain_viable,
        "exploit_scenario": exploit_scenario[:800] or missing_link[:400],
        "poc_code": poc_code[:2000],
        "missing_link": missing_link[:400],
        "hypothetical_prereq": hypothetical_prereq,
        "cvss_estimate": cvss,
        "severity_estimate": severity,
        "notes": notes or missing_link[:200],
        "verdict": verdict,
    }
    # Store raw report for the render functions
    if report_text.strip():
        result["_raw_report"] = report_text.strip()
    return result


def _empty_chain(reason: str) -> dict:
    return {
        "chain_viable": False, "exploit_scenario": "", "poc_code": "",
        "missing_link": reason, "hypothetical_prereq": "",
        "cvss_estimate": "", "severity_estimate": "UNKNOWN", "notes": "",
    }


def _parse_text_fallback(text: str, finding: ChainFinding) -> dict:
    """Heuristic parse when codex doesn't return clean JSON."""
    lc = text.lower()

    # Check for hypothetical indicators
    hypothetical_prereq = ""
    if any(k in lc for k in ("requires xss", "needs xss", "prior xss", "xss first", "javascript execution first",
                               "requires prior", "needs prior", "depends on a separate", "separate exploit")):
        hypothetical_prereq = "XSS or equivalent JS execution (unconfirmed)"

    chain_viable = any(tok in lc for tok in (
        "chain viable: true", "yes, exploitable", "can be chained", "confirmed", "real exploit",
        '"chain_viable": true')) and bool(_extract_field_heuristic(text, "poc_code"))

    result = {
        "chain_viable": chain_viable,
        "exploit_scenario": _extract_field_heuristic(text, "exploit_scenario") or text[:400],
        "poc_code": _extract_field_heuristic(text, "poc_code") or "",
        "missing_link": _extract_field_heuristic(text, "missing_link") or "",
        "hypothetical_prereq": hypothetical_prereq,
        "cvss_estimate": _extract_field_heuristic(text, "cvss_estimate") or "",
        "severity_estimate": _extract_field_heuristic(text, "severity_estimate") or "UNKNOWN",
        "notes": _extract_field_heuristic(text, "notes") or text[:200],
    }
    try:
        return copy.deepcopy(result)
    except Exception as exc:
        print(f"[chainer] fallback deepcopy failed for {finding.fid}: {exc}")
        return dict(result)


def _latest_report_path(reports_dir: Path, filename: str) -> Path | None:
    candidates: list[Path] = []
    for path in reports_dir.glob(f"*/{filename}"):
        if path.is_file():
            candidates.append(path)

    legacy_prefix = filename.rsplit(".", 1)[0]
    for path in reports_dir.glob(f"{legacy_prefix}_*.md"):
        if path.is_file():
            candidates.append(path)

    if not candidates:
        return None
    return max(candidates, key=lambda item: item.stat().st_mtime)


def _extract_field_heuristic(text: str, field: str) -> str:
    """Extract field value from non-JSON text using loose pattern matching."""
    # Try JSON-style "field": "value"
    patterns = [
        rf'"{field}"[:\s]+\[([^\]]+)\]',   # array
        rf'"{field}"[:\s]+"([^"\\]*(?:\\.[^"\\]*)*)"',  # quoted string
        rf'"{field}"[:\s]+([^\n,\}}]+)',     # bare value
        rf'{field}[:\s]+"([^"]+)"',          # no quotes around field
        rf'{field}[:\s]+([^\n]+)',            # plain text
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1).strip().strip('"` \'"')
    return ""


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

def _is_hypothetical(chain: dict) -> bool:
    """Return True if this chain's impact is entirely contingent on a prior exploit."""
    poc = chain.get("poc_code", "").strip()
    prereq = chain.get("hypothetical_prereq", "").strip()
    verdict = chain.get("verdict", "").upper()
    severity = chain.get("severity_estimate", "UNKNOWN")

    # CONFIRMED → never hypothetical (verdict is authoritative)
    if verdict == "CONFIRMED":
        return False

    # NOT EXPLOITABLE → hypothetical (not a real vuln)
    if verdict == "NOT EXPLOITABLE":
        return True

    # NEEDS MORE RESEARCH → hypothetical (plausible but unproven)
    if verdict == "NEEDS MORE RESEARCH":
        return True

    # Check for real working exploit code (JavaScript/Electron API patterns)
    real_poc_patterns = (
        "window.", "document.", "require(", "ipcRenderer",
        "electronApi", "fs.", "child_process", "spawn(",
        "eval(", "innerHTML", "document.createElement",
    )
    if any(p in poc for p in real_poc_patterns):
        return False

    # Has prerequisite → hypothetical
    if prereq:
        return True

    # PoC says it needs prior exploit → hypothetical
    needs_prior = (
        "requires prior", "needs prior", "requires xss",
        "no standalone weaponized", "no working rce",
        "no working exploit",
    )
    if any(p in poc.lower() for p in needs_prior):
        return True

    # No real PoC code → hypothetical
    if not poc or len(poc) < 20 or poc.startswith("```"):
        return True

    return False


def _write_reports(
    findings: list[ChainFinding],
    chains: dict,
    output_dir: Path,
    program: str,
) -> tuple[Path, Path]:
    date_folder = datetime.now(timezone.utc).strftime("%d-%m-%Y")
    date_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Date-stamped subdirs
    day_dir = output_dir / date_folder
    active_dir = day_dir / "active"
    hypoth_dir = day_dir / "hypothetical"
    active_dir.mkdir(parents=True, exist_ok=True)
    hypoth_dir.mkdir(parents=True, exist_ok=True)

    active_report_path = active_dir / "index.md"
    hypoth_path = hypoth_dir / "index.md"

    # Categorize findings
    active_viable = []    # chain_viable=True, real PoC, no hypothetical prereq
    hypothetical = []      # entire impact depends on a prior exploit
    unchained = []        # real finding but no working chain

    for f in findings:
        chain = chains.get(f.fid, {})
        if chain.get("chain_viable") and not _is_hypothetical(chain):
            active_viable.append((f, chain))
        elif _is_hypothetical(chain):
            hypothetical.append((f, chain))
        else:
            unchained.append((f, chain))

    # ---- Per-finding active exploit files ----
    if active_viable:
        for finding, chain in active_viable:
            finding_path = active_dir / f"{finding.fid}_{slug(finding.title)}.md"
            finding_path.write_text(_render_active_finding(finding, chain), encoding="utf-8")
        print(f"[chainer]   wrote {len(active_viable)} finding(s) → {active_dir}/")

    # ---- Index for active report ----
    idx_lines = [
        f"# Exploit Chain Report — {program}",
        f"**Generated:** {date_stamp}",
        f"**Actively exploitable findings:** {len(active_viable)}",
        "",
    ]
    if active_viable:
        for finding, _ in active_viable:
            slug_title = slug(finding.title)
            idx_lines.append(f"- [{finding.fid}] {finding.title} → `{finding.fid}_{slug_title}.md`")
    else:
        idx_lines.extend([
            "No findings met the bar for active exploitability.",
            "Run with Claude for deeper analysis.",
        ])
    active_report_path.write_text("\n".join(idx_lines), encoding="utf-8")

    # ---- Per-finding hypothetical files ----
    if hypothetical:
        for finding, chain in hypothetical:
            finding_path = hypoth_dir / f"{finding.fid}_{slug(finding.title)}.md"
            finding_path.write_text(_render_hypothetical_finding(finding, chain), encoding="utf-8")
        print(f"[chainer]   wrote {len(hypothetical)} hypothetical(s) → {hypoth_dir}/")

    # ---- Index for hypothetical report ----
    hypoth_idx = [
        f"# Hypothetical Chains — {program}",
        f"**Generated:** {date_stamp}",
        "",
        "⚠️ **NOT FOR PUBLICATION** — These are idea generators for agent research.",
        "Impact is entirely contingent on a prior exploit (e.g. XSS, arbitrary file write).",
        "",
        f"**Total hypothetical chains:** {len(hypothetical)}",
        "",
    ]
    if hypothetical:
        hypoth_idx.append("## Hypothetical Chains")
        hypoth_idx.append("")
        for finding, _ in hypothetical:
            slug_title = slug(finding.title)
            hypoth_idx.append(f"- [{finding.fid}] {finding.title} → `{finding.fid}_{slug_title}.md`")
    else:
        hypoth_idx.extend(["## Hypothetical Chains", "", "None identified.", ""])

    if unchained:
        hypoth_idx.extend(["", "## Investigated — Not Chainable", "",
                           "Real vulnerabilities found but no concrete chain could be constructed.",
                           "They remain dormant in the source.", ""])
        for finding, chain in unchained:
            s_title = slug(finding.title)
            finding_path = hypoth_dir / f"{finding.fid}_{s_title}.md"
            finding_path.write_text(_render_unchained_finding(finding, chain), encoding="utf-8")
            hypoth_idx.append(f"- [{finding.fid}] {finding.title} → `{finding.fid}_{s_title}.md`")

    hypoth_path.write_text("\n".join(hypoth_idx), encoding="utf-8")

    # ---- Summary JSON ----
    summary = {
        "program": program,
        "generated": date_stamp,
        "total_findings": len(findings),
        "active_chains": len(active_viable),
        "hypothetical_chains": len(hypothetical),
        "unchained": len(unchained),
        "findings": [
            {
                "fid": f.fid,
                "title": f.title,
                "vuln_class": f.vuln_class,
                "is_novel": f.is_novel,
                "chain_viable": chains.get(f.fid, {}).get("chain_viable", False),
                "hypothetical": _is_hypothetical(chains.get(f.fid, {})),
                "severity": chains.get(f.fid, {}).get("severity_estimate", "UNKNOWN"),
            }
            for f in findings
        ],
    }
    (day_dir / f"chain_summary_{date_stamp}.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    return active_report_path, hypoth_path


def slug(title: str) -> str:
    """Convert a finding title into a safe short filename slug."""
    slug = re.sub(r"[^a-zA-Z0-9\s\-_]", "", title)
    slug = re.sub(r"[\s_]+", "_", slug)
    return slug[:60].rstrip("_")


def _render_active_finding(finding: ChainFinding, chain: dict) -> str:
    # Use the full readable report if available, otherwise build from fields
    slug_title = slug(finding.title)
    report_path = f"{finding.fid}_{slug_title}_report.md"
    raw_report = (chain.get("_raw_report") or "").strip()

    if raw_report and len(raw_report) > 100:
        # Embed the full readable report as-is
        header = (
            f"# {finding.fid} — {finding.title}\n"
            f"**File:** `{finding.file_ref}`\n"
            f"**Report:** `{report_path}`\n"
        )
        return f"{header}\n{raw_report}\n"

    # Fallback: build from extracted fields
    lines = [
        f"# {finding.fid} — {finding.title}",
        f"**Severity:** {chain.get('severity_estimate', 'UNKNOWN')}",
        f"**Class:** {finding.vuln_class}",
        f"**File:** `{finding.file_ref}`",
        "",
        "## Verdict",
        chain.get("verdict", "CONFIRMED"),
        "",
        "## Why It's Dangerous",
        finding.description[:500] or "Not provided.",
        "",
        "## Exploit Scenario",
        chain.get("exploit_scenario", "Not provided.")[:1000],
        "",
        "## Working PoC",
        "",
        f"```code\n{chain.get('poc_code', 'Not provided.')}\n```",
        "",
        "## What's Still Missing",
        chain.get("missing_link", "Nothing — this IS the exploit."),
        "",
        "## CVSS",
        f"`{chain.get('cvss_estimate', 'N/A')}`",
        "",
        "## Technical Notes",
        chain.get("notes", "None."),
        "",
        f"**Original chain requirements:** {finding.chain_requirements[:300]}",
    ]
    return "\n".join(lines)


def _render_hypothetical_finding(finding: ChainFinding, chain: dict) -> str:
    slug_title = slug(finding.title)
    report_path = f"{finding.fid}_{slug_title}_report.md"
    raw_report = (chain.get("_raw_report") or "").strip()

    if raw_report and len(raw_report) > 100:
        header = (
            f"# {finding.fid} — {finding.title}\n"
            f"**File:** `{finding.file_ref}`\n"
            f"**Report:** `{report_path}`\n"
        )
        return f"{header}\n{raw_report}\n"

    prereq = chain.get("hypothetical_prereq", "Unknown — requires investigation")
    lines = [
        f"# {finding.fid} — {finding.title}",
        f"**Prerequisite:** {prereq}",
        f"**Class:** {finding.vuln_class}",
        f"**File:** `{finding.file_ref}`",
        "",
        "## Status",
        "This finding's impact is entirely contingent on a prior exploit. "
        "It is a real vulnerability but not independently exploitable.",
        "",
        "## Verdict",
        chain.get("verdict", "NEEDS MORE RESEARCH"),
        "",
        "## Exploit Scenario",
        chain.get("exploit_scenario", "Not provided.")[:800],
        "",
        "## Why It's Blocked",
        chain.get("missing_link", "No concrete path identified.")[:400],
        "",
        f"**CVSS (if prerequisite met):** `{chain.get('cvss_estimate', 'N/A')}` "
        f"({chain.get('severity_estimate', 'UNKNOWN')})",
        "",
        "## Technical Notes",
        chain.get("notes", "None.")[:300],
    ]
    return "\n".join(lines)


def _render_unchained_finding(finding: ChainFinding, chain: dict) -> str:
    lines = [
        f"# {finding.fid} — {finding.title}",
        f"**Class:** {finding.vuln_class}",
        f"**File:** `{finding.file_ref}`",
        "",
        "## Status",
        "No concrete exploit chain could be constructed from this finding.",
        "",
        "## Blocking Reason",
        chain.get("missing_link", finding.blocked_reason)[:400],
        "",
        "## What Was Examined",
        chain.get("notes", "No usable analysis returned.")[:300],
        "",
        f"**Original blocked reason:** {finding.blocked_reason[:200]}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Develop exploit chains from dormant and novel zero-day findings.",
        epilog=textwrap.dedent("""\
            Examples:
              python3 agents/chainer.py evernote --source ~/source/
              python3 agents/chainer.py evernote --source ~/source/ --novel-only
              python3 agents/chainer.py evernote --source ~/source/ --skip-codex
        """),
    )
    parser.add_argument("program", help="Bug bounty program name")
    parser.add_argument("--source", default="~/source/",
                        help="Path to the application source code (default: ~/source/)")
    parser.add_argument("--output-dir",
                        help="Output directory (default: ~/Shared/bounty_recon/{program}/ghost/chained/)")
    parser.add_argument("--findings-json",
                        help="Optional JSON array of reviewed findings to process instead of report markdown.")
    parser.add_argument("--dormant-only", action="store_true", help="Only process dormant findings")
    parser.add_argument("--novel-only", action="store_true", help="Only process novel findings")
    parser.add_argument("--skip-codex", action="store_true",
                        help="Parse findings and write report without running codex")
    parser.add_argument("--hunt-type", default="source", choices=("source", "web"),
                        help="Type of target: source (exe/apk) or web. Default: source.")
    return parser.parse_args(argv or sys.argv[1:])


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    program = args.program
    source_path = Path(args.source).expanduser().resolve()
    output_dir = (Path(args.output_dir) if args.output_dir else
                  Path.home() / "Shared" / "bounty_recon" / program / "ghost" / "chained")
    output_dir.mkdir(parents=True, exist_ok=True)

    reports_dir = Path.home() / "Shared" / "bounty_recon" / program / "ghost" / f"reports_{args.hunt_type}"
    dormant_path = _latest_report_path(reports_dir, "dormant.md")
    novel_path = _latest_report_path(reports_dir, "novel_findings.md")

    print(f"[chainer] Program: {program}")
    print(f"[chainer] Source: {source_path}")
    print(f"[chainer] Output: {output_dir}")
    print(f"[chainer] Reports: dormant={dormant_path}, novel={novel_path}")

    findings: list[ChainFinding] = []
    if args.findings_json:
        findings = _load_json_findings(Path(args.findings_json).expanduser().resolve())
        print(f"[chainer] Loaded {len(findings)} finding(s) from JSON filter input")
    else:
        if not args.novel_only and dormant_path:
            d = _load_dormant_findings(dormant_path)
            findings.extend(d)
            print(f"[chainer] Loaded {len(d)} real dormant findings")
        if not args.dormant_only and novel_path:
            n = _load_novel_findings(novel_path)
            findings.extend(n)
            print(f"[chainer] Loaded {len(n)} real novel findings")

    if not findings:
        print("[chainer] No real findings found.")
        return 0

    real_findings: list[ChainFinding] = []
    for finding in findings:
        if not _is_real_finding(finding):
            print(f"[chainer] SKIPPED placeholder: {finding.fid} {finding.title}")
            continue
        real_findings.append(finding)
    findings = real_findings

    if not findings:
        print("[chainer] No real findings found.")
        return 0

    print(f"[chainer] Total real findings to chain: {len(findings)}")

    if args.skip_codex:
        print("[chainer] --skip-codex set — parsing only.")
        chains = {f.fid: {"chain_viable": False, "poc_code": "", "missing_link": "skipped",
                          "hypothetical_prereq": "", "severity_estimate": "UNKNOWN",
                          "exploit_scenario": "", "cvss_estimate": "", "notes": "skipped"}
                  for f in findings}
    else:
        chains: dict[str, dict] = {}
        for i, finding in enumerate(findings, start=1):
            print(f"[chainer] [{i}/{len(findings)}] {finding.fid} — {finding.title[:55]}")
            result = _codex_develop_chain(finding, source_path, output_dir)
            try:
                chains[finding.fid] = result
            except Exception as exc:
                print(f"[chainer] failed to store chain result for {finding.fid}: {exc}")
                chains[finding.fid] = _empty_chain(f"failed to store chain result: {exc}")
            hypo = " [HYPOTHETICAL]" if _is_hypothetical(result) else ""
            verdict = result.get("verdict", "?")
            print(f"[chainer]   {verdict}{ hypo}  severity={result.get('severity_estimate','?')}  "
                  f"chain_viable={result.get('chain_viable')}")

    active_path, hypoth_path = _write_reports(findings, chains, output_dir, program)
    print(f"[chainer] Active report:  {active_path}")
    print(f"[chainer] Hypothetical:  {hypoth_path}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
