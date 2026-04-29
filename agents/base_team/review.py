"""Shared review orchestration and review-gate helpers for BaseTeam-backed teams."""

from __future__ import annotations

import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Sequence

from agents.base_team.reporting_compat import display_file_reference, is_placeholder_finding, split_file_reference
from agents.base_team.reports import write_report_indexes
from agents.base_team.storage import resolve_team_storage

ReviewSingleFn = Callable[[dict[str, Any], Path], dict[str, Any]]
NormalizeTierFn = Callable[[Any], str]
ResolveSourcePathFn = Callable[[Any], Path | None]
SourceExcerptFn = Callable[[Path, int], str]
ExtractJsonFn = Callable[[str], dict[str, Any]]


REVIEW_TIERS = {"CONFIRMED", "DORMANT", "NOVEL", "INCONCLUSIVE"}
DEFAULT_REVIEW_MAX_WORKERS = 4


def stage2_review(
    findings: list[dict[str, Any]],
    target_path: Path,
    *,
    review_single_finding: ReviewSingleFn,
    normalize_review_tier: NormalizeTierFn,
    set_last_review_error: Callable[[str | None], None],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Review findings with Claude first and Codex as fallback."""
    confirmed: list[dict[str, Any]] = []
    dormant: list[dict[str, Any]] = []
    novel: list[dict[str, Any]] = []
    set_last_review_error(None)

    for finding in findings:
        try:
            reviewed = review_single_finding(finding, target_path)
        except Exception as exc:
            reviewed = dict(finding)
            reviewed["review_tier"] = "INCONCLUSIVE"
            reviewed["review_error"] = str(exc)
            set_last_review_error(str(exc))

        category = str(reviewed.get("category") or "").strip().lower()
        tier = normalize_review_tier(reviewed.get("review_tier"))
        reviewed["review_tier"] = tier

        if tier == "INCONCLUSIVE":
            dormant.append(reviewed)
        elif category == "novel" or tier == "NOVEL":
            novel.append(reviewed)
        elif tier == "CONFIRMED":
            confirmed.append(reviewed)
        else:
            dormant.append(reviewed)

    return confirmed, dormant, novel


def review_single_finding(
    finding: dict[str, Any],
    target_path: Path,
    *,
    build_review_prompt: Callable[[dict[str, Any], Path], str],
    run_review_cli: Callable[[str, str, int], str],
    extract_json_object: ExtractJsonFn,
    normalize_review_tier: NormalizeTierFn,
    review_timeout: int,
) -> dict[str, Any]:
    prompt = build_review_prompt(finding, target_path)
    review_data: dict[str, Any] | None = None
    errors: list[str] = []

    for cli_name in ("claude", "codex"):
        try:
            output = run_review_cli(cli_name, prompt, timeout=review_timeout)
            try:
                review_data = extract_json_object(output)
            except Exception as exc:
                errors.append(f"{cli_name}: {exc}")
                continue
            if not review_data:
                errors.append(f"{cli_name}: empty review result")
                review_data = None
                continue
            break
        except Exception as exc:
            errors.append(f"{cli_name}: {exc}")

    if review_data is None:
        reviewed = dict(finding)
        reviewed["review_tier"] = "INCONCLUSIVE"
        reviewed["review_error"] = "; ".join(errors) if errors else "All review CLIs failed"
        return reviewed

    reviewed = dict(finding)
    tier = normalize_review_tier(review_data.get("tier") or review_data.get("review_tier"))
    assumption_text = str(review_data.get("safety_assumption") or "").strip()
    break_text = str(review_data.get("assumption_break") or "").strip()
    intendedness = str(review_data.get("intended_behavior_analysis") or "").strip()
    exploit_path = str(review_data.get("exploit_path") or "").strip()
    review_notes = str(review_data.get("review_notes") or "").strip()
    blocked_reason = str(review_data.get("blocked_reason") or "").strip()
    impact = str(review_data.get("impact") or "").strip()

    if not review_notes:
        review_notes = "No review notes provided."

    if not assumption_text:
        tier = "INCONCLUSIVE"
        blocked_reason = blocked_reason or "Reviewer did not identify the safety assumption that makes the implementation safe."
        review_notes = f"{review_notes} Missing safety_assumption in shared review gate.".strip()

    if tier == "CONFIRMED":
        if not break_text or not exploit_path:
            tier = "INCONCLUSIVE"
            blocked_reason = blocked_reason or "Confirmed finding missing an explicit assumption-break or exploit path."
            review_notes = f"{review_notes} Confirmed findings must explain both the broken assumption and the concrete exploit path.".strip()
        elif intendedness and any(token in intendedness.lower() for token in ("intended feature", "expected behavior", "working as designed", "appears intended")):
            tier = "INCONCLUSIVE"
            blocked_reason = blocked_reason or "Reviewer marked the behavior as intended/expected, so it cannot be promoted without a clearer boundary break."
            review_notes = f"{review_notes} Intended-behavior analysis conflicts with CONFIRMED tier.".strip()

    reviewed["review_tier"] = tier
    reviewed["review_notes"] = review_notes
    reviewed["blocked_reason"] = blocked_reason
    reviewed["impact"] = impact
    reviewed["remediation"] = str(review_data.get("remediation") or "").strip()
    reviewed["review_model"] = str(review_data.get("model") or "").strip()
    reviewed["safety_assumption"] = assumption_text
    reviewed["assumption_break"] = break_text
    reviewed["intended_behavior_analysis"] = intendedness
    reviewed["exploit_path"] = exploit_path
    return reviewed


def run_review_cli(cli_name: str, prompt: str, timeout: int, *, workdir: Path) -> str:
    if cli_name == "claude":
        command = ["claude", "--print", "--permission-mode", "bypassPermissions"]
    elif cli_name == "codex":
        command = [
            "codex",
            "exec",
            "-s",
            "danger-full-access",
            "--skip-git-repo-check",
            "-C",
            str(workdir),
        ]
    else:
        raise ValueError(f"unsupported review CLI {cli_name!r}")

    process = subprocess.Popen(
        command,
        cwd=str(workdir),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout_text, stderr_text = process.communicate(prompt, timeout=max(1, int(timeout)))
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.communicate(timeout=5)
        raise TimeoutError(f"{cli_name} review timed out") from exc
    if process.returncode != 0 and not (stdout_text or "").strip():
        raise RuntimeError(stderr_text.strip() or f"{cli_name} exited with {process.returncode}")
    return stdout_text.strip() or stderr_text.strip()


def build_review_prompt(
    finding: dict[str, Any],
    target_path: Path,
    *,
    resolve_source_path: ResolveSourcePathFn,
    source_excerpt: SourceExcerptFn,
    safe_int: Callable[[Any], int],
) -> str:
    source_path = resolve_source_path(finding.get("file"))
    excerpt = source_excerpt(source_path, safe_int(finding.get("line"))) if source_path else "UNAVAILABLE"
    return f"""Review this single vulnerability-hunting finding.

Return only one JSON object. No markdown and no prose outside JSON.
Allowed tiers: CONFIRMED, DORMANT, NOVEL, INCONCLUSIVE.

Core review doctrine:
- Identify the safety assumption that makes this implementation seem safe.
- Decide whether an attacker can realistically break that assumption.
- Decide whether the resulting behavior is actually unintended and security-relevant, or just an intended feature/capability.
- Prefer INCONCLUSIVE over overstating a capability as a vulnerability.

JSON schema:
{{"tier":"CONFIRMED|DORMANT|NOVEL|INCONCLUSIVE","safety_assumption":"...","assumption_break":"...","intended_behavior_analysis":"...","exploit_path":"...","impact":"...","blocked_reason":"...","remediation":"...","review_notes":"...","model":"{{optional}}"}}

Review rules:
- safety_assumption must name the assumption that makes the code appear safe, such as trusted origin, trusted caller, trusted file source, meaningful user friction, validated callback source, or trusted parser input.
- assumption_break must explain how attacker-controlled input, routing, origin confusion, file content, IPC, or another vector can violate that assumption. If no realistic break is visible, say so explicitly.
- intended_behavior_analysis must judge whether the observed behavior is likely intended product behavior or an unintended boundary break. Dangerous capability alone is not enough.
- exploit_path must describe the practical attacker path from input to impact. If the path is incomplete, say what is missing.
- Use CONFIRMED only when the assumption break and exploit path are concrete, and the behavior is not just intended feature behavior.
- Use DORMANT when something security-relevant may exist but the exploit path or boundary break is incomplete.
- Use NOVEL when the pattern is genuinely interesting/new and likely security-relevant, but still be honest about whether the assumption break is proven.
- Use INCONCLUSIVE when the behavior appears intended, the assumption break is weak, or the impact is not clearly security-relevant.

Target path: {target_path}
Resolved source path: {source_path or "UNRESOLVED"}

Finding:
{json.dumps(finding, indent=2, sort_keys=True)}

Source excerpt:
{excerpt}
"""


def normalize_review_tier(value: Any) -> str:
    tier = str(value or "").strip().upper().replace("-", "_")
    if tier in {"DORMANT_ACTIVE", "DORMANT_HYPOTHETICAL"}:
        tier = "DORMANT"
    if tier not in REVIEW_TIERS:
        return "INCONCLUSIVE"
    return tier



def finding_dedupe_key(finding: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    return (
        str(finding.get("category", "class")).strip().lower(),
        str(finding.get("class_name", "")).strip().lower(),
        str(split_file_reference(finding.get("file", ""))[0]).strip().lower(),
        str(finding.get("type", "")).strip().lower(),
        str(finding.get("source", "")).strip().lower(),
        str(finding.get("sink", "")).strip().lower(),
    )


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _default_vulnerability_name(finding: dict[str, Any]) -> str:
    finding_type = str(finding.get("type") or "Finding").strip().replace("_", " ").title()
    class_name = str(finding.get("class_name") or "").strip()
    return f"{finding_type} in {class_name}" if class_name else finding_type or "Reviewed Finding"


def _ensure_report_fields(finding: dict[str, Any]) -> dict[str, Any]:
    reviewed = dict(finding)
    raw_tier = str(reviewed.get("review_tier") or reviewed.get("tier") or "").strip().upper().replace("-", "_")
    tier = "REJECTED" if raw_tier == "REJECTED" else normalize_review_tier(raw_tier)
    reviewed["review_tier"] = tier
    reviewed["tier"] = tier
    reviewed.setdefault("agent", str(reviewed.get("agent") or "unknown"))
    reviewed.setdefault("category", str(reviewed.get("category") or "class"))
    reviewed.setdefault("class_name", str(reviewed.get("class_name") or "unknown"))
    reviewed.setdefault("file", str(reviewed.get("file") or "unknown"))
    reviewed.setdefault("type", str(reviewed.get("type") or "unknown"))
    reviewed.setdefault("description", str(reviewed.get("description") or "No description provided."))
    reviewed.setdefault("severity_label", str(reviewed.get("severity") or "UNKNOWN").upper())
    reviewed.setdefault("severity", reviewed.get("severity_label") or "UNKNOWN")
    reviewed.setdefault("vulnerability_name", _default_vulnerability_name(reviewed))
    reviewed.setdefault("impact", "")
    reviewed.setdefault("poc", None)
    reviewed.setdefault("cvss_vector", "")
    reviewed.setdefault("cvss_score", "")
    reviewed.setdefault("blocked_reason", "")
    reviewed.setdefault("chain_requirements", "")
    reviewed.setdefault("remediation", "")
    reviewed.setdefault("review_notes", str(reviewed.get("decision_reason") or reviewed.get("review_reason") or ""))
    reviewed.setdefault("review_reason", str(reviewed.get("review_notes") or tier.lower()))
    return reviewed


def _inconclusive_report_review(finding: dict[str, Any], note: str) -> dict[str, Any]:
    reviewed = dict(finding)
    reviewed["review_tier"] = "INCONCLUSIVE"
    reviewed["tier"] = "INCONCLUSIVE"
    reviewed["blocked_reason"] = note
    reviewed["review_notes"] = note
    reviewed["review_reason"] = note
    return _ensure_report_fields(reviewed)


def _resolve_source_path(target_path: Path, file_value: Any) -> Path | None:
    file_path, _ = split_file_reference(file_value)
    if not file_path:
        return None
    raw_path = Path(file_path).expanduser()
    candidates: list[Path] = []
    if raw_path.is_absolute():
        candidates.append(raw_path)
    else:
        trimmed = file_path[2:] if file_path.startswith("./") else file_path
        relative_path = Path(trimmed)
        candidates.append((target_path / relative_path).resolve(strict=False))
        candidates.append((Path.cwd() / relative_path).resolve(strict=False))
        if relative_path.parts and relative_path.parts[0] == target_path.name:
            candidates.append((target_path.parent / relative_path).resolve(strict=False))
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _source_excerpt_for_path(path: Path, line_number: int, radius: int = 20) -> str:
    try:
        source_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "UNAVAILABLE"
    lines = source_text.splitlines()
    if not lines:
        return "UNAVAILABLE"
    if line_number <= 0:
        start = 0
        end = min(len(lines), (radius * 2) + 1)
    else:
        start = max(0, line_number - radius - 1)
        end = min(len(lines), line_number + radius)
    return "\n".join(f"{index + 1}: {lines[index]}" for index in range(start, end))


def _extract_json_object_for_review(text: str) -> dict[str, Any]:
    stripped = str(text or "").strip()
    if not stripped:
        raise ValueError("empty model output")
    fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", stripped, re.DOTALL)
    if fence_match:
        stripped = fence_match.group(1).strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start < 0 or end < start:
        raise ValueError("model output did not contain a JSON object")
    payload = json.loads(stripped[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("model output was not a JSON object")
    return payload


def _render_confirmed_report(findings: Sequence[dict[str, Any]]) -> str:
    if not findings:
        return "# Confirmed Findings\n\nNo confirmed findings.\n"
    sections = ["# Confirmed Findings", ""]
    for finding in findings:
        severity_label = str(finding.get("severity_label") or finding.get("severity", "UNKNOWN"))
        sections.extend([
            f"## [{severity_label}] {finding['vulnerability_name']}",
            f"**Type:** {finding['type']}",
            f"**Class:** {finding.get('class_name', 'unknown')}",
            f"**File:** {display_file_reference(finding)}",
            f"**Agent:** {finding['agent']}",
            "", "### Description", str(finding.get("description") or "None provided."),
            "", "### Source -> Sink",
            f"Source: {str(finding.get('source', '')).strip() or 'None provided.'}",
            f"Trust boundary: {str(finding.get('trust_boundary', '')).strip() or 'None provided.'}",
            f"Flow: {str(finding.get('flow_path', '')).strip() or 'None provided.'}",
            f"Sink: {str(finding.get('sink', '')).strip() or 'None provided.'}",
            "", "### Impact", str(finding.get("impact", "")).strip() or "None provided.",
            "", "### Review Notes", str(finding.get("review_notes", "")).strip() or "None provided.",
            "", "### PoC", str(finding.get("poc", "")).strip() or "None provided.",
            "", "### CVSS Estimate", f"{finding.get('cvss_vector', '')} -> {finding.get('cvss_score', '')} ({severity_label})",
            "", "### Remediation", str(finding.get("remediation", "")).strip() or "None provided.", "",
        ])
    return "\n".join(sections).rstrip() + "\n"


def _render_dormant_report(findings: Sequence[dict[str, Any]]) -> str:
    if not findings:
        return "# Dormant Findings\n\nNo dormant findings.\n"
    sections = ["# Dormant Findings", ""]
    for finding in findings:
        tier = str(finding.get("review_tier", "DORMANT")).upper()
        sections.extend([
            f"## [{tier}] {finding['vulnerability_name']}",
            f"**Type:** {finding['type']}",
            f"**Class:** {finding.get('class_name', 'unknown')}",
            f"**File:** {display_file_reference(finding)}",
            f"**Agent:** {finding['agent']}",
            "", "### Why It's Dangerous (if triggered)", str(finding.get("description") or "None provided."),
            "", "### Source -> Sink",
            f"Source: {str(finding.get('source', '')).strip() or 'None provided.'}",
            f"Trust boundary: {str(finding.get('trust_boundary', '')).strip() or 'None provided.'}",
            f"Flow: {str(finding.get('flow_path', '')).strip() or 'None provided.'}",
            f"Sink: {str(finding.get('sink', '')).strip() or 'None provided.'}",
            "", "### Impact If Chained", str(finding.get("impact", "")).strip() or "None provided.",
            "", "### Review Notes", str(finding.get("review_notes", "")).strip() or "None provided.",
            "", "### Why It's Blocked Right Now", str(finding.get("blocked_reason", "")).strip() or "None provided.",
            "", "### What's Needed to Exploit", str(finding.get("chain_requirements", "")).strip() or "None provided.",
            "", "### Remediation", str(finding.get("remediation", "")).strip() or "None provided.", "",
        ])
    return "\n".join(sections).rstrip() + "\n"


def _render_novel_findings_report(findings: Sequence[dict[str, Any]]) -> str:
    if not findings:
        return "# Novel Findings\n\nNo reviewed novel findings.\n"
    sections = ["# Novel Findings", ""]
    for finding in findings:
        tier = str(finding.get("review_tier", "DORMANT")).upper()
        sections.extend([
            f"## [{tier}] {finding['vulnerability_name']}",
            f"**Type:** {finding['type']}",
            f"**Discovered During Class Pass:** {finding['agent']}",
            f"**File:** {display_file_reference(finding)}",
            "", "### Why It Looks Novel", str(finding.get("description") or "None provided."),
            "", "### Source -> Sink",
            f"Source: {str(finding.get('source', '')).strip() or 'None provided.'}",
            f"Trust boundary: {str(finding.get('trust_boundary', '')).strip() or 'None provided.'}",
            f"Flow: {str(finding.get('flow_path', '')).strip() or 'None provided.'}",
            f"Sink: {str(finding.get('sink', '')).strip() or 'None provided.'}",
            "", "### Impact", str(finding.get("impact", "")).strip() or "None provided.",
            "", "### Review Notes", str(finding.get("review_notes", "")).strip() or "None provided.", "",
        ])
        if tier == "CONFIRMED":
            sections.extend(["### PoC", str(finding.get("poc", "")).strip() or "None provided.", ""])
        else:
            sections.extend([
                "### Why It's Blocked Right Now", str(finding.get("blocked_reason", "")).strip() or "None provided.", "",
                "### What's Needed to Chain It", str(finding.get("chain_requirements", "")).strip() or "None provided.", "",
            ])
        sections.extend(["### Remediation", str(finding.get("remediation", "")).strip() or "None provided.", ""])
    return "\n".join(sections).rstrip() + "\n"


def stage2_ghost_review(
    findings: list[dict[str, Any]],
    target_path: Path,
    program: str,
    hunt_type: str,
    *,
    output_root: Path | None = None,
    review_single: ReviewSingleFn | None = None,
    review_timeout: int = 600,
    max_workers: int = DEFAULT_REVIEW_MAX_WORKERS,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Shared Stage 2 review gate for BaseTeam-backed procedural teams."""
    confirmed: list[dict[str, Any]] = []
    dormant: list[dict[str, Any]] = []
    novel: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str, str, str, str]] = set()
    review_candidates: list[dict[str, Any]] = []

    for finding in findings:
        dedupe_key = finding_dedupe_key(finding)
        description = str(finding.get("description", "")).strip()
        severity = str(finding.get("severity", "")).strip()
        category = str(finding.get("category", "class")).strip().lower()
        finding_type = str(finding.get("type", "unknown"))
        finding_file = str(finding.get("file", "unknown"))

        if description == "..." or is_placeholder_finding(finding):
            print(f"[REVIEW] REJECTED | {finding_type} | {finding_file} | placeholder finding")
            continue
        if not severity:
            print(f"[REVIEW] REJECTED | {finding_type} | {finding_file} | missing severity")
            continue
        if category == "novel" and (not str(finding.get("source", "")).strip() or not str(finding.get("sink", "")).strip()):
            print(f"[REVIEW] REJECTED | {finding_type} | {finding_file} | novel finding missing source or sink")
            continue
        if dedupe_key in seen_keys:
            print(f"[REVIEW] REJECTED | {finding_type} | {finding_file} | duplicate finding")
            continue
        seen_keys.add(dedupe_key)
        review_candidates.append(finding)

    if review_single is None:
        def _default_review(candidate: dict[str, Any], target: Path) -> dict[str, Any]:
            return review_single_finding(
                candidate,
                target,
                build_review_prompt=lambda item, path: build_review_prompt(
                    item,
                    path,
                    resolve_source_path=lambda file_value: _resolve_source_path(path, file_value),
                    source_excerpt=lambda source_path, line: _source_excerpt_for_path(source_path, line),
                    safe_int=lambda value: _safe_int(value),
                ),
                run_review_cli=lambda cli_name, prompt, timeout: run_review_cli(cli_name, prompt, timeout, workdir=target),
                extract_json_object=_extract_json_object_for_review,
                normalize_review_tier=normalize_review_tier,
                review_timeout=review_timeout,
            )
        review_single = _default_review

    with ThreadPoolExecutor(max_workers=max(1, int(max_workers))) as pool:
        futures = {pool.submit(review_single, finding, target_path): finding for finding in review_candidates}
        for future in as_completed(futures):
            finding = futures[future]
            try:
                reviewed = _ensure_report_fields(future.result())
                raw_tier = str(reviewed.get("review_tier") or reviewed.get("tier") or "").strip().upper().replace("-", "_")
                tier = "REJECTED" if raw_tier == "REJECTED" else normalize_review_tier(raw_tier)
                reason = str(reviewed.get("review_notes") or reviewed.get("review_reason") or tier.lower()).strip()
            except Exception as exc:
                tier = "INCONCLUSIVE"
                reason = f"review inconclusive: {exc}"
                reviewed = _inconclusive_report_review(finding, reason)

            print(
                f"[REVIEW] {tier} | {finding.get('category', 'class')} | "
                f"{finding.get('type', 'unknown')} | {finding.get('file', 'unknown')} | {reason}"
            )
            if tier == "REJECTED":
                continue
            if str(reviewed.get("category", "class")).strip().lower() == "novel" or tier == "NOVEL":
                novel.append(reviewed)
            elif tier == "CONFIRMED":
                confirmed.append(reviewed)
            else:
                dormant.append(reviewed)

    storage = resolve_team_storage(program, team_type=hunt_type, output_root=output_root)
    write_report_indexes(
        storage,
        confirmed=confirmed,
        dormant=dormant,
        novel=novel,
        render_confirmed=_render_confirmed_report,
        render_dormant=_render_dormant_report,
        render_novel=_render_novel_findings_report,
    )
    return confirmed, dormant, novel
