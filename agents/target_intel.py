#!/usr/bin/env python3
"""Beta/offline-first Target Intel CVE mapper.

This tool is intentionally passive. It reads local stack, advisory, company
pattern, asset graph, and surface map artifacts, then writes lane-local intel
recommendations without probing targets or writing findings ledgers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agents.storage_resolver import resolve_storage


INTEL_SCHEMA_VERSION = 1
MAX_LOCAL_FILE_BYTES = 2_000_000

SEVERITY_POINTS = {
    "critical": 35,
    "high": 28,
    "medium": 18,
    "moderate": 18,
    "low": 8,
    "info": 2,
    "informational": 2,
    "unknown": 5,
}

VULN_CLASS_SKILLS = {
    "access-control": ["access-control", "idor"],
    "idor": ["idor", "access-control"],
    "bola": ["idor", "access-control"],
    "sqli": ["sqli", "waf"],
    "sql-injection": ["sqli", "waf"],
    "xss": ["xss", "waf"],
    "ssrf": ["ssrf", "headers"],
    "csrf": ["csrf", "headers"],
    "rce": ["bypass", "waf"],
    "auth": ["access-control", "headers"],
    "file-upload": ["xss", "ssrf", "waf"],
    "graphql": ["access-control", "idor", "sqli"],
}


@dataclass(slots=True)
class StackFingerprint:
    name: str
    version: str | None = None
    ecosystem: str | None = None
    cpe: str | None = None
    confidence: float = 0.6
    target: str | None = None
    service: str | None = None
    evidence_type: str = "local-artifact"
    evidence_source: str | None = None
    fingerprint_method: str = "local-stack-reader"
    active_probe: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = INTEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        self.name = clean_text(self.name)
        self.version = clean_text(self.version) or None
        self.confidence = clamp_float(self.confidence, 0.0, 1.0)

    @property
    def normalized_name(self) -> str:
        return normalize_name(self.name)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["normalized_name"] = self.normalized_name
        return drop_none(payload)


@dataclass(slots=True)
class AdvisoryRecord:
    advisory_id: str
    title: str
    products: list[str] = field(default_factory=list)
    package: str | None = None
    ecosystem: str | None = None
    cpe: str | None = None
    affected_versions: list[str] = field(default_factory=list)
    severity: str = "unknown"
    cvss: float | None = None
    epss: float | None = None
    known_exploited: bool = False
    vuln_class: str | None = None
    cwe: str | None = None
    references: list[str] = field(default_factory=list)
    source: str = "local-fixture"
    published_at: str | None = None
    summary: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = INTEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        self.advisory_id = clean_text(self.advisory_id)
        self.title = clean_text(self.title) or self.advisory_id
        self.products = sorted(dict.fromkeys(clean_text(item) for item in self.products if clean_text(item)))
        self.affected_versions = sorted(
            dict.fromkeys(clean_text(item) for item in self.affected_versions if clean_text(item))
        )
        self.references = sorted(dict.fromkeys(clean_text(item) for item in self.references if clean_text(item)))
        self.severity = normalize_severity(self.severity)
        self.cvss = clamp_float(self.cvss, 0.0, 10.0) if self.cvss is not None else None
        self.epss = clamp_float(self.epss, 0.0, 1.0) if self.epss is not None else None

    def names(self) -> list[str]:
        values = [*self.products]
        for value in (self.package, self.cpe):
            if value:
                values.append(value)
        return sorted(dict.fromkeys(values))

    def to_dict(self) -> dict[str, Any]:
        return drop_none(asdict(self))


@dataclass(slots=True)
class CompanyPatternRecord:
    vuln_class: str
    affected_product: str | None = None
    surface: str | None = None
    source_url: str | None = None
    disclosure_date: str | None = None
    platform: str = "local-fixture"
    cwe: str | None = None
    exploit_preconditions: list[str] = field(default_factory=list)
    remediation_theme: str | None = None
    relevance: float = 0.5
    title: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = INTEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        self.vuln_class = normalize_vuln_class(self.vuln_class)
        self.relevance = clamp_float(self.relevance, 0.0, 1.0)
        self.exploit_preconditions = sorted(
            dict.fromkeys(clean_text(item) for item in self.exploit_preconditions if clean_text(item))
        )

    def to_dict(self) -> dict[str, Any]:
        return drop_none(asdict(self))


@dataclass(slots=True)
class IntelRecommendation:
    recommendation_id: str
    title: str
    score: int
    priority: str
    recommendation_type: str
    component: str | None = None
    advisory_id: str | None = None
    pattern_refs: list[str] = field(default_factory=list)
    match_type: str | None = None
    recommended_skills: list[str] = field(default_factory=list)
    coverage_status: str = "untested"
    scope_status: str = "unknown"
    reasons: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    source_refs: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = INTEL_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return drop_none(asdict(self))


@dataclass(slots=True)
class TargetIntelConfig:
    program: str
    target: str
    family: str = "web_bounty"
    lane: str = "web"
    root: str | Path | None = None
    surface_map_paths: list[Path] = field(default_factory=list)
    asset_graph_paths: list[Path] = field(default_factory=list)
    stack_paths: list[Path] = field(default_factory=list)
    advisory_fixture_paths: list[Path] = field(default_factory=list)
    company_pattern_fixture_paths: list[Path] = field(default_factory=list)
    offline: bool = True
    run_date: str | None = None


@dataclass(slots=True)
class IntelContext:
    stack: list[StackFingerprint] = field(default_factory=list)
    advisories: list[AdvisoryRecord] = field(default_factory=list)
    company_patterns: list[CompanyPatternRecord] = field(default_factory=list)
    surfaces: list[dict[str, Any]] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def run_target_intel(config: TargetIntelConfig) -> Path:
    storage = resolve_storage(
        config.program,
        family=config.family,
        lane=config.lane,
        root_override=config.root,
        create=True,
    )
    run_date = config.run_date or utc_date()
    output_dir = storage.lane_root / "intel" / run_date
    output_dir.mkdir(parents=True, exist_ok=True)

    context = IntelContext()
    load_inputs(config, context)
    recommendations = build_recommendations(context)
    artifact_paths = write_outputs(output_dir, config, storage.lane_root, context, recommendations)
    return artifact_paths["intel_json"]


def load_inputs(config: TargetIntelConfig, context: IntelContext) -> None:
    for path in config.stack_paths:
        stack = read_stack_path(path, config.target, context)
        context.stack.extend(stack)
    for path in config.advisory_fixture_paths:
        context.advisories.extend(read_advisory_fixture(path, context))
    for path in config.company_pattern_fixture_paths:
        context.company_patterns.extend(read_company_pattern_fixture(path, context))
    for path in config.surface_map_paths:
        context.surfaces.extend(read_json_records(path, context, source_type="surface-map"))
    for path in config.asset_graph_paths:
        context.assets.extend(read_json_records(path, context, source_type="asset-graph"))

    context.stack = dedupe_stack(context.stack)
    context.advisories = dedupe_advisories(context.advisories)
    context.company_patterns = dedupe_patterns(context.company_patterns)


def read_stack_path(path: Path, target: str, context: IntelContext) -> list[StackFingerprint]:
    path = path.expanduser()
    payloads = read_loose_payloads(path, context, "stack")
    stack: list[StackFingerprint] = []
    for payload in payloads:
        stack.extend(stack_from_payload(payload, path, target))
    return stack


def stack_from_payload(payload: Any, path: Path, target: str) -> list[StackFingerprint]:
    source = str(path)
    if isinstance(payload, str):
        record = parse_stack_line(payload, source, target)
        return [record] if record else []
    if isinstance(payload, list):
        result: list[StackFingerprint] = []
        for item in payload:
            result.extend(stack_from_payload(item, path, target))
        return result
    if not isinstance(payload, dict):
        return []

    nested_fields = ("technologies", "tech_stack", "stack", "components", "libraries", "frameworks", "services")
    result: list[StackFingerprint] = []
    if any(field in payload for field in ("name", "product", "library", "framework", "technology", "service")):
        name = first_present(payload, "name", "product", "library", "framework", "technology", "service")
        if name:
            result.append(
                StackFingerprint(
                    name=str(name),
                    version=string_or_none(first_present(payload, "version", "detected_version")),
                    ecosystem=string_or_none(payload.get("ecosystem")),
                    cpe=string_or_none(payload.get("cpe")),
                    confidence=safe_float(payload.get("confidence"), 0.75),
                    target=string_or_none(payload.get("target") or target),
                    service=string_or_none(payload.get("host") or payload.get("service")),
                    evidence_type=string_or_none(payload.get("evidence_type")) or "local-artifact",
                    evidence_source=source,
                    fingerprint_method=string_or_none(payload.get("fingerprint_method")) or "json-stack",
                    active_probe=bool(payload.get("active_probe", False)),
                    metadata={"json_keys": sorted(str(key) for key in payload.keys())},
                )
            )
    for field_name in nested_fields:
        if field_name in payload:
            result.extend(stack_from_payload(payload[field_name], path, target))
    if not result:
        for key, value in payload.items():
            if isinstance(value, str) and key.lower() not in {"target", "host", "url", "source"}:
                parsed = parse_stack_line(f"{key}: {value}", source, target)
                if parsed:
                    result.append(parsed)
    return result


def parse_stack_line(line: str, source: str, target: str) -> StackFingerprint | None:
    text = clean_stack_line(line)
    if not text:
        return None
    match = re.match(r"^(?P<name>[A-Za-z0-9_.@/ +:-]{2,80}?)(?:\s*[:=]\s*|\s+v?)(?P<version>\d+(?:\.\d+){0,4}[A-Za-z0-9_.+-]*)$", text)
    if match:
        name = match.group("name").strip(" -:/")
        version = match.group("version")
    else:
        name = re.sub(r"\s+\(.*?\)$", "", text).strip()
        version_match = re.search(r"\b(?:v|version\s*)?(\d+(?:\.\d+){1,4}[A-Za-z0-9_.+-]*)\b", text, re.I)
        version = version_match.group(1) if version_match else None
        if version:
            name = text[: version_match.start()].strip(" :-")
    if not name or looks_like_url(name):
        return None
    return StackFingerprint(
        name=name,
        version=version,
        confidence=0.65 if version else 0.5,
        target=target,
        evidence_source=source,
        fingerprint_method="text-stack",
    )


def read_advisory_fixture(path: Path, context: IntelContext) -> list[AdvisoryRecord]:
    records: list[AdvisoryRecord] = []
    for payload in read_loose_payloads(path, context, "advisory-fixture"):
        records.extend(advisories_from_payload(payload, str(path)))
    return records


def advisories_from_payload(payload: Any, source_path: str) -> list[AdvisoryRecord]:
    if isinstance(payload, list):
        result: list[AdvisoryRecord] = []
        for item in payload:
            result.extend(advisories_from_payload(item, source_path))
        return result
    if not isinstance(payload, dict):
        return []
    for child_field in ("advisories", "vulnerabilities", "cves", "items", "records"):
        if child_field in payload and not any(key in payload for key in ("id", "advisory_id", "cve", "cve_id", "ghsa_id")):
            return advisories_from_payload(payload[child_field], source_path)

    advisory_id = string_or_none(first_present(payload, "advisory_id", "id", "cve_id", "cve", "ghsa_id"))
    if not advisory_id:
        return []
    products = list_values(first_present(payload, "products", "product", "affected_products", "names"))
    package = string_or_none(first_present(payload, "package", "package_name", "module_name"))
    if package:
        products.append(package)
    return [
        AdvisoryRecord(
            advisory_id=advisory_id,
            title=string_or_none(first_present(payload, "title", "summary", "name")) or advisory_id,
            products=products,
            package=package,
            ecosystem=string_or_none(payload.get("ecosystem")),
            cpe=string_or_none(payload.get("cpe")),
            affected_versions=list_values(first_present(payload, "affected_versions", "affected", "version_range", "versions")),
            severity=string_or_none(payload.get("severity")) or "unknown",
            cvss=safe_optional_float(first_present(payload, "cvss", "cvss_score", "base_score")),
            epss=safe_optional_float(payload.get("epss")),
            known_exploited=parse_bool(first_present(payload, "known_exploited", "kev", "exploited_in_the_wild")),
            vuln_class=string_or_none(first_present(payload, "vuln_class", "class", "category", "weakness")),
            cwe=string_or_none(first_present(payload, "cwe", "cwe_id")),
            references=list_values(first_present(payload, "references", "refs", "urls", "source_urls")),
            source=string_or_none(payload.get("source")) or "local-fixture",
            published_at=string_or_none(first_present(payload, "published_at", "published", "date")),
            summary=truncate_summary(string_or_none(payload.get("summary") or payload.get("description"))),
            metadata={"fixture_path": source_path},
        )
    ]


def read_company_pattern_fixture(path: Path, context: IntelContext) -> list[CompanyPatternRecord]:
    records: list[CompanyPatternRecord] = []
    for payload in read_loose_payloads(path, context, "company-pattern-fixture"):
        records.extend(patterns_from_payload(payload, str(path)))
    return records


def patterns_from_payload(payload: Any, source_path: str) -> list[CompanyPatternRecord]:
    if isinstance(payload, list):
        result: list[CompanyPatternRecord] = []
        for item in payload:
            result.extend(patterns_from_payload(item, source_path))
        return result
    if not isinstance(payload, dict):
        return []
    for child_field in ("patterns", "reports", "writeups", "items", "records"):
        if child_field in payload and not any(key in payload for key in ("vuln_class", "category", "weakness", "cwe")):
            return patterns_from_payload(payload[child_field], source_path)
    vuln_class = string_or_none(first_present(payload, "vuln_class", "category", "weakness", "class"))
    if not vuln_class and string_or_none(payload.get("cwe")):
        vuln_class = str(payload["cwe"])
    if not vuln_class:
        return []
    return [
        CompanyPatternRecord(
            vuln_class=vuln_class,
            affected_product=string_or_none(first_present(payload, "affected_product", "product", "asset")),
            surface=string_or_none(first_present(payload, "surface", "endpoint", "area")),
            source_url=string_or_none(first_present(payload, "source_url", "url", "report_url", "writeup_url")),
            disclosure_date=string_or_none(first_present(payload, "disclosure_date", "published_at", "date")),
            platform=string_or_none(first_present(payload, "platform", "source")) or "local-fixture",
            cwe=string_or_none(payload.get("cwe")),
            exploit_preconditions=list_values(first_present(payload, "exploit_preconditions", "preconditions")),
            remediation_theme=string_or_none(first_present(payload, "remediation_theme", "remediation")),
            relevance=safe_float(payload.get("relevance"), 0.65),
            title=string_or_none(first_present(payload, "title", "name")),
            metadata={"fixture_path": source_path},
        )
    ]


def read_json_records(path: Path, context: IntelContext, *, source_type: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for payload in read_loose_payloads(path, context, source_type):
        if isinstance(payload, list):
            records.extend(item for item in payload if isinstance(item, dict))
        elif isinstance(payload, dict):
            records.append(payload)
    return records


def read_loose_payloads(path: Path, context: IntelContext, source_type: str) -> list[Any]:
    path = path.expanduser()
    if not path.exists() or not path.is_file():
        context.warnings.append(f"missing {source_type}: {path}")
        return []
    if path.stat().st_size > MAX_LOCAL_FILE_BYTES:
        context.warnings.append(f"skipped large {source_type}: {path}")
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        context.warnings.append(f"failed reading {source_type}: {path}: {exc}")
        return []
    context.sources.append(
        {
            "source_type": source_type,
            "path": str(path),
            "bytes": path.stat().st_size,
            "ingested_at": utc_now(),
            "raw_text_policy": "third-party or fixture text is parsed as data only; it is not agent instruction input",
        }
    )
    suffix = path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        payloads: list[Any] = []
        for line in text.splitlines():
            cleaned = clean_stack_line(line)
            if not cleaned:
                continue
            try:
                payloads.append(json.loads(cleaned))
            except json.JSONDecodeError:
                context.warnings.append(f"skipped malformed JSONL line in {path}")
        return payloads
    if suffix == ".json":
        try:
            return [json.loads(text)]
        except json.JSONDecodeError:
            context.warnings.append(f"skipped malformed JSON: {path}")
            return []
    return [line for line in text.splitlines() if clean_stack_line(line)]


def build_recommendations(context: IntelContext) -> list[IntelRecommendation]:
    recommendations: list[IntelRecommendation] = []
    for advisory in context.advisories:
        matches = match_advisory(advisory, context.stack)
        for component, match_type, match_metadata in matches:
            recommendations.append(score_advisory_recommendation(advisory, component, match_type, match_metadata, context))
    recommendations.extend(score_pattern_recommendations(context))
    return sorted(
        dedupe_recommendations(recommendations),
        key=lambda item: (-item.score, item.recommendation_type, item.title, item.recommendation_id),
    )


def match_advisory(
    advisory: AdvisoryRecord, stack: list[StackFingerprint]
) -> list[tuple[StackFingerprint, str, dict[str, Any]]]:
    matches: list[tuple[StackFingerprint, str, dict[str, Any]]] = []
    advisory_names = [(name, normalize_name(name)) for name in advisory.names()]
    for component in stack:
        component_name = component.normalized_name
        for raw_name, advisory_name in advisory_names:
            if not advisory_name or not component_name:
                continue
            version_match = version_matches(component.version, advisory.affected_versions)
            if component.cpe and advisory.cpe and normalize_name(component.cpe) == normalize_name(advisory.cpe):
                matches.append((component, "exact-cpe", {"matched_name": raw_name, "version_match": version_match}))
                break
            if component_name == advisory_name:
                matches.append((component, "exact-stack", {"matched_name": raw_name, "version_match": version_match}))
                break
            if conservative_fuzzy_match(component_name, advisory_name):
                matches.append((component, "fuzzy-name", {"matched_name": raw_name, "version_match": version_match}))
                break
    return matches


def score_advisory_recommendation(
    advisory: AdvisoryRecord,
    component: StackFingerprint,
    match_type: str,
    match_metadata: dict[str, Any],
    context: IntelContext,
) -> IntelRecommendation:
    score = SEVERITY_POINTS.get(advisory.severity, SEVERITY_POINTS["unknown"])
    reasons = [f"{advisory.severity} advisory severity"]
    if advisory.cvss is not None:
        cvss_points = int(round(advisory.cvss * 2))
        score += cvss_points
        reasons.append(f"CVSS {advisory.cvss:g} contributes {cvss_points} points")
    if advisory.epss is not None and advisory.epss >= 0.5:
        score += 8
        reasons.append(f"EPSS {advisory.epss:g} is elevated")
    if advisory.known_exploited:
        score += 18
        reasons.append("known exploited signal present")
    if match_type in {"exact-cpe", "exact-stack"}:
        score += 18
        reasons.append(f"{match_type} match to observed stack")
    else:
        score += 7
        reasons.append("fuzzy stack name match; validate manually")
    if match_metadata.get("version_match") is True:
        score += 15
        reasons.append("observed version is compatible with affected version hint")
    elif match_metadata.get("version_match") is False:
        score -= 15
        reasons.append("observed version did not match affected version hint")
    else:
        reasons.append("affected version compatibility is unknown")

    surface_bonus, surface_refs, coverage_status, scope_status = surface_context(advisory, component, context)
    score += surface_bonus
    if surface_bonus:
        reasons.append("exposed local surface evidence exists")
    if coverage_status == "untested":
        score += 10
        reasons.append("local surface coverage hints are untested")
    elif coverage_status == "partially-tested":
        score += 4
        reasons.append("local surface coverage appears partial")
    elif coverage_status == "already-covered":
        score -= 10
        reasons.append("local surface coverage appears already covered")
    if scope_status == "in-scope":
        score += 8
        reasons.append("surface or asset scope is in-scope")
    elif scope_status == "out-of-scope":
        score -= 40
        coverage_status = "blocked-by-scope-or-policy"
        reasons.append("scope evidence indicates out-of-scope")
    elif scope_status == "needs-human-review":
        reasons.append("scope needs human review before testing")

    pattern_bonus, pattern_refs = pattern_context(advisory.vuln_class, component.name, context)
    score += pattern_bonus
    if pattern_bonus:
        reasons.append("company/program pattern increases relevance")

    score = max(0, min(100, score))
    skills = skills_for(advisory.vuln_class, surface_refs)
    evidence = [component.evidence_source or "local stack"] + surface_refs
    return IntelRecommendation(
        recommendation_id=make_recommendation_id("advisory", advisory.advisory_id, component.name, component.version or ""),
        title=f"Review {component.name} for {advisory.advisory_id}",
        score=score,
        priority=priority_for_score(score),
        recommendation_type="advisory-match",
        component=component.name,
        advisory_id=advisory.advisory_id,
        pattern_refs=pattern_refs,
        match_type=match_type,
        recommended_skills=skills,
        coverage_status=coverage_status,
        scope_status=scope_status,
        reasons=reasons,
        evidence=sorted(dict.fromkeys(item for item in evidence if item)),
        source_refs=advisory.references,
        metadata={
            "match": match_metadata,
            "component": component.to_dict(),
            "advisory": advisory.to_dict(),
            "safety_boundary": "recommendation only; no exploitation or finding promotion performed",
        },
    )


def score_pattern_recommendations(context: IntelContext) -> list[IntelRecommendation]:
    recommendations: list[IntelRecommendation] = []
    for pattern in context.company_patterns:
        relevant_surfaces = surfaces_for_vuln_class(pattern.vuln_class, context.surfaces)
        if not relevant_surfaces:
            continue
        coverage = aggregate_coverage(relevant_surfaces)
        scope = aggregate_scope(relevant_surfaces, context.assets)
        score = int(round(18 + pattern.relevance * 20))
        reasons = [f"company/program pattern for {pattern.vuln_class}"]
        if coverage == "untested":
            score += 12
            reasons.append("matching local surfaces appear untested")
        if scope == "in-scope":
            score += 8
            reasons.append("matching local surface is in-scope")
        elif scope == "out-of-scope":
            score -= 30
            coverage = "blocked-by-scope-or-policy"
            reasons.append("matching local surface is out-of-scope")
        surface_refs = surface_refs_for(relevant_surfaces[:5])
        score = max(0, min(100, score))
        recommendations.append(
            IntelRecommendation(
                recommendation_id=make_recommendation_id(
                    "pattern", pattern.vuln_class, pattern.source_url or pattern.title or pattern.surface or ""
                ),
                title=f"Prioritize {pattern.vuln_class} coverage on matching surfaces",
                score=score,
                priority=priority_for_score(score),
                recommendation_type="company-pattern",
                pattern_refs=[pattern.source_url or pattern.title or pattern.vuln_class],
                recommended_skills=skills_for(pattern.vuln_class, surface_refs),
                coverage_status=coverage,
                scope_status=scope,
                reasons=reasons,
                evidence=surface_refs,
                source_refs=[pattern.source_url] if pattern.source_url else [],
                metadata={
                    "pattern": pattern.to_dict(),
                    "safety_boundary": "prioritization signal only; disclosed reports are not proof of current vulnerability",
                },
            )
        )
    return recommendations


def write_outputs(
    output_dir: Path,
    config: TargetIntelConfig,
    lane_root: Path,
    context: IntelContext,
    recommendations: list[IntelRecommendation],
) -> dict[str, Path]:
    paths = {
        "intel_json": output_dir / "intel.json",
        "intel_md": output_dir / "intel.md",
        "sources_jsonl": output_dir / "sources.jsonl",
        "stack_jsonl": output_dir / "stack_fingerprints.jsonl",
        "patterns_jsonl": output_dir / "company_patterns.jsonl",
        "recommendations_jsonl": output_dir / "recommendations.jsonl",
    }
    write_jsonl(paths["sources_jsonl"], context.sources)
    write_jsonl(paths["stack_jsonl"], [item.to_dict() for item in context.stack])
    write_jsonl(paths["patterns_jsonl"], [item.to_dict() for item in context.company_patterns])
    write_jsonl(paths["recommendations_jsonl"], [item.to_dict() for item in recommendations])
    summary = {
        "tool": "target-intel",
        "schema_version": INTEL_SCHEMA_VERSION,
        "program": config.program,
        "target": config.target,
        "family": config.family,
        "lane": config.lane,
        "lane_root": str(lane_root),
        "date": config.run_date or output_dir.name,
        "mode": "offline" if config.offline else "local",
        "artifact_dir": str(output_dir),
        "artifact_files": {key: str(value) for key, value in paths.items()},
        "counts": {
            "stack_fingerprints": len(context.stack),
            "advisories": len(context.advisories),
            "company_patterns": len(context.company_patterns),
            "surface_records": len(context.surfaces),
            "asset_records": len(context.assets),
            "recommendations": len(recommendations),
            "promoted_findings": 0,
        },
        "warnings": context.warnings,
        "recommendations": [item.to_dict() for item in recommendations],
        "promotion_policy": "No finding ledger writes. Intel recommendations are passive prioritization leads only.",
        "next_builder_contract": {
            "recommendations_jsonl": str(paths["recommendations_jsonl"]),
            "record_key": "recommendation_id",
            "matching_metadata": "metadata.match distinguishes exact-cpe/exact-stack/fuzzy-name and version compatibility",
        },
    }
    paths["intel_json"].write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["intel_md"].write_text(build_markdown(summary, recommendations), encoding="utf-8")
    return paths


def build_markdown(summary: dict[str, Any], recommendations: list[IntelRecommendation]) -> str:
    lines = [
        f"# Target Intel: {summary['target']}",
        "",
        f"- Program: {summary['program']}",
        f"- Mode: {summary['mode']}",
        f"- Stack fingerprints: {summary['counts']['stack_fingerprints']}",
        f"- Recommendations: {len(recommendations)}",
        "- Safety: passive prioritization only; no exploitation, active scanning, or findings promotion performed.",
        "",
        "## Recommendations",
        "",
    ]
    if not recommendations:
        lines.append("- No local fixture-backed recommendations generated.")
    for rec in recommendations:
        skills = ", ".join(rec.recommended_skills) if rec.recommended_skills else "manual review"
        lines.append(f"- `{rec.priority}` `{rec.score}` {rec.title}")
        lines.append(f"  - Coverage: {rec.coverage_status}; scope: {rec.scope_status}; skills: {skills}")
        for reason in rec.reasons[:4]:
            lines.append(f"  - {reason}")
        for ref in rec.source_refs[:3]:
            lines.append(f"  - Source: {ref}")
    if summary.get("warnings"):
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in summary["warnings"])
    return "\n".join(lines) + "\n"


def surface_context(
    advisory: AdvisoryRecord, component: StackFingerprint, context: IntelContext
) -> tuple[int, list[str], str, str]:
    relevant = surfaces_for_component_or_vuln(component, advisory.vuln_class, context.surfaces)
    if not relevant:
        return 0, [], "untested", "unknown"
    refs = surface_refs_for(relevant[:5])
    bonus = min(15, 5 + len(relevant) * 3)
    return bonus, refs, aggregate_coverage(relevant), aggregate_scope(relevant, context.assets)


def surfaces_for_component_or_vuln(
    component: StackFingerprint, vuln_class: str | None, surfaces: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    component_name = component.normalized_name
    for surface in surfaces:
        haystack = " ".join(
            str(surface.get(field) or "")
            for field in ("family", "subtype", "entry_vector", "candidate_child_skills", "labels", "metadata")
        ).lower()
        if component_name and component_name in normalize_name(haystack):
            result.append(surface)
            continue
        if vuln_class and surface_matches_vuln_class(surface, vuln_class):
            result.append(surface)
    return result


def surfaces_for_vuln_class(vuln_class: str, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [surface for surface in surfaces if surface_matches_vuln_class(surface, vuln_class)]


def surface_matches_vuln_class(surface: dict[str, Any], vuln_class: str) -> bool:
    normalized = normalize_vuln_class(vuln_class)
    family = str(surface.get("family") or "").lower()
    subtype = str(surface.get("subtype") or "").lower()
    skills = [str(item).lower() for item in surface.get("candidate_child_skills") or []]
    if normalized in skills:
        return True
    if normalized in {"idor", "access-control", "bola"}:
        return family in {"account-tenant-object", "graphql-rpc-operation", "admin-support-impersonation"}
    if normalized == "ssrf":
        return family in {"url-fetch-import-webhook", "file-upload-ingestion", "media-avatar-profile", "third-party-integration"}
    if normalized == "xss":
        return family in {"search-filter-query", "notification-email-template", "cdn-static-js-asset", "file-upload-ingestion"}
    if normalized in {"sqli", "sql-injection"}:
        return family in {"search-filter-query", "api-endpoint-operation", "graphql-rpc-operation"}
    if normalized == "csrf":
        return family in {"auth-session-flow", "rate-limit-stateful-action"}
    if normalized == "graphql":
        return "graphql" in family or "graphql" in subtype
    return False


def pattern_context(
    vuln_class: str | None, component_name: str, context: IntelContext
) -> tuple[int, list[str]]:
    refs: list[str] = []
    bonus = 0
    normalized_component = normalize_name(component_name)
    normalized_vuln = normalize_vuln_class(vuln_class or "")
    for pattern in context.company_patterns:
        pattern_component = normalize_name(pattern.affected_product or "")
        same_class = normalized_vuln and normalized_vuln == pattern.vuln_class
        same_product = pattern_component and (
            pattern_component == normalized_component
            or conservative_fuzzy_match(normalized_component, pattern_component)
        )
        if same_class or same_product:
            bonus += int(round(4 + pattern.relevance * 6))
            refs.append(pattern.source_url or pattern.title or pattern.vuln_class)
    return min(15, bonus), sorted(dict.fromkeys(refs))


def aggregate_coverage(surfaces: list[dict[str, Any]]) -> str:
    if not surfaces:
        return "untested"
    hints = [str(hint).lower() for surface in surfaces for hint in surface.get("coverage_hints") or []]
    if any(hint in {"blocked-by-scope-or-policy", "needs-human-approval"} for hint in hints):
        return "needs-human-approval"
    if any(hint in {"already-covered", "covered", "tested"} for hint in hints) and not any(
        hint in {"untested", "partially-tested", "partial"} for hint in hints
    ):
        return "already-covered"
    if any(hint in {"partially-tested", "partial"} for hint in hints):
        return "partially-tested"
    return "untested"


def aggregate_scope(surfaces: list[dict[str, Any]], assets: list[dict[str, Any]]) -> str:
    statuses = [str(surface.get("scope_status") or "unknown") for surface in surfaces]
    if not statuses:
        related_assets = [asset for asset in assets if asset_is_target_related(asset)]
        statuses.extend(str(asset.get("scope_status") or "unknown") for asset in related_assets)
    if "out-of-scope" in statuses:
        return "out-of-scope"
    if "in-scope" in statuses:
        return "in-scope"
    if "needs-human-review" in statuses:
        return "needs-human-review"
    return "unknown"


def asset_is_target_related(asset: dict[str, Any]) -> bool:
    host = host_from_asset(asset)
    if not host:
        return False
    metadata = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
    target = str(metadata.get("target") or metadata.get("program") or "").lower()
    if target:
        return host == target or host.endswith(f".{target}")
    scope_status = str(asset.get("scope_status") or "unknown")
    return scope_status in {"in-scope", "needs-human-review"}


def host_from_asset(asset: dict[str, Any]) -> str:
    value = str(asset.get("normalized_value") or asset.get("value") or "")
    if value.startswith(("http://", "https://")):
        return (urlparse(value).hostname or "").lower()
    return value.split("/", 1)[0].split(":", 1)[0].lower().strip(".")


def skills_for(vuln_class: str | None, surface_refs: list[str]) -> list[str]:
    normalized = normalize_vuln_class(vuln_class or "")
    skills = list(VULN_CLASS_SKILLS.get(normalized, []))
    haystack = " ".join(surface_refs).lower()
    if "graphql" in haystack:
        skills.extend(["access-control", "idor", "sqli"])
    if not skills:
        skills = ["recon"]
    return sorted(dict.fromkeys(skills))


def surface_refs_for(surfaces: list[dict[str, Any]]) -> list[str]:
    refs: list[str] = []
    for surface in surfaces:
        method = string_or_none(surface.get("http_method"))
        entry = string_or_none(surface.get("entry_vector"))
        if method and entry:
            refs.append(f"{method} {entry}")
        elif entry:
            refs.append(entry)
        elif surface.get("surface_id"):
            refs.append(str(surface["surface_id"]))
    return sorted(dict.fromkeys(refs))


def version_matches(version: str | None, affected_versions: list[str]) -> bool | None:
    if not affected_versions:
        return None
    if not version:
        return None
    normalized_version = normalize_version(version)
    for affected in affected_versions:
        text = affected.lower()
        if normalized_version and normalize_version(affected) == normalized_version:
            return True
        if version in affected:
            return True
        upper = re.search(r"<\s*=?\s*(\d+(?:\.\d+){0,4})", text)
        lower = re.search(r">=?\s*(\d+(?:\.\d+){0,4})", text)
        if upper and compare_versions(normalized_version, upper.group(1)) < 0:
            if not lower or compare_versions(normalized_version, lower.group(1)) >= 0:
                return True
    return False


def compare_versions(left: str, right: str) -> int:
    left_parts = [int(part) for part in re.findall(r"\d+", left)[:4]]
    right_parts = [int(part) for part in re.findall(r"\d+", right)[:4]]
    width = max(len(left_parts), len(right_parts), 1)
    left_parts.extend([0] * (width - len(left_parts)))
    right_parts.extend([0] * (width - len(right_parts)))
    return (left_parts > right_parts) - (left_parts < right_parts)


def conservative_fuzzy_match(left: str, right: str) -> bool:
    left_tokens = meaningful_tokens(left)
    right_tokens = meaningful_tokens(right)
    if not left_tokens or not right_tokens:
        return False
    if len(left_tokens & right_tokens) >= 2:
        return True
    if len(left_tokens) == 1 and len(right_tokens) == 1:
        left_token = next(iter(left_tokens))
        right_token = next(iter(right_tokens))
        return len(left_token) >= 6 and (left_token in right_token or right_token in left_token)
    return False


def meaningful_tokens(value: str) -> set[str]:
    ignored = {"js", "http", "server", "framework", "library", "cms", "app", "web"}
    return {token for token in re.findall(r"[a-z0-9]{3,}", normalize_name(value)) if token not in ignored}


def dedupe_stack(stack: list[StackFingerprint]) -> list[StackFingerprint]:
    seen: dict[tuple[str, str | None, str | None], StackFingerprint] = {}
    for item in stack:
        key = (item.normalized_name, item.version, item.service)
        current = seen.get(key)
        if current is None or item.confidence > current.confidence:
            seen[key] = item
    return sorted(seen.values(), key=lambda item: (item.normalized_name, item.version or ""))


def dedupe_advisories(advisories: list[AdvisoryRecord]) -> list[AdvisoryRecord]:
    seen: dict[str, AdvisoryRecord] = {}
    for item in advisories:
        seen[item.advisory_id] = item
    return sorted(seen.values(), key=lambda item: item.advisory_id)


def dedupe_patterns(patterns: list[CompanyPatternRecord]) -> list[CompanyPatternRecord]:
    seen: dict[tuple[str, str, str], CompanyPatternRecord] = {}
    for item in patterns:
        key = (item.vuln_class, item.source_url or "", item.surface or "")
        seen[key] = item
    return sorted(seen.values(), key=lambda item: (item.vuln_class, item.source_url or "", item.surface or ""))


def dedupe_recommendations(recommendations: list[IntelRecommendation]) -> list[IntelRecommendation]:
    seen: dict[str, IntelRecommendation] = {}
    for item in recommendations:
        current = seen.get(item.recommendation_id)
        if current is None or item.score > current.score:
            seen[item.recommendation_id] = item
    return list(seen.values())


def write_jsonl(path: Path, records: Iterable[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build passive target intel recommendations from local fixtures.")
    parser.add_argument("program")
    parser.add_argument("--target", required=True, help="Target domain or host.")
    parser.add_argument("--family", default="web_bounty")
    parser.add_argument("--lane", default="web")
    parser.add_argument("--root", help="Canonical shared storage root override.")
    parser.add_argument("--surface-map", action="append", dest="surface_maps", help="surface_map.jsonl to consume.")
    parser.add_argument("--asset-graph", action="append", dest="asset_graphs", help="asset_graph.jsonl to consume.")
    parser.add_argument("--stack", action="append", dest="stacks", help="Tech stack text/json/jsonl file to consume.")
    parser.add_argument("--advisory-fixture", action="append", dest="advisories", help="Advisory JSON/JSONL fixture.")
    parser.add_argument(
        "--company-pattern-fixture",
        action="append",
        dest="patterns",
        help="Company/program disclosure pattern JSON/JSONL fixture.",
    )
    parser.add_argument("--run-date", help="Output date directory, YYYY-MM-DD.")
    parser.add_argument("--offline", action="store_true", default=False, help="Disable live provider hooks.")
    parser.add_argument("--json", action="store_true", help="Print intel.json.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.offline:
        print("[target-intel] live providers are not implemented in beta; running local-only", file=sys.stderr)
    config = TargetIntelConfig(
        program=args.program,
        target=args.target,
        family=args.family,
        lane=args.lane,
        root=args.root,
        surface_map_paths=[Path(value) for value in args.surface_maps or []],
        asset_graph_paths=[Path(value) for value in args.asset_graphs or []],
        stack_paths=[Path(value) for value in args.stacks or []],
        advisory_fixture_paths=[Path(value) for value in args.advisories or []],
        company_pattern_fixture_paths=[Path(value) for value in args.patterns or []],
        offline=True,
        run_date=args.run_date,
    )
    intel_json = run_target_intel(config)
    if args.json:
        print(intel_json.read_text(encoding="utf-8"), end="")
    else:
        print(intel_json)
    return 0


def clean_stack_line(value: str) -> str:
    line = str(value or "").strip()
    if not line or line.startswith("#"):
        return ""
    if " #" in line:
        line = line.split(" #", 1)[0].strip()
    return line.strip().strip(",")


def clean_text(value: Any) -> str:
    return str(value or "").strip()


def string_or_none(value: Any) -> str | None:
    text = clean_text(value)
    return text or None


def first_present(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = payload.get(key)
        if value is not None and value != "":
            return value
    return None


def list_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, dict):
        return [str(item).strip() for item in value.values() if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    if "," in text:
        return [item.strip() for item in text.split(",") if item.strip()]
    return [text]


def normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def normalize_version(value: str) -> str:
    match = re.search(r"\d+(?:\.\d+){0,4}", str(value or ""))
    return match.group(0) if match else ""


def normalize_severity(value: str) -> str:
    text = str(value or "unknown").strip().lower()
    return text if text in SEVERITY_POINTS else "unknown"


def normalize_vuln_class(value: str) -> str:
    text = normalize_name(value).replace(" ", "-")
    mappings = {
        "cwe-79": "xss",
        "cross-site-scripting": "xss",
        "sql-injection": "sqli",
        "cwe-89": "sqli",
        "broken-access-control": "access-control",
        "authorization": "access-control",
        "cwe-639": "idor",
        "server-side-request-forgery": "ssrf",
        "cwe-918": "ssrf",
    }
    return mappings.get(text, text or "unknown")


def safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "y", "kev", "known-exploited"}


def clamp_float(value: Any, lower: float, upper: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = lower
    return max(lower, min(upper, number))


def truncate_summary(value: str | None) -> str | None:
    if not value:
        return None
    text = re.sub(r"\s+", " ", value).strip()
    return text[:500]


def looks_like_url(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def drop_none(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value is not None}


def make_recommendation_id(*parts: str) -> str:
    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"intel:{digest}"


def priority_for_score(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 25:
        return "low"
    return "info"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def utc_date() -> str:
    return datetime.now(timezone.utc).date().isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
