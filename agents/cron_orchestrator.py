#!/usr/bin/env python3
"""Dry-run planner for scheduled Bug Bounty Harness jobs.

The orchestrator intentionally starts with validation and planning only. Live
tool execution should be added behind explicit job gates after the plan shape is
stable and covered by tests.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sqlite3
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

try:
    from scope_validator import ScopeValidator
except ModuleNotFoundError:
    from agents.scope_validator import ScopeValidator


KNOWN_JOB_NAMES = {
    "authenticated_parameter_mining",
    "juicy_target_fuzz",
    "naabu_discovery",
    "nmap_enrichment",
    "parameter_mining",
    "recon_refresh",
    "tech_fingerprint",
}
SENSITIVE_TARGET_TERMS = (
    "api",
    "dev",
    "staging",
    "stage",
    "admin",
    "preview",
    "beta",
    "upload",
    "import",
    "export",
    "internal",
    "dashboard",
    "graphql",
    "swagger",
    "openapi",
)
DEFAULT_ARTIFACT_ROOT = Path.home() / "Shared" / "web_bounty"
DEFAULT_CONFIG_ROOT = Path(__file__).resolve().parent / "config" / "cron"
LIVE_HTTP_JOBS = {
    "authenticated_parameter_mining",
    "juicy_target_fuzz",
    "parameter_mining",
}
EXECUTABLE_PLANNED_JOBS = LIVE_HTTP_JOBS | {"naabu_discovery", "nmap_enrichment"}

TECH_WORDLIST_SIGNALS = {
    "api": {
        "api",
        "application/json",
        "openapi",
        "swagger",
        "rest",
        "oauth",
        "jwt",
        "mcp",
        "graphql",
    },
    "graphql": {"graphql", "graphiql", "apollo", "__schema"},
    "javascript": {
        ".js",
        "javascript",
        "webpack",
        "vite",
        "react",
        "vue",
        "angular",
        "svelte",
        "source-map",
        "sourcemap",
        "_next",
    },
}

WAF_SIGNALS = {
    "cloudflare": {"cloudflare", "cf-ray", "cf-cache-status"},
    "aws": {"awselb", "x-amzn", "cloudfront", "x-cache"},
    "akamai": {"akamai", "akamai-ghost", "x-akamai"},
    "fastly": {"fastly", "x-served-by", "x-cache-hits"},
}

CDN_WAF_NAMES = {"akamai", "aws", "cloudflare", "fastly"}


@dataclass
class TargetCandidate:
    key: str
    base_url: str
    host: str
    source: str
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        self.score += points
        if reason not in self.reasons:
            self.reasons.append(reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "base_url": self.base_url,
            "host": self.host,
            "source": self.source,
            "score": self.score,
            "reasons": list(self.reasons),
        }


def load_config(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config root must be a mapping")
    return data


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_scheduler_config(
    program: str | None = None,
    *,
    config_path: str | Path | None = None,
    config_root: str | Path | None = None,
) -> dict[str, Any]:
    if config_path:
        return load_config(Path(config_path).expanduser())

    root = Path(config_root).expanduser() if config_root else DEFAULT_CONFIG_ROOT
    defaults_path = root / "defaults.yaml"
    data: dict[str, Any] = load_config(defaults_path) if defaults_path.is_file() else {"version": 1}

    if program:
        program_path = root / "programs" / f"{program}.yaml"
        if not program_path.is_file():
            legacy_path = root / f"{program}-juicy-fuzz-and-params.yaml"
            program_path = legacy_path if legacy_path.is_file() else program_path
        if not program_path.is_file():
            raise FileNotFoundError(f"program cron config not found: {program_path}")
        data = deep_merge(data, load_config(program_path))
        return data

    programs_dir = root / "programs"
    if programs_dir.is_dir():
        for program_path in sorted(programs_dir.glob("*.yaml")):
            data = deep_merge(data, load_config(program_path))
    return data


def expand_path(value: str | Path) -> Path:
    return Path(str(value)).expanduser()


def expand_pattern(value: str, context: dict[str, str]) -> str:
    result = str(value)
    for key, replacement in context.items():
        result = result.replace(f"<{key}>", replacement)
    return result


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def render_runtime_path(value: str | Path, run_id_value: str) -> Path:
    rendered = str(value).replace("<YYYY-MM-DD>", today_utc()).replace("<run-id>", run_id_value)
    return expand_path(rendered)


def host_from_url(value: str) -> str:
    parsed = urlparse(value if re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I) else f"https://{value}")
    return (parsed.hostname or "").lower()


def normalize_base_url(value: str) -> str:
    if not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I):
        value = f"https://{value}"
    parsed = urlparse(value)
    if not parsed.hostname:
        return value.rstrip("/")
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def validate_config(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if data.get("version") != 1:
        errors.append("version must be 1")
    programs = data.get("programs")
    if not isinstance(programs, dict) or not programs:
        errors.append("programs must be a non-empty mapping")
        return errors

    platforms = data.get("platforms") if isinstance(data.get("platforms"), dict) else {}
    for program, program_cfg in programs.items():
        if not isinstance(program_cfg, dict):
            errors.append(f"program {program}: config must be a mapping")
            continue
        platform = str(program_cfg.get("platform") or "")
        if platform and platform not in platforms:
            errors.append(f"program {program}: unknown platform {platform}")
        targets = program_cfg.get("targets")
        if not isinstance(targets, dict) or not targets:
            errors.append(f"program {program}: targets must be a non-empty mapping")
        jobs = program_cfg.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            errors.append(f"program {program}: jobs must be a non-empty mapping")
            continue
        for job_name, job_cfg in jobs.items():
            if job_name not in KNOWN_JOB_NAMES:
                errors.append(f"program {program}: unknown job {job_name}")
            if not isinstance(job_cfg, dict):
                errors.append(f"program {program} job {job_name}: config must be a mapping")
                continue
            target = job_cfg.get("target")
            if target and target != "inherit_target_selection" and isinstance(targets, dict) and target not in targets:
                errors.append(f"program {program} job {job_name}: unknown target alias {target}")
    return errors


def candidate_from_url(
    url: str,
    *,
    key_prefix: str,
    source: str,
    collapse_to_origin: bool = False,
) -> TargetCandidate | None:
    base_url = normalize_base_url(url)
    host = host_from_url(base_url)
    if not host:
        return None
    if collapse_to_origin:
        parsed = urlparse(base_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
    digest = hashlib.sha1(base_url.encode("utf-8")).hexdigest()[:10]
    return TargetCandidate(key=f"{key_prefix}_{digest}", base_url=base_url, host=host, source=source)


def read_lines(path: Path, *, limit: int | None = None) -> list[str]:
    if not path.is_file():
        return []
    rows: list[str] = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            rows.append(value)
            if limit is not None and len(rows) >= limit:
                break
    return rows


def extract_urls(value: str) -> list[str]:
    matches = re.findall(r"https?://[^\s\"'<>]+", value)
    if matches:
        return matches
    if "." in value and not value.startswith("{"):
        return [value]
    return []


def add_or_merge(candidates: dict[str, TargetCandidate], candidate: TargetCandidate | None) -> None:
    if candidate is None:
        return
    existing = candidates.get(candidate.base_url)
    if existing is None:
        candidates[candidate.base_url] = candidate
        return
    sources = []
    for source in (*existing.source.split(","), *candidate.source.split(",")):
        if source and source not in sources:
            sources.append(source)
    existing.source = ",".join(sources)


def collect_target_candidates(program: str, program_cfg: dict[str, Any]) -> list[TargetCandidate]:
    candidates: dict[str, TargetCandidate] = {}
    targets = program_cfg.get("targets") if isinstance(program_cfg.get("targets"), dict) else {}
    for key, target_cfg in targets.items():
        if not isinstance(target_cfg, dict):
            continue
        for base_url in target_cfg.get("base_urls") or ():
            candidate = candidate_from_url(str(base_url), key_prefix=str(key), source="config.target")
            if candidate:
                candidate.key = str(key)
            add_or_merge(candidates, candidate)

    selection = program_cfg.get("target_selection") if isinstance(program_cfg.get("target_selection"), dict) else {}
    for raw_path in selection.get("ranking_inputs") or ():
        path = expand_path(str(raw_path))
        if path.is_dir():
            for name in ("alive.txt", "urls.txt", "params.txt", "params_raw.txt"):
                for line in read_lines(path / name):
                    for url in extract_urls(line):
                        add_or_merge(
                            candidates,
                            candidate_from_url(url, key_prefix="recon", source=str(path / name), collapse_to_origin=True),
                        )
            continue
        if path.suffix == ".sqlite" and path.is_file():
            for url in urls_from_url_ingest(path):
                add_or_merge(
                    candidates,
                    candidate_from_url(url, key_prefix="url_ingest", source=str(path), collapse_to_origin=True),
                )
            continue
        if path.is_file():
            for line in read_lines(path):
                for url in extract_urls(line):
                    add_or_merge(
                        candidates,
                        candidate_from_url(url, key_prefix="recon", source=str(path), collapse_to_origin=True),
                    )

    filtered = scope_filter_candidates(program, program_cfg, list(candidates.values()))
    for candidate in filtered:
        score_candidate(candidate, program, program_cfg)
    return sorted(filtered, key=lambda item: (-item.score, item.host, item.base_url))


def scope_filter_candidates(
    program: str,
    program_cfg: dict[str, Any],
    candidates: list[TargetCandidate],
) -> list[TargetCandidate]:
    scope_cfg = program_cfg.get("scope") if isinstance(program_cfg.get("scope"), dict) else {}
    if not scope_cfg.get("fail_closed", False):
        return candidates
    validator = ScopeValidator(program, strict=False)
    return [
        candidate
        for candidate in candidates
        if validator.is_in_scope(candidate.base_url) or validator.is_in_scope(candidate.host)
    ]


def urls_from_url_ingest(path: Path, *, limit: int | None = None) -> list[str]:
    try:
        with sqlite3.connect(path) as conn:
            if limit is None:
                rows = conn.execute(
                    "SELECT url FROM urls ORDER BY id DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT url FROM urls ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [str(row[0]) for row in rows if row and row[0]]
    except sqlite3.Error:
        return []


def score_candidate(candidate: TargetCandidate, program: str, program_cfg: dict[str, Any]) -> None:
    haystack = f"{candidate.host} {urlparse(candidate.base_url).path}".lower()
    for term in SENSITIVE_TARGET_TERMS:
        if term in haystack:
            candidate.add(12, f"sensitive term: {term}")

    if candidate.source != "config.target":
        candidate.add(5, "discovered from recon evidence")

    if has_existing_url_ingest(candidate.host, program_cfg):
        candidate.add(8, "has URL-ingest history")

    if has_fuzz_gap(candidate, program_cfg):
        candidate.add(10, "no matching fuzz-history entry")

    if has_naabu_or_nmap_hint(candidate.host, program_cfg):
        candidate.add(10, "has naabu/nmap service hint")

    if candidate.score == 0:
        candidate.add(1, "baseline configured target")


def has_existing_url_ingest(host: str, program_cfg: dict[str, Any]) -> bool:
    selection = program_cfg.get("target_selection") if isinstance(program_cfg.get("target_selection"), dict) else {}
    for raw_path in selection.get("ranking_inputs") or ():
        path = expand_path(str(raw_path))
        if path.suffix != ".sqlite" or not path.is_file():
            continue
        try:
            with sqlite3.connect(path) as conn:
                row = conn.execute(
                    "SELECT 1 FROM urls WHERE host LIKE ? LIMIT 1",
                    (f"%{host}%",),
                ).fetchone()
            if row:
                return True
        except sqlite3.Error:
            continue
    return False


def has_fuzz_gap(candidate: TargetCandidate, program_cfg: dict[str, Any]) -> bool:
    selection = program_cfg.get("target_selection") if isinstance(program_cfg.get("target_selection"), dict) else {}
    for raw_path in selection.get("ranking_inputs") or ():
        path = expand_path(str(raw_path))
        if path.name != "fuzz_runs.jsonl" or not path.is_file():
            continue
        for line in read_lines(path):
            if candidate.host in line or candidate.base_url in line:
                return False
    return True


def has_naabu_or_nmap_hint(host: str, program_cfg: dict[str, Any]) -> bool:
    for record in collect_naabu_ports(program_cfg, selected_host=host, max_hosts=1, max_ports=1):
        if record["host"] == host:
            return True
    selection = program_cfg.get("target_selection") if isinstance(program_cfg.get("target_selection"), dict) else {}
    for raw_path in selection.get("ranking_inputs") or ():
        path = expand_path(str(raw_path))
        if not path.exists() or "nmap" not in str(path):
            continue
        if path.is_dir():
            for child in path.rglob("*"):
                if child.is_file() and host in child.read_text(encoding="utf-8", errors="ignore"):
                    return True
        elif host in path.read_text(encoding="utf-8", errors="ignore"):
            return True
    return False


def collect_naabu_ports(
    program_cfg: dict[str, Any],
    *,
    selected_host: str | None = None,
    max_hosts: int = 3,
    max_ports: int = 20,
) -> list[dict[str, Any]]:
    jobs = program_cfg.get("jobs") if isinstance(program_cfg.get("jobs"), dict) else {}
    job = jobs.get("nmap_enrichment") if isinstance(jobs.get("nmap_enrichment"), dict) else {}
    inputs = job.get("inputs") if isinstance(job.get("inputs"), dict) else {}
    records: dict[str, set[int]] = {}
    for raw_path in inputs.get("naabu_ports") or ():
        path = expand_path(str(raw_path))
        for host, port in parse_port_records(path):
            if selected_host and host != selected_host:
                continue
            records.setdefault(host, set()).add(port)
    result: list[dict[str, Any]] = []
    for host in sorted(records)[:max_hosts]:
        ports = sorted(records[host])[:max_ports]
        result.append({"host": host, "ports": ports})
    return result


def parse_port_records(path: Path) -> list[tuple[str, int]]:
    if not path.is_file():
        return []
    records: list[tuple[str, int]] = []
    for line in read_lines(path):
        parsed = parse_port_line(line)
        if parsed:
            records.append(parsed)
    return records


def parse_port_line(line: str) -> tuple[str, int] | None:
    value = line.strip()
    if not value:
        return None
    if value.startswith("{"):
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            return None
        host = str(payload.get("host") or payload.get("ip") or payload.get("url") or "")
        port_value = payload.get("port")
        if port_value is None and isinstance(payload.get("ports"), list) and payload["ports"]:
            port_value = payload["ports"][0]
        return normalize_host_port(host, port_value)
    if "://" in value:
        parsed = urlparse(value)
        return normalize_host_port(parsed.hostname or "", parsed.port)
    if ":" in value:
        host, port = value.rsplit(":", 1)
        return normalize_host_port(host, port)
    return None


def normalize_host_port(host: str, port_value: Any) -> tuple[str, int] | None:
    host = host_from_url(host) if "://" in str(host) else str(host).strip().lower()
    try:
        port = int(port_value)
    except (TypeError, ValueError):
        return None
    if not host or port < 1 or port > 65535:
        return None
    return host, port


def _json_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        return " ".join(f"{key} {_json_text(item)}" for key, item in value.items())
    if isinstance(value, list):
        return " ".join(_json_text(item) for item in value)
    return str(value)


def _source_matches_target(text: str, selected: TargetCandidate) -> bool:
    lowered = text.lower()
    return selected.host in lowered or selected.base_url.lower() in lowered


def _iter_technology_source_files(program_cfg: dict[str, Any], wordlists: dict[str, Any]) -> list[Path]:
    raw_paths: list[str] = []
    raw_paths.extend(str(path) for path in wordlists.get("tech_sources") or ())
    selection = program_cfg.get("target_selection") if isinstance(program_cfg.get("target_selection"), dict) else {}
    raw_paths.extend(str(path) for path in selection.get("ranking_inputs") or ())

    files: list[Path] = []
    seen: set[Path] = set()
    interesting_names = ("httpx", "header", "headers", "tech", "waf", "map", "summary", "service")
    for raw_path in raw_paths:
        path = expand_path(raw_path)
        candidates: list[Path]
        if path.is_dir():
            candidates = [
                child
                for child in path.rglob("*")
                if child.is_file()
                and child.suffix.lower() in {".json", ".jsonl", ".md", ".txt"}
                and any(marker in child.name.lower() or marker in str(child.parent).lower() for marker in interesting_names)
            ]
        elif path.is_file():
            candidates = [path]
        else:
            continue
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                files.append(candidate)
    return files


def _read_technology_source(path: Path, selected: TargetCandidate, *, max_records: int = 2000) -> list[str]:
    texts: list[str] = []
    try:
        if path.suffix.lower() == ".jsonl":
            for index, line in enumerate(read_lines(path, limit=max_records)):
                if index >= max_records:
                    break
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    payload = line
                text = _json_text(payload)
                if _source_matches_target(text, selected):
                    texts.append(text)
            return texts
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return texts

    if not _source_matches_target(raw, selected):
        return texts
    if path.suffix.lower() == ".json":
        try:
            raw = _json_text(json.loads(raw))
        except json.JSONDecodeError:
            pass
    texts.append(raw[:20000])
    return texts


def build_technology_map(program_cfg: dict[str, Any], selected: TargetCandidate) -> dict[str, Any]:
    jobs = program_cfg.get("jobs") if isinstance(program_cfg.get("jobs"), dict) else {}
    fuzz_job = jobs.get("juicy_target_fuzz") if isinstance(jobs.get("juicy_target_fuzz"), dict) else {}
    wordlists = fuzz_job.get("wordlists") if isinstance(fuzz_job.get("wordlists"), dict) else {}
    available_groups = set((wordlists.get("tech_wordlists") or {}).keys())

    signals: dict[str, list[str]] = {}
    wafs: dict[str, list[str]] = {}
    selected_groups: list[str] = []
    sources: list[str] = []

    def add_signal(kind: str, evidence: str, source: Path) -> None:
        signals.setdefault(kind, [])
        if evidence not in signals[kind]:
            signals[kind].append(evidence)
        source_text = str(source)
        if source_text not in sources:
            sources.append(source_text)

    for source in _iter_technology_source_files(program_cfg, wordlists):
        for text in _read_technology_source(source, selected):
            lowered = text.lower()
            for group, keywords in TECH_WORDLIST_SIGNALS.items():
                if group not in available_groups:
                    continue
                matched = sorted(keyword for keyword in keywords if keyword in lowered)
                if matched:
                    add_signal(group, ", ".join(matched[:6]), source)
            for waf_name, keywords in WAF_SIGNALS.items():
                matched = sorted(keyword for keyword in keywords if keyword in lowered)
                if matched:
                    wafs.setdefault(waf_name, [])
                    evidence = ", ".join(matched[:4])
                    if evidence not in wafs[waf_name]:
                        wafs[waf_name].append(evidence)
                    source_text = str(source)
                    if source_text not in sources:
                        sources.append(source_text)

    for group in sorted(available_groups):
        if signals.get(group):
            selected_groups.append(group)

    return {
        "target": selected.to_dict(),
        "selected_wordlist_groups": selected_groups,
        "signals": signals,
        "wafs": wafs,
        "source_count": len(sources),
        "sources": sources[:50],
    }


def resolve_program(data: dict[str, Any], program: str) -> dict[str, Any]:
    programs = data.get("programs") if isinstance(data.get("programs"), dict) else {}
    program_cfg = programs.get(program)
    if not isinstance(program_cfg, dict):
        raise ValueError(f"program not found in config: {program}")
    return program_cfg


def select_target(program: str, program_cfg: dict[str, Any]) -> TargetCandidate:
    candidates = collect_target_candidates(program, program_cfg)
    if candidates:
        return candidates[0]
    selection = program_cfg.get("target_selection") if isinstance(program_cfg.get("target_selection"), dict) else {}
    default_target = selection.get("default_target")
    targets = program_cfg.get("targets") if isinstance(program_cfg.get("targets"), dict) else {}
    target_cfg = targets.get(default_target) if isinstance(targets.get(default_target), dict) else None
    if not target_cfg:
        raise ValueError(f"no selectable target found for {program}")
    base_url = str((target_cfg.get("base_urls") or [""])[0])
    candidate = candidate_from_url(base_url, key_prefix=str(default_target), source="config.default")
    if not candidate:
        raise ValueError(f"default target has no valid base URL: {default_target}")
    candidate.key = str(default_target)
    candidate.add(1, "default target fallback")
    return candidate


def target_select_count(program_cfg: dict[str, Any]) -> int:
    selection = program_cfg.get("target_selection") if isinstance(program_cfg.get("target_selection"), dict) else {}
    raw_count = selection.get("select_n") or selection.get("max_targets") or selection.get("top_targets")
    agent_review = selection.get("agent_review") if isinstance(selection.get("agent_review"), dict) else {}
    raw_count = raw_count or agent_review.get("select_n")
    try:
        return max(1, int(raw_count or 1))
    except (TypeError, ValueError):
        return 1


def select_targets(program: str, program_cfg: dict[str, Any]) -> list[TargetCandidate]:
    candidates = collect_target_candidates(program, program_cfg)
    count = target_select_count(program_cfg)
    if candidates:
        return candidates[:count]
    return [select_target(program, program_cfg)]


def safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return slug[:80] or "target"


def build_nmap_plan(program: str, program_cfg: dict[str, Any], selected: TargetCandidate) -> dict[str, Any]:
    jobs = program_cfg.get("jobs") if isinstance(program_cfg.get("jobs"), dict) else {}
    job = jobs.get("nmap_enrichment")
    if not isinstance(job, dict):
        return {"job": "nmap_enrichment", "state": "absent", "status": "skipped", "reason": "job not configured"}

    inputs = job.get("inputs") if isinstance(job.get("inputs"), dict) else {}
    max_hosts = int(inputs.get("max_hosts_per_run") or 3)
    max_ports = int(inputs.get("max_ports_per_host") or 20)
    port_records = collect_naabu_ports(program_cfg, selected_host=selected.host, max_hosts=max_hosts, max_ports=max_ports)
    if not port_records:
        if isinstance(jobs.get("naabu_discovery"), dict):
            return {
                "job": "nmap_enrichment",
                "state": job.get("state", "unknown"),
                "status": "waiting_on_dependency",
                "reason": "waiting_on_naabu_discovery",
                "dependency": "naabu_discovery",
                "target": selected.to_dict(),
                "host": selected.host,
            }
        return {
            "job": "nmap_enrichment",
            "state": job.get("state", "unknown"),
            "status": "skipped",
            "reason": "missing_naabu_output_or_no_ports_for_selected_host",
        }

    if inputs.get("require_saved_scope", False) and not ScopeValidator(program, strict=False).is_in_scope(selected.host):
        return {
            "job": "nmap_enrichment",
            "state": job.get("state", "unknown"),
            "status": "blocked",
            "reason": "selected_host_not_in_saved_scope",
            "host": selected.host,
        }

    ports = port_records[0]["ports"]
    context = {
        "naabu-discovered-ports": ",".join(str(port) for port in ports),
        "run-root": str(expand_path(job.get("outputs", {}).get("run_root", "<run-root>"))),
        "selected-host": selected.host,
    }
    command = [expand_pattern(str(part), context) for part in job.get("command_template") or ()]
    return {
        "job": "nmap_enrichment",
        "state": job.get("state", "unknown"),
        "status": "planned",
        "tool": job.get("tool", "nmap"),
        "mode": job.get("mode"),
        "target": selected.to_dict(),
        "host": selected.host,
        "ports": ports,
        "command": command,
        "outputs": job.get("outputs", {}),
    }


def naabu_rate(job: dict[str, Any]) -> int:
    rate_limit = job.get("rate_limit") if isinstance(job.get("rate_limit"), dict) else {}
    for key in ("pps", "desired_pps", "rps", "desired_rps"):
        if rate_limit.get(key) is None:
            continue
        try:
            return max(1, int(rate_limit[key]))
        except (TypeError, ValueError):
            pass
    return 100


def naabu_ports_value(job: dict[str, Any]) -> str:
    inputs = job.get("inputs") if isinstance(job.get("inputs"), dict) else {}
    value = str(inputs.get("ports") or inputs.get("port_range") or "-")
    if value.lower() in {"all", "full", "full_range", "full-range"}:
        return "-"
    return value


def build_naabu_plan(program: str, program_cfg: dict[str, Any], selected: TargetCandidate) -> dict[str, Any]:
    jobs = program_cfg.get("jobs") if isinstance(program_cfg.get("jobs"), dict) else {}
    job = jobs.get("naabu_discovery")
    if not isinstance(job, dict):
        return {"job": "naabu_discovery", "state": "absent", "status": "skipped", "reason": "job not configured"}

    nmap_job = jobs.get("nmap_enrichment") if isinstance(jobs.get("nmap_enrichment"), dict) else {}
    nmap_inputs = nmap_job.get("inputs") if isinstance(nmap_job.get("inputs"), dict) else {}
    if collect_naabu_ports(program_cfg, selected_host=selected.host, max_hosts=1, max_ports=1):
        return {
            "job": "naabu_discovery",
            "state": job.get("state", "unknown"),
            "status": "skipped",
            "reason": "service_inventory_exists_for_selected_host",
            "target": selected.to_dict(),
            "host": selected.host,
        }

    inputs = job.get("inputs") if isinstance(job.get("inputs"), dict) else {}
    require_scope = inputs.get("require_saved_scope", nmap_inputs.get("require_saved_scope", True))
    if require_scope and not ScopeValidator(program, strict=False).is_in_scope(selected.host):
        return {
            "job": "naabu_discovery",
            "state": job.get("state", "unknown"),
            "status": "blocked",
            "reason": "selected_host_not_in_saved_scope",
            "target": selected.to_dict(),
            "host": selected.host,
        }

    context = {
        "selected-host": selected.host,
        "naabu-ports": naabu_ports_value(job),
        "effective-rate": str(naabu_rate(job)),
        "run-root": str(expand_path(job.get("outputs", {}).get("run_root", "<run-root>"))),
    }
    template = job.get("command_template") or [
        "naabu",
        "-host",
        "<selected-host>",
        "-p",
        "<naabu-ports>",
        "-json",
        "-rate",
        "<effective-rate>",
        "-o",
        "<run-root>/raw/naabu.jsonl",
    ]
    command = [expand_pattern(str(part), context) for part in template]
    return {
        "job": "naabu_discovery",
        "state": job.get("state", "unknown"),
        "status": "planned",
        "tool": job.get("tool", "naabu"),
        "mode": job.get("mode"),
        "target": selected.to_dict(),
        "host": selected.host,
        "ports": context["naabu-ports"],
        "rate": naabu_rate(job),
        "command": command,
        "outputs": job.get("outputs", {}),
    }


def requested_http_rps(
    job_name: str,
    job: dict[str, Any],
    defaults: dict[str, Any],
    program_cfg: dict[str, Any],
) -> int:
    job_limit = job.get("rate_limit") if isinstance(job.get("rate_limit"), dict) else {}
    if job_limit.get("rps") is not None:
        return max(1, int(job_limit["rps"]))

    program_limit = program_cfg.get("rate_limit") if isinstance(program_cfg.get("rate_limit"), dict) else {}
    default_limit = defaults.get("rate_limit") if isinstance(defaults.get("rate_limit"), dict) else {}
    merged = {**default_limit, **program_limit}
    if job_name == "authenticated_parameter_mining":
        return max(1, int(merged.get("authenticated_rps") or 2))
    return max(1, int(merged.get("unauthenticated_rps") or 5))


def global_http_rps(defaults: dict[str, Any], program_cfg: dict[str, Any]) -> int:
    default_limit = defaults.get("rate_limit") if isinstance(defaults.get("rate_limit"), dict) else {}
    program_limit = program_cfg.get("rate_limit") if isinstance(program_cfg.get("rate_limit"), dict) else {}
    value = program_limit.get("global_http_rps", default_limit.get("global_http_rps", 15))
    return max(1, int(value))


def replace_command_rate(command: list[str], allocated_rps: int) -> tuple[list[str], bool]:
    updated = list(command)
    for index, part in enumerate(updated):
        if part == "<effective-rate>":
            updated[index] = str(allocated_rps)
            return updated, True
        if part in {"-rate", "--rate"} and index + 1 < len(updated):
            updated[index + 1] = str(allocated_rps)
            return updated, True
    return updated, False


def registrable_domain(host: str) -> str:
    parts = [part for part in host.lower().strip(".").split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)
    # Good enough for scheduler bucketing; this avoids an extra runtime
    # dependency while keeping common UK-style suffixes grouped sanely.
    if len(parts[-2]) <= 3 and parts[-1] in {"au", "br", "jp", "nz", "uk", "za"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def resolve_host_addresses(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    addresses = sorted({str(info[4][0]) for info in infos if info and info[4]})
    return addresses


def target_cdnish(job: dict[str, Any]) -> bool:
    tech_map = job.get("technology_map") if isinstance(job.get("technology_map"), dict) else {}
    wafs = tech_map.get("wafs") if isinstance(tech_map.get("wafs"), dict) else {}
    if any(str(name).lower() in CDN_WAF_NAMES for name in wafs):
        return True
    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    text = _json_text(target).lower()
    return any(marker in text for marker in ("cdn", "cloudflare", "akamai", "fastly", "cloudfront"))


def job_rate_bucket(
    job: dict[str, Any],
    *,
    host_counts: dict[str, int],
    shared_addresses: set[str],
) -> dict[str, Any] | None:
    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    host = str(target.get("host") or "").lower()
    if not host:
        return None
    domain = registrable_domain(host)
    addresses = list(job.get("resolved_addresses") or resolve_host_addresses(host))
    cdnish = target_cdnish(job)
    if host_counts.get(host, 0) > 1:
        return {
            "kind": "host",
            "key": host,
            "scope": f"host:{host}",
            "host": host,
            "domain": domain,
            "cdnish": cdnish,
            "resolved_addresses": addresses,
        }
    if cdnish and domain:
        return {
            "kind": "domain",
            "key": domain,
            "scope": f"domain:{domain}",
            "host": host,
            "domain": domain,
            "cdnish": cdnish,
            "resolved_addresses": addresses,
        }
    shared = sorted(address for address in addresses if address in shared_addresses)
    if shared:
        key = shared[0]
        return {
            "kind": "ip",
            "key": key,
            "scope": f"ip:{key}",
            "host": host,
            "domain": domain,
            "cdnish": cdnish,
            "resolved_addresses": addresses,
        }
    return {
        "kind": "host",
        "key": host,
        "scope": f"host:{host}",
        "host": host,
        "domain": domain,
        "cdnish": cdnish,
        "resolved_addresses": addresses,
    }


def apply_rate_budgets(data: dict[str, Any], program_cfg: dict[str, Any], jobs: list[dict[str, Any]]) -> None:
    defaults = data.get("defaults") if isinstance(data.get("defaults"), dict) else {}
    cap = global_http_rps(defaults, program_cfg)
    grouped: dict[str, list[dict[str, Any]]] = {}
    live_jobs: list[dict[str, Any]] = []

    for job in jobs:
        if job.get("job") not in LIVE_HTTP_JOBS or job.get("status") != "planned":
            continue
        target = job.get("target") if isinstance(job.get("target"), dict) else {}
        host = str(target.get("host") or "").lower()
        if not host:
            continue
        job["resolved_addresses"] = resolve_host_addresses(host)
        live_jobs.append(job)

    host_counts: dict[str, int] = {}
    address_counts: dict[str, int] = {}
    for job in live_jobs:
        target = job.get("target") if isinstance(job.get("target"), dict) else {}
        host = str(target.get("host") or "").lower()
        host_counts[host] = host_counts.get(host, 0) + 1
        if target_cdnish(job):
            continue
        for address in job.get("resolved_addresses") or ():
            address_counts[str(address)] = address_counts.get(str(address), 0) + 1
    shared_addresses = {address for address, count in address_counts.items() if count > 1}

    for job in live_jobs:
        bucket = job_rate_bucket(job, host_counts=host_counts, shared_addresses=shared_addresses)
        if not bucket:
            continue
        grouped.setdefault(bucket["scope"], []).append(job)
        job["rate_bucket"] = bucket

    for scope, scoped_jobs in grouped.items():
        split_cap = max(1, cap // len(scoped_jobs))
        for job in scoped_jobs:
            job_cfg = program_cfg.get("jobs", {}).get(job["job"], {})
            requested = requested_http_rps(job["job"], job_cfg, defaults, program_cfg)
            allocated = max(1, min(requested, split_cap))
            bucket = job.get("rate_bucket") if isinstance(job.get("rate_bucket"), dict) else {}
            budget = {
                "scope": scope,
                "bucket_kind": bucket.get("kind"),
                "bucket_key": bucket.get("key"),
                "shared_bucket_rps": cap,
                "global_host_rps": cap,
                "concurrent_live_http_jobs": len(scoped_jobs),
                "requested_rps": requested,
                "allocated_rps": allocated,
                "policy": "split_evenly_by_shared_bucket_then_cap_to_request",
                "cdnish": bool(bucket.get("cdnish")),
                "resolved_addresses": bucket.get("resolved_addresses", []),
            }
            job["rate_budget"] = budget
            if isinstance(job.get("command"), list):
                job["command"], rate_enforced = replace_command_rate(job["command"], allocated)
                job["rate_budget"]["command_rate_enforced"] = rate_enforced


def build_fuzz_plan(program_cfg: dict[str, Any], selected: TargetCandidate) -> dict[str, Any]:
    job = program_cfg.get("jobs", {}).get("juicy_target_fuzz", {})
    technology_map = build_technology_map(program_cfg, selected)
    context = {
        "selected-base-url": selected.base_url,
        "composed-wordlist": "<dry-run-composed-wordlist>",
        "run-root": "<ffuf-run-root>",
    }
    command = [expand_pattern(str(part), context) for part in job.get("command_template") or ()]
    return {
        "job": "juicy_target_fuzz",
        "job_instance_id": "juicy_target_fuzz",
        "state": job.get("state", "unknown"),
        "status": "planned",
        "target": selected.to_dict(),
        "wordlists": job.get("wordlists", {}),
        "technology_map": technology_map,
        "selected_tech_wordlist_groups": technology_map.get("selected_wordlist_groups", []),
        "command": command,
    }


def build_parameter_plan(program_cfg: dict[str, Any], selected: TargetCandidate) -> dict[str, Any]:
    job = program_cfg.get("jobs", {}).get("authenticated_parameter_mining", {})
    technology_map = build_technology_map(program_cfg, selected)
    context = {
        "endpoint-queue": str(expand_path(job.get("inputs", {}).get("endpoint_queue", "<endpoint-queue>"))),
        "run-root": "<arjun-run-root>",
    }
    command = [expand_pattern(str(part), context) for part in job.get("command_template") or ()]
    endpoint_queue = expand_path(job.get("inputs", {}).get("endpoint_queue", ""))
    return {
        "job": "authenticated_parameter_mining",
        "job_instance_id": "authenticated_parameter_mining",
        "state": job.get("state", "unknown"),
        "status": "planned" if endpoint_queue.is_file() else "needs_endpoint_queue",
        "target": selected.to_dict(),
        "technology_map": technology_map,
        "auth": job.get("auth", {}),
        "command": command,
    }


def with_target_instance(job: dict[str, Any], selected_count: int) -> dict[str, Any]:
    if selected_count <= 1:
        return job
    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    host = str(target.get("host") or "target")
    key = str(target.get("key") or host)
    updated = dict(job)
    updated["job_instance_id"] = f"{job.get('job')}_{safe_slug(key or host)}"
    return updated


def run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"cron-plan-{timestamp}-{uuid.uuid4().hex[:8]}"


def execution_run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"cron-run-{timestamp}-{uuid.uuid4().hex[:8]}"


def plan(data: dict[str, Any], program: str, *, write: bool = False) -> dict[str, Any]:
    errors = validate_config(data)
    if errors:
        raise ValueError("; ".join(errors))
    program_cfg = resolve_program(data, program)
    selected_targets = select_targets(program, program_cfg)
    selected = selected_targets[0]
    all_candidates = collect_target_candidates(program, program_cfg)
    candidates = [candidate.to_dict() for candidate in all_candidates[:25]]
    jobs: list[dict[str, Any]] = []
    naabu_plan = build_naabu_plan(program, program_cfg, selected)
    if naabu_plan.get("reason") != "job not configured":
        jobs.append(naabu_plan)
    jobs.append(build_nmap_plan(program, program_cfg, selected))
    for target in selected_targets:
        jobs.append(with_target_instance(build_fuzz_plan(program_cfg, target), len(selected_targets)))
        jobs.append(with_target_instance(build_parameter_plan(program_cfg, target), len(selected_targets)))
    apply_rate_budgets(data, program_cfg, jobs)
    payload = {
        "run_id": run_id(),
        "mode": "dry-run",
        "program": program,
        "selected_target": selected.to_dict(),
        "selected_targets": [target.to_dict() for target in selected_targets],
        "candidate_count": len(all_candidates),
        "top_candidates": candidates,
        "rate_policy": {
            "global_http_rps": global_http_rps(
                data.get("defaults") if isinstance(data.get("defaults"), dict) else {},
                program_cfg,
            ),
            "scope": "per-shared-backend-or-domain-bucket",
            "same_host_behavior": "split_evenly_across_concurrent_live_http_jobs",
            "independent_bucket_behavior": "each_bucket_uses_its_own_configured_cap",
        },
        "jobs": jobs,
    }
    if write:
        write_plan(program, payload, resolved_config=data)
    return payload


def default_cron_run_root(program: str, run_id_value: str) -> Path:
    return DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "cron" / "_runs" / run_id_value


def job_output_root(program: str, job: dict[str, Any], run_id_value: str) -> Path:
    outputs = job.get("outputs") if isinstance(job.get("outputs"), dict) else {}
    if outputs.get("run_root"):
        return render_runtime_path(str(outputs["run_root"]), run_id_value)
    return default_cron_run_root(program, run_id_value) / "outputs" / str(job.get("job_instance_id") or job.get("job", "job"))


def command_has_unresolved_placeholders(command: list[str]) -> bool:
    return any(bool(re.search(r"<[^>]+>", str(part))) for part in command)


def render_command(command: list[str], run_root: Path, run_id_value: str) -> list[str]:
    context = {
        "run-root": str(run_root),
        "ffuf-run-root": str(run_root),
        "arjun-run-root": str(run_root),
        "YYYY-MM-DD": today_utc(),
        "run-id": run_id_value,
    }
    return [expand_pattern(str(part), context) for part in command]


def command_text(command: list[str]) -> str:
    return " ".join(shlex_quote(part) for part in command)


def shlex_quote(value: str) -> str:
    if re.match(r"^[A-Za-z0-9_./:=,@%+-]+$", value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def default_tmux_session(program: str) -> str:
    return safe_slug(f"{program}-cron-recon")


def render_template(value: str, context: dict[str, str]) -> str:
    rendered = value
    for key, replacement in context.items():
        rendered = rendered.replace(f"{{{key}}}", replacement)
    return rendered


def runtime_config(data: dict[str, Any], program_cfg: dict[str, Any]) -> dict[str, Any]:
    runtime = data.get("runtime") if isinstance(data.get("runtime"), dict) else {}
    program_runtime = program_cfg.get("runtime") if isinstance(program_cfg.get("runtime"), dict) else {}
    return deep_merge(runtime, program_runtime)


def runtime_tmux_enabled(data: dict[str, Any], program_cfg: dict[str, Any], override: bool | None) -> bool:
    if override is not None:
        return override
    runtime = runtime_config(data, program_cfg)
    tmux_cfg = runtime.get("tmux") if isinstance(runtime.get("tmux"), dict) else {}
    return bool(tmux_cfg.get("enabled") or str(runtime.get("mode") or "").lower() == "tmux")


def runtime_tmux_session(data: dict[str, Any], program: str, program_cfg: dict[str, Any], override: str | None) -> str:
    if override:
        return safe_slug(override)
    runtime = runtime_config(data, program_cfg)
    tmux_cfg = runtime.get("tmux") if isinstance(runtime.get("tmux"), dict) else {}
    template = str(tmux_cfg.get("session_template") or "{program}-cron-recon")
    return safe_slug(render_template(template, {"program": program}))


def tmux_shell_command(job_name: str, run_root: Path, command: list[str]) -> str:
    log_dir = run_root / "logs"
    return (
        f"cd {shlex_quote(str(run_root))} && "
        f"printf '[cron] {job_name} started at %s\\n' \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" | tee -a {shlex_quote(str(log_dir / 'tmux.log'))}; "
        f"{command_text(command)} "
        f"> {shlex_quote(str(log_dir / 'stdout.txt'))} "
        f"2> {shlex_quote(str(log_dir / 'stderr.txt'))}; "
        f"printf '[cron] {job_name} exited with %s at %s\\n' \"$?\" \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" | tee -a {shlex_quote(str(log_dir / 'tmux.log'))}; "
        "exec bash"
    )


def render_tmux_invocations(session: str, panes: list[dict[str, Any]]) -> list[list[str]]:
    if not panes:
        return []
    invocations: list[list[str]] = [["tmux", "new-session", "-d", "-s", session, "-n", "cron", panes[0]["shell"]]]
    for pane in panes[1:]:
        invocations.append(["tmux", "split-window", "-t", f"{session}:0", "-v", pane["shell"]])
        invocations.append(["tmux", "select-layout", "-t", f"{session}:0", "tiled"])
    return invocations


def launch_tmux_session(session: str, panes: list[dict[str, Any]]) -> dict[str, Any]:
    if not panes:
        return {"status": "skipped", "reason": "no_tmux_panes"}
    if shutil.which("tmux") is None:
        return {"status": "blocked", "reason": "tmux_not_found", "session": session}
    invocations = render_tmux_invocations(session, panes)
    for invocation in invocations:
        proc = subprocess.run(invocation, text=True, capture_output=True, check=False)
        if proc.returncode != 0:
            return {
                "status": "blocked",
                "reason": "tmux_command_failed",
                "session": session,
                "command": invocation,
                "stderr": proc.stderr,
            }
    return {"status": "started", "session": session, "pane_count": len(panes)}


def _target_wordlist_fallback(job: dict[str, Any]) -> list[str]:
    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    host = str(target.get("host") or "")
    parsed = urlparse(str(target.get("base_url") or ""))
    candidates = ["api", "admin", "assets", "static", "login"]
    candidates.extend(part for part in host.split(".") if part and part not in {"www", "com", "net", "org"})
    candidates.extend(part for part in parsed.path.strip("/").split("/") if part)
    return list(dict.fromkeys(candidates))


def _configured_fuzz_wordlist_paths(
    wordlists: dict[str, Any],
    selected_tech_groups: list[str] | tuple[str, ...] | set[str] | None = None,
) -> list[str]:
    configured_paths: list[str] = [str(raw_path) for raw_path in wordlists.get("include") or ()]
    tech_wordlists = wordlists.get("tech_wordlists")
    if isinstance(tech_wordlists, dict):
        groups = list(selected_tech_groups) if selected_tech_groups is not None else list(tech_wordlists.keys())
        for group in groups:
            group_paths = tech_wordlists.get(str(group)) or ()
            configured_paths.extend(str(raw_path) for raw_path in group_paths or ())
    return configured_paths


def materialize_fuzz_wordlist(job: dict[str, Any], root: Path) -> dict[str, Any]:
    wordlists = job.get("wordlists") if isinstance(job.get("wordlists"), dict) else {}
    batch_dir = root / "_batches"
    batch_dir.mkdir(parents=True, exist_ok=True)
    composed = batch_dir / "composed-wordlist.txt"
    seen: set[str] = set()
    candidates: list[str] = []
    sources: list[dict[str, Any]] = []
    missing: list[str] = []

    selected_groups = job.get("selected_tech_wordlist_groups")
    for raw_path in _configured_fuzz_wordlist_paths(
        wordlists,
        selected_groups if isinstance(selected_groups, list) else None,
    ):
        path = expand_path(str(raw_path))
        if not path.is_file():
            missing.append(str(path))
            continue
        before = len(candidates)
        for value in read_lines(path):
            if value not in seen:
                seen.add(value)
                candidates.append(value)
        sources.append({"path": str(path), "candidates_added": len(candidates) - before})

    if not candidates:
        for value in _target_wordlist_fallback(job):
            if value not in seen:
                seen.add(value)
                candidates.append(value)
        sources.append({"path": "target-derived-fallback", "candidates_added": len(candidates)})

    composed.write_text("\n".join(candidates) + ("\n" if candidates else ""), encoding="utf-8")
    return {
        "path": str(composed),
        "candidate_count": len(candidates),
        "source_count": len(sources),
        "sources": sources,
        "missing": missing,
    }


def prepare_job_capsule(program: str, job: dict[str, Any], run_id_value: str) -> dict[str, Any]:
    root = job_output_root(program, job, run_id_value)
    raw = root / "raw"
    parsed = root / "parsed"
    normalized = root / "normalized"
    logs = root / "logs"
    for path in (raw, parsed, normalized, logs):
        path.mkdir(parents=True, exist_ok=True)

    materialized_inputs: dict[str, Any] = {}
    command_parts = [str(part) for part in job.get("command") or ()]
    if job.get("job") == "juicy_target_fuzz":
        wordlist = materialize_fuzz_wordlist(job, root)
        materialized_inputs["wordlist"] = wordlist
        command_parts = [
            str(part)
            .replace("<composed-wordlist>", wordlist["path"])
            .replace("<dry-run-composed-wordlist>", wordlist["path"])
            for part in command_parts
        ]

    command = render_command(command_parts, root, run_id_value)
    (root / "command.txt").write_text(command_text(command) + "\n", encoding="utf-8")
    manifest = {
        "run_id": run_id_value,
        "job": job.get("job"),
        "tool": job.get("tool") or infer_tool(command),
        "state": job.get("state"),
        "planned_status": job.get("status"),
        "target": job.get("target", {}),
        "rate_budget": job.get("rate_budget"),
        "command": command,
        "paths": {
            "root": str(root),
            "raw": str(raw),
            "parsed": str(parsed),
            "normalized": str(normalized),
            "logs": str(logs),
        },
        "status": "prepared",
        "started_at": None,
        "finished_at": None,
        "exit_code": None,
    }
    if materialized_inputs:
        manifest["materialized_inputs"] = materialized_inputs
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (root / "summary.md").write_text(
        "\n".join(
            [
                f"# {job.get('job')} Run Capsule",
                "",
                f"- Status: `prepared`",
                f"- Planned status: `{job.get('status')}`",
                f"- Command: `{command_text(command)}`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return {"root": root, "manifest": manifest, "command": command}


def infer_tool(command: list[str]) -> str | None:
    if not command:
        return None
    return Path(command[0]).name


def _append_deduped_lines(path: Path, lines: list[str]) -> dict[str, int]:
    try:
        from agents.recon_store import append_deduped_lines

        return append_deduped_lines(path, lines)
    except Exception:
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = set(read_lines(path)) if path.is_file() else set()
        new_lines = [line for line in lines if line and line not in existing]
        if new_lines:
            with path.open("a", encoding="utf-8") as handle:
                for line in new_lines:
                    handle.write(line + "\n")
        return {"read": len(lines), "new": len(new_lines)}


def _append_deduped_jsonl(path: Path, rows: list[dict[str, Any]], *, key_fields: list[str]) -> dict[str, int]:
    try:
        from agents.recon_store import append_deduped_jsonl

        return append_deduped_jsonl(path, rows, key_fields=key_fields)
    except Exception:
        path.parent.mkdir(parents=True, exist_ok=True)
        keys = [str(field) for field in key_fields]
        existing: set[tuple[str, ...]] = set()
        if path.is_file():
            for line in read_lines(path):
                with contextlib.suppress(json.JSONDecodeError):
                    payload = json.loads(line)
                    if isinstance(payload, dict):
                        existing.add(tuple(str(payload.get(field) or "") for field in keys))
        new_rows: list[dict[str, Any]] = []
        for row in rows:
            key = tuple(str(row.get(field) or "") for field in keys)
            if key in existing:
                continue
            existing.add(key)
            new_rows.append(row)
        if new_rows:
            with path.open("a", encoding="utf-8") as handle:
                for row in new_rows:
                    handle.write(json.dumps(row, sort_keys=True) + "\n")
        return {"read": len(rows), "new": len(new_rows)}


def normalize_naabu_output(
    program: str,
    job: dict[str, Any],
    root: Path,
    run_id_value: str,
    manifest: dict[str, Any],
) -> None:
    raw_path = root / "raw" / "naabu.jsonl"
    if not raw_path.is_file():
        return

    observed_at = utc_now()
    rows: list[dict[str, Any]] = []
    lines: list[str] = []
    seen: set[tuple[str, int]] = set()
    for line in read_lines(raw_path):
        parsed = parse_port_line(line)
        if not parsed:
            continue
        host, port = parsed
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "program": program,
                "host": host,
                "port": port,
                "source": "naabu",
                "run_id": run_id_value,
                "observed_at": observed_at,
            }
        )
        lines.append(f"{host}:{port}")

    normalized_jsonl = root / "normalized" / "ports.jsonl"
    normalized_txt = root / "normalized" / "ports.txt"
    normalized_jsonl.parent.mkdir(parents=True, exist_ok=True)
    normalized_jsonl.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    normalized_txt.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    outputs = job.get("outputs") if isinstance(job.get("outputs"), dict) else {}
    global_jsonl = outputs.get("global_ports_jsonl") or outputs.get("services_ports_jsonl")
    global_txt = outputs.get("global_ports_txt") or outputs.get("services_ports_txt")
    append_summary: dict[str, Any] = {"normalized_count": len(rows)}
    if global_jsonl:
        append_summary["global_ports_jsonl"] = _append_deduped_jsonl(
            expand_path(str(global_jsonl)),
            rows,
            key_fields=["host", "port"],
        )
    if global_txt:
        append_summary["global_ports_txt"] = _append_deduped_lines(expand_path(str(global_txt)), lines)
    manifest["normalized_outputs"] = {
        "ports_jsonl": str(normalized_jsonl),
        "ports_txt": str(normalized_txt),
        **append_summary,
    }


def parent_state_reason(data: dict[str, Any], program: str, program_cfg: dict[str, Any]) -> str | None:
    platform_name = str(program_cfg.get("platform") or "")
    platforms = data.get("platforms") if isinstance(data.get("platforms"), dict) else {}
    platform_cfg = platforms.get(platform_name) if isinstance(platforms.get(platform_name), dict) else {}
    platform_state = str(platform_cfg.get("state") or "active").lower()
    program_state = str(program_cfg.get("state") or "active").lower()
    if platform_state != "active":
        return f"platform_{platform_name or 'unknown'}_{platform_state or 'unknown'}"
    if program_state != "active":
        return f"program_{program}_{program_state or 'unknown'}"
    return None


def _target_in_scope(program: str, host: str) -> bool:
    """Check whether *host* is in the saved scope for *program*.

    Uses ScopeValidator in non-strict mode so partial wildcard matches
    (e.g. ``*.example.com``) still resolve.
    """
    if not host:
        return False
    try:
        validator = ScopeValidator(program, strict=False)
        if validator.is_in_scope(host):
            return True
        if validator.is_in_scope(f"https://{host}"):
            return True
    except Exception:
        pass
    return False


def execution_decision(
    job: dict[str, Any],
    *,
    execute: bool,
    approve_manual: bool,
    approved_jobs: set[str] | None = None,
    parent_block_reason: str | None = None,
    program: str = "",
) -> tuple[bool, str]:
    """Decide whether a job should execute.

    When approve_manual is True and either the job is in approved_jobs
    OR the target is in the saved scope, the manual-approval gate is
    bypassed (auto-allowlist).
    """
    job_name = str(job.get("job") or "")
    if parent_block_reason:
        return False, parent_block_reason
    if job.get("job") not in EXECUTABLE_PLANNED_JOBS:
        return False, "job_family_not_executable_by_orchestrator"
    if job.get("status") != "planned":
        return False, f"planned_status_{job.get('status')}"
    if job_name in LIVE_HTTP_JOBS and not job.get("rate_budget", {}).get("command_rate_enforced"):
        return False, "live_http_rate_not_enforced_in_command"
    if not execute:
        return False, "execute_flag_not_set"
    state = str(job.get("state") or "").lower()
    if state == "active":
        return True, "active_execute_allowed"
    if state == "manual_review_required" and approve_manual and approved_jobs and job_name in approved_jobs:
        return True, "manual_review_approved"
    if state == "manual_review_required" and approve_manual:
        # Auto-allowlist: if the target is in scope, bypass the manual gate.
        target = job.get("target") if isinstance(job.get("target"), dict) else {}
        host = str(target.get("host") or "")
        if _target_in_scope(program, host):
            return True, "manual_review_approved_by_scope"
        return False, "manual_approval_requires_job_allowlist"
    return False, f"state_{state or 'unknown'}_not_approved"


def lock_scope(job: dict[str, Any]) -> str:
    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    host = str(target.get("host") or job.get("host") or "unknown").lower()
    job_name = str(job.get("job") or "job")
    if job_name in LIVE_HTTP_JOBS:
        return f"host-{host}"
    return f"{job_name}-{host}"


@contextlib.contextmanager
def job_lock(program: str, job: dict[str, Any]):
    locks_dir = DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "tools" / ".locks"
    locks_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", lock_scope(job)).strip("._") or "lock"
    path = locks_dir / f"{safe_name}.lock"
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        handle.seek(0)
        handle.truncate()
        handle.write(json.dumps({"pid": os.getpid(), "job": job.get("job"), "locked_at": utc_now()}) + "\n")
        handle.flush()
        try:
            yield str(path)
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def cron_run_lock(program: str):
    locks_dir = DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "cron" / ".locks"
    locks_dir.mkdir(parents=True, exist_ok=True)
    path = locks_dir / "orchestrator.lock"
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        handle.seek(0)
        handle.truncate()
        handle.write(json.dumps({"pid": os.getpid(), "program": program, "locked_at": utc_now()}) + "\n")
        handle.flush()
        try:
            yield str(path)
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _wordlist_size(manifest: dict[str, Any]) -> int:
    """Extract the expected request count.

    Tries the manifest's materialized_inputs first, then falls back to
    counting lines in any composed-wordlist.txt in the batch directory."""
    materialized = manifest.get("materialized_inputs") if isinstance(manifest.get("materialized_inputs"), dict) else {}
    wordlist_info = materialized.get("wordlist", {})
    if isinstance(wordlist_info, dict):
        try:
            count = int(wordlist_info.get("candidate_count") or 0)
        except (TypeError, ValueError):
            count = 0
        if count:
            return count
    paths = manifest.get("paths") if isinstance(manifest.get("paths"), dict) else {}
    batch_file = Path(str(paths.get("root", ""))) / "_batches" / "composed-wordlist.txt"
    if batch_file.is_file():
        try:
            return sum(1 for _ in batch_file.open("rb"))
        except OSError:
            pass
    return 0


def _compute_timeout(
    rate_limit: dict[str, Any],
    payload: dict[str, Any],
    program_cfg: dict[str, Any],
) -> int:
    """Compute per-run timeout from wordlist size and rate.

    Falls back to the config's timeout_seconds when no wordlist info is
    available. Uses wordlist_size / rate * margin, with an optional ceiling
    only when timeout_seconds_max is explicitly set.
    """
    floor = int(rate_limit.get("timeout_seconds") or 300)
    ceiling_raw = rate_limit.get("timeout_seconds_max")
    ceiling = int(ceiling_raw) if ceiling_raw not in (None, "", False) else None
    margin = float(rate_limit.get("timeout_margin") or 1.5)

    # Find the effective rate for this run
    effective_rate: float | None = None
    for job in payload.get("jobs") or ():
        budget = job.get("rate_budget") if isinstance(job.get("rate_budget"), dict) else {}
        rps = float(budget.get("allocated_rps") or 0)
        if rps > 0:
            effective_rate = rps
            break
    if effective_rate is None:
        effective_rate = float(rate_limit.get("unauthenticated_rps") or 5)

    # Estimate wordlist size from the fuzz job's wordlists config
    seen_words: set[str] = set()
    for job in payload.get("jobs") or ():
        if job.get("job") != "juicy_target_fuzz":
            continue
        wordlists = job.get("wordlists") if isinstance(job.get("wordlists"), dict) else {}
        selected_groups = job.get("selected_tech_wordlist_groups")
        for wl_path in _configured_fuzz_wordlist_paths(
            wordlists,
            selected_groups if isinstance(selected_groups, list) else None,
        ):
            wl = Path(str(wl_path)).expanduser()
            if wl.is_file():
                seen_words.update(read_lines(wl))
        break

    wordlist_count = len(seen_words)
    if wordlist_count > 0 and effective_rate > 0:
        estimated = max(floor, math.ceil(wordlist_count / effective_rate * margin))
        return min(ceiling, estimated) if ceiling is not None else estimated
    return floor


def _read_stderr(root: Path) -> str:
    """Read stderr log if it exists."""
    stderr_path = root / "logs" / "stderr.txt"
    if stderr_path.is_file():
        return stderr_path.read_text(encoding="utf-8", errors="ignore")
    return ""


def _check_cf_block(
    program: str,
    job: dict[str, Any],
    root: Path,
    manifest: dict[str, Any],
) -> None:
    """Run Cloudflare / WAF block detection on ffuf JSON output.

    When a block is detected the classification is written to the manifest
    and recorded to the program's cf_blocked.jsonl / cf_blocked_hosts.txt.
    """
    try:
        from agents.cloudflare_detector import classify, record as cf_record
    except Exception:
        return

    ffuf_json = root / "raw" / "ffuf.json"
    if not ffuf_json.is_file():
        return

    try:
        results = json.loads(ffuf_json.read_text(encoding="utf-8"))
        rows = results.get("results") if isinstance(results, dict) else results
        if not isinstance(rows, list) or not rows:
            return
    except (json.JSONDecodeError, OSError):
        return

    cf = classify(
        rows,
        expected_requests=_wordlist_size(manifest),
        stderr_text=_read_stderr(root),
    )
    if cf is None:
        return

    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    host = str(target.get("host") or "unknown")
    manifest["cloudflare_block"] = cf

    try:
        cf_record(program, host, cf, target_url=str(target.get("base_url") or ""))
    except Exception:
        pass


def execute_job(
    program: str,
    job: dict[str, Any],
    run_id_value: str,
    *,
    execute: bool,
    approve_manual: bool,
    approved_jobs: set[str] | None,
    parent_block_reason: str | None,
    timeout_seconds: int,
    launch_mode: str = "subprocess",
    tmux_panes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    capsule = prepare_job_capsule(program, job, run_id_value)
    manifest = capsule["manifest"]
    command = capsule["command"]
    root = capsule["root"]
    allowed, reason = execution_decision(
        job,
        execute=execute,
        approve_manual=approve_manual,
        approved_jobs=approved_jobs,
        parent_block_reason=parent_block_reason,
        program=program,
    )
    manifest["execution_decision"] = reason
    manifest["timeout_seconds"] = timeout_seconds

    if not allowed:
        if reason == "execute_flag_not_set" or reason.startswith("planned_status_"):
            manifest["status"] = "prepared_not_executed"
        else:
            manifest["status"] = "blocked"
            manifest["block_reason"] = reason
    elif command_has_unresolved_placeholders(command):
        manifest["status"] = "blocked"
        manifest["block_reason"] = "unresolved_command_placeholders"
    elif launch_mode == "tmux":
        manifest["status"] = "tmux_queued"
        manifest["tmux"] = {"queued_at": utc_now()}
        if tmux_panes is not None:
            tmux_panes.append(
                {
                    "job": job.get("job"),
                    "job_instance_id": job.get("job_instance_id") or job.get("job"),
                    "run_root": str(root),
                    "command": command,
                    "shell": tmux_shell_command(str(job.get("job_instance_id") or job.get("job")), root, command),
                }
            )
    else:
        manifest["status"] = "running"
        manifest["started_at"] = utc_now()
        try:
            with job_lock(program, job) as lock_path:
                manifest["lock_path"] = lock_path
                proc = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    timeout=timeout_seconds,
                    check=False,
                )
            (root / "logs" / "stdout.txt").write_text(proc.stdout, encoding="utf-8")
            (root / "logs" / "stderr.txt").write_text(proc.stderr, encoding="utf-8")
            manifest["exit_code"] = proc.returncode
            manifest["status"] = "completed" if proc.returncode == 0 else "failed"
        except BlockingIOError:
            manifest["status"] = "blocked"
            manifest["block_reason"] = "run_lock_already_held"
        except subprocess.TimeoutExpired as exc:
            manifest["status"] = "failed"
            manifest["block_reason"] = "timeout"
            manifest["timeout_seconds"] = timeout_seconds
            (root / "logs" / "stdout.txt").write_text(exc.stdout or "", encoding="utf-8")
            (root / "logs" / "stderr.txt").write_text(exc.stderr or "", encoding="utf-8")
        except OSError as exc:
            manifest["status"] = "blocked"
            manifest["block_reason"] = "subprocess_start_failed"
            manifest["error"] = str(exc)
            (root / "logs" / "stderr.txt").write_text(str(exc) + "\n", encoding="utf-8")

    manifest["finished_at"] = utc_now()

    if job.get("job") == "juicy_target_fuzz" and manifest.get("status") in ("completed", "failed"):
        _check_cf_block(program, job, root, manifest)
    if job.get("job") == "naabu_discovery" and manifest.get("status") == "completed":
        normalize_naabu_output(program, job, root, run_id_value, manifest)

    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (root / "summary.md").write_text(
        "\n".join(
            [
                f"# {job.get('job')} Run Capsule",
                "",
                f"- Status: `{manifest['status']}`",
                f"- Decision: `{manifest.get('execution_decision')}`",
                f"- Root: `{root}`",
                f"- Command: `{command_text(command)}`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result = dict(job)
    result["run_root"] = str(root)
    result["manifest_path"] = str(root / "manifest.json")
    result["execution_status"] = manifest["status"]
    result["execution_decision"] = manifest.get("execution_decision")
    if manifest.get("block_reason"):
        result["block_reason"] = manifest["block_reason"]
    return result


def run(
    data: dict[str, Any],
    program: str,
    *,
    execute: bool = False,
    approve_manual: bool = False,
    approved_jobs: set[str] | None = None,
    write: bool = True,
    tmux: bool | None = None,
    tmux_session: str | None = None,
) -> dict[str, Any]:
    payload = plan(data, program, write=False)
    run_id_value = execution_run_id()
    program_cfg = resolve_program(data, program)
    defaults = data.get("defaults") if isinstance(data.get("defaults"), dict) else {}
    rate_limit = defaults.get("rate_limit") if isinstance(defaults.get("rate_limit"), dict) else {}
    timeout_seconds = _compute_timeout(rate_limit, payload, program_cfg)
    parent_block = parent_state_reason(data, program, program_cfg)
    tmux_panes: list[dict[str, Any]] = []
    tmux_enabled = runtime_tmux_enabled(data, program_cfg, tmux)
    launch_mode = "tmux" if tmux_enabled and execute else "subprocess"
    selected_payload = payload.get("selected_target") if isinstance(payload.get("selected_target"), dict) else {}
    selected_candidate = TargetCandidate(
        key=str(selected_payload.get("key") or "selected"),
        base_url=str(selected_payload.get("base_url") or ""),
        host=str(selected_payload.get("host") or ""),
        source=str(selected_payload.get("source") or "selected_target"),
        score=int(selected_payload.get("score") or 0),
        reasons=list(selected_payload.get("reasons") or []),
    )
    try:
        with cron_run_lock(program) as run_lock_path:
            results = []
            planned_jobs = list(payload["jobs"])
            for index, job in enumerate(planned_jobs):
                result = execute_job(
                    program,
                    job,
                    run_id_value,
                    execute=execute,
                    approve_manual=approve_manual,
                    approved_jobs=approved_jobs,
                    parent_block_reason=parent_block,
                    timeout_seconds=timeout_seconds,
                    launch_mode=launch_mode,
                    tmux_panes=tmux_panes,
                )
                results.append(result)
                if (
                    launch_mode == "subprocess"
                    and result.get("job") == "naabu_discovery"
                    and result.get("execution_status") == "completed"
                ):
                    for later_index in range(index + 1, len(planned_jobs)):
                        later = planned_jobs[later_index]
                        if later.get("job") == "nmap_enrichment" and later.get("status") == "waiting_on_dependency":
                            planned_jobs[later_index] = build_nmap_plan(program, program_cfg, selected_candidate)
    except BlockingIOError:
        run_lock_path = None
        results = []
        for job in payload["jobs"]:
            result = dict(job)
            result["execution_status"] = "blocked"
            result["execution_decision"] = "cron_run_lock_already_held"
            result["block_reason"] = "cron_run_lock_already_held"
            results.append(result)
    payload.update(
        {
            "run_id": run_id_value,
            "mode": "tmux" if launch_mode == "tmux" else ("execute" if execute else "prepare-only"),
            "run_lock_path": run_lock_path,
            "jobs": results,
        }
    )
    if launch_mode == "tmux":
        session = runtime_tmux_session(data, program, program_cfg, tmux_session)
        payload["tmux"] = {
            "session": session,
            "attach_command": f"tmux attach -t {session}",
            "panes": tmux_panes,
            "invocations": render_tmux_invocations(session, tmux_panes),
        }
        launch_result = launch_tmux_session(session, tmux_panes)
        payload["tmux"]["launch"] = launch_result
        if launch_result.get("status") == "blocked":
            payload["status"] = "blocked"
            payload["block_reason"] = launch_result.get("reason")
    if run_lock_path is None:
        payload["status"] = "blocked"
        payload["block_reason"] = "cron_run_lock_already_held"
    if write:
        write_plan(program, payload, resolved_config=data)
    return payload


def write_plan(program: str, payload: dict[str, Any], *, resolved_config: dict[str, Any] | None = None) -> None:
    root = DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "cron" / "_runs" / payload["run_id"] / "_meta"
    root.mkdir(parents=True, exist_ok=True)
    plan_path = root / "resolved_plan.json"
    if resolved_config is not None:
        config_path = root / "resolved_config.yaml"
        config_path.write_text(yaml.safe_dump(resolved_config, sort_keys=False), encoding="utf-8")
        payload["resolved_config_path"] = str(config_path)
    if isinstance(payload.get("tmux"), dict):
        tmux_path = root / "tmux_manifest.json"
        tmux_path.write_text(json.dumps(payload["tmux"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
        payload["tmux_manifest_path"] = str(tmux_path)
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = [
        f"# Cron Plan Dry Run",
        "",
        f"- Program: `{program}`",
        f"- Run id: `{payload['run_id']}`",
        f"- Selected target: `{payload['selected_target']['base_url']}`",
        f"- Candidate count: `{payload['candidate_count']}`",
        "",
        "## Jobs",
    ]
    for job in payload["jobs"]:
        summary.append(f"- `{job['job']}`: {job['status']}")
        if job.get("reason"):
            summary.append(f"  - reason: {job['reason']}")
    (root.parent / "SUMMARY.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    payload["plan_path"] = str(plan_path)
    payload["summary_path"] = str(root.parent / "SUMMARY.md")


def cmd_validate(args: argparse.Namespace) -> int:
    data = load_scheduler_config(args.program, config_path=args.config, config_root=args.config_root)
    errors = validate_config(data)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("config ok")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    data = load_scheduler_config(args.program, config_path=args.config, config_root=args.config_root)
    payload = plan(data, args.program, write=args.write)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    data = load_scheduler_config(args.program, config_path=args.config, config_root=args.config_root)
    payload = run(
        data,
        args.program,
        execute=args.run or args.execute,
        approve_manual=args.approve_manual,
        approved_jobs=set(args.job or ()),
        write=True,
        tmux=True if args.tmux else None,
        tmux_session=args.tmux_session,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_tmux_launch(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).expanduser()
    if not manifest_path.is_file():
        print(f"ERROR: tmux manifest not found: {manifest_path}", file=sys.stderr)
        return 1
    try:
        manifest = load_config(manifest_path)
    except (OSError, yaml.YAMLError, ValueError) as exc:
        print(f"ERROR: could not read tmux manifest: {exc}", file=sys.stderr)
        return 1
    if not isinstance(manifest.get("panes"), list):
        print("ERROR: tmux manifest must contain panes", file=sys.stderr)
        return 1
    session = safe_slug(args.session or str(manifest.get("session") or "cron-recon"))
    result = launch_tmux_session(session, manifest["panes"])
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BBH cron orchestrator dry-run planner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="validate scheduler config")
    validate_parser.add_argument("program", nargs="?")
    validate_parser.add_argument("--config")
    validate_parser.add_argument("--config-root", help="cron config root; defaults to agents/config/cron")
    validate_parser.set_defaults(func=cmd_validate)

    plan_parser = subparsers.add_parser("plan", help="write or print dry-run plan")
    plan_parser.add_argument("program")
    plan_parser.add_argument("--config")
    plan_parser.add_argument("--config-root", help="cron config root; defaults to agents/config/cron")
    plan_parser.add_argument("--write", action="store_true", help="write plan capsule under Shared web bounty storage")
    plan_parser.set_defaults(func=cmd_plan)

    run_parser = subparsers.add_parser("run", help="manually invoke the scheduler pipeline for one program")
    run_parser.add_argument("program")
    run_parser.add_argument("--config")
    run_parser.add_argument("--config-root", help="cron config root; defaults to agents/config/cron")
    run_parser.add_argument(
        "--run",
        action="store_true",
        help="execute jobs that pass state, scope, rate, lock, and manual-approval gates",
    )
    run_parser.add_argument(
        "--execute",
        action="store_true",
        help="deprecated alias for --run",
    )
    run_parser.add_argument(
        "--approve-manual",
        action="store_true",
        help="allow manual_review_required jobs to execute when --run is also set",
    )
    run_parser.add_argument(
        "--job",
        action="append",
        choices=sorted(EXECUTABLE_PLANNED_JOBS),
        help="allow execution for a specific job name; required for manual_review_required jobs",
    )
    run_parser.add_argument(
        "--tmux",
        action="store_true",
        help="queue executable scanner jobs in an inspectable tmux session instead of blocking in subprocess.run",
    )
    run_parser.add_argument(
        "--tmux-session",
        help="tmux session name for --tmux; defaults to <program>-cron-recon",
    )
    run_parser.set_defaults(func=cmd_run)

    tmux_parser = subparsers.add_parser("tmux-launch", help="launch a generated tmux manifest")
    tmux_parser.add_argument("manifest")
    tmux_parser.add_argument("--session", help="override tmux session name from the manifest")
    tmux_parser.set_defaults(func=cmd_tmux_launch)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
