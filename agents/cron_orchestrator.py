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
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sqlite3
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

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
QUEUE_TERMINAL_STATES = {"completed", "failed", "blocked", "cancelled", "stale"}
JOB_RUN_TYPES = {
    "authenticated_parameter_mining": "parameter_mining",
    "juicy_target_fuzz": "fuzz",
    "naabu_discovery": "port_discovery",
    "nmap_enrichment": "nmap",
    "parameter_mining": "parameter_mining",
    "recon_refresh": "recon_refresh",
    "tech_fingerprint": "tech_fingerprint",
}

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


def expand_program_placeholders(value: Any, program: str) -> Any:
    """Render program-local path/value placeholders without altering config keys."""
    if isinstance(value, str):
        return value.replace("<program>", program)
    if isinstance(value, list):
        return [expand_program_placeholders(item, program) for item in value]
    if isinstance(value, dict):
        return {key: expand_program_placeholders(item, program) for key, item in value.items()}
    return value


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
        return expand_program_placeholders(data, program)

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
        selection = program_cfg.get("target_selection") if isinstance(program_cfg.get("target_selection"), dict) else {}
        review = selection.get("agent_review") if isinstance(selection.get("agent_review"), dict) else {}
        if review.get("enabled"):
            if review.get("mode") != "structured_response_file":
                errors.append(f"program {program}: agent_review mode must be structured_response_file")
            if not isinstance(review.get("response_file"), str) or not str(review.get("response_file")).strip():
                errors.append(f"program {program}: enabled agent_review requires response_file")
            if not isinstance(review.get("require_reason", False), bool):
                errors.append(f"program {program}: agent_review require_reason must be boolean")
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


def collect_job_target_candidates(program: str, program_cfg: dict[str, Any], source_paths: list[str]) -> list[TargetCandidate]:
    """Build scoped targets only from one job family's evidence sources."""
    candidates: dict[str, TargetCandidate] = {}
    for raw_path in source_paths:
        path = expand_path(raw_path)
        if not path.is_file():
            continue
        for line in read_lines(path):
            for url in extract_urls(line):
                add_or_merge(candidates, candidate_from_url(url, key_prefix="job", source=str(path), collapse_to_origin=True))
    return sorted(
        scope_filter_candidates(program, program_cfg, list(candidates.values())),
        key=lambda item: (item.host, 0 if item.base_url.startswith("https://") else 1, item.base_url),
    )


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
    exclude_ports: set[int] | None = None,
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
    excluded = exclude_ports or set()
    result: list[dict[str, Any]] = []
    for host, discovered in records.items():
        ports = sorted(port for port in discovered if port not in excluded)[:max_ports]
        if ports:
            result.append({"host": host, "ports": ports})
    return sorted(result, key=lambda record: (-len(record["ports"]), record["host"]))[:max_hosts]


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
        host = str(payload.get("input_host") or payload.get("host") or payload.get("ip") or payload.get("url") or "")
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


def is_ip_literal(value: str) -> bool:
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(value.strip("[]"))
        return True
    return False


def naabu_port_identity(line: str) -> tuple[str, str, int] | None:
    """Return (scoped input hostname, resolved IP, port) from a Naabu JSON row.

    The hostname is intentionally the planned input when available; an IP alone
    is evidence, not an authorization target.
    """
    parsed = parse_port_line(line)
    if not parsed:
        return None
    observed_host, port = parsed
    try:
        payload = json.loads(line) if line.lstrip().startswith("{") else {}
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}

    raw_candidates = [
        payload.get("input_host"),
        payload.get("input"),
        payload.get("hostname"),
        payload.get("domain"),
        payload.get("host"),
        payload.get("url"),
    ]
    input_host = ""
    for candidate in raw_candidates:
        candidate_host = host_from_url(str(candidate)) if candidate else ""
        if candidate_host and not is_ip_literal(candidate_host):
            input_host = candidate_host
            break
    resolved_ip = ""
    for candidate in (payload.get("ip"), observed_host):
        value = str(candidate or "").strip("[]")
        if is_ip_literal(value):
            resolved_ip = value
            break
    return input_host or observed_host, resolved_ip, port


def normalize_host_port(host: str, port_value: Any) -> tuple[str, int] | None:
    host = host_from_url(host) if "://" in str(host) else str(host).strip().lower()
    if isinstance(port_value, str) and "/" in port_value:
        port_value = port_value.split("/", 1)[0]
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


def structured_agent_review(
    program_cfg: dict[str, Any], candidates: list[TargetCandidate]
) -> tuple[TargetCandidate | None, dict[str, Any]]:
    """Accept a bounded external review decision without delegating execution.

    An external AI/analyst may write JSON to ``response_file``.  This planner
    accepts only a candidate it already found and scope-filtered, and only
    wordlist groups explicitly declared by the fuzz configuration.
    """
    selection = program_cfg.get("target_selection") if isinstance(program_cfg.get("target_selection"), dict) else {}
    review_cfg = selection.get("agent_review") if isinstance(selection.get("agent_review"), dict) else {}
    enabled = bool(review_cfg.get("enabled"))
    response_file = expand_path(str(review_cfg.get("response_file") or "")) if review_cfg.get("response_file") else None
    metadata: dict[str, Any] = {
        "enabled": enabled,
        "configured": bool(response_file),
        "response_file": str(response_file) if response_file else None,
        "allowed_candidate_count": len(candidates),
        "outcome": "fallback",
        "reason": "agent_review_not_configured" if not response_file else "response_file_missing",
        "accepted_wordlist_groups": [],
    }
    if not enabled:
        metadata["reason"] = "agent_review_disabled"
        return None, metadata
    if not response_file or not response_file.is_file():
        return None, metadata
    try:
        payload = json.loads(response_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        metadata["reason"] = "response_file_invalid_json"
        return None, metadata
    if not isinstance(payload, dict):
        metadata["reason"] = "response_file_not_object"
        return None, metadata

    selected_value = payload.get("selected_target")
    if not isinstance(selected_value, str) or not selected_value.strip():
        metadata["reason"] = "selected_target_missing_or_invalid"
        return None, metadata
    selected_value = selected_value.strip()
    by_value: dict[str, TargetCandidate] = {}
    for candidate in candidates:
        # Hostnames are deliberately excluded: a host can have multiple
        # origins/paths and is not an exact selection identity.
        for value in (candidate.key, candidate.base_url):
            by_value.setdefault(value, candidate)
    selected = by_value.get(selected_value)
    if selected is None:
        metadata["reason"] = "selected_target_not_in_scoped_candidates"
        return None, metadata

    require_reason = bool(review_cfg.get("require_reason"))
    reason = payload.get("reason")
    if require_reason and (not isinstance(reason, str) or not reason.strip()):
        metadata["reason"] = "required_reason_missing_or_invalid"
        return None, metadata

    jobs = program_cfg.get("jobs") if isinstance(program_cfg.get("jobs"), dict) else {}
    fuzz = jobs.get("juicy_target_fuzz") if isinstance(jobs.get("juicy_target_fuzz"), dict) else {}
    wordlists = fuzz.get("wordlists") if isinstance(fuzz.get("wordlists"), dict) else {}
    allowed_groups = set((wordlists.get("tech_wordlists") or {}).keys())
    requested_groups = payload.get("wordlist_groups") or []
    if not isinstance(requested_groups, list) or not all(isinstance(group, str) for group in requested_groups):
        metadata["reason"] = "wordlist_groups_must_be_string_list"
        return None, metadata
    accepted_groups = [group for group in requested_groups if group in allowed_groups]
    metadata.update(
        {
            "outcome": "accepted",
            "reason": str(payload.get("reason") or "structured_review_accepted"),
            "selected_target": selected.to_dict(),
            "accepted_wordlist_groups": list(dict.fromkeys(accepted_groups)),
        }
    )
    return selected, metadata


def select_targets_with_review(program: str, program_cfg: dict[str, Any]) -> tuple[list[TargetCandidate], dict[str, Any]]:
    candidates = collect_target_candidates(program, program_cfg)
    if not candidates:
        selected = [select_target(program, program_cfg)]
        return selected, {
            "enabled": False,
            "configured": False,
            "allowed_candidate_count": 0,
            "outcome": "fallback",
            "reason": "no_ranked_candidates_default_target_used",
            "accepted_wordlist_groups": [],
        }
    selected, metadata = structured_agent_review(program_cfg, candidates)
    count = target_select_count(program_cfg)
    if selected is None:
        return candidates[:count], metadata
    ordered = [selected, *(candidate for candidate in candidates if candidate.base_url != selected.base_url)]
    return ordered[:count], metadata


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
    interesting_only = bool(inputs.get("interesting_ports_only", False))
    common_ports = {int(port) for port in inputs.get("common_web_ports", []) if str(port).isdigit()}
    require_scope = bool(inputs.get("require_saved_scope", False))
    port_records = collect_naabu_ports(
        program_cfg,
        selected_host=None if interesting_only else selected.host,
        max_hosts=100000 if require_scope else max_hosts,
        max_ports=max_ports,
        exclude_ports=common_ports if interesting_only else None,
    )
    dropped_out_of_scope_records = 0
    if require_scope:
        validator = ScopeValidator(program, strict=False)
        original_count = len(port_records)
        port_records = [record for record in port_records if validator.is_in_scope(str(record["host"]))]
        dropped_out_of_scope_records = original_count - len(port_records)
        port_records = port_records[:max_hosts]
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

    selected_record = port_records[0]
    selected_host = str(selected_record["host"])
    nmap_target = selected
    if selected_host != selected.host:
        nmap_target = TargetCandidate(
            key=f"naabu:{selected_host}",
            base_url=f"{urlparse(selected.base_url).scheme or 'https'}://{selected_host}",
            host=selected_host,
            source="naabu_interesting_service",
        )
    if inputs.get("require_saved_scope", False) and not ScopeValidator(program, strict=False).is_in_scope(nmap_target.host):
        return {
            "job": "nmap_enrichment",
            "state": job.get("state", "unknown"),
            "status": "blocked",
            "reason": "selected_host_not_in_saved_scope",
            "host": selected.host,
        }

    ports = selected_record["ports"]
    context = {
        "naabu-discovered-ports": ",".join(str(port) for port in ports),
        "selected-ports": ",".join(str(port) for port in ports),
        "run-root": str(expand_path(job.get("outputs", {}).get("run_root", "<run-root>"))),
        "selected-host": nmap_target.host,
    }
    command = [expand_pattern(str(part), context) for part in job.get("command_template") or ()]
    return {
        "job": "nmap_enrichment",
        "state": job.get("state", "unknown"),
        "status": "planned",
        "tool": job.get("tool", "nmap"),
        "mode": job.get("mode"),
        "target": nmap_target.to_dict(),
        "host": nmap_target.host,
        "ports": ports,
        "dropped_out_of_scope_naabu_records": dropped_out_of_scope_records,
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


def aggregated_domain_hosts(inputs: dict[str, Any]) -> list[str]:
    """Read deduplicated hostnames from canonical aggregated recon sources."""
    hosts: set[str] = set()
    for raw_path in inputs.get("aggregated_domain_sources") or ():
        path = expand_path(str(raw_path))
        if not path.is_file():
            continue
        for line in read_lines(path):
            value = line.strip().split(maxsplit=1)[0] if line.strip() else ""
            if not value:
                continue
            parsed = urlparse(value if "://" in value else f"//{value}")
            if parsed.hostname:
                hosts.add(parsed.hostname.lower())
    return sorted(hosts)


def build_naabu_plan(
    program: str,
    program_cfg: dict[str, Any],
    selected: TargetCandidate,
    *,
    candidates: list[TargetCandidate] | None = None,
) -> dict[str, Any]:
    jobs = program_cfg.get("jobs") if isinstance(program_cfg.get("jobs"), dict) else {}
    job = jobs.get("naabu_discovery")
    if not isinstance(job, dict):
        return {"job": "naabu_discovery", "state": "absent", "status": "skipped", "reason": "job not configured"}

    nmap_job = jobs.get("nmap_enrichment") if isinstance(jobs.get("nmap_enrichment"), dict) else {}
    nmap_inputs = nmap_job.get("inputs") if isinstance(nmap_job.get("inputs"), dict) else {}
    inputs = job.get("inputs") if isinstance(job.get("inputs"), dict) else {}
    batch_limit = max(1, int(inputs.get("batch_candidate_limit") or 1))
    if batch_limit == 1 and collect_naabu_ports(program_cfg, selected_host=selected.host, max_hosts=1, max_ports=1):
        return {
            "job": "naabu_discovery",
            "state": job.get("state", "unknown"),
            "status": "skipped",
            "reason": "service_inventory_exists_for_selected_host",
            "target": selected.to_dict(),
            "host": selected.host,
        }

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

    validator = ScopeValidator(program, strict=False)
    covered_hosts: set[str] = set()
    if inputs.get("source_first", False):
        covered_hosts = {
            str(record["host"]).lower()
            for record in collect_naabu_ports(program_cfg, max_hosts=100000, max_ports=1)
        }
    source_hosts = aggregated_domain_hosts(inputs)
    candidate_hosts = []
    host_candidates = source_hosts or [candidate.host for candidate in (candidates or [selected])]
    for host in host_candidates:
        host = str(host).lower()
        if host in covered_hosts:
            continue
        if host and validator.is_in_scope(host) and host not in candidate_hosts:
            candidate_hosts.append(host)
        if len(candidate_hosts) >= batch_limit:
            break
    if not candidate_hosts:
        return {
            "job": "naabu_discovery",
            "state": job.get("state", "unknown"),
            "status": "blocked",
            "reason": "no_saved_scope_candidate_hosts",
            "target": selected.to_dict(),
        }

    context = {
        "selected-host": selected.host,
        "naabu-hosts-file": "<naabu-hosts-file>",
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
        "candidate_hosts": candidate_hosts,
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
        "outputs": job.get("outputs", {}),
        "post_run": job.get("post_run", {}),
        "technology_map": technology_map,
        "run_auth": (program_cfg.get("runtime") or {}).get("auth", "off") if isinstance(program_cfg.get("runtime"), dict) else "off",
        "auth_resolver": program_cfg.get("auth", {}),
        "selected_tech_wordlist_groups": technology_map.get("selected_wordlist_groups", []),
        "command": command,
    }


def parameter_source_endpoints(job: dict[str, Any], selected: TargetCandidate) -> tuple[list[str], list[str]]:
    """Shape in-scope parameterized URLs into Arjun endpoint inputs.

    ``params.txt`` is evidence, not a direct command input: retain only HTTP(S)
    URLs for the selected origin, strip values/query strings, and dedupe routes.
    """
    inputs = job.get("inputs") if isinstance(job.get("inputs"), dict) else {}
    paths = inputs.get("parameter_url_sources") or []
    endpoints: set[str] = set()
    selected_scheme = urlparse(selected.base_url).scheme.lower()
    sources: list[str] = []
    for raw_path in paths:
        path = expand_path(str(raw_path))
        if not path.is_file():
            continue
        sources.append(str(path))
        for raw in read_lines(path):
            for value in extract_urls(raw):
                parsed = urlparse(value)
                path_value = unquote(parsed.path or "/")
                suffix = Path(path_value).suffix.lower()
                if (
                    parsed.scheme not in {"http", "https"}
                    or (parsed.hostname or "").lower() != selected.host
                    or (selected_scheme and parsed.scheme != selected_scheme)
                ):
                    continue
                # Crawler artifacts frequently turn third-party asset references into
                # same-host-looking paths. They are not meaningful Arjun endpoints.
                if any(char.isspace() for char in path_value) or suffix in {
                    ".css", ".csv", ".eot", ".gif", ".ico", ".jpg", ".jpeg", ".js", ".map", ".png", ".svg", ".ttf", ".webp", ".woff", ".woff2",
                }:
                    continue
                endpoints.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}")
    limit = max(1, int(inputs.get("max_endpoints_per_run") or 50))
    return sorted(endpoints)[:limit], sources


def materialize_parameter_endpoints(job: dict[str, Any], root: Path) -> dict[str, Any]:
    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    selected = TargetCandidate(
        key=str(target.get("key") or "selected"),
        base_url=str(target.get("base_url") or ""),
        host=str(target.get("host") or "").lower(),
        source="prepared_parameter_plan",
    )
    endpoints, sources = parameter_source_endpoints(job, selected)
    path = root / "_batches" / "parameter-endpoints.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(endpoints) + ("\n" if endpoints else ""), encoding="utf-8")
    return {"path": str(path), "candidate_count": len(endpoints), "sources": sources, "target_host": selected.host}


def build_parameter_plan(program_cfg: dict[str, Any], selected: TargetCandidate) -> dict[str, Any]:
    job = program_cfg.get("jobs", {}).get("authenticated_parameter_mining", {})
    technology_map = build_technology_map(program_cfg, selected)
    inputs = job.get("inputs") if isinstance(job.get("inputs"), dict) else {}
    source_endpoints, source_paths = parameter_source_endpoints(job, selected)
    legacy_endpoint_queue = expand_path(inputs.get("endpoint_queue", ""))
    use_parameter_sources = bool(inputs.get("parameter_url_sources"))
    endpoint_reference = "<parameter-endpoint-queue>" if use_parameter_sources else str(legacy_endpoint_queue)
    context = {
        "endpoint-queue": endpoint_reference,
        "run-root": "<arjun-run-root>",
    }
    command = [expand_pattern(str(part), context) for part in job.get("command_template") or ()]
    status = "planned" if source_endpoints or legacy_endpoint_queue.is_file() else "needs_endpoint_queue"
    return {
        "job": "authenticated_parameter_mining",
        "job_instance_id": "authenticated_parameter_mining",
        "state": job.get("state", "unknown"),
        "status": status,
        "target": selected.to_dict(),
        "inputs": inputs,
        "parameter_source_preview": {"candidate_count": len(source_endpoints), "sources": source_paths},
        "technology_map": technology_map,
        "run_auth": (program_cfg.get("runtime") or {}).get("auth", "off") if isinstance(program_cfg.get("runtime"), dict) else "off",
        "auth_resolver": program_cfg.get("auth", {}),
        "auth": job.get("auth", {}),
        "outputs": job.get("outputs", {}),
        "post_run": job.get("post_run", {}),
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


def job_run_type(job: dict[str, Any]) -> str:
    return str(job.get("run_type") or JOB_RUN_TYPES.get(str(job.get("job") or ""), job.get("job") or "unknown"))


def queue_path(data: dict[str, Any], program: str, program_cfg: dict[str, Any]) -> Path:
    queue_cfg: dict[str, Any] = {}
    runtime = runtime_config(data, program_cfg)
    if isinstance(runtime.get("queue"), dict):
        queue_cfg = runtime["queue"]
    if isinstance(program_cfg.get("queue"), dict):
        queue_cfg = deep_merge(queue_cfg, program_cfg["queue"])
    configured = queue_cfg.get("path") or queue_cfg.get("queue_file")
    if configured:
        return expand_path(render_template(str(configured), {"program": program}))
    return DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "cron" / "queue.json"


def queue_worker_stop_path(data: dict[str, Any], program: str, program_cfg: dict[str, Any], run_type: str) -> Path:
    runtime = runtime_config(data, program_cfg)
    worker_cfg = runtime.get("worker") if isinstance(runtime.get("worker"), dict) else {}
    stop_template = worker_cfg.get("stop_file")
    context = {"program": program, "run_type": safe_slug(run_type)}
    if stop_template:
        return expand_path(render_template(str(stop_template), context))
    return queue_path(data, program, program_cfg).parent / ".stop" / f"{safe_slug(run_type)}.stop"


def empty_queue() -> dict[str, Any]:
    return {"version": 1, "queues": {}}


def load_queue(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return empty_queue()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return empty_queue()
    if not isinstance(data, dict):
        return empty_queue()
    if data.get("version") != 1:
        data["version"] = 1
    if not isinstance(data.get("queues"), dict):
        data["queues"] = {}
    return data


def write_queue(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(path)


@contextlib.contextmanager
def locked_queue(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield load_queue(path)
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def queue_dedupe_key(program: str, job: dict[str, Any]) -> str:
    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    host = str(target.get("host") or job.get("host") or "")
    base_url = str(target.get("base_url") or "")
    command_hash = hashlib.sha1(json.dumps(job.get("command") or [], sort_keys=True).encode("utf-8")).hexdigest()[:12]
    raw = "|".join([program, str(job.get("job") or ""), host, base_url, command_hash])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def queue_entry_id(run_type: str, dedupe_key: str) -> str:
    return f"{safe_slug(run_type)}-{dedupe_key[:12]}"


def job_queue_entry(program: str, payload: dict[str, Any], job: dict[str, Any]) -> dict[str, Any]:
    run_type = job_run_type(job)
    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    dedupe_key = queue_dedupe_key(program, job)
    now = utc_now()
    return {
        "id": queue_entry_id(run_type, dedupe_key),
        "version": 1,
        "program": program,
        "lane": "web",
        "run_type": run_type,
        "job": job.get("job"),
        "job_instance_id": job.get("job_instance_id") or job.get("job"),
        "target": target,
        "target_host": target.get("host") or job.get("host"),
        "priority": int(job.get("priority") or 50),
        "reason": job.get("reason") or "planned_by_cron",
        "source": {
            "planner": "cron_orchestrator",
            "plan_run_id": payload.get("run_id"),
            "selected_target": payload.get("selected_target"),
        },
        "policy": {
            "state": job.get("state"),
            "rate_budget": job.get("rate_budget"),
            "mode": job.get("mode"),
        },
        "state": "pending",
        "attempts": 0,
        "created_at": now,
        "updated_at": now,
        "run_root": None,
        "manifest_path": None,
        "terminal_status": None,
        "dedupe_key": dedupe_key,
        "job_payload": job,
    }


def enqueue_planned_jobs(
    data: dict[str, Any],
    program: str,
    payload: dict[str, Any],
    *,
    only_jobs: set[str] | None = None,
) -> dict[str, Any]:
    program_cfg = resolve_program(data, program)
    path = queue_path(data, program, program_cfg)
    planned_jobs = [
        job
        for job in payload.get("jobs", [])
        if isinstance(job, dict)
        and job.get("status") == "planned"
        and (only_jobs is None or str(job.get("job") or "") in only_jobs)
    ]
    summary = {"queue_path": str(path), "read": len(planned_jobs), "created": 0, "deduped": 0, "by_run_type": {}}
    with locked_queue(path) as queue:
        queues = queue.setdefault("queues", {})
        for job in planned_jobs:
            entry = job_queue_entry(program, payload, job)
            run_type = str(entry["run_type"])
            section = queues.setdefault(run_type, [])
            active = [
                item
                for item in section
                if isinstance(item, dict)
                and item.get("dedupe_key") == entry["dedupe_key"]
                and str(item.get("state") or "pending") not in QUEUE_TERMINAL_STATES
            ]
            if active:
                active[0]["updated_at"] = utc_now()
                active[0]["last_seen_plan_run_id"] = payload.get("run_id")
                summary["deduped"] += 1
                action = "deduped"
            else:
                section.append(entry)
                summary["created"] += 1
                action = "created"
            run_type_summary = summary["by_run_type"].setdefault(run_type, {"created": 0, "deduped": 0})
            run_type_summary[action] += 1
        queue["updated_at"] = utc_now()
        write_queue(path, queue)
    return summary


def plan(data: dict[str, Any], program: str, *, write: bool = False) -> dict[str, Any]:
    errors = validate_config(data)
    if errors:
        raise ValueError("; ".join(errors))
    program_cfg = resolve_program(data, program)
    selected_targets, agent_review = select_targets_with_review(program, program_cfg)
    selected = selected_targets[0]
    all_candidates = collect_target_candidates(program, program_cfg)
    candidates = [candidate.to_dict() for candidate in all_candidates[:25]]
    jobs: list[dict[str, Any]] = []
    # Naabu/Nmap retain their discovery/enrichment selection. Web scanners select
    # independently from their own durable evidence queues.
    naabu_plan = build_naabu_plan(program, program_cfg, selected, candidates=all_candidates)
    if naabu_plan.get("reason") != "job not configured":
        jobs.append(naabu_plan)
    jobs.append(build_nmap_plan(program, program_cfg, selected))

    configured_jobs = program_cfg.get("jobs") if isinstance(program_cfg.get("jobs"), dict) else {}
    fuzz_cfg = configured_jobs.get("juicy_target_fuzz") if isinstance(configured_jobs.get("juicy_target_fuzz"), dict) else {}
    fuzz_inputs = fuzz_cfg.get("inputs") if isinstance(fuzz_cfg.get("inputs"), dict) else {}
    fuzz_sources = fuzz_inputs.get("target_url_sources")
    fuzz_targets = (collect_job_target_candidates(program, program_cfg, list(fuzz_sources or ()))[:1]
                    if fuzz_sources is not None else selected_targets)
    if fuzz_targets:
        jobs.extend(with_target_instance(build_fuzz_plan(program_cfg, target), len(fuzz_targets)) for target in fuzz_targets)
    else:
        jobs.append({"job": "juicy_target_fuzz", "job_instance_id": "juicy_target_fuzz", "state": fuzz_cfg.get("state", "unknown"), "status": "skipped", "reason": "no_scoped_target_evidence"})

    parameter_cfg = configured_jobs.get("authenticated_parameter_mining") if isinstance(configured_jobs.get("authenticated_parameter_mining"), dict) else {}
    parameter_inputs = parameter_cfg.get("inputs") if isinstance(parameter_cfg.get("inputs"), dict) else {}
    parameter_sources = parameter_inputs.get("parameter_url_sources")
    parameter_targets = (collect_job_target_candidates(program, program_cfg, list(parameter_sources or ()))[:1]
                         if parameter_sources is not None else selected_targets)
    if parameter_targets:
        jobs.extend(with_target_instance(build_parameter_plan(program_cfg, target), len(parameter_targets)) for target in parameter_targets)
    else:
        jobs.append({"job": "authenticated_parameter_mining", "job_instance_id": "authenticated_parameter_mining", "state": parameter_cfg.get("state", "unknown"), "status": "skipped", "reason": "no_scoped_target_evidence"})
    smart_fuzzing = resolve_smart_fuzzing(data, program_cfg, "web")
    for job in jobs:
        if job.get("job") == "juicy_target_fuzz":
            job["smart_fuzzing"] = smart_fuzzing
    apply_rate_budgets(data, program_cfg, jobs)
    payload = {
        "run_id": run_id(),
        "mode": "dry-run",
        "program": program,
        "selected_target": selected.to_dict(),
        "selected_targets": [target.to_dict() for target in selected_targets],
        "candidate_count": len(all_candidates),
        "top_candidates": candidates,
        "agent_review": agent_review,
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


def resolve_smart_fuzzing(global_cfg: dict[str, Any], program_cfg: dict[str, Any], lane: str) -> dict[str, Any]:
    """Resolve global → program → lane smart-fuzzing policy without execution authority."""
    base = global_cfg.get("smart_fuzzing") if isinstance(global_cfg.get("smart_fuzzing"), dict) else {}
    program = program_cfg.get("smart_fuzzing") if isinstance(program_cfg.get("smart_fuzzing"), dict) else {}
    merged = deep_merge(base, {key: value for key, value in program.items() if key != "lanes"})
    lanes = program.get("lanes") if isinstance(program.get("lanes"), dict) else {}
    lane_cfg = lanes.get(lane) if isinstance(lanes.get(lane), dict) else {}
    resolved = deep_merge(merged, lane_cfg)
    resolved["lane"] = lane
    return resolved


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


def resolve_job_auth(program: str, job: dict[str, Any]) -> dict[str, Any]:
    """Resolve one run-level auth selector without ever returning header values."""
    requested = str(job.get("run_auth") or "off").strip().lower()
    if requested in {"", "off", "none"}:
        return {"requested": "off", "effective": "off", "status": "not_requested"}
    cfg = job.get("auth_resolver") if isinstance(job.get("auth_resolver"), dict) else {}
    template = cfg.get("resolver", {}).get("command_template") if isinstance(cfg.get("resolver"), dict) else None
    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    if not isinstance(template, list):
        return {"requested": requested, "effective": "off", "status": "downgraded", "reason": "resolver_not_configured"}
    context = {"program": program, "selected-base-url": str(target.get("base_url") or ""), "selected-host": str(target.get("host") or "")}
    command = [expand_pattern(str(part), context) for part in template]
    command = [requested if part == "blue" and requested != "blue" else part for part in command]
    try:
        proc = subprocess.run(command, text=True, capture_output=True, timeout=20, cwd=str(Path(__file__).resolve().parent.parent))
        payload = json.loads(proc.stdout) if proc.returncode == 0 else {}
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        payload = {}
    seed = payload.get("auth_seed") if isinstance(payload.get("auth_seed"), dict) else {}
    seed_path = seed.get("path") if seed.get("status") == "available" else None
    if payload.get("status") == "ready" and isinstance(seed_path, str) and Path(seed_path).is_file():
        return {"requested": requested, "effective": requested, "status": "ready", "account": requested, "seed_path": seed_path, "header_names": seed.get("header_names", [])}
    return {"requested": requested, "effective": "off", "status": "downgraded", "reason": str(payload.get("status") or "resolver_unavailable")}


def wrap_authenticated_command(command: list[str], auth: dict[str, Any]) -> list[str]:
    if auth.get("effective") == "off":
        return command
    tool = infer_tool(command)
    if tool not in {"ffuf", "arjun"}:
        return command
    return [sys.executable, str(Path(__file__).with_name("authenticated_tool_runner.py")), "--auth-seed", str(auth["seed_path"]), "--tool", tool, "--", *command]


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

    if job.get("job") == "naabu_discovery" and "<naabu-hosts-file>" in command_parts:
        hosts = sorted({str(host).lower() for host in job.get("candidate_hosts") or [] if str(host).strip()})
        path = root / "_batches" / "naabu-hosts.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
        materialized_inputs["naabu_hosts"] = {"path": str(path), "candidate_count": len(hosts)}
        command_parts = [str(part).replace("<naabu-hosts-file>", str(path)) for part in command_parts]

    if job.get("job") == "authenticated_parameter_mining" and "<parameter-endpoint-queue>" in command_parts:
        endpoints = materialize_parameter_endpoints(job, root)
        materialized_inputs["parameter_endpoints"] = endpoints
        command_parts = [str(part).replace("<parameter-endpoint-queue>", endpoints["path"]) for part in command_parts]

    command = render_command(command_parts, root, run_id_value)
    auth = resolve_job_auth(program, job)
    command = wrap_authenticated_command(command, auth)
    (root / "command.txt").write_text(command_text(command) + "\n", encoding="utf-8")
    manifest = {
        "run_id": run_id_value,
        "job": job.get("job"),
        "tool": job.get("tool") or infer_tool(command),
        "state": job.get("state"),
        "planned_status": job.get("status"),
        "target": job.get("target", {}),
        "rate_budget": job.get("rate_budget"),
        "auth": {key: value for key, value in auth.items() if key != "seed_path"},
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


def naabu_candidate_ip_map(job: dict[str, Any]) -> dict[str, set[str]]:
    """Map planned hostname inputs to their resolver answers for this Naabu run."""
    mapping: dict[str, set[str]] = {}
    for raw_host in job.get("candidate_hosts") or ():
        host = host_from_url(str(raw_host))
        if not host or is_ip_literal(host):
            continue
        with contextlib.suppress(socket.gaierror):
            for _family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
                ip = str(sockaddr[0]).strip("[]")
                if is_ip_literal(ip):
                    mapping.setdefault(ip, set()).add(host)
    return mapping


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
    candidate_ip_map = naabu_candidate_ip_map(job)
    rows: list[dict[str, Any]] = []
    lines: list[str] = []
    seen: set[tuple[str, str, int]] = set()
    for line in read_lines(raw_path):
        identity = naabu_port_identity(line)
        if not identity:
            continue
        host, resolved_ip, port = identity
        attribution = "naabu_hostname" if not is_ip_literal(host) else "unattributed_ip"
        if is_ip_literal(host) and resolved_ip:
            mapped_hosts = sorted(candidate_ip_map.get(resolved_ip, set()))
            if len(mapped_hosts) == 1:
                host = mapped_hosts[0]
                attribution = "planned_hostname_dns_match"
        input_host = "" if is_ip_literal(host) else host
        key = (host, resolved_ip, port)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "program": program,
                "host": host,
                "input_host": input_host,
                "resolved_ip": resolved_ip,
                "attribution": attribution,
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
    services_jsonl = outputs.get("services_ports_jsonl")
    services_txt = outputs.get("services_ports_txt")
    aggregate_jsonl = (
        outputs.get("aggregate_ports_jsonl")
        or outputs.get("aggregated_ports_jsonl")
        or outputs.get("global_ports_jsonl")
    )
    aggregate_txt = (
        outputs.get("aggregate_ports_txt")
        or outputs.get("aggregated_ports_txt")
        or outputs.get("global_ports_txt")
    )
    append_summary: dict[str, Any] = {"normalized_count": len(rows)}
    if services_jsonl:
        append_summary["services_ports_jsonl"] = _append_deduped_jsonl(
            expand_path(str(services_jsonl)),
            rows,
            key_fields=["host", "port", "resolved_ip"],
        )
    if services_txt:
        append_summary["services_ports_txt"] = _append_deduped_lines(expand_path(str(services_txt)), lines)
    if aggregate_jsonl:
        append_summary["aggregated_ports_jsonl"] = _append_deduped_jsonl(
            expand_path(str(aggregate_jsonl)),
            rows,
            key_fields=["host", "port", "resolved_ip"],
        )
    if aggregate_txt:
        append_summary["aggregated_ports_txt"] = _append_deduped_lines(expand_path(str(aggregate_txt)), lines)
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

    When approved_jobs is provided, it is a strict allowlist for this run.
    Otherwise, approve_manual can auto-approve in-scope manual jobs so a
    default run can execute every planned job that passes its normal gates.
    """
    job_name = str(job.get("job") or "")
    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    target_host = str(target.get("host") or "")
    if not _target_in_scope(program, target_host):
        return False, "target_not_in_saved_scope"
    if parent_block_reason:
        return False, parent_block_reason
    if job.get("job") not in EXECUTABLE_PLANNED_JOBS:
        return False, "job_family_not_executable_by_orchestrator"
    if job.get("status") != "planned":
        return False, f"planned_status_{job.get('status')}"
    if approved_jobs is not None and job_name not in approved_jobs:
        return False, "job_not_selected"
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
) -> int | None:
    """Compute per-run timeout only when the config opts into one.

    A missing/empty timeout_seconds means long-running workers are bounded by
    rate, locks, and stop conditions rather than a default wall-clock budget.
    When timeout_seconds is configured, wordlist size can raise that floor and
    timeout_seconds_max can cap it.
    """
    floor_raw = rate_limit.get("timeout_seconds")
    floor = int(floor_raw) if floor_raw not in (None, "", False) else None
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
    if wordlist_count > 0 and effective_rate > 0 and floor is not None:
        estimated = max(floor, math.ceil(wordlist_count / effective_rate * margin))
        return min(ceiling, estimated) if ceiling is not None else estimated
    return floor


def _read_stderr(root: Path) -> str:
    """Read stderr log if it exists."""
    stderr_path = root / "logs" / "stderr.txt"
    if stderr_path.is_file():
        return stderr_path.read_text(encoding="utf-8", errors="ignore")
    return ""


def write_job_heartbeat(root: Path, manifest: dict[str, Any], *, pid: int, event: str) -> dict[str, Any]:
    """Persist a compact, independently readable progress signal for a live run."""
    log_root = root / "logs"
    stdout_path = log_root / "stdout.txt"
    stderr_path = log_root / "stderr.txt"
    heartbeat = {
        "at": utc_now(),
        "event": event,
        "pid": pid,
        "status": manifest.get("status"),
        "started_at": manifest.get("started_at"),
        "stdout_bytes": stdout_path.stat().st_size if stdout_path.is_file() else 0,
        "stderr_bytes": stderr_path.stat().st_size if stderr_path.is_file() else 0,
    }
    (root / "heartbeat.json").write_text(json.dumps(heartbeat, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest["heartbeat"] = heartbeat
    return heartbeat


def progress_interval_seconds(job: dict[str, Any]) -> int:
    """Return a bounded live-job heartbeat cadence, defaulting to ten minutes."""
    raw_notifications = job.get("notifications")
    notifications: dict[str, Any] = raw_notifications if isinstance(raw_notifications, dict) else {}
    try:
        interval = int(notifications.get("progress_every_seconds") or 600)
    except (TypeError, ValueError):
        interval = 600
    return max(30, interval)


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


def result_url_is_usable(program: str, raw_url: str, target_host: str) -> bool:
    """Keep reusable leads pinned to the planned origin and saved program scope."""
    parsed = urlparse(raw_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host or host != target_host.lower():
        return False
    return _target_in_scope(program, host)


def uniform_ffuf_surface(rows: list[dict[str, Any]], *, threshold: int) -> dict[str, Any] | None:
    """Classify a large FFUF result set with one indistinguishable response shape.

    A full uniform response set is retained in the run capsule but is not a
    route-lead set. Requiring every observed row to share the signature avoids
    dropping an otherwise interesting run that has even one genuine
    differential response.
    """
    if len(rows) < threshold:
        return None
    signatures = {
        (row.get("status"), row.get("length"), row.get("words"), row.get("lines"))
        for row in rows
    }
    if len(signatures) != 1:
        return None
    status, length, words, lines = signatures.pop()
    return {
        "classification": "uniform_response_surface",
        "response_count": len(rows),
        "threshold": threshold,
        "signature": {"status": status, "length": length, "words": words, "lines": lines},
    }


def normalize_nmap_output(
    program: str,
    job: dict[str, Any],
    root: Path,
    run_id_value: str,
) -> dict[str, Any]:
    """Promote open Nmap ports into the single aggregated evidence store and follow-up queues."""
    xml_path = root / "raw" / "nmap.xml"
    outputs = job.get("outputs") if isinstance(job.get("outputs"), dict) else {}
    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    input_host = str(target.get("host") or "").lower()
    if not xml_path.is_file() or not input_host:
        return {"nmap_open_ports": {"read": 0, "new": 0}, "errors": ["missing_nmap_xml_or_target_host"]}
    try:
        document = ET.parse(xml_path)
    except (ET.ParseError, OSError) as exc:
        return {"nmap_open_ports": {"read": 0, "new": 0}, "errors": [f"nmap_xml: {exc}"]}

    observed_at = utc_now()
    rows: list[dict[str, Any]] = []
    http_rows: list[dict[str, Any]] = []
    port_lines: list[str] = []
    endpoint_lines: list[str] = []
    http_names = {"http", "https", "http-alt", "https-alt", "http-proxy", "ssl/http"}
    for host_node in document.findall(".//host"):
        address = host_node.find("address[@addrtype='ipv4']")
        if address is None:
            address = host_node.find("address[@addrtype='ipv6']")
        resolved_ip = str(address.get("addr") if address is not None else "")
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue
            with contextlib.suppress(TypeError, ValueError):
                port = int(str(port_node.get("portid") or ""))
                service_node = port_node.find("service")
                service = ""
                product = ""
                version = ""
                tunnel = ""
                if service_node is not None:
                    service = str(service_node.get("name") or "")
                    product = str(service_node.get("product") or "")
                    version = str(service_node.get("version") or "")
                    tunnel = str(service_node.get("tunnel") or "")
                row = {
                    "program": program,
                    "host": input_host,
                    "input_host": input_host,
                    "resolved_ip": resolved_ip,
                    "port": port,
                    "protocol": str(port_node.get("protocol") or "tcp"),
                    "state": "open",
                    "service": service,
                    "product": product,
                    "version": version,
                    "source": "nmap",
                    "run_id": run_id_value,
                    "observed_at": observed_at,
                }
                rows.append(row)
                port_lines.append(f"{input_host}:{port}")
                if service.lower() in http_names:
                    scheme = "https" if "https" in service.lower() or tunnel == "ssl" else "http"
                    endpoint = f"{scheme}://{input_host}:{port}/"
                    endpoint_lines.append(endpoint)
                    http_rows.append({**row, "url": endpoint, "queue": "nmap_http_followup"})

    normalized_root = root / "normalized"
    normalized_root.mkdir(parents=True, exist_ok=True)
    (normalized_root / "ports.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    (normalized_root / "ports.txt").write_text("\n".join(port_lines) + ("\n" if port_lines else ""), encoding="utf-8")
    aggregate_jsonl = expand_path(str(outputs.get("aggregated_ports_jsonl") or DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "aggregated" / "ports.jsonl"))
    aggregate_txt = expand_path(str(outputs.get("aggregated_ports_txt") or DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "aggregated" / "ports.txt"))
    fuzz_queue = expand_path(str(outputs.get("fuzz_endpoint_queue") or DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "queues" / "nmap_http_fuzz.jsonl"))
    parameter_queue = expand_path(str(outputs.get("parameter_endpoint_queue") or DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "queues" / "nmap_http_parameters.txt"))
    return {
        "nmap_open_ports": _append_deduped_jsonl(aggregate_jsonl, rows, key_fields=["host", "port", "resolved_ip", "source"]),
        "aggregated_ports_txt": _append_deduped_lines(aggregate_txt, port_lines),
        "fuzz_endpoint_queue": _append_deduped_jsonl(fuzz_queue, http_rows, key_fields=["url"]),
        "parameter_endpoint_queue": _append_deduped_lines(parameter_queue, endpoint_lines),
        "normalized_ports": len(rows),
        "http_followups": len(http_rows),
        "errors": [],
    }


def postprocess_completed_job(
    program: str,
    job: dict[str, Any],
    root: Path,
    run_id_value: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Normalize completed scanner output into small, reviewable recon artifacts.

    Post-processing is intentionally local and best-effort: it must never
    change a completed scanner result into a failed one.
    """
    outputs = job.get("outputs") if isinstance(job.get("outputs"), dict) else {}
    post_run = job.get("post_run") if isinstance(job.get("post_run"), dict) else {}
    target = job.get("target") if isinstance(job.get("target"), dict) else {}
    host = str(target.get("host") or "unknown")
    summary: dict[str, Any] = {"job": job.get("job"), "run_id": run_id_value, "errors": []}

    try:
        if job.get("job") == "nmap_enrichment":
            summary.update(normalize_nmap_output(program, job, root, run_id_value))

        elif job.get("job") == "juicy_target_fuzz":
            from agents.cloudflare_detector import load_ffuf_results

            rows = load_ffuf_results(root / "raw" / "ffuf.json")
            normalized: list[dict[str, Any]] = []
            for row in rows:
                url = str(row.get("url") or row.get("input", {}).get("FUZZ") or "").strip()
                try:
                    status = int(row.get("status") or row.get("status_code"))
                except (TypeError, ValueError):
                    continue
                if not url or not result_url_is_usable(program, url, host):
                    continue
                normalized.append(
                    {
                        "program": program,
                        "url": url,
                        "host": host,
                        "status": status,
                        "length": row.get("length"),
                        "words": row.get("words"),
                        "lines": row.get("lines"),
                        "run_id": run_id_value,
                        "observed_at": utc_now(),
                    }
                )
            default_root = DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "fuzz"
            status_path = expand_path(str(outputs.get("status_leads") or default_root / "status_leads.jsonl"))
            forbidden_path = expand_path(str(outputs.get("forbidden_leads") or default_root / "403.jsonl"))
            history_path = expand_path(str(outputs.get("fuzz_history") or DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "fuzz_history" / "fuzz_runs.jsonl"))
            inputs = job.get("inputs") if isinstance(job.get("inputs"), dict) else {}
            threshold = int(inputs.get("uniform_response_threshold") or 10_000)
            surface = uniform_ffuf_surface(normalized, threshold=threshold)
            forbidden: list[dict[str, Any]] = []
            if surface:
                quarantine_path = root / "normalized" / "quarantined_uniform_results.jsonl"
                quarantine_path.parent.mkdir(parents=True, exist_ok=True)
                quarantine_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in normalized), encoding="utf-8")
                surface["quarantine_path"] = str(quarantine_path)
                manifest["ffuf_surface"] = surface
                summary["uniform_surface"] = surface
                summary["status_leads"] = {"read": 0, "new": 0}
                summary["forbidden_leads"] = {"read": 0, "new": 0}
            else:
                summary["status_leads"] = _append_deduped_jsonl(status_path, normalized, key_fields=["url", "status"])
                forbidden = [row for row in normalized if row["status"] in {401, 403, 405}]
                summary["forbidden_leads"] = _append_deduped_jsonl(forbidden_path, forbidden, key_fields=["url", "status"])
            summary["fuzz_history"] = _append_deduped_jsonl(
                history_path,
                [{"program": program, "host": host, "run_id": run_id_value, "result_count": len(normalized), "uniform_surface": bool(surface), "observed_at": utc_now()}],
                key_fields=["run_id"],
            )
            normalized_urls = root / "normalized" / "urls.txt"
            if surface is None:
                _append_deduped_lines(normalized_urls, [row["url"] for row in normalized])
            if surface is None and post_run.get("feed_url_ingest"):
                try:
                    from agents.recon_store import import_url_artifacts

                    summary["url_ingest"] = import_url_artifacts(
                        program=program, artifacts=[normalized_urls], run_id=run_id_value, scope_filter="auto", repull_scope=False
                    )
                except Exception as exc:
                    summary["errors"].append(f"url_ingest: {exc}")
            handoff_path = expand_path(str(post_run.get("handoff_path") or default_root / "403_handoff.md"))
            handoff_path.parent.mkdir(parents=True, exist_ok=True)
            handoff_lines = ["# Fuzz boundary review", "", f"- Program: `{program}`", f"- Host: `{host}`", f"- Run: `{run_id_value}`", "", "## 401 / 403 / 405 leads"]
            if surface is not None:
                handoff_lines.append(f"- Uniform response surface quarantined: `{surface['response_count']}` rows with signature `{surface['signature']}`.")
            else:
                handoff_lines.extend(f"- `{row['status']}` {row['url']}" for row in forbidden[:100])
                if not forbidden:
                    handoff_lines.append("- No boundary responses recorded in this run.")
            handoff_path.write_text("\n".join(handoff_lines) + "\n", encoding="utf-8")
            summary["handoff_path"] = str(handoff_path)

        elif job.get("job") in {"authenticated_parameter_mining", "parameter_mining"}:
            raw_path = root / "raw" / "arjun.json"
            try:
                payload = json.loads(raw_path.read_text(encoding="utf-8")) if raw_path.is_file() else {}
            except (OSError, json.JSONDecodeError):
                payload = {}
            parameter_rows: list[dict[str, Any]] = []
            endpoints: set[str] = set()
            if isinstance(payload, dict):
                for endpoint, values in payload.items():
                    endpoint_text = str(endpoint).strip()
                    if not result_url_is_usable(program, endpoint_text, host):
                        continue
                    names = values.get("parameters") if isinstance(values, dict) else values
                    if not isinstance(names, list):
                        continue
                    endpoints.add(endpoint_text)
                    for name in names:
                        if isinstance(name, dict):
                            name = name.get("name") or name.get("parameter") or name.get("param")
                        value = str(name or "").strip()
                        if value:
                            parameter_rows.append({"program": program, "endpoint": endpoint_text, "parameter": value, "host": host, "run_id": run_id_value, "observed_at": utc_now()})
            default_root = DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "parameter_mining"
            params_jsonl = expand_path(str(outputs.get("parameters_jsonl") or default_root / "parameters.jsonl"))
            aggregate_path = expand_path(str(outputs.get("aggregated_params") or DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "aggregated" / "params.txt"))
            source_path = expand_path(str(outputs.get("parameter_source_log") or default_root / "parameter_sources.jsonl"))
            queue_path_value = expand_path(str(outputs.get("endpoint_queue") or default_root / "latest" / "queue" / "recon-hidden-param-patterns.txt"))
            summary["parameters"] = _append_deduped_jsonl(params_jsonl, parameter_rows, key_fields=["endpoint", "parameter"])
            _append_deduped_lines(aggregate_path, sorted({row["parameter"] for row in parameter_rows}))
            _append_deduped_lines(queue_path_value, sorted(endpoints))
            summary["parameter_sources"] = _append_deduped_jsonl(source_path, parameter_rows, key_fields=["endpoint", "parameter"])
            summary["endpoint_queue"] = str(queue_path_value)
    except Exception as exc:  # post-run artifacts should not break the scanner lifecycle
        summary["errors"].append(str(exc))

    report_path = expand_path(str(post_run.get("report_path") or DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "cron" / "latest_summary.md"))
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_lines = ["# Automated Recon Review", "", f"- Program: `{program}`", f"- Job: `{job.get('job')}`", f"- Run: `{run_id_value}`", f"- Target: `{host}`"]
    if summary.get("status_leads"):
        report_lines.append(f"- Interesting status leads added: `{summary['status_leads'].get('new', 0)}`")
    if summary.get("forbidden_leads"):
        report_lines.append(f"- Boundary leads (401/403/405) added: `{summary['forbidden_leads'].get('new', 0)}`")
    if summary.get("parameters"):
        report_lines.append(f"- Parameters added: `{summary['parameters'].get('new', 0)}`")
    report_lines.extend(["", "## Next review", "- Review boundary leads and unusual successful routes before deeper testing."])
    if summary["errors"]:
        report_lines.append("- Post-processing had recoverable errors; inspect the run manifest.")
    report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    summary["report_path"] = str(report_path)
    manifest["post_processing"] = summary
    return summary


def execute_job(
    program: str,
    job: dict[str, Any],
    run_id_value: str,
    *,
    execute: bool,
    approve_manual: bool,
    approved_jobs: set[str] | None,
    parent_block_reason: str | None,
    timeout_seconds: int | None,
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
                stdout_path = root / "logs" / "stdout.txt"
                stderr_path = root / "logs" / "stderr.txt"
                interval = progress_interval_seconds(job)
                with stdout_path.open("w", encoding="utf-8") as stdout_handle, stderr_path.open("w", encoding="utf-8") as stderr_handle:
                    proc = subprocess.Popen(command, text=True, stdout=stdout_handle, stderr=stderr_handle)
                    manifest["pid"] = proc.pid
                    write_job_heartbeat(root, manifest, pid=proc.pid, event="started")
                    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    deadline = time.monotonic() + timeout_seconds if timeout_seconds is not None else None
                    while True:
                        wait_seconds = interval
                        if deadline is not None:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                assert timeout_seconds is not None
                                proc.kill()
                                proc.wait()
                                raise subprocess.TimeoutExpired(command, timeout_seconds)
                            wait_seconds = min(wait_seconds, remaining)
                        try:
                            proc.wait(timeout=wait_seconds)
                            break
                        except subprocess.TimeoutExpired:
                            stdout_handle.flush()
                            stderr_handle.flush()
                            write_job_heartbeat(root, manifest, pid=proc.pid, event="progress")
                            (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                manifest["exit_code"] = proc.returncode
                manifest["status"] = "completed" if proc.returncode == 0 else "failed"
                write_job_heartbeat(root, manifest, pid=proc.pid, event="completed")
        except BlockingIOError:
            manifest["status"] = "blocked"
            manifest["block_reason"] = "run_lock_already_held"
        except subprocess.TimeoutExpired as exc:
            manifest["status"] = "failed"
            manifest["block_reason"] = "timeout"
            manifest["timeout_seconds"] = timeout_seconds
            stdout_path = root / "logs" / "stdout.txt"
            stderr_path = root / "logs" / "stderr.txt"
            if not stdout_path.exists():
                stdout_path.write_text(exc.stdout or "", encoding="utf-8")
            if not stderr_path.exists():
                stderr_path.write_text(exc.stderr or "", encoding="utf-8")
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
    if job.get("job") in {"nmap_enrichment", "juicy_target_fuzz", "authenticated_parameter_mining", "parameter_mining"} and manifest.get("status") == "completed":
        postprocess_completed_job(program, job, root, run_id_value, manifest)

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


def queue_entry_host(entry: dict[str, Any]) -> str:
    target = entry.get("target") if isinstance(entry.get("target"), dict) else {}
    payload = entry.get("job_payload") if isinstance(entry.get("job_payload"), dict) else {}
    payload_target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    return str(
        target.get("host")
        or entry.get("target_host")
        or payload_target.get("host")
        or payload.get("host")
        or ""
    ).lower()


def queue_entry_bucket_scopes(entry: dict[str, Any]) -> set[str]:
    scopes: set[str] = set()
    host = queue_entry_host(entry)
    if host:
        scopes.add(f"host:{host}")
        domain = registrable_domain(host)
        if domain:
            policy = entry.get("policy") if isinstance(entry.get("policy"), dict) else {}
            budget = policy.get("rate_budget") if isinstance(policy.get("rate_budget"), dict) else {}
            if str(budget.get("bucket_kind") or "") == "domain":
                scopes.add(f"domain:{domain}")
        policy = entry.get("policy") if isinstance(entry.get("policy"), dict) else {}
        budget = policy.get("rate_budget") if isinstance(policy.get("rate_budget"), dict) else {}
        addresses = [str(address) for address in budget.get("resolved_addresses") or ()]
        if not addresses:
            addresses = resolve_host_addresses(host)
        scopes.update(f"ip:{address}" for address in addresses)

    policy = entry.get("policy") if isinstance(entry.get("policy"), dict) else {}
    budget = policy.get("rate_budget") if isinstance(policy.get("rate_budget"), dict) else {}
    scope = budget.get("scope")
    if scope:
        scopes.add(str(scope))
    return scopes


def active_queue_bucket_scopes(queue: dict[str, Any], *, exclude_run_type: str | None = None) -> set[str]:
    queues = queue.get("queues") if isinstance(queue.get("queues"), dict) else {}
    scopes: set[str] = set()
    for run_type, section in queues.items():
        if exclude_run_type is not None and str(run_type) == exclude_run_type:
            continue
        if not isinstance(section, list):
            continue
        for entry in section:
            if isinstance(entry, dict) and str(entry.get("state") or "pending") == "running":
                scopes.update(queue_entry_bucket_scopes(entry))
    return scopes


def process_is_alive(pid_value: Any) -> bool:
    try:
        pid = int(pid_value)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def reap_stale_running_entries(queue: dict[str, Any], *, now: str | None = None) -> list[dict[str, Any]]:
    queues = queue.get("queues") if isinstance(queue.get("queues"), dict) else {}
    stale: list[dict[str, Any]] = []
    checked_at = now or utc_now()
    for run_type, section in queues.items():
        if not isinstance(section, list):
            continue
        for entry in section:
            if not isinstance(entry, dict) or str(entry.get("state") or "pending") != "running":
                continue
            worker_pid = entry.get("worker_pid")
            if worker_pid is None or process_is_alive(worker_pid):
                continue
            entry["state"] = "stale"
            entry["terminal_status"] = "stale"
            entry["stale_reason"] = "worker_pid_not_alive"
            entry["stale_checked_at"] = checked_at
            entry["updated_at"] = checked_at
            stale.append(
                {
                    "id": entry.get("id"),
                    "run_type": run_type,
                    "target_host": queue_entry_host(entry),
                    "worker_pid": worker_pid,
                    "reason": "worker_pid_not_alive",
                }
            )
    return stale


def sorted_pending_entries(
    queue: dict[str, Any],
    run_type: str,
    *,
    limit: int | None = None,
    avoid_scopes: set[str] | None = None,
) -> list[dict[str, Any]]:
    section = queue.get("queues", {}).get(run_type, [])
    if not isinstance(section, list):
        return []
    pending = [
        entry
        for entry in section
        if isinstance(entry, dict) and str(entry.get("state") or "pending") == "pending"
    ]
    pending.sort(key=lambda entry: (int(entry.get("priority") or 50), str(entry.get("created_at") or "")))
    selected: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    active_scopes = set(avoid_scopes or set())
    for entry in pending:
        entry_scopes = queue_entry_bucket_scopes(entry)
        if active_scopes and entry_scopes.intersection(active_scopes):
            blocked.append(entry)
            continue
        selected.append(entry)
        # Reserve scopes immediately: a multi-item drain must not select two
        # same-backend jobs before either one is transitioned to running.
        active_scopes.update(entry_scopes)
        if limit is not None and len(selected) >= limit:
            break
    if blocked:
        queue["_last_bucket_skips"] = [
            {
                "id": entry.get("id"),
                "run_type": entry.get("run_type"),
                "job": entry.get("job"),
                "target_host": queue_entry_host(entry),
                "bucket_scopes": sorted(queue_entry_bucket_scopes(entry)),
                "reason": "active_shared_bucket",
            }
            for entry in blocked
        ]
    else:
        queue["_last_bucket_skips"] = []
    return selected


def queue_counts(queue: dict[str, Any]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    queues = queue.get("queues") if isinstance(queue.get("queues"), dict) else {}
    for run_type, section in queues.items():
        if not isinstance(section, list):
            continue
        run_counts: dict[str, int] = {}
        for entry in section:
            if not isinstance(entry, dict):
                continue
            state = str(entry.get("state") or "pending")
            run_counts[state] = run_counts.get(state, 0) + 1
        counts[str(run_type)] = run_counts
    return counts


def rotate_bucket_skips_to_tail(queue: dict[str, Any], run_type: str) -> None:
    skipped_ids = {
        str(item.get("id"))
        for item in queue.get("_last_bucket_skips", [])
        if isinstance(item, dict) and item.get("id")
    }
    if not skipped_ids:
        return
    section = queue.get("queues", {}).get(run_type, [])
    if not isinstance(section, list):
        return
    kept: list[dict[str, Any]] = []
    moved: list[dict[str, Any]] = []
    for entry in section:
        if isinstance(entry, dict) and str(entry.get("id")) in skipped_ids:
            entry["deferred_at"] = utc_now()
            entry["defer_reason"] = "active_shared_bucket"
            moved.append(entry)
        else:
            kept.append(entry)
    section[:] = kept + moved


@contextlib.contextmanager
def queue_worker_lock(program: str, run_type: str):
    locks_dir = DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "cron" / ".locks"
    locks_dir.mkdir(parents=True, exist_ok=True)
    path = locks_dir / f"worker-{safe_slug(run_type)}.lock"
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        handle.seek(0)
        handle.truncate()
        handle.write(
            json.dumps({"pid": os.getpid(), "program": program, "run_type": run_type, "locked_at": utc_now()})
            + "\n"
        )
        handle.flush()
        try:
            yield str(path)
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def update_queue_entry(path: Path, run_type: str, entry_id: str, updates: dict[str, Any]) -> None:
    with locked_queue(path) as queue:
        section = queue.get("queues", {}).get(run_type, [])
        if isinstance(section, list):
            for entry in section:
                if isinstance(entry, dict) and entry.get("id") == entry_id:
                    entry.update(updates)
                    entry["updated_at"] = utc_now()
                    break
        queue["updated_at"] = utc_now()
        write_queue(path, queue)


def revalidate_queued_job(data: dict[str, Any], program: str, queued_job: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Rebuild a queued job from current scope/config before it can execute.

    Queue JSON is an untrusted transport layer: the stored command is never
    execution authority. A job must still be selected by the current plan and
    match its target plus command/rate material before the rebuilt job is run.
    """
    target = queued_job.get("target") if isinstance(queued_job.get("target"), dict) else {}
    base_url = str(target.get("base_url") or "")
    job_name = str(queued_job.get("job") or "")
    if not job_name or not base_url:
        return None, "queued_payload_missing_job_or_target"
    current_plan = plan(data, program)
    matches = [
        job for job in current_plan.get("jobs", [])
        if isinstance(job, dict)
        and str(job.get("job") or "") == job_name
        and isinstance(job.get("target"), dict)
        and str(job["target"].get("base_url") or "") == base_url
    ]
    if len(matches) != 1:
        return None, "queued_target_not_in_current_plan"
    rebuilt = matches[0]
    for field in ("command", "rate_budget"):
        if queued_job.get(field) != rebuilt.get(field):
            return None, f"queued_payload_{field}_mismatch_current_plan"
    return rebuilt, None


def drain_queue(
    data: dict[str, Any],
    program: str,
    *,
    run_type: str,
    limit: int = 1,
    execute: bool = False,
    approve_manual: bool = False,
    approved_jobs: set[str] | None = None,
    tmux: bool | None = None,
    tmux_session: str | None = None,
) -> dict[str, Any]:
    program_cfg = resolve_program(data, program)
    path = queue_path(data, program, program_cfg)
    run_id_value = execution_run_id()
    if limit < 1:
        limit = 1
    # Queue entries need durable completion reconciliation. Until a pane wrapper
    # owns that lifecycle, fail closed rather than marking a tmux launch as done.
    if execute and runtime_tmux_enabled(data, program_cfg, tmux):
        return {
            "run_id": run_id_value,
            "mode": "queue-drain",
            "program": program,
            "run_type": run_type,
            "queue_path": str(path),
            "status": "blocked",
            "block_reason": "queue_tmux_requires_durable_completion_wrapper",
        }

    with locked_queue(path) as queue:
        stale_entries = reap_stale_running_entries(queue)
        active_scopes = active_queue_bucket_scopes(queue)
        selected = sorted_pending_entries(queue, run_type, limit=limit, avoid_scopes=active_scopes)
        bucket_skips = list(queue.get("_last_bucket_skips") or [])
        if stale_entries:
            queue["updated_at"] = utc_now()
            write_queue(path, queue)
        if not execute:
            return {
                "run_id": run_id_value,
                "mode": "queue-preview",
                "program": program,
                "run_type": run_type,
                "queue_path": str(path),
                "selected_count": len(selected),
                "bucket_skip_count": len(bucket_skips),
                "bucket_skips": bucket_skips,
                "active_bucket_scopes": sorted(active_scopes),
                "stale_reaped_count": len(stale_entries),
                "stale_reaped": stale_entries,
                "entries": selected,
                "counts": queue_counts(queue),
            }
        rotate_bucket_skips_to_tail(queue, run_type)
        selected_ids = {str(entry.get("id")) for entry in selected}
        section = queue.get("queues", {}).get(run_type, [])
        if isinstance(section, list):
            for entry in section:
                if isinstance(entry, dict) and str(entry.get("id")) in selected_ids:
                    entry["state"] = "running"
                    entry["attempts"] = int(entry.get("attempts") or 0) + 1
                    entry["last_run_id"] = run_id_value
                    entry["worker_pid"] = os.getpid()
                    entry["worker_started_at"] = utc_now()
                    entry["updated_at"] = utc_now()
        queue["updated_at"] = utc_now()
        queue.pop("_last_bucket_skips", None)
        write_queue(path, queue)

    defaults = data.get("defaults") if isinstance(data.get("defaults"), dict) else {}
    rate_limit = defaults.get("rate_limit") if isinstance(defaults.get("rate_limit"), dict) else {}
    timeout_seconds = _compute_timeout(rate_limit, {"jobs": []}, program_cfg)
    parent_block = parent_state_reason(data, program, program_cfg)
    tmux_panes: list[dict[str, Any]] = []
    tmux_enabled = runtime_tmux_enabled(data, program_cfg, tmux)
    launch_mode = "tmux" if tmux_enabled and execute else "subprocess"
    results: list[dict[str, Any]] = []

    for entry in selected:
        queued_job = entry.get("job_payload") if isinstance(entry.get("job_payload"), dict) else {}
        if not queued_job:
            result = {"queue_entry_id": entry.get("id"), "execution_status": "blocked", "block_reason": "missing_job_payload"}
        else:
            job, validation_error = revalidate_queued_job(data, program, queued_job)
            if validation_error or job is None:
                result = {
                    "queue_entry_id": entry.get("id"),
                    "execution_status": "blocked",
                    "block_reason": validation_error or "queued_payload_revalidation_failed",
                }
            else:
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
                result["queue_entry_id"] = entry.get("id")
        state = str(result.get("execution_status") or "blocked")
        if state == "tmux_queued":
            queue_state = "running"
        elif state in {"completed", "failed", "blocked"}:
            queue_state = state
        else:
            queue_state = "failed"
        updates = {
            "state": queue_state,
            "terminal_status": None if queue_state == "running" else state,
            "run_root": result.get("run_root"),
            "manifest_path": result.get("manifest_path"),
            "execution_decision": result.get("execution_decision"),
            "block_reason": result.get("block_reason"),
            "last_result": {k: v for k, v in result.items() if k not in {"job_payload"}},
        }
        update_queue_entry(path, run_type, str(entry.get("id")), updates)
        results.append(result)

    payload = {
        "run_id": run_id_value,
        "mode": "queue-tmux" if launch_mode == "tmux" else "queue-drain",
        "program": program,
        "run_type": run_type,
        "queue_path": str(path),
        "selected_count": len(selected),
        "bucket_skip_count": len(bucket_skips),
        "bucket_skips": bucket_skips,
            "active_bucket_scopes": sorted(active_scopes),
            "stale_reaped_count": len(stale_entries),
            "stale_reaped": stale_entries,
            "jobs": results,
        }
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
    return payload


def runtime_worker_defaults(data: dict[str, Any], program_cfg: dict[str, Any]) -> dict[str, Any]:
    runtime = runtime_config(data, program_cfg)
    worker_cfg = runtime.get("worker") if isinstance(runtime.get("worker"), dict) else {}
    return {
        "limit": max(1, int(worker_cfg.get("limit") or 1)),
        "idle_sleep_seconds": float(worker_cfg.get("idle_sleep_seconds", 60)),
        "max_idle_cycles": int(worker_cfg.get("max_idle_cycles", 0)),
        "max_cycles": int(worker_cfg["max_cycles"]) if worker_cfg.get("max_cycles") is not None else None,
    }


def queue_worker(
    data: dict[str, Any],
    program: str,
    *,
    run_type: str,
    limit: int | None = None,
    execute: bool = False,
    approve_manual: bool = False,
    approved_jobs: set[str] | None = None,
    tmux: bool | None = None,
    tmux_session: str | None = None,
    idle_sleep_seconds: float | None = None,
    max_idle_cycles: int | None = None,
    max_cycles: int | None = None,
) -> dict[str, Any]:
    program_cfg = resolve_program(data, program)
    defaults = runtime_worker_defaults(data, program_cfg)
    effective_limit = max(1, int(limit if limit is not None else defaults["limit"]))
    effective_sleep = float(idle_sleep_seconds if idle_sleep_seconds is not None else defaults["idle_sleep_seconds"])
    effective_max_idle = int(max_idle_cycles if max_idle_cycles is not None else defaults["max_idle_cycles"])
    effective_max_cycles = max_cycles if max_cycles is not None else defaults["max_cycles"]
    path = queue_path(data, program, program_cfg)
    stop_path = queue_worker_stop_path(data, program, program_cfg, run_type)
    worker_run_id = execution_run_id()

    if not execute:
        preview = drain_queue(
            data,
            program,
            run_type=run_type,
            limit=effective_limit,
            execute=False,
            approve_manual=approve_manual,
            approved_jobs=approved_jobs,
            tmux=tmux,
            tmux_session=tmux_session,
        )
        return {
            "run_id": worker_run_id,
            "mode": "queue-worker-preview",
            "program": program,
            "run_type": run_type,
            "queue_path": str(path),
            "stop_file": str(stop_path),
            "preview": preview,
        }

    try:
        with queue_worker_lock(program, run_type) as lock_path:
            cycles = 0
            idle_cycles = 0
            drained_count = 0
            drains: list[dict[str, Any]] = []
            status = "idle"
            stop_reason = "idle_limit_reached" if effective_max_idle > 0 else "max_cycles_reached"

            while True:
                if stop_path.is_file():
                    status = "stopped"
                    stop_reason = "stop_file_present"
                    break
                if effective_max_cycles is not None and cycles >= effective_max_cycles:
                    status = "stopped"
                    stop_reason = "max_cycles_reached"
                    break

                drain = drain_queue(
                    data,
                    program,
                    run_type=run_type,
                    limit=effective_limit,
                    execute=True,
                    approve_manual=approve_manual,
                    approved_jobs=approved_jobs,
                    tmux=tmux,
                    tmux_session=tmux_session,
                )
                drains.append(drain)
                cycles += 1
                selected = int(drain.get("selected_count") or 0)
                drained_count += selected
                if selected:
                    idle_cycles = 0
                    status = "running"
                    continue

                idle_cycles += 1
                status = "idle"
                if effective_max_idle > 0 and idle_cycles >= effective_max_idle:
                    stop_reason = "idle_limit_reached"
                    break
                if effective_sleep > 0:
                    time.sleep(effective_sleep)

            return {
                "run_id": worker_run_id,
                "mode": "queue-worker",
                "status": status,
                "stop_reason": stop_reason,
                "program": program,
                "run_type": run_type,
                "queue_path": str(path),
                "worker_lock_path": lock_path,
                "stop_file": str(stop_path),
                "limit": effective_limit,
                "idle_sleep_seconds": effective_sleep,
                "max_idle_cycles": effective_max_idle,
                "max_cycles": effective_max_cycles,
                "cycles": cycles,
                "idle_cycles": idle_cycles,
                "drained_count": drained_count,
                "drains": drains,
            }
    except BlockingIOError:
        return {
            "run_id": worker_run_id,
            "mode": "queue-worker",
            "status": "blocked",
            "block_reason": "queue_worker_lock_already_held",
            "program": program,
            "run_type": run_type,
            "queue_path": str(path),
            "stop_file": str(stop_path),
        }


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
    enqueue: bool = False,
) -> dict[str, Any]:
    payload = plan(data, program, write=False)
    run_id_value = execution_run_id()
    program_cfg = resolve_program(data, program)
    if enqueue:
        payload["run_id"] = run_id_value
        payload["mode"] = "enqueue"
        payload["queue"] = enqueue_planned_jobs(data, program, payload, only_jobs=approved_jobs)
        payload["jobs"] = [
            {
                **job,
                "queue_status": "eligible" if job.get("status") == "planned" else "not_enqueued",
            }
            for job in payload["jobs"]
        ]
        if write:
            write_plan(program, payload, resolved_config=data)
        return payload

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
        approved_jobs=set(args.job) if args.job else None,
        write=True,
        tmux=True if args.tmux else None,
        tmux_session=args.tmux_session,
        enqueue=args.enqueue,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_queue_list(args: argparse.Namespace) -> int:
    data = load_scheduler_config(args.program, config_path=args.config, config_root=args.config_root)
    program_cfg = resolve_program(data, args.program)
    path = queue_path(data, args.program, program_cfg)
    queue = load_queue(path)
    queues = queue.get("queues") if isinstance(queue.get("queues"), dict) else {}
    if args.run_type:
        queues = {args.run_type: queues.get(args.run_type, [])}
    payload = {
        "program": args.program,
        "queue_path": str(path),
        "counts": queue_counts(queue),
        "queues": queues,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_queue_drain(args: argparse.Namespace) -> int:
    data = load_scheduler_config(args.program, config_path=args.config, config_root=args.config_root)
    payload = drain_queue(
        data,
        args.program,
        run_type=args.run_type,
        limit=args.limit,
        execute=args.run or args.execute,
        approve_manual=args.approve_manual,
        approved_jobs=set(args.job) if args.job else None,
        tmux=True if args.tmux else None,
        tmux_session=args.tmux_session,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_queue_worker(args: argparse.Namespace) -> int:
    data = load_scheduler_config(args.program, config_path=args.config, config_root=args.config_root)
    payload = queue_worker(
        data,
        args.program,
        run_type=args.run_type,
        limit=args.limit,
        execute=args.run or args.execute,
        approve_manual=args.approve_manual,
        approved_jobs=set(args.job) if args.job else None,
        tmux=True if args.tmux else None,
        tmux_session=args.tmux_session,
        idle_sleep_seconds=args.idle_sleep,
        max_idle_cycles=0 if args.forever else args.max_idle_cycles,
        max_cycles=args.max_cycles,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
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
        help="limit execution to a specific job name; omit to run all planned jobs that pass normal gates",
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
    run_parser.add_argument(
        "--enqueue",
        action="store_true",
        help="enqueue planned jobs into the shared program queue instead of executing or preparing run capsules",
    )
    run_parser.set_defaults(func=cmd_run)

    queue_list_parser = subparsers.add_parser("queue-list", help="list the shared queued-run store")
    queue_list_parser.add_argument("program")
    queue_list_parser.add_argument("--config")
    queue_list_parser.add_argument("--config-root", help="cron config root; defaults to agents/config/cron")
    queue_list_parser.add_argument("--run-type", help="show one queue section, such as nmap, fuzz, or parameter_mining")
    queue_list_parser.set_defaults(func=cmd_queue_list)

    queue_drain_parser = subparsers.add_parser("queue-drain", help="drain pending work for one run-type section")
    queue_drain_parser.add_argument("program")
    queue_drain_parser.add_argument("--config")
    queue_drain_parser.add_argument("--config-root", help="cron config root; defaults to agents/config/cron")
    queue_drain_parser.add_argument("--run-type", required=True, help="queue section to drain, such as nmap or fuzz")
    queue_drain_parser.add_argument("--limit", type=int, default=1, help="maximum pending queue entries to drain")
    queue_drain_parser.add_argument(
        "--run",
        action="store_true",
        help="execute drained jobs that pass state, scope, rate, lock, and manual-approval gates",
    )
    queue_drain_parser.add_argument("--execute", action="store_true", help="deprecated alias for --run")
    queue_drain_parser.add_argument(
        "--approve-manual",
        action="store_true",
        help="allow manual_review_required queued jobs to execute when --run is also set",
    )
    queue_drain_parser.add_argument(
        "--job",
        action="append",
        choices=sorted(EXECUTABLE_PLANNED_JOBS),
        help="limit queue execution to a specific job name",
    )
    queue_drain_parser.add_argument(
        "--tmux",
        action="store_true",
        help="queue drained scanner jobs in an inspectable tmux session instead of blocking in subprocess.run",
    )
    queue_drain_parser.add_argument("--tmux-session", help="tmux session name for --tmux")
    queue_drain_parser.set_defaults(func=cmd_queue_drain)

    queue_worker_parser = subparsers.add_parser("queue-worker", help="keep draining one queued-run section")
    queue_worker_parser.add_argument("program")
    queue_worker_parser.add_argument("--config")
    queue_worker_parser.add_argument("--config-root", help="cron config root; defaults to agents/config/cron")
    queue_worker_parser.add_argument("--run-type", required=True, help="queue section to drain, such as nmap or fuzz")
    queue_worker_parser.add_argument("--limit", type=int, help="maximum pending queue entries to drain per cycle")
    queue_worker_parser.add_argument(
        "--run",
        action="store_true",
        help="execute queued jobs that pass state, scope, rate, lock, and manual-approval gates",
    )
    queue_worker_parser.add_argument("--execute", action="store_true", help="deprecated alias for --run")
    queue_worker_parser.add_argument(
        "--approve-manual",
        action="store_true",
        help="allow manual_review_required queued jobs to execute when --run is also set",
    )
    queue_worker_parser.add_argument(
        "--job",
        action="append",
        choices=sorted(EXECUTABLE_PLANNED_JOBS),
        help="limit queue execution to a specific job name",
    )
    queue_worker_parser.add_argument(
        "--tmux",
        action="store_true",
        help="queue drained scanner jobs in an inspectable tmux session instead of blocking in subprocess.run",
    )
    queue_worker_parser.add_argument("--tmux-session", help="tmux session name for --tmux")
    queue_worker_parser.add_argument("--idle-sleep", type=float, help="seconds to sleep between empty queue polls")
    queue_worker_parser.add_argument(
        "--max-idle-cycles",
        type=int,
        help="stop after this many empty polls; 0 means keep waiting",
    )
    queue_worker_parser.add_argument("--max-cycles", type=int, help="stop after this many drain cycles")
    queue_worker_parser.add_argument("--forever", action="store_true", help="keep waiting after empty polls")
    queue_worker_parser.set_defaults(func=cmd_queue_worker)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
