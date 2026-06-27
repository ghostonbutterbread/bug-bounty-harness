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
import os
import re
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
LIVE_HTTP_JOBS = {
    "authenticated_parameter_mining",
    "juicy_target_fuzz",
    "parameter_mining",
}
EXECUTABLE_PLANNED_JOBS = LIVE_HTTP_JOBS | {"nmap_enrichment"}


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


def read_lines(path: Path, *, limit: int = 5000) -> list[str]:
    if not path.is_file():
        return []
    rows: list[str] = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            rows.append(value)
            if len(rows) >= limit:
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


def urls_from_url_ingest(path: Path, *, limit: int = 5000) -> list[str]:
    try:
        with sqlite3.connect(path) as conn:
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


def apply_rate_budgets(data: dict[str, Any], program_cfg: dict[str, Any], jobs: list[dict[str, Any]]) -> None:
    defaults = data.get("defaults") if isinstance(data.get("defaults"), dict) else {}
    cap = global_http_rps(defaults, program_cfg)
    grouped: dict[str, list[dict[str, Any]]] = {}

    for job in jobs:
        if job.get("job") not in LIVE_HTTP_JOBS or job.get("status") != "planned":
            continue
        target = job.get("target") if isinstance(job.get("target"), dict) else {}
        host = str(target.get("host") or "").lower()
        if not host:
            continue
        grouped.setdefault(host, []).append(job)

    for host, host_jobs in grouped.items():
        split_cap = max(1, cap // len(host_jobs))
        for job in host_jobs:
            job_cfg = program_cfg.get("jobs", {}).get(job["job"], {})
            requested = requested_http_rps(job["job"], job_cfg, defaults, program_cfg)
            allocated = max(1, min(requested, split_cap))
            budget = {
                "scope": f"host:{host}",
                "global_host_rps": cap,
                "concurrent_live_http_jobs": len(host_jobs),
                "requested_rps": requested,
                "allocated_rps": allocated,
                "policy": "split_evenly_by_host_then_cap_to_request",
            }
            job["rate_budget"] = budget
            if isinstance(job.get("command"), list):
                job["command"], rate_enforced = replace_command_rate(job["command"], allocated)
                job["rate_budget"]["command_rate_enforced"] = rate_enforced


def build_fuzz_plan(program_cfg: dict[str, Any], selected: TargetCandidate) -> dict[str, Any]:
    job = program_cfg.get("jobs", {}).get("juicy_target_fuzz", {})
    context = {
        "selected-base-url": selected.base_url,
        "composed-wordlist": "<dry-run-composed-wordlist>",
        "run-root": "<ffuf-run-root>",
    }
    command = [expand_pattern(str(part), context) for part in job.get("command_template") or ()]
    return {
        "job": "juicy_target_fuzz",
        "state": job.get("state", "unknown"),
        "status": "planned",
        "target": selected.to_dict(),
        "wordlists": job.get("wordlists", {}),
        "command": command,
    }


def build_parameter_plan(program_cfg: dict[str, Any], selected: TargetCandidate) -> dict[str, Any]:
    job = program_cfg.get("jobs", {}).get("authenticated_parameter_mining", {})
    context = {
        "endpoint-queue": str(expand_path(job.get("inputs", {}).get("endpoint_queue", "<endpoint-queue>"))),
        "run-root": "<arjun-run-root>",
    }
    command = [expand_pattern(str(part), context) for part in job.get("command_template") or ()]
    endpoint_queue = expand_path(job.get("inputs", {}).get("endpoint_queue", ""))
    return {
        "job": "authenticated_parameter_mining",
        "state": job.get("state", "unknown"),
        "status": "planned" if endpoint_queue.is_file() else "needs_endpoint_queue",
        "target": selected.to_dict(),
        "auth": job.get("auth", {}),
        "command": command,
    }


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
    selected = select_target(program, program_cfg)
    all_candidates = collect_target_candidates(program, program_cfg)
    candidates = [candidate.to_dict() for candidate in all_candidates[:25]]
    jobs = [
        build_nmap_plan(program, program_cfg, selected),
        build_fuzz_plan(program_cfg, selected),
        build_parameter_plan(program_cfg, selected),
    ]
    apply_rate_budgets(data, program_cfg, jobs)
    payload = {
        "run_id": run_id(),
        "mode": "dry-run",
        "program": program,
        "selected_target": selected.to_dict(),
        "candidate_count": len(all_candidates),
        "top_candidates": candidates,
        "rate_policy": {
            "global_http_rps": global_http_rps(
                data.get("defaults") if isinstance(data.get("defaults"), dict) else {},
                program_cfg,
            ),
            "scope": "per-host-or-app-area",
            "same_host_behavior": "split_evenly_across_concurrent_live_http_jobs",
        },
        "jobs": jobs,
    }
    if write:
        write_plan(program, payload)
    return payload


def default_cron_run_root(program: str, run_id_value: str) -> Path:
    return DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "cron" / "_runs" / run_id_value


def job_output_root(program: str, job: dict[str, Any], run_id_value: str) -> Path:
    outputs = job.get("outputs") if isinstance(job.get("outputs"), dict) else {}
    if outputs.get("run_root"):
        return render_runtime_path(str(outputs["run_root"]), run_id_value)
    return default_cron_run_root(program, run_id_value) / "outputs" / str(job.get("job", "job"))


def command_has_unresolved_placeholders(command: list[str]) -> bool:
    return any(bool(re.search(r"<[^>]+>", str(part))) for part in command)


def render_command(command: list[str], run_root: Path, run_id_value: str) -> list[str]:
    context = {
        "run-root": str(run_root),
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


def prepare_job_capsule(program: str, job: dict[str, Any], run_id_value: str) -> dict[str, Any]:
    root = job_output_root(program, job, run_id_value)
    raw = root / "raw"
    parsed = root / "parsed"
    normalized = root / "normalized"
    logs = root / "logs"
    for path in (raw, parsed, normalized, logs):
        path.mkdir(parents=True, exist_ok=True)

    command = render_command([str(part) for part in job.get("command") or ()], root, run_id_value)
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


def execution_decision(
    job: dict[str, Any],
    *,
    execute: bool,
    approve_manual: bool,
    approved_jobs: set[str] | None = None,
    parent_block_reason: str | None = None,
) -> tuple[bool, str]:
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
    )
    manifest["execution_decision"] = reason

    if not allowed:
        if reason == "execute_flag_not_set" or reason.startswith("planned_status_"):
            manifest["status"] = "prepared_not_executed"
        else:
            manifest["status"] = "blocked"
            manifest["block_reason"] = reason
    elif command_has_unresolved_placeholders(command):
        manifest["status"] = "blocked"
        manifest["block_reason"] = "unresolved_command_placeholders"
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
) -> dict[str, Any]:
    payload = plan(data, program, write=False)
    run_id_value = execution_run_id()
    program_cfg = resolve_program(data, program)
    defaults = data.get("defaults") if isinstance(data.get("defaults"), dict) else {}
    rate_limit = defaults.get("rate_limit") if isinstance(defaults.get("rate_limit"), dict) else {}
    timeout_seconds = int(rate_limit.get("timeout_seconds") or 300)
    parent_block = parent_state_reason(data, program, program_cfg)
    results = [
        execute_job(
            program,
            job,
            run_id_value,
            execute=execute,
            approve_manual=approve_manual,
            approved_jobs=approved_jobs,
            parent_block_reason=parent_block,
            timeout_seconds=timeout_seconds,
        )
        for job in payload["jobs"]
    ]
    payload.update(
        {
            "run_id": run_id_value,
            "mode": "execute" if execute else "prepare-only",
            "jobs": results,
        }
    )
    if write:
        write_plan(program, payload)
    return payload


def write_plan(program: str, payload: dict[str, Any]) -> None:
    root = DEFAULT_ARTIFACT_ROOT / program / "web" / "recon" / "cron" / "_runs" / payload["run_id"] / "_meta"
    root.mkdir(parents=True, exist_ok=True)
    plan_path = root / "resolved_plan.json"
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
    data = load_config(Path(args.config).expanduser())
    errors = validate_config(data)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("config ok")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    data = load_config(Path(args.config).expanduser())
    payload = plan(data, args.program, write=args.write)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    data = load_config(Path(args.config).expanduser())
    payload = run(
        data,
        args.program,
        execute=args.run or args.execute,
        approve_manual=args.approve_manual,
        approved_jobs=set(args.job or ()),
        write=True,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BBH cron orchestrator dry-run planner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="validate scheduler config")
    validate_parser.add_argument("--config", required=True)
    validate_parser.set_defaults(func=cmd_validate)

    plan_parser = subparsers.add_parser("plan", help="write or print dry-run plan")
    plan_parser.add_argument("program")
    plan_parser.add_argument("--config", required=True)
    plan_parser.add_argument("--write", action="store_true", help="write plan capsule under Shared web bounty storage")
    plan_parser.set_defaults(func=cmd_plan)

    run_parser = subparsers.add_parser("run", help="manually invoke the scheduler pipeline for one program")
    run_parser.add_argument("program")
    run_parser.add_argument("--config", required=True)
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
    run_parser.set_defaults(func=cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
