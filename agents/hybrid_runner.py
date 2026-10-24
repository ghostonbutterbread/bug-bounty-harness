#!/usr/bin/env python3
"""Config-driven hybrid planner/worker orchestration for bug bounty runs.

The first implementation slice is intentionally conservative:
- planning is deterministic and safe by default
- CLI execution requires --execute
- worker request budgets default to 0, meaning no arbitrary hard cap while
  still carrying scope/rate/stop-condition policy into each packet
- XSS continuation is an inert review packet, not the Hoster Bunny/Pi orchestrator
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.attempts import append_attempt, new_attempt_run_id, resolve_attempts_path


DEFAULT_PLANNER_ENGINE = "codex"
DEFAULT_PLANNER_MODEL = "gpt-5.5"
DEFAULT_WORKER_ENGINE = "opencode"
DEFAULT_WORKER_MODEL = "deepseek/deepseek-v4-pro"
DEFAULT_RATE_LIMIT = "from_scope"
DEFAULT_MAX_REQUESTS = 0
DEFAULT_WORKER_LIMIT = 8
DEFAULT_LINE_LIMIT = 5000
RUNS_DIRNAME = "hybrid-runs"
SANITIZED_ARTIFACT_SUFFIXES = {".json", ".jsonl", ".log", ".md", ".txt"}
REQUIRED_ATTEMPT_FIELDS = ("timestamp", "tool", "target", "outcome", "stop_reason")

ROLE_PARAM_HINTS: dict[str, set[str]] = {
    "xss": {"q", "query", "search", "keyword", "term", "title", "text", "name", "message", "content"},
    "ssrf": {"url", "uri", "callback", "webhook", "redirect", "redirect_uri", "next", "target", "image"},
    "lfi": {"file", "path", "template", "page", "dir", "folder", "download", "asset"},
    "auth": {"client_id", "redirect_uri", "nonce", "state", "scope", "response_type", "next"},
    "object": {"id", "design", "design_id", "template", "team", "user", "resource", "project"},
    "sqli": {"q", "query", "search", "filter", "sort", "order", "category", "page"},
}


@dataclass(frozen=True, slots=True)
class EngineConfig:
    engine: str
    model: str | None = None
    transport: str = "cli"
    command_template: str | None = None
    env: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HybridConfig:
    planner: EngineConfig = field(
        default_factory=lambda: EngineConfig(DEFAULT_PLANNER_ENGINE, DEFAULT_PLANNER_MODEL)
    )
    worker: EngineConfig = field(
        default_factory=lambda: EngineConfig(DEFAULT_WORKER_ENGINE, DEFAULT_WORKER_MODEL)
    )
    reviewer: EngineConfig = field(
        default_factory=lambda: EngineConfig(DEFAULT_PLANNER_ENGINE, DEFAULT_PLANNER_MODEL)
    )
    max_requests_per_worker: int = DEFAULT_MAX_REQUESTS
    rate_limit_rps: str = DEFAULT_RATE_LIMIT
    worker_limit: int = DEFAULT_WORKER_LIMIT
    monitor_workers: bool = True
    browser_escalation: str = "challenge_only"
    prefer_cli: bool = True
    lane_overrides: dict[str, EngineConfig] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class UrlRecord:
    url: str
    host: str
    path: str
    params: tuple[str, ...]
    cluster_key: str
    lane_hints: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WorkerPacket:
    packet_id: str
    lane: str
    title: str
    engine: EngineConfig
    max_requests: int
    rate_limit_rps: str
    urls: tuple[str, ...]
    route_clusters: tuple[str, ...]
    params: tuple[str, ...]
    skills: tuple[str, ...]
    output_dir: str
    scratch_dir: str
    attempt_run_id: str
    attempts_path: str
    prompt_path: str
    metadata_path: str


def utc_run_id(prefix: str = "hybrid") -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{stamp}"


def slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip().lower()).strip("-")
    return cleaned or "unnamed"


def shared_web_recon_root(program: str) -> Path:
    shared_base = Path(os.getenv("HARNESS_SHARED_BASE", "~/Shared/web_bounty")).expanduser()
    return shared_base / program / "web" / "recon"


def default_output_root(program: str, run_id: str) -> Path:
    return shared_web_recon_root(program) / RUNS_DIRNAME / run_id


def resolve_input_path(program: str, raw_input: str | Path) -> Path:
    path = Path(raw_input).expanduser()
    if path.exists():
        return path.resolve()
    aggregate = shared_web_recon_root(program) / "aggregated" / str(raw_input)
    if aggregate.exists():
        return aggregate.resolve()
    raise FileNotFoundError(
        f"input file not found: {raw_input}; also checked {aggregate}"
    )


def load_config(path: str | Path | None = None) -> HybridConfig:
    if path is None:
        env_path = os.getenv("BBH_HYBRID_CONFIG")
        path = env_path if env_path else None
    if path is None:
        return _config_from_environment(HybridConfig())
    config_path = Path(path).expanduser().resolve(strict=False)
    payload = _load_config_payload(config_path)
    return _config_from_environment(config_from_mapping(payload))


def _config_from_environment(config: HybridConfig) -> HybridConfig:
    planner = config.planner
    worker = config.worker
    reviewer = config.reviewer
    if os.getenv("BBH_HYBRID_PLANNER_ENGINE"):
        planner = EngineConfig(os.environ["BBH_HYBRID_PLANNER_ENGINE"], planner.model, planner.transport, planner.command_template, planner.env)
    if os.getenv("BBH_HYBRID_PLANNER_MODEL"):
        planner = EngineConfig(planner.engine, os.environ["BBH_HYBRID_PLANNER_MODEL"], planner.transport, planner.command_template, planner.env)
        reviewer = EngineConfig(reviewer.engine, os.environ["BBH_HYBRID_PLANNER_MODEL"], reviewer.transport, reviewer.command_template, reviewer.env)
    if os.getenv("BBH_HYBRID_WORKER_ENGINE"):
        worker = EngineConfig(os.environ["BBH_HYBRID_WORKER_ENGINE"], worker.model, worker.transport, worker.command_template, worker.env)
    if os.getenv("BBH_HYBRID_WORKER_MODEL"):
        worker = EngineConfig(worker.engine, os.environ["BBH_HYBRID_WORKER_MODEL"], worker.transport, worker.command_template, worker.env)
    return HybridConfig(
        planner=planner,
        worker=worker,
        reviewer=reviewer,
        max_requests_per_worker=config.max_requests_per_worker,
        rate_limit_rps=config.rate_limit_rps,
        worker_limit=config.worker_limit,
        monitor_workers=config.monitor_workers,
        browser_escalation=config.browser_escalation,
        prefer_cli=config.prefer_cli,
        lane_overrides=config.lane_overrides,
    )


def _load_config_payload(path: Path) -> Mapping[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("YAML config requires PyYAML; use JSON or install PyYAML") from exc
        payload = yaml.safe_load(text) or {}
    else:
        payload = json.loads(text or "{}")
    if not isinstance(payload, Mapping):
        raise ValueError(f"hybrid config must be an object: {path}")
    return payload


def config_from_mapping(payload: Mapping[str, Any]) -> HybridConfig:
    defaults = HybridConfig()
    return HybridConfig(
        planner=_engine_from_mapping(payload.get("planner"), defaults.planner),
        worker=_engine_from_mapping(payload.get("worker") or payload.get("worker_defaults"), defaults.worker),
        reviewer=_engine_from_mapping(payload.get("reviewer"), defaults.reviewer),
        max_requests_per_worker=_non_negative_int(
            payload.get("max_requests_per_worker", payload.get("max_requests", defaults.max_requests_per_worker))
        ),
        rate_limit_rps=str(payload.get("rate_limit_rps", defaults.rate_limit_rps)),
        worker_limit=_positive_int(payload.get("worker_limit", defaults.worker_limit)),
        monitor_workers=bool(payload.get("monitor_workers", defaults.monitor_workers)),
        browser_escalation=str(payload.get("browser_escalation", defaults.browser_escalation)),
        prefer_cli=bool(payload.get("prefer_cli", defaults.prefer_cli)),
        lane_overrides=_lane_overrides(payload.get("lanes") or payload.get("lane_overrides") or {}),
    )


def _engine_from_mapping(value: Any, default: EngineConfig) -> EngineConfig:
    if value is None:
        return default
    if isinstance(value, str):
        return EngineConfig(engine=value, model=default.model, transport=default.transport)
    if not isinstance(value, Mapping):
        raise ValueError(f"engine config must be object or string, got {type(value).__name__}")
    return EngineConfig(
        engine=str(value.get("engine", default.engine)),
        model=None if value.get("model", default.model) is None else str(value.get("model", default.model)),
        transport=str(value.get("transport", default.transport)),
        command_template=None
        if value.get("command_template", default.command_template) is None
        else str(value.get("command_template", default.command_template)),
        env={str(k): str(v) for k, v in dict(value.get("env") or default.env).items()},
    )


def _lane_overrides(value: Any) -> dict[str, EngineConfig]:
    if not isinstance(value, Mapping):
        return {}
    defaults = HybridConfig()
    overrides: dict[str, EngineConfig] = {}
    for lane, lane_config in value.items():
        if not isinstance(lane_config, Mapping):
            continue
        engine_config = lane_config.get("engine_config") if isinstance(lane_config.get("engine_config"), Mapping) else lane_config
        overrides[str(lane)] = _engine_from_mapping(engine_config, defaults.worker)
    return overrides


def apply_cli_overrides(config: HybridConfig, args: argparse.Namespace) -> HybridConfig:
    planner = config.planner
    worker = config.worker
    reviewer = config.reviewer
    if args.planner:
        planner = EngineConfig(args.planner, planner.model, planner.transport, planner.command_template, planner.env)
    if args.planner_model:
        planner = EngineConfig(planner.engine, args.planner_model, planner.transport, planner.command_template, planner.env)
        reviewer = EngineConfig(reviewer.engine, args.planner_model, reviewer.transport, reviewer.command_template, reviewer.env)
    if args.worker:
        worker = EngineConfig(args.worker, worker.model, worker.transport, worker.command_template, worker.env)
    if args.worker_model:
        worker = EngineConfig(worker.engine, args.worker_model, worker.transport, worker.command_template, worker.env)
    if args.subagent_model:
        worker = EngineConfig(worker.engine, args.subagent_model, worker.transport, worker.command_template, worker.env)
    max_requests = config.max_requests_per_worker
    if args.max_requests_per_worker is not None:
        max_requests = args.max_requests_per_worker
    worker_limit = config.worker_limit
    if args.worker_limit is not None:
        worker_limit = args.worker_limit
    return HybridConfig(
        planner=planner,
        worker=worker,
        reviewer=reviewer,
        max_requests_per_worker=max_requests,
        rate_limit_rps=args.rate_limit_rps or config.rate_limit_rps,
        worker_limit=worker_limit,
        monitor_workers=not args.no_monitor,
        browser_escalation=args.browser_escalation or config.browser_escalation,
        prefer_cli=config.prefer_cli,
        lane_overrides=config.lane_overrides,
    )


def read_url_records(path: Path, *, limit: int = DEFAULT_LINE_LIMIT) -> list[UrlRecord]:
    records: list[UrlRecord] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        if raw in seen:
            continue
        seen.add(raw)
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        params = tuple(sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
        path_shape = re.sub(r"/[A-Za-z0-9_-]{8,}(?=/|$)", "/{id}", parsed.path or "/")
        cluster_key = f"{parsed.netloc.lower()} {path_shape} ?{','.join(params)}"
        records.append(
            UrlRecord(
                url=raw,
                host=parsed.netloc.lower(),
                path=parsed.path or "/",
                params=params,
                cluster_key=cluster_key,
                lane_hints=tuple(classify_lanes(parsed.path or "/", params)),
            )
        )
        if len(records) >= limit:
            break
    return records


def classify_lanes(path: str, params: Sequence[str]) -> list[str]:
    lanes: set[str] = set()
    lower_path = path.lower()
    lower_params = {param.lower() for param in params}
    for lane, hints in ROLE_PARAM_HINTS.items():
        if lower_params & hints:
            lanes.add(lane)
    if any(part in lower_path for part in ("/search", "/template", "/apps", "/help")):
        lanes.add("xss")
    if any(part in lower_path for part in ("/api", "/_spi", "/webhook", "/embed", "/oembed")):
        lanes.add("ssrf")
        lanes.add("api")
    if any(part in lower_path for part in ("/auth", "/oauth", "/sso", "/callback", "/login")):
        lanes.add("auth")
    if any(part in lower_path for part in ("/design", "/project", "/team", "/share")):
        lanes.add("object")
    if not lanes:
        lanes.add("recon")
    return sorted(lanes)


def build_worker_packets(
    records: Sequence[UrlRecord],
    *,
    program: str,
    objective: str,
    config: HybridConfig,
    output_root: Path,
) -> list[WorkerPacket]:
    lane_records: dict[str, list[UrlRecord]] = {}
    for record in records:
        for lane in record.lane_hints:
            lane_records.setdefault(lane, []).append(record)

    lane_order = ["xss", "ssrf", "api", "auth", "object", "lfi", "sqli", "recon"]
    ordered_lanes = [lane for lane in lane_order if lane in lane_records]
    ordered_lanes.extend(sorted(set(lane_records) - set(ordered_lanes)))
    selected_lanes = ordered_lanes[: config.worker_limit]

    packets: list[WorkerPacket] = []
    packets_dir = output_root / "worker_packets"
    packets_dir.mkdir(parents=True, exist_ok=True)
    for index, lane in enumerate(selected_lanes, start=1):
        lane_items = lane_records[lane]
        representative = _representative_records(lane_items, limit=20)
        engine = config.lane_overrides.get(lane, config.worker)
        packet_id = f"W{index:03d}-{slug(lane)}"
        prompt_path = packets_dir / f"{packet_id}.md"
        metadata_path = packets_dir / f"{packet_id}.json"
        attempt_run_id = new_attempt_run_id()
        attempts_path = resolve_attempts_path(program, lane=lane, run_id=attempt_run_id)
        packet = WorkerPacket(
            packet_id=packet_id,
            lane=lane,
            title=_lane_title(lane),
            engine=engine,
            max_requests=config.max_requests_per_worker,
            rate_limit_rps=config.rate_limit_rps,
            urls=tuple(item.url for item in representative),
            route_clusters=tuple(sorted({item.cluster_key for item in representative})[:20]),
            params=tuple(sorted({param for item in representative for param in item.params})[:50]),
            skills=tuple(_lane_skills(lane)),
            output_dir=str(output_root / "workers" / packet_id),
            scratch_dir=str(output_root / "workers" / packet_id / "scratch"),
            attempt_run_id=attempt_run_id,
            attempts_path=str(attempts_path),
            prompt_path=str(prompt_path),
            metadata_path=str(metadata_path),
        )
        prompt_path.write_text(render_worker_prompt(packet, program=program, objective=objective), encoding="utf-8")
        metadata_path.write_text(json.dumps(packet_to_json(packet), indent=2, sort_keys=True), encoding="utf-8")
        packets.append(packet)
    return packets


def _representative_records(records: Sequence[UrlRecord], *, limit: int) -> list[UrlRecord]:
    by_cluster: dict[str, UrlRecord] = {}
    for record in records:
        by_cluster.setdefault(record.cluster_key, record)
    selected = list(by_cluster.values())
    selected.sort(key=lambda item: (-len(item.params), item.host, item.path, item.url))
    return selected[:limit]


def _lane_title(lane: str) -> str:
    return {
        "xss": "DOM/reflected XSS and frontend source-sink review",
        "ssrf": "URL-fetch, callback, embed, and SSRF-shaped review",
        "api": "API parser, response, and request-shape review",
        "auth": "Auth, OAuth, redirect, and session-boundary review",
        "object": "Object, template, design, and ownership-boundary review",
        "lfi": "Path, file, and traversal-boundary review",
        "sqli": "Search/filter parser and SQL-like error review",
        "recon": "General route classification and surface review",
    }.get(lane, f"{lane} review")


def _lane_skills(lane: str) -> list[str]:
    return {
        "xss": ["hunter-loop", "xss", "xss-lifecycle", "coverage", "leads"],
        "ssrf": ["hunter-loop", "ssrf", "error-mapper"],
        "api": ["hunter-loop", "headers", "error-mapper"],
        "auth": ["hunter-loop", "access-control", "jwt-auth", "error-triage"],
        "object": ["hunter-loop", "access-control", "idor"],
        "lfi": ["hunter-loop", "lfi", "error-mapper"],
        "sqli": ["hunter-loop", "sqli", "error-mapper"],
        "recon": ["hunter-loop", "url-ingest", "live-map"],
    }.get(lane, ["hunter-loop"])


def _lane_specific_guidance(packet: WorkerPacket) -> str:
    if packet.lane != "xss":
        return "No extra lane-specific instructions."
    return """XSS deep default:
- Do source-to-sink mapping before indiscriminate payload volume. For every selected
  plausible input, run and record an adaptive, context-appropriate live discovery
  sequence; no arbitrary initial-request cap applies. Signal controls escalation
  severity, not permission to begin testing.
- Record framework and edge clues before payload choice: React/Vue/Angular/router/state libraries, bundle names, CSP, WAF/challenge signal, and raw HTTP vs browser-rendered differences.
- Choose payload families from the observed context: marker/baseline, attribute breakout, tag breakout, event-handler, URL-scheme/navigation, template-literal/expression, JSON/XML/iframe attribute, hash/router source, storage/message source, or WAF/parser mutation.
- For every deliberate probe, write one attempts.jsonl row with payload family, source, sink/context, encoding or normalization result, browser result, and stop reason.
- Do not mark the XSS lane complete from raw HTTP alone when framework rendering or browser-only routing affects the route. Stop increasing payload volume once representative probes prove the context inert; switch source/sink hypothesis or hand off."""


def render_worker_prompt(packet: WorkerPacket, *, program: str, objective: str) -> str:
    request_budget = (
        "0 means no arbitrary hard cap; continue only while scoped, rate-limited, "
        "evidence-driven, and below stop conditions."
        if packet.max_requests == 0
        else str(packet.max_requests)
    )
    return f"""# Hybrid Worker Packet: {packet.packet_id}

Program: {program}
Lane: {packet.lane}
Title: {packet.title}
Engine: {packet.engine.engine}
Model: {packet.engine.model or "default"}
Objective: {objective}

## Budget And Policy

- Max requests for this worker: {request_budget}
- Rate limit: {packet.rate_limit_rps}
- Do not treat unlimited budget as permission to ignore scope, target stress, CAPTCHA/challenge, non-owned object boundaries, or side effects.
- Browser escalation policy: challenge/fingerprint/browser-only cases only; plain app/server 403/401 should be classified through the relevant 403/auth/access-control/error workflow first.
- Do not store or print cookies, tokens, private headers, auth material, reset links, nonce values, Set-Cookie headers, or secrets. When inspecting redirects or headers, filter or redact sensitive fields before they reach logs.
- Auth/session logging rule: never log cookie values, bearer values, CSRF values, nonce/state values, or full private headers. Log only the test-relevant state: user/account label if known, authenticated vs anonymous, cookie/header names and counts, redirect host/path with sensitive query values redacted, status code, content type, response length, stable response fingerprint, framework/JS/API clues, parameter behavior, and evidence artifact paths.

## Skills To Apply

{_bullet_list(packet.skills)}

## Lane-Specific Instructions

{_lane_specific_guidance(packet)}

## Representative URLs

{_bullet_list(packet.urls)}

## Route Clusters

{_bullet_list(packet.route_clusters)}

## Parameter Keys

{", ".join(packet.params) if packet.params else "none observed"}

For XSS, also read `worker_packets/{packet.packet_id}-mapped.md`: it retains the
source/field route pairing. The union above is not evidence that each field
exists on each route or reaches a sink.

## Required Output

Write artifacts under:
`{packet.output_dir}`

Use this packet-owned scratch directory for temporary files:
`{packet.scratch_dir}`

Do not write scratch files under `/tmp`, `/var/tmp`, the project repo, the user
home directory, or any path outside the packet output directory.

Required files:
- `summary.md` with exact boundaries, useful leads, and no inflated claims.
- `handoff.json` if this lane discovers follow-up work for another skill/model.

For an XSS continuation, write one `handoff.json` object with `source_route`
(host + path, without query values), `input_field` (literal named parameter or
`(path only)`), optional `input_location` (`query`, `path`, or `body`; default
`query` for named URL parameters), and `input_evidence_ref` for a body key
(an existing worker-owned run-relative JSON observation containing the same
`source_route`, `input_location: body`, and `input_field`; record names only,
never request values). Body keys are not inferred
from an API route: cite the observed request/key and leave it for reviewer
verification. Include `consumer` (`unknown` if not observed), `sink_context`
(`unknown`, `HTML text`, `HTML attribute`, `JavaScript`, `URL`, `DOM HTML`,
or `other`; name the precise sink in the cited handoff/evidence),
`chain_state` (`mapped` or `connected`), `observed_basis`, `candidate_chain`,
`blocker` (`none` if no prerequisite), `unknown`, `next_discriminator`, and
`evidence_refs` (nonempty list of existing run-relative artifact paths, e.g.
`classification.jsonl` and `workers/{packet.packet_id}/summary.md`). Do not
place credentials, query values, or synthetic examples in these fields. The
review card does not reproduce free-text handoff claims; inspect handoff and
cited evidence before promoting any observation. A mapped name or sink is not a
connected source-to-consumer edge. `connected` requires evidence for the actual
edge, not a name/proximity match. Do not claim XSS without execution proof.
The runner validates this handoff and writes a review-only follow-up packet;
it never dispatches follow-up target traffic. Promote reusable observed facts
through MapStore/Leads and map reviewed inputs through Coverage using their
canonical writers; this run-local card is not a competing evidence store.

Attempt staging context (injected by the harness):
- Run ID: `{packet.attempt_run_id}`
- Write a JSONL staging file at `$BBH_ATTEMPTS_PATH` inside this packet directory.
- The harness validates, redacts, and appends accepted rows through
  `agents.attempts.append_attempt`; workers must never write a canonical stream.

For every deliberate target-directed test, write a staging record and `summary.md`.
If you stop early because of policy, auth, challenge, rate limit, or target-stress
boundaries, write the corresponding Attempt boundary record.

## Attempt Recording Contract

Attempts are **not** a general live-observation log. They record each deliberate
application-directed test: payload, canary, representation, method/field/header,
role/object, timing, browser-action, or other meaningful request variation.
For every such test, write one `attempts.jsonl` record with what was sent,
payload family/technique, input location, changed dimension or comparison,
outcome, and stop/pivot reason. Include blocked, request-error, and inert results
when they arise from an attempt. Do not record passive reconnaissance or
untested ideas here.

When BBH is importable, use `agents.attempts.append_attempt`; it validates the
stable fields (`timestamp`, `tool`, `target`, `outcome`, `stop_reason`), creates
a redacted canonical Core row, and returns its `attempt_id`. Use that ID or the
sanitized Attempts path when promoting a fact to MapStore or preserving a future
branch in the Hypothesis Ledger. Read `docs/attempt-recording-contract.md` for
the full routing boundary. Do not put secrets into Attempts.

Stay focused on this lane. If a different lane becomes clearly relevant, create a handoff packet instead of absorbing all work into this worker.
"""


def render_planner_prompt(
    *,
    program: str,
    objective: str,
    input_path: Path,
    output_root: Path,
    config: HybridConfig,
    packets: Sequence[WorkerPacket],
) -> str:
    return f"""# Hybrid Planner Packet

Program: {program}
Planner engine: {config.planner.engine}
Planner model: {config.planner.model}
Objective: {objective}
Input: {input_path}
Output root: {output_root}

You are the goal-mode planner. Your job is to map at scale, keep the goal alive,
monitor worker artifacts, and decide whether the goal is actually complete.

## Worker Model

Default worker engine: {config.worker.engine}
Default worker model: {config.worker.model}
Max requests per worker: {config.max_requests_per_worker}

`max_requests_per_worker: 0` means no arbitrary hard cap. It does not remove
scope, rate, stop-condition, safety, or ownership boundaries.

## Worker Packets

{_bullet_list(Path(packet.prompt_path).name for packet in packets)}

## Planner Responsibilities

1. Read the classification and worker packets.
2. Confirm each worker owns one focused lane.
3. Monitor worker logs/artifacts if execution is enabled.
4. If a worker finishes, inspect its artifacts before deciding next steps.
5. If the overall goal is incomplete, create the next narrow packet rather than broadening an existing worker.
6. Prefer CLI engines by default. Use API engines only when config explicitly asks for them.

XSS `continuations/` packets are review-only proposals from validated worker
handoffs, not instructions to auto-dispatch. Verify evidence and obtain normal
scope/policy approval before any follow-up worker or target traffic. This runner
is distinct from the Hoster Bunny/Pi orchestrator.

Do not micromanage every request. Check whether workers are stuck, off-policy,
or finished, then re-plan.
"""


def build_plan(
    *,
    program: str,
    objective: str,
    input_path: Path,
    output_root: Path,
    config: HybridConfig,
    line_limit: int = DEFAULT_LINE_LIMIT,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    records = read_url_records(input_path, limit=line_limit)
    if not records:
        raise ValueError(f"no valid http(s) URLs found in {input_path}")
    packets = build_worker_packets(records, program=program, objective=objective, config=config, output_root=output_root)
    planner_prompt = render_planner_prompt(
        program=program,
        objective=objective,
        input_path=input_path,
        output_root=output_root,
        config=config,
        packets=packets,
    )
    planner_packet_path = output_root / "planner_packet.md"
    planner_packet_path.write_text(planner_prompt, encoding="utf-8")

    classification_path = output_root / "classification.jsonl"
    with classification_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(asdict(record), sort_keys=True))
            handle.write("\n")

    write_xss_mapping_cards(output_root, packets)

    input_copy = output_root / "input_urls.txt"
    input_copy.write_text("\n".join(record.url for record in records) + "\n", encoding="utf-8")

    plan = {
        "schema_version": 1,
        "program": program,
        "objective": objective,
        "input_path": str(input_path),
        "output_root": str(output_root),
        "planner_packet": str(planner_packet_path),
        "classification": str(classification_path),
        "input_urls": str(input_copy),
        "records": len(records),
        "clusters": len({record.cluster_key for record in records}),
        "config": config_to_json(config),
        "worker_packets": [packet_to_json(packet) for packet in packets],
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    (output_root / "plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True), encoding="utf-8")
    (output_root / "config.resolved.json").write_text(
        json.dumps(config_to_json(config), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    write_monitor_state(output_root, plan, worker_status={packet.packet_id: "planned" for packet in packets})
    return plan


def config_to_json(config: HybridConfig) -> dict[str, Any]:
    payload = asdict(config)
    return payload


def packet_to_json(packet: WorkerPacket) -> dict[str, Any]:
    payload = asdict(packet)
    payload["engine"] = asdict(packet.engine)
    return payload

def _xss_routes(packet: Mapping[str, Any]) -> dict[str, set[str]]:
    """Retain named input provenance rather than unioning fields across routes."""
    routes: dict[str, set[str]] = {}
    for url in packet.get("urls", []):
        parsed = urlparse(url)
        route = f"{parsed.netloc.lower()}{parsed.path or '/'}"
        routes.setdefault(route, set()).update(key for key, _ in parse_qsl(parsed.query, keep_blank_values=True))
    return routes

def _safe_card_value(value: Any) -> str:
    """Redact each derived-card value before interpolating it into Markdown."""
    redacted = redact_sensitive_text(str(value))
    return re.sub(r"(\bapi[_-]?key%3D)[^;\s\"',`/?&#]+", r"\1REDACTED", redacted, flags=re.IGNORECASE)


def write_xss_mapping_cards(output_root: Path, packets: Sequence[WorkerPacket]) -> None:
    """Run-local, non-canonical inventory; no sink or edge is inferred."""
    for packet in packets:
        if packet.lane != "xss":
            continue
        lines = ["# XSS mapped inputs (not a finding)", "", "Evidence: `classification.jsonl` (URL inventory only).", ""]
        for route, fields in _xss_routes(packet_to_json(packet)).items():
            for field_name in sorted(fields) if fields else ["(path only)"]:
                lines.extend((f"- Source/field route: `{_safe_card_value(route)}` / `{_safe_card_value(field_name)}`", "  Consumer: unknown; chain: mapped, not connected.",
                              "  Blocker: no observed input-to-consumer edge; unknown: render destination/context.",
                              "  Next discriminator: trace this named input to an owned consumer under the selected policy.", ""))
        (output_root / "worker_packets" / f"{packet.packet_id}-mapped.md").write_text("\n".join(lines), encoding="utf-8")

def _validated_xss_handoff(path: Path, packet: Mapping[str, Any], output_root: Path) -> dict[str, Any]:
    """Accept one bounded, source-attributed card, never executable instructions."""
    handoff = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(handoff, dict):
        raise ValueError("handoff-not-object")
    names = ("source_route", "input_field", "consumer", "chain_state", "observed_basis",
             "candidate_chain", "blocker", "unknown", "next_discriminator")
    if any(not isinstance(handoff.get(name), str) or not handoff[name].strip() or
           len(handoff[name]) > 500 or "\n" in handoff[name] or "\r" in handoff[name]
           for name in names):
        raise ValueError("missing-or-invalid-card-field")
    if handoff["chain_state"] not in {"mapped", "connected"}:
        raise ValueError("invalid-chain-state")
    context = handoff.get("sink_context", "unknown")
    if not isinstance(context, str) or context not in {"unknown", "HTML text", "HTML attribute", "JavaScript", "URL", "DOM HTML", "other"}:
        raise ValueError("invalid-sink-context")
    routes = _xss_routes(packet)
    route = handoff["source_route"]
    field = handoff["input_field"]
    location = handoff.get("input_location", "path" if field == "(path only)" else "query")
    if not isinstance(location, str) or route not in routes or location not in {"query", "path", "body"}:
        raise ValueError("source-not-in-packet")
    if location == "query" and field not in routes[route]:
        raise ValueError("source-not-in-packet")
    if location == "path" and (field != "(path only)" or routes[route]):
        raise ValueError("source-not-in-packet")
    if location == "body" and (field == "(path only)" or not field.strip()):
        raise ValueError("source-not-in-packet")
    if handoff["chain_state"] == "connected" and handoff["consumer"] == "unknown":
        raise ValueError("connected-without-consumer")
    if handoff["chain_state"] == "connected" and context == "unknown":
        raise ValueError("connected-without-sink-context")
    refs = handoff.get("evidence_refs")
    if not isinstance(refs, list) or not 1 <= len(refs) <= 8:
        raise ValueError("missing-evidence")
    for ref in refs:
        if not isinstance(ref, str) or len(ref) > 250 or not ref or Path(ref).is_absolute():
            raise ValueError("invalid-evidence-ref")
        target = (output_root / ref).resolve()
        if not target.is_relative_to(output_root.resolve()) or not target.is_file():
            raise ValueError("evidence-outside-run-or-missing")
    worker_prefix = f"workers/{packet['packet_id']}/"
    if handoff["chain_state"] == "connected" and not any(
        ref.startswith(worker_prefix) and ref != f"{worker_prefix}handoff.json" for ref in refs
    ):
        raise ValueError("connected-without-worker-evidence")
    if location == "body":
        observation = handoff.get("input_evidence_ref")
        if (not isinstance(observation, str) or observation not in refs or
                not observation.startswith(worker_prefix) or observation == f"{worker_prefix}handoff.json"):
            raise ValueError("body-without-worker-observation")
        try:
            observed = json.loads((output_root / observation).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            raise ValueError("invalid-body-observation") from None
        if not isinstance(observed, dict) or any(observed.get(key) != value for key, value in (
            ("source_route", route), ("input_location", "body"), ("input_field", field)
        )):
            raise ValueError("body-observation-mismatch")
    return handoff

def write_xss_continuation(output_root: Path, packet: Mapping[str, Any]) -> str:
    """Generate an inert review packet; never spawn from a worker handoff."""
    packet_id = str(packet["packet_id"])
    path = output_root / "workers" / packet_id / "handoff.json"
    card_path = output_root / "continuations" / f"{packet_id}.md"
    card_path.unlink(missing_ok=True)
    if not path.is_file():
        return "none"
    try:
        card = _validated_xss_handoff(path, packet, output_root)
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return f"rejected:{str(exc) if isinstance(exc, ValueError) else 'invalid-json'}"
    # Redact each dynamic value before interpolation, including provenance and paths.
    # Sanitizing worker artifacts alone does not protect cards written afterwards.
    safe = _safe_card_value
    card_path.parent.mkdir(parents=True, exist_ok=True)
    card_path.write_text("\n".join((
        f"# XSS chain card / review-only follow-up: {safe(packet_id)}", "",
        "Owner: XSS specialist (manual admission required). No automatic dispatch or target traffic.",
        f"Source/field route (worker-reported): {safe(card['source_route'])} / {safe(card['input_field'])}",
        f"Input location: {safe(card.get('input_location', 'path' if card['input_field'] == '(path only)' else 'query'))}",
        f"Consumer (worker-reported): {safe(card['consumer'])}",
        f"Sink context (worker-reported): {safe(card.get('sink_context', 'unknown'))}",
        f"Worker-reported state: {safe(card['chain_state'])} (not XSS proof)",
        f"Observed basis (worker-reported): {safe(card['observed_basis'])}",
        f"Candidate chain (worker-reported): {safe(card['candidate_chain'])}",
        f"Blocker (worker-reported): {safe(card['blocker'])}",
        f"Unknown (worker-reported): {safe(card['unknown'])}",
        f"Next discriminator (worker-reported): {safe(card['next_discriminator'])}",
        "Evidence pointers (run-relative, existence checked, not proof):",
        *(f"- {safe(ref)}" for ref in card['evidence_refs']),
        f"Worker handoff: {safe(f'workers/{packet_id}/handoff.json')}", "",
        "Follow-up packet: verify the cited edge and scope/ownership first; choose the XSS lane via",
        "the xss router, then apply live-testing policy before any probe. Record actual tests in",
        "Attempts, mapped questions in Coverage, and reusable unresolved observations in Leads/MapStore.",
        "A mapped input or named sink is not a connected chain or confirmed XSS.", "",
    )), encoding="utf-8")
    return "planned"


def write_monitor_state(output_root: Path, plan: Mapping[str, Any], *, worker_status: Mapping[str, str]) -> None:
    state = {
        "run_id": output_root.name,
        "planner": plan.get("config", {}).get("planner"),
        "monitor_workers": plan.get("config", {}).get("monitor_workers"),
        "worker_status": dict(worker_status),
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    (output_root / "monitor_state.json").write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def execute_plan(plan: Mapping[str, Any], *, include_planner: bool = False) -> dict[str, str]:
    output_root = Path(str(plan["output_root"]))
    statuses: dict[str, str] = {
        str(packet_payload.get("packet_id")): "planned"
        for packet_payload in plan.get("worker_packets", [])
    }
    processes: dict[str, subprocess.Popen[Any]] = {}
    for packet_payload in plan.get("worker_packets", []):
        if packet_payload.get("lane") == "xss":
            packet_id = str(packet_payload["packet_id"])
            (output_root / "continuations" / f"{packet_id}.md").unlink(missing_ok=True)
            (output_root / "workers" / packet_id / "handoff.json").unlink(missing_ok=True)
    (output_root / "continuation_state.json").unlink(missing_ok=True)
    write_monitor_state(output_root, plan, worker_status=statuses)

    for packet_payload in plan.get("worker_packets", []):
        packet_id = str(packet_payload.get("packet_id"))
        engine = _engine_from_mapping(packet_payload.get("engine"), HybridConfig().worker)
        prompt_path = Path(str(packet_payload.get("prompt_path")))
        log_path = output_root / "logs" / f"{slug(packet_id)}.log"
        output_dir = Path(str(packet_payload.get("output_dir")))
        output_dir.mkdir(parents=True, exist_ok=True)
        Path(str(packet_payload.get("scratch_dir", output_dir / "scratch"))).mkdir(parents=True, exist_ok=True)
        processes[packet_id] = spawn_cli_engine(
            engine,
            prompt_path=prompt_path,
            log_path=log_path,
            workdir=output_dir,
            title=f"Hybrid worker {packet_id}",
            extra_env={
                "BBH_ATTEMPT_RUN_ID": str(packet_payload["attempt_run_id"]),
                "BBH_ATTEMPTS_PATH": str(output_dir / "attempts.staged.jsonl"),
            },
        )
        statuses[packet_id] = "running"
        write_monitor_state(output_root, plan, worker_status=statuses)

    for key, process in processes.items():
        returncode = process.wait()
        packet_dir = Path(str(_packet_output_dir(plan, key)))
        packet_payload = _packet_payload(plan, key)
        canonical_attempts_path = Path(str(packet_payload["attempts_path"]))
        staged_attempts_path = packet_dir / "attempts.staged.jsonl"
        sanitize_artifacts(packet_dir)
        try:
            ingest_staged_attempts(staged_attempts_path, canonical_attempts_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            statuses[key] = f"incomplete:canonical-attempts:{exc}"
            write_monitor_state(output_root, plan, worker_status=statuses)
            continue
        missing_artifacts = missing_required_worker_artifacts(
            packet_dir,
            attempts_path=canonical_attempts_path,
        )
        if returncode != 0:
            statuses[key] = f"failed:{returncode}"
        elif missing_artifacts:
            statuses[key] = f"incomplete:missing-artifacts:{','.join(missing_artifacts)}"
        else:
            statuses[key] = "completed"
        write_monitor_state(output_root, plan, worker_status=statuses)
    continuation_status = {}
    for packet_payload in plan.get("worker_packets", []):
        key = str(packet_payload.get("packet_id"))
        if packet_payload.get("lane") == "xss":
            continuation_status[key] = (write_xss_continuation(output_root, packet_payload)
                                        if statuses[key] == "completed" else "skipped:worker-incomplete")
    if continuation_status:
        (output_root / "continuation_state.json").write_text(
            json.dumps(continuation_status, indent=2, sort_keys=True), encoding="utf-8")
    if include_planner:
        planner_config = _engine_from_mapping(plan.get("config", {}).get("planner"), HybridConfig().planner)
        prompt_path = Path(str(plan["planner_packet"]))
        log_path = output_root / "logs" / "planner.log"
        statuses["planner"] = "running"
        write_monitor_state(output_root, plan, worker_status=statuses)
        planner = spawn_cli_engine(
            planner_config,
            prompt_path=prompt_path,
            log_path=log_path,
            workdir=output_root,
            title="Hybrid planner",
        )
        returncode = planner.wait()
        sanitize_artifacts(output_root)
        statuses["planner"] = "completed" if returncode == 0 else f"failed:{returncode}"
        write_monitor_state(output_root, plan, worker_status=statuses)
    return statuses


def _packet_payload(plan: Mapping[str, Any], packet_id: str) -> Mapping[str, Any]:
    for packet_payload in plan.get("worker_packets", []):
        if str(packet_payload.get("packet_id")) == packet_id:
            return packet_payload
    raise KeyError(f"worker packet not found: {packet_id}")


def _packet_output_dir(plan: Mapping[str, Any], packet_id: str) -> str:
    try:
        return str(_packet_payload(plan, packet_id)["output_dir"])
    except KeyError:
        return str(Path(str(plan["output_root"])) / "workers" / slug(packet_id))


def ingest_staged_attempts(staged_path: Path, canonical_path: Path) -> None:
    """Validate worker staging then append it once through the canonical writer.

    Workers never receive a writable canonical evidence path; their staging file
    may be redacted or discarded without mutating historical evidence.
    """
    if not staged_path.exists():
        return
    if not staged_path.is_file() or not _is_valid_jsonl(staged_path):
        raise ValueError("invalid-staged-attempts")
    for line in staged_path.read_text(encoding="utf-8").splitlines():
        append_attempt(canonical_path, json.loads(line))


def missing_required_worker_artifacts(packet_dir: Path, *, attempts_path: Path | None = None) -> list[str]:
    required = ["summary.md"]
    missing = [name for name in required if not (packet_dir / name).is_file()]
    if attempts_path is None:
        attempts_path = packet_dir / "attempts.jsonl"
    if not attempts_path.is_file():
        missing.append("canonical-attempts:missing")
    elif not _is_valid_jsonl(attempts_path):
        missing.append("canonical-attempts:invalid-jsonl")
    return missing


def _is_valid_jsonl(path: Path) -> bool:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not lines:
        return False
    for line in lines:
        if not line.strip():
            return False
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not isinstance(row, dict):
            return False
        if any(not isinstance(row.get(field), str) or not row[field].strip() for field in REQUIRED_ATTEMPT_FIELDS):
            return False
    return True


def sanitize_artifacts(root: Path) -> None:
    """Redact sensitive values from worker-created artifacts, not only logs."""

    if not root.exists():
        return
    files = [root] if root.is_file() else [
        path for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in SANITIZED_ARTIFACT_SUFFIXES
    ]
    for path in files:
        try:
            original = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        redacted = redact_sensitive_text(original)
        if redacted != original:
            path.write_text(redacted, encoding="utf-8")


def redact_sensitive_text(text: str) -> str:
    redacted = re.sub(r"([?&]nonce=)[A-Za-z0-9._~%+-]+", r"\1REDACTED", text, flags=re.IGNORECASE)
    redacted = re.sub(r"(nonce%3D)[A-Za-z0-9._~%+-]+", r"\1REDACTED", redacted, flags=re.IGNORECASE)
    redacted = re.sub(
        r"((?:[?&]|\\u0026)__cf_chl_[A-Za-z0-9_%-]*tk=)[A-Za-z0-9._~%+-]+",
        r"\1REDACTED",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(r"(?im)^(\s*<?\s*set-cookie:\s*).*$", r"\1REDACTED", redacted)
    redacted = re.sub(r"(?im)^(\s*<?\s*cookie:\s*).*$", r"\1REDACTED", redacted)
    redacted = re.sub(r'("set-cookie:\s*)[^"]+(")', r"\1REDACTED\2", redacted, flags=re.IGNORECASE)
    redacted = re.sub(r'("cookie:\s*)[^"]+(")', r"\1REDACTED\2", redacted, flags=re.IGNORECASE)
    redacted = re.sub(
        r'("Cookie"\s*:\s*")(?!none"|REDACTED")[^"]+(")',
        r"\1REDACTED\2",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r'("Authorization"\s*:\s*"Bearer\s+)[^"]+(")',
        r"\1REDACTED\2",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(Authorization:\s*Bearer\s+)[A-Za-z0-9._~+/-]+",
        r"\1REDACTED",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(\b(?:TOKEN|NONCE|SESSION|COOKIE)\b\s*=)[^;\s\"']+",
        r"\1REDACTED",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(access[_-]?token[\"'\s:=]+)[A-Za-z0-9._~+/-]+",
        r"\1REDACTED",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(\bapi[_-]?key\b[\"']?\s*[:=]\s*[\"']?)[^;\s\"',`]+",
        r"\1REDACTED",
        redacted,
        flags=re.IGNORECASE,
    )
    return redacted


def spawn_cli_engine(
    engine: EngineConfig,
    *,
    prompt_path: Path,
    log_path: Path,
    workdir: Path,
    title: str,
    extra_env: Mapping[str, str] | None = None,
) -> subprocess.Popen[Any]:
    if engine.transport != "cli":
        raise NotImplementedError(f"hybrid runner currently executes CLI engines only, got transport={engine.transport}")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)
    scratch_dir = workdir / "scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True)
    command = sanitized_log_command(command_for_engine(engine, prompt_path=prompt_path, workdir=workdir, title=title))
    log_handle = log_path.open("ab")
    env = os.environ.copy()
    env.update(engine.env)
    if extra_env:
        env.update(extra_env)
    env.pop("CODEX_HOME", None)
    env.setdefault("TMPDIR", str(scratch_dir))
    env.setdefault("TMP", str(scratch_dir))
    env.setdefault("TEMP", str(scratch_dir))
    env.setdefault("OPENCODE_WORKER_OUTPUT_DIR", str(workdir))
    env.setdefault("OPENCODE_WORKER_SCRATCH_DIR", str(scratch_dir))
    process = subprocess.Popen(
        ["bash", "-lc", command],
        cwd=str(workdir),
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        env=env,
    )
    setattr(process, "_bbh_log_handle", log_handle)
    return process


def sanitized_log_command(command: str) -> str:
    """Wrap a CLI command so sensitive output is redacted before log capture."""

    return (
        "set -o pipefail; "
        f"( {command} ) 2>&1 | "
        "perl -pe "
        + shlex.quote(
            r"s/([?&]nonce=)[A-Za-z0-9._~%+-]+/${1}REDACTED/gi; "
            r"s/(nonce%3D)[A-Za-z0-9._~%+-]+/${1}REDACTED/gi; "
            r"s/((?:[?&]|\\u0026)__cf_chl_[A-Za-z0-9_%-]*tk=)[A-Za-z0-9._~%+-]+/${1}REDACTED/gi; "
            r"s/^(\s*<?\s*set-cookie:\s*).*$/\1REDACTED/gi; "
            r"s/^(\s*<?\s*cookie:\s*).*$/\1REDACTED/gi; "
            r"s/(\b(?:TOKEN|NONCE|SESSION|COOKIE)\b\s*=)[^;\s]+/${1}REDACTED/gi; "
            r"s/(Authorization:\s*Bearer\s+)[A-Za-z0-9._~+\/-]+/${1}REDACTED/gi; "
            r"s/(access[_-]?token[\"'\s:=]+)[A-Za-z0-9._~+\/-]+/${1}REDACTED/gi;"
        )
    )


def command_for_engine(engine: EngineConfig, *, prompt_path: Path, workdir: Path, title: str) -> str:
    if engine.command_template:
        return engine.command_template.format(
            prompt_path=shlex.quote(str(prompt_path)),
            workdir=shlex.quote(str(workdir)),
            model=shlex.quote(str(engine.model or "")),
            title=shlex.quote(title),
        )
    name = engine.engine.strip().lower()
    model = engine.model or ""
    if name == "codex":
        model_arg = f" --model {shlex.quote(model)}" if model else ""
        return (
            "codex exec -s workspace-write --skip-git-repo-check"
            f"{model_arg} --cd {shlex.quote(str(workdir))} < {shlex.quote(str(prompt_path))}"
        )
    if name == "opencode":
        model_arg = f" --model {shlex.quote(model)}" if model else ""
        return (
            "opencode run"
            f"{model_arg} --dir {shlex.quote(str(workdir))}"
            f" --file {shlex.quote(str(prompt_path))}"
            f" --title {shlex.quote(title)}"
            " 'Run the attached hybrid worker packet exactly. Write required artifacts under the packet output directory. "
            "Use ./scratch for temporary files; do not use /tmp or paths outside the packet output directory.'"
        )
    if name == "claude":
        return f"claude --print --permission-mode bypassPermissions < {shlex.quote(str(prompt_path))}"
    raise ValueError(f"unsupported hybrid CLI engine: {engine.engine}")


def _bullet_list(values: Iterable[str]) -> str:
    items = [str(value).strip() for value in values if str(value).strip()]
    return "\n".join(f"- {item}" for item in items) if items else "- none"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hybrid Codex planner + swappable worker CLI orchestrator.")
    subparsers = parser.add_subparsers(dest="command", metavar="command")
    deep = subparsers.add_parser("deep-dive", help="plan or run a hybrid deep-dive over URL/recon input")
    deep.add_argument("mode", help="requested mode, e.g. recon, xss, ssrf, fuzz")
    deep.add_argument("program", help="program slug, e.g. canva")
    deep.add_argument("--input", "-i", required=True, help="input URL file; relative names resolve from program aggregate store")
    deep.add_argument("--objective", help="human-readable objective; defaults from mode/input")
    deep.add_argument("--config", help="JSON/YAML hybrid config path; env BBH_HYBRID_CONFIG also supported")
    deep.add_argument("--run-id", help="explicit run id")
    deep.add_argument("--output-dir", help="explicit output directory")
    deep.add_argument("--planner", choices=("codex", "opencode", "claude"), help="planner CLI engine")
    deep.add_argument("--planner-model", help="planner model, default gpt-5.5")
    deep.add_argument("--worker", choices=("opencode", "codex", "claude"), help="default worker CLI engine")
    deep.add_argument("--worker-model", help="default worker model")
    deep.add_argument("--subagent-model", help="alias for --worker-model")
    deep.add_argument(
        "--max-requests-per-worker",
        type=_non_negative_int,
        default=None,
        help="0 means no arbitrary hard cap; still policy/rate/stop-condition bounded",
    )
    deep.add_argument("--rate-limit-rps", help="rate limit label/value passed into worker packets")
    deep.add_argument("--worker-limit", type=_positive_int, help="maximum worker packets to create")
    deep.add_argument("--line-limit", type=_positive_int, default=DEFAULT_LINE_LIMIT, help="maximum input URLs to classify")
    deep.add_argument("--browser-escalation", choices=("challenge_only", "always", "never"), help="worker browser escalation policy label")
    deep.add_argument("--no-monitor", action="store_true", help="disable planner/runner monitor state")
    deep.add_argument("--execute", action="store_true", help="actually spawn configured CLI workers")
    deep.add_argument("--include-planner", action="store_true", help="when executing, also spawn the planner CLI packet")
    deep.set_defaults(func=_cmd_deep_dive)

    status = subparsers.add_parser("status", help="show hybrid run status")
    status.add_argument("run_dir", help="hybrid run output directory")
    status.set_defaults(func=_cmd_status)
    return parser


def _cmd_deep_dive(args: argparse.Namespace) -> int:
    config = apply_cli_overrides(load_config(args.config), args)
    input_path = resolve_input_path(args.program, args.input)
    run_id = args.run_id or utc_run_id(f"hybrid-{slug(args.program)}-{slug(args.mode)}")
    output_root = Path(args.output_dir).expanduser().resolve(strict=False) if args.output_dir else default_output_root(args.program, run_id)
    objective = args.objective or f"Hybrid deep dive {args.mode} into {input_path.name}"
    plan = build_plan(
        program=args.program,
        objective=objective,
        input_path=input_path,
        output_root=output_root,
        config=config,
        line_limit=args.line_limit,
    )
    result: dict[str, Any] = {
        "run_id": output_root.name,
        "output_root": str(output_root),
        "plan": str(output_root / "plan.json"),
        "planner_packet": plan["planner_packet"],
        "worker_packets": len(plan["worker_packets"]),
        "records": plan["records"],
        "clusters": plan["clusters"],
        "execute": bool(args.execute),
        "max_requests_per_worker": config.max_requests_per_worker,
        "planner": asdict(config.planner),
        "worker": asdict(config.worker),
    }
    if args.execute:
        result["execution_status"] = execute_plan(plan, include_planner=bool(args.include_planner))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).expanduser().resolve(strict=False)
    plan_path = run_dir / "plan.json"
    state_path = run_dir / "monitor_state.json"
    payload = {
        "run_dir": str(run_dir),
        "plan_exists": plan_path.exists(),
        "monitor_state_exists": state_path.exists(),
    }
    if plan_path.exists():
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        payload.update(
            {
                "records": plan.get("records"),
                "clusters": plan.get("clusters"),
                "worker_packets": len(plan.get("worker_packets") or []),
                "max_requests_per_worker": plan.get("config", {}).get("max_requests_per_worker"),
            }
        )
    if state_path.exists():
        payload["monitor_state"] = json.loads(state_path.read_text(encoding="utf-8"))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _non_negative_int(value: Any) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be >= 0")
    return parsed


def _positive_int(value: Any) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be > 0")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
