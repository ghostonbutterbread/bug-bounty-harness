#!/usr/bin/env python3
"""Config-driven hybrid planner/worker orchestration for bug bounty runs.

The first implementation slice is intentionally conservative:
- planning is deterministic and safe by default
- CLI execution requires --execute
- worker request budgets default to 0, meaning no arbitrary hard cap while
  still carrying scope/rate/stop-condition policy into each packet
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


DEFAULT_PLANNER_ENGINE = "codex"
DEFAULT_PLANNER_MODEL = "gpt-5.5"
DEFAULT_WORKER_ENGINE = "opencode"
DEFAULT_WORKER_MODEL = "deepseek/deepseek-v4-pro"
DEFAULT_RATE_LIMIT = "from_scope"
DEFAULT_MAX_REQUESTS = 0
DEFAULT_WORKER_LIMIT = 8
DEFAULT_LINE_LIMIT = 5000
RUNS_DIRNAME = "hybrid-runs"

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
    prompt_path: str
    metadata_path: str


def utc_run_id(prefix: str = "hybrid") -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{stamp}"


def slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip().lower()).strip("-")
    return cleaned or "unnamed"


def shared_web_recon_root(program: str) -> Path:
    return Path.home() / "Shared" / "web_bounty" / program / "web" / "recon"


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
        "xss": ["deep-hunt", "dom-xss", "reflected-xss", "error-mapper"],
        "ssrf": ["deep-hunt", "ssrf", "error-mapper"],
        "api": ["deep-hunt", "headers", "error-mapper"],
        "auth": ["deep-hunt", "access-control", "jwt-auth", "error-triage"],
        "object": ["deep-hunt", "access-control", "idor"],
        "lfi": ["deep-hunt", "lfi", "error-mapper"],
        "sqli": ["deep-hunt", "sqli", "error-mapper"],
        "recon": ["deep-hunt", "url-ingest", "live-map"],
    }.get(lane, ["deep-hunt"])


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
- Do not store or print cookies, tokens, private headers, auth material, reset links, or secrets.

## Skills To Apply

{_bullet_list(packet.skills)}

## Representative URLs

{_bullet_list(packet.urls)}

## Route Clusters

{_bullet_list(packet.route_clusters)}

## Parameter Keys

{", ".join(packet.params) if packet.params else "none observed"}

## Required Output

Write artifacts under:
`{packet.output_dir}`

Required files:
- `attempts.jsonl` with one JSON object per deliberate observation.
- `summary.md` with exact boundaries, useful leads, and no inflated claims.
- `handoff.json` if this lane discovers follow-up work for another skill/model.

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
    statuses: dict[str, str] = {}
    processes: dict[str, subprocess.Popen[Any]] = {}

    if include_planner:
        planner_config = _engine_from_mapping(plan.get("config", {}).get("planner"), HybridConfig().planner)
        prompt_path = Path(str(plan["planner_packet"]))
        log_path = output_root / "logs" / "planner.log"
        processes["planner"] = spawn_cli_engine(
            planner_config,
            prompt_path=prompt_path,
            log_path=log_path,
            workdir=output_root,
            title="Hybrid planner",
        )

    for packet_payload in plan.get("worker_packets", []):
        packet_id = str(packet_payload.get("packet_id"))
        engine = _engine_from_mapping(packet_payload.get("engine"), HybridConfig().worker)
        prompt_path = Path(str(packet_payload.get("prompt_path")))
        log_path = output_root / "logs" / f"{slug(packet_id)}.log"
        Path(str(packet_payload.get("output_dir"))).mkdir(parents=True, exist_ok=True)
        processes[packet_id] = spawn_cli_engine(
            engine,
            prompt_path=prompt_path,
            log_path=log_path,
            workdir=Path(str(packet_payload.get("output_dir"))),
            title=f"Hybrid worker {packet_id}",
        )

    for key, process in processes.items():
        returncode = process.wait()
        statuses[key] = "completed" if returncode == 0 else f"failed:{returncode}"
        write_monitor_state(output_root, plan, worker_status=statuses)
    return statuses


def spawn_cli_engine(
    engine: EngineConfig,
    *,
    prompt_path: Path,
    log_path: Path,
    workdir: Path,
    title: str,
) -> subprocess.Popen[Any]:
    if engine.transport != "cli":
        raise NotImplementedError(f"hybrid runner currently executes CLI engines only, got transport={engine.transport}")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)
    command = command_for_engine(engine, prompt_path=prompt_path, workdir=workdir, title=title)
    log_handle = log_path.open("ab")
    env = os.environ.copy()
    env.update(engine.env)
    env.pop("CODEX_HOME", None)
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
            " 'Run the attached hybrid worker packet exactly. Write required artifacts under the packet output directory.'"
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
