"""Offline-first Recon surface map normalizer."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse, urlunparse

_AGENT_DIR = Path(__file__).resolve().parents[1]
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

from bounty_core_bootstrap import ensure_bounty_core_importable

ensure_bounty_core_importable("bounty_core.recon")

from bounty_core.recon import start_run, write_manifest

from .models import EvidenceSource, ReconSurfaceRecord, SURFACE_FAMILIES, utc_now


KNOWN_TEXT_FILES = {
    "alive.txt",
    "all_urls.txt",
    "endpoints.txt",
    "hosts.txt",
    "jsfiles.txt",
    "routes.txt",
    "subdomains.txt",
    "urls.txt",
}
KNOWN_JSON_SUFFIXES = {".json", ".jsonl", ".ndjson"}
MAX_LOCAL_FILE_BYTES = 1_000_000

FAMILY_SKILLS = {
    "auth-session-flow": ["access-control", "csrf", "headers", "xss"],
    "account-tenant-object": ["access-control", "idor", "race"],
    "api-endpoint-operation": ["access-control", "sqli", "headers", "waf"],
    "graphql-rpc-operation": ["access-control", "idor", "sqli"],
    "file-upload-ingestion": ["xss", "ssrf", "waf"],
    "media-avatar-profile": ["pfp", "xss", "ssrf"],
    "url-fetch-import-webhook": ["ssrf", "headers", "waf"],
    "payment-gift-card-promo": ["access-control", "race"],
    "search-filter-query": ["xss", "sqli", "waf"],
    "admin-support-impersonation": ["access-control", "idor"],
    "notification-email-template": ["xss", "prompt-injection"],
    "storage-cache-export": ["access-control", "idor"],
    "cdn-static-js-asset": ["xss"],
    "third-party-integration": ["access-control", "ssrf", "headers"],
    "rate-limit-stateful-action": ["race", "csrf", "access-control"],
}


@dataclass(slots=True)
class SurfaceMapConfig:
    program: str
    target: str
    family: str = "web_bounty"
    lane: str = "web"
    root: str | Path | None = None
    input_paths: list[Path] = field(default_factory=list)
    asset_graph_paths: list[Path] = field(default_factory=list)
    run_id: str | None = None
    offline: bool = True
    run_date: str | None = None


@dataclass(slots=True)
class SurfaceMapStats:
    files_seen: int = 0
    files_parsed: int = 0
    files_skipped: int = 0
    asset_graph_records_seen: int = 0
    local_records_seen: int = 0
    surfaces_written: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "files_seen": self.files_seen,
            "files_parsed": self.files_parsed,
            "files_skipped": self.files_skipped,
            "asset_graph_records_seen": self.asset_graph_records_seen,
            "local_records_seen": self.local_records_seen,
            "surfaces_written": self.surfaces_written,
        }


class ReconSurfaceMap:
    """In-memory surface map with stable ids and deterministic dedupe."""

    def __init__(self, program: str, target: str) -> None:
        self.program = program
        self.target = normalize_host(target) or target
        self.records: dict[tuple[str, str, str], ReconSurfaceRecord] = {}

    def add_record(self, record: ReconSurfaceRecord) -> ReconSurfaceRecord:
        key = record.dedupe_key()
        if key in self.records:
            self.records[key].merge(record)
            return self.records[key]
        self.records[key] = record
        return record

    def add_observation(
        self,
        value: str,
        *,
        source: EvidenceSource,
        method: str | None = None,
        scope_status: str = "unknown",
        labels: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        confidence: float = 0.65,
    ) -> ReconSurfaceRecord | None:
        observation = normalize_observation(value, target=self.target, method=method)
        if not observation:
            return None
        inferred = infer_surface(observation, method=method, labels=labels or [])
        normalized_method = normalize_method(method)
        identity_vector = f"{normalized_method} {observation}" if normalized_method else observation
        surface_id = make_surface_id(inferred["family"], inferred["subtype"], identity_vector)
        evidence = [observation] if observation.startswith(("http://", "https://")) else []
        record = ReconSurfaceRecord(
            surface_id=surface_id,
            family=inferred["family"],
            subtype=inferred["subtype"],
            entry_vector=observation,
            attacker_influence=inferred["attacker_influence"],
            auth_context=inferred["auth_context"],
            reachable_evidence=evidence,
            source_artifact_path=source.path,
            candidate_child_skills=FAMILY_SKILLS[inferred["family"]],
            http_method=normalized_method,
            confidence=confidence_for_observation(confidence, inferred["family"], observation),
            coverage_hints=inferred["coverage_hints"],
            scope_status=scope_status,
            sources=[source],
            labels=labels or [],
            metadata=metadata or {},
        )
        return self.add_record(record)

    def sorted_records(self) -> list[ReconSurfaceRecord]:
        return sorted(self.records.values(), key=lambda item: (item.family, item.entry_vector, item.subtype))


def run_surface_map(config: SurfaceMapConfig) -> Path:
    surface_map = ReconSurfaceMap(config.program, config.target)
    stats = SurfaceMapStats()
    input_paths = config.input_paths or default_input_paths(config)
    asset_graph_paths = config.asset_graph_paths or discover_asset_graphs(input_paths)

    for path in asset_graph_paths:
        ingest_asset_graph(path.expanduser(), surface_map, stats)
    for path in input_paths:
        ingest_local_path(path.expanduser(), surface_map, stats)

    run = start_run(
        tool="surface-map",
        target=config.target,
        program=config.program,
        family=config.family,
        lane=config.lane,
        date=config.run_date,
        run_id=config.run_id,
        root_override=config.root,
    )
    run.command_path.write_text(build_command_note(config, input_paths, asset_graph_paths), encoding="utf-8")
    run.stdout_path.write_text("", encoding="utf-8")
    run.stderr_path.write_text("", encoding="utf-8")

    records = surface_map.sorted_records()
    stats.surfaces_written = len(records)
    jsonl_path = run.run_dir / "surface_map.jsonl"
    md_path = run.run_dir / "surface_map.md"
    write_jsonl(jsonl_path, records)
    write_markdown(md_path, records, config)

    manifest = {
        "finished_at": utc_now(),
        "exit_code": 0,
        "mode": "offline" if config.offline else "local",
        "inputs": [str(path) for path in input_paths],
        "asset_graph_inputs": [str(path) for path in asset_graph_paths],
        "artifact_files": [str(jsonl_path), str(md_path)],
        "raw_files": [],
        "parsed_files": [str(jsonl_path), str(md_path)],
        "counts": {
            "raw_records": stats.local_records_seen + stats.asset_graph_records_seen,
            "parsed_records": len(records),
            "promotion_candidates": 0,
            "promoted_findings": 0,
            "surface_records": len(records),
            **stats.to_dict(),
        },
        "promotion_policy": "No finding ledger writes. Surface records are recon routing leads only.",
        "next_builder_contract": {
            "jsonl": str(jsonl_path),
            "record_key": ["family", "subtype", "entry_vector"],
            "stable_id": "surface_id",
            "families": sorted(SURFACE_FAMILIES),
        },
    }
    return write_manifest(run, manifest)


def ingest_asset_graph(path: Path, surface_map: ReconSurfaceMap, stats: SurfaceMapStats) -> None:
    if not path.exists() or not path.is_file():
        return
    stats.files_seen += 1
    if path.stat().st_size > MAX_LOCAL_FILE_BYTES:
        stats.files_skipped += 1
        return
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        stats.files_skipped += 1
        return
    stats.files_parsed += 1
    source = EvidenceSource(name=path.name, path=str(path), source_type="asset-graph", observed_at=utc_now())
    for line in text.splitlines():
        line = clean_line(line)
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        stats.asset_graph_records_seen += 1
        ingest_asset_graph_record(payload, surface_map, source)


def ingest_asset_graph_record(
    payload: dict[str, Any], surface_map: ReconSurfaceMap, source: EvidenceSource
) -> ReconSurfaceRecord | None:
    kind = str(payload.get("kind") or "").lower()
    if kind not in {"url", "domain", "service"}:
        return None
    value = str(payload.get("normalized_value") or payload.get("value") or "")
    if not value:
        return None
    scope_status = safe_scope_status(payload.get("scope_status"))
    labels = [str(item) for item in payload.get("labels") or []]
    metadata = {
        "asset_graph_key": {
            "kind": kind,
            "normalized_value": payload.get("normalized_value") or value,
        },
        "asset_graph_id": payload.get("graph_id"),
        "asset_scope_status": scope_status,
    }
    if scope_status == "in-scope" and not is_target_related(value, surface_map.target):
        scope_status = "needs-human-review"
        metadata["scope_downgrade_reason"] = "asset graph in-scope claim was off target"
    if isinstance(payload.get("metadata"), dict):
        metadata["asset_metadata"] = payload["metadata"]
    return surface_map.add_observation(
        value,
        source=source,
        scope_status=scope_status,
        labels=labels,
        metadata=metadata,
        confidence=safe_float(payload.get("confidence"), 0.55),
    )


def ingest_local_path(path: Path, surface_map: ReconSurfaceMap, stats: SurfaceMapStats) -> None:
    if not path.exists():
        return
    if path.is_file():
        ingest_local_file(path, surface_map, stats)
        return
    for candidate in sorted(path.rglob("*")):
        if candidate.is_file():
            ingest_local_file(candidate, surface_map, stats)


def ingest_local_file(path: Path, surface_map: ReconSurfaceMap, stats: SurfaceMapStats) -> None:
    stats.files_seen += 1
    if path.stat().st_size > MAX_LOCAL_FILE_BYTES:
        stats.files_skipped += 1
        return
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name not in KNOWN_TEXT_FILES and suffix not in KNOWN_JSON_SUFFIXES:
        stats.files_skipped += 1
        return
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        stats.files_skipped += 1
        return
    stats.files_parsed += 1
    source = EvidenceSource(name=path.name, path=str(path), observed_at=utc_now())
    if suffix == ".jsonl" or suffix == ".ndjson":
        for line in text.splitlines():
            line = clean_line(line)
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            stats.local_records_seen += ingest_json_payload(payload, surface_map, source)
        return
    if suffix == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            stats.files_skipped += 1
            return
        stats.local_records_seen += ingest_json_payload(payload, surface_map, source)
        return
    for line in text.splitlines():
        value = clean_line(line)
        if not value:
            continue
        if surface_map.add_observation(value, source=source, confidence=0.7):
            stats.local_records_seen += 1


def ingest_json_payload(payload: Any, surface_map: ReconSurfaceMap, source: EvidenceSource) -> int:
    count = 0
    if isinstance(payload, list):
        for item in payload:
            count += ingest_json_payload(item, surface_map, source)
        return count
    if not isinstance(payload, dict):
        return 0
    if looks_like_asset_graph_record(payload):
        return 1 if ingest_asset_graph_record(payload, surface_map, source) else 0

    value_fields = ("url", "urls", "endpoint", "endpoints", "route", "routes", "path", "paths", "host", "domain")
    method = string_or_none(payload.get("method") or payload.get("http_method") or payload.get("verb"))
    for field_name in value_fields:
        if field_name not in payload:
            continue
        values = payload[field_name] if isinstance(payload[field_name], list) else [payload[field_name]]
        for value in values:
            source_with_field = EvidenceSource(
                name=source.name,
                source_type=source.source_type,
                path=source.path,
                field=field_name,
                observed_at=source.observed_at,
            )
            if surface_map.add_observation(
                str(value),
                source=source_with_field,
                method=method,
                labels=labels_from_payload(payload),
                metadata={"json_field": field_name, "http_method": normalize_method(method)} if method else {"json_field": field_name},
                confidence=0.75,
            ):
                count += 1
    for child_field in ("requests", "records", "surfaces", "items", "entries"):
        if child_field in payload:
            count += ingest_json_payload(payload[child_field], surface_map, source)
    return count


def infer_surface(observation: str, *, method: str | None = None, labels: list[str] | None = None) -> dict[str, Any]:
    labels = labels or []
    parsed = safe_parse_observation(observation)
    host = parsed.hostname if parsed else observation
    path = ((parsed.path if parsed else "") or "/").lower()
    query = (parsed.query if parsed else "").lower()
    haystack = " ".join([host.lower(), path, query, method or "", *labels]).lower()

    family = "api-endpoint-operation"
    subtype = "http-route"
    attacker_influence = "request-parameters" if query else "request-path"
    auth_context = "unknown"

    checks = [
        ("admin-support-impersonation", "admin-support", r"\b(admin|support|impersonat|sudo|agent|staff)\b"),
        ("auth-session-flow", "auth-flow", r"\b(login|logout|signin|sign-in|signup|register|session|oauth|saml|sso|token|mfa|2fa|password|reset)\b"),
        ("graphql-rpc-operation", "graphql-rpc", r"\b(graphql|gql|jsonrpc|json-rpc|rpc)\b"),
        ("url-fetch-import-webhook", "server-url-fetch", r"\b(webhook|callback|redirect_uri|url=|uri=|fetch|import|rss|feed|scan)\b"),
        ("file-upload-ingestion", "upload-ingestion", r"\b(upload|attachment|file|document|csv|bulk)\b"),
        ("media-avatar-profile", "media-profile", r"\b(avatar|profile.?photo|picture|image|media|pfp)\b"),
        ("payment-gift-card-promo", "payment-promo", r"\b(payment|billing|checkout|gift.?card|promo|coupon|discount|invoice|subscription)\b"),
        ("search-filter-query", "search-query", r"\b(search|query|filter|sort|q=|keyword|lookup)\b"),
        ("notification-email-template", "notification-template", r"\b(email|notification|template|message|invite|mail)\b"),
        ("storage-cache-export", "storage-export", r"\b(export|download|cache|storage|bucket|backup|archive|snapshot)\b"),
        ("rate-limit-stateful-action", "stateful-action", r"\b(resend|verify|confirm|redeem|transfer|vote|like|follow|submit)\b"),
        ("account-tenant-object", "account-object", r"\b(account|tenant|org|organization|workspace|team|member|user|users|customer|project|object|settings)\b"),
        ("third-party-integration", "integration", r"\b(integration|connect|slack|github|google|stripe|shopify|salesforce|zapier)\b"),
    ]
    for candidate_family, candidate_subtype, pattern in checks:
        if re.search(pattern, haystack):
            family = candidate_family
            subtype = candidate_subtype
            break
    if family == "api-endpoint-operation" and re.search(r"(^|/)(api|v\d+|rest)(/|$)", path):
        subtype = "rest-api"
    if is_static_js_asset(host, path):
        family = "cdn-static-js-asset"
        subtype = "javascript-asset"
        attacker_influence = "static-client-asset"
    if family in {"auth-session-flow", "admin-support-impersonation", "account-tenant-object"}:
        auth_context = "authenticated-or-session-adjacent"
    if family in {"file-upload-ingestion", "media-avatar-profile"}:
        attacker_influence = "user-controlled-content"
    if family in {"url-fetch-import-webhook", "third-party-integration"}:
        attacker_influence = "server-side-url-or-provider-input"

    coverage_hints = ["untested", "reachable" if observation.startswith(("http://", "https://")) else "inferred"]
    return {
        "family": family,
        "subtype": subtype,
        "attacker_influence": attacker_influence,
        "auth_context": auth_context,
        "coverage_hints": coverage_hints,
    }


def safe_parse_observation(observation: str):
    try:
        return urlparse(observation if observation.startswith(("http://", "https://")) else f"//{observation}")
    except ValueError:
        return None


def normalize_observation(value: str, *, target: str, method: str | None = None) -> str:
    raw = clean_line(value)
    if not raw:
        return ""
    lower = raw.lower()
    if method and raw.startswith("/"):
        raw = urljoin(f"https://{target}/", raw.lstrip("/"))
        lower = raw.lower()
    if lower.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        if not parsed.netloc:
            return ""
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        return urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))
    if raw.startswith("/"):
        return urljoin(f"https://{target}/", raw.lstrip("/"))
    host = normalize_host(raw)
    if host:
        return host
    return raw


def is_static_js_asset(host: str, path: str) -> bool:
    return path.endswith(".js") or "/static/" in path or "/assets/" in path or host.startswith(("cdn.", "static."))


def confidence_for_observation(base: float, family: str, observation: str) -> float:
    value = base
    if observation.startswith(("http://", "https://")):
        value += 0.1
    if family == "api-endpoint-operation":
        value -= 0.05
    return max(0.1, min(0.95, value))


def make_surface_id(family: str, subtype: str, entry_vector: str) -> str:
    digest = hashlib.sha256(f"{family}\n{subtype}\n{entry_vector}".encode("utf-8")).hexdigest()[:16]
    return f"surface:{digest}"


def default_input_paths(config: SurfaceMapConfig) -> list[Path]:
    paths: list[Path] = []
    base = Path(config.root).expanduser() if config.root else Path.home() / "Shared"
    if config.root:
        paths.extend(
            [
                base / "bounty_recon" / config.program,
                base / "web_bounty" / config.program / config.lane / "recon",
            ]
        )
    else:
        home = Path.home()
        paths.extend(
            [
                home / "Shared" / "bounty_recon" / config.program,
                home / "Shared" / "web_bounty" / config.program / config.lane / "recon",
            ]
        )
    return list(dict.fromkeys(paths))


def discover_asset_graphs(paths: list[Path]) -> list[Path]:
    found: list[Path] = []
    for path in paths:
        if path.is_file() and path.name == "asset_graph.jsonl":
            found.append(path)
        elif path.exists() and path.is_dir():
            found.extend(sorted(path.rglob("asset_graph.jsonl")))
    return list(dict.fromkeys(found))


def write_jsonl(path: Path, records: Iterable[ReconSurfaceRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")


def write_markdown(path: Path, records: list[ReconSurfaceRecord], config: SurfaceMapConfig) -> None:
    counts: dict[str, int] = {}
    for record in records:
        counts[record.family] = counts.get(record.family, 0) + 1
    lines = [
        f"# Recon Surface Map: {config.target}",
        "",
        f"- Program: {config.program}",
        f"- Mode: {'offline' if config.offline else 'local'}",
        f"- Surface records: {len(records)}",
        "",
        "## Families",
        "",
    ]
    for family, count in sorted(counts.items()):
        lines.append(f"- `{family}`: {count}")
    lines.extend(["", "## Records", ""])
    for record in records:
        skills = ", ".join(record.candidate_child_skills)
        lines.append(f"- `{record.family}` `{record.entry_vector}` - {record.scope_status}; skills: {skills}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_command_note(
    config: SurfaceMapConfig, input_paths: list[Path], asset_graph_paths: list[Path]
) -> str:
    return "\n".join(
        [
            f"program={config.program}",
            f"target={config.target}",
            f"family={config.family}",
            f"lane={config.lane}",
            f"offline={config.offline}",
            "inputs:",
            *[f"- {path}" for path in input_paths],
            "asset_graph_inputs:",
            *[f"- {path}" for path in asset_graph_paths],
            "",
        ]
    )


def write_surface_records_to_json(records: list[ReconSurfaceRecord]) -> list[dict[str, Any]]:
    return [record.to_dict() for record in records]


def clean_line(value: str) -> str:
    line = str(value or "").strip()
    if not line or line.startswith("#"):
        return ""
    if " #" in line:
        line = line.split(" #", 1)[0].strip()
    return line.strip().strip(",")


def normalize_host(value: str) -> str:
    raw = str(value or "").strip()
    if raw.startswith(("http://", "https://")):
        raw = urlparse(raw).hostname or ""
    raw = raw.split("/", 1)[0].split(":", 1)[0].lower().strip(".")
    if raw.startswith("*."):
        raw = raw[2:]
    if re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", raw, flags=re.I):
        return raw
    return ""


def string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def normalize_method(value: str | None) -> str | None:
    text = string_or_none(value)
    return text.upper() if text else None


def safe_scope_status(value: Any) -> str:
    text = str(value or "unknown").strip()
    return text if text in {"in-scope", "out-of-scope", "needs-human-review", "unknown"} else "unknown"


def safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def is_target_related(value: str, target: str) -> bool:
    host = normalize_host(value)
    target_host = normalize_host(target) or str(target or "").strip().lower()
    return bool(host and target_host and (host == target_host or host.endswith(f".{target_host}")))


def labels_from_payload(payload: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    for field_name in ("label", "labels", "tags", "family", "type"):
        value = payload.get(field_name)
        if isinstance(value, list):
            labels.extend(str(item) for item in value)
        elif value:
            labels.append(str(value))
    return labels


def looks_like_asset_graph_record(payload: dict[str, Any]) -> bool:
    return "kind" in payload and "normalized_value" in payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build an offline Recon surface map.")
    parser.add_argument("program")
    parser.add_argument("--target", required=True, help="Target domain or asset label.")
    parser.add_argument("--family", default="web_bounty")
    parser.add_argument("--lane", default="web")
    parser.add_argument("--root", help="Canonical shared storage root override.")
    parser.add_argument("--input", action="append", dest="inputs", help="Local file or directory to ingest.")
    parser.add_argument("--asset-graph", action="append", dest="asset_graphs", help="asset_graph.jsonl to consume.")
    parser.add_argument("--run-id")
    parser.add_argument("--offline", action="store_true", default=False, help="Run without live probing.")
    parser.add_argument("--json", action="store_true", help="Print the written manifest JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = SurfaceMapConfig(
        program=args.program,
        target=args.target,
        family=args.family,
        lane=args.lane,
        root=args.root,
        input_paths=[Path(value) for value in args.inputs or []],
        asset_graph_paths=[Path(value) for value in args.asset_graphs or []],
        run_id=args.run_id,
        offline=bool(args.offline),
    )
    manifest_path = run_surface_map(config)
    if args.json:
        print(manifest_path.read_text(encoding="utf-8"), end="")
    else:
        print(manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
