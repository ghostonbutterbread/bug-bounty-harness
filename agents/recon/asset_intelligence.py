"""Passive/offline-first recon asset intelligence graph builder."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

_AGENT_DIR = Path(__file__).resolve().parents[1]
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

from bounty_core_bootstrap import ensure_bounty_core_importable

ensure_bounty_core_importable("bounty_core.recon")

from bounty_core.recon import start_run, write_manifest

from .models import AssetGraphRecord, EvidenceSource, GraphEdge, make_graph_id, utc_now


KNOWN_TEXT_FILES = {
    "alive.txt",
    "all_urls.txt",
    "domains.txt",
    "hosts.txt",
    "in-scope.txt",
    "ips.txt",
    "jsfiles.txt",
    "out-of-scope.txt",
    "scope.txt",
    "subdomains.txt",
    "urls.txt",
    "wild.txt",
}
KNOWN_JSON_SUFFIXES = {".json", ".jsonl", ".ndjson"}
MAX_LOCAL_FILE_BYTES = 1_000_000


@dataclass(slots=True)
class AssetIntelligenceConfig:
    program: str
    target: str
    family: str = "web_bounty"
    lane: str = "web"
    root: str | Path | None = None
    input_paths: list[Path] = field(default_factory=list)
    run_id: str | None = None
    offline: bool = True
    allow_network: bool = False
    run_date: str | None = None


@dataclass(slots=True)
class IngestStats:
    files_seen: int = 0
    files_parsed: int = 0
    files_skipped: int = 0
    local_records_seen: int = 0
    records_written: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "files_seen": self.files_seen,
            "files_parsed": self.files_parsed,
            "files_skipped": self.files_skipped,
            "local_records_seen": self.local_records_seen,
            "records_written": self.records_written,
        }


class AssetIntelligenceGraph:
    """In-memory graph with deterministic dedupe and conservative scope labels."""

    def __init__(self, program: str, target: str) -> None:
        self.program = program
        self.target = normalize_domain(target) or target
        self.records: dict[tuple[str, str], AssetGraphRecord] = {}
        self.in_scope_patterns: list[str] = []
        self.out_of_scope_patterns: list[str] = []

    def add_scope_pattern(self, value: str, *, in_scope: bool) -> None:
        normalized = normalize_scope_pattern(value)
        if not normalized:
            return
        bucket = self.in_scope_patterns if in_scope else self.out_of_scope_patterns
        if normalized not in bucket:
            bucket.append(normalized)
        record = record_from_value(
            value,
            source=EvidenceSource(
                name="scope",
                source_type="local-scope",
                field="in_scope" if in_scope else "out_of_scope",
            ),
            scope_status="in-scope" if in_scope else "out-of-scope",
            labels=["scope-entry"],
        )
        if record:
            self.add_record(record)

    def classify_scope(self, value: str) -> str:
        if not value:
            return "unknown"
        if any(scope_matches(pattern, value) for pattern in self.out_of_scope_patterns):
            return "out-of-scope"
        if any(scope_matches(pattern, value) for pattern in self.in_scope_patterns):
            return "in-scope"
        host = host_from_value(value)
        target = self.target.lower()
        if host and target and (host == target or host.endswith(f".{target}")):
            return "needs-human-review"
        return "unknown"

    def add_record(self, record: AssetGraphRecord) -> AssetGraphRecord:
        if record.scope_status == "unknown":
            record.scope_status = self.classify_scope(record.value)
        key = record.dedupe_key()
        if key in self.records:
            self.records[key].merge(record)
            return self.records[key]
        self.records[key] = record
        return record

    def add_value(
        self,
        value: str,
        *,
        source: EvidenceSource,
        kind_hint: str | None = None,
        labels: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AssetGraphRecord | None:
        record = record_from_value(
            value,
            source=source,
            kind_hint=kind_hint,
            labels=labels,
            metadata=metadata,
            scope_status=self.classify_scope(value),
        )
        if not record:
            return None
        record = self.add_record(record)
        if record.kind == "url":
            host = host_from_value(record.value)
            if host:
                host_record = self.add_value(
                    host,
                    source=source,
                    kind_hint="domain",
                    labels=["derived-from-url"],
                    metadata={"derived_from": record.value},
                )
                if host_record:
                    record.edges.append(
                        GraphEdge(
                            relation="hosted-on-domain",
                            source_id=record.graph_id,
                            target_id=host_record.graph_id,
                            confidence=0.9,
                        )
                    )
        return record

    def sorted_records(self) -> list[AssetGraphRecord]:
        return sorted(self.records.values(), key=lambda item: (item.kind, item.normalized_value))


class PassiveProvider:
    """Optional passive provider interface. Providers must fail closed."""

    name = "passive-provider"

    def collect(self, graph: AssetIntelligenceGraph) -> list[AssetGraphRecord]:
        return []


class DNSPassiveProvider(PassiveProvider):
    """Stdlib DNS hook. Only runs when network is explicitly enabled."""

    name = "dns-stdlib"

    def collect(self, graph: AssetIntelligenceGraph) -> list[AssetGraphRecord]:
        try:
            infos = socket.getaddrinfo(graph.target, None, proto=socket.IPPROTO_TCP)
        except OSError:
            return []
        records: list[AssetGraphRecord] = []
        source = EvidenceSource(name=self.name, source_type="passive-network")
        for info in infos:
            address = info[4][0]
            record = record_from_value(address, source=source, kind_hint="ip", scope_status="needs-human-review")
            if record:
                records.append(record)
        return records


class RDAPPassiveProvider(PassiveProvider):
    """Minimal RDAP hook for future online runs. Offline tests do not use it."""

    name = "rdap-arin"

    def collect(self, graph: AssetIntelligenceGraph) -> list[AssetGraphRecord]:
        url = f"https://rdap.org/domain/{graph.target}"
        req = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            return []
        source = EvidenceSource(name=self.name, source_type="passive-network", path=url)
        records: list[AssetGraphRecord] = []
        for nameserver in payload.get("nameservers") or []:
            host = nameserver.get("ldhName") if isinstance(nameserver, dict) else None
            if host:
                record = record_from_value(host, source=source, kind_hint="domain", labels=["nameserver"])
                if record:
                    records.append(record)
        return records


class CTLogPassiveProvider(PassiveProvider):
    """Explicit placeholder for future CT log adapters."""

    name = "ct-log-stub"

    def collect(self, graph: AssetIntelligenceGraph) -> list[AssetGraphRecord]:
        return []


def run_asset_intelligence(config: AssetIntelligenceConfig) -> Path:
    graph = AssetIntelligenceGraph(config.program, config.target)
    stats = IngestStats()

    input_paths = config.input_paths or default_input_paths(config)
    for path in input_paths:
        ingest_local_path(path.expanduser(), graph, stats)

    if config.allow_network and not config.offline:
        for provider in (DNSPassiveProvider(), RDAPPassiveProvider(), CTLogPassiveProvider()):
            for record in provider.collect(graph):
                graph.add_record(record)

    run = start_run(
        tool="asset-intel",
        target=config.target,
        program=config.program,
        family=config.family,
        lane=config.lane,
        date=config.run_date,
        run_id=config.run_id,
        root_override=config.root,
    )
    run.command_path.write_text(build_command_note(config, input_paths), encoding="utf-8")
    run.stdout_path.write_text("", encoding="utf-8")
    run.stderr_path.write_text("", encoding="utf-8")

    records = graph.sorted_records()
    stats.records_written = len(records)
    jsonl_path = run.run_dir / "asset_graph.jsonl"
    md_path = run.run_dir / "asset_graph.md"
    write_jsonl(jsonl_path, records)
    write_markdown(md_path, records, config)

    manifest = {
        "finished_at": utc_now(),
        "exit_code": 0,
        "mode": "offline" if config.offline else "passive",
        "allow_network": bool(config.allow_network and not config.offline),
        "inputs": [str(path) for path in input_paths],
        "artifact_files": [str(jsonl_path), str(md_path)],
        "raw_files": [],
        "parsed_files": [str(jsonl_path), str(md_path)],
        "counts": {
            "raw_records": stats.local_records_seen,
            "parsed_records": len(records),
            "promotion_candidates": 0,
            "promoted_findings": 0,
            "asset_graph_records": len(records),
            **stats.to_dict(),
        },
        "promotion_policy": "No finding ledger writes. Asset graph records are recon leads only.",
        "next_builder_contract": {
            "jsonl": str(jsonl_path),
            "record_key": ["kind", "normalized_value"],
            "scope_statuses": ["in-scope", "out-of-scope", "needs-human-review", "unknown"],
        },
    }
    return write_manifest(run, manifest)


def ingest_local_path(path: Path, graph: AssetIntelligenceGraph, stats: IngestStats) -> None:
    if not path.exists():
        return
    if path.is_file():
        ingest_local_file(path, graph, stats)
        return
    for candidate in sorted(path.rglob("*")):
        if candidate.is_file():
            ingest_local_file(candidate, graph, stats)


def ingest_local_file(path: Path, graph: AssetIntelligenceGraph, stats: IngestStats) -> None:
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
    if name in {"in-scope.txt", "scope.txt", "wild.txt"}:
        for line in text.splitlines():
            value = clean_line(line)
            if value:
                if name == "wild.txt" and not value.startswith("*."):
                    value = f"*.{value}"
                graph.add_scope_pattern(value, in_scope=True)
                stats.local_records_seen += 1
        return
    if name in {"out-of-scope.txt"}:
        for line in text.splitlines():
            value = clean_line(line)
            if value:
                graph.add_scope_pattern(value, in_scope=False)
                stats.local_records_seen += 1
        return
    if suffix == ".jsonl" or suffix == ".ndjson":
        for line in text.splitlines():
            value = clean_line(line)
            if not value:
                continue
            try:
                payload = json.loads(value)
            except json.JSONDecodeError:
                continue
            stats.local_records_seen += ingest_json_payload(payload, graph, source)
        return
    if suffix == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            stats.files_skipped += 1
            return
        stats.local_records_seen += ingest_json_payload(payload, graph, source)
        return
    for line in text.splitlines():
        value = clean_line(line)
        if not value:
            continue
        if graph.add_value(value, source=source):
            stats.local_records_seen += 1


def ingest_json_payload(payload: Any, graph: AssetIntelligenceGraph, source: EvidenceSource) -> int:
    count = 0
    if isinstance(payload, list):
        for item in payload:
            count += ingest_json_payload(item, graph, source)
        return count
    if not isinstance(payload, dict):
        return 0

    if isinstance(payload.get("in_scope"), list):
        for value in payload["in_scope"]:
            graph.add_scope_pattern(str(value), in_scope=True)
            count += 1
    if isinstance(payload.get("out_of_scope"), list):
        for value in payload["out_of_scope"]:
            graph.add_scope_pattern(str(value), in_scope=False)
            count += 1

    field_map = {
        "url": "url",
        "urls": "url",
        "domain": "domain",
        "domains": "domain",
        "host": "domain",
        "hosts": "domain",
        "subdomain": "domain",
        "subdomains": "domain",
        "ip": "ip",
        "ips": "ip",
        "asn": "asn",
        "asns": "asn",
        "netblock": "netblock",
        "netblocks": "netblock",
        "provider": "provider",
        "providers": "provider",
        "service": "service",
        "services": "service",
        "name": None,
        "value": None,
    }
    explicit_kind = payload.get("kind") or payload.get("type")
    for field_name, kind in field_map.items():
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
            if graph.add_value(
                str(value),
                source=source_with_field,
                kind_hint=kind or str(explicit_kind or ""),
                metadata={"json_field": field_name},
            ):
                count += 1
    return count


def record_from_value(
    value: str,
    *,
    source: EvidenceSource,
    kind_hint: str | None = None,
    labels: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    scope_status: str = "unknown",
) -> AssetGraphRecord | None:
    raw = clean_line(value)
    if not raw:
        return None
    kind = normalize_kind(kind_hint) or infer_kind(raw)
    if not kind:
        return None
    normalized = normalize_value(raw, kind)
    if not normalized:
        return None
    display = raw if kind == "url" else normalized
    return AssetGraphRecord(
        kind=kind,
        value=display,
        normalized_value=normalized,
        graph_id=make_graph_id(kind, normalized),
        scope_status=scope_status,
        sources=[source],
        confidence=0.85 if source.source_type.startswith("local") else 0.55,
        labels=labels or [],
        metadata=metadata or {},
    )


def default_input_paths(config: AssetIntelligenceConfig) -> list[Path]:
    paths: list[Path] = []
    base = Path(config.root).expanduser() if config.root else Path.home() / "Shared"
    if config.root:
        paths.extend(
            [
                base / "scopes" / config.program,
                base / "bounty_recon" / config.program,
                base / "web_bounty" / config.program / config.lane / "recon",
            ]
        )
    else:
        home = Path.home()
        paths.extend(
            [
                home / "Shared" / "scopes" / config.program,
                home / "Shared" / "bounty_recon" / config.program,
                home / "Shared" / "web_bounty" / config.program / config.lane / "recon",
            ]
        )
    return list(dict.fromkeys(paths))


def write_jsonl(path: Path, records: Iterable[AssetGraphRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")


def write_markdown(path: Path, records: list[AssetGraphRecord], config: AssetIntelligenceConfig) -> None:
    counts: dict[str, int] = {}
    for record in records:
        counts[record.scope_status] = counts.get(record.scope_status, 0) + 1
    lines = [
        f"# Asset Intelligence Graph: {config.target}",
        "",
        f"- Program: {config.program}",
        f"- Mode: {'offline' if config.offline else 'passive'}",
        f"- Records: {len(records)}",
        f"- In scope: {counts.get('in-scope', 0)}",
        f"- Needs review: {counts.get('needs-human-review', 0)}",
        f"- Unknown: {counts.get('unknown', 0)}",
        f"- Out of scope: {counts.get('out-of-scope', 0)}",
        "",
        "## Records",
        "",
    ]
    for record in records:
        lines.append(f"- `{record.kind}` `{record.value}` - {record.scope_status}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_command_note(config: AssetIntelligenceConfig, input_paths: list[Path]) -> str:
    return "\n".join(
        [
            f"program={config.program}",
            f"target={config.target}",
            f"family={config.family}",
            f"lane={config.lane}",
            f"offline={config.offline}",
            f"allow_network={config.allow_network}",
            "inputs:",
            *[f"- {path}" for path in input_paths],
            "",
        ]
    )


def clean_line(value: str) -> str:
    line = str(value or "").strip()
    if not line or line.startswith("#"):
        return ""
    if " #" in line:
        line = line.split(" #", 1)[0].strip()
    return line.strip().strip(",")


def infer_kind(value: str) -> str | None:
    lower = value.lower().strip()
    if lower.startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"as\d+", lower):
        return "asn"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return "netblock"
    except ValueError:
        pass
    if is_probable_domain(value):
        return "domain"
    return None


def normalize_kind(value: str | None) -> str | None:
    if not value:
        return None
    kind = str(value).strip().lower().replace("_", "-")
    aliases = {
        "host": "domain",
        "hostname": "domain",
        "subdomain": "domain",
        "ip-address": "ip",
        "cidr": "netblock",
        "cert": "certificate",
        "certificate-san": "certificate",
        "cloud": "provider",
    }
    return aliases.get(kind, kind) if aliases.get(kind, kind) in {
        "asn",
        "certificate",
        "domain",
        "entity",
        "ip",
        "netblock",
        "provider",
        "service",
        "url",
    } else None


def normalize_value(value: str, kind: str) -> str:
    if kind == "url":
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            return ""
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{parsed.scheme.lower()}://{netloc}{path}{query}"
    if kind == "domain":
        return normalize_domain(value)
    if kind == "asn":
        digits = re.sub(r"[^0-9]", "", value)
        return f"AS{digits}" if digits else ""
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return ""
    if kind == "netblock":
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return ""
    return value.strip().lower()


def normalize_domain(value: str) -> str:
    host = host_from_value(value)
    if not host:
        return ""
    host = host.lower().strip(".")
    if host.startswith("*."):
        host = host[2:]
    return host


def normalize_scope_pattern(value: str) -> str:
    raw = clean_line(value).lower()
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        return parsed.geturl().rstrip("/")
    if raw.startswith("*."):
        return raw
    try:
        return str(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        return normalize_domain(raw)


def host_from_value(value: str) -> str:
    raw = str(value or "").strip()
    if raw.startswith(("http://", "https://")):
        return (urlparse(raw).hostname or "").lower()
    return raw.split("/", 1)[0].split(":", 1)[0].lower().strip(".")


def is_probable_domain(value: str) -> bool:
    host = host_from_value(value)
    return bool(re.fullmatch(r"(\*\.)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", host, flags=re.I))


def scope_matches(pattern: str, value: str) -> bool:
    host = host_from_value(value)
    raw = str(value or "").strip().lower().rstrip("/")
    pattern = pattern.lower().rstrip("/")
    if not pattern:
        return False
    if pattern.startswith(("http://", "https://")):
        return raw == pattern or raw.startswith(f"{pattern}/")
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith(f".{base}")
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        address = ipaddress.ip_address(host)
        return address in network
    except ValueError:
        pass
    return host == pattern


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a passive recon asset intelligence graph.")
    parser.add_argument("program")
    parser.add_argument("--target", required=True, help="Target domain or asset label.")
    parser.add_argument("--family", default="web_bounty")
    parser.add_argument("--lane", default="web")
    parser.add_argument("--root", help="Canonical shared storage root override.")
    parser.add_argument("--input", action="append", dest="inputs", help="Local file or directory to ingest.")
    parser.add_argument("--run-id")
    parser.add_argument("--offline", action="store_true", default=False, help="Disable network providers.")
    parser.add_argument("--allow-network", action="store_true", help="Opt in to passive network providers.")
    parser.add_argument("--json", action="store_true", help="Print the written manifest JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    offline = bool(args.offline or not args.allow_network)
    config = AssetIntelligenceConfig(
        program=args.program,
        target=args.target,
        family=args.family,
        lane=args.lane,
        root=args.root,
        input_paths=[Path(value) for value in args.inputs or []],
        run_id=args.run_id,
        offline=offline,
        allow_network=bool(args.allow_network),
    )
    manifest_path = run_asset_intelligence(config)
    if args.json:
        print(manifest_path.read_text(encoding="utf-8"), end="")
    else:
        print(manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
