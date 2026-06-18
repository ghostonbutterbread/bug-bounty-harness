#!/usr/bin/env python3
"""Map XSS canary sources to reflected/rendered sinks from saved artifacts.

This is intentionally script-first and artifact-oriented. It ingests candidate
parameters/fields from existing tools or JSONL artifacts, generates unique inert
canaries, mutates GET URLs as planned requests, can fetch those requests with
scope controls, scans responses for canaries, classifies the observed context,
and writes compact packets for XSS lane agents.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


SECRET_FIELD_RE = re.compile(
    r"(authorization|cookie|token|secret|session|password|passwd|csrf|xsrf|api[-_]?key)",
    re.I,
)
KXSS_RE = re.compile(r"URL:\s*(?P<url>\S+)\s+Param:\s*(?P<param>[^\s]+)", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
URL_ATTRS = {
    "action",
    "background",
    "cite",
    "data",
    "formaction",
    "href",
    "poster",
    "src",
    "srcdoc",
    "srcset",
}
DEFAULT_MAX_BODY_BYTES = 1_000_000
LIVE_SNIPPET_WIDTH = 500
PRIVATE_REPLAY_FILENAME = "private_replay_requests.jsonl"


def is_secret_name(name: str) -> bool:
    return bool(SECRET_FIELD_RE.search(name))


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:length]


def safe_run_id(run_id: str | None) -> str:
    if run_id:
        cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", run_id).strip("-")
        if cleaned:
            return cleaned[:32]
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def json_dump(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, ensure_ascii=False)


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json_dump(record) + "\n")
            count += 1
    return count


def write_private_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> int:
    count = write_jsonl(path, records)
    path.chmod(0o600)
    return count


def read_json_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".jsonl":
        records = []
        for line_no, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
            if isinstance(value, dict):
                records.append(value)
        return records

    value = json.loads(text)
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in ("sources", "results", "items", "records"):
            nested = value.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
        return [value]
    return []


def value_preview(value: Any) -> dict[str, Any]:
    text = "" if value is None else str(value)
    return {
        "redacted": True,
        "length": len(text),
        "sha256_12": stable_hash(text, 12),
    }


def sanitize_query_pairs(pairs: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], bool]:
    sanitized: list[tuple[str, str]] = []
    redacted = False
    for key, value in pairs:
        if is_secret_name(key):
            sanitized.append((key, "REDACTED"))
            redacted = True
        else:
            sanitized.append((key, value))
    return sanitized, redacted


def sanitize_url(url: str) -> tuple[str, bool]:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    sanitized_pairs, redacted = sanitize_query_pairs(pairs)
    query = urlencode(sanitized_pairs, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment)), redacted


def has_secret_query(url: str) -> bool:
    return any(is_secret_name(key) for key, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True))


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass(frozen=True)
class Source:
    method: str
    url: str
    vector: str
    field: str
    source_type: str
    origin: str
    original_value: str = ""
    evidence: str = ""

    @property
    def source_id(self) -> str:
        sanitized_url, _redacted = sanitize_url(self.url)
        basis = "|".join([self.method, sanitized_url, self.vector, self.field, self.source_type])
        return stable_hash(basis, 16)

    def canary(self, run_id: str) -> str:
        return f"GHOST_XSS_{run_id}_{self.source_id[:10]}"

    def to_record(self, run_id: str) -> dict[str, Any]:
        sanitized_url, redacted_url = sanitize_url(self.url)
        record = {
            "source_id": self.source_id,
            "run_id": run_id,
            "method": self.method,
            "url": sanitized_url,
            "url_redacted": redacted_url,
            "vector": self.vector,
            "field": self.field,
            "source_type": self.source_type,
            "origin": self.origin,
            "canary": self.canary(run_id),
            "evidence": self.evidence,
        }
        if self.original_value:
            record["original_value"] = value_preview(self.original_value)
        return record


def source_from_url_param(url: str, param: str, origin: str, method: str = "GET") -> Source:
    value = ""
    for key, current in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if key == param:
            value = current
            break
    return Source(
        method=method.upper(),
        url=url,
        vector="query",
        field=param,
        source_type="url_param",
        origin=origin,
        original_value=value,
    )


def extract_sources_from_url(url: str, origin: str, method: str = "GET") -> list[Source]:
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return []
    sources = []
    for param, _value in parse_qsl(parsed.query, keep_blank_values=True):
        if is_secret_name(param):
            continue
        sources.append(source_from_url_param(url, param, origin, method))
    return sources


def nested_value(record: dict[str, Any], paths: list[tuple[str, ...]]) -> Any:
    for path in paths:
        current: Any = record
        for key in path:
            if not isinstance(current, dict) or key not in current:
                current = None
                break
            current = current[key]
        if current is not None and current != "":
            return current
    return None


def urls_from_record(record: dict[str, Any]) -> list[str]:
    candidates = [
        nested_value(
            record,
            [
                ("url",),
                ("target",),
                ("request_url",),
                ("target_url",),
                ("endpoint",),
                ("poc",),
                ("request", "url"),
                ("request", "endpoint"),
                ("data", "url"),
                ("data", "target"),
                ("data", "request_url"),
                ("data", "endpoint"),
            ],
        )
    ]
    urls: list[str] = []
    for candidate in candidates:
        if isinstance(candidate, str):
            urls.extend(URL_RE.findall(candidate) or [candidate])
        elif isinstance(candidate, list):
            for item in candidate:
                if isinstance(item, str):
                    urls.extend(URL_RE.findall(item) or [item])
    return [url for url in urls if urlsplit(url).scheme in {"http", "https"}]


def fields_from_record(record: dict[str, Any]) -> list[str]:
    candidates = [
        nested_value(
            record,
            [
                ("field",),
                ("param",),
                ("parameter",),
                ("name",),
                ("key",),
                ("data", "field"),
                ("data", "param"),
                ("data", "parameter"),
                ("data", "name"),
                ("evidence", "param"),
            ],
        )
    ]
    params = record.get("params") or record.get("parameters") or nested_value(record, [("data", "params")])
    if isinstance(params, dict):
        candidates.extend(params.keys())
    elif isinstance(params, list):
        candidates.extend(params)

    fields: list[str] = []
    for candidate in candidates:
        if isinstance(candidate, str):
            fields.append(candidate)
        elif isinstance(candidate, list):
            fields.extend(str(item) for item in candidate if item is not None)
    deduped = []
    for field in fields:
        field = str(field).strip()
        if field and field not in deduped and not is_secret_name(field):
            deduped.append(field)
    return deduped


def extract_sources_from_record(record: dict[str, Any], origin: str) -> list[Source]:
    urls = urls_from_record(record)
    url = urls[0] if urls else ""
    method = str(record.get("method") or "GET").upper()
    sources: list[Source] = []

    fields = fields_from_record(record)
    vector = str(record.get("vector") or record.get("location") or "query")
    if url and fields:
        for field in fields:
            sources.append(
                Source(
                    method=method,
                    url=url,
                    vector=vector,
                    field=str(field),
                    source_type=str(record.get("source_type") or record.get("scanner") or "tool_record"),
                    origin=origin,
                    original_value=str(record.get("value") or ""),
                    evidence=str(record.get("evidence") or record.get("source") or ""),
                )
            )

    params = record.get("params") or record.get("parameters") or record.get("query")
    if url and isinstance(params, dict):
        for key, value in params.items():
            if is_secret_name(str(key)):
                continue
            sources.append(
                Source(
                    method=method,
                    url=url,
                    vector="query",
                    field=str(key),
                    source_type="param_dict",
                    origin=origin,
                    original_value=str(value),
                )
            )
    elif url and not sources:
        sources.extend(extract_sources_from_url(url, origin, method))

    request_fields = record.get("body_fields") or record.get("json_fields") or record.get("form_fields")
    if url and isinstance(request_fields, dict):
        body_vector = "json" if "json_fields" in record else "body"
        for key, value in request_fields.items():
            if is_secret_name(str(key)):
                continue
            sources.append(
                Source(
                    method=method if method != "GET" else "POST",
                    url=url,
                    vector=body_vector,
                    field=str(key),
                    source_type="body_field",
                    origin=origin,
                    original_value=str(value),
                )
            )
    return sources


def extract_sources_from_text(path: Path) -> list[Source]:
    sources: list[Source] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        match = KXSS_RE.search(line)
        if match and not is_secret_name(match.group("param")):
            sources.append(
                source_from_url_param(
                    match.group("url"),
                    match.group("param"),
                    f"{path}:{line_no}",
                )
            )
            continue
        for url in URL_RE.findall(line):
            sources.extend(extract_sources_from_url(url, f"{path}:{line_no}"))
    return sources


def load_sources(inputs: list[Path]) -> list[Source]:
    sources: list[Source] = []
    for path in inputs:
        if path.suffix.lower() in {".json", ".jsonl"}:
            for record in read_json_records(path):
                sources.extend(extract_sources_from_record(record, str(path)))
        else:
            sources.extend(extract_sources_from_text(path))

    deduped: dict[str, Source] = {}
    for source in sources:
        deduped.setdefault(source.source_id, source)
    return list(deduped.values())


def mutate_query_url(url: str, field: str, canary: str) -> str | None:
    parsed = urlsplit(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not any(key == field for key, _ in params):
        return None
    mutated = [(key, canary if key == field else value) for key, value in params]
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated, doseq=True), parsed.fragment)
    )


def planned_request(source_record: dict[str, Any]) -> dict[str, Any]:
    mutated_url = None
    status = "needs_custom_submitter"
    notes = "No network request was sent by this planner."
    sensitive_replay_required = False
    if source_record["vector"] == "query" and source_record["method"] == "GET":
        mutated_url = mutate_query_url(
            source_record["url"], source_record["field"], source_record["canary"]
        )
        sensitive_replay_required = bool(source_record.get("url_redacted"))
        if mutated_url:
            status = "ready"
            if sensitive_replay_required:
                notes = (
                    "Public URL is redacted. Fetch uses private replay artifacts only "
                    "when --allow-sensitive-replay is supplied."
                )
    return {
        "source_id": source_record["source_id"],
        "run_id": source_record["run_id"],
        "method": source_record["method"],
        "url": source_record["url"],
        "mutated_url": mutated_url,
        "vector": source_record["vector"],
        "field": source_record["field"],
        "canary": source_record["canary"],
        "status": status,
        "notes": notes,
        "sensitive_replay_required": sensitive_replay_required,
    }


def private_replay_request(source: Source, source_record: dict[str, Any]) -> dict[str, Any]:
    mutated_url = None
    if source_record["vector"] == "query" and source_record["method"] == "GET":
        mutated_url = mutate_query_url(source.url, source_record["field"], source_record["canary"])
    return {
        "source_id": source_record["source_id"],
        "run_id": source_record["run_id"],
        "method": source_record["method"],
        "url": source.url,
        "mutated_url": mutated_url,
        "field": source_record["field"],
        "canary": source_record["canary"],
        "has_secret_query": has_secret_query(source.url),
    }


def load_response_records(paths: list[Path]) -> list[dict[str, Any]]:
    responses: list[dict[str, Any]] = []
    for path in paths:
        if path.suffix.lower() in {".json", ".jsonl"}:
            for index, record in enumerate(read_json_records(path), 1):
                body = (
                    record.get("body")
                    or record.get("html")
                    or record.get("text")
                    or record.get("content")
                )
                body_path = record.get("body_path") or record.get("file") or record.get("path")
                if body is None and body_path:
                    body = Path(str(body_path)).read_text(encoding="utf-8", errors="replace")
                if body is None:
                    continue
                responses.append(
                    {
                        "response_id": str(record.get("response_id") or f"{path}:{index}"),
                        "url": str(record.get("url") or record.get("response_url") or path),
                        "body": str(body),
                        "origin": str(path),
                    }
                )
        else:
            responses.append(
                {
                    "response_id": str(path),
                    "url": path.as_uri() if path.is_absolute() else str(path),
                    "body": path.read_text(encoding="utf-8", errors="replace"),
                    "origin": str(path),
                }
            )
    return responses


def line_col(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    last_newline = text.rfind("\n", 0, index)
    col = index + 1 if last_newline < 0 else index - last_newline
    return line, col


def snippet_around(text: str, index: int, marker: str, width: int = 160) -> str:
    start = max(0, index - width)
    end = min(len(text), index + len(marker) + width)
    return text[start:end].replace("\n", "\\n")


def artifact_body_for_canaries(body: str, canaries: Iterable[str], width: int = LIVE_SNIPPET_WIDTH) -> str:
    snippets: list[str] = []
    for canary in canaries:
        start = 0
        while True:
            index = body.find(canary, start)
            if index < 0:
                break
            snippets.append(snippet_around(body, index, canary, width))
            start = index + len(canary)
    return "\n".join(snippets)


def in_script_context(text: str, index: int) -> bool:
    before = text[:index].lower()
    last_open = before.rfind("<script")
    last_close = before.rfind("</script")
    return last_open > last_close


def classify_context(text: str, index: int, marker: str) -> dict[str, Any]:
    before = text[:index]
    after = text[index + len(marker) :]
    snippet = snippet_around(text, index, marker, 120)

    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    inside_tag = last_lt > last_gt

    if inside_tag:
        tag_fragment = text[last_lt : min(len(text), index + len(marker) + 120)]
        attr_match = re.search(
            r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*([\"']?)[^<>\"']*"
            + re.escape(marker),
            tag_fragment,
        )
        if attr_match:
            attr = attr_match.group(1).lower()
            quote = attr_match.group(2)
            if attr in URL_ATTRS:
                context = "url_attribute"
            elif quote in {"'", '"'}:
                context = "quoted_attribute"
            else:
                context = "unquoted_attribute"
            return {
                "context": context,
                "attribute": attr,
                "quote": quote or "none",
                "snippet": snippet,
            }
        return {"context": "html_tag", "snippet": snippet}

    if in_script_context(text, index):
        local_before = before[max(0, len(before) - 120) :]
        quote = None
        for candidate in ("'", '"', "`"):
            if local_before.count(candidate) % 2 == 1:
                quote = candidate
                break
        return {
            "context": "inline_javascript_string" if quote else "inline_javascript",
            "quote": quote or "unknown",
            "snippet": snippet,
        }

    jsonish = re.search(r'["\'][A-Za-z0-9_.:-]+["\']\s*:\s*["\']?$', before[-80:]) or re.match(
        r'^\s*["\']?\s*[,}\]]', after[:20]
    )
    if jsonish:
        return {"context": "json_or_bootstrap_blob", "snippet": snippet}

    return {"context": "html_text", "snippet": snippet}


def sink_kind(context: str, source_vector: str) -> str:
    if context.startswith("inline_javascript") or context == "json_or_bootstrap_blob":
        return "dom-xss"
    if source_vector in {"body", "json", "form"}:
        return "stored-or-reflected-xss"
    return "reflected-xss"


def allowed_host(url: str, allowed_hosts: set[str]) -> bool:
    host = urlsplit(url).hostname or ""
    for allowed in allowed_hosts:
        allowed = allowed.strip().lower()
        if not allowed:
            continue
        if allowed.startswith("*."):
            base = allowed[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == allowed:
            return True
    return False


def load_scope_validator(program: str | None) -> Any | None:
    if not program:
        return None
    repo_root = Path(__file__).resolve().parents[3]
    agents_dir = repo_root / "agents"
    if str(agents_dir) not in sys.path:
        sys.path.insert(0, str(agents_dir))
    try:
        from scope_validator import ScopeValidator
    except ImportError as exc:
        raise SystemExit(f"Could not load scope validator for --program {program}: {exc}") from exc
    validator = ScopeValidator(program)
    if validator.is_empty():
        raise SystemExit(f"No saved scope entries found for --program {program}.")
    return validator


def load_program_policy(program: str | None) -> dict[str, Any]:
    if not program:
        return {}
    candidates = [
        Path.home() / "Shared" / "scopes" / program / "rules-of-engagement.json",
        Path.home() / "Shared" / "bounty_recon" / program / "scope" / "rules-of-engagement.json",
    ]
    for path in candidates:
        if path.exists():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return {}
            return value if isinstance(value, dict) else {}
    return {}


def effective_rate_delay(args: argparse.Namespace) -> float:
    if args.rate_delay is not None:
        return max(0.0, float(args.rate_delay))
    policy = load_program_policy(getattr(args, "program", None))
    for key in ("rate_delay", "rate_delay_seconds", "minimum_delay_seconds", "min_delay_seconds"):
        value = policy.get(key)
        if isinstance(value, (int, float)) and value >= 0:
            return float(value)
    rps = policy.get("max_requests_per_second")
    if isinstance(rps, (int, float)) and rps > 0:
        return 1.0 / float(rps)
    return 0.5


def allowed_by_live_scope(url: str, allowed_hosts: set[str], scope_validator: Any | None) -> bool:
    if allowed_host(url, allowed_hosts):
        return True
    if scope_validator is not None:
        return bool(scope_validator.is_in_scope(url))
    return False


def require_live_scope(args: argparse.Namespace) -> tuple[set[str], Any | None]:
    allowed_hosts = set(args.allow_host or [])
    scope_validator = load_scope_validator(getattr(args, "program", None))
    if not allowed_hosts and scope_validator is None:
        raise SystemExit("Live fetch requires --program saved scope or at least one --allow-host.")
    return allowed_hosts, scope_validator


def load_private_replay_records(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    path_text = getattr(args, "private_planned", None)
    if path_text:
        path = Path(path_text)
    else:
        path = Path(args.planned).parent / PRIVATE_REPLAY_FILENAME
    if not path.exists():
        return {}
    return {
        str(record.get("source_id")): record
        for record in read_json_records(path)
        if record.get("source_id")
    }


def replay_url_for_record(
    public_record: dict[str, Any],
    private_records: dict[str, dict[str, Any]],
    allow_sensitive_replay: bool,
) -> tuple[str | None, str | None]:
    public_url = str(public_record.get("mutated_url") or "")
    if not public_record.get("sensitive_replay_required"):
        return public_url or None, None
    if not allow_sensitive_replay:
        return None, "sensitive_replay_requires_explicit_flag"
    private_record = private_records.get(str(public_record.get("source_id"))) or {}
    private_url = str(private_record.get("mutated_url") or "")
    if not private_url:
        return None, "sensitive_replay_private_artifact_missing"
    return private_url, None


def response_record(
    response_id: str,
    url: str,
    body: str,
    status_code: int | None,
    origin: str,
    content_type: str | None = None,
) -> dict[str, Any]:
    return {
        "response_id": response_id,
        "url": sanitize_url(url)[0],
        "status_code": status_code,
        "content_type": content_type,
        "body": body,
        "origin": origin,
        "captured_at": now_iso(),
    }


def scan_responses(
    source_records: list[dict[str, Any]], responses: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sinks: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    source_by_canary = {record["canary"]: record for record in source_records}

    for response in responses:
        body = response["body"]
        for canary, source in source_by_canary.items():
            start = 0
            while True:
                index = body.find(canary, start)
                if index < 0:
                    break
                line, col = line_col(body, index)
                classified = classify_context(body, index, canary)
                sink_id = stable_hash(
                    "|".join([response["response_id"], canary, str(line), str(col)]), 16
                )
                sink = {
                    "sink_id": sink_id,
                    "run_id": source["run_id"],
                    "response_id": response["response_id"],
                    "response_url": response["url"],
                    "source_id": source["source_id"],
                    "canary": canary,
                    "line": line,
                    "column": col,
                    "context": classified["context"],
                    "context_detail": {
                        key: value
                        for key, value in classified.items()
                        if key not in {"context", "snippet"}
                    },
                    "snippet": classified["snippet"],
                    "origin": response["origin"],
                }
                edge = {
                    "edge_id": stable_hash(source["source_id"] + sink_id, 16),
                    "run_id": source["run_id"],
                    "source_id": source["source_id"],
                    "sink_id": sink_id,
                    "source_url": source["url"],
                    "source_method": source["method"],
                    "source_vector": source["vector"],
                    "source_field": source["field"],
                    "sink_url": response["url"],
                    "sink_context": classified["context"],
                    "recommended_lane": sink_kind(classified["context"], source["vector"]),
                    "status": "Potential",
                    "stop_reason": "Canary reflected; context-specific XSS proof not attempted by mapper.",
                }
                sinks.append(sink)
                edges.append(edge)
                start = index + len(canary)
    return sinks, edges


def packet_name(edge: dict[str, Any]) -> str:
    host = urlsplit(edge["sink_url"]).netloc or "local"
    field = re.sub(r"[^A-Za-z0-9_-]+", "-", edge["source_field"]).strip("-") or "field"
    return f"{edge['recommended_lane']}_{host}_{field}_{edge['edge_id'][:8]}.md"


def write_agent_packets(
    out_dir: Path,
    source_records: list[dict[str, Any]],
    sinks: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> int:
    packet_dir = out_dir / "agent_packets"
    packet_dir.mkdir(parents=True, exist_ok=True)
    sources_by_id = {record["source_id"]: record for record in source_records}
    sinks_by_id = {record["sink_id"]: record for record in sinks}
    count = 0
    for edge in edges:
        source = sources_by_id[edge["source_id"]]
        sink = sinks_by_id[edge["sink_id"]]
        text = "\n".join(
            [
                f"# XSS Canary Edge {edge['edge_id']}",
                "",
                "## Route",
                "",
                f"- Recommended lane: `{edge['recommended_lane']}`",
                f"- Status: `{edge['status']}`",
                f"- Stop reason: {edge['stop_reason']}",
                "",
                "## Source",
                "",
                f"- Method: `{source['method']}`",
                f"- URL: `{source['url']}`",
                f"- Vector: `{source['vector']}`",
                f"- Field: `{source['field']}`",
                f"- Source id: `{source['source_id']}`",
                "",
                "## Sink",
                "",
                f"- URL: `{sink['response_url']}`",
                f"- Context: `{sink['context']}`",
                f"- Location: line `{sink['line']}`, column `{sink['column']}`",
                f"- Sink id: `{sink['sink_id']}`",
                "",
                "## Evidence",
                "",
                "```text",
                sink["snippet"],
                "```",
                "",
                "## Next Agent Task",
                "",
                "Use the XSS lane to choose a small context-matched payload family. "
                "Do not spray generic payloads; reason from the recorded source, sink, "
                "context, and encoding boundary first.",
                "",
            ]
        )
        (packet_dir / packet_name(edge)).write_text(text, encoding="utf-8")
        count += 1
    return count


def fetch_planned_http(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.offline:
        out_dir = Path(args.out_dir)
        write_jsonl(out_dir / "responses.jsonl", [])
        return []
    allowed_hosts, scope_validator = require_live_scope(args)

    planned = read_json_records(Path(args.planned))
    private_records = load_private_replay_records(args)
    canaries = [str(record.get("canary", "")) for record in planned if record.get("canary")]
    responses: list[dict[str, Any]] = []
    processed = 0
    rate_delay = effective_rate_delay(args)
    opener = build_opener(NoRedirectHandler)
    for record in planned:
        if record.get("status") != "ready" or not record.get("mutated_url"):
            continue
        if processed >= args.max_requests:
            break
        processed += 1
        url, blocked_reason = replay_url_for_record(record, private_records, args.allow_sensitive_replay)
        if not url:
            responses.append(
                response_record(
                    response_id=f"blocked:{record.get('source_id', processed)}",
                    url=str(record.get("mutated_url") or record.get("url") or ""),
                    body="",
                    status_code=None,
                    origin="http-fetch-blocked-sensitive",
                    content_type=None,
                )
                | {"blocked_reason": blocked_reason or "replay_url_missing"}
            )
            continue
        if not allowed_by_live_scope(url, allowed_hosts, scope_validator):
            responses.append(
                response_record(
                    response_id=f"blocked:{record.get('source_id', processed)}",
                    url=url,
                    body="",
                    status_code=None,
                    origin="http-fetch-blocked-host",
                    content_type=None,
                )
                | {"blocked_reason": "host_not_allowlisted"}
            )
            continue
        request = Request(url, headers={"User-Agent": args.user_agent})
        try:
            with opener.open(request, timeout=args.timeout) as response:
                raw = response.read(args.max_body_bytes)
                body = raw.decode("utf-8", errors="replace")
                status_code = response.getcode()
                content_type = response.headers.get("content-type")
        except HTTPError as exc:
            raw = exc.read(args.max_body_bytes)
            body = raw.decode("utf-8", errors="replace")
            status_code = exc.code
            content_type = exc.headers.get("content-type")
        except URLError as exc:
            body = str(exc.reason)
            status_code = None
            content_type = None
        responses.append(
            response_record(
                response_id=f"http:{record.get('source_id', processed)}",
                url=url,
                body=artifact_body_for_canaries(body, canaries),
                status_code=status_code,
                origin="http-fetch",
                content_type=content_type,
            )
        )
        if rate_delay > 0:
            time.sleep(rate_delay)
    out_dir = Path(args.out_dir)
    write_jsonl(out_dir / "responses.jsonl", responses)
    return responses


def browser_fetch_planned(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.offline:
        out_dir = Path(args.out_dir)
        write_jsonl(out_dir / "responses.jsonl", [])
        return []
    allowed_hosts, scope_validator = require_live_scope(args)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit("Playwright is not installed; install it before browser-fetch.") from exc

    planned = read_json_records(Path(args.planned))
    private_records = load_private_replay_records(args)
    canaries = [str(record.get("canary", "")) for record in planned if record.get("canary")]
    responses: list[dict[str, Any]] = []
    rate_delay = effective_rate_delay(args)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=not args.headful)
        context_kwargs: dict[str, Any] = {}
        if args.storage_state:
            context_kwargs["storage_state"] = args.storage_state
        context = browser.new_context(**context_kwargs)
        page = context.new_page()
        def route_handler(route):  # type: ignore[no-untyped-def]
            if allowed_by_live_scope(route.request.url, allowed_hosts, scope_validator):
                route.continue_()
            else:
                route.abort()

        context.route("**/*", route_handler)
        processed = 0
        try:
            for record in planned:
                if record.get("status") != "ready" or not record.get("mutated_url"):
                    continue
                if processed >= args.max_requests:
                    break
                processed += 1
                url, blocked_reason = replay_url_for_record(
                    record, private_records, args.allow_sensitive_replay
                )
                if not url:
                    responses.append(
                        response_record(
                            response_id=f"blocked:{record.get('source_id', processed)}",
                            url=str(record.get("mutated_url") or record.get("url") or ""),
                            body="",
                            status_code=None,
                            origin="browser-fetch-blocked-sensitive",
                        )
                        | {"blocked_reason": blocked_reason or "replay_url_missing"}
                    )
                    continue
                if not allowed_by_live_scope(url, allowed_hosts, scope_validator):
                    responses.append(
                        response_record(
                            response_id=f"blocked:{record.get('source_id', processed)}",
                            url=url,
                            body="",
                            status_code=None,
                            origin="browser-fetch-blocked-host",
                        )
                        | {"blocked_reason": "host_not_allowlisted"}
                    )
                    continue
                page.goto(url, wait_until=args.wait_until, timeout=args.timeout * 1000)
                html = page.evaluate("document.documentElement.outerHTML")
                responses.append(
                    response_record(
                        response_id=f"browser-dom:{record.get('source_id', processed)}",
                        url=url,
                        body=artifact_body_for_canaries(str(html), canaries),
                        status_code=None,
                        origin="browser-dom",
                        content_type="text/html",
                    )
                )
                storage_blob = page.evaluate(
                    "() => JSON.stringify({localStorage: Object.assign({}, window.localStorage), "
                    "sessionStorage: Object.assign({}, window.sessionStorage)})"
                )
                responses.append(
                    response_record(
                        response_id=f"browser-storage:{record.get('source_id', processed)}",
                        url=url,
                        body=artifact_body_for_canaries(str(storage_blob), canaries),
                        status_code=None,
                        origin="browser-storage",
                        content_type="application/json",
                    )
                )
                if rate_delay > 0:
                    time.sleep(rate_delay)
        finally:
            context.close()
            browser.close()
    out_dir = Path(args.out_dir)
    write_jsonl(out_dir / "responses.jsonl", responses)
    return responses


def build_sources(args: argparse.Namespace) -> list[dict[str, Any]]:
    run_id = safe_run_id(args.run_id)
    sources = load_sources([Path(path) for path in args.input])
    records = [source.to_record(run_id) for source in sources]
    out_dir = Path(args.out_dir)
    write_jsonl(out_dir / "sources.jsonl", records)
    write_jsonl(out_dir / "planned_requests.jsonl", (planned_request(record) for record in records))
    write_private_jsonl(
        out_dir / PRIVATE_REPLAY_FILENAME,
        (private_replay_request(source, record) for source, record in zip(sources, records)),
    )
    return records


def load_source_records(path: Path) -> list[dict[str, Any]]:
    records = read_json_records(path)
    return [record for record in records if "source_id" in record and "canary" in record]


def scan(args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    out_dir = Path(args.out_dir)
    source_records = load_source_records(Path(args.sources))
    responses = load_response_records([Path(path) for path in args.response])
    sinks, edges = scan_responses(source_records, responses)
    write_jsonl(out_dir / "sinks.jsonl", sinks)
    write_jsonl(out_dir / "edges.jsonl", edges)
    packets = write_agent_packets(out_dir, source_records, sinks, edges)
    summary = {
        "generated_at": now_iso(),
        "sources": len(source_records),
        "responses": len(responses),
        "sinks": len(sinks),
        "edges": len(edges),
        "agent_packets": packets,
    }
    (out_dir / "summary.json").write_text(json_dump(summary) + "\n", encoding="utf-8")
    return sinks, edges


def cmd_plan(args: argparse.Namespace) -> int:
    records = build_sources(args)
    print(json_dump({"sources": len(records), "out_dir": args.out_dir}))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    sinks, edges = scan(args)
    print(json_dump({"sinks": len(sinks), "edges": len(edges), "out_dir": args.out_dir}))
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    responses = fetch_planned_http(args)
    print(json_dump({"responses": len(responses), "out_dir": args.out_dir}))
    return 0


def cmd_browser_fetch(args: argparse.Namespace) -> int:
    responses = browser_fetch_planned(args)
    print(json_dump({"responses": len(responses), "out_dir": args.out_dir}))
    return 0


def cmd_map(args: argparse.Namespace) -> int:
    source_records = build_sources(args)
    args.sources = str(Path(args.out_dir) / "sources.jsonl")
    sinks, edges = scan(args)
    print(
        json_dump(
            {
                "sources": len(source_records),
                "sinks": len(sinks),
                "edges": len(edges),
                "out_dir": args.out_dir,
            }
        )
    )
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Plan and map inert XSS canaries from saved artifacts."
    )
    sub = root.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan", help="Build sources.jsonl and planned_requests.jsonl.")
    plan.add_argument("--input", action="append", required=True, help="Tool output or source JSONL.")
    plan.add_argument("--out-dir", required=True)
    plan.add_argument("--run-id")
    plan.set_defaults(func=cmd_plan)

    scan_parser = sub.add_parser("scan", help="Scan saved responses for generated canaries.")
    scan_parser.add_argument("--sources", required=True, help="sources.jsonl from plan.")
    scan_parser.add_argument("--response", action="append", required=True, help="Saved response file.")
    scan_parser.add_argument("--out-dir", required=True)
    scan_parser.set_defaults(func=cmd_scan)

    fetch = sub.add_parser("fetch", help="Fetch planned GET canaries over HTTP with scope controls.")
    fetch.add_argument("--planned", required=True, help="planned_requests.jsonl from plan.")
    fetch.add_argument("--out-dir", required=True)
    fetch.add_argument("--offline", action="store_true", help="Do not send requests; write empty responses.jsonl.")
    fetch.add_argument("--program", help="Program slug; loads saved scope from ~/Shared/scopes/<program>.")
    fetch.add_argument("--allow-host", action="append", help="Exact host allowed for live requests.")
    fetch.add_argument("--private-planned", help=f"Private replay artifact. Defaults to {PRIVATE_REPLAY_FILENAME} next to --planned.")
    fetch.add_argument("--allow-sensitive-replay", action="store_true", help="Use private replay URLs when public planned rows are redacted.")
    fetch.add_argument("--max-requests", type=int, default=20)
    fetch.add_argument("--rate-delay", type=float, default=None, help="Delay between requests. Defaults to program policy when available, else 0.5.")
    fetch.add_argument("--timeout", type=int, default=20)
    fetch.add_argument("--max-body-bytes", type=int, default=DEFAULT_MAX_BODY_BYTES)
    fetch.add_argument("--user-agent", default="Ghost-XSS-Canary-Mapper/0.1")
    fetch.set_defaults(func=cmd_fetch)

    browser_fetch = sub.add_parser(
        "browser-fetch", help="Fetch planned GET canaries in Playwright Chromium with scope controls."
    )
    browser_fetch.add_argument("--planned", required=True, help="planned_requests.jsonl from plan.")
    browser_fetch.add_argument("--out-dir", required=True)
    browser_fetch.add_argument("--offline", action="store_true", help="Do not send requests; write empty responses.jsonl.")
    browser_fetch.add_argument("--program", help="Program slug; loads saved scope from ~/Shared/scopes/<program>.")
    browser_fetch.add_argument("--allow-host", action="append", help="Exact host allowed for live requests.")
    browser_fetch.add_argument("--private-planned", help=f"Private replay artifact. Defaults to {PRIVATE_REPLAY_FILENAME} next to --planned.")
    browser_fetch.add_argument("--allow-sensitive-replay", action="store_true", help="Use private replay URLs when public planned rows are redacted.")
    browser_fetch.add_argument("--storage-state", help="Optional Playwright storage state file.")
    browser_fetch.add_argument("--headful", action="store_true")
    browser_fetch.add_argument("--max-requests", type=int, default=20)
    browser_fetch.add_argument("--rate-delay", type=float, default=None, help="Delay between requests. Defaults to program policy when available, else 0.5.")
    browser_fetch.add_argument("--timeout", type=int, default=30)
    browser_fetch.add_argument(
        "--wait-until",
        choices=["commit", "domcontentloaded", "load", "networkidle"],
        default="domcontentloaded",
    )
    browser_fetch.set_defaults(func=cmd_browser_fetch)

    map_parser = sub.add_parser("map", help="Plan sources and scan responses in one command.")
    map_parser.add_argument("--input", action="append", required=True, help="Tool output or source JSONL.")
    map_parser.add_argument("--response", action="append", required=True, help="Saved response file.")
    map_parser.add_argument("--out-dir", required=True)
    map_parser.add_argument("--run-id")
    map_parser.set_defaults(func=cmd_map)
    return root


def main(argv: list[str]) -> int:
    args = parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
