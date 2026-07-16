#!/usr/bin/env python3
"""Script-first JavaScript inventory and chunk packet builder.

This helper handles deterministic high-volume work for the /js skill:
collecting JS URLs from pages or files, downloading bodies, hashing/deduping,
extracting cheap signals, and writing bounded agent packets for deep review.
"""

from __future__ import annotations

import argparse
import hashlib
import html.parser
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


SHARED_WEB_BASE = Path("/mnt/bounty")
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATHS = (
    REPO_ROOT / "config" / "js_analyzer.json",
    Path.home() / ".config" / "bug_bounty_harness" / "js_analyzer.json",
)

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
PATH_RE = re.compile(r"['\"](?P<path>/(?:api|v\d|graphql|gql|rest|backend|auth|oauth|login|admin|user|account|billing|checkout)[^'\"<>\s]{0,180})['\"]", re.IGNORECASE)
PARAM_RE = re.compile(r"[?&]([A-Za-z0-9_.:-]{2,80})=")
SOURCE_MAP_RE = re.compile(r"//#\s*sourceMappingURL=(?P<url>\S+)")
IMPORT_RE = re.compile(r"\bimport\s*(?:\(|[^;\n]+from\s*)['\"]([^'\"]+)['\"]")
SECRET_HINT_RE = re.compile(r"\b(api[_-]?key|secret|token|bearer|authorization|password|client[_-]?secret|private[_-]?key)\b", re.IGNORECASE)
PARAM_NAME_RE = re.compile(
    r"['\"]?([A-Za-z0-9_.:-]*(?:"
    r"id|uuid|slug|token|csrf|state|nonce|redirect|return|next|url|uri|callback|"
    r"role|admin|permission|scope|tenant|team|org|workspace|project|design|owner|"
    r"invoice|coupon|plan|subscription|entitlement|price|billing|checkout|"
    r"file|path|template|webhook|import|export|upload|download|preview"
    r")[A-Za-z0-9_.:-]*)['\"]?\s*[:=]",
    re.IGNORECASE,
)
GRAPHQL_RE = re.compile(r"\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)")
ROUTE_RE = re.compile(r"\b(?:path|route|url|href|to)\s*[:=]\s*['\"]([^'\"]{2,180})['\"]", re.IGNORECASE)
PATH_PARAM_RE = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")
HIDDEN_STATE_RE = re.compile(
    r"(?:\b(?:"
    r"hidden|type\s*[:=]\s*['\"]hidden|data-[A-Za-z0-9_-]+|dataset|"
    r"__NEXT_DATA__|__APOLLO_STATE__|__INITIAL_STATE__|__PRELOADED_STATE__|"
    r"bootstrap|hydration|hydrate|initialData|initialState|"
    r"document\.getElementById"
    r")\b|(?:getAttribute|querySelector)\s*\()",
    re.IGNORECASE,
)

SOURCE_KEYWORDS = {
    "location": re.compile(r"\b(?:location|document\.URL|document\.documentURI|URLSearchParams|hash|search)\b"),
    "storage": re.compile(r"\b(?:localStorage|sessionStorage|indexedDB|cookie)\b"),
    "message": re.compile(r"\b(?:postMessage|message)\b"),
    "form": re.compile(r"\b(?:FormData|HTMLInputElement|querySelector)\b"),
}

SINK_KEYWORDS = {
    "dom_write": re.compile(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b"),
    "script_create": re.compile(r"\b(?:createElement\s*\(\s*['\"]script|appendChild|setAttribute\s*\(\s*['\"]src)\b"),
    "navigation": re.compile(r"\b(?:location\.href|location\.assign|open\()\b"),
    "eval": re.compile(r"\b(?:eval|Function|setTimeout|setInterval)\s*\("),
    "request": re.compile(r"\b(?:fetch|XMLHttpRequest|axios|sendBeacon)\b"),
    "storage_write": re.compile(r"\b(?:localStorage|sessionStorage)\.setItem\b"),
}

FLOW_HINTS = {
    "auth": re.compile(r"\b(?:login|logout|oauth|saml|sso|mfa|password|reset|session|csrf|jwt|token)\b", re.IGNORECASE),
    "access_control": re.compile(r"\b(?:role|permission|admin|owner|tenant|organization|workspace|team|entitlement|scope)(?:\b|[_-])", re.IGNORECASE),
    "object_ids": re.compile(r"\b(?:design|project|folder|user|account|team|org|workspace|tenant|invoice|subscription)[_-]?id\b", re.IGNORECASE),
    "payment": re.compile(r"\b(?:billing|checkout|payment|invoice|coupon|subscription|plan|price|refund|tax)\b", re.IGNORECASE),
    "upload_import_export": re.compile(r"\b(?:upload|import|export|download|attachment|file|blob|media|asset)\b", re.IGNORECASE),
    "server_fetch": re.compile(r"\b(?:webhook|preview|fetchUrl|fetch_url|remoteUrl|remote_url|imageUrl|image_url|callbackUrl|callback_url)\b", re.IGNORECASE),
    "redirect": re.compile(r"\b(?:redirect|returnTo|return_to|next|continue|callback|deeplink|deep_link)\b", re.IGNORECASE),
    "feature_flag": re.compile(r"\b(?:featureFlag|feature_flag|experiment|variant|treatment|rollout|beta)\b", re.IGNORECASE),
    "graphql": re.compile(r"\b(?:graphql|gql|query|mutation|subscription)\b", re.IGNORECASE),
    "realtime": re.compile(r"\b(?:websocket|socket|channel|presence|collab|comment|share|invite)\b", re.IGNORECASE),
}


class ScriptSrcParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        for name, value in attrs:
            if name.lower() == "src" and value:
                self.scripts.append(value)


@dataclass(slots=True)
class JsRecord:
    url: str
    status: int | None
    content_type: str
    byte_count: int
    sha256: str
    artifact_path: str
    reused_download: bool = False
    reused_chunks: bool = False
    page_context: str = ""
    source: str = ""
    source_map: str = ""
    endpoints: list[str] = field(default_factory=list)
    in_scope_endpoints: list[str] = field(default_factory=list)
    external_endpoints: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    secret_hints: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    flow_hints: list[str] = field(default_factory=list)
    interesting_keys: list[str] = field(default_factory=list)
    graphql_operations: list[str] = field(default_factory=list)
    route_hints: list[str] = field(default_factory=list)
    hidden_state_hints: list[str] = field(default_factory=list)
    chunk_count: int = 0


@dataclass(slots=True)
class ExternalIntegration:
    external_url: str
    host: str
    classification: str
    action_policy: str
    allowed_context_actions: list[str]
    found_in_js_url: str
    found_in_sha256: str
    found_in_source: str
    page_context: str
    run_id: str
    evidence_path: str
    in_scope_target_host: str
    first_seen: str
    last_seen: str


@dataclass(slots=True)
class JsProvenance:
    js_url: str
    sha256: str
    run_id: str
    source: str
    page_url: str = ""
    document_url: str = ""
    page_context: str = ""
    proxy_request_id: str = ""
    initiator: str = ""
    referrer: str = ""
    frame_url: str = ""
    method: str = ""
    status: int | None = None
    content_type: str = ""
    timestamp: str = ""
    related_requests: list[str] = field(default_factory=list)


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def read_json_file(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON config {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"invalid JSON config {path}: expected object")
    return data


def load_config(explicit_path: str | None = None) -> dict:
    paths: list[Path] = []
    if explicit_path:
        paths.append(Path(explicit_path).expanduser())
    env_path = os.environ.get("JS_ANALYZER_CONFIG")
    if env_path:
        paths.append(Path(env_path).expanduser())
    paths.extend(DEFAULT_CONFIG_PATHS)

    for path in paths:
        if path.exists():
            config = read_json_file(path)
            config["_config_path"] = str(path)
            return config
    return {}


def program_config(config: dict, program: str) -> dict:
    merged: dict = {}
    defaults = config.get("defaults")
    if isinstance(defaults, dict):
        merged.update(defaults)
    programs = config.get("programs")
    if isinstance(programs, dict):
        specific = programs.get(program)
        if isinstance(specific, dict):
            merged.update(specific)
    return merged


def configured_path(value: object) -> Path | None:
    if not value:
        return None
    if not isinstance(value, str):
        raise SystemExit(f"invalid path config value: expected string, got {type(value).__name__}")
    return Path(value).expanduser()


def resolve_inventory_paths(args: argparse.Namespace, run_id: str) -> tuple[Path, Path, Path, dict]:
    config = load_config(getattr(args, "config", None))
    program_settings = program_config(config, args.program)
    shared_base = configured_path(program_settings.get("shared_web_base") or config.get("shared_web_base")) or SHARED_WEB_BASE
    program_root = configured_path(program_settings.get("program_root")) or shared_base / args.program
    js_root = configured_path(program_settings.get("js_root")) or program_root / "web" / "recon" / "js"

    output_base = configured_path(program_settings.get("output_base")) or js_root
    root = Path(args.output_root).expanduser() if args.output_root else output_base / run_id
    library_root = (
        Path(args.library_root).expanduser()
        if args.library_root
        else configured_path(program_settings.get("library_root")) or js_root / "_library"
    )
    integration_index_root = (
        Path(args.integration_index_root).expanduser()
        if args.integration_index_root
        else configured_path(program_settings.get("integration_index_root"))
        or program_root / "web" / "intel" / "integrations"
    )
    config_summary = {
        "config_path": config.get("_config_path", ""),
        "shared_web_base": str(shared_base),
        "program_root": str(program_root),
        "js_root": str(js_root),
    }
    return root, library_root, integration_index_root, config_summary


def resolve_library_root(args: argparse.Namespace) -> tuple[Path, dict]:
    config = load_config(getattr(args, "config", None))
    program_settings = program_config(config, args.program)
    shared_base = configured_path(program_settings.get("shared_web_base") or config.get("shared_web_base")) or SHARED_WEB_BASE
    program_root = configured_path(program_settings.get("program_root")) or shared_base / args.program
    js_root = configured_path(program_settings.get("js_root")) or program_root / "web" / "recon" / "js"
    library_root = (
        Path(args.library_root).expanduser()
        if args.library_root
        else configured_path(program_settings.get("library_root")) or js_root / "_library"
    )
    return library_root, {
        "config_path": config.get("_config_path", ""),
        "shared_web_base": str(shared_base),
        "program_root": str(program_root),
        "js_root": str(js_root),
    }


def http_get(url: str, timeout: int = 20) -> tuple[bytes, int | None, str]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            "Accept": "*/*",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(), int(getattr(resp, "status", 0) or 0), resp.headers.get("content-type", "")
    except urllib.error.HTTPError as exc:
        return exc.read(), exc.code, exc.headers.get("content-type", "") if exc.headers else ""
    except Exception:
        return b"", None, ""


def normalize_url(value: str, base: str | None = None) -> str | None:
    value = value.strip()
    if not value or value.startswith(("data:", "javascript:", "mailto:")):
        return None
    try:
        if base:
            value = urllib.parse.urljoin(base, value)
        parsed = urllib.parse.urlparse(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return urllib.parse.urlunparse(parsed._replace(fragment=""))


def same_host_or_child(url: str, host_or_domain: str | None) -> bool:
    if not host_or_domain:
        return True
    host = urllib.parse.urlparse(url).hostname or ""
    return host == host_or_domain or host.endswith(f".{host_or_domain}")


def normalize_host_value(value: str) -> str | None:
    value = value.strip()
    if not value or value.startswith("#"):
        return None
    if "://" in value:
        host = urllib.parse.urlparse(value).hostname or ""
    else:
        host = value.split("/", 1)[0]
    host = host.strip().lower().rstrip(".")
    return host or None


def build_scope_hosts(*, target_host: str | None, page: str | None) -> list[str]:
    hosts: list[str] = []
    if target_host:
        normalized = normalize_host_value(target_host)
        if normalized:
            hosts.append(normalized)
    if not hosts and page:
        page_host = urllib.parse.urlparse(page).hostname
        if page_host:
            hosts.append(page_host.lower().rstrip("."))
    return dedupe(hosts)


def in_scope_url(url: str, scope_hosts: list[str]) -> bool:
    if not scope_hosts:
        return True
    return any(same_host_or_child(url, scope_host) for scope_host in scope_hosts)


def url_host(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except ValueError:
        return ""


def classify_external_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    haystack = f"{host} {path} {query}"
    if any(token in haystack for token in ("docs", "help", "support", "knowledgebase", "tutorial", "guide", "policy", "terms", "privacy")):
        return "public_reference"
    if any(token in haystack for token in ("marketplace", "appxlisting", "/apps/", "integration", "integrations", "plugin", "connect")):
        return "integration_reference"
    if any(token in haystack for token in ("callback", "redirect", "return", "oauth", "saml", "provider_id", "client_id", "clientid")):
        return "auth_or_callback_reference"
    if any(token in haystack for token in ("token", "key", "secret", "signature", "signed", "expires", "credential")):
        return "possible_sensitive_reference"
    return "external_reference"


def external_action_policy(classification: str) -> str:
    if classification == "possible_sensitive_reference":
        return "sanitize-and-pivot-to-scoped-leak-question"
    if classification in {"integration_reference", "auth_or_callback_reference"}:
        return "context-only-find-scoped-integration-flow"
    return "context-only-do-not-test-host"


def allowed_context_actions(classification: str) -> list[str]:
    """Read-only actions allowed for out-of-scope URLs discovered in scoped JS."""
    base = ["record_url", "classify_purpose", "preserve_found_location"]
    if classification in {"integration_reference", "auth_or_callback_reference", "public_reference"}:
        return base + ["open_public_page_read_only", "capture_title_and_description"]
    if classification == "possible_sensitive_reference":
        return base + ["sanitize_url_before_notes", "do_not_open_without_approval"]
    return base


def collect_from_page(page_url: str, page_context: str, scope_hosts: list[str]) -> tuple[list[str], list[dict]]:
    body, status, content_type = http_get(page_url)
    if not body:
        return [], []
    text = body.decode("utf-8", errors="ignore")
    parser = ScriptSrcParser()
    parser.feed(text)
    js_urls = []
    for script in parser.scripts:
        normalized = normalize_url(script, page_url)
        if normalized and in_scope_url(normalized, scope_hosts):
            js_urls.append(normalized)
    page_records = [{
        "page_url": page_url,
        "status": status,
        "content_type": content_type,
        "page_context": page_context,
        "script_count": len(js_urls),
    }]
    return dedupe(js_urls), page_records


def extract_signals(text: str, base_url: str, scope_hosts: list[str] | None = None) -> dict:
    endpoints = set()
    for match in URL_RE.findall(text):
        normalized = normalize_url(match.rstrip(".,;)"), base_url)
        if normalized:
            endpoints.add(normalized)
    for match in PATH_RE.finditer(text):
        endpoints.add(urllib.parse.urljoin(base_url, match.group("path")))

    params = set(PARAM_RE.findall(text))
    for endpoint in endpoints:
        try:
            parsed = urllib.parse.urlparse(endpoint)
        except ValueError:
            continue
        params.update(name for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

    source_map = ""
    sm = SOURCE_MAP_RE.search(text[-3000:])
    if sm:
        source_map = normalize_url(sm.group("url"), base_url) or ""

    secret_hints = sorted(set(m.group(1).lower() for m in SECRET_HINT_RE.finditer(text)))[:50]
    sources = sorted(name for name, pattern in SOURCE_KEYWORDS.items() if pattern.search(text))
    sinks = sorted(name for name, pattern in SINK_KEYWORDS.items() if pattern.search(text))
    flow_hints = sorted(name for name, pattern in FLOW_HINTS.items() if pattern.search(text))
    interesting_keys = set(PARAM_NAME_RE.findall(text))
    graphql_operations = sorted(set(GRAPHQL_RE.findall(text)))[:100]
    route_hints = sorted(
        hint for hint in set(ROUTE_RE.findall(text))
        if hint.startswith(("/", "http", "api", "v1", "v2", "graphql", "gql"))
    )[:200]
    hidden_state_hints = sorted(set(match.group(0) for match in HIDDEN_STATE_RE.finditer(text)))[:100]
    for route in route_hints:
        interesting_keys.update(PATH_PARAM_RE.findall(route))
    imports = sorted(set(IMPORT_RE.findall(text)))[:100]

    sorted_endpoints = sorted(endpoints)
    if scope_hosts:
        in_scope_endpoints = [endpoint for endpoint in sorted_endpoints if in_scope_url(endpoint, scope_hosts)]
        external_endpoints = [endpoint for endpoint in sorted_endpoints if not in_scope_url(endpoint, scope_hosts)]
    else:
        in_scope_endpoints = sorted_endpoints
        external_endpoints = []

    return {
        "endpoints": sorted_endpoints[:500],
        "in_scope_endpoints": in_scope_endpoints[:500],
        "external_endpoints": external_endpoints[:500],
        "params": sorted(params)[:300],
        "source_map": source_map,
        "imports": imports,
        "secret_hints": secret_hints,
        "sources": sources,
        "sinks": sinks,
        "flow_hints": flow_hints,
        "interesting_keys": sorted(interesting_keys)[:300],
        "graphql_operations": graphql_operations,
        "route_hints": route_hints,
        "hidden_state_hints": hidden_state_hints,
    }


def chunk_text(text: str, size: int, overlap: int) -> list[tuple[int, int, str]]:
    if size <= 0 or len(text) <= size:
        return [(0, len(text), text)]
    chunks: list[tuple[int, int, str]] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        chunks.append((start, end, text[start:end]))
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


def write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def append_jsonl(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def load_ledger(path: Path) -> dict:
    if not path.exists():
        return {"schema_version": 1, "urls": {}, "files": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": 1, "urls": {}, "files": {}}
    if not isinstance(data, dict):
        return {"schema_version": 1, "urls": {}, "files": {}}
    data.setdefault("schema_version", 1)
    data.setdefault("urls", {})
    data.setdefault("files", {})
    return data


def save_ledger(path: Path, ledger: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def write_external_integration_index(index_root: Path, rows: list[ExternalIntegration]) -> dict[str, str]:
    """Append scoped-run external URL evidence to the program integration index."""
    if not rows:
        return {}
    raw_path = index_root / "external_urls.jsonl"
    raw_rows: list[dict] = []
    if raw_path.exists():
        for line in raw_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                raw_rows.append(row)
    raw_rows.extend(asdict(row) for row in rows)
    deduped_reversed: list[dict] = []
    seen_keys: set[tuple[str, str, str]] = set()
    for row in reversed(raw_rows):
        key = (
            str(row.get("external_url") or ""),
            str(row.get("found_in_sha256") or ""),
            str(row.get("run_id") or ""),
        )
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped_reversed.append(row)
    deduped_rows = list(reversed(deduped_reversed))
    write_jsonl(raw_path, deduped_rows)

    by_host: dict[str, dict] = {}
    for row in deduped_rows:
        host = row.get("host")
        if not host:
            continue
        entry = by_host.setdefault(host, {
            "host": host,
            "classifications": [],
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "examples": [],
        })
        classification = row.get("classification")
        if classification and classification not in entry["classifications"]:
            entry["classifications"].append(classification)
        if row.get("last_seen") and str(row["last_seen"]) > str(entry.get("last_seen") or ""):
            entry["last_seen"] = row["last_seen"]
        if row.get("first_seen") and str(row["first_seen"]) < str(entry.get("first_seen") or row["first_seen"]):
            entry["first_seen"] = row["first_seen"]
        if len(entry["examples"]) < 8:
            entry["examples"].append({
                "external_url": row.get("external_url"),
                "found_in_js_url": row.get("found_in_js_url"),
                "run_id": row.get("run_id"),
                "classification": classification,
                "action_policy": row.get("action_policy"),
                "evidence_path": row.get("evidence_path"),
            })

    host_index_path = index_root / "external_hosts.json"
    host_index_path.write_text(
        json.dumps({
            "updated": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "hosts": sorted(by_host.values(), key=lambda item: item["host"]),
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "external_urls": str(raw_path),
        "external_hosts": str(host_index_path),
    }


def load_provenance_hints(path: Path | None) -> dict[str, list[dict]]:
    if not path:
        return {}
    hints: dict[str, list[dict]] = {}
    for row in read_jsonl(path):
        raw_url = str(row.get("js_url") or row.get("url") or "")
        normalized = normalize_url(raw_url)
        if not normalized:
            continue
        hints.setdefault(normalized, []).append(row)
    return hints


def merge_related_requests(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [value]
    return []


def hint_int(value: object, fallback: int | None = None) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return fallback


def build_provenance_rows(
    *,
    record: JsRecord,
    run_id: str,
    source: str,
    page_url: str,
    target_host: str,
    hints: list[dict],
) -> list[JsProvenance]:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    if not hints:
        return [JsProvenance(
            js_url=record.url,
            sha256=record.sha256,
            run_id=run_id,
            source=source,
            page_url=page_url,
            document_url=page_url,
            page_context=record.page_context,
            status=record.status,
            content_type=record.content_type,
            timestamp=now,
        )]

    rows: list[JsProvenance] = []
    for hint in hints:
        hint_page = str(hint.get("page_url") or hint.get("document_url") or page_url or "")
        rows.append(JsProvenance(
            js_url=record.url,
            sha256=record.sha256,
            run_id=run_id,
            source=str(hint.get("source") or source),
            page_url=hint_page,
            document_url=str(hint.get("document_url") or hint_page),
            page_context=str(hint.get("page_context") or record.page_context),
            proxy_request_id=str(hint.get("proxy_request_id") or hint.get("request_id") or ""),
            initiator=str(hint.get("initiator") or ""),
            referrer=str(hint.get("referrer") or ""),
            frame_url=str(hint.get("frame_url") or ""),
            method=str(hint.get("method") or ""),
            status=hint_int(hint.get("status"), record.status),
            content_type=str(hint.get("content_type") or record.content_type),
            timestamp=str(hint.get("timestamp") or now),
            related_requests=merge_related_requests(hint.get("related_requests")),
        ))
    return rows


def summarize_provenance(rows: list[dict]) -> dict:
    page_urls = dedupe(str(row.get("page_url") or "") for row in rows if row.get("page_url"))
    document_urls = dedupe(str(row.get("document_url") or "") for row in rows if row.get("document_url"))
    page_contexts = dedupe(str(row.get("page_context") or "") for row in rows if row.get("page_context"))
    sources = dedupe(str(row.get("source") or "") for row in rows if row.get("source"))
    proxy_request_ids = dedupe(str(row.get("proxy_request_id") or "") for row in rows if row.get("proxy_request_id"))
    related_requests: list[str] = []
    for row in rows:
        related_requests.extend(str(item) for item in row.get("related_requests") or [] if str(item))
    return {
        "row_count": len(rows),
        "page_urls": page_urls[:50],
        "document_urls": document_urls[:50],
        "page_contexts": page_contexts[:50],
        "sources": sources[:50],
        "proxy_request_ids": proxy_request_ids[:50],
        "related_requests": dedupe(related_requests)[:100],
    }


def build_metadata_row(
    *,
    record: JsRecord,
    run_id: str,
    target_host: str | None,
    packet_rows: list[dict],
    provenance_rows: list[dict],
    library_root: Path,
    generated_at: str,
) -> dict:
    chunk_paths = [str(row.get("chunk_path") or "") for row in packet_rows if row.get("chunk_path")]
    packet_paths = [str(row.get("packet_path") or "") for row in packet_rows if row.get("packet_path")]
    chunk_set_keys = dedupe(str(row.get("chunk_set_key") or "") for row in packet_rows if row.get("chunk_set_key"))
    row = asdict(record)
    row.update({
        "metadata_schema_version": 2,
        "run_id": run_id,
        "generated_at": generated_at,
        "target_host": target_host or "",
        "signal_counts": {
            "endpoints": len(record.endpoints),
            "in_scope_endpoints": len(record.in_scope_endpoints),
            "external_endpoints": len(record.external_endpoints),
            "params": len(record.params),
            "imports": len(record.imports),
            "secret_hints": len(record.secret_hints),
            "sources": len(record.sources),
            "sinks": len(record.sinks),
            "flow_hints": len(record.flow_hints),
            "interesting_keys": len(record.interesting_keys),
            "graphql_operations": len(record.graphql_operations),
            "route_hints": len(record.route_hints),
            "hidden_state_hints": len(record.hidden_state_hints),
        },
        "chunk_set_keys": chunk_set_keys,
        "chunk_paths": chunk_paths,
        "packet_paths": packet_paths,
        "provenance": summarize_provenance(provenance_rows),
        "artifact_links": {
            "download": record.artifact_path,
            "library_root": str(library_root),
            "library_metadata": str(library_root / "metadata.jsonl"),
            "library_provenance": str(library_root / "provenance.jsonl"),
            "js_info_db": str(library_root / "js_info.sqlite"),
            "chunks": chunk_paths,
            "packets": packet_paths,
        },
    })
    return row


def write_provenance_table(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS js_provenance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                js_url TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                run_id TEXT NOT NULL,
                source TEXT,
                page_url TEXT,
                document_url TEXT,
                page_context TEXT,
                proxy_request_id TEXT,
                initiator TEXT,
                referrer TEXT,
                frame_url TEXT,
                method TEXT,
                status INTEGER,
                content_type TEXT,
                timestamp TEXT,
                related_requests_json TEXT,
                UNIQUE(js_url, sha256, run_id, source, page_url, proxy_request_id, timestamp)
            )
        """)
        db.executemany(
            """
            INSERT OR IGNORE INTO js_provenance (
                js_url, sha256, run_id, source, page_url, document_url,
                page_context, proxy_request_id, initiator, referrer, frame_url,
                method, status, content_type, timestamp, related_requests_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    str(row.get("js_url") or ""),
                    str(row.get("sha256") or ""),
                    str(row.get("run_id") or ""),
                    str(row.get("source") or ""),
                    str(row.get("page_url") or ""),
                    str(row.get("document_url") or ""),
                    str(row.get("page_context") or ""),
                    str(row.get("proxy_request_id") or ""),
                    str(row.get("initiator") or ""),
                    str(row.get("referrer") or ""),
                    str(row.get("frame_url") or ""),
                    str(row.get("method") or ""),
                    row.get("status") if isinstance(row.get("status"), int) else None,
                    str(row.get("content_type") or ""),
                    str(row.get("timestamp") or ""),
                    json.dumps(row.get("related_requests") or []),
                )
                for row in rows
            ],
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_provenance_js_url ON js_provenance(js_url)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_provenance_sha256 ON js_provenance(sha256)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_provenance_page_url ON js_provenance(page_url)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_provenance_source ON js_provenance(source)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_provenance_context ON js_provenance(page_context)")
        db.commit()


def write_metadata_db(path: Path, metadata_rows: list[dict], packet_rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS js_files (
                sha256 TEXT PRIMARY KEY,
                artifact_path TEXT NOT NULL,
                byte_count INTEGER NOT NULL,
                content_type TEXT,
                first_seen TEXT,
                last_seen TEXT,
                latest_run_id TEXT,
                target_host TEXT,
                source_map TEXT,
                chunk_count INTEGER,
                signal_counts_json TEXT,
                metadata_json TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS js_url_aliases (
                js_url TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                latest_run_id TEXT,
                status INTEGER,
                content_type TEXT,
                source TEXT,
                page_context TEXT,
                PRIMARY KEY (js_url, sha256)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS js_artifacts (
                sha256 TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                run_id TEXT,
                chunk_set_key TEXT,
                chunk_index INTEGER,
                PRIMARY KEY (sha256, artifact_type, artifact_path)
            )
        """)
        db.executemany(
            """
            INSERT INTO js_files (
                sha256, artifact_path, byte_count, content_type, first_seen,
                last_seen, latest_run_id, target_host, source_map, chunk_count,
                signal_counts_json, metadata_json
            ) VALUES (?, ?, ?, ?, COALESCE((SELECT first_seen FROM js_files WHERE sha256 = ?), ?), ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
                artifact_path = excluded.artifact_path,
                byte_count = excluded.byte_count,
                content_type = excluded.content_type,
                last_seen = excluded.last_seen,
                latest_run_id = excluded.latest_run_id,
                target_host = excluded.target_host,
                source_map = excluded.source_map,
                chunk_count = excluded.chunk_count,
                signal_counts_json = excluded.signal_counts_json,
                metadata_json = excluded.metadata_json
            """,
            [
                (
                    str(row.get("sha256") or ""),
                    str(row.get("artifact_path") or ""),
                    int(row.get("byte_count") or 0),
                    str(row.get("content_type") or ""),
                    str(row.get("sha256") or ""),
                    str(row.get("generated_at") or ""),
                    str(row.get("generated_at") or ""),
                    str(row.get("run_id") or ""),
                    str(row.get("target_host") or ""),
                    str(row.get("source_map") or ""),
                    int(row.get("chunk_count") or 0),
                    json.dumps(row.get("signal_counts") or {}, sort_keys=True),
                    json.dumps(row, sort_keys=True),
                )
                for row in metadata_rows
            ],
        )
        db.executemany(
            """
            INSERT INTO js_url_aliases (
                js_url, sha256, first_seen, last_seen, latest_run_id,
                status, content_type, source, page_context
            ) VALUES (?, ?, COALESCE((SELECT first_seen FROM js_url_aliases WHERE js_url = ? AND sha256 = ?), ?), ?, ?, ?, ?, ?, ?)
            ON CONFLICT(js_url, sha256) DO UPDATE SET
                last_seen = excluded.last_seen,
                latest_run_id = excluded.latest_run_id,
                status = excluded.status,
                content_type = excluded.content_type,
                source = excluded.source,
                page_context = excluded.page_context
            """,
            [
                (
                    str(row.get("url") or ""),
                    str(row.get("sha256") or ""),
                    str(row.get("url") or ""),
                    str(row.get("sha256") or ""),
                    str(row.get("generated_at") or ""),
                    str(row.get("generated_at") or ""),
                    str(row.get("run_id") or ""),
                    row.get("status") if isinstance(row.get("status"), int) else None,
                    str(row.get("content_type") or ""),
                    str(row.get("source") or ""),
                    str(row.get("page_context") or ""),
                )
                for row in metadata_rows
            ],
        )
        artifact_rows: list[tuple] = []
        for row in metadata_rows:
            sha = str(row.get("sha256") or "")
            run_id = str(row.get("run_id") or "")
            if row.get("artifact_path"):
                artifact_rows.append((sha, "download", str(row["artifact_path"]), run_id, "", None))
            for packet_path in row.get("packet_paths") or []:
                artifact_rows.append((sha, "packet", str(packet_path), run_id, "", None))
            for chunk_path in row.get("chunk_paths") or []:
                artifact_rows.append((sha, "chunk", str(chunk_path), run_id, "", None))
        for packet in packet_rows:
            sha = str(packet.get("sha256") or "")
            artifact_rows.append((
                sha,
                "packet",
                str(packet.get("packet_path") or ""),
                "",
                str(packet.get("chunk_set_key") or ""),
                packet.get("chunk_index") if isinstance(packet.get("chunk_index"), int) else None,
            ))
            artifact_rows.append((
                sha,
                "chunk",
                str(packet.get("chunk_path") or ""),
                "",
                str(packet.get("chunk_set_key") or ""),
                packet.get("chunk_index") if isinstance(packet.get("chunk_index"), int) else None,
            ))
        db.executemany(
            """
            INSERT OR IGNORE INTO js_artifacts (
                sha256, artifact_type, artifact_path, run_id, chunk_set_key, chunk_index
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [row for row in artifact_rows if row[0] and row[2]],
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_files_run ON js_files(latest_run_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_alias_sha ON js_url_aliases(sha256)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_alias_url ON js_url_aliases(js_url)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_artifacts_sha ON js_artifacts(sha256)")
        db.commit()


def normalize_observation_row(row: dict) -> dict:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    normalized = dict(row)
    normalized.setdefault("created_at", now)
    normalized.setdefault("updated_at", normalized["created_at"])
    normalized.setdefault("status", "observed")
    normalized.setdefault("confidence", "")
    normalized.setdefault("lens", "")
    normalized.setdefault("run_id", "")
    normalized.setdefault("agent_id", "")
    normalized.setdefault("sha256", "")
    normalized.setdefault("js_url", "")
    normalized.setdefault("packet_path", "")
    normalized.setdefault("title", "")
    normalized.setdefault("summary", "")
    normalized.setdefault("evidence", [])
    normalized.setdefault("next_action", "")
    normalized.setdefault("artifact_path", "")
    if not normalized.get("observation_id"):
        identity = json.dumps({
            "sha256": normalized.get("sha256"),
            "js_url": normalized.get("js_url"),
            "packet_path": normalized.get("packet_path"),
            "lens": normalized.get("lens"),
            "run_id": normalized.get("run_id"),
            "title": normalized.get("title"),
            "summary": normalized.get("summary"),
        }, sort_keys=True)
        normalized["observation_id"] = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    return normalized


def write_observations_table(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS js_observations (
                observation_id TEXT PRIMARY KEY,
                sha256 TEXT,
                js_url TEXT,
                packet_path TEXT,
                lens TEXT,
                run_id TEXT,
                agent_id TEXT,
                title TEXT,
                summary TEXT,
                status TEXT,
                confidence TEXT,
                evidence_json TEXT,
                next_action TEXT,
                artifact_path TEXT,
                created_at TEXT,
                updated_at TEXT,
                observation_json TEXT NOT NULL
            )
        """)
        db.executemany(
            """
            INSERT INTO js_observations (
                observation_id, sha256, js_url, packet_path, lens, run_id,
                agent_id, title, summary, status, confidence, evidence_json,
                next_action, artifact_path, created_at, updated_at,
                observation_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(observation_id) DO UPDATE SET
                sha256 = excluded.sha256,
                js_url = excluded.js_url,
                packet_path = excluded.packet_path,
                lens = excluded.lens,
                run_id = excluded.run_id,
                agent_id = excluded.agent_id,
                title = excluded.title,
                summary = excluded.summary,
                status = excluded.status,
                confidence = excluded.confidence,
                evidence_json = excluded.evidence_json,
                next_action = excluded.next_action,
                artifact_path = excluded.artifact_path,
                updated_at = excluded.updated_at,
                observation_json = excluded.observation_json
            """,
            [
                (
                    str(row.get("observation_id") or ""),
                    str(row.get("sha256") or ""),
                    str(row.get("js_url") or ""),
                    str(row.get("packet_path") or ""),
                    str(row.get("lens") or ""),
                    str(row.get("run_id") or ""),
                    str(row.get("agent_id") or ""),
                    str(row.get("title") or ""),
                    str(row.get("summary") or ""),
                    str(row.get("status") or ""),
                    str(row.get("confidence") or ""),
                    json.dumps(row.get("evidence") or [], sort_keys=True),
                    str(row.get("next_action") or ""),
                    str(row.get("artifact_path") or ""),
                    str(row.get("created_at") or ""),
                    str(row.get("updated_at") or ""),
                    json.dumps(row, sort_keys=True),
                )
                for row in rows
            ],
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_observations_sha ON js_observations(sha256)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_observations_url ON js_observations(js_url)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_observations_packet ON js_observations(packet_path)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_observations_lens ON js_observations(lens)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_js_observations_run ON js_observations(run_id)")
        db.commit()


def append_observations(*, observations_path: Path, db_path: Path, rows: list[dict]) -> list[dict]:
    normalized_rows = [normalize_observation_row(row) for row in rows]
    append_jsonl(observations_path, normalized_rows)
    write_observations_table(db_path, read_jsonl(observations_path))
    return normalized_rows


def ledger_lookup_url(ledger: dict, url: str) -> str | None:
    entry = ledger.get("urls", {}).get(url)
    if isinstance(entry, dict):
        sha = entry.get("sha256")
        return sha if isinstance(sha, str) and sha else None
    if isinstance(entry, str):
        return entry
    return None


def update_ledger_for_file(
    ledger: dict,
    *,
    url: str,
    sha256: str,
    artifact_path: Path,
    byte_count: int,
    status: int | None,
    content_type: str,
    chunk_set_key: str,
    chunk_count: int,
    chunk_manifest_path: Path,
) -> None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    urls = ledger.setdefault("urls", {})
    files = ledger.setdefault("files", {})
    urls[url] = {
        "sha256": sha256,
        "last_seen": now,
        "status": status,
        "content_type": content_type,
    }
    file_entry = files.setdefault(sha256, {})
    first_seen = file_entry.get("first_seen") or now
    known_urls = file_entry.get("urls") if isinstance(file_entry.get("urls"), list) else []
    if url not in known_urls:
        known_urls.append(url)
    chunk_sets = file_entry.get("chunk_sets") if isinstance(file_entry.get("chunk_sets"), dict) else {}
    chunk_sets[chunk_set_key] = {
        "chunk_count": chunk_count,
        "manifest_path": str(chunk_manifest_path),
        "last_seen": now,
    }
    files[sha256] = {
        "first_seen": first_seen,
        "last_seen": now,
        "artifact_path": str(artifact_path),
        "byte_count": byte_count,
        "urls": known_urls,
        "chunk_sets": chunk_sets,
    }


def load_body_from_ledger(
    ledger: dict,
    *,
    url: str,
    downloads_dir: Path,
) -> tuple[bytes, str, Path] | None:
    sha = ledger_lookup_url(ledger, url)
    if not sha:
        return None
    artifact_path = downloads_dir / f"{sha}.js"
    if not artifact_path.exists():
        file_entry = ledger.get("files", {}).get(sha, {})
        candidate = file_entry.get("artifact_path") if isinstance(file_entry, dict) else None
        if candidate:
            artifact_path = Path(candidate)
    if not artifact_path.exists():
        return None
    body = artifact_path.read_bytes()
    actual_sha = hashlib.sha256(body).hexdigest()
    if actual_sha != sha:
        return None
    return body, sha, artifact_path


def cached_artifact_from_ledger(
    ledger: dict,
    *,
    url: str,
    downloads_dir: Path,
) -> tuple[str, Path] | None:
    sha = ledger_lookup_url(ledger, url)
    if not sha:
        return None
    artifact_path = downloads_dir / f"{sha}.js"
    if not artifact_path.exists():
        file_entry = ledger.get("files", {}).get(sha, {})
        candidate = file_entry.get("artifact_path") if isinstance(file_entry, dict) else None
        if candidate:
            artifact_path = Path(candidate)
    if not artifact_path.exists():
        return None
    return sha, artifact_path


def write_chunk_set(
    *,
    chunks_root: Path,
    sha256: str,
    chunks: list[tuple[int, int, str]],
    chunk_size: int,
    chunk_overlap: int,
) -> tuple[str, Path, list[dict], bool]:
    chunk_set_key = f"size-{chunk_size}_overlap-{chunk_overlap}"
    chunk_dir = chunks_root / sha256 / chunk_set_key
    manifest_path = chunk_dir / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            rows = manifest.get("chunks", [])
            if isinstance(rows, list) and len(rows) == len(chunks) and all(Path(row.get("chunk_path", "")).exists() for row in rows if isinstance(row, dict)):
                return chunk_set_key, manifest_path, rows, True
        except (OSError, json.JSONDecodeError):
            pass

    chunk_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    for chunk_index, (start, end, chunk) in enumerate(chunks):
        chunk_path = chunk_dir / f"{chunk_index + 1:03d}.js"
        chunk_path.write_text(chunk, encoding="utf-8")
        rows.append({
            "sha256": sha256,
            "chunk_index": chunk_index,
            "chunk_count": len(chunks),
            "chunk_path": str(chunk_path),
            "byte_start": start,
            "byte_end": end,
        })
    manifest = {
        "sha256": sha256,
        "chunk_set_key": chunk_set_key,
        "chunk_size": chunk_size,
        "chunk_overlap": chunk_overlap,
        "chunk_count": len(chunks),
        "chunks": rows,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return chunk_set_key, manifest_path, rows, False


def build_packet(record: JsRecord, chunk_index: int, start: int, end: int, chunk: str) -> str:
    lines = [
        f"# JS Deep Review Packet {chunk_index + 1}/{record.chunk_count}",
        "",
        f"- URL: {record.url}",
        f"- SHA256: {record.sha256}",
        f"- Bytes: {record.byte_count}",
        f"- Chunk byte range: {start}-{end}",
        f"- Page context: {record.page_context or 'unknown'}",
        f"- Source map: {record.source_map or 'none detected'}",
        f"- In-scope extracted endpoints: {len(record.in_scope_endpoints)}",
        f"- External integration/reference endpoints: {len(record.external_endpoints)}",
        f"- Sources: {', '.join(record.sources) or 'none detected'}",
        f"- Sinks: {', '.join(record.sinks) or 'none detected'}",
        f"- Flow hints: {', '.join(record.flow_hints) or 'none detected'}",
        f"- Interesting keys: {', '.join(record.interesting_keys[:40]) or 'none detected'}",
        f"- GraphQL operations: {', '.join(record.graphql_operations[:20]) or 'none detected'}",
        f"- Hidden/bootstrap state hints: {', '.join(record.hidden_state_hints[:30]) or 'none detected'}",
        f"- Params: {', '.join(record.params[:40]) or 'none detected'}",
        "",
        "## Review Goals",
        "",
        "- Identify flows, endpoints, params, auth/session/storage behavior, source-to-sink paths, object or tenant assumptions, and vuln-lane handoffs.",
        "- Prefer exploitable surface over generic secret scanning: hidden routes, request fields, object IDs, redirect/fetch/import/export/upload/payment/auth behavior, API clients, and dataflow.",
        "- Do function-level tracing: name the source value, intermediate variables/functions, caller/callee path, final sink or request field, and whether the value appears attacker-controlled.",
        "- Backtrace suspicious sinks or bad practices to the nearest source. If controllability is unclear, say exactly which caller, event handler, DOM node, bootstrap JSON field, or proxy request must be inspected next.",
        "- Check hidden page state: hidden inputs, data-* attributes, non-rendered JSON/script blobs, hydration/bootstrap globals, feature flags, and DOM nodes read by this chunk but not visible in the page UI.",
        "- If a function looks important, inspect nearby callers/callees in adjacent chunks from the same chunk set before deciding confidence.",
        "- Treat regex hits as hints, not findings. Verify impact before promotion.",
        "- Keep scope boundaries explicit: Canva-owned endpoints can become test targets; external integration/reference endpoints are read-only context/evidence only unless program scope explicitly includes them.",
        "- Produce structured notes: endpoints, params, interesting keys, flows, sources, sinks, high-value key signals, confidence, and next tests.",
        "",
        "## Expected Review Output",
        "",
        "- Leads: concise title plus owning lane, for example `/ato`, `/access-control`, `/idor`, `/dom-xss`, `/ssrf`, `/request-exploration`, `/analyze-endpoint`, or `/create-wordlists`.",
        "- Evidence: exact strings, functions, fields, routes, or chunk lines that support the lead.",
        "- Trace: `source -> transforms/checks -> caller/callee -> sink/request/DOM effect`; include controllability and missing proof.",
        "- Confidence and gating condition: what must be true before this becomes worth live testing.",
        "- Adjacent chunks to inspect: callers, callees, lazy imports, source map modules, or packet numbers from the same chunk set.",
        "- Next test: one bounded follow-up action using owned accounts/resources.",
        "",
        "## Nearby In-Scope Extracted Endpoints",
        "",
    ]
    lines.extend(f"- {endpoint}" for endpoint in record.in_scope_endpoints[:80])
    if record.external_endpoints:
        lines.extend([
            "",
            "## External Integration/Reference Endpoints",
            "",
            "Read-only context only: agents may open public pages to understand purpose, title, description, and parameters. Do not fuzz, mutate, replay, authenticate, or probe these hosts unless scope explicitly includes them.",
            "",
        ])
        lines.extend(f"- {endpoint}" for endpoint in record.external_endpoints[:80])
    if record.route_hints:
        lines.extend(["", "## Route Hints", ""])
        lines.extend(f"- {route}" for route in record.route_hints[:80])
    lines.extend([
        "",
        "## Chunk",
        "",
        "```javascript",
        chunk,
        "```",
        "",
    ])
    return "\n".join(lines)


def command_inventory(args: argparse.Namespace) -> int:
    run_id = args.run_id or f"js-{utc_stamp()}"
    root, library_root, integration_index_root, config_summary = resolve_inventory_paths(args, run_id)
    provenance_input = Path(args.provenance_input).expanduser() if args.provenance_input else None
    downloads_dir = library_root / "downloads"
    library_chunks_dir = library_root / "chunks"
    packets_dir = root / "packets"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    library_chunks_dir.mkdir(parents=True, exist_ok=True)
    packets_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = library_root / "ledger.json"
    library_provenance_path = library_root / "provenance.jsonl"
    library_metadata_path = library_root / "metadata.jsonl"
    library_observations_path = library_root / "observations.jsonl"
    js_info_db_path = library_root / "js_info.sqlite"
    ledger = load_ledger(ledger_path)
    provenance_hints = load_provenance_hints(provenance_input)

    target_host = normalize_host_value(args.target_host) if args.target_host else None
    scope_hosts = build_scope_hosts(target_host=target_host, page=args.page)

    urls: list[str] = []
    page_records: list[dict] = []
    if args.input:
        urls.extend(read_lines(Path(args.input).expanduser()))
    if args.page:
        page_urls, records = collect_from_page(args.page, args.page_context or "", scope_hosts)
        urls.extend(page_urls)
        page_records.extend(records)

    normalized_urls = []
    for url in urls:
        normalized = normalize_url(url)
        if normalized and normalized.lower().split("?", 1)[0].endswith(".js") and in_scope_url(normalized, scope_hosts):
            normalized_urls.append(normalized)
    normalized_urls = dedupe(normalized_urls)
    if args.limit:
        normalized_urls = normalized_urls[: args.limit]

    records: list[JsRecord] = []
    packet_rows: list[dict] = []
    external_integration_rows: list[ExternalIntegration] = []
    provenance_rows: list[JsProvenance] = []
    provenance_rows_by_sha: dict[str, list[dict]] = {}
    reused_downloads = 0
    reused_chunk_sets = 0
    skipped_cached_urls = 0
    for index, url in enumerate(normalized_urls, start=1):
        if args.skip_cached_processing and not args.refresh:
            cached_artifact = cached_artifact_from_ledger(ledger, url=url, downloads_dir=downloads_dir)
            if cached_artifact:
                skipped_cached_urls += 1
                sha, artifact_path = cached_artifact
                print(
                    f"[{index}/{len(normalized_urls)}] {url} -> skipped cached "
                    f"{sha[:16]} {artifact_path}",
                    file=sys.stderr,
                )
                continue

        reused_download = False
        cached = None if args.refresh else load_body_from_ledger(ledger, url=url, downloads_dir=downloads_dir)
        if cached:
            body, digest, artifact_path = cached
            status = None
            content_type = ""
            reused_download = True
            reused_downloads += 1
        else:
            if args.delay:
                time.sleep(args.delay)
            body, status, content_type = http_get(url, timeout=args.timeout)
            if not body:
                continue
            digest = hashlib.sha256(body).hexdigest()
            artifact_path = downloads_dir / f"{digest}.js"
            if artifact_path.exists():
                reused_download = True
                reused_downloads += 1
            else:
                artifact_path.write_bytes(body)
        text = body.decode("utf-8", errors="ignore")
        signals = extract_signals(text, url, scope_hosts)
        chunks = chunk_text(text, args.chunk_size, args.chunk_overlap)
        chunk_set_key, chunk_manifest_path, chunk_rows, reused_chunks = write_chunk_set(
            chunks_root=library_chunks_dir,
            sha256=digest,
            chunks=chunks,
            chunk_size=args.chunk_size,
            chunk_overlap=args.chunk_overlap,
        )
        if reused_chunks:
            reused_chunk_sets += 1
        record = JsRecord(
            url=url,
            status=status,
            content_type=content_type,
            byte_count=len(body),
            sha256=digest,
            artifact_path=str(artifact_path),
            reused_download=reused_download,
            reused_chunks=reused_chunks,
            page_context=args.page_context or "",
            source=args.input or args.page or "",
            source_map=signals["source_map"],
            endpoints=signals["endpoints"],
            in_scope_endpoints=signals["in_scope_endpoints"],
            external_endpoints=signals["external_endpoints"],
            params=signals["params"],
            imports=signals["imports"],
            secret_hints=signals["secret_hints"],
            sources=signals["sources"],
            sinks=signals["sinks"],
            flow_hints=signals["flow_hints"],
            interesting_keys=signals["interesting_keys"],
            graphql_operations=signals["graphql_operations"],
            route_hints=signals["route_hints"],
            hidden_state_hints=signals["hidden_state_hints"],
            chunk_count=len(chunks),
        )
        records.append(record)
        record_provenance_rows = build_provenance_rows(
            record=record,
            run_id=run_id,
            source=args.provenance_source or args.input or args.page or "",
            page_url=args.page or "",
            target_host=target_host or "",
            hints=provenance_hints.get(url, []),
        )
        provenance_rows.extend(record_provenance_rows)
        provenance_rows_by_sha.setdefault(digest, []).extend(asdict(row) for row in record_provenance_rows)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        for external_url in record.external_endpoints:
            host = url_host(external_url)
            classification = classify_external_url(external_url)
            external_integration_rows.append(ExternalIntegration(
                external_url=external_url,
                host=host,
                classification=classification,
                action_policy=external_action_policy(classification),
                allowed_context_actions=allowed_context_actions(classification),
                found_in_js_url=url,
                found_in_sha256=digest,
                found_in_source=record.source,
                page_context=record.page_context,
                run_id=run_id,
                evidence_path=str(root / "metadata.jsonl"),
                in_scope_target_host=",".join(scope_hosts),
                first_seen=now,
                last_seen=now,
            ))
        update_ledger_for_file(
            ledger,
            url=url,
            sha256=digest,
            artifact_path=artifact_path,
            byte_count=len(body),
            status=status,
            content_type=content_type,
            chunk_set_key=chunk_set_key,
            chunk_count=len(chunks),
            chunk_manifest_path=chunk_manifest_path,
        )
        for chunk_row in chunk_rows:
            chunk_index = int(chunk_row["chunk_index"])
            start = int(chunk_row["byte_start"])
            end = int(chunk_row["byte_end"])
            chunk_path = Path(str(chunk_row["chunk_path"]))
            chunk = chunk_path.read_text(encoding="utf-8", errors="ignore")
            packet_path = packets_dir / f"{digest[:16]}-{chunk_index + 1:03d}.md"
            packet_path.write_text(build_packet(record, chunk_index, start, end, chunk), encoding="utf-8")
            packet_rows.append({
                "url": url,
                "sha256": digest,
                "chunk_set_key": chunk_set_key,
                "chunk_index": chunk_index,
                "chunk_count": len(chunks),
                "chunk_path": str(chunk_path),
                "packet_path": str(packet_path),
                "byte_start": start,
                "byte_end": end,
            })
        reuse_note = " reused" if reused_download else " downloaded"
        chunk_note = " reused-chunks" if reused_chunks else " chunked"
        print(f"[{index}/{len(normalized_urls)}] {url} -> {len(chunks)} chunk(s){reuse_note}{chunk_note}", file=sys.stderr)

    save_ledger(ledger_path, ledger)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    packet_rows_by_sha: dict[str, list[dict]] = {}
    for packet_row in packet_rows:
        packet_rows_by_sha.setdefault(str(packet_row.get("sha256") or ""), []).append(packet_row)
    metadata_rows = [
        build_metadata_row(
            record=record,
            run_id=run_id,
            target_host=",".join(scope_hosts),
            packet_rows=packet_rows_by_sha.get(record.sha256, []),
            provenance_rows=provenance_rows_by_sha.get(record.sha256, []),
            library_root=library_root,
            generated_at=generated_at,
        )
        for record in records
    ]
    write_jsonl(root / "metadata.jsonl", metadata_rows)
    write_jsonl(root / "packets.jsonl", packet_rows)
    write_jsonl(root / "page_context.jsonl", page_records)
    write_jsonl(root / "js_provenance.jsonl", (asdict(row) for row in provenance_rows))
    write_jsonl(root / "external_integrations.jsonl", (asdict(row) for row in external_integration_rows))
    if metadata_rows:
        append_jsonl(library_metadata_path, metadata_rows)
    if provenance_rows:
        append_jsonl(library_provenance_path, (asdict(row) for row in provenance_rows))
        write_provenance_table(js_info_db_path, read_jsonl(library_provenance_path))
    if metadata_rows or packet_rows:
        write_metadata_db(js_info_db_path, read_jsonl(library_metadata_path), packet_rows)
        write_observations_table(js_info_db_path, read_jsonl(library_observations_path))
    integration_outputs = write_external_integration_index(integration_index_root, external_integration_rows)
    manifest = {
        "program": args.program,
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "input": args.input,
        "page": args.page,
        "target_host": target_host,
        "scope_hosts": scope_hosts,
        "config": config_summary,
        "root": str(root),
        "js_urls_seen": len(normalized_urls),
        "js_downloaded": len(records),
        "cached_urls_skipped": skipped_cached_urls,
        "downloads_reused": reused_downloads,
        "chunk_sets_reused": reused_chunk_sets,
        "packets": len(packet_rows),
        "external_integrations": len(external_integration_rows),
        "outputs": {
            "metadata": str(root / "metadata.jsonl"),
            "library_metadata": str(library_metadata_path),
            "packets": str(root / "packets.jsonl"),
            "page_context": str(root / "page_context.jsonl"),
            "js_provenance": str(root / "js_provenance.jsonl"),
            "library_provenance": str(library_provenance_path),
            "library_observations": str(library_observations_path),
            "js_info_db": str(js_info_db_path),
            "external_integrations": str(root / "external_integrations.jsonl"),
            "integration_index": integration_outputs,
            "ledger": str(ledger_path),
            "library": str(library_root),
            "downloads": str(downloads_dir),
            "chunks": str(library_chunks_dir),
            "packet_dir": str(packets_dir),
        },
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def command_observe(args: argparse.Namespace) -> int:
    library_root, config_summary = resolve_library_root(args)
    observations_path = library_root / "observations.jsonl"
    js_info_db_path = library_root / "js_info.sqlite"
    input_path = Path(args.input).expanduser()
    rows = read_jsonl(input_path)
    if not rows:
        raise SystemExit(f"no observation rows found in {input_path}")
    normalized_rows = append_observations(
        observations_path=observations_path,
        db_path=js_info_db_path,
        rows=rows,
    )
    manifest = {
        "program": args.program,
        "config": config_summary,
        "observations_added": len(normalized_rows),
        "outputs": {
            "library_observations": str(observations_path),
            "js_info_db": str(js_info_db_path),
        },
    }
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="JavaScript inventory and deep-review packet builder")
    sub = parser.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("inventory", help="Collect/download/hash/chunk JavaScript and write agent packets")
    inv.add_argument("program", help="Program name, e.g. canva")
    inv.add_argument("--input", help="File containing JavaScript URLs, e.g. aggregated/jsfiles.txt")
    inv.add_argument("--page", help="Page URL to fetch and extract script[src] from")
    inv.add_argument("--page-context", default="", help="Short context such as login/auth, billing, editor")
    inv.add_argument("--target-host", help="Host or parent domain to constrain JS URLs")
    inv.add_argument("--run-id", help="Stable run id")
    inv.add_argument("--output-root", help="Override output root")
    inv.add_argument("--library-root", help="Override shared JS library root")
    inv.add_argument("--config", help="Optional JSON config for default roots")
    inv.add_argument("--integration-index-root", help="Override external integration index root")
    inv.add_argument("--provenance-input", help="Optional JSONL mapping JS URLs to page/proxy/flow provenance")
    inv.add_argument("--provenance-source", help="Source label for provenance rows, e.g. ryushe-proxy, katana, playwright")
    inv.add_argument("--refresh", action="store_true", help="Refetch URLs even if the URL is already mapped in the ledger")
    inv.add_argument(
        "--skip-cached-processing",
        action="store_true",
        help="For exact URL aliases already mapped to an existing cached artifact, skip signal extraction, chunking, packet generation, metadata, provenance, and DB updates",
    )
    inv.add_argument("--limit", type=int, help="Maximum JS URLs to download")
    inv.add_argument("--timeout", type=int, default=20)
    inv.add_argument("--delay", type=float, default=0.0, help="Delay between JS downloads")
    inv.add_argument("--chunk-size", type=int, default=60000)
    inv.add_argument("--chunk-overlap", type=int, default=500)
    inv.set_defaults(func=command_inventory)

    observe = sub.add_parser("observe", help="Append reviewed JS observations and index them in js_info.sqlite")
    observe.add_argument("program", help="Program name, e.g. canva")
    observe.add_argument("--input", required=True, help="JSONL file containing JS observation rows")
    observe.add_argument("--library-root", help="Override shared JS library root")
    observe.add_argument("--config", help="Optional JSON config for default roots")
    observe.set_defaults(func=command_observe)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.input and not args.page:
        raise SystemExit("inventory requires --input and/or --page")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
