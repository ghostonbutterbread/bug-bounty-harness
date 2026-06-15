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
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


SHARED_WEB_BASE = Path.home() / "Shared" / "web_bounty"

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


def same_host_or_child(url: str, target_host: str | None) -> bool:
    if not target_host:
        return True
    host = urllib.parse.urlparse(url).hostname or ""
    return host == target_host or host.endswith(f".{target_host}")


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


def collect_from_page(page_url: str, page_context: str, target_host: str | None) -> tuple[list[str], list[dict]]:
    body, status, content_type = http_get(page_url)
    if not body:
        return [], []
    text = body.decode("utf-8", errors="ignore")
    parser = ScriptSrcParser()
    parser.feed(text)
    js_urls = []
    for script in parser.scripts:
        normalized = normalize_url(script, page_url)
        if normalized and same_host_or_child(normalized, target_host):
            js_urls.append(normalized)
    page_records = [{
        "page_url": page_url,
        "status": status,
        "content_type": content_type,
        "page_context": page_context,
        "script_count": len(js_urls),
    }]
    return dedupe(js_urls), page_records


def extract_signals(text: str, base_url: str, target_host: str | None = None) -> dict:
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
    if target_host:
        in_scope_endpoints = [endpoint for endpoint in sorted_endpoints if same_host_or_child(endpoint, target_host)]
        external_endpoints = [endpoint for endpoint in sorted_endpoints if not same_host_or_child(endpoint, target_host)]
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
    root = Path(args.output_root).expanduser() if args.output_root else SHARED_WEB_BASE / args.program / "web" / "recon" / "js" / run_id
    library_root = Path(args.library_root).expanduser() if args.library_root else SHARED_WEB_BASE / args.program / "web" / "recon" / "js" / "_library"
    integration_index_root = (
        Path(args.integration_index_root).expanduser()
        if args.integration_index_root
        else SHARED_WEB_BASE / args.program / "web" / "intel" / "integrations"
    )
    downloads_dir = library_root / "downloads"
    library_chunks_dir = library_root / "chunks"
    packets_dir = root / "packets"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    library_chunks_dir.mkdir(parents=True, exist_ok=True)
    packets_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = library_root / "ledger.json"
    ledger = load_ledger(ledger_path)

    target_host = args.target_host
    if not target_host and args.page:
        target_host = urllib.parse.urlparse(args.page).hostname

    urls: list[str] = []
    page_records: list[dict] = []
    if args.input:
        urls.extend(read_lines(Path(args.input).expanduser()))
    if args.page:
        page_urls, records = collect_from_page(args.page, args.page_context or "", target_host)
        urls.extend(page_urls)
        page_records.extend(records)

    normalized_urls = []
    for url in urls:
        normalized = normalize_url(url)
        if normalized and normalized.lower().split("?", 1)[0].endswith(".js") and same_host_or_child(normalized, target_host):
            normalized_urls.append(normalized)
    normalized_urls = dedupe(normalized_urls)
    if args.limit:
        normalized_urls = normalized_urls[: args.limit]

    records: list[JsRecord] = []
    packet_rows: list[dict] = []
    external_integration_rows: list[ExternalIntegration] = []
    reused_downloads = 0
    reused_chunk_sets = 0
    for index, url in enumerate(normalized_urls, start=1):
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
        signals = extract_signals(text, url, target_host)
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
                in_scope_target_host=target_host or "",
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
    write_jsonl(root / "metadata.jsonl", (asdict(record) for record in records))
    write_jsonl(root / "packets.jsonl", packet_rows)
    write_jsonl(root / "page_context.jsonl", page_records)
    write_jsonl(root / "external_integrations.jsonl", (asdict(row) for row in external_integration_rows))
    integration_outputs = write_external_integration_index(integration_index_root, external_integration_rows)
    manifest = {
        "program": args.program,
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "input": args.input,
        "page": args.page,
        "target_host": target_host,
        "root": str(root),
        "js_urls_seen": len(normalized_urls),
        "js_downloaded": len(records),
        "downloads_reused": reused_downloads,
        "chunk_sets_reused": reused_chunk_sets,
        "packets": len(packet_rows),
        "external_integrations": len(external_integration_rows),
        "outputs": {
            "metadata": str(root / "metadata.jsonl"),
            "packets": str(root / "packets.jsonl"),
            "page_context": str(root / "page_context.jsonl"),
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
    inv.add_argument("--integration-index-root", help="Override external integration index root")
    inv.add_argument("--refresh", action="store_true", help="Refetch URLs even if the URL is already mapped in the ledger")
    inv.add_argument("--limit", type=int, help="Maximum JS URLs to download")
    inv.add_argument("--timeout", type=int, default=20)
    inv.add_argument("--delay", type=float, default=0.0, help="Delay between JS downloads")
    inv.add_argument("--chunk-size", type=int, default=60000)
    inv.add_argument("--chunk-overlap", type=int, default=500)
    inv.set_defaults(func=command_inventory)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.input and not args.page:
        raise SystemExit("inventory requires --input and/or --page")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
