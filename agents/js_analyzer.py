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

SOURCE_KEYWORDS = {
    "location": re.compile(r"\b(?:location|document\.URL|document\.documentURI|URLSearchParams|hash|search)\b"),
    "storage": re.compile(r"\b(?:localStorage|sessionStorage|indexedDB|cookie)\b"),
    "message": re.compile(r"\b(?:postMessage|message)\b"),
    "form": re.compile(r"\b(?:FormData|HTMLInputElement|querySelector)\b"),
}

SINK_KEYWORDS = {
    "dom_write": re.compile(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b"),
    "navigation": re.compile(r"\b(?:location\.href|location\.assign|open\()\b"),
    "eval": re.compile(r"\b(?:eval|Function|setTimeout|setInterval)\s*\("),
    "request": re.compile(r"\b(?:fetch|XMLHttpRequest|axios|sendBeacon)\b"),
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
    page_context: str = ""
    source: str = ""
    source_map: str = ""
    endpoints: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    secret_hints: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    chunk_count: int = 0


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
    if base:
        value = urllib.parse.urljoin(base, value)
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return urllib.parse.urlunparse(parsed._replace(fragment=""))


def same_host_or_child(url: str, target_host: str | None) -> bool:
    if not target_host:
        return True
    host = urllib.parse.urlparse(url).hostname or ""
    return host == target_host or host.endswith(f".{target_host}")


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


def extract_signals(text: str, base_url: str) -> dict:
    endpoints = set()
    for match in URL_RE.findall(text):
        normalized = normalize_url(match.rstrip(".,;)"), base_url)
        if normalized:
            endpoints.add(normalized)
    for match in PATH_RE.finditer(text):
        endpoints.add(urllib.parse.urljoin(base_url, match.group("path")))

    params = set(PARAM_RE.findall(text))
    for endpoint in endpoints:
        parsed = urllib.parse.urlparse(endpoint)
        params.update(name for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

    source_map = ""
    sm = SOURCE_MAP_RE.search(text[-3000:])
    if sm:
        source_map = urllib.parse.urljoin(base_url, sm.group("url"))

    secret_hints = sorted(set(m.group(1).lower() for m in SECRET_HINT_RE.finditer(text)))[:50]
    sources = sorted(name for name, pattern in SOURCE_KEYWORDS.items() if pattern.search(text))
    sinks = sorted(name for name, pattern in SINK_KEYWORDS.items() if pattern.search(text))
    imports = sorted(set(IMPORT_RE.findall(text)))[:100]

    return {
        "endpoints": sorted(endpoints)[:500],
        "params": sorted(params)[:300],
        "source_map": source_map,
        "imports": imports,
        "secret_hints": secret_hints,
        "sources": sources,
        "sinks": sinks,
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
        f"- Sources: {', '.join(record.sources) or 'none detected'}",
        f"- Sinks: {', '.join(record.sinks) or 'none detected'}",
        f"- Params: {', '.join(record.params[:40]) or 'none detected'}",
        "",
        "## Review Goals",
        "",
        "- Identify endpoints, params, auth/session/storage behavior, source-to-sink paths, object or tenant assumptions, and vuln-lane handoffs.",
        "- Treat regex hits as hints, not findings. Verify impact before promotion.",
        "- Produce structured notes: endpoints, params, sources, sinks, secrets signals, confidence, and next tests.",
        "",
        "## Nearby Extracted Endpoints",
        "",
    ]
    lines.extend(f"- {endpoint}" for endpoint in record.endpoints[:80])
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
    downloads_dir = root / "downloads"
    packets_dir = root / "packets"
    chunks_dir = root / "chunks"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    packets_dir.mkdir(parents=True, exist_ok=True)
    chunks_dir.mkdir(parents=True, exist_ok=True)

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
    for index, url in enumerate(normalized_urls, start=1):
        if args.delay:
            time.sleep(args.delay)
        body, status, content_type = http_get(url, timeout=args.timeout)
        if not body:
            continue
        digest = hashlib.sha256(body).hexdigest()
        artifact_path = downloads_dir / f"{digest}.js"
        if not artifact_path.exists():
            artifact_path.write_bytes(body)
        text = body.decode("utf-8", errors="ignore")
        signals = extract_signals(text, url)
        chunks = chunk_text(text, args.chunk_size, args.chunk_overlap)
        record = JsRecord(
            url=url,
            status=status,
            content_type=content_type,
            byte_count=len(body),
            sha256=digest,
            artifact_path=str(artifact_path),
            page_context=args.page_context or "",
            source=args.input or args.page or "",
            source_map=signals["source_map"],
            endpoints=signals["endpoints"],
            params=signals["params"],
            imports=signals["imports"],
            secret_hints=signals["secret_hints"],
            sources=signals["sources"],
            sinks=signals["sinks"],
            chunk_count=len(chunks),
        )
        records.append(record)
        for chunk_index, (start, end, chunk) in enumerate(chunks):
            chunk_name = f"{digest[:16]}-{chunk_index + 1:03d}.js"
            chunk_path = chunks_dir / chunk_name
            packet_path = packets_dir / f"{digest[:16]}-{chunk_index + 1:03d}.md"
            chunk_path.write_text(chunk, encoding="utf-8")
            packet_path.write_text(build_packet(record, chunk_index, start, end, chunk), encoding="utf-8")
            packet_rows.append({
                "url": url,
                "sha256": digest,
                "chunk_index": chunk_index,
                "chunk_count": len(chunks),
                "chunk_path": str(chunk_path),
                "packet_path": str(packet_path),
                "byte_start": start,
                "byte_end": end,
            })
        print(f"[{index}/{len(normalized_urls)}] {url} -> {len(chunks)} chunk(s)", file=sys.stderr)

    write_jsonl(root / "metadata.jsonl", (asdict(record) for record in records))
    write_jsonl(root / "packets.jsonl", packet_rows)
    write_jsonl(root / "page_context.jsonl", page_records)
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
        "packets": len(packet_rows),
        "outputs": {
            "metadata": str(root / "metadata.jsonl"),
            "packets": str(root / "packets.jsonl"),
            "page_context": str(root / "page_context.jsonl"),
            "downloads": str(downloads_dir),
            "chunks": str(chunks_dir),
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

