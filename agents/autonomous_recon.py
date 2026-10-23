"""
Autonomous Recon Agent — One-shot full recon pipeline.

Usage:
    python3 autonomous_recon.py --program superdrug --target https://www.superdrug.com
    python3 autonomous_recon.py --target https://www.example.com

Output:
    ~/Shared/bounty_recon/{program}/agent_shared/findings/recon/
    ├── urls.txt
    ├── params.txt
    ├── js_files.txt
    ├── tech_stack.txt
    └── summary.json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_AGENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _AGENT_DIR.parent
for _path in (_AGENT_DIR, _PROJECT_ROOT):
    _path_str = str(_path)
    if _path_str not in sys.path:
        sys.path.insert(0, _path_str)


try:
    from scope_validator import ScopeValidator
except ImportError:
    ScopeValidator = None
try:
    from rate_limiter import RateLimiter
except ImportError:
    RateLimiter = None
try:
    from recon_store import record_recon_artifacts
except ImportError:
    record_recon_artifacts = None

try:
    from subagent_logger import SubagentLogger
except ImportError:  # pragma: no cover
    SubagentLogger = None

# Module-level rate limiter (initialized in run_recon)
_g_limiter = None
_g_scope = None
_RECON_LOGGER = None

class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urllib.parse.urljoin(req.full_url, newurl)
        if not _authorized(destination):
            raise ValueError(f"HTTP redirect outside saved scope: {destination}")
        if _g_limiter is not None:
            _g_limiter.wait()
        return super().redirect_request(req, fp, code, msg, headers, destination)

_scoped_opener = urllib.request.build_opener(_ScopedRedirect())

def _authorized(url: str) -> bool:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme in ("http", "https") and _same_host(url, _g_target_host) and is_in_scope(url, _g_scope)

_g_target_host = ""

def _open_scoped(req, timeout):
    if not _authorized(req.full_url):
        raise ValueError(f"HTTP request outside saved scope: {req.full_url}")
    return _scoped_opener.open(req, timeout=timeout)

# ──────────────────────────────────────────────────────────────────────────────
# Regex helpers
# ──────────────────────────────────────────────────────────────────────────────

URL_RE = re.compile(r'https?://[^\s\'"<>()\[\]{}]+', re.IGNORECASE)
JS_URL_RE = re.compile(r'["\'](?P<path>/[a-zA-Z0-9_\-/\.]+\.js(?:\?[^"\']*)?)["\']')
PARAM_RE = re.compile(r'[?&]([a-zA-Z0-9_\-]+)=', re.IGNORECASE)
FORM_ACTION_RE = re.compile(r'<form[^>]*action=["\']?([^"\'>\s]+)', re.IGNORECASE)
FORM_BLOCK_RE = re.compile(r'<form\b[^>]*>.*?</form>', re.IGNORECASE | re.DOTALL)
INPUT_NAME_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
SRC_RE = re.compile(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)

# Secret detection patterns (derived from secrets_finder.py patterns)
SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("api_key",    "P2", re.compile(r'(?:api[_\-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', re.IGNORECASE)),
    ("aws_key",    "P1", re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE)),
    ("jwt",        "P2", re.compile(r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+')),
    ("secret",     "P2", re.compile(r'(?:secret|token|password|passwd|auth)[_\-]?(?:key|token)?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{8,})["\']?', re.IGNORECASE)),
    ("bearer",     "P2", re.compile(r'[Bb]earer\s+([A-Za-z0-9_\-\.]{20,})')),
    ("private_key","P1", re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----')),
    ("gh_token",   "P1", re.compile(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}')),
    ("slack_token","P2", re.compile(r'xox[baprs]-[A-Za-z0-9\-]{10,}')),
]

INTERESTING_PATHS = [
    "/admin", "/admin/", "/administrator", "/wp-admin", "/dashboard",
    "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql", "/swagger",
    "/swagger-ui", "/swagger.json", "/openapi.json", "/api-docs",
    "/debug", "/debug/", "/.env", "/.git", "/config", "/config.json",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/server-status", "/phpinfo.php", "/test", "/dev", "/staging",
    "/backup", "/old", "/changelog", "/health", "/metrics", "/status",
]

TECH_HEADERS = {
    "x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version",
    "x-drupal-cache", "x-wordpress-cache", "x-magento-cache-debug",
    "x-shopify-stage", "x-generator", "x-frame-options",
    "content-security-policy", "x-waf", "x-sucuri-id",
    "x-cache", "cf-ray", "x-amz-cf-id", "x-vercel-id",
}

WAF_SIGNATURES = {
    "Cloudflare":   re.compile(r'cloudflare|cf-ray|__cfduid', re.IGNORECASE),
    "AWS WAF":      re.compile(r'awswaf|x-amzn-requestid|aws-cf', re.IGNORECASE),
    "Akamai":       re.compile(r'akamai|x-check-cacheable|akamaighost', re.IGNORECASE),
    "Imperva":      re.compile(r'imperva|incapsula|visid_incap|x-iinfo', re.IGNORECASE),
    "Sucuri":       re.compile(r'sucuri|x-sucuri', re.IGNORECASE),
    "ModSecurity":  re.compile(r'mod_security|modsecurity|mod-security', re.IGNORECASE),
    "F5 BIG-IP":    re.compile(r'bigip|f5|x-wa-info', re.IGNORECASE),
    "Fastly":       re.compile(r'x-fastly|fastly-io-warning|x-cache.*HIT.*fastly', re.IGNORECASE),
}


# ──────────────────────────────────────────────────────────────────────────────
# Data containers
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ReconResult:
    program: str
    target: str
    target_host: str
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Phase 1 - Discover
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    tech_stack: list[str] = field(default_factory=list)
    waf_detected: Optional[str] = None
    response_headers: dict[str, str] = field(default_factory=dict)

    # Phase 2 - Crawl
    urls: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)

    # Phase 3 - Analyze
    secrets_found: list[dict] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    interesting_paths_found: list[str] = field(default_factory=list)

    # Meta
    errors: list[str] = field(default_factory=list)
    end_time: str = ""
    crawl_pages_attempted: int = 0
    crawl_pages_pending: int = 0
    crawl_frontier_overflow: int = 0
    crawl_status: str = "not_started"
    js_files_scoped: int = 0
    js_files_attempted: int = 0
    js_files_failed: int = 0
    analysis_status: str = "not_started"
    discovery_status: str = "complete"
    pause_reason: str = ""
    run_id: str = ""


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _log(msg: str, level: str = "INFO") -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    tag = {"INFO": "[ ]", "OK": "[+]", "WARN": "[!]", "ERR": "[x]"}.get(level, "[ ]")
    print(f"{ts} {tag} {msg}", flush=True)


def _safe_log_span(**fields) -> None:
    if _RECON_LOGGER is None:
        return
    try:
        _RECON_LOGGER.log_span(**fields)
    except Exception:
        pass


def _http_get(url: str, timeout: int = 15) -> tuple[bytes, dict]:
    """Simple HTTP GET, returns (body_bytes, headers_dict)."""
    if _g_limiter is not None:
        _g_limiter.wait()
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
    )
    start = time.time()
    try:
        with _open_scoped(req, timeout=timeout) as resp:
            body = resp.read()
            _safe_log_span(
                span_type="tool",
                level="STEP",
                message=f"Tool: GET {url}",
                tool_name="urllib_request",
                tool_category="http_request",
                input_bytes=len(url.encode("utf-8", errors="replace")),
                output_bytes=len(body),
                latency_ms=int((time.time() - start) * 1000),
                output_tokens_est=max(0, math.ceil(len(body) / 4)),
                success=True,
            )
            return body, dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read()
        _safe_log_span(
            span_type="tool",
            level="STEP",
            message=f"Tool: GET {url}",
            tool_name="urllib_request",
            tool_category="http_request",
            input_bytes=len(url.encode("utf-8", errors="replace")),
            output_bytes=len(body),
            latency_ms=int((time.time() - start) * 1000),
            output_tokens_est=max(0, math.ceil(len(body) / 4)),
            success=False,
        )
        return body, dict(e.headers) if e.headers else {}
    except Exception:
        _safe_log_span(
            span_type="tool",
            level="STEP",
            message=f"Tool: GET {url}",
            tool_name="urllib_request",
            tool_category="http_request",
            input_bytes=len(url.encode("utf-8", errors="replace")),
            output_bytes=0,
            latency_ms=int((time.time() - start) * 1000),
            success=False,
        )
        return b"", {}


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_cmd(cmd: list[str], timeout: int = 120) -> str:
    """Run a subprocess, return stdout as string."""
    start = time.time()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        stdout = result.stdout or ""
        _safe_log_span(
            span_type="tool",
            level="STEP",
            message=f"Tool: {cmd[0]}",
            tool_name=cmd[0],
            tool_category="subprocess",
            input_bytes=len(" ".join(cmd).encode("utf-8", errors="replace")),
            output_bytes=len(stdout.encode("utf-8", errors="replace")),
            latency_ms=int((time.time() - start) * 1000),
            output_tokens_est=max(0, math.ceil(len(stdout.encode("utf-8", errors="replace")) / 4)),
            success=result.returncode == 0,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        if _g_result is not None:
            _g_result.discovery_status = "partial"
            _g_result.errors.append(f"Discovery tool timed out (retryable): {cmd[0]}")
        _safe_log_span(
            span_type="tool",
            level="STEP",
            message=f"Tool: {cmd[0]}",
            tool_name=cmd[0],
            tool_category="subprocess",
            input_bytes=len(" ".join(cmd).encode("utf-8", errors="replace")),
            output_bytes=0,
            latency_ms=int((time.time() - start) * 1000),
            success=False,
        )
        return ""
    except FileNotFoundError:
        return ""
    except Exception:
        return ""

_g_result = None


def _normalize_url(url: str, base: str) -> Optional[str]:
    """Resolve a possibly-relative URL against base."""
    try:
        resolved = urllib.parse.urljoin(base, url)
        parsed = urllib.parse.urlparse(resolved)
        if parsed.scheme not in ("http", "https"):
            return None
        return resolved
    except Exception:
        return None


def _same_host(url: str, host: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc == host or parsed.netloc.endswith(f".{host}")
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Phase 1 — DISCOVER
# ──────────────────────────────────────────────────────────────────────────────

def phase_discover(result: ReconResult) -> None:
    _log("=== Phase 1: DISCOVER ===", "INFO")
    host = result.target_host

    # Nmap quick scan
    _log(f"Running nmap quick scan on {host} …")
    if _tool_available("nmap"):
        nmap_out = _run_cmd(["nmap", "-vv", "-T4", "--top-ports", "100", host], timeout=90)
        _parse_nmap_output(nmap_out, result)
        if result.open_ports:
            _log(f"Open ports: {result.open_ports}", "OK")
            # Service scan only on open ports
            ports_str = ",".join(str(p) for p in result.open_ports[:20])
            _log(f"Running service detection on ports {ports_str} …")
            svc_out = _run_cmd(["nmap", "-sV", "-T4", "-p", ports_str, host], timeout=120)
            _parse_nmap_services(svc_out, result)
        else:
            _log("No open ports detected (or nmap blocked)", "WARN")
    else:
        _log("nmap not found — skipping port scan", "WARN")
        result.errors.append("nmap not available")

    # HTTP probe: headers, tech stack, WAF
    _log(f"Probing {result.target} for technology fingerprints …")
    body, headers = _http_get(result.target)
    if headers:
        result.response_headers = {k.lower(): v for k, v in headers.items()}
        _fingerprint_tech(result)
        _detect_waf(body, headers, result)
    else:
        _log("No HTTP response from target", "WARN")
        result.errors.append(f"No HTTP response from {result.target}")

    # Whatweb if available
    if _tool_available("whatweb"):
        _log("Running whatweb …")
        ww_out = _run_cmd(["whatweb", "--color=never", "-a", "1", result.target], timeout=30)
        if ww_out:
            result.tech_stack.append(f"whatweb: {ww_out.strip()[:300]}")

    # httpx tech probe if available
    if _tool_available("httpx"):
        _log("Running httpx tech detection …")
        hx_out = _run_cmd(
            ["httpx", "-u", result.target, "-tech-detect", "-silent", "-json"],
            timeout=30,
        )
        for line in hx_out.strip().splitlines():
            try:
                data = json.loads(line)
                techs = data.get("tech", [])
                if techs:
                    result.tech_stack.extend(techs)
            except json.JSONDecodeError:
                pass

    if result.tech_stack:
        _log(f"Tech stack detected: {', '.join(result.tech_stack[:10])}", "OK")
    if result.waf_detected:
        _log(f"WAF detected: {result.waf_detected}", "WARN")


def _parse_nmap_output(output: str, result: ReconResult) -> None:
    port_re = re.compile(r'^(\d+)/tcp\s+open', re.MULTILINE)
    for m in port_re.finditer(output):
        port = int(m.group(1))
        if port not in result.open_ports:
            result.open_ports.append(port)


def _parse_nmap_services(output: str, result: ReconResult) -> None:
    svc_re = re.compile(r'^(\d+)/tcp\s+open\s+(\S+)\s+(.*)', re.MULTILINE)
    for m in svc_re.finditer(output):
        port = int(m.group(1))
        svc = f"{m.group(2)} {m.group(3)}".strip()
        result.services[port] = svc
        # Add to tech stack
        tech_hint = f"port {port}: {svc}"
        if tech_hint not in result.tech_stack:
            result.tech_stack.append(tech_hint)


def _fingerprint_tech(result: ReconResult) -> None:
    headers = result.response_headers
    for h in TECH_HEADERS:
        v = headers.get(h)
        if v:
            entry = f"{h}: {v}"
            if entry not in result.tech_stack:
                result.tech_stack.append(entry)

    # Server header shorthand
    server = headers.get("server", "")
    if server:
        for tech in ("nginx", "apache", "iis", "caddy", "litespeed", "gunicorn", "node"):
            if tech in server.lower() and tech not in result.tech_stack:
                result.tech_stack.append(tech)

    # Powered-by
    xpb = headers.get("x-powered-by", "")
    if xpb:
        for tech in ("php", "asp.net", "express", "next.js", "nuxt"):
            if tech in xpb.lower() and tech not in result.tech_stack:
                result.tech_stack.append(tech)


def _detect_waf(body: bytes, headers: dict, result: ReconResult) -> None:
    combined = " ".join(headers.values()) + (body.decode(errors="ignore")[:2000])
    for name, pattern in WAF_SIGNATURES.items():
        if pattern.search(combined):
            result.waf_detected = name
            return


# ──────────────────────────────────────────────────────────────────────────────
# Phase 2 — CRAWL
# ──────────────────────────────────────────────────────────────────────────────

CRAWL_PAGE_BUDGET = 60
CRAWL_URL_LIMIT = 10000  # explicit stop boundary for generated/infinite paths
MIN_OUTPUT_FREE_BYTES = 5 * 1024 ** 3


def _output_dir(result: ReconResult) -> Path:
    return Path.home() / "Shared" / "bounty_recon" / result.program / "agent_shared" / "findings" / "recon"


def _require_output_space(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(path).free
    if free < MIN_OUTPUT_FREE_BYTES:
        raise DiskFloorPause(f"Recon output paused: available disk below 5 GiB at {path} ({free} bytes free)")

class DiskFloorPause(OSError):
    pass

def _save_checkpoint(path: Path, state: dict) -> None:
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(state))
    temp.replace(path)


def phase_crawl(result: ReconResult, scope=None) -> None:
    """BFS in bounded invocations, retaining the full frontier between runs."""
    _log("=== Phase 2: CRAWL ===")
    out_dir = _output_dir(result)
    checkpoint = out_dir / "crawl_checkpoint.json"
    overflow_path = out_dir / "crawl_overflow.txt"
    if checkpoint.exists():
        saved = json.loads(checkpoint.read_text())
        if saved.get("target") != result.target or saved.get("program") != result.program:
            raise ValueError(f"Crawl checkpoint belongs to another target: {checkpoint}")
        result.run_id = saved.get("run_id") or secrets.token_hex(12)
        pending = deque(saved["pending"])
        visited = set(saved["visited"])
        failed = set(saved.get("retryable_failed", []))
        succeeded = set(saved.get("succeeded", []))
        all_urls = set(saved["urls"])
        all_params = set(saved["params"])
        all_js = set(saved["js_files"])
        for restored in set(pending) | visited | failed | succeeded | all_urls | all_js:
            if not _same_host(restored, result.target_host) or not is_in_scope(restored, scope):
                raise ValueError(f"Checkpoint URL is no longer authorized by current scope: {restored}")
        result.forms = saved["forms"]
        overflow = saved.get("frontier_overflow", 0)
        _log(f"Resuming crawl: {len(visited)} attempted, {len(pending)} pending")
    else:
        result.run_id = secrets.token_hex(12)
        pending = deque([result.target])
        visited = set()
        failed, succeeded = set(), set()
        overflow = 0
        all_urls, all_params, all_js = set(), set(), set()
    def spill(url: str) -> None:
        # Preserve identities beyond the in-memory discovery boundary for operator replay.
        try:
            _require_output_space(out_dir)
        except DiskFloorPause as exc:
            result.pause_reason = str(exc)
            pending.append(url)
            return
        with overflow_path.open("a") as stream:
            stream.write(url + "\n")

    queued = set(pending) | visited
    # Failed requests are retried once per invocation, not silently treated as done.
    pending.extend(sorted(failed))
    queued.update(failed)

    def save() -> None:
        _save_checkpoint(checkpoint, {"program": result.program, "target": result.target,
            "run_id": result.run_id,
            "pending": list(pending), "visited": sorted(visited),
            "succeeded": sorted(succeeded), "retryable_failed": sorted(failed),
            "frontier_overflow": overflow, "urls": sorted(all_urls),
            "params": sorted(all_params), "js_files": sorted(all_js), "forms": result.forms})

    browser = None
    pw_context = None
    route_failure: list[str] = []
    navigation_redirect: list[str] = []
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
        pw_context = sync_playwright()
        pw = pw_context.__enter__()
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(service_workers="block")
        # Older Playwright releases cannot intercept WebSocket handshakes.
        # Prefer the HTTP-only urllib crawler over an unguarded browser.
        if not hasattr(context, "route_web_socket"):
            raise RuntimeError("Playwright WebSocket interception unavailable")
        def guard_ws(route):
            u = route.url
            parsed = urllib.parse.urlsplit(u)
            equivalent = urllib.parse.urlunsplit(("https" if parsed.scheme == "wss" else "http",
                parsed.netloc, parsed.path, parsed.query, parsed.fragment))
            if parsed.scheme not in ("ws", "wss") or not _same_host(equivalent, result.target_host) or not is_in_scope(equivalent, scope):
                route.close()
                return
            if _g_limiter is not None:
                _g_limiter.wait()
            route.connect_to_server()
        context.route_web_socket("**/*", guard_ws)
        def permitted(u):
            return (urllib.parse.urlsplit(u).scheme in ("http", "https")
                    and _same_host(u, result.target_host) and is_in_scope(u, scope))
        def guard(route):
            u = route.request.url
            if not permitted(u):
                route.abort()
                return
            try:
                if _g_limiter is not None:
                    _g_limiter.wait()
                # continue_() lets Chromium follow a 30x without another route
                # callback. Fetch one response only, before the browser sees it.
                response = route.fetch(max_redirects=0)
                if response.status in (301, 302, 303, 307, 308):
                    location = response.headers.get("location")
                    destination = urllib.parse.urljoin(u, location) if location else None
                    route.abort()
                    if destination and permitted(destination) and route.request.is_navigation_request():
                        # urllib validates and rates every hop; browser navigation
                        # cannot safely follow a fulfilled redirect either.
                        navigation_redirect.append(u)
                    else:
                        route_failure.append(f"Browser redirect not followed: {u} -> {destination or 'missing Location'}")
                    return
                route.fulfill(response=response)
            except Exception as exc:
                route_failure.append(f"Browser route failed: {u}: {type(exc).__name__}")
                route.abort()
        context.route("**/*", guard)
        page = context.new_page()
        def on_request(req):
            nonlocal overflow
            u = req.url
            if _same_host(u, result.target_host) and is_in_scope(u, scope):
                if u not in all_urls and len(all_urls) >= CRAWL_URL_LIMIT:
                    overflow += 1
                    spill(u)
                    return
                all_urls.add(u)
                for param in PARAM_RE.finditer(u):
                    all_params.add(param.group(1))
                if u.endswith(".js") or ".js?" in u:
                    all_js.add(u)
        page.on("request", on_request)
    except Exception:
        if browser is not None:
            browser.close()
        browser = None
        if pw_context is not None:
            pw_context.__exit__(None, None, None)
            pw_context = None
        _log("Playwright unavailable — using urllib crawler")

    attempted = 0
    current_page = None
    try:
        while pending and attempted < CRAWL_PAGE_BUDGET:
            try:
                _require_output_space(out_dir)
            except DiskFloorPause as exc:
                result.pause_reason = str(exc)
                save()
                break
            url = pending.popleft()
            current_page = url
            if not _same_host(url, result.target_host) or not is_in_scope(url, scope):
                raise ValueError(f"Checkpoint page is no longer authorized by current scope: {url}")
            if url in visited and url not in failed:
                continue
            visited.add(url)
            failed.discard(url)
            attempted += 1
            _log(f"  Crawling: {url[:80]}")
            if browser is not None:
                navigation_redirect.clear()
                try:
                    page.goto(url, timeout=15000, wait_until="domcontentloaded")
                    if not _same_host(page.url, result.target_host) or not is_in_scope(page.url, scope):
                        raise ValueError("Browser navigation left saved scope")
                    page.wait_for_timeout(1000)
                    if navigation_redirect:
                        raise RuntimeError("Scoped browser navigation redirect requires urllib fallback")
                    if route_failure:
                        raise RuntimeError("; ".join(route_failure))
                    text = page.content()
                    links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                    scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
                except Exception as exc:
                    if navigation_redirect and not route_failure:
                        # The browser must not follow its own redirect; urllib's
                        # scoped redirect handler safely obtains the document.
                        body, _ = _http_get(url, timeout=10)
                        if body:
                            text = body.decode(errors="ignore")
                            links, scripts = HREF_RE.findall(text), SRC_RE.findall(text)
                        else:
                            result.errors.append(f"Redirected crawl page failed (retryable): {url}")
                            failed.add(url)
                            text, links, scripts = "", [], []
                    else:
                        result.errors.append(f"Crawl page failed (retryable): {url}: {type(exc).__name__}; {'; '.join(route_failure)}")
                        failed.add(url)
                        text, links, scripts = "", [], []
            else:
                body, _ = _http_get(url, timeout=10)
                if not body:
                    result.errors.append(f"Crawl page returned no body (retryable): {url}")
                    failed.add(url)
                text = body.decode(errors="ignore")
                links = HREF_RE.findall(text)
                scripts = SRC_RE.findall(text)
            if url not in failed:
                succeeded.add(url)
            for link in links:
                u = _normalize_url(link, url)
                if u and _same_host(u, result.target_host) and is_in_scope(u, scope):
                    if u not in queued:
                        if len(queued) < CRAWL_URL_LIMIT:
                            pending.append(u)
                            queued.add(u)
                        else:
                            overflow += 1
                            spill(u)
                            continue
                    all_urls.add(u)
                    for param in PARAM_RE.finditer(u):
                        all_params.add(param.group(1))
            for script in scripts:
                u = _normalize_url(script, url)
                if u and _same_host(u, result.target_host) and is_in_scope(u, scope):
                    all_js.add(u)
            for m in URL_RE.finditer(text):
                u = m.group(0).rstrip('.,;)')
                if _same_host(u, result.target_host) and is_in_scope(u, scope):
                    if u not in all_urls and len(all_urls) >= CRAWL_URL_LIMIT:
                        overflow += 1
                        spill(u)
                        continue
                    all_urls.add(u)
                    for param in PARAM_RE.finditer(u):
                        all_params.add(param.group(1))
            _extract_forms(text, url, result)
            for m in PARAM_RE.finditer(url):
                all_params.add(m.group(1))
            save()
    finally:
        if browser is not None:
            browser.close()
        if pw_context is not None:
            pw_context.__exit__(None, None, None)
        if route_failure:
            result.pause_reason = "Browser request guard failed; retry after reviewing crawl errors"
            result.errors.extend(error for error in route_failure if error not in result.errors)
            failed.add(current_page or result.target)
            succeeded.discard(current_page or result.target)
            save()
        result.urls = sorted(all_urls)
        result.params = sorted(all_params)
        result.js_files = sorted(all_js)
        result.crawl_pages_attempted = len(visited)
        result.crawl_pages_pending = len(pending) + len(failed)
        result.crawl_frontier_overflow = overflow
        result.crawl_status = "paused" if pending or failed or overflow or result.pause_reason else "complete"
        if len(queued) >= CRAWL_URL_LIMIT or overflow:
            result.errors.append(f"Crawl frontier limit {CRAWL_URL_LIMIT} reached; paused for operator review")

    _log(f"Crawl {result.crawl_status}: {len(visited)} attempted, {len(succeeded)} succeeded, "
         f"{len(pending)} pending, {len(failed)} retryable failed, {overflow} frontier overflow, "
         f"{len(result.urls)} URLs, {len(result.js_files)} JS files")

def _extract_forms(html: str, base_url: str, result: ReconResult) -> None:
    for form_html in FORM_BLOCK_RE.findall(html):
        action_match = FORM_ACTION_RE.search(form_html)
        if not action_match:
            continue
        action = _normalize_url(action_match.group(1), base_url) or action_match.group(1)
        inputs = INPUT_NAME_RE.findall(form_html)
        form = {"action": action, "inputs": inputs}
        # Avoid exact duplicates
        if form not in result.forms:
            result.forms.append(form)


# ──────────────────────────────────────────────────────────────────────────────
# Phase 3 — ANALYZE
# ──────────────────────────────────────────────────────────────────────────────

def phase_analyze(result: ReconResult, scope=None) -> None:
    _log("=== Phase 3: ANALYZE ===", "INFO")

    # Scan JS files for secrets and API endpoints
    _log(f"Analyzing {len(result.js_files)} JS files …")
    api_endpoint_re = re.compile(
        r'["\'](?P<path>/(?:api|v\d|graphql|rest|gql|backend)[^\s"\'<>]{0,100})["\']',
        re.IGNORECASE,
    )
    endpoint_set: set[str] = set()

    active_scope = scope if scope is not None else _g_scope
    scoped_js_urls = sorted({js_url for js_url in result.js_files
                             if _same_host(js_url, result.target_host) and is_in_scope(js_url, active_scope)})
    result.js_files_scoped = len(scoped_js_urls)
    checkpoint = _output_dir(result) / "analysis_checkpoint.json"
    saved = json.loads(checkpoint.read_text()) if checkpoint.exists() else {}
    if saved and (saved.get("target") != result.target or saved.get("program") != result.program):
        raise ValueError("Analysis checkpoint belongs to another target")
    for restored in saved.get("done", []):
        if not _same_host(restored, result.target_host) or not is_in_scope(restored, active_scope):
            raise ValueError(f"Analysis checkpoint URL is no longer authorized by current scope: {restored}")
    done = set(saved.get("done", [])) & set(scoped_js_urls)
    endpoint_set.update(u for u in saved.get("endpoints", [])
                        if _same_host(u, result.target_host) and is_in_scope(u, active_scope))
    result.secrets_found = [finding for finding in saved.get("secrets", []) if finding.get("source") in scoped_js_urls]
    def save_analysis():
        _save_checkpoint(checkpoint, {"target": result.target, "program": result.program,
            "done": sorted(done), "endpoints": sorted(endpoint_set), "secrets": result.secrets_found})
    for js_url in scoped_js_urls:
        if js_url in done:
            continue
        _require_output_space(_output_dir(result))
        body, _ = _http_get(js_url, timeout=10)
        result.js_files_attempted += 1
        if not body:
            result.js_files_failed += 1
            result.errors.append(f"JS fetch returned no body: {js_url}")
            continue
        text = body.decode(errors="ignore")

        # Secret detection
        for kind, severity, pattern in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                lineno = text[: m.start()].count("\n") + 1
                snippet = text[max(0, m.start() - 40): m.end() + 40].replace("\n", " ")
                finding = {
                    "type": kind,
                    "severity": severity,
                    "value": m.group(0)[:120],
                    "source": js_url,
                    "line": lineno,
                    "context": snippet[:200],
                }
                if finding not in result.secrets_found:
                    result.secrets_found.append(finding)
                    _log(f"  SECRET [{severity}] {kind} in {js_url}", "WARN")

        # API endpoint extraction
        for m in api_endpoint_re.finditer(text):
            path = m.group("path")
            full = urllib.parse.urljoin(result.target, path)
            endpoint_set.add(full)

        # Generic URL extraction from JS
        for m in URL_RE.finditer(text):
            u = m.group(0).rstrip('.,;)')
            if _same_host(u, result.target_host) and is_in_scope(u, active_scope):
                endpoint_set.add(u)
        done.add(js_url)
        save_analysis()

    result.js_files_attempted = len(done) + result.js_files_failed
    result.analysis_status = "partial" if result.js_files_failed else "complete"
    result.api_endpoints = sorted(endpoint_set)

    # Probe interesting paths
    _log("Probing interesting paths …")
    for path in INTERESTING_PATHS:
        url = urllib.parse.urljoin(result.target, path)
        if not _same_host(url, result.target_host) or not is_in_scope(url, active_scope):
            continue
        _require_output_space(_output_dir(result))
        probe_start = time.time()
        try:
            if _g_limiter is not None:
                _g_limiter.wait()
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; BountyRecon/1.0)"},
            )
            with _open_scoped(req, timeout=6) as resp:
                body = resp.read()
                _safe_log_span(
                    span_type="tool",
                    level="STEP",
                    message=f"Tool: probe {url}",
                    tool_name="urllib_request",
                    tool_category="http_request",
                    input_bytes=len(url.encode("utf-8", errors="replace")),
                    output_bytes=len(body),
                    latency_ms=int((time.time() - probe_start) * 1000),
                    output_tokens_est=max(0, math.ceil(len(body) / 4)),
                    success=True,
                )
                if resp.status in (200, 301, 302, 403, 401):
                    result.interesting_paths_found.append(f"{url} [{resp.status}]")
                    _log(f"  Found: {url} [{resp.status}]", "OK")
        except urllib.error.HTTPError as e:
            _safe_log_span(
                span_type="tool",
                level="STEP",
                message=f"Tool: probe {url}",
                tool_name="urllib_request",
                tool_category="http_request",
                input_bytes=len(url.encode("utf-8", errors="replace")),
                output_bytes=0,
                latency_ms=int((time.time() - probe_start) * 1000),
                success=False,
            )
            if e.code in (401, 403):
                result.interesting_paths_found.append(f"{url} [{e.code}]")
                _log(f"  Found (restricted): {url} [{e.code}]", "OK")
        except Exception:
            pass

    _log(
        f"Analysis complete: {len(result.secrets_found)} secrets, "
        f"{len(result.api_endpoints)} API endpoints, "
        f"{len(result.interesting_paths_found)} interesting paths",
        "OK",
    )


# ──────────────────────────────────────────────────────────────────────────────
# Phase 4 — ORGANIZE
# ──────────────────────────────────────────────────────────────────────────────

def phase_organize(result: ReconResult) -> Path:
    _log("=== Phase 4: ORGANIZE ===", "INFO")

    out_dir = _output_dir(result)
    if not result.pause_reason:
        _require_output_space(out_dir)

    # Deduplicate and write urls.txt
    urls = sorted(set(result.urls + result.api_endpoints))
    if not result.pause_reason:
        (out_dir / "urls.txt").write_text("\n".join(urls) + "\n")

    # params.txt
    params = sorted(set(result.params))
    if not result.pause_reason:
        (out_dir / "params.txt").write_text("\n".join(params) + "\n")

    # js_files.txt
    js_files = sorted(set(result.js_files))
    if not result.pause_reason:
        (out_dir / "js_files.txt").write_text("\n".join(js_files) + "\n")

    # tech_stack.txt
    tech = sorted(set(result.tech_stack))
    lines = [f"WAF: {result.waf_detected}" if result.waf_detected else "WAF: None detected"]
    lines += tech
    if not result.pause_reason:
        (out_dir / "tech_stack.txt").write_text("\n".join(lines) + "\n")

    # summary.json
    prior = json.loads((out_dir / "summary.json").read_text()) if (out_dir / "summary.json").exists() else {}
    result.end_time = datetime.now(timezone.utc).isoformat()
    summary = {
        "program": result.program,
        "target": result.target,
        "generated": result.end_time,
        "run_id": result.run_id,
        "open_ports": result.open_ports,
        "services": {str(k): v for k, v in result.services.items()},
        "waf": result.waf_detected,
        "tech_stack_count": len(tech),
        "urls_total": len(urls),
        "params_total": len(params),
        "js_files_total": len(js_files),
        "crawl_status": result.crawl_status,
        "discovery_status": result.discovery_status,
        "pause_reason": result.pause_reason,
        "crawl_pages_attempted": result.crawl_pages_attempted,
        "crawl_pages_pending": result.crawl_pages_pending,
        "crawl_frontier_overflow": result.crawl_frontier_overflow,
        "crawl_checkpoint": str(out_dir / "crawl_checkpoint.json") if (out_dir / "crawl_checkpoint.json").exists() else None,
        "analysis_status": result.analysis_status,
        "js_files_scoped": result.js_files_scoped,
        "js_files_attempted": result.js_files_attempted,
        "js_files_failed": result.js_files_failed,
        "secrets_found": len(result.secrets_found),
        "api_endpoints": len(result.api_endpoints),
        "interesting_paths": result.interesting_paths_found,
        "secrets": result.secrets_found,
        "errors": result.errors,
    }
    _save_checkpoint(out_dir / "summary.json", summary)

    complete = (result.crawl_status == "complete" and result.analysis_status == "complete"
                and result.discovery_status == "complete" and not result.pause_reason)
    previous_manifest = prior.get("canonical_manifest") if prior.get("run_id") == result.run_id else None
    if complete and previous_manifest and Path(previous_manifest).is_file():
        summary["canonical_manifest"] = previous_manifest
        _save_checkpoint(out_dir / "summary.json", summary)
    elif record_recon_artifacts is not None and complete:
        manifest_path = record_recon_artifacts(
            program=result.program,
            target=result.target_host or result.target,
            tool="autonomous-recon",
            run_id=result.run_id or None,
            source_paths=[
                out_dir / "urls.txt",
                out_dir / "params.txt",
                out_dir / "js_files.txt",
                out_dir / "tech_stack.txt",
                out_dir / "summary.json",
            ],
            command=f"autonomous_recon.py --program {result.program} --target {result.target}",
            scope_filter="auto",
            repull_scope=True,
            extra_manifest={"legacy_output_dir": str(out_dir)},
        )
        summary["canonical_manifest"] = str(manifest_path)
        summary["crawl_checkpoint"] = None
        _save_checkpoint(out_dir / "summary.json", summary)

    if complete:
        (out_dir / "crawl_checkpoint.json").unlink(missing_ok=True)
        (out_dir / "analysis_checkpoint.json").unlink(missing_ok=True)
        (out_dir / "crawl_overflow.txt").unlink(missing_ok=True)
        summary["crawl_checkpoint"] = None
        _save_checkpoint(out_dir / "summary.json", summary)

    _log(f"Output saved to: {out_dir}", "OK")
    return out_dir


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def is_in_scope(url: str, scope) -> bool:
    """Check if URL is in scope. Skip if no scope loaded."""
    if not scope:
        return True
    return scope.is_in_scope(url)


def run_recon(program: str, target: str) -> ReconResult:
    global _g_limiter, _RECON_LOGGER, _g_scope, _g_target_host, _g_result

    # Normalise target
    if not target.startswith("http"):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    host = parsed.netloc or parsed.path

    _log(f"Starting autonomous recon: program={program}  target={target}", "INFO")
    _log(f"Host: {host}", "INFO")
    if SubagentLogger is not None:
        try:
            _RECON_LOGGER = SubagentLogger("autonomous_recon", program, f"recon_{int(time.time())}")
            _RECON_LOGGER.start(target=target)
        except Exception:
            _RECON_LOGGER = None

    # Initialize scope validator
    scope = None
    if program and ScopeValidator is not None:
        scope = ScopeValidator(program)
    _g_scope = scope
    _g_target_host = host

    # Initialize rate limiter
    if RateLimiter is not None:
        _g_limiter = RateLimiter(requests_per_second=5)

    if not is_in_scope(target, scope):
        _log(f"[SKIP] Out of scope: {target}", "WARN")
        return ReconResult(program=program, target=target, target_host=host)

    result = ReconResult(program=program, target=target, target_host=host)
    _g_result = result

    phase_discover(result)
    phase_crawl(result, scope=scope)
    if result.crawl_status == "complete":
        try:
            phase_analyze(result, scope=scope)
        except DiskFloorPause as exc:
            result.pause_reason = str(exc)
            result.analysis_status = "paused_disk_floor"
            result.api_endpoints = []  # resume reads the analysis checkpoint
    else:
        result.analysis_status = "pending_crawl"
        _log(f"Crawl paused with {result.crawl_pages_pending} pages outstanding; rerun the same target to resume", "WARN")
    try:
        out_dir = phase_organize(result)
    except DiskFloorPause as exc:
        result.pause_reason = str(exc)
        out_dir = phase_organize(result)  # small atomic summary only; checkpoints stay intact

    # Final report
    print()
    print("=" * 60)
    print(" RECON COMPLETE" if recon_complete(result) else " RECON PARTIAL / PAUSED")
    print("=" * 60)
    print(f"  Target        : {target}")
    print(f"  Open ports    : {result.open_ports or 'none found'}")
    print(f"  WAF           : {result.waf_detected or 'not detected'}")
    print(f"  Tech stack    : {len(result.tech_stack)} hints")
    print(f"  URLs          : {len(result.urls)}")
    print(f"  Params        : {len(result.params)}")
    print(f"  JS files      : {len(result.js_files)}")
    print(f"  Secrets found : {len(result.secrets_found)}")
    print(f"  API endpoints : {len(result.api_endpoints)}")
    print(f"  Interesting   : {len(result.interesting_paths_found)}")
    print(f"  Crawl         : {result.crawl_status} ({result.crawl_pages_attempted} attempted, {result.crawl_pages_pending} outstanding)")
    print(f"  JS analysis   : {result.analysis_status} ({result.js_files_attempted}/{result.js_files_scoped} attempted, {result.js_files_failed} failed)")
    print(f"  Output dir    : {out_dir}")
    print("=" * 60)

    return result


def recon_complete(result: ReconResult) -> bool:
    return (result.crawl_status == "complete" and result.analysis_status == "complete"
            and result.discovery_status == "complete" and not result.pause_reason)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Autonomous Recon Agent — full one-shot recon pipeline"
    )
    parser.add_argument("--target", required=True, help="Target URL or domain")
    parser.add_argument(
        "--program",
        default="",
        help="Bug bounty program name (used for output dir). Derived from target if omitted.",
    )
    args = parser.parse_args()

    program = args.program
    if not program:
        # Derive from target host
        parsed = urllib.parse.urlparse(
            args.target if args.target.startswith("http") else f"https://{args.target}"
        )
        program = parsed.netloc.lstrip("www.").split(".")[0] or "unknown"

    result = run_recon(program=program, target=args.target)
    if not recon_complete(result):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
