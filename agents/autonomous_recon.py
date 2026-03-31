"""
Autonomous Recon Agent — One-shot full recon pipeline.

Usage:
    python3 autonomous_recon.py --program superdrug --target https://www.superdrug.com
    python3 autonomous_recon.py --target https://www.example.com

Output:
    ~/Shared/bounty_recon/{program}/ghost/recon/
    ├── urls.txt
    ├── params.txt
    ├── js_files.txt
    ├── tech_stack.txt
    └── summary.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, "/home/ryushe/workspace/bug_bounty_harness")
sys.path.insert(0, "/home/ryushe/projects/bounty-tools")

try:
    from scope_validator import ScopeValidator
except ImportError:
    ScopeValidator = None
try:
    from rate_limiter import RateLimiter
except ImportError:
    RateLimiter = None

# Module-level rate limiter (initialized in run_recon)
_g_limiter = None

# ──────────────────────────────────────────────────────────────────────────────
# Regex helpers
# ──────────────────────────────────────────────────────────────────────────────

URL_RE = re.compile(r'https?://[^\s\'"<>()\[\]{}]+', re.IGNORECASE)
JS_URL_RE = re.compile(r'["\'](?P<path>/[a-zA-Z0-9_\-/\.]+\.js(?:\?[^"\']*)?)["\']')
PARAM_RE = re.compile(r'[?&]([a-zA-Z0-9_\-]+)=', re.IGNORECASE)
FORM_ACTION_RE = re.compile(r'<form[^>]*action=["\']?([^"\'>\s]+)', re.IGNORECASE)
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


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _log(msg: str, level: str = "INFO") -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    tag = {"INFO": "[ ]", "OK": "[+]", "WARN": "[!]", "ERR": "[x]"}.get(level, "[ ]")
    print(f"{ts} {tag} {msg}", flush=True)


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
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return b"", dict(e.headers) if e.headers else {}
    except Exception:
        return b"", {}


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_cmd(cmd: list[str], timeout: int = 120) -> str:
    """Run a subprocess, return stdout as string."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        return ""
    except Exception:
        return ""


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

def phase_crawl(result: ReconResult) -> None:
    _log("=== Phase 2: CRAWL ===", "INFO")
    crawled_urls: set[str] = set()
    pending: list[str] = [result.target]
    all_urls: set[str] = set()
    all_params: set[str] = set()
    all_js: set[str] = set()
    depth = 0
    max_depth = 2
    max_pages = 60

    # Try playwright first
    playwright_ok = _try_playwright_crawl(result, all_urls, all_params, all_js)
    if playwright_ok:
        _log(f"Playwright crawl found {len(all_urls)} URLs, {len(all_js)} JS files", "OK")
    else:
        _log("Playwright unavailable — using curl/urllib crawler", "INFO")
        # Simple BFS crawler
        while pending and len(crawled_urls) < max_pages and depth <= max_depth:
            current_batch = pending[:10]
            pending = pending[10:]
            depth += 1
            for url in current_batch:
                if url in crawled_urls:
                    continue
                crawled_urls.add(url)
                _log(f"  Crawling: {url[:80]}")
                body, headers = _http_get(url, timeout=10)
                if not body:
                    continue
                text = body.decode(errors="ignore")
                # Extract URLs from HTML
                for m in HREF_RE.finditer(text):
                    u = _normalize_url(m.group(1), url)
                    if u and _same_host(u, result.target_host):
                        all_urls.add(u)
                        if u not in crawled_urls:
                            pending.append(u)
                # Extract JS files
                for m in SRC_RE.finditer(text):
                    u = _normalize_url(m.group(1), url)
                    if u:
                        all_js.add(u)
                # Extract all URLs from body text
                for m in URL_RE.finditer(text):
                    u = m.group(0).rstrip('.,;)')
                    if _same_host(u, result.target_host):
                        all_urls.add(u)
                # Extract params
                for m in PARAM_RE.finditer(url):
                    all_params.add(m.group(1))
                # Extract form data
                _extract_forms(text, url, result)

    # Collect params from all discovered URLs
    for u in all_urls:
        for m in PARAM_RE.finditer(u):
            all_params.add(m.group(1))

    result.urls = sorted(all_urls)
    result.params = sorted(all_params)
    result.js_files = sorted(all_js)

    _log(f"Crawl complete: {len(result.urls)} URLs, {len(result.params)} params, {len(result.js_files)} JS files", "OK")


def _try_playwright_crawl(
    result: ReconResult,
    all_urls: set[str],
    all_params: set[str],
    all_js: set[str],
) -> bool:
    """Attempt playwright-based crawl. Returns True if successful."""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return False

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
            )
            page = context.new_page()

            visited: set[str] = set()
            queue: list[str] = [result.target]
            max_pages = 50

            # Intercept network requests to grab all URLs / JS files
            def on_request(req):
                u = req.url
                if _same_host(u, result.target_host):
                    all_urls.add(u)
                    for m in PARAM_RE.finditer(u):
                        all_params.add(m.group(1))
                if u.endswith(".js") or ".js?" in u:
                    all_js.add(u)

            page.on("request", on_request)

            while queue and len(visited) < max_pages:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                try:
                    page.goto(url, timeout=15000, wait_until="domcontentloaded")
                    page.wait_for_timeout(1000)
                    html = page.content()
                    # Grab links
                    links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                    for link in links:
                        n = _normalize_url(link, url)
                        if n and _same_host(n, result.target_host) and n not in visited:
                            queue.append(n)
                    # Grab JS src
                    scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
                    for s in scripts:
                        n = _normalize_url(s, url)
                        if n:
                            all_js.add(n)
                    # Extract forms
                    _extract_forms(html, url, result)
                except Exception:
                    pass

            browser.close()
        return True
    except Exception:
        return False


def _extract_forms(html: str, base_url: str, result: ReconResult) -> None:
    for m in FORM_ACTION_RE.finditer(html):
        action = _normalize_url(m.group(1), base_url) or m.group(1)
        inputs = INPUT_NAME_RE.findall(html)
        form = {"action": action, "inputs": inputs}
        # Avoid exact duplicates
        if form not in result.forms:
            result.forms.append(form)


# ──────────────────────────────────────────────────────────────────────────────
# Phase 3 — ANALYZE
# ──────────────────────────────────────────────────────────────────────────────

def phase_analyze(result: ReconResult) -> None:
    _log("=== Phase 3: ANALYZE ===", "INFO")

    # Scan JS files for secrets and API endpoints
    _log(f"Analyzing {len(result.js_files)} JS files …")
    api_endpoint_re = re.compile(
        r'["\'](?P<path>/(?:api|v\d|graphql|rest|gql|backend)[^\s"\'<>]{0,100})["\']',
        re.IGNORECASE,
    )
    endpoint_set: set[str] = set()

    for js_url in result.js_files[:80]:  # cap at 80 JS files
        body, _ = _http_get(js_url, timeout=10)
        if not body:
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
            if _same_host(u, result.target_host):
                endpoint_set.add(u)

    result.api_endpoints = sorted(endpoint_set)

    # Probe interesting paths
    _log("Probing interesting paths …")
    for path in INTERESTING_PATHS:
        url = urllib.parse.urljoin(result.target, path)
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; BountyRecon/1.0)"},
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status in (200, 301, 302, 403, 401):
                    result.interesting_paths_found.append(f"{url} [{resp.status}]")
                    _log(f"  Found: {url} [{resp.status}]", "OK")
        except urllib.error.HTTPError as e:
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

    out_dir = Path.home() / "Shared" / "bounty_recon" / result.program / "ghost" / "recon"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Deduplicate and write urls.txt
    urls = sorted(set(result.urls + result.api_endpoints))
    (out_dir / "urls.txt").write_text("\n".join(urls) + "\n")

    # params.txt
    params = sorted(set(result.params))
    (out_dir / "params.txt").write_text("\n".join(params) + "\n")

    # js_files.txt
    js_files = sorted(set(result.js_files))
    (out_dir / "js_files.txt").write_text("\n".join(js_files) + "\n")

    # tech_stack.txt
    tech = sorted(set(result.tech_stack))
    lines = [f"WAF: {result.waf_detected}" if result.waf_detected else "WAF: None detected"]
    lines += tech
    (out_dir / "tech_stack.txt").write_text("\n".join(lines) + "\n")

    # summary.json
    result.end_time = datetime.now(timezone.utc).isoformat()
    summary = {
        "program": result.program,
        "target": result.target,
        "generated": result.end_time,
        "open_ports": result.open_ports,
        "services": {str(k): v for k, v in result.services.items()},
        "waf": result.waf_detected,
        "tech_stack_count": len(tech),
        "urls_total": len(urls),
        "params_total": len(params),
        "js_files_total": len(js_files),
        "secrets_found": len(result.secrets_found),
        "api_endpoints": len(result.api_endpoints),
        "interesting_paths": result.interesting_paths_found,
        "secrets": result.secrets_found,
        "errors": result.errors,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

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
    global _g_limiter

    # Normalise target
    if not target.startswith("http"):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    host = parsed.netloc or parsed.path

    _log(f"Starting autonomous recon: program={program}  target={target}", "INFO")
    _log(f"Host: {host}", "INFO")

    # Initialize scope validator
    scope = None
    if program and ScopeValidator is not None:
        scope = ScopeValidator(program)

    # Initialize rate limiter
    if RateLimiter is not None:
        _g_limiter = RateLimiter(requests_per_second=5)

    if not is_in_scope(target, scope):
        _log(f"[SKIP] Out of scope: {target}", "WARN")
        return ReconResult(program=program, target=target, target_host=host)

    result = ReconResult(program=program, target=target, target_host=host)

    phase_discover(result)
    phase_crawl(result)
    phase_analyze(result)
    out_dir = phase_organize(result)

    # Final report
    print()
    print("=" * 60)
    print(" RECON COMPLETE")
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
    print(f"  Output dir    : {out_dir}")
    print("=" * 60)

    return result


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

    run_recon(program=program, target=args.target)


if __name__ == "__main__":
    main()
