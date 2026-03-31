"""
Subdomain Enumeration Agent — Multi-source aggregation with takeover detection.

Phases:
  1. COLLECT  — passive APIs, brute-force wordlist, JS/HTML extraction, local files
  2. AGGREGATE — dedup via set + anew/uro if available
  3. PROBE    — httpx async probing (status, title, IP, content-length)
  4. ORGANIZE  — write structured output files
  5. TAKEOVER  — fingerprint dead subs against known vulnerable service patterns

Usage:
    python3 subdomain_agent.py --target example.com --program example
    python3 subdomain_agent.py --target example.com --program example \\
        --wordlist ~/wordlists/commonspeak2/subdomains.txt \\
        --use-apis crtsh,otx,bufferover,urlscan,rdap,whoxy
"""

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import socket

import requests

try:
    from scope_validator import ScopeValidator
except ImportError:
    ScopeValidator = None
try:
    from rate_limiter import RateLimiter
except ImportError:
    RateLimiter = None

# ---------------------------------------------------------------------------
# Config / constants
# ---------------------------------------------------------------------------

RECON_BASE = Path.home() / "Shared" / "bounty_recon"

TAKEOVER_FINGERPRINTS: dict[str, list[str]] = {
    "github-pages":    ["There isn't a GitHub Pages site here",
                        "For root URLs (like http://example.com/) you must provide an index"],
    "heroku":          ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    "aws-s3":          ["NoSuchBucket", "The specified bucket does not exist"],
    "cloudfront":      ["Bad request.", "ERROR: The request could not be satisfied"],
    "fastly":          ["Fastly error: unknown domain"],
    "shopify":         ["Sorry, this shop is currently unavailable.",
                        "Only one step left!"],
    "tumblr":          ["There's nothing here.", "Whatever you were looking for doesn't live here"],
    "wordpress":       ["Do you want to register"],
    "sendgrid":        ["The provided host name is not valid for this server"],
    "mailgun":         ["mailgun"],
    "stripe":          ["Activate your Stripe account"],
    "ghost":           ["The thing you were looking for is no longer here"],
    "helpjuice":       ["We could not find what you're looking for"],
    "helpscout":       ["No settings were found for this company"],
    "cargo":           ["If you're moving your domain away from Cargo you must make this configuration"],
    "feedpress":       ["The feed has not been found."],
    "surveysparrow":   ["Account not found"],
    "readme-io":       ["Project doesnt exist..."],
    "acquia":          ["Web Site Not Found"],
    "agile-crm":       ["Sorry, this page is no longer available"],
    "airee":           ["Ошибка. Сервис Айри.рф не работает"],
    "anima":           ["is not registered in Anima"],
    "pingdom":         ["This public status page has not been claimed"],
    "tave":            ["This page is no longer available"],
    "teamwork":        ["Oops - We didn't find your site."],
    "thinkific":       ["You may have mistyped the address or the page may have moved"],
    "tictail":         ["Building a brand new site"],
    "campaignmonitor": ["Trying to access your account?"],
    "canny":           ["There is no such company. Did you enter the right URL?"],
    "desk":            ["Please try again or try Desk.com free for 14 days"],
    "launchrock":      ["It looks like you may have taken a wrong turn somewhere"],
    "statuspage-io":   ["You are being redirected"],
    "surge-sh":        ["project not found"],
    "uberflip":        ["Non-Existing Domain"],
    "unbounce":        ["The requested URL was not found on this server"],
    "uservoice":       ["This UserVoice subdomain is currently available"],
    "vend":            ["Looks like you've traveled too far into cyberspace"],
    "wishpond":        ["https://www.wishpond.com/404"],
    "zendesk":         ["Help Center Closed", "Redirecting to https://www.zendesk.com"],
}

MUTATION_PREFIXES = [
    "dev", "dev2", "staging", "stage", "stg", "uat", "qa", "test", "testing",
    "prod", "production", "preprod", "pre-prod", "sandbox", "demo",
    "api", "api2", "api-v1", "api-v2", "rest", "graphql",
    "admin", "dashboard", "portal", "panel", "backoffice", "internal",
    "mail", "smtp", "webmail", "email",
    "cdn", "static", "assets", "media", "img", "images",
    "blog", "forum", "help", "support", "docs", "wiki",
    "vpn", "remote", "ssh", "ftp", "sftp",
    "corp", "intranet", "extranet", "private",
    "mobile", "m", "app", "apps",
    "beta", "alpha", "canary", "preview",
    "status", "monitor", "metrics", "grafana", "kibana", "jenkins", "jira",
    "git", "gitlab", "github", "bitbucket",
    "auth", "login", "sso", "oauth", "idp",
    "shop", "store", "checkout", "payment", "billing",
    "legacy", "old", "v1", "v2", "new",
    "us", "eu", "uk", "ap", "asia", "aws", "gcp",
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    subdomain: str
    url: str
    status: int
    title: str
    content_length: int
    ip: str
    redirect_url: str
    source: str
    probed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Source collectors
# ---------------------------------------------------------------------------

class SubdomainCollector:
    def __init__(self, target: str, program: str, use_apis: list[str],
                 wordlist: Optional[str], verbose: bool = False):
        self.target = target
        self.program = program
        self.use_apis = use_apis
        self.wordlist = wordlist
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (compatible; subdomain-recon/1.0)"
        )

        # Load scope
        if program and ScopeValidator is not None:
            self.scope = ScopeValidator(program)
        else:
            self.scope = None

        # Setup rate limiter
        self.limiter = RateLimiter(requests_per_second=5) if RateLimiter else None

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope. Skip if no scope loaded."""
        if not self.scope:
            return True
        return self.scope.is_in_scope(url)

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"  [collect] {msg}")

    # --- crt.sh ---
    def from_crtsh(self) -> set[str]:
        subs: set[str] = set()
        try:
            self.log("querying crt.sh ...")
            if self.limiter:
                self.limiter.wait()
            r = self.session.get(
                "https://crt.sh/",
                params={"q": f"%.{self.target}", "output": "json"},
                timeout=30,
            )
            if r.status_code == 200:
                for entry in r.json():
                    names = entry.get("name_value", "")
                    for name in names.split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(f".{self.target}") or name == self.target:
                            subs.add(name.lower())
            self.log(f"crt.sh → {len(subs)} subs")
        except Exception as e:
            print(f"  [warn] crt.sh failed: {e}")
        return subs

    # --- AlienVault OTX ---
    def from_otx(self) -> set[str]:
        subs: set[str] = set()
        try:
            self.log("querying AlienVault OTX ...")
            page = 1
            while True:
                if self.limiter:
                    self.limiter.wait()
                r = self.session.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/"
                    f"{self.target}/passive_dns",
                    params={"page": page, "limit": 500},
                    timeout=30,
                )
                if r.status_code != 200:
                    break
                data = r.json()
                records = data.get("passive_dns", [])
                if not records:
                    break
                for rec in records:
                    hostname = rec.get("hostname", "").lower().lstrip("*.")
                    if hostname.endswith(f".{self.target}") or hostname == self.target:
                        subs.add(hostname)
                if not data.get("has_next"):
                    break
                page += 1
                time.sleep(0.5)
            self.log(f"OTX → {len(subs)} subs")
        except Exception as e:
            print(f"  [warn] OTX failed: {e}")
        return subs

    # --- Bufferover ---
    def from_bufferover(self) -> set[str]:
        subs: set[str] = set()
        try:
            self.log("querying Bufferover ...")
            if self.limiter:
                self.limiter.wait()
            r = self.session.get(
                f"https://dns.bufferover.run/dns",
                params={"q": f".{self.target}"},
                timeout=20,
            )
            if r.status_code == 200:
                data = r.json()
                for record in data.get("FDNS_A", []) + data.get("RDNS", []):
                    parts = record.split(",")
                    hostname = parts[-1].strip().rstrip(".").lower()
                    if hostname.endswith(f".{self.target}") or hostname == self.target:
                        subs.add(hostname)
            self.log(f"Bufferover → {len(subs)} subs")
        except Exception as e:
            print(f"  [warn] Bufferover failed: {e}")
        return subs

    # --- URLScan ---
    def from_urlscan(self) -> set[str]:
        subs: set[str] = set()
        try:
            self.log("querying URLScan ...")
            if self.limiter:
                self.limiter.wait()
            r = self.session.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{self.target}", "size": 10000},
                timeout=30,
            )
            if r.status_code == 200:
                for result in r.json().get("results", []):
                    task = result.get("task", {})
                    page = result.get("page", {})
                    for key in ("domain", "apex"):
                        val = page.get(key, "").lower()
                        if val.endswith(f".{self.target}") or val == self.target:
                            subs.add(val)
                    sub = urlparse(task.get("url", "")).hostname or ""
                    if sub and (sub.endswith(f".{self.target}") or sub == self.target):
                        subs.add(sub.lower())
            self.log(f"URLScan → {len(subs)} subs")
        except Exception as e:
            print(f"  [warn] URLScan failed: {e}")
        return subs

    # --- RDAP ---
    def from_rdap(self) -> set[str]:
        """RDAP gives registration info — less useful for subdomain enum but
        we mine nameservers + related entities."""
        subs: set[str] = set()
        try:
            self.log("querying RDAP ...")
            if self.limiter:
                self.limiter.wait()
            r = self.session.get(
                f"https://rdap.org/domain/{self.target}",
                timeout=20,
            )
            if r.status_code == 200:
                data = r.json()
                # Sometimes related subdomains show up in nameserver entries
                for ns in data.get("nameservers", []):
                    ldhName = ns.get("ldhName", "").lower().rstrip(".")
                    if ldhName.endswith(f".{self.target}"):
                        subs.add(ldhName)
            self.log(f"RDAP → {len(subs)} subs")
        except Exception as e:
            print(f"  [warn] RDAP failed: {e}")
        return subs

    # --- Whoxy ---
    def from_whoxy(self) -> set[str]:
        subs: set[str] = set()
        api_key = os.getenv("WHOXY_API_KEY", "")
        if not api_key:
            self.log("Whoxy skipped (no WHOXY_API_KEY)")
            return subs
        try:
            self.log("querying Whoxy ...")
            if self.limiter:
                self.limiter.wait()
            r = self.session.get(
                "https://api.whoxy.com/",
                params={"key": api_key, "reverse": "whois",
                        "keyword": self.target, "mode": "mini"},
                timeout=30,
            )
            if r.status_code == 200:
                # Whoxy returns JSON with search results — mine domain names
                data = r.json()
                for entry in data.get("search_result", []):
                    domain = entry.get("domain_name", "").lower()
                    if domain.endswith(f".{self.target}") or domain == self.target:
                        subs.add(domain)
            self.log(f"Whoxy → {len(subs)} subs")
        except Exception as e:
            print(f"  [warn] Whoxy failed: {e}")
        return subs

    # --- Wordlist brute-force ---
    def from_wordlist(self) -> set[str]:
        subs: set[str] = set()
        if not self.wordlist:
            return subs
        wl_path = Path(self.wordlist).expanduser()
        if not wl_path.exists():
            print(f"  [warn] Wordlist not found: {wl_path}")
            return subs
        try:
            self.log(f"loading wordlist {wl_path} ...")
            count = 0
            with open(wl_path) as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith("#"):
                        subs.add(f"{word}.{self.target}")
                        count += 1
            self.log(f"Wordlist → {count} candidates")
        except Exception as e:
            print(f"  [warn] Wordlist failed: {e}")
        return subs

    # --- Alteration mutations ---
    def from_mutations(self, known_subs: set[str]) -> set[str]:
        """Generate mutations from known subs + add common prefixes to base domain."""
        subs: set[str] = set()
        # Prefix mutations on base domain
        for prefix in MUTATION_PREFIXES:
            subs.add(f"{prefix}.{self.target}")
        # Prefix mutations on known subs (one level deep)
        for sub in list(known_subs)[:200]:  # cap to avoid explosion
            parts = sub.split(".")
            if len(parts) > 2:
                base = ".".join(parts[1:])
                first = parts[0]
                for prefix in ["dev", "staging", "test", "api", "old", "new", "v2"]:
                    subs.add(f"{prefix}-{first}.{base}")
                    subs.add(f"{first}-{prefix}.{base}")
        self.log(f"Mutations → {len(subs)} candidates")
        return subs

    # --- JS file extraction ---
    def from_js_files(self) -> set[str]:
        subs: set[str] = set()
        js_list = RECON_BASE / self.program / "ghost" / "recon" / "js_files.txt"
        if not js_list.exists():
            return subs
        try:
            self.log(f"parsing JS file list: {js_list}")
            pattern = re.compile(
                r'(?:https?://)?([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.'
                + re.escape(self.target) + r')'
            )
            with open(js_list) as f:
                js_urls = [line.strip() for line in f if line.strip()]
            for js_url in js_urls[:100]:  # cap: fetch only first 100
                if not is_safe_url(js_url):
                    continue
                try:
                    r = self.session.get(js_url, timeout=10)
                    for m in pattern.finditer(r.text):
                        subs.add(m.group(1).lower())
                except Exception:
                    pass
            self.log(f"JS extraction → {len(subs)} subs")
        except Exception as e:
            print(f"  [warn] JS extraction failed: {e}")
        return subs

    # --- Local urls.txt extraction ---
    def from_local_urls(self) -> set[str]:
        subs: set[str] = set()
        urls_file = RECON_BASE / self.program / "ghost" / "recon" / "urls.txt"
        if not urls_file.exists():
            return subs
        try:
            self.log(f"parsing local urls.txt: {urls_file}")
            pattern = re.compile(
                r'([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.'
                + re.escape(self.target) + r')'
            )
            with open(urls_file) as f:
                for line in f:
                    for m in pattern.finditer(line):
                        subs.add(m.group(1).lower())
            self.log(f"Local URLs → {len(subs)} subs")
        except Exception as e:
            print(f"  [warn] Local URL extraction failed: {e}")
        return subs

    # --- Wayback Machine ---
    def from_wayback(self) -> set[str]:
        subs: set[str] = set()
        try:
            self.log("querying Wayback CDX ...")
            if self.limiter:
                self.limiter.wait()
            r = self.session.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{self.target}/*",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": 50000,
                },
                timeout=60,
            )
            if r.status_code == 200:
                data = r.json()
                if not isinstance(data, list):
                    self.log(f"Wayback returned error: {data}")
                    return subs
                pattern = re.compile(
                    r'(?:https?://)?([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.'
                    + re.escape(self.target) + r')'
                )
                for row in data[1:]:  # skip header
                    url = row[0] if row else ""
                    m = pattern.match(url)
                    if m:
                        subs.add(m.group(1).lower())
            self.log(f"Wayback → {len(subs)} subs")
        except Exception as e:
            print(f"  [warn] Wayback failed: {e}")
        return subs


# ---------------------------------------------------------------------------
# URL safety helper
# ---------------------------------------------------------------------------

_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.",
)


def is_safe_url(url: str) -> bool:
    """Return False for non-HTTP(S) schemes or private/internal hosts."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.netloc.split(":")[0].lower()
    if host in ("127.0.0.1", "localhost", "0.0.0.0") or host.startswith(_PRIVATE_PREFIXES):
        return False
    return True


# ---------------------------------------------------------------------------
# Async HTTP prober
# ---------------------------------------------------------------------------

async def probe_subdomain(subdomain: str, sem: asyncio.Semaphore,
                          client, timeout: int = 10) -> Optional[ProbeResult]:
    """Probe a subdomain with httpx async. Returns None on total failure."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            async with sem:
                resp = await client.get(url)
                title = ""
                m = re.search(r"<title[^>]*>([^<]{1,200})</title>",
                              resp.text, re.IGNORECASE)
                if m:
                    title = m.group(1).strip()
                ip = ""
                try:
                    ip = socket.getaddrinfo(subdomain, None)[0][4][0]
                except Exception:
                    ip = ""
                redirect_url = str(resp.url) if str(resp.url) != url else ""
                return ProbeResult(
                    subdomain=subdomain,
                    url=url,
                    status=resp.status_code,
                    title=title,
                    content_length=len(resp.content),
                    ip=ip,
                    redirect_url=redirect_url,
                    source="httpx",
                )
        except Exception:
            continue
    return ProbeResult(
        subdomain=subdomain,
        url=f"https://{subdomain}",
        status=0,
        title="",
        content_length=0,
        ip="",
        redirect_url="",
        source="httpx",
    )


async def probe_all(subdomains: list[str], threads: int = 20,
                    timeout: int = 10) -> list[ProbeResult]:
    try:
        import httpx as _httpx
    except ImportError:
        print("[error] httpx not installed — run: pip install httpx")
        sys.exit(1)
    sem = asyncio.Semaphore(threads)
    async with _httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=timeout,
        limits=_httpx.Limits(max_keepalive_connections=20, max_connections=100),
    ) as client:
        tasks = [probe_subdomain(sub, sem, client, timeout) for sub in subdomains]
        results = []
        total = len(tasks)
        done = 0
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                results.append(result)
            done += 1
            if done % 50 == 0 or done == total:
                print(f"  [probe] {done}/{total} probed", end="\r", flush=True)
        print()
        return results



# ---------------------------------------------------------------------------
# Takeover checker
# ---------------------------------------------------------------------------

async def check_takeover_async(result: ProbeResult, semaphore: asyncio.Semaphore,
                               client) -> Optional[dict]:
    """Async takeover check. Returns candidate dict or None."""
    if result.status not in (200, 404, 403):
        return None
    async with semaphore:
        try:
            r = await client.get(result.url, timeout=10)
            body = r.text
            for service, patterns in TAKEOVER_FINGERPRINTS.items():
                for pat in patterns:
                    if pat.lower() in body.lower():
                        return {
                            "subdomain": result.subdomain,
                            "url": result.url,
                            "status": result.status,
                            "service": service,
                        }
        except Exception:
            pass
    return None


async def _run_takeover_checks(dead_results: list[ProbeResult],
                                threads: int) -> list[dict]:
    try:
        import httpx as _httpx
    except ImportError:
        return []
    sem = asyncio.Semaphore(threads)
    async with _httpx.AsyncClient(verify=False, follow_redirects=True,
                                   timeout=10) as client:
        tasks = [check_takeover_async(r, sem, client) for r in dead_results]
        candidates: list[dict] = []
        total = len(tasks)
        done = 0
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                candidates.append(result)
            done += 1
            if done % 10 == 0:
                print(f"  [takeover] {done}/{total} checked",
                      end="\r", flush=True)
        if dead_results:
            print()
        return candidates


# ---------------------------------------------------------------------------
# Dedup helpers
# ---------------------------------------------------------------------------

def dedup_with_anew(subs: set[str]) -> list[str]:
    """Try to use `anew` for order-preserving dedup; fall back to sorted set."""
    anew_bin = _which("anew")
    if anew_bin:
        try:
            proc = subprocess.run(
                [anew_bin],
                input="\n".join(sorted(subs)),
                capture_output=True, text=True, timeout=30,
            )
            return [l for l in proc.stdout.splitlines() if l.strip()]
        except Exception:
            pass
    return sorted(subs)


def normalize_with_uro(urls: list[str]) -> list[str]:
    """Run `uro` for URL normalization if available; otherwise return as-is."""
    uro_bin = _which("uro")
    if uro_bin:
        try:
            proc = subprocess.run(
                [uro_bin],
                input="\n".join(urls),
                capture_output=True, text=True, timeout=30,
            )
            return [l for l in proc.stdout.splitlines() if l.strip()]
        except Exception:
            pass
    return urls


def _which(cmd: str) -> Optional[str]:
    try:
        result = subprocess.run(["which", cmd], capture_output=True, text=True)
        path = result.stdout.strip()
        return path if path else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------

def write_outputs(program: str, target: str,
                  raw_subs: set[str],
                  all_subs: list[str],
                  probe_results: list[ProbeResult],
                  takeover_candidates: list[dict],
                  sources_used: Optional[dict] = None) -> Path:
    out_dir = RECON_BASE / program / "ghost" / "subdomain"
    out_dir.mkdir(parents=True, exist_ok=True)

    # raw_subs.txt
    (out_dir / "raw_subs.txt").write_text("\n".join(sorted(raw_subs)) + "\n")

    # all_subs.txt
    (out_dir / "all_subs.txt").write_text("\n".join(all_subs) + "\n")

    alive = [r for r in probe_results if r.status in range(200, 400)]
    alive_urls = {r.url for r in alive}
    dead = [r for r in probe_results if r.url not in alive_urls]

    # alive_subs.txt
    (out_dir / "alive_subs.txt").write_text(
        "\n".join(r.subdomain for r in alive) + "\n"
    )

    # dead_subs.txt
    (out_dir / "dead_subs.txt").write_text(
        "\n".join(r.subdomain for r in dead) + "\n"
    )

    # takeover_candidates.txt
    (out_dir / "takeover_candidates.txt").write_text(
        "\n".join(
            f"{c['subdomain']}  [{c['service']}]  ({c['url']})"
            for c in takeover_candidates
        ) + "\n"
    )

    # scan_results.json
    scan_data = [asdict(r) for r in probe_results]
    (out_dir / "scan_results.json").write_text(
        json.dumps(scan_data, indent=2)
    )

    # summary.json
    summary = {
        "target": target,
        "program": program,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "total_raw": len(raw_subs),
        "total_deduped": len(all_subs),
        "total_probed": len(probe_results),
        "alive": len(alive),
        "dead": len(dead),
        "takeover_candidates": len(takeover_candidates),
        "sources": sources_used or {},
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    return out_dir


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run(target: str, program: str, use_apis: list[str],
        wordlist: Optional[str], threads: int, verbose: bool,
        skip_probe: bool, skip_takeover: bool) -> None:

    # Fix 7: path traversal guard
    if ".." in program or "/" in program or "\\" in program:
        raise ValueError(f"Invalid program name: {program}")

    print(f"\n[*] Target  : {target}")
    print(f"[*] Program : {program}")
    print(f"[*] APIs    : {', '.join(use_apis) if use_apis else 'none'}")
    print(f"[*] Wordlist: {wordlist or 'none'}")

    collector = SubdomainCollector(target, program, use_apis, wordlist, verbose)
    raw_subs: set[str] = set()
    sources_used: dict[str, int] = {}

    # ---- Phase 1: COLLECT ----
    print("\n[Phase 1] Collecting subdomains ...")

    if "crtsh" in use_apis:
        subs = collector.from_crtsh(); sources_used["crtsh"] = len(subs); raw_subs |= subs
    if "otx" in use_apis:
        subs = collector.from_otx(); sources_used["otx"] = len(subs); raw_subs |= subs
    if "bufferover" in use_apis:
        subs = collector.from_bufferover(); sources_used["bufferover"] = len(subs); raw_subs |= subs
    if "urlscan" in use_apis:
        subs = collector.from_urlscan(); sources_used["urlscan"] = len(subs); raw_subs |= subs
    if "rdap" in use_apis:
        subs = collector.from_rdap(); sources_used["rdap"] = len(subs); raw_subs |= subs
    if "whoxy" in use_apis:
        subs = collector.from_whoxy(); sources_used["whoxy"] = len(subs); raw_subs |= subs
    if "wayback" in use_apis:
        subs = collector.from_wayback(); sources_used["wayback"] = len(subs); raw_subs |= subs

    if wordlist:
        subs = collector.from_wordlist(); sources_used["wordlist"] = len(subs); raw_subs |= subs

    # Always try local sources
    subs = collector.from_js_files(); sources_used["js_files"] = len(subs); raw_subs |= subs
    subs = collector.from_local_urls(); sources_used["local_urls"] = len(subs); raw_subs |= subs

    # Mutations on what we've found so far
    raw_subs |= collector.from_mutations(raw_subs)

    # Filter: keep only subdomains of target (no wildcards, no IPs)
    ip_re = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    raw_subs = {
        s for s in raw_subs
        if (s.endswith(f".{target}") or s == target)
        and not ip_re.match(s)
        and " " not in s
        and s  # not empty
    }

    print(f"  [+] Raw collected : {len(raw_subs)}")

    # ---- Phase 2: AGGREGATE & DEDUPE ----
    print("\n[Phase 2] Deduplicating ...")
    all_subs = dedup_with_anew(raw_subs)
    all_subs = normalize_with_uro(all_subs)
    print(f"  [+] Deduped       : {len(all_subs)}")

    # ---- Phase 3: PROBE ----
    probe_results: list[ProbeResult] = []
    if not skip_probe and all_subs:
        print(f"\n[Phase 3] Probing {len(all_subs)} subdomains (threads={threads}) ...")
        import warnings
        import urllib3
        urllib3.disable_warnings()
        probe_results = asyncio.run(probe_all(all_subs, threads=threads))
        alive_count = sum(1 for r in probe_results if r.status in range(200, 400))
        print(f"  [+] Alive         : {alive_count}")
        print(f"  [+] Dead/No-resp  : {len(probe_results) - alive_count}")
    else:
        print("\n[Phase 3] Probe skipped.")
        # Create stub results for all subs so output files are populated
        probe_results = [
            ProbeResult(s, f"https://{s}", 0, "", 0, "", "", "skipped")
            for s in all_subs
        ]

    # ---- Phase 4: ORGANIZE ----
    print("\n[Phase 4] Writing output files ...")
    out_dir = write_outputs(program, target, raw_subs, all_subs,
                            probe_results, [], sources_used)
    print(f"  [+] Output dir    : {out_dir}")

    # ---- Phase 5: TAKEOVER CHECK ----
    takeover_candidates: list[dict] = []
    if not skip_takeover:
        print("\n[Phase 5] Checking takeover candidates ...")
        dead_results = [r for r in probe_results
                        if r.status not in range(200, 400)]
        takeover_candidates = asyncio.run(
            _run_takeover_checks(dead_results, threads)
        )
        for c in takeover_candidates:
            print(f"  [!] TAKEOVER CANDIDATE: {c['subdomain']} [{c['service']}]")
        print(f"  [+] Candidates    : {len(takeover_candidates)}")
    else:
        print("\n[Phase 5] Takeover check skipped.")

    # Re-write outputs with takeover data
    write_outputs(program, target, raw_subs, all_subs,
                  probe_results, takeover_candidates, sources_used)

    # ---- Summary ----
    print("\n" + "="*60)
    print(f"  Target    : {target}")
    print(f"  Raw subs  : {len(raw_subs)}")
    print(f"  Deduped   : {len(all_subs)}")
    print(f"  Alive     : {sum(1 for r in probe_results if r.status in range(200,400))}")
    print(f"  Takeovers : {len(takeover_candidates)}")
    print(f"  Output    : {out_dir}")
    print("="*60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Subdomain enumeration agent — multi-source with takeover detection"
    )
    p.add_argument("--target",   required=True,
                   help="Root domain (e.g. example.com)")
    p.add_argument("--program",  required=True,
                   help="Program slug for output directory")
    p.add_argument("--wordlist", default=None,
                   help="Path to wordlist for brute-force")
    p.add_argument("--use-apis",
                   default="crtsh,otx,bufferover,urlscan,rdap,wayback",
                   help="Comma-separated APIs: crtsh,otx,bufferover,urlscan,rdap,whoxy,wayback")
    p.add_argument("--threads",  type=int, default=20,
                   help="Concurrent probe threads (default: 20)")
    p.add_argument("--skip-probe",    action="store_true",
                   help="Skip HTTP probing")
    p.add_argument("--skip-takeover", action="store_true",
                   help="Skip takeover fingerprinting")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose output")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    use_apis = [a.strip().lower() for a in args.use_apis.split(",") if a.strip()]
    run(
        target=args.target.lower().strip(),
        program=args.program,
        use_apis=use_apis,
        wordlist=args.wordlist,
        threads=args.threads,
        verbose=args.verbose,
        skip_probe=args.skip_probe,
        skip_takeover=args.skip_takeover,
    )
