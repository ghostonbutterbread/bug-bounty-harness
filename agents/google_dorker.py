"""
Google Dorking Agent — Search for exposed endpoints, admin panels, and sensitive files.

Usage:
    from agents.google_dorker import GoogleDorker
    dorker = GoogleDorker("superdrug", ["superdrug.com", "api.superdrug.com"])
    results = dorker.run(max_dorks=50)

Or via CLI:
    python3 -c "from agents.google_dorker import GoogleDorker; GoogleDorker('superdrug', ['superdrug.com']).run()"
"""

import sys
sys.path.insert(0, "/home/ryushe/workspace/bug_bounty_harness")

import json
import time
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_plus

# ─── Google Dork Payloads ───────────────────────────────────────────────────────

DORK_CATEGORIES = {
    "admin_panels": {
        "description": "Admin and control panel discovery",
        "dorks": [
            'site:{domain} inurl:admin',
            'site:{domain} inurl:administrator',
            'site:{domain} inurl:"admin/login"',
            'site:{domain} inurl:"adminpanel"',
            'site:{domain} inurl:"backend"',
            'site:{domain} inurl:"controlpanel"',
            'site:{domain} inurl:"dashboard"',
            'site:{domain} inurl:"manage"',
            'site:{domain} inurl:"management"',
            'site:{domain} inurl:"panel"',
            'site:{domain} inurl:"wp-admin"',
            'site:{domain} inurl:"cpanel"',
            'site:{domain} inurl:"plesk"',
            'site:{domain} "admin" "login"',
            'site:{domain} "login" "admin"',
            'site:{domain} inurl:login inurl:admin',
        ],
    },
    "sensitive_files": {
        "description": "Sensitive file discovery (env, sql, config)",
        "dorks": [
            'site:{domain} filetype:env',
            'site:{domain} filetype:env "AWS_ACCESS_KEY"',
            'site:{domain} filetype:env "DB_PASSWORD"',
            'site:{domain} filetype:env "SECRET_KEY"',
            'site:{domain} filetype:sql',
            'site:{domain} filetype:sql "INSERT INTO"',
            'site:{domain} filetype:cfg',
            'site:{domain} filetype:conf',
            'site:{domain} filetype:config',
            'site:{domain} filetype:ini',
            'site:{domain} filetype:json "password"',
            'site:{domain} filetype:xml "password"',
            'site:{domain} filetype:yml "password"',
            'site:{domain} filetype:yaml "password"',
            'site:{domain} filetype:log',
            'site:{domain} filetype:txt "password"',
            'site:{domain} filetype:bak',
            'site:{domain} filetype:backup',
            'site:{domain} filetype:old',
            'site:{domain} filetype:swp',
            'site:{domain} filetype:tar.gz',
            'site:{domain} filetype:zip "database"',
            'site:{domain} "index of" "database"',
            'site:{domain} "index of" "backup"',
            'site:{domain} "index of" "config"',
        ],
    },
    "api_documentation": {
        "description": "API docs, Swagger, OpenAPI endpoints",
        "dorks": [
            'site:{domain} inurl:api',
            'site:{domain} inurl:swagger',
            'site:{domain} inurl:"api-docs"',
            'site:{domain} inurl:"api/v"',
            'site:{domain} inurl:"restapi"',
            'site:{domain} "openapi" filetype:json',
            'site:{domain} "swagger" filetype:json',
            'site:{domain} "api" "documentation"',
            'site:{domain} "developer" "api"',
            'site:{domain} inurl:/v1/',
            'site:{domain} inurl:/v2/',
            'site:{domain} inurl:/v3/',
            'site:{domain} inurl:/api/v1/',
            'site:{domain} inurl:/api/v2/',
        ],
    },
    "debug_exposed": {
        "description": "Debug and diagnostic pages",
        "dorks": [
            'site:{domain} inurl:debug',
            'site:{domain} inurl:debug=1',
            'site:{domain} inurl:"?debug"',
            'site:{domain} inurl:test',
            'site:{domain} inurl:"phpinfo"',
            'site:{domain} "phpinfo()"',
            'site:{domain} inurl:health',
            'site:{domain} inurl:status',
            'site:{domain} inurl:metrics',
            'site:{domain} inurl:info',
            'site:{domain} inurl:ping',
            'site:{domain} inurl:actuator',
            'site:{domain} inurl:env',
            'site:{domain} inurl:.env',
            'site:{domain} inurl:console',
            'site:{domain} inurl:graphiql',
            'site:{domain} inurl:graphql',
            'site:{domain} inurl:"debug" "error"',
        ],
    },
    "internal_apps": {
        "description": "Internal/hidden applications and portals",
        "dorks": [
            'site:{domain} inurl:internal',
            'site:{domain} inurl:intranet',
            'site:{domain} inurl:"private"',
            'site:{domain} inurl:portal',
            'site:{domain} inurl:citrix',
            'site:{domain} inurl:"vpn"',
            'site:{domain} inurl:"webmail"',
            'site:{domain} inurl:"owa"',
            'site:{domain} inurl:"exchange"',
            'site:{domain} inurl:jira',
            'site:{domain} inurl:confluence',
            'site:{domain} inurl:gitlab',
            'site:{domain} inurl:jenkins',
            'site:{domain} inurl:grafana',
            'site:{domain} inurl:prometheus',
            'site:{domain} inurl:kibana',
            'site:{domain} inurl:elastic',
        ],
    },
    "source_code": {
        "description": "Exposed source code and git repositories",
        "dorks": [
            'site:{domain} inurl:.git',
            'site:{domain} inurl:.git/config',
            'site:{domain} inurl:.git/HEAD',
            'site:{domain} inurl:.svn',
            'site:{domain} inurl:.hg',
            'site:{domain} inurl:.env',
            'site:{domain} inurl:composer.json',
            'site:{domain} inurl:package.json',
            'site:{domain} inurl:"credentials" filetype:json',
            'site:{domain} "Dumped from"',
        ],
    },
    "cloud_storage": {
        "description": "Cloud storage buckets and CDN misconfigs",
        "dorks": [
            'site:{domain} inurl:s3',
            'site:{domain} inurl:"s3.amazonaws.com"',
            'site:{domain} inurl:blob.core.windows.net',
            'site:{domain} inurl:storage.googleapis.com',
            'site:{domain} inurl:"cloudfront"',
            'site:{domain} filetype:xml "x-amz',
            'site:{domain} filetype:xml "Bucket"',
        ],
    },
}

# Google search URL builder
GOOGLE_SEARCH_URL = "https://www.google.com/search?q={query}&num=10&hl=en"


class GoogleDorker:
    """
    Run Google dorks against a target domain and filter for real matches.

    Results are saved to ~/Shared/bounty_recon/{program}/ghost/dorks/
    """

    def __init__(self, program: str, domains: list[str], results_dir: str = None):
        self.program = program
        self.domains = domains
        if results_dir:
            self.results_dir = Path(results_dir)
        else:
            self.results_dir = Path.home() / "Shared" / "bounty_recon" / program / "ghost" / "dorks"
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def run(self, max_dorks: int = 50, delay: float = 3.0) -> dict:
        """
        Run dorks against all domains. Returns summary dict.

        Args:
            max_dorks: Max dorks to run per domain (None = all)
            delay: Seconds between Google searches (be respectful)

        Returns:
            dict with keys: total_searches, interesting_results, by_category
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        all_results = []
        stats = {
            "total_searches": 0,
            "interesting_results": 0,
            "domains": self.domains,
            "started": timestamp,
            "by_category": {},
        }

        for domain in self.domains:
            print(f"🔍 Dorking: {domain}")

            for category, info in DORK_CATEGORIES.items():
                if max_dorks and stats["total_searches"] >= max_dorks:
                    break

                dorks = info["dorks"]
                for dork_template in dorks:
                    if max_dorks and stats["total_searches"] >= max_dorks:
                        break

                    query = dork_template.format(domain=domain)
                    stats["total_searches"] += 1

                    try:
                        results = self._search_google(query)
                        interesting = self._filter_results(results, domain)

                        if interesting:
                            for r in interesting:
                                r["dork"] = query
                                r["category"] = category
                                r["domain"] = domain
                                r["found_at"] = datetime.now(timezone.utc).isoformat()

                            all_results.extend(interesting)
                            stats["interesting_results"] += len(interesting)

                            if category not in stats["by_category"]:
                                stats["by_category"][category] = {"searches": 0, "hits": 0}
                            stats["by_category"][category]["hits"] += len(interesting)

                            print(f"   ✅ [{category}] {len(interesting)} hits for: {dork_template[:60]}")

                        time.sleep(delay)

                    except Exception as e:
                        print(f"   ⚠️  Error on '{query[:40]}...': {e}")
                        time.sleep(delay * 2)  # back off on error

                    if category not in stats["by_category"]:
                        stats["by_category"][category] = {"searches": 0, "hits": 0}
                    stats["by_category"][category]["searches"] += 1

        # Save results
        results_file = self.results_dir / f"dork_results_{timestamp}.json"
        findings_file = self.results_dir / f"dork_findings_{timestamp}.txt"

        with open(results_file, "w") as f:
            json.dump({
                "program": self.program,
                "domains": self.domains,
                "stats": stats,
                "results": all_results,
            }, f, indent=2)

        self._write_findings_summary(findings_file, all_results, stats)

        stats["results_file"] = str(results_file)
        stats["findings_file"] = str(findings_file)

        return stats

    def _search_google(self, query: str) -> list[dict]:
        """
        Search Google/Brave and return structured results.
        Uses Brave Search API (respects privacy), falls back to direct Google HTML fetch.
        """
        import os
        api_key = os.getenv("BRAVE_API_KEY") or os.getenv("WEB_SEARCH_API_KEY")

        if api_key:
            # Use Brave Search API — best for this use case
            try:
                import httpx
                headers = {"Accept": "application/json", "X-Subscription-Token": api_key}
                params = {"q": query, "count": 10}
                resp = httpx.get(
                    "https://api.search.brave.com/res/v1/web/search",
                    headers=headers, params=params, timeout=15
                )
                if resp.status_code == 200:
                    data = resp.json()
                    results = []
                    for item in data.get("web", {}).get("results", []):
                        results.append({
                            "title": item.get("title", ""),
                            "url": item.get("url", ""),
                            "snippet": item.get("description", ""),
                        })
                    return results
            except Exception:
                pass

        # Fallback: direct HTTP with Brave SERP or Google
        try:
            import httpx
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            }
            # Use DuckDuckGo HTML (less aggressive blocking than Google)
            url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}&kl=en-us"
            resp = httpx.get(url, headers=headers, timeout=15)
            return self._parse_ddg_html(resp.text)
        except Exception:
            return []

    def _parse_ddg_html(self, html: str) -> list[dict]:
        """Parse DuckDuckGo HTML results — extracts real URLs from uddg redirect links."""
        import re
        from urllib.parse import unquote

        # Normalize HTML entities
        html = html.replace('&amp;', '&').replace('&quot;', '"').replace('&#x27;', "'").replace('&apos;', "'")

        results = []
        url_data = {}

        # Pattern 1: <a class="result__a" href="//duckduckgo.com/l/?uddg=URL">Title</a>
        link_pattern = re.compile(
            r'<a class="result__a"[^>]+href="//duckduckgo\.com/l/\?uddg=([^"]+)"[^>]*>([^<]+)</a>',
            re.IGNORECASE
        )

        # Pattern 2: <a class="result__snippet" ...>Snippet text</a>
        # (the snippet follows the title link for the same URL)
        snippet_pattern = re.compile(
            r'(<a class="result__a"[^>]+href="//duckduckgo\.com/l/\?uddg=([^"]+)"[^>]*>[^<]+</a>'
            r'.*?<a class="result__snippet"[^>]*>)([^<]+)</a>',
            re.DOTALL | re.IGNORECASE
        )

        # Extract title links
        for m in link_pattern.finditer(html):
            raw_url = m.group(1)
            title = re.sub(r'<[^>]+>', '', m.group(2)).strip()
            try:
                real_url = unquote(raw_url)
                if real_url.startswith('http'):
                    url_data[real_url] = {"title": title, "snippet": ""}
            except Exception:
                pass

        # Extract snippets
        for m in snippet_pattern.finditer(html):
            raw_url = m.group(2)
            snippet = re.sub(r'<[^>]+>', '', m.group(3)).strip()
            try:
                real_url = unquote(raw_url)
                if real_url in url_data:
                    url_data[real_url]["snippet"] = snippet
            except Exception:
                pass

        # Fallback: just get any URLs from uddg params
        if not url_data:
            all_links = re.findall(r'href="//duckduckgo\.com/l/\?uddg=([^"]+)"', html)
            for raw_url in all_links[:10]:
                try:
                    real_url = unquote(raw_url)
                    if real_url.startswith('http') and real_url not in url_data:
                        url_data[real_url] = {"title": "DDG Result", "snippet": ""}
                except Exception:
                    pass

        for url, data in url_data.items():
            results.append({
                "title": data["title"],
                "url": url,
                "snippet": data["snippet"],
            })

        return results[:10]

    def _parse_google_html(self, html: str) -> list[dict]:
        """Parse Google search results from HTML (legacy fallback)."""
        results = []
        pattern = re.compile(r'<a href="([^"]+)"[^>]*><span[^>]*>([^<]+)</span></a>')
        for match in pattern.finditer(html):
            url = match.group(1)
            if url and not url.startswith("https://www.google") and not url.startswith("/"):
                results.append({"title": match.group(2).strip(), "url": url, "snippet": ""})
        return results[:10]

    def _filter_results(self, results: list[dict], domain: str) -> list[dict]:
        """
        Filter Google results to only those actually belonging to the target domain.
        This removes junk results from aggregators, cached copies, etc.
        """
        if not results:
            return []

        interesting = []
        for r in results:
            url = r.get("url", "").lower()
            title = r.get("title", "").lower()
            snippet = r.get("snippet", "").lower()

            # Must actually be from the target domain
            if not any(d in url for d in self.domains):
                continue

            # Filter out Google cache, translate, etc.
            skip_patterns = [
                "google.com/search", "google.com/url", "googleusercontent.com",
                "gstatic.com", "doubleclick.net", "google.co.uk",
                "cache:", "webcache:",
            ]
            if any(p in url for p in skip_patterns):
                continue

            # Filter out known non-interesting results
            skip_titles = ["privacy policy", "terms of service", "cookie policy",
                           "accessibility", "sitemap"]
            if any(t in title for t in skip_titles):
                continue

            interesting.append(r)

        return interesting

    def _write_findings_summary(self, path: Path, results: list[dict], stats: dict) -> None:
        """Write a human-readable findings summary."""
        lines = [
            f"# Google Dork Results — {self.program}",
            f"Generated: {stats['started']}",
            f"Domains: {', '.join(self.domains)}",
            f"Searches: {stats['total_searches']}",
            f"Interesting results: {stats['interesting_results']}",
            "",
        ]

        # Group by category
        by_cat = {}
        for r in results:
            cat = r.get("category", "unknown")
            if cat not in by_cat:
                by_cat[cat] = []
            by_cat[cat].append(r)

        for cat, items in by_cat.items():
            lines.append(f"\n## {cat.replace('_', ' ').title()} ({len(items)} hits)")
            lines.append("")
            for item in items:
                lines.append(f"- [{item['domain']}] {item['url']}")
                lines.append(f"  Dork: `{item['dork']}`")
                if item.get('snippet'):
                    lines.append(f"  Snippet: {item['snippet'][:100]}...")
                lines.append("")

        path.write_text("\n".join(lines))
