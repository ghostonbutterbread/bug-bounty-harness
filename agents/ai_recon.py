"""
AI-Powered Recon Agent — Uses Perplexity + Tavily for intelligent, targeted reconnaissance.

Unlike blind Google dorking, this agent:
1. Asks Perplexity what it knows about the target (tech stack, subdomains, forgotten endpoints)
2. Gets Perplexity to generate TARGETED dorks based on that intelligence
3. Executes those dorks via Tavily (no CAPTCHA/rate limit on our end)
4. Validates findings against scope before reporting

Research source: Bug bounty researchers using Perplexity for recon
(Saeed @ medium, Aug 2025 — "How I Use Perplexity for Bug Bounty Recon")

Usage:
    from agents.ai_recon import AIReconAgent
    agent = AIReconAgent("superdrug", ["superdrug.com", "api.superdrug.com"])
    findings = agent.run()
"""

import sys
sys.path.insert(0, "/home/ryushe/workspace/bug_bounty_harness")

import json
import os
import time
import re
import httpx
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field


try:
    from scope_validator import ScopeValidator
except ImportError:
    ScopeValidator = None
try:
    from rate_limiter import RateLimiter
except ImportError:
    RateLimiter = None

TAVILY_API_KEY = os.getenv("TAVILY_KEY", "")

# Perplexity API (sonar model — cheap and fast)
PERPLEXITY_API_KEY = os.getenv("PERPLEXITY_API_KEY", "")
PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"


@dataclass
class ReconFinding:
    url: str
    source: str          # "perplexity" | "tavily" | "dork"
    finding_type: str     # "admin_panel" | "sensitive_file" | "api_doc" | "dev_endpoint" | etc.
    target_domain: str
    dork_used: str = ""
    snippet: str = ""
    confidence: float = 0.5  # 0-1


@dataclass
class ReconReport:
    findings: list = field(default_factory=list)
    target: str = ""
    domains: list = field(default_factory=list)
    perplexity_intel: str = ""
    generated_dorks: list = field(default_factory=list)
    tavily_results: int = 0
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "domains": self.domains,
            "perplexity_intel": self.perplexity_intel,
            "generated_dorks": self.generated_dorks,
            "tavily_results": self.tavily_results,
            "findings": [
                {
                    "url": f.url,
                    "source": f.source,
                    "type": f.finding_type,
                    "domain": f.target_domain,
                    "dork": f.dork_used,
                    "snippet": f.snippet,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
            "errors": self.errors,
        }


class AIReconAgent:
    """
    AI-powered recon using Perplexity for intelligence + Tavily for search.

    Workflow:
    1. Ask Perplexity what it knows about the target (tech, subdomains, history)
    2. Get Perplexity to generate targeted dorks based on its knowledge
    3. Execute dorks via Tavily (avoids CAPTCHA/rate limits)
    4. Validate all findings are in-scope
    5. Return prioritized findings
    """

    def __init__(self, program: str, domains: list[str], results_dir: str = None):
        self.program = program
        self.domains = domains
        self.primary_domain = domains[0] if domains else ""

        if results_dir:
            self.results_dir = Path(results_dir)
        else:
            self.results_dir = Path.home() / "Shared" / "bounty_recon" / program / "ghost" / "ai_recon"
        self.results_dir.mkdir(parents=True, exist_ok=True)

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

    def run(self, max_dorks: int = 20) -> ReconReport:
        """Run the full AI recon workflow."""
        report = ReconReport(
            target=self.primary_domain,
            domains=self.domains,
        )

        print(f"🎯 AI Recon: {self.program} ({', '.join(self.domains)})")

        # Step 1: Ask Perplexity what it knows
        intel = self._ask_perplexity()
        report.perplexity_intel = intel
        print(f"  ✅ Perplexity intel collected")

        # Step 2: Generate targeted dorks from intel
        dorks = self._generate_dorks(intel)
        report.generated_dorks = dorks
        print(f"  ✅ Generated {len(dorks)} targeted dorks")

        # Step 3: Execute dorks via Tavily
        findings = self._execute_dorks(dorks, max_dorks)
        report.findings = findings
        report.tavily_results = len(findings)
        print(f"  ✅ Tavily returned {len(findings)} findings")

        # Step 4: Save results
        self._save_report(report)
        return report

    def _ask_perplexity(self) -> str:
        """Ask Perplexity what it knows about the target."""
        if not PERPLEXITY_API_KEY:
            return self._fallback_perplexity_intel()

        scope_str = "\n".join([f"- {d}" for d in self.domains])

        prompt = f"""You are a bug bounty reconnaissance assistant. I have permission to perform passive recon on these in-scope assets:

Scope:
{scope_str}

Please provide:

1. **What you know about this target** — tech stack, common subdomains, known APIs, any public code or documentation
2. **Forgotten or lesser-known endpoints** — based on historical data, what endpoints may have existed?
3. **Dev/staging patterns** — what dev URLs or internal tools might be exposed?
4. **Specific dork suggestions** — give me 10-15 Google/Brave dorks that would find exposed panels, APIs, or sensitive files SPECIFICALLY for this target. Include both site: and inurl: operators where relevant.

Be specific. Generic advice is not useful. I need dorks that would only work for this target.

Format your dork suggestions as a simple list, one dork per line, starting with "- ". Example:
- site:example.com inurl:api/v2
- site:example.com filetype:env
"""

        try:
            import httpx
            resp = httpx.post(
                PERPLEXITY_API_URL,
                headers={
                    "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "sonar",
                    "messages": [
                        {"role": "system", "content": "Be concise and technical. Focus on bug bounty recon."},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 2000,
                    "temperature": 0.3,
                },
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"  ⚠️  Perplexity error: {e}")

        return self._fallback_perplexity_intel()

    def _fallback_perplexity_intel(self) -> str:
        """Fallback when no Perplexity API key."""
        return f"""Target: {self.primary_domain}
Scope: {', '.join(self.domains)}

No Perplexity API key — using fallback intel.
Try running with PERPLEXITY_API_KEY set for full AI-powered recon.
"""

    def _generate_dorks(self, intel: str) -> list[str]:
        """
        Parse Perplexity's response to extract dork queries.
        Also generate our own based on common patterns.
        """
        dorks = []

        # Extract dorks from Perplexity's response
        for line in intel.split("\n"):
            line = line.strip()
            if line.startswith("-"):
                dork = line[1:].strip()
                # Clean up markdown formatting
                dork = re.sub(r'^[`"\']|[`"\']$', '', dork)
                if dork and len(dork) > 5:
                    dorks.append(dork)

        # Add domain-specific variations of our standard dorks
        for domain in self.domains:
            dorks.extend([
                f"site:{domain} inurl:admin",
                f"site:{domain} inurl:api",
                f"site:{domain} inurl:swagger",
                f"site:{domain} inurl:actuator",
                f"site:{domain} inurl:.env",
                f"site:{domain} filetype:env",
                f"site:{domain} inurl:login",
                f"site:{domain} inurl:dashboard",
                f"site:{domain} inurl:debug",
                f"site:{domain} filetype:sql",
                f"site:{domain} filetype:bak",
                f"site:{domain} inurl:jenkins",
                f"site:{domain} inurl:graphiql",
                f"site:{domain} inurl:health",
            ])

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for d in dorks:
            key = d.lower().strip()
            if key and key not in seen:
                seen.add(key)
                unique.append(d)

        return unique

    def _execute_dorks(self, dorks: list[str], max_dorks: int = 20) -> list[ReconFinding]:
        """Execute dorks via Tavily Search API."""
        if not TAVILY_API_KEY:
            return self._execute_dorks_via_perplexity(dorks[:max_dorks])

        findings = []
        headers = {"Authorization": f"Bearer {TAVILY_API_KEY}", "Content-Type": "application/json"}

        for dork in dorks[:max_dorks]:
            # Check if dork is for our domains
            if not any(d in dork.lower() for d in self.domains):
                continue

            try:
                if self.limiter:
                    self.limiter.wait()
                resp = httpx.post(
                    "https://api.tavily.com/search",
                    headers=headers,
                    json={"query": dork, "max_results": 5, "include_answer": False},
                    timeout=15,
                )
                if resp.status_code != 200:
                    continue

                data = resp.json()
                for result in data.get("results", []):
                    url = result.get("url", "")
                    # Verify it's from our domains
                    if not any(d in url.lower() for d in self.domains):
                        continue
                    if not self.is_in_scope(url):
                        print(f"  [SKIP] Out of scope: {url}")
                        continue

                    # Classify the finding
                    finding_type = self._classify_finding(url, dork)

                    findings.append(ReconFinding(
                        url=url,
                        source="tavily",
                        finding_type=finding_type,
                        target_domain=self._which_domain(url),
                        dork_used=dork,
                        snippet=result.get("content", "")[:200],
                        confidence=self._confidence(url, dork),
                    ))

                time.sleep(1)  # Be respectful

            except Exception as e:
                print(f"  ⚠️  Tavily error on '{dork[:40]}...': {e}")
                time.sleep(2)

        # Deduplicate by URL
        seen_urls = set()
        unique = []
        for f in findings:
            if f.url not in seen_urls:
                seen_urls.add(f.url)
                unique.append(f)

        return unique

    def _execute_dorks_via_perplexity(self, dorks: list[str]) -> list[ReconFinding]:
        """Fallback: use Perplexity to execute dorks directly."""
        if not PERPLEXITY_API_KEY:
            return []

        findings = []
        prompt = f"""For each of these dork queries, tell me if you find any relevant URLs from these domains: {', '.join(self.domains)}.

Dorks to check:
{chr(10).join(['- ' + d for d in dorks[:10]])}

For each dork, if you find URLs in scope, list them with the domain they belong to.
Format:
DORK: [the dork]
URL: [the URL]
DOMAIN: [which domain]

If no results, say NONE."""

        try:
            import httpx
            resp = httpx.post(
                PERPLEXITY_API_URL,
                headers={"Authorization": f"Bearer {PERPLEXITY_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "sonar",
                    "messages": [
                        {"role": "system", "content": "You are a recon assistant. Return URLs found by dork queries. Be concise."},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 1500,
                    "temperature": 0.2,
                },
                timeout=30,
            )
            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"]["content"]
                # Parse URLs from response
                for line in content.split("\n"):
                    if line.startswith("URL:"):
                        url = line[4:].strip()
                        if any(d in url for d in self.domains):
                            findings.append(ReconFinding(
                                url=url,
                                source="perplexity",
                                finding_type=self._classify_finding(url, ""),
                                target_domain=self._which_domain(url),
                                snippet=content[:200],
                                confidence=0.6,
                            ))
        except Exception as e:
            print(f"  ⚠️  Perplexity fallback error: {e}")

        return findings

    def _classify_finding(self, url: str, dork: str) -> str:
        """Classify what type of endpoint this is."""
        url_lower = url.lower()
        dork_lower = dork.lower()

        if any(x in url_lower for x in ["admin", "login", "auth", "signin", "cpanel", "wp-admin"]):
            return "admin_panel"
        elif any(x in url_lower for x in [".env", "filetype:env", "filetype:sql", "filetype:bak", "filetype:cfg"]):
            return "sensitive_file"
        elif any(x in url_lower for x in ["swagger", "api-docs", "/api/v", "openapi", "api-doc"]):
            return "api_doc"
        elif any(x in url_lower for x in ["debug", "test", "phpinfo", "actuator", "/debug"]):
            return "debug_exposed"
        elif any(x in url_lower for x in [".git", "/.git", "composer.json", "package.json"]):
            return "source_code"
        elif any(x in url_lower for x in ["jenkins", "grafana", "kibana", "jira", "gitlab"]):
            return "internal_app"
        elif any(x in url_lower for x in ["s3.", "blob.core.windows", "storage.googleapis"]):
            return "cloud_storage"
        elif any(x in url_lower for x in ["swagger", "api/v", "restapi", "graphql"]):
            return "api_endpoint"
        else:
            return "other"

    def _which_domain(self, url: str) -> str:
        """Which of our domains does this URL belong to?"""
        for d in self.domains:
            if d in url.lower():
                return d
        return self.primary_domain

    def _confidence(self, url: str, dork: str) -> float:
        """Score confidence that this is a real, in-scope finding."""
        url_lower = url.lower()
        dork_lower = dork.lower()
        score = 0.5

        # Higher confidence signals
        if "admin" in url_lower and ("login" in url_lower or "auth" in url_lower):
            score = 0.9
        elif ".env" in url_lower or "filetype:env" in dork_lower:
            score = 0.95
        elif "swagger" in url_lower or "openapi" in url_lower:
            score = 0.85
        elif "jenkins" in url_lower or "grafana" in url_lower:
            score = 0.9
        elif "debug" in url_lower or "actuator" in url_lower:
            score = 0.85
        elif "wp-admin" in url_lower or "/admin/" in url_lower:
            score = 0.9
        elif "api/v" in url_lower or "restapi" in url_lower:
            score = 0.8

        return min(score, 1.0)

    def _save_report(self, report: ReconReport) -> None:
        """Save the recon report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        json_file = self.results_dir / f"ai_recon_{timestamp}.json"
        md_file = self.results_dir / f"ai_recon_{timestamp}.md"

        # Save JSON
        with open(json_file, "w") as f:
            json.dump(report.to_dict(), f, indent=2)

        # Save Markdown summary
        lines = [
            f"# AI Recon Report — {self.program}",
            f"Generated: {timestamp}",
            f"Domains: {', '.join(self.domains)}",
            f"",
            f"## Perplexity Intel",
            f"",
            f"```",
            f"{report.perplexity_intel[:3000]}",
            f"```",
            f"",
            f"## Generated Dorks ({len(report.generated_dorks)})",
            f"",
        ]
        for d in report.generated_dorks[:30]:
            lines.append(f"- `{d}`")

        lines.extend([
            f"",
            f"## Findings ({len(report.findings)})",
            f"",
            f"| URL | Type | Domain | Confidence | Source |",
            f"|-----|------|--------|------------|--------|",
        ])
        for f in sorted(report.findings, key=lambda x: -x.confidence):
            lines.append(f"| {f.url} | {f.finding_type} | {f.target_domain} | {f.confidence:.0%} | {f.source} |")

        with open(md_file, "w") as f:
            f.write("\n".join(lines))

        print(f"  💾 Report saved: {json_file}")
        print(f"  💾 Summary: {md_file}")
