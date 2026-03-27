"""
Threat Map Agent — Generates a comprehensive threat landscape report for a bug bounty program.

Uses Claude CLI to analyze:
1. All existing findings and recon data from ~/Shared/bounty_recon/{program}/
2. Public bug bounty reports for the same program
3. Common vulnerability patterns in the target's tech stack

Output: A structured markdown report covering:
- Common vulnerability types and where they occur
- Attack surface analysis
- Patterns that worked historically
- Recommendations for where to focus hunting

Usage:
    python3 threat_map.py superdrug
    python3 threat_map.py --program superdrug --claude
"""

import sys
sys.path.insert(0, "/home/ryushe/workspace/bug_bounty_harness")

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


BASE_DIR = Path.home() / "Shared" / "bounty_recon"
TAVILY_KEY = os.getenv("TAVILY_KEY", "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")


def load_program_data(program: str) -> dict:
    """Load all existing findings, recon data, and scope from the program directory."""
    program_dir = BASE_DIR / program
    if not program_dir.exists():
        return {"error": f"Program directory not found: {program_dir}"}

    data = {
        "program": program,
        "program_dir": str(program_dir),
        "findings": [],
        "recon": {},
        "scope": {},
        "notes": [],
        "urls_analyzed": [],
    }

    # Load all JSON findings
    findings_file = program_dir / "ghost" / "findings_2026-03-21_1425.json"
    if findings_file.exists():
        with open(findings_file) as f:
            data["findings"].extend(json.load(f))

    owasp_file = program_dir / "ghost" / "owasp_findings_2026-03-21_1541.json"
    if owasp_file.exists():
        with open(owasp_file) as f:
            data["findings"].extend(json.load(f))

    # Load curated targets
    curated = program_dir / "ghost" / "curated_targets_2026-03-17.md"
    if curated.exists():
        data["recon"]["curated_targets"] = curated.read_text()[:5000]

    # Load latest dork results
    dork_dir = program_dir / "ghost" / "dorks"
    if dork_dir.exists():
        dork_files = sorted(dork_dir.glob("dork_results_*.json"))
        if dork_files:
            with open(dork_files[-1]) as f:
                dork_data = json.load(f)
                data["recon"]["dorking"] = {
                    "total_dorks": dork_data.get("total_dorks", 0),
                    "total_findings": dork_data.get("interesting_results", 0),
                    "findings": dork_data.get("results", [])[:20],
                }

    # Load scope
    scope_file = program_dir / "scope" / "scope.md"
    if scope_file.exists():
        data["scope"]["markdown"] = scope_file.read_text()[:3000]
    scope_txt = program_dir / "scope"
    if scope_txt.exists():
        for f in scope_txt.glob("*.txt"):
            data["scope"][f.name] = f.read_text()[:1000]

    # Load credentials dir info
    creds_dir = program_dir / "credentials"
    if creds_dir.exists():
        data["credentials"] = {
            "files": [f.name for f in creds_dir.glob("*") if f.is_file()]
        }

    return data


def fetch_public_reports(program: str, domains: list[str]) -> dict:
    """
    Search for public bug bounty reports for this program using Tavily.
    Returns HackerOne, Bugcrowd, Intigriti public writeups.
    """
    import httpx

    reports = {"hackerone": [], "bugcrowd": [], "intigriti": [], "general": []}

    queries = [
        f'bug bounty {program} site:hackerone.com report',
        f'bug bounty {program} site:bugcrowd.com',
        f'bug bounty {program} site:intigriti.com',
        f'{program} vulnerability writeup site:medium.com OR site:dev.to',
    ]

    headers = {"Authorization": f"Bearer {TAVILY_KEY}", "Content-Type": "application/json"}

    for query in queries[:4]:
        try:
            resp = httpx.post(
                "https://api.tavily.com/search",
                headers=headers,
                json={"query": query, "max_results": 5, "include_answer": True},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                source = "hackerone" if "hackerone" in query else \
                         "bugcrowd" if "bugcrowd" in query else \
                         "intigriti" if "intigriti" in query else "general"
                for r in data.get("results", []):
                    reports[source].append({
                        "url": r.get("url", ""),
                        "title": r.get("title", ""),
                        "snippet": r.get("content", "")[:300],
                    })
        except Exception:
            pass

    return reports


def build_claude_prompt(program: str, data: dict, reports: dict) -> str:
    """Build a comprehensive prompt for Claude to generate the threat landscape."""

    # Summarize findings
    findings_summary = ""
    if data.get("findings"):
        by_type = {}
        for f in data["findings"]:
            t = f.get("vuln_type", f.get("type", "unknown"))
            by_type[t] = by_type.get(t, 0) + 1
        findings_summary = "## Known Findings\n"
        for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
            findings_summary += f"- **{t}**: {c} finding(s)\n"

    # Summarize dorking
    dorking_summary = ""
    if data.get("recon", {}).get("dorking"):
        d = data["recon"]["dorking"]
        dorking_summary = f"\n## Dorking Results\n- {d['total_dorks']} dorks run, {d['total_findings']} findings\n"
        for f in d.get("findings", [])[:5]:
            dorking_summary += f"- [{f.get('type', '?')}] {f.get('url', '?')[:80]}\n"

    # Scope
    scope_summary = ""
    if data.get("scope", {}).get("markdown"):
        scope_summary = "\n## Program Scope\n" + data["scope"]["markdown"][:2000]

    # Public reports
    public_reports = ""
    total_reports = sum(len(v) for v in reports.values())
    if total_reports > 0:
        public_reports = f"\n## Public Bug Bounty Reports ({total_reports} found)\n"
        for source, items in reports.items():
            if items:
                public_reports += f"\n### {source.title()} Reports\n"
                for item in items[:3]:
                    public_reports += f"- [{item['title']}]({item['url']})\n"
                    if item.get("snippet"):
                        public_reports += f"  _{{item['snippet'][:200]}}..._\n"

    prompt = f"""You are a senior bug bounty researcher generating a comprehensive threat landscape report.

## Program: {program}
{scope_summary}
{findings_summary}
{dorking_summary}
{public_reports}

---

## Your Task

Generate a comprehensive **Threat Landscape Report** for this bug bounty program. Your audience is an experienced bug bounty hunter who wants to understand:
1. What vulnerability types have been found (or are likely given the tech stack)
2. Where the common attack surfaces are
3. What testing patterns have worked historically
4. What areas are likely under-tested and high-value
5. Specific endpoints and parameters worth targeting

## Format your report as follows:

### Executive Summary
Brief overview of the program's attack surface and key findings.

### Common Vulnerability Patterns
For each vuln type relevant to this program:
- Where it typically appears
- What to look for
- Example endpoints/parameters

### High-Value Targets
Ranked list of the most promising areas to test, based on:
- Known exposed endpoints from recon
- Tech stack implications
- Public report patterns
- Historical findings

### Under-Tested Areas
Where most hunters DON'T look but SHOULD:
- Less obvious attack surfaces
- Third-party integrations
- Legacy endpoints
- Mobile API vs web API differences

### Recommended Testing Workflow
A practical step-by-step approach for testing this specific program.

### Key Endpoints to Test
Specific URLs, parameters, and techniques worth trying.

---

Be specific. Generic advice is useless. Reference the actual data above. If you don't have enough data on a section, say so and suggest how to gather more intel.
"""

    return prompt


def generate_with_claude(prompt: str, output_path: str) -> str:
    """Run Claude CLI with the prompt and save the output."""
    import uuid

    # Write prompt to temp file
    prompt_file = Path(output_path).parent / "_threat_map_prompt.txt"
    prompt_file.write_text(prompt)

    # Use heredoc to pass prompt to claude --print
    result = subprocess.run(
        f"claude --print << 'CLAUDEPROMPT'\n{prompt}\nCLAUDEPROMPT",
        capture_output=True,
        text=True,
        timeout=120,
        shell=True,
        executable="/bin/bash",
    )

    if result.returncode == 0:
        return result.stdout
    else:
        return f"Claude CLI error (code {result.returncode}):\n{result.stderr}"


def run_threat_map(program: str, use_claude: bool = True) -> dict:
    """Run the full threat map pipeline."""

    print(f"🗺️  Threat Map: {program}")

    # Step 1: Load existing data
    print("  📂 Loading program data...")
    data = load_program_data(program)
    if "error" in data:
        return data

    domains = []
    if data.get("scope", {}).get("markdown"):
        import re
        found_domains = re.findall(r'[\w\-\.]+\.(?:com|co\.uk|org|net|io)', data["scope"]["markdown"])
        domains = list(set(found_domains))[:10]

    print(f"  ✅ Found: {len(data.get('findings', []))} findings, "
          f"{len(data.get('recon', {}))} recon files, "
          f"{len(domains)} scope domains")

    # Step 2: Fetch public reports
    print("  🔍 Fetching public bug bounty reports...")
    reports = fetch_public_reports(program, domains)
    total_reports = sum(len(v) for v in reports.values())
    print(f"  ✅ Found {total_reports} public reports")

    # Step 3: Build prompt
    print("  🧠 Building Claude prompt...")
    prompt = build_claude_prompt(program, data, reports)

    # Step 4: Generate report
    output_dir = Path.home() / "Shared" / "bounty_recon" / program / "ghost" / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = output_dir / f"threat_map_{timestamp}.md"

    if use_claude:
        print("  🤖 Running Claude CLI analysis...")
        report_content = generate_with_claude(prompt, str(output_path))
    else:
        report_content = prompt  # Debug: save the prompt

    # Step 5: Save
    output_path.write_text(report_content)
    print(f"  💾 Report saved: {output_path}")

    return {
        "program": program,
        "output_path": str(output_path),
        "findings_count": len(data.get("findings", [])),
        "recon_sources": list(data.get("recon", {}).keys()),
        "public_reports": {k: len(v) for k, v in reports.items()},
        "report_length": len(report_content),
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Threat Map — Bug Bounty Landscape Analysis")
    parser.add_argument("program", help="Program name (e.g. superdrug)")
    parser.add_argument("--no-claude", action="store_true", help="Skip Claude, just dump the prompt")
    parser.add_argument("--output", "-o", help="Output file path")

    args = parser.parse_args()
    result = run_threat_map(args.program, use_claude=not args.no_claude)
    print(f"\n✅ Threat map complete: {result}")
