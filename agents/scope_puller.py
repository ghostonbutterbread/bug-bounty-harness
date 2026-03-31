#!/usr/bin/env python3
"""Pull scope from bug bounty platforms."""

import argparse
import re
from textwrap import dedent
from pathlib import Path

PLATFORMS = {
    "hackerone": "https://hackerone.com/{program}",
    "bugcrowd": "https://bugcrowd.com/{program}",
    "intigriti": "https://app.intigriti.com/researcher/{program}",
}


def fetch_page(url: str) -> str:
    """Fetch a page using curl."""
    import subprocess
    try:
        result = subprocess.run(
            ["curl", "-s", "-L", "--max-time", "30", url],
            capture_output=True, text=True, timeout=35
        )
        return result.stdout
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return ""


def parse_hackerone_scope(html_content: str) -> dict:
    """Parse scope from HackerOne page."""
    domains = set()
    urls = set()
    
    # Look for domain patterns in JSON/JS
    domain_pattern = r'"domain":"([^"]+)"'
    for match in re.finditer(domain_pattern, html_content):
        domain = match.group(1)
        if domain.startswith("*."):
            domains.add(domain)
        elif "." in domain:
            domains.add(domain)
    
    # Look for URL patterns
    url_pattern = r'"url":"(https?://[^"]+)"'
    for match in re.finditer(url_pattern, html_content):
        urls.add(match.group(1))
    
    return {"domains": domains, "urls": urls}


def save_scope(program: str, scope_data: dict):
    """Save scope data to files."""
    base = Path.home() / "Shared" / "bounty_recon" / program / "scope"
    base.mkdir(parents=True, exist_ok=True)
    
    with open(base / "in-scope.txt", "w") as f:
        f.write("# In-scope domains and URLs\n")
        for domain in sorted(scope_data.get("domains", [])):
            f.write(f"{domain}\n")
        for url in sorted(scope_data.get("urls", [])):
            f.write(f"{url}\n")
    
    print(f"[+] Saved scope to: {base}")
    print(f"    Domains: {len(scope_data.get('domains', []))}")
    print(f"    URLs: {len(scope_data.get('urls', []))}")


def pull_scope(program: str, platform: str = None):
    """Pull scope for a program."""
    print(f"[*] Pulling scope for: {program}")
    
    # Auto-detect platform
    if not platform:
        if "hackerone" in program.lower() or "h1" in program.lower():
            platform = "hackerone"
        elif "bugcrowd" in program.lower() or "bc" in program.lower():
            platform = "bugcrowd"
        elif "intigriti" in program.lower():
            platform = "intigriti"
        else:
            platform = "hackerone"  # Default
    
    # Build URL
    if platform == "hackerone" and not program.startswith("http"):
        url = PLATFORMS.get(platform, PLATFORMS["hackerone"]).format(program=program)
    else:
        url = program
    print(f"[*] Fetching from: {url}")
    
    # Fetch
    content = fetch_page(url)
    if not content:
        print("[!] Failed to fetch page")
        return
    
    # Parse
    if platform == "hackerone":
        scope_data = parse_hackerone_scope(content)
    else:
        domains = set()
        domain_pattern = r'(?:[*]?\.)?([a-z0-9][-a-z0-9]*\.[a-z]{2,})'
        for match in re.finditer(domain_pattern, content):
            d = match.group(0)
            if d and not d.startswith("www.") and "." in d:
                domains.add(d)
        scope_data = {"domains": domains, "urls": set()}
    
    # Save
    save_scope(program, scope_data)
    return scope_data


def build_arg_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description="Pull published bug bounty scope from a platform page.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent(
            """\
            Example:
              python3 agents/scope_puller.py adobe --platform hackerone

            Output:
              ~/Shared/bounty_recon/<program>/scope/in-scope.txt
            """
        ),
    )


def main() -> int:
    parser = build_arg_parser()
    parser.add_argument("program", help="Program handle or full scope page URL")
    parser.add_argument(
        "--platform",
        "-p",
        choices=["hackerone", "bugcrowd", "intigriti"],
        help="Platform slug. Auto-detected when omitted.",
    )
    args = parser.parse_args()

    pull_scope(args.program, args.platform)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
