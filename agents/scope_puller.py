#!/usr/bin/env python3
"""Pull scope from bug bounty platforms."""

import argparse
import html
import json
import re
import urllib.request
from html.parser import HTMLParser
from textwrap import dedent
from pathlib import Path
from urllib.parse import urlparse

try:
    from scope_seed_files import write_recon_seed_files
except ModuleNotFoundError:
    from agents.scope_seed_files import write_recon_seed_files

PLATFORMS = {
    "hackerone": "https://hackerone.com/{program}",
    "bugcrowd": "https://bugcrowd.com/{program}",
    "intigriti": "https://app.intigriti.com/researcher/{program}",
}

RULE_SCHEMA_VERSION = 1


class TextExtractor(HTMLParser):
    """Small HTML-to-text helper for public program brief fragments."""

    BLOCK_TAGS = {"p", "div", "li", "br", "h1", "h2", "h3", "h4", "ol", "ul", "tr"}

    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        text = data.strip()
        if text:
            self.parts.append(text)

    def get_text(self) -> str:
        text = " ".join(self.parts)
        text = re.sub(r"[ \t\r\f\v]+", " ", text)
        text = re.sub(r"\n\s+", "\n", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return html.unescape(text).strip()


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


def fetch_json(url: str) -> dict:
    """Fetch JSON using only public web access."""
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (compatible; ScopePuller/1.0)",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def html_to_text(fragment: str | None) -> str:
    if not fragment:
        return ""
    parser = TextExtractor()
    parser.feed(fragment)
    return parser.get_text()


def canonical_program_slug(program: str) -> str:
    """Convert a handle or URL into the local program directory name."""
    if not program.startswith("http"):
        return program.strip("/").split("/")[-1]
    parsed = urlparse(program)
    parts = [p for p in parsed.path.split("/") if p]
    if "engagements" in parts:
        idx = parts.index("engagements")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    if parts:
        return parts[-1]
    return parsed.netloc.replace(".", "-")


def write_if_changed(path: Path, content: str) -> bool:
    """Write a text file only when content changed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == content:
        return False
    path.write_text(content)
    return True


def extract_json_attr(html_content: str, attr: str) -> dict | None:
    match = re.search(attr + r'="([^"]*)"', html_content)
    if not match:
        return None
    return json.loads(html.unescape(match.group(1)))


def default_source_url(program: str, platform: str) -> str:
    """Return the resolved source URL for a program/platform pair."""
    if program.startswith("http"):
        return program
    if platform == "bugcrowd":
        return f"https://bugcrowd.com/engagements/{program}"
    return PLATFORMS.get(platform, "https://{program}").format(program=program)


def build_rules_profile(
    *,
    program: str,
    platform: str,
    source_url: str,
    source_brief_url: str | None = None,
    rules_text: str = "",
    status: str | None = None,
    participation: str | None = None,
    safe_harbor_status: str | None = None,
    blocked_or_sensitive_classes: list[str] | None = None,
    needs_review: list[str] | None = None,
) -> dict:
    """Build the normalized program policy profile consumed by agents."""
    return {
        "schema_version": RULE_SCHEMA_VERSION,
        "program": canonical_program_slug(program),
        "platform": platform,
        "source_url": source_url,
        "source_brief_url": source_brief_url,
        "status": status,
        "participation": participation,
        "safe_harbor_status": safe_harbor_status,
        "blocked_or_sensitive_classes": blocked_or_sensitive_classes or [],
        "rules_text": rules_text,
        "needs_review": needs_review or [
            "Review rules_text before enabling live testing lanes.",
            "Only obvious exclusions are machine-tagged in v1.",
        ],
    }


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


def add_bugcrowd_target_to_scope(domains: set[str], urls: set[str], *, name: str, uri: str) -> None:
    """Normalize a Bugcrowd target into scope sets without losing wildcard semantics."""
    value = uri or name
    if not value:
        return

    if value.startswith("http"):
        host = urlparse(value).netloc
        if "*" in host:
            domains.add(host)
        else:
            urls.add(value)
            # Bugcrowd sometimes uses a wildcard name with a root URI.
            # Preserve the wildcard target so scope validation can match subdomains.
            if name.startswith("*."):
                domains.add(name)
        return

    if "." in value and " " not in value:
        domains.add(value)


def parse_bugcrowd_public_engagement(program: str, html_content: str) -> dict:
    """Parse Bugcrowd's public /engagements/<slug> page and brief JSON."""
    api_endpoints = extract_json_attr(html_content, "data-api-endpoints") or {}
    brief_path = (
        api_endpoints.get("engagementBriefApi", {})
        .get("getBriefVersionDocument")
    )
    if not brief_path:
        raise RuntimeError("Bugcrowd public page did not expose engagement brief JSON endpoint")
    if not brief_path.endswith(".json"):
        brief_path = f"{brief_path}.json"
    brief_url = f"https://bugcrowd.com{brief_path}"
    raw = fetch_json(brief_url)

    data = raw.get("data", {})
    brief = data.get("brief", {})
    scope_groups = data.get("scope", [])

    domains: set[str] = set()
    urls: set[str] = set()
    assets = []
    out_of_scope = []
    for group in scope_groups:
        group_entry = {
            "id": group.get("id"),
            "name": group.get("name"),
            "in_scope": bool(group.get("inScope")),
            "description": html_to_text(group.get("descriptionHtml") or group.get("description")),
            "reward_range": group.get("rewardRangeData") or group.get("rewardRange"),
            "targets": [],
        }
        for target in group.get("targets") or []:
            uri = (target.get("uri") or "").strip()
            name = (target.get("name") or "").strip()
            target_entry = {
                "id": target.get("id"),
                "name": name,
                "uri": uri,
                "category": target.get("category"),
                "ip_address": target.get("ipAddress") or None,
                "in_scope": bool(group.get("inScope")),
                "group": group.get("name"),
            }
            group_entry["targets"].append(target_entry)
            if not group.get("inScope"):
                out_of_scope.append(target_entry)
                continue
            add_bugcrowd_target_to_scope(domains, urls, name=name, uri=uri)
        assets.append(group_entry)

    rules_text = "\n\n".join(
        part for part in [
            html_to_text(brief.get("targetsOverview")),
            html_to_text(brief.get("additionalInformation")),
            *(group.get("description") for group in assets if group.get("description")),
        ] if part
    )

    blocked_keywords = {
        "clickjacking": "clickjacking",
        "rate limit": "rate-limit testing",
        "brute force": "brute force",
        "social engineering": "social engineering",
        "physical": "physical attacks",
        "spam": "spam",
        "denial of service": "denial of service",
        "dos": "denial of service",
        "destruction of data": "destructive testing",
        "degradation of user experience": "user-impacting testing",
    }
    blocked = sorted({label for needle, label in blocked_keywords.items() if needle in rules_text.lower()})

    rules = build_rules_profile(
        program=program,
        platform="bugcrowd",
        source_url=f"https://bugcrowd.com/engagements/{canonical_program_slug(program)}",
        source_brief_url=brief_url,
        status=raw.get("statusLabel") or raw.get("data", {}).get("engagement", {}).get("state"),
        participation=raw.get("participation") or data.get("engagementConfiguration", {}).get("participation"),
        safe_harbor_status=brief.get("safeHarborStatus"),
        rules_text=rules_text,
        blocked_or_sensitive_classes=blocked,
    )

    return {
        "program": canonical_program_slug(program),
        "platform": "bugcrowd",
        "domains": domains,
        "urls": urls,
        "assets": assets,
        "out_of_scope": out_of_scope,
        "rules": rules,
        "raw": raw,
    }


def render_program_policy(scope_data: dict) -> str:
    rules = scope_data.get("rules", {})
    lines = [
        f"# {scope_data.get('program')} Program Policy",
        "",
        f"- Platform: {scope_data.get('platform')}",
        f"- Source: {rules.get('source_url', '')}",
        f"- Brief JSON: {rules.get('source_brief_url', '')}",
        f"- Participation: {rules.get('participation') or 'unknown'}",
        f"- Status: {rules.get('status') or 'unknown'}",
        "",
        "## In-Scope Assets",
        "",
    ]
    for domain in sorted(scope_data.get("domains", [])):
        lines.append(f"- `{domain}`")
    for url in sorted(scope_data.get("urls", [])):
        lines.append(f"- `{url}`")
    if scope_data.get("out_of_scope"):
        lines.extend(["", "## Out-Of-Scope Assets", ""])
        for target in scope_data["out_of_scope"]:
            lines.append(f"- `{target.get('uri') or target.get('name')}` ({target.get('group')})")
    lines.extend(["", "## Machine-Tagged Blocked/Sensitive Classes", ""])
    blocked = rules.get("blocked_or_sensitive_classes") or []
    if blocked:
        for item in blocked:
            lines.append(f"- {item}")
    else:
        lines.append("- None machine-tagged; review rules text before live testing.")
    lines.extend(["", "## Rules Text", "", rules.get("rules_text") or "No rules text extracted."])
    return "\n".join(lines).rstrip() + "\n"


def save_scope(program: str, scope_data: dict, *, legacy: bool = True):
    """Save scope data to the canonical Shared scopes folder."""
    slug = canonical_program_slug(program)
    base = Path.home() / "Shared" / "scopes" / slug
    raw_base = base / "raw"

    in_scope = "# In-scope domains and URLs\n"
    for domain in sorted(scope_data.get("domains", [])):
        in_scope += f"{domain}\n"
    for url in sorted(scope_data.get("urls", [])):
        in_scope += f"{url}\n"

    changed = [
        write_if_changed(base / "in-scope.txt", in_scope),
        write_if_changed(base / "assets.json", json.dumps(scope_data.get("assets", []), indent=2, sort_keys=True) + "\n"),
        write_if_changed(base / "rules-of-engagement.json", json.dumps(scope_data.get("rules", {}), indent=2, sort_keys=True) + "\n"),
        write_if_changed(base / "program-policy.md", render_program_policy(scope_data)),
    ]
    if scope_data.get("raw"):
        changed.append(write_if_changed(raw_base / f"{scope_data.get('platform', 'source')}-brief.json", json.dumps(scope_data["raw"], indent=2, sort_keys=True) + "\n"))

    if legacy:
        legacy_program_base = Path.home() / "Shared" / "bounty_recon" / slug
        legacy_base = legacy_program_base / "scope"
        write_if_changed(legacy_base / "in-scope.txt", in_scope)
        seed_counts = write_recon_seed_files(
            legacy_program_base,
            scope_data.get("domains", set()),
            scope_data.get("urls", set()),
        )
    else:
        seed_counts = {"urls": 0, "wildcards": 0}

    print(f"[+] Saved scope to: {base}")
    print(f"    Changed: {'yes' if any(changed) else 'no'}")
    print(f"    Domains: {len(scope_data.get('domains', []))}")
    print(f"    URLs: {len(scope_data.get('urls', []))}")
    if legacy:
        print(f"    Recon seeds: {seed_counts['urls']} urls, {seed_counts['wildcards']} wildcards")


def pull_scope(program: str, platform: str = None, *, use_api: bool = False):
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
    
    if use_api and platform != "bugcrowd":
        print("[!] --api is currently only reserved for Bugcrowd API-backed scope pulls")
    if use_api and platform == "bugcrowd":
        raise RuntimeError("Bugcrowd API mode is not implemented yet; omit --api to use the public engagement scrape")

    # Build URL
    if platform == "hackerone" and not program.startswith("http"):
        url = PLATFORMS.get(platform, PLATFORMS["hackerone"]).format(program=program)
    elif platform == "bugcrowd" and not program.startswith("http"):
        url = f"https://bugcrowd.com/engagements/{program}"
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
        scope_data.update({
            "program": canonical_program_slug(program),
            "platform": "hackerone",
            "assets": [],
            "rules": build_rules_profile(
                program=program,
                platform="hackerone",
                source_url=url,
                rules_text=html_to_text(content),
                needs_review=[
                    "HackerOne public fallback currently extracts assets best-effort; review policy text/API output before live testing.",
                ],
            ),
            "raw": None,
        })
    elif platform == "bugcrowd":
        scope_data = parse_bugcrowd_public_engagement(program, content)
    else:
        domains = set()
        domain_pattern = r'(?:[*]?\.)?([a-z0-9][-a-z0-9]*\.[a-z]{2,})'
        for match in re.finditer(domain_pattern, content):
            d = match.group(0)
            if d and not d.startswith("www.") and "." in d:
                domains.add(d)
        scope_data = {
            "program": canonical_program_slug(program),
            "platform": platform,
            "domains": domains,
            "urls": set(),
            "assets": [],
            "rules": build_rules_profile(
                program=program,
                platform=platform,
                source_url=url,
                rules_text=html_to_text(content),
                needs_review=[
                    f"{platform} fallback currently extracts assets best-effort; review policy text/API output before live testing.",
                ],
            ),
            "raw": None,
        }
    
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
              python3 agents/scope_puller.py canva --platform bugcrowd

            Output:
              ~/Shared/scopes/<program>/
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
    parser.add_argument(
        "--api",
        action="store_true",
        help="Use the platform API path where implemented. Bugcrowd defaults to public engagement scraping unless this is set.",
    )
    args = parser.parse_args()

    try:
        pull_scope(args.program, args.platform, use_api=args.api)
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
