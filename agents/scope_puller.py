#!/usr/bin/env python3
"""Pull scope from bug bounty platforms."""

import argparse
import html
import ipaddress
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
    "intigriti": "https://app.intigriti.com/researcher/programs/{program}",
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


def hackerone_handle(program: str) -> str:
    """Extract a HackerOne team handle from a handle, shorthand, or URL."""
    value = program.strip()
    if not value.startswith("http"):
        return value.strip("/").split("/")[-1]
    parts = [part for part in urlparse(value).path.split("/") if part]
    if not parts:
        raise RuntimeError(f"Cannot determine HackerOne handle from: {program}")
    return parts[0]


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
    if platform == "intigriti":
        return f"https://app.intigriti.com/researcher/programs/{program}"
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


HACKERONE_GRAPHQL = "https://hackerone.com/graphql"

H1_TEAM_QUERY = """query TeamScope($handle: String!, $after: String) {
  team(handle: $handle) {
    handle
    policy
    submission_state
    offers_bounties
    structured_scopes(first: 500, after: $after, archived: false) {
      pageInfo {
        hasNextPage
        endCursor
      }
      edges {
        node {
          asset_type
          asset_identifier
          eligible_for_bounty
          eligible_for_submission
          instruction
          max_severity
        }
      }
    }
  }
}"""

H1_ASSET_CATEGORY = {
    "URL": "url", "WILDCARD": "wildcard", "CIDR": "cidr",
    "GOOGLE_PLAY_APP_ID": "android", "OTHER_APK": "android",
    "APPLE_STORE_APP_ID": "ios", "TESTFLIGHT": "ios",
    "SOURCE_CODE": "source_code", "DOWNLOADABLE_EXECUTABLES": "executable",
    "WINDOWS_APP_STORE_APP_ID": "executable", "HARDWARE": "hardware",
    "AI_MODEL": "ai_model", "SMART_CONTRACT": "smart_contract", "OTHER": "other",
}

H1_NON_NETWORK_ASSET_TYPES = {
    "GOOGLE_PLAY_APP_ID", "OTHER_APK", "APPLE_STORE_APP_ID", "TESTFLIGHT",
    "WINDOWS_APP_STORE_APP_ID", "DOWNLOADABLE_EXECUTABLES", "HARDWARE",
    "AI_MODEL", "SMART_CONTRACT", "CIDR",
}

# These are code-hosting services, not an executable web target just because a
# program lists one repository under HackerOne's broad SOURCE_CODE category.
H1_HOSTED_SOURCE_CODE_HOSTS = {
    "github.com", "gist.github.com", "gitlab.com", "bitbucket.org", "dev.azure.com",
}


def fetch_hackerone_team(handle: str) -> dict:
    """Fetch the public HackerOne policy and structured scope for one team."""
    cursor = None
    seen_cursors: set[str] = set()
    all_edges: list[dict] = []
    first_team = None

    while True:
        payload = json.dumps({
            "operationName": "TeamScope",
            "variables": {"handle": handle, "after": cursor},
            "query": H1_TEAM_QUERY,
        }).encode("utf-8")
        request = urllib.request.Request(
            HACKERONE_GRAPHQL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (compatible; ScopePuller/1.0)",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
        errors = body.get("errors") or []
        if errors:
            first = errors[0]
            message = first.get("message", str(first)) if isinstance(first, dict) else str(first)
            raise RuntimeError(f"HackerOne GraphQL error: {message}")
        team = (body.get("data") or {}).get("team")
        if not team:
            raise RuntimeError(f"HackerOne program '{handle}' was not found or is not public")
        if first_team is None:
            first_team = team

        structured_scopes = team.get("structured_scopes")
        if not isinstance(structured_scopes, dict):
            raise RuntimeError("HackerOne GraphQL response omitted structured scope data")
        edges = structured_scopes.get("edges")
        page_info = structured_scopes.get("pageInfo")
        if not isinstance(edges, list) or not isinstance(page_info, dict):
            raise RuntimeError("HackerOne GraphQL response omitted scope pagination metadata")
        all_edges.extend(edges)

        has_next_page = page_info.get("hasNextPage")
        if not isinstance(has_next_page, bool):
            raise RuntimeError("HackerOne GraphQL response has invalid scope pagination metadata")
        if not has_next_page:
            result = dict(first_team)
            result["structured_scopes"] = {"edges": all_edges, "pageInfo": page_info}
            return result

        cursor = page_info.get("endCursor")
        if not isinstance(cursor, str) or not cursor or cursor in seen_cursors:
            raise RuntimeError("HackerOne GraphQL response cannot continue scope pagination")
        seen_cursors.add(cursor)


def add_hackerone_target_to_scope(
    domains: set[str], urls: set[str], *, asset_type: str, identifier: str,
) -> None:
    """Add a network-shaped HackerOne asset without treating prose as scope."""
    value = (identifier or "").strip()
    if not value or asset_type in H1_NON_NETWORK_ASSET_TYPES:
        return
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        host = parsed.hostname or ""
        # HackerOne uses SOURCE_CODE both for actual product URLs and hosted
        # repositories. A hosted repository is metadata, never a web seed.
        if asset_type == "SOURCE_CODE" and host.lower() in H1_HOSTED_SOURCE_CODE_HOSTS:
            return
        if "*" in host:
            domains.add(host)
        else:
            urls.add(value)
        return
    if re.fullmatch(r"(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+", value):
        domains.add(value.lower())


def parse_hackerone_scope(team: dict) -> dict:
    """Normalize a HackerOne structured-scope payload into BBH scope data."""
    domains: set[str] = set()
    urls: set[str] = set()
    groups: dict[str, list[dict]] = {}
    out_of_scope: list[dict] = []
    for edge in ((team.get("structured_scopes") or {}).get("edges") or []):
        node = edge.get("node") or {}
        asset_type = node.get("asset_type") or "OTHER"
        identifier = node.get("asset_identifier") or ""
        in_scope = bool(node.get("eligible_for_submission"))
        severity = node.get("max_severity") or "none"
        target = {
            "name": identifier,
            "uri": identifier,
            "category": H1_ASSET_CATEGORY.get(asset_type, "other"),
            "asset_type": asset_type,
            "description": (node.get("instruction") or "").strip(),
            "group": severity if in_scope else "out-of-scope",
            "in_scope": in_scope,
            "eligible_for_bounty": bool(node.get("eligible_for_bounty")),
            "max_severity": severity,
            "ip_address": None,
        }
        if not in_scope:
            out_of_scope.append(target)
            continue
        add_hackerone_target_to_scope(domains, urls, asset_type=asset_type, identifier=identifier)
        groups.setdefault(severity, []).append(target)
    severity_order = ["critical", "high", "medium", "low", "none"]
    assets = [
        {"name": name, "targets": groups[name]}
        for name in sorted(groups, key=lambda name: severity_order.index(name) if name in severity_order else len(severity_order))
    ]
    return {"domains": domains, "urls": urls, "assets": assets, "out_of_scope": out_of_scope}


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


INTIGRITI_ASSET_TYPES = {"URL", "Wildcard", "Other", "Android", "iOS", "Source code"}


def parse_intigriti_public_program(program: str, html_content: str) -> dict:
    """Parse rendered public Intigriti asset cards without an authenticated API."""
    domains: set[str] = set()
    urls: set[str] = set()
    groups: dict[str, list[dict]] = {}
    out_of_scope: list[dict] = []
    cards = re.findall(
        r"<lib-asset-detail\b.*?</lib-asset-detail>", html_content,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not cards:
        raise RuntimeError("Intigriti public page did not expose rendered asset cards")

    for card in cards:
        name_match = re.search(
            r'class="[^"]*asset-name[^"]*"[^>]*>.*?<(?:span|a)\b[^>]*>(.*?)</(?:span|a)>',
            card,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if not name_match:
            continue
        name = html_to_text(name_match.group(1)).strip()
        if not name:
            continue
        card_text = html_to_text(card)
        asset_type = next(
            (kind for kind in INTIGRITI_ASSET_TYPES if re.search(rf"\b{re.escape(kind)}\b", card_text, re.IGNORECASE)),
            "other",
        )
        is_out_of_scope = "oos-asset" in card or bool(re.search(r"\bOut of scope\b", card_text, re.IGNORECASE))
        tier_match = re.search(r"\bTier\s+(\d+)\b", card_text, re.IGNORECASE)
        group = "out-of-scope" if is_out_of_scope else (f"tier-{tier_match.group(1)}" if tier_match else "in-scope")
        target = {
            "name": name,
            "uri": name,
            "category": asset_type.lower().replace(" ", "_"),
            "asset_type": asset_type,
            "description": "",
            "group": group,
            "in_scope": not is_out_of_scope,
            "ip_address": None,
        }
        if is_out_of_scope:
            out_of_scope.append(target)
            continue
        add_bugcrowd_target_to_scope(domains, urls, name=name, uri=name)
        groups.setdefault(group, []).append(target)

    if not domains and not urls:
        raise RuntimeError("Intigriti public page contained no in-scope network assets")

    source_url = default_source_url(program, "intigriti")
    rules_text = html_to_text(html_content)
    blocked_keywords = {
        "brute force": "brute force",
        "denial of service": "denial of service",
        "dos/ddos": "denial of service",
        "social engineering": "social engineering",
        "physical access": "physical attacks",
        "spam": "spam",
    }
    blocked = sorted({label for needle, label in blocked_keywords.items() if needle in rules_text.lower()})
    return {
        "program": canonical_program_slug(program),
        "platform": "intigriti",
        "domains": domains,
        "urls": urls,
        "assets": [{"name": group, "targets": groups[group]} for group in sorted(groups)],
        "out_of_scope": out_of_scope,
        "rules": build_rules_profile(
            program=program,
            platform="intigriti",
            source_url=source_url,
            source_brief_url=source_url,
            status="open" if re.search(r"\bOpen\b", rules_text) else None,
            participation="public" if re.search(r"\bPublic\b", rules_text) else None,
            rules_text=rules_text,
            blocked_or_sensitive_classes=blocked,
            needs_review=["Public rendered Intigriti asset cards are authoritative for assets; review the program rules before live testing."],
        ),
        "raw": html_content,
    }


SCOPE_DOMAIN_PATTERN = re.compile(
    r"(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def routable_scope_entry(value: str, *, url_to_host: bool = False) -> str | None:
    """Return a strict scope entry, dropping non-routable platform metadata.

    Preserve an in-scope HTTP(S) URL exactly so a path-scoped grant never widens.
    Out-of-scope callers may conservatively reduce a path URL to its host.
    """
    candidate = value.strip()
    if not candidate:
        return None
    parsed = urlparse(candidate)
    if parsed.scheme.lower() in {"http", "https"}:
        if not parsed.hostname:
            return None
        if url_to_host:
            return parsed.hostname
        return candidate
    candidate = re.sub(r"\.\s+", ".", candidate)
    if candidate.endswith("/*") and SCOPE_DOMAIN_PATTERN.fullmatch(candidate[:-2]):
        candidate = candidate[:-2]
    if any(char.isspace() for char in candidate):
        return None
    if "/" in candidate:
        try:
            return str(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    return candidate.lower() if SCOPE_DOMAIN_PATTERN.fullmatch(candidate) else None


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
    if not scope_data.get("domains") and not scope_data.get("urls"):
        raise RuntimeError(
            f"Parsed 0 in-scope network assets for '{slug}'; refusing to overwrite scope files. "
            "Check the program handle, platform response, and current program scope."
        )
    base = Path.home() / "Shared" / "scopes" / slug
    raw_base = base / "raw"

    in_scope = "# In-scope domains and URLs\n"
    strict_in_scope = {
        entry
        for value in [*scope_data.get("domains", []), *scope_data.get("urls", [])]
        if (entry := routable_scope_entry(str(value)))
    }
    for entry in sorted(strict_in_scope):
        in_scope += f"{entry}\n"

    out_of_scope = ""
    strict_out_of_scope = {
        entry
        for target in scope_data.get("out_of_scope", [])
        if (entry := routable_scope_entry(str(target.get("uri") or target.get("name") or ""), url_to_host=True))
    }
    for entry in sorted(strict_out_of_scope):
        out_of_scope += f"{entry}\n"

    changed = [
        write_if_changed(base / "in-scope.txt", in_scope),
        write_if_changed(base / "out-of-scope.txt", out_of_scope),
        write_if_changed(base / "out-of-scope.json", json.dumps(scope_data.get("out_of_scope", []), indent=2, sort_keys=True) + "\n"),
        write_if_changed(base / "assets.json", json.dumps(scope_data.get("assets", []), indent=2, sort_keys=True) + "\n"),
        write_if_changed(base / "rules-of-engagement.json", json.dumps(scope_data.get("rules", {}), indent=2, sort_keys=True) + "\n"),
        write_if_changed(base / "program-policy.md", render_program_policy(scope_data)),
    ]
    if scope_data.get("raw"):
        raw = scope_data["raw"]
        if isinstance(raw, str):
            changed.append(write_if_changed(raw_base / f"{scope_data.get('platform', 'source')}-page.html", raw))
        else:
            changed.append(write_if_changed(raw_base / f"{scope_data.get('platform', 'source')}-brief.json", json.dumps(raw, indent=2, sort_keys=True) + "\n"))

    if legacy:
        legacy_program_base = Path.home() / "Shared" / "bounty_recon" / slug
        legacy_base = legacy_program_base / "scope"
        write_if_changed(legacy_base / "in-scope.txt", in_scope)
        write_if_changed(legacy_base / "out-of-scope.txt", out_of_scope)
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

    if platform == "hackerone":
        handle = hackerone_handle(program)
        source_url = PLATFORMS["hackerone"].format(program=handle)
        print(f"[*] Fetching structured scope from: {HACKERONE_GRAPHQL} (handle={handle})")
        team = fetch_hackerone_team(handle)
        scope_data = parse_hackerone_scope(team)
        scope_data.update({
            "program": handle,
            "platform": "hackerone",
            "rules": build_rules_profile(
                program=handle,
                platform="hackerone",
                source_url=f"{source_url}/policy_scopes",
                source_brief_url=HACKERONE_GRAPHQL,
                rules_text=team.get("policy") or "",
                status="open" if team.get("submission_state") == "open" else team.get("submission_state"),
                participation="bounty" if team.get("offers_bounties") else "vdp",
                needs_review=["Structured scope is authoritative for assets; review policy text before live testing."],
            ),
            "raw": team,
        })
        save_scope(handle, scope_data)
        return scope_data

    # Build URL
    if platform == "hackerone" and not program.startswith("http"):
        url = PLATFORMS.get(platform, PLATFORMS["hackerone"]).format(program=program)
    elif platform == "bugcrowd" and not program.startswith("http"):
        url = f"https://bugcrowd.com/engagements/{program}"
    elif platform == "intigriti" and not program.startswith("http"):
        url = default_source_url(program, "intigriti")
    else:
        url = program
    print(f"[*] Fetching from: {url}")
    
    # Fetch
    content = fetch_page(url)
    if not content:
        print("[!] Failed to fetch page")
        return
    
    # Parse
    if platform == "bugcrowd":
        scope_data = parse_bugcrowd_public_engagement(program, content)
    elif platform == "intigriti":
        scope_data = parse_intigriti_public_program(program, content)
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
              bbh agents/scope_puller.py canva --platform bugcrowd

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
