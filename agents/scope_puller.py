#!/usr/bin/env python3
"""Pull scope from bug bounty platforms."""

import argparse
import html
import ipaddress
import json
import os
import re
import tempfile
import unicodedata
import urllib.request
from datetime import timedelta
from html.parser import HTMLParser
from textwrap import dedent
from pathlib import Path
from urllib.parse import urlparse

try:
    from scope_seed_files import recon_seed_lines
    import scope_inventory
except ModuleNotFoundError:
    from agents.scope_seed_files import recon_seed_lines
    from agents import scope_inventory

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
    normalized = routable_scope_entry(value)
    if normalized and not normalized.startswith(("http://", "https://")):
        domains.add(normalized.lower())


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


def bugcrowd_descriptive_host(name: str) -> str | None:
    """Recognize only the unambiguous '<host> Web Apps' label, not prose."""
    match = re.fullmatch(r"(\S+)\s+Web\s+Apps", name.strip(), re.IGNORECASE)
    if match and SCOPE_DOMAIN_PATTERN.fullmatch(match.group(1)):
        return match.group(1).lower()
    return None


def add_bugcrowd_target_to_scope(domains: set[str], urls: set[str], *, name: str, uri: str) -> None:
    """Normalize a Bugcrowd target into scope sets without losing wildcard semantics."""
    if uri and has_scope_control(uri):
        raise ValueError("control character in scope URI")
    if not uri and has_scope_control(name):
        return
    value = uri or name
    if not value:
        return

    if not uri and (host := bugcrowd_descriptive_host(name)):
        domains.add(host)
        return

    # Without a URI, a URL-shaped label containing whitespace may be prose
    # qualifying the target rather than part of a URL. Do not turn it into
    # permission. Explicit URI values retain their existing path semantics.
    if not uri and any(char.isspace() for char in name):
        return

    if value.startswith("http"):
        # Validate the original authority before deriving any permission from it.
        if not routable_scope_entry(value):
            return
        parsed = urlparse(value)
        urls.add(value)
        # A wildcard name paired with its root URI grants subdomains only at
        # that URI's scheme and port, not an unrestricted hostname wildcard.
        if (name.startswith("*.") and SCOPE_DOMAIN_PATTERN.fullmatch(name)
                and parsed.hostname and name[2:].lower() == parsed.hostname.lower()
                and parsed.path in ("", "/") and not parsed.query and not parsed.fragment):
            netloc = f"{name}:{parsed.port}" if parsed.port is not None else name
            urls.add(parsed._replace(netloc=netloc).geturl())
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
            uri = target.get("uri") or ""
            name = target.get("name") or ""
            if has_scope_control(uri) or (not group.get("inScope") and has_scope_control(name)):
                raise ValueError("control character in Bugcrowd scope target")
            uri = uri.strip()
            name = name.strip()
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


def has_scope_control(value: str) -> bool:
    """Scope entries must remain one physical line through every consumer."""
    return any(unicodedata.category(char) in {"Cc", "Zl", "Zp"} for char in value)


def routable_scope_entry(value: str, *, url_to_host: bool = False) -> str | None:
    """Return a strict scope entry, dropping non-routable platform metadata.

    Preserve an in-scope HTTP(S) URL exactly so a path-scoped grant never widens.
    Out-of-scope callers may conservatively reduce a path URL to its host.
    """
    if has_scope_control(value):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    if parsed.scheme.lower() in {"http", "https"}:
        try:
            host = parsed.hostname
            parsed.port  # Forces validation, including range checking.
        except ValueError:
            return None
        authority = parsed.netloc
        if (not host or "\\" in candidate or any(char in authority for char in "@%")
                or any(char.isspace() for char in authority) or authority.endswith(":")):
            return None
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if "[" in authority or "]" in authority or not SCOPE_DOMAIN_PATTERN.fullmatch(host):
                return None
        else:
            if ("[" in authority or "]" in authority) and address.version != 6:
                return None
        if url_to_host:
            return host
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


def bugcrowd_exclusion_entries(target: dict) -> set[str]:
    """Resolve both fields conservatively; never publish an ambiguous exclusion."""
    uri = str(target.get("uri") or "")
    name = str(target.get("name") or "")
    if has_scope_control(uri) or has_scope_control(name):
        raise RuntimeError("unresolved Bugcrowd exclusion; review scope before saving")
    uri = uri.strip()
    name = name.strip()
    entries: set[str] = set()
    for field, value in (("uri", uri), ("name", name)):
        if not value:
            continue
        entry = bugcrowd_descriptive_host(value) if field == "name" else None
        if not entry and not any(char.isspace() for char in value):
            entry = routable_scope_entry(value, url_to_host=True)
            if entry and not routable_scope_entry(entry, url_to_host=True):
                entry = None
        if entry:
            entries.add(entry)
        else:
            raise RuntimeError("unresolved Bugcrowd exclusion; review scope before saving")
    if not entries:
        raise RuntimeError("unresolved Bugcrowd exclusion; review scope before saving")
    return entries


def load_scope_review(slug: str) -> dict | None:
    """Load the operator-reviewed scope resolution file for a program."""
    path = Path.home() / "Shared" / "scopes" / slug / "scope-review.json"
    if not path.exists():
        return None
    try:
        review = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid scope review file {path}: {exc}") from exc
    if not isinstance(review, dict):
        raise ValueError(f"scope review file {path} must be a JSON object")
    return review


def apply_scope_review(slug: str, scope_data: dict) -> dict:
    """Apply reviewed grant/exclusion resolutions to parsed scope data.

    ``~/Shared/scopes/<slug>/scope-review.json`` records operator resolutions
    for platform targets the conservative parser refuses to auto-publish
    (wildcard grants paired with mismatched URIs, wildcard exclusions). The
    verbatim platform exclusion records are preserved under
    ``platform_exclusions_verbatim`` so ``out-of-scope.json`` keeps its
    complete-platform-record contract.
    """
    review = load_scope_review(slug)
    if not review:
        return scope_data
    applied = {"source": str(review.get("source") or ""), "grants": [], "exclusions": [], "skipped": []}

    for grant in review.get("grants") or []:
        entry = str(grant.get("entry") or "")
        if not str(grant.get("platform_name") or "") or not routable_scope_entry(entry):
            raise ValueError(f"invalid reviewed grant in scope-review.json: {grant!r}")
        if entry not in scope_data.get("domains", set()) and entry not in scope_data.get("urls", set()):
            scope_data.setdefault("domains", set()).add(entry)
        applied["grants"].append({"platform_name": grant["platform_name"], "entry": entry,
                                  "reason": str(grant.get("reason") or "")})

    resolutions = {}
    for exclusion in review.get("exclusions") or []:
        platform_name = str(exclusion.get("platform_name") or "")
        if not platform_name:
            raise ValueError(f"invalid reviewed exclusion in scope-review.json: {exclusion!r}")
        resolutions[platform_name] = exclusion

    scope_data["platform_exclusions_verbatim"] = [dict(t) for t in scope_data.get("out_of_scope", [])]
    resolved_out = []
    for target in scope_data["out_of_scope"]:
        reviewed = resolutions.get(str(target.get("name") or ""))
        if reviewed is None:
            resolved_out.append(target)
            continue
        if reviewed.get("skip"):
            applied["skipped"].append({"platform_name": reviewed["platform_name"],
                                       "reason": str(reviewed.get("reason") or "")})
            continue
        entry = str(reviewed.get("entry") or "")
        if not routable_scope_entry(entry):
            raise ValueError(f"invalid reviewed exclusion entry for {reviewed['platform_name']!r}: {entry!r}")
        resolved = dict(target)
        resolved["name"] = entry
        resolved["uri"] = ""
        resolved["review_resolved_from"] = reviewed["platform_name"]
        resolved_out.append(resolved)
        applied["exclusions"].append({"platform_name": reviewed["platform_name"], "entry": entry,
                                      "reason": str(reviewed.get("reason") or "")})
    scope_data["out_of_scope"] = resolved_out
    scope_data["scope_review_applied"] = applied
    return scope_data


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
    applied_review = scope_data.get("scope_review_applied")
    if applied_review:
        lines.extend(["", "## Reviewed Scope Resolution", ""])
        if applied_review.get("source"):
            lines.append(f"Review source: {applied_review['source']}")
        for grant in applied_review.get("grants") or []:
            reason = f" — {grant['reason']}" if grant.get("reason") else ""
            lines.append(f"- Grant `{grant['entry']}` resolved from platform target `{grant['platform_name']}`{reason}")
        for exclusion in applied_review.get("exclusions") or []:
            reason = f" — {exclusion['reason']}" if exclusion.get("reason") else ""
            lines.append(f"- Exclusion `{exclusion['entry']}` resolved from platform target `{exclusion['platform_name']}`{reason}")
        for skipped in applied_review.get("skipped") or []:
            reason = f" — {skipped['reason']}" if skipped.get("reason") else ""
            lines.append(f"- Platform exclusion `{skipped['platform_name']}` deliberately not published as a strict entry{reason}")
        lines.append("- Verbatim platform exclusion records: `out-of-scope.json`.")
    return "\n".join(lines).rstrip() + "\n"


def initialize_duplicate_intelligence(base: Path) -> bool:
    """Create a manual, non-authoritative record without replacing user data."""
    path = base / "duplicate-intelligence.md"
    if os.path.lexists(path):
        return False
    fd, name = tempfile.mkstemp(prefix=".duplicate-intelligence-", dir=base)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(
                "# Duplicate intelligence\n\n"
                "No observations recorded. Duplicate risk is unknown until evidence is supplied.\n\n"
                "## Program-level observations\n\n"
                "## Target and vulnerability-category observations\n"
            )
        try:
            os.link(temporary, path)
        except FileExistsError:
            return False
        return True
    finally:
        temporary.unlink(missing_ok=True)


def scopes_root() -> Path:
    return Path.home() / "Shared" / "scopes"


def save_scope(program: str, scope_data: dict, *, legacy: bool = True, release_check: bool = False):
    """Save scope data to the canonical Shared scopes folder.

    After the scope files are written, the typed inventory files
    (``scope-items.json``, ``scope-history.jsonl``, ``scope-pull.json``) are
    rebuilt from them. ``release_check`` adds the per-pull release-changed
    requests for in-scope app and executable items.
    """
    slug = canonical_program_slug(program)
    if not scope_data.get("domains") and not scope_data.get("urls"):
        raise RuntimeError(
            f"Parsed 0 in-scope network assets for '{slug}'; refusing to overwrite scope files. "
            "Check the program handle, platform response, and current program scope."
        )
    if any(has_scope_control(str(value)) for value in [*scope_data.get("domains", []), *scope_data.get("urls", [])]):
        raise ValueError("control character in scope entry; refusing to save")
    if any(has_scope_control(str(target.get(field) or ""))
           for target in scope_data.get("out_of_scope", []) for field in ("name", "uri")):
        raise ValueError("control character in scope exclusion; refusing to save")
    base = scopes_root() / slug
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
    if scope_data.get("platform") == "bugcrowd":
        strict_out_of_scope = set().union(*(
            bugcrowd_exclusion_entries(target) for target in scope_data.get("out_of_scope", [])
        ))
    else:
        strict_out_of_scope = {
            entry
            for target in scope_data.get("out_of_scope", [])
            if (entry := routable_scope_entry(str(target.get("uri") or target.get("name") or ""), url_to_host=True))
        }
    for entry in sorted(strict_out_of_scope):
        out_of_scope += f"{entry}\n"

    # Build every body and expand seeds before touching either scope tree.
    files = [
        (base / "in-scope.txt", in_scope),
        (base / "out-of-scope.txt", out_of_scope),
        (base / "out-of-scope.json", json.dumps(scope_data.get("platform_exclusions_verbatim") or scope_data.get("out_of_scope", []), indent=2, sort_keys=True) + "\n"),
        (base / "assets.json", json.dumps(scope_data.get("assets", []), indent=2, sort_keys=True) + "\n"),
        (base / "rules-of-engagement.json", json.dumps(scope_data.get("rules", {}), indent=2, sort_keys=True) + "\n"),
        (base / "program-policy.md", render_program_policy(scope_data)),
    ]
    if scope_data.get("raw"):
        raw = scope_data["raw"]
        if isinstance(raw, str):
            files.append((raw_base / f"{scope_data.get('platform', 'source')}-page.html", raw))
        else:
            files.append((raw_base / f"{scope_data.get('platform', 'source')}-brief.json", json.dumps(raw, indent=2, sort_keys=True) + "\n"))

    if legacy:
        legacy_program_base = Path.home() / "Shared" / "bounty_recon" / slug
        legacy_base = legacy_program_base / "scope"
        url_lines, wild_lines = recon_seed_lines(scope_data.get("domains", set()), scope_data.get("urls", set()))
        seed_counts = {"urls": len(url_lines), "wildcards": len(wild_lines)}
        files.extend([
            (legacy_base / "in-scope.txt", in_scope),
            (legacy_base / "out-of-scope.txt", out_of_scope),
            (legacy_program_base / "urls.txt", "\n".join(url_lines) + ("\n" if url_lines else "")),
            (legacy_program_base / "wild.txt", "\n".join(wild_lines) + ("\n" if wild_lines else "")),
        ])
    else:
        seed_counts = {"urls": 0, "wildcards": 0}

    changed = [write_if_changed(path, body) for path, body in files]
    try:
        intelligence_created = initialize_duplicate_intelligence(base)
    except OSError as exc:
        intelligence_created = False
        print(f"[!] Scope saved, but manual duplicate intelligence could not be initialized: {exc}")
    print(f"[+] Saved scope to: {base}")
    print(f"    Changed: {'yes' if any(changed) else 'no'}")
    if intelligence_created:
        print("    Initialized manual duplicate-intelligence.md (risk unknown)")
    print(f"    Domains: {len(scope_data.get('domains', []))}")
    print(f"    URLs: {len(scope_data.get('urls', []))}")
    if legacy:
        print(f"    Recon seeds: {seed_counts['urls']} urls, {seed_counts['wildcards']} wildcards")
    try:
        summary = scope_inventory.write_inventory(base, source="pull", program=slug, release_check=release_check)
    except Exception as exc:  # noqa: BLE001 - the inventory never fails a saved pull
        print(f"[!] Scope saved, but the scope inventory could not be written: {exc}")
        if not isinstance(exc, scope_inventory.InventoryLockTimeout):
            try:  # Keep pulled_at current so --if-older-than does not re-pull every run.
                scope_inventory.record_attempt(base, "ok", program=slug)
            except OSError:
                pass
    else:
        note = f", history: {summary['history']}" if summary["history"] else ""
        print(f"    Inventory: {summary['items']} items{note}, release changes: {summary['release_changed']}")


def detect_platform(program: str, platform: str | None = None) -> str:
    """Return the given platform or auto-detect one from the program string."""
    if platform:
        return platform
    if "hackerone" in program.lower() or "h1" in program.lower():
        return "hackerone"
    if "bugcrowd" in program.lower() or "bc" in program.lower():
        return "bugcrowd"
    if "intigriti" in program.lower():
        return "intigriti"
    return "hackerone"  # Default


def scope_slug(program: str, platform: str | None = None) -> str:
    """The scope directory name a pull of this program writes."""
    if detect_platform(program, platform) == "hackerone":
        return hackerone_handle(program)
    return canonical_program_slug(program)


def _pin_slug(scope_data: dict, slug: str | None) -> dict:
    """Keep a refresh's program name on the scope dir it refreshes."""
    if slug:
        scope_data["program"] = slug
        if isinstance(scope_data.get("rules"), dict):
            scope_data["rules"]["program"] = slug
    return scope_data


def pull_scope(program: str, platform: str = None, *, use_api: bool = False, release_check: bool = True,
               slug: str | None = None):
    """Pull scope for a program.

    ``slug`` pins the output directory. A refresh passes the existing dir name
    with the recorded source URL so the save lands in the dir being refreshed
    even when its name differs from the URL's last path part.
    """
    print(f"[*] Pulling scope for: {program}")
    platform = detect_platform(program, platform)

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
        scope_data = apply_scope_review(slug or handle, _pin_slug(scope_data, slug))
        save_scope(slug or handle, scope_data, release_check=release_check)
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
    scope_data = apply_scope_review(slug or canonical_program_slug(program), _pin_slug(scope_data, slug))
    save_scope(slug or program, scope_data, release_check=release_check)
    return scope_data


DAY_SECONDS = 86400
FAILED_PULL_BACKOFF = timedelta(hours=24)


def rebuild_inventory(slug: str) -> int:
    """Rebuild the inventory for one saved scope dir from its files only."""
    base = scopes_root() / slug
    if not base.is_dir():
        print(f"[!] No saved scope for '{slug}' at {base}")
        return 1
    try:
        summary = scope_inventory.write_inventory(base, source="rebuild", program=slug)
    except Exception as exc:  # noqa: BLE001 - report one line, not a traceback
        print(f"[!] {slug}: inventory rebuild failed: {type(exc).__name__}: {exc}")
        return 1
    note = f", history: {summary['history']}" if summary["history"] else ""
    print(f"[+] {slug}: {summary['items']} items{note}")
    return 0


def rebuild_all_inventories() -> int:
    root = scopes_root()
    if not root.is_dir():
        print(f"[!] No scopes directory at {root}")
        return 1
    failures = 0
    for base in sorted(root.iterdir()):
        # Alias symlinks point at a real program dir that is rebuilt on its own.
        if base.is_symlink() or not base.is_dir() or base.name.startswith("."):
            continue
        failures += rebuild_inventory(base.name)
    return 1 if failures else 0


def _age_days(moment) -> float:
    return (scope_inventory.utcnow() - moment).total_seconds() / DAY_SECONDS


def recorded_origin(base: Path) -> tuple[str | None, str | None]:
    """Platform and source URL an existing scope dir was pulled from."""
    platform = source_url = None
    for name in (scope_inventory.PULL_FILE, "rules-of-engagement.json"):
        data = scope_inventory.read_json(base / name)
        if not isinstance(data, dict):
            continue
        value = data.get("platform")
        if platform is None and isinstance(value, str) and value.strip():
            platform = value.strip().lower()
        value = data.get("source_url")
        if source_url is None and isinstance(value, str) and re.match(r"https?://\S+$", value.strip()):
            source_url = value.strip()
    return platform, source_url


def _record(base: Path, status: str, *, error: str | None = None, program: str) -> None:
    try:
        scope_inventory.record_attempt(base, status, error=error, program=program)
    except OSError as exc:
        print(f"[!] could not record pull state: {exc}")


def run_pull(program: str, platform: str | None, *, use_api: bool, release_check: bool,
             if_older_than: float | None = None, force_platform: bool = False) -> int:
    """CLI pull with saved-origin reuse, freshness skip, failure recording and backoff.

    An existing scope dir is refreshed from the platform and source URL it
    records, never from platform auto-detection. A different explicit
    ``--platform`` refuses unless ``force_platform``.
    """
    slug = scope_slug(program, platform)
    base = scopes_root() / slug
    saved = base.is_dir()
    target, target_slug = program, None
    if saved:
        recorded_platform, recorded_source = recorded_origin(base)
        if recorded_platform:
            if platform and platform != recorded_platform and not force_platform:
                print(f"[!] {slug}: saved scope was pulled from {recorded_platform}; refusing --platform {platform} "
                      "(pass --force-platform to replace it)")
                return 1
            if not (platform and force_platform):
                platform = recorded_platform
                target, target_slug = recorded_source or program, slug
    pulled = scope_inventory.last_pulled(base) if saved else None
    if if_older_than is not None and saved:
        if pulled is not None and _age_days(pulled) < if_older_than:
            print(f"scope fresh (pulled {int(_age_days(pulled))} days ago)")
            return 0
        state = scope_inventory.read_json(base / scope_inventory.PULL_FILE)
        failed_at = scope_inventory.parse_iso(state.get("last_failed_at")) if isinstance(state, dict) else None
        if failed_at is not None and scope_inventory.utcnow() - failed_at < FAILED_PULL_BACKOFF:
            retry = scope_inventory.iso(failed_at + FAILED_PULL_BACKOFF)
            _record(base, "skipped_backoff", program=slug)
            print(f"[!] scope stale but last pull failed at {scope_inventory.iso(failed_at)}; "
                  f"not retrying before {retry}; continuing with saved scope")
            return 0

    if platform is not None and platform not in PLATFORMS:
        error = f"saved scope platform '{platform}' is not supported by scope_puller; refresh it manually"
        _record(base, "failed", error=error, program=slug)
        print(f"[!] {slug}: {error}" + ("; continuing with saved scope" if if_older_than is not None else ""))
        return 0 if if_older_than is not None else 1

    try:
        result = pull_scope(target, platform, use_api=use_api, release_check=release_check, slug=target_slug)
        error = None if result is not None else "failed to fetch program page"
    except Exception as exc:  # noqa: BLE001 - any pull failure keeps the saved scope
        error = f"{type(exc).__name__}: {exc}"
    if error is None:
        return 0
    _record(base, "failed", error=error, program=slug)
    if if_older_than is not None and saved:
        age = f"{int(_age_days(pulled))} days old" if pulled is not None else "of unknown age"
        print(f"[!] scope refresh failed ({error}); continuing with saved scope ({age})")
        return 0
    print(f"[!] {error}")
    return 1


def build_arg_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description="Pull published bug bounty scope from a platform page.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent(
            """\
            Example:
              bbh agents/scope_puller.py canva --platform bugcrowd
              bbh agents/scope_puller.py canva --if-older-than 7
              bbh agents/scope_puller.py --rebuild-inventory --all

            Output:
              ~/Shared/scopes/<program>/
            """
        ),
    )


def main() -> int:
    parser = build_arg_parser()
    parser.add_argument("program", nargs="?", help="Program handle or full scope page URL")
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
    parser.add_argument(
        "--if-older-than",
        type=float,
        metavar="DAYS",
        help="Pull only when the saved scope is at least DAYS old. A failed refresh keeps the saved "
             "scope, prints a warning and exits 0; retries are skipped for 24 h after a failure.",
    )
    parser.add_argument(
        "--rebuild-inventory",
        action="store_true",
        help="Rebuild scope-items.json/scope-history.jsonl/scope-pull.json offline from the saved scope files.",
    )
    parser.add_argument(
        "--force-platform",
        action="store_true",
        help="Allow --platform to differ from the platform an existing scope dir was pulled from.",
    )
    parser.add_argument("--all", action="store_true", help="With --rebuild-inventory: every saved scope dir.")
    parser.add_argument(
        "--no-release-check",
        action="store_true",
        help="Skip the per-pull app/executable release-changed requests.",
    )
    args = parser.parse_args()

    if args.force_platform and not args.platform:
        parser.error("--force-platform requires --platform")
    if args.all and not args.rebuild_inventory:
        parser.error("--all requires --rebuild-inventory")
    if args.rebuild_inventory:
        if args.all == bool(args.program):
            parser.error("--rebuild-inventory needs exactly one of <program> or --all")
        if args.if_older_than is not None:
            parser.error("--if-older-than does not apply to --rebuild-inventory")
        return rebuild_all_inventories() if args.all else rebuild_inventory(scope_slug(args.program, args.platform))
    if not args.program:
        parser.error("program is required")
    if args.if_older_than is not None and args.if_older_than < 0:
        parser.error("--if-older-than must be >= 0")
    return run_pull(args.program, args.platform, use_api=args.api,
                    release_check=not args.no_release_check, if_older_than=args.if_older_than,
                    force_platform=args.force_platform)


if __name__ == "__main__":
    raise SystemExit(main())
