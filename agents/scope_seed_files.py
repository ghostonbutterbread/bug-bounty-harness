"""Build recon seed files from normalized program scope."""

from __future__ import annotations

import re
from itertools import product
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlparse

_OPT_GROUP_RE = re.compile(r"\(([^()]+)\)\?")
MAX_OPTIONAL_GROUPS = 8
MAX_OPTIONAL_PATTERN_LENGTH = 4096
_DNS_SCOPE_RE = re.compile(r"^(?:\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")



def clean_scope_value(value: str) -> str:
    """Return a normalized single-line scope value without inline comments."""
    value = str(value or "").strip()
    if not value or value.startswith("#"):
        return ""
    if "#" in value:
        value = value.split("#", 1)[0].strip()
    return value.strip().rstrip("/")


def host_from_scope_value(value: str) -> str:
    value = clean_scope_value(value)
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return (urlparse(value).hostname or "").lower()
    try:
        address = ip_address(value.strip("[]"))
        return f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        pass
    return value.split("/", 1)[0].split(":", 1)[0].lower()


def wildcard_base(value: str) -> str:
    host = host_from_scope_value(value)
    if host.startswith("*."):
        return host[2:]
    return ""


def _expand_optional_groups(value: str) -> list[str]:
    """Expand one ``(alt)?`` optional group into both spelling variants.

    Program scopes sometimes serialize regex-style wildcards such as
    ``*.site(-eu1)?.example``; recon-ry only understands plain ``*.host``
    wildcards, so each optional group expands into the two concrete hosts.
    """
    groups = []
    for match in _OPT_GROUP_RE.finditer(value):
        groups.append(match)
        if len(groups) > MAX_OPTIONAL_GROUPS:
            raise ValueError(f"optional host pattern exceeds {MAX_OPTIONAL_GROUPS} groups (256 variants)")
    pieces = []
    end = 0
    for match in groups:
        pieces.append(value[end:match.start()])
        end = match.end()
    pieces.append(value[end:])
    return [
        "".join(part for pair in zip(pieces, choices) for part in pair) + pieces[-1]
        for choices in product(*[("", match.group(1)) for match in groups])
    ]


def is_dns_scope_value(value: str) -> bool:
    """True for recon-ry host rules: DNS, wildcard DNS, IPs or CIDRs."""
    v = value.strip().lower()
    if not v or _OPT_GROUP_RE.search(v):
        return False
    if "/" in v:
        try:
            ip_network(v, strict=False)
            return True
        except ValueError:
            return False
    if "[" in v or "]" in v:
        if not (v.startswith("[") and v.endswith("]") and v.count("[") == v.count("]") == 1):
            return False
        try:
            return ip_address(v[1:-1]).version == 6
        except ValueError:
            return False
    try:
        ip_address(v)
        return True
    except ValueError:
        pass
    if v.startswith("*."):
        try:
            ip_address(v[2:])
            return False
        except ValueError:
            pass
    if re.fullmatch(r"[\d.]+", v) or len(v.removeprefix("*.")) > 253:
        return False
    return bool(_DNS_SCOPE_RE.fullmatch(v)) and all(len(label) <= 63 for label in v.removeprefix("*.").split("."))


def optional_host_variants(value: str) -> list[str]:
    """Expand only host-only optional groups that produce valid exact hosts."""
    if value.startswith(("http://", "https://")) or "(" not in value:
        return [value]
    if len(value) > MAX_OPTIONAL_PATTERN_LENGTH:
        raise ValueError(f"optional host pattern exceeds {MAX_OPTIONAL_PATTERN_LENGTH} characters")
    if not _OPT_GROUP_RE.search(value):
        return [value]
    variants = _expand_optional_groups(value)
    return variants if all(is_dns_scope_value(variant) for variant in variants) else [value]


_PIPE_ANNOTATION_RE = re.compile(r"\s+\|(?:\s+|$)")


def _glob_probe_host(host: str) -> str:
    """Return ``host`` with infix ``*`` globs replaced by a letter for syntax checks."""
    lead = "*." if host.startswith("*.") else ""
    return lead + host[len(lead):].replace("*", "a")


def is_scope_rule_token(value: str) -> bool:
    """True when one whitespace-free token is a host, wildcard, glob, IP, CIDR or http(s) URL."""
    token = str(value or "").strip().rstrip("/")
    if not token or any(ch.isspace() for ch in token):
        return False
    if token.lower().startswith(("http://", "https://")):
        try:
            host = (urlparse(token).hostname or "").rstrip(".")
        except ValueError:
            return False
        return bool(host) and is_dns_scope_value(_glob_probe_host(host))
    if "(" in token:
        try:
            variants = optional_host_variants(token)
        except ValueError:
            return False
        return variants != [token] and all(is_scope_rule_token(variant) for variant in variants)
    return is_dns_scope_value(_glob_probe_host(token.rstrip(".")))


_TOKEN_PUNCTUATION = "(),;:"
_NAMED_RULE_RE = re.compile(r"^(?P<words>.*\S)\s+-\s+(?P<rule>\S+)$")
# Leftover exclusion prose that still looks like a host or address (a dotted
# label pair, an IPv6 fragment) is a rule the token stripper could not unwrap,
# for example "[a.x.test]" or "a.x.test;b.x.test": fail closed as base did.
_HOSTISH_RE = re.compile(r"[a-z0-9-]\.[a-z0-9-]|[0-9a-f]:[0-9a-f:]|::", re.IGNORECASE)
# Grant words that negate the rule ("Out of scope - a.x.test") never grant.
_NEGATING_WORDS_RE = re.compile(r"out[\s-]+of[\s-]+scope|exclud|except", re.IGNORECASE)


def parse_scope_line(line: str, *, exclusion: bool = False) -> tuple[list[str], str]:
    """Return ``(rules, status)`` for one saved scope line.

    Platform exports append `` | type | In Scope | ...`` columns; only the first
    field is a rule. A whitespace-free first field passes through unchanged so
    existing validation (including fail-closed invalid exclusions) applies.

    A first field containing whitespace mixes rules and prose:

    - every token is a rule (``a.x.test, b.x.test``): all of them, ``exact``;
    - exclusion: every token (punctuation ``(),;:`` stripped) that is itself a
      host, wildcard, glob, IP, CIDR or URL is kept, so exclusions err wide;
      ``lossy`` when prose remains, ``skipped`` when no token is rule-shaped;
      prose that still looks like a host or address the stripper could not
      unwrap (``[a.x.test]``, ``a.x.test;b.x.test``) adds the whole field as
      an invalid exclusion, so every target is refused (fail closed);
    - grant: only the export shape ``<words> - <rule>`` with no rule-shaped
      word and no negating words (out of scope, exclud, except) keeps
      ``<rule>`` (``exact``); anything else is ``skipped`` so prose
      such as ``All assets except a.x.test`` never grants.

    ``lossy`` and ``skipped`` lines carry meaning a host filter may not
    represent; callers needing a faithful scope (the Recon-Ry handoff) refuse.
    """
    value = _PIPE_ANNOTATION_RE.split(str(line or "").strip(), maxsplit=1)[0].strip()
    if not value:
        return [], "skipped"
    if not any(ch.isspace() for ch in value):
        return [value], "exact"
    raw_tokens = [token for token in re.split(r"[\s,]+", value) if token]
    if raw_tokens and all(is_scope_rule_token(token) for token in raw_tokens):
        return raw_tokens, "exact"
    if exclusion:
        stripped = [token.strip(_TOKEN_PUNCTUATION) for token in raw_tokens]
        rules = [token for token in stripped if token and is_scope_rule_token(token)]
        leftover = [token for token in stripped if token and token not in rules]
        if any(_HOSTISH_RE.search(token) for token in leftover):
            # The whole field is an invalid exclusion: every target is refused.
            return [*rules, value], "lossy"
        return (rules, "lossy") if rules else ([], "skipped")
    named = _NAMED_RULE_RE.match(value)
    if named and is_scope_rule_token(named.group("rule")) and not _NEGATING_WORDS_RE.search(named.group("words")) and not any(
        is_scope_rule_token(word.strip(_TOKEN_PUNCTUATION))
        for word in re.split(r"[\s,]+", named.group("words")) if word
    ):
        return [named.group("rule")], "exact"
    return [], "skipped"


def scope_line_rules(line: str, *, exclusion: bool = False) -> list[str]:
    """Rule values carried by one saved scope line; see parse_scope_line."""
    return parse_scope_line(line, exclusion=exclusion)[0]


def recon_seed_lines(domains: set[str] | list[str], urls: set[str] | list[str]) -> tuple[list[str], list[str]]:
    """Return ``(urls_txt, wild_txt)`` lines for recon-ry-compatible seeds.

    ``urls.txt`` receives exact URLs and exact host/domain entries.
    ``wild.txt`` receives wildcard base domains with the leading ``*.`` removed.
    """
    url_lines: list[str] = []
    wild_lines: list[str] = []

    for value in sorted(clean_scope_value(v) for v in urls):
        if value:
            url_lines.append(value)

    for value in sorted(clean_scope_value(v) for v in domains):
        if not value:
            continue
        if wildcard_base(value):
            for variant in optional_host_variants(value):
                base = wildcard_base(variant)
                if base and is_dns_scope_value(base):
                    wild_lines.append(base)
            continue
        if value.startswith(("http://", "https://")):
            url_lines.append(value)
            continue
        if "*" in value:
            # An infix wildcard cannot be represented as a recon-ry seed or
            # host scope; never widen it to a parent domain.
            continue
        # Non-DNS entries (program category labels such as "customer portal")
        # are not hosts recon-ry can seed; skip them rather than emit junk.
        for variant in optional_host_variants(value):
            if is_dns_scope_value(variant) and "/" not in variant:
                url_lines.append(host_from_scope_value(variant) or variant)

    return _dedupe(url_lines), _dedupe(wild_lines)


def write_recon_seed_files(base: Path, domains: set[str] | list[str], urls: set[str] | list[str]) -> dict[str, int]:
    """Write root-level recon seed files under a program bounty_recon directory."""
    url_lines, wild_lines = recon_seed_lines(domains, urls)
    base.mkdir(parents=True, exist_ok=True)
    urls_body = "\n".join(url_lines) + ("\n" if url_lines else "")
    wild_body = "\n".join(wild_lines) + ("\n" if wild_lines else "")
    (base / "urls.txt").write_text(urls_body, encoding="utf-8")
    (base / "wild.txt").write_text(wild_body, encoding="utf-8")
    return {"urls": len(url_lines), "wildcards": len(wild_lines)}


def recon_scope_file_lines(values: set[str] | list[str]) -> tuple[list[str], list[str]]:
    """Return ``(scope_lines, deferred)`` for a recon-ry ``--scope-file``.

    recon-ry scope entries are hostnames, wildcard hosts, IPs or CIDRs; it
    rejects anything carrying a path. A URL scoped to a specific path is
    therefore returned as ``deferred`` rather than widened to its whole host,
    which would claim more authorization than the program granted.
    """
    scope_lines: list[str] = []
    deferred: list[str] = []

    for raw in values:
        value = clean_scope_value(raw)
        if not value:
            continue
        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            if parsed.path.strip("/"):
                deferred.append(value)
                continue
            host = (parsed.hostname or "").lower()
            if host and is_dns_scope_value(host):
                scope_lines.append(host)
            else:
                deferred.append(value)
            continue
        # Expand regex-style optional groups into concrete wildcard hosts.
        for variant in optional_host_variants(value.removesuffix(".")):
            if is_dns_scope_value(variant):
                # Bare hosts, wildcards, IPs and CIDRs pass through as written.
                scope_lines.append(str(ip_network(variant, strict=False)) if "/" in variant else variant.lower())
            else:
                # Program category labels are not hosts recon-ry can scope;
                # defer them rather than writing entries it will reject.
                deferred.append(variant)

    return _dedupe(scope_lines), _dedupe(deferred)


def write_recon_scope_files(
    base: Path,
    in_scope: set[str] | list[str],
    out_of_scope: set[str] | list[str],
) -> dict[str, object]:
    """Write recon-ry ``--scope-file``/``--out-scope-file`` bodies."""
    allow_lines, deferred = recon_scope_file_lines(in_scope)
    deny_lines, deferred_denials = recon_scope_file_lines(out_of_scope)
    if deferred_denials:
        raise ValueError(f"unrepresentable scope exclusions: {', '.join(deferred_denials)}")
    base.mkdir(parents=True, exist_ok=True)
    header = "# Generated from saved program scope; edit the program scope, not this file.\n"
    (base / "in-scope-hosts.txt").write_text(
        header + "\n".join(sorted(allow_lines)) + ("\n" if allow_lines else ""), encoding="utf-8"
    )
    (base / "out-of-scope-hosts.txt").write_text(
        header + "\n".join(sorted(deny_lines)) + ("\n" if deny_lines else ""), encoding="utf-8"
    )
    return {"in_scope": len(allow_lines), "out_of_scope": len(deny_lines), "deferred": deferred}


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))
