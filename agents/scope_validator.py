"""
Scope Validator — Ensures recon and testing stays within program scope.

Supports:
  - Exact domains:         example.com
  - Wildcard domains:      *.example.com
  - URL patterns:          https://api.example.com/v1/*
  - CIDR ranges:           10.0.0.0/8, 192.168.1.0/24

Authority spellings with percent escapes, userinfo, malformed ports, non-ASCII
hosts or backslashes are refused before comparison; an invalid exclusion can
therefore deny all targets. URL grants require a full URL, even at the root.
Path-scoped URLs use conservative lexical checks, not a model of application
routing or HTTP redirects. With a path restriction, ambiguous path spellings
(including percent escapes at any depth, dot/trailing-dot segments, repeated
separators, backslashes, matrix parameters, whitespace or non-ASCII) are
refused; a path exclusion also refuses colon-bearing paths. Verify the actual
consumer enforces scope for every request and redirect. Do not decode or
rewrite an ambiguous target into a purportedly authorized one without checking
the program's scope and downstream behavior.

Scope files are loaded from standard locations:
  ~/Shared/scopes/{program}/in-scope.txt
  ~/Shared/scopes/{program}/rules-of-engagement.json
  Legacy fallback:
  ~/Shared/bounty_recon/{program}/scope/in-scope.txt
  ~/Shared/bounty_recon/{program}/scope/domains.txt

Usage:
    from scope_validator import ScopeValidator

    validator = ScopeValidator(program="superdrug")
    validator.is_in_scope("api.superdrug.com")     # True
    validator.is_in_scope("evil.com")              # False
    validator.filter_in_scope(all_subs)            # returns only in-scope
    validator.validate_or_fail("api.target.com")   # raises if not in scope
"""

import ipaddress
import json
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlsplit

try:
    from agents.scope_seed_files import optional_host_variants
except ModuleNotFoundError:
    from scope_seed_files import optional_host_variants

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class OutOfScopeError(Exception):
    """Raised by validate_or_fail() when a target is not in scope."""
    pass


# ---------------------------------------------------------------------------
# Scope entry types
# ---------------------------------------------------------------------------

class _ScopeEntry:
    """
    Represents a single scope entry. Can be:
    - Exact domain:   example.com
    - Wildcard:       *.example.com
    - URL pattern:    https://api.example.com/v1/*
    - CIDR:           10.0.0.0/8
    """

    def __init__(self, raw: str):
        self.raw = raw.strip()
        self._type = self._classify()

    def _classify(self) -> str:
        r = self.raw
        if not r or r.startswith("#"):
            return "comment"
        if "/" in r and not r.startswith("http"):
            try:
                ipaddress.ip_network(r, strict=False)
                return "cidr"
            except ValueError:
                pass
        if r.startswith("http://") or r.startswith("https://"):
            return "url_pattern"
        if r.startswith("*."):
            return "wildcard"
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", r):
            return "ip"
        return "domain"

    def matches(self, target: str, *, exclusion: bool = False) -> bool:
        """
        Check if target matches this scope entry.

        Target can be a hostname, IP, or full URL.
        """
        if self._type == "comment":
            return False

        # An unparseable exclusion could name any destination after another
        # parser normalizes it. Do not silently discard it as a non-match.
        if self._type != "cidr":
            if self._type == "url_pattern":
                entry_host = _extract_host(self.raw.replace("*.", "wildcard.", 1))
            else:
                entry_host = _safe_host(self.raw[2:] if self._type == "wildcard" else self.raw)
            if not entry_host:
                return exclusion

        # Normalise target: extract hostname/IP from URL if needed
        host = _extract_host(target)
        if not host:
            return exclusion

        if self._type == "domain":
            return host == _safe_host(self.raw)

        if self._type == "wildcard":
            # *.example.com matches api.example.com, x.y.example.com
            base = _safe_host(self.raw[2:])  # strip "*."
            h = host.lower()
            return h == base or h.endswith("." + base)

        if self._type == "ip":
            return host == self.raw

        if self._type == "cidr":
            try:
                network = ipaddress.ip_network(self.raw, strict=False)
                addr = ipaddress.ip_address(host)
                return addr in network
            except ValueError:
                return False

        if self._type == "url_pattern":
            return self._match_url_pattern(target, host, exclusion=exclusion)

        return False

    def _match_url_pattern(self, target: str, host: str, *, exclusion: bool) -> bool:
        """Match URL scope conservatively; a path exclusion wins ambiguity."""
        try:
            pattern_parsed = urlsplit(self.raw)
            raw_host = pattern_parsed.hostname or ""
            pattern_host = (
                "*." + _safe_host(raw_host[2:])
                if raw_host.startswith("*.") else _safe_host(raw_host)
            )
            pattern_path = pattern_parsed.path.rstrip("*")
        except ValueError:
            return False

        # Exclusions cover either HTTP scheme and every port; allows must not
        # infer permission for another origin.
        if host.lower() != pattern_host:
            wildcard_match = pattern_host.startswith("*.") and (
                host.lower().endswith(pattern_host[1:])
                or (exclusion and host.lower() == pattern_host[2:])
            )
            if not wildcard_match:
                return False

        if _ambiguous_path(pattern_path) or any(ord(c) < 32 or ord(c) == 127 for c in self.raw):
            return exclusion

        target = strip_tool_annotation(target)
        if not target.startswith(("http://", "https://")):
            # A bare hostname cannot preserve any URL origin restriction.
            # An exclusion still covers an unknown path and origin.
            return exclusion
        try:
            target_parsed = urlsplit(target)
            target_path = target_parsed.path or "/"
            pattern_port = pattern_parsed.port
            target_port = target_parsed.port
            if pattern_port is None:
                pattern_port = {"http": 80, "https": 443}.get(pattern_parsed.scheme)
            if target_port is None:
                target_port = {"http": 80, "https": 443}.get(target_parsed.scheme)
        except ValueError:
            return exclusion
        if not exclusion and (target_parsed.scheme != pattern_parsed.scheme or target_port != pattern_port):
            return False
        if pattern_path not in ("", "/") and (
            _ambiguous_path(target_path)
            or (exclusion and ":" in target_path)
            or any(ord(c) < 32 or ord(c) == 127 for c in target)
        ):
            return exclusion
        if exclusion:
            # Deny case-insensitively and include the directory itself; some
            # servers redirect /private to /private/ or fold path case.
            path = target_path.lower()
            prefix = pattern_path.lower()
            return path.startswith(prefix) or (prefix.endswith("/") and path == prefix[:-1])
        if not pattern_path or pattern_path == "/":
            return True
        if pattern_parsed.path.endswith("*") or pattern_path.endswith("/"):
            return target_path.startswith(pattern_path)
        return target_path == pattern_path or target_path.startswith(pattern_path + "/")

    @property
    def entry_type(self) -> str:
        return self._type

    @property
    def is_wildcard(self) -> bool:
        return self._type == "wildcard"

    @property
    def base_domain(self) -> Optional[str]:
        """Return the base domain for wildcard entries, else None."""
        if self._type == "wildcard":
            return self.raw[2:]
        if self._type == "domain":
            return self.raw
        return None

    def __repr__(self) -> str:
        return f"<ScopeEntry type={self._type!r} raw={self.raw!r}>"


# ---------------------------------------------------------------------------
# ScopeValidator
# ---------------------------------------------------------------------------

class ScopeValidator:
    """
    Validates targets against bug bounty program scope.

    Loads scope from:
      ~/Shared/scopes/{program}/in-scope.txt
      ~/Shared/scopes/{program}/rules-of-engagement.json
      legacy fallback: ~/Shared/bounty_recon/{program}/scope/

    Supports: exact domains, wildcards (*.example.com), URL patterns,
    CIDR ranges, and inline comments (#).

    Args:
        program:  Bug bounty program slug (e.g. "superdrug")
        strict:   If True, validate_or_fail() raises; if False it warns.
                  Defaults to True.
    """

    SCOPES_BASE = Path.home() / "Shared" / "scopes"
    LEGACY_RECON_BASE = Path.home() / "Shared" / "bounty_recon"

    # Standard scope file locations (tried in order)
    SCOPE_FILE_NAMES = [
        "scope/in-scope.txt",
        "scope/domains.txt",
        "scope/scope.txt",
        "recon/scope.txt",
    ]

    def __init__(self, program: str, strict: bool = True, scopes_base: Path | None = None):
        self.program = program
        self.strict = strict
        self.scopes_base = scopes_base or self.SCOPES_BASE
        self.policy: dict = {}
        self.platform = "unknown"
        self.source_url = None
        self.source_brief_url = None
        self.blocked_or_sensitive_classes: list[str] = []
        self._entries: list[_ScopeEntry] = []
        self._out_of_scope: list[_ScopeEntry] = []
        self.load_scope()

    # ── Loading ───────────────────────────────────────────────────────────

    def load_scope(self) -> None:
        """
        Load scope entries from standard file locations.
        Silently skips missing files — call add_domain() to add manually.
        """
        canonical_dir = self.scopes_base / self.program
        legacy_program_dir = self.LEGACY_RECON_BASE / self.program
        self._load_policy(canonical_dir / "rules-of-engagement.json")
        loaded = False
        for path in [canonical_dir / "in-scope.txt", *(legacy_program_dir / rel for rel in self.SCOPE_FILE_NAMES)]:
            if path.exists():
                self._load_file(path, is_out_of_scope=False)
                loaded = True
                break

        # Also check for out-of-scope file
        out_of_scope_candidates = [
            canonical_dir / "out-of-scope.txt",
            canonical_dir / "excluded.txt",
            legacy_program_dir / "scope/out-of-scope.txt",
            legacy_program_dir / "scope/excluded.txt",
        ]
        for path in out_of_scope_candidates:
            if path.exists():
                self._load_file(path, is_out_of_scope=True)
                break

    def _load_policy(self, path: Path) -> None:
        """Load normalized platform/rules metadata when present."""
        if not path.exists():
            return
        try:
            self.policy = json.loads(path.read_text())
            self.platform = self.policy.get("platform", "unknown")
            self.source_url = self.policy.get("source_url")
            self.source_brief_url = self.policy.get("source_brief_url")
            self.blocked_or_sensitive_classes = self.policy.get("blocked_or_sensitive_classes", [])
        except (OSError, json.JSONDecodeError) as e:
            print(f"[scope_validator] Warning: could not read policy metadata {path}: {e}")

    def _load_file(self, path: Path, is_out_of_scope: bool = False) -> None:
        """Parse a scope file and add its entries."""
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Annotations are whitespace-delimited; bare :: may be IPv6
                    # compression or part of a URL and must remain intact.
                    line = re.split(r"\s+::(?:\s+|$)", line, maxsplit=1)[0].strip()
                    for variant in optional_host_variants(line):
                        entry = _ScopeEntry(variant)
                        if entry.entry_type != "comment":
                            if is_out_of_scope:
                                self._out_of_scope.append(entry)
                            else:
                                self._entries.append(entry)
        except (OSError, PermissionError) as e:
            print(f"[scope_validator] Warning: could not read {path}: {e}")

    def load_from_file(self, path: str, is_out_of_scope: bool = False) -> None:
        """Load scope from an arbitrary file path."""
        self._load_file(Path(path).expanduser(), is_out_of_scope=is_out_of_scope)

    def add_domain(self, domain: str, is_out_of_scope: bool = False) -> None:
        """Manually add a domain or pattern to scope."""
        for variant in optional_host_variants(domain.strip()):
            entry = _ScopeEntry(variant)
            if entry.entry_type == "comment":
                continue
            if is_out_of_scope:
                self._out_of_scope.append(entry)
            else:
                self._entries.append(entry)

    def add_domains(self, domains: list[str], is_out_of_scope: bool = False) -> None:
        """Add multiple domains at once."""
        for d in domains:
            self.add_domain(d, is_out_of_scope=is_out_of_scope)

    # ── Core checks ───────────────────────────────────────────────────────

    def is_in_scope(self, target: str) -> bool:
        """
        Return True if target is within program scope.

        Checks:
        1. Target must match at least one in-scope entry
        2. Target must NOT match any out-of-scope entry

        Args:
            target: Hostname, IP, or full URL

        Returns:
            True if in scope, False otherwise
        """
        if not target or not target.strip():
            return False

        if _unsafe_controls(target):
            return False
        target = target.strip()

        # Must match at least one in-scope entry
        in_scope = any(e.matches(target) for e in self._entries)
        if not in_scope:
            return False

        # Must not match any exclusion
        excluded = any(e.matches(target, exclusion=True) for e in self._out_of_scope)
        return not excluded

    def is_out_of_scope(self, target: str) -> bool:
        """Return True if target is explicitly out of scope."""
        if not target or not target.strip():
            return False
        if _unsafe_controls(target):
            return bool(self._out_of_scope)
        return any(e.matches(target.strip(), exclusion=True) for e in self._out_of_scope)

    def is_wildcard_scope(self, domain: str) -> bool:
        """
        Check if *.domain is explicitly in scope (wildcard entry exists).

        Example:
            is_wildcard_scope("example.com") → True if *.example.com is in scope
        """
        domain = domain.lower().strip()
        for entry in self._entries:
            if entry.is_wildcard:
                base = (entry.base_domain or "").lower()
                if base == domain:
                    return True
        return False

    # ── Filtering ─────────────────────────────────────────────────────────

    def filter_in_scope(self, targets: list[str]) -> list[str]:
        """
        Filter a list of targets/URLs to only those in scope.

        Args:
            targets: List of hostnames, IPs, or URLs

        Returns:
            Filtered list containing only in-scope targets
        """
        return [t for t in targets if self.is_in_scope(t)]

    def filter_out_of_scope(self, targets: list[str]) -> list[str]:
        """Return targets that are NOT in scope."""
        return [t for t in targets if not self.is_in_scope(t)]

    def partition(self, targets: list[str]) -> tuple[list[str], list[str]]:
        """
        Partition targets into (in_scope, out_of_scope).

        Returns:
            (in_scope_list, out_of_scope_list)
        """
        in_scope = []
        out_of_scope = []
        for t in targets:
            (in_scope if self.is_in_scope(t) else out_of_scope).append(t)
        return in_scope, out_of_scope

    # ── Strict enforcement ────────────────────────────────────────────────

    def validate_or_fail(self, target: str) -> None:
        """
        Raise OutOfScopeError if target is not in scope.

        In non-strict mode (strict=False), prints a warning instead.

        Args:
            target: Hostname, IP, or full URL to validate

        Raises:
            OutOfScopeError: If target is out of scope and strict=True
        """
        if not self.is_in_scope(target):
            msg = (
                f"[scope] {target!r} is NOT in scope for program {self.program!r}. "
                f"Check the saved allow/exclusion entries and use an unambiguous full URL; "
                f"do not normalize an unknown path without verifying program scope. "
                f"In-scope entries: {self.scope_summary()}"
            )
            if self.strict:
                raise OutOfScopeError(msg)
            else:
                print(f"[!] WARNING: {msg}")

    # ── Introspection ─────────────────────────────────────────────────────

    def scope_summary(self) -> str:
        """Return a short human-readable summary of in-scope entries."""
        if not self._entries:
            return "(no scope loaded)"
        entries = [e.raw for e in self._entries[:10]]
        suffix = f" (+{len(self._entries)-10} more)" if len(self._entries) > 10 else ""
        return ", ".join(entries) + suffix

    def get_domains(self) -> list[str]:
        """Return all in-scope domain entries (exact + wildcard base domains)."""
        domains = []
        for entry in self._entries:
            base = entry.base_domain
            if base:
                domains.append(base)
        return list(dict.fromkeys(domains))  # dedup, preserve order

    def get_wildcards(self) -> list[str]:
        """Return all wildcard entries (raw form, e.g. '*.example.com')."""
        return [e.raw for e in self._entries if e.is_wildcard]

    def entry_count(self) -> int:
        return len(self._entries)

    def is_empty(self) -> bool:
        return len(self._entries) == 0

    def __repr__(self) -> str:
        return (
            f"ScopeValidator(program={self.program!r}, "
            f"entries={len(self._entries)}, "
            f"exclusions={len(self._out_of_scope)}, "
            f"strict={self.strict})"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ambiguous_path(path: str) -> bool:
    """Refuse path spellings whose interpretation can differ downstream.

    Never decode a finite number of layers: another intermediary may decode
    again. Matrix parameters and repeated separators can also be normalized.
    """
    return (
        any(char in path for char in "%\\;")
        or "//" in path
        or any(segment.endswith(".") for segment in path.split("/"))
        or any(ord(char) <= 32 or ord(char) >= 127 for char in path)
    )


# httpx-style output: a target followed only by bracketed annotations, e.g.
# "https://api.example.com [192.168.1.1]" or "... [200] [nginx]".
_TOOL_ANNOTATION = re.compile(r"^(\S+)(?:[ \t]+\[[^\]]*\])+$")


def _unsafe_controls(value: str) -> bool:
    controls = [c for c in value if ord(c) < 32 or ord(c) == 127]
    if not controls:
        return False
    # Tabs are permitted only in an exact tool-annotation shape, which is
    # stripped by the shared normalization contract before use.
    return not (all(c == "\t" for c in controls) and _TOOL_ANNOTATION.fullmatch(value.strip(" ")))


def strip_tool_annotation(value: str) -> str:
    """Drop trailing bracketed tool annotations from a single target line.

    Only the exact annotated shape is unwrapped. Any other whitespace is left
    in place so the value still fails to resolve to a host and is refused:
    a line carrying a second target must never be vouched for by checking only
    its first token. Callers that persist the value must normalize with this
    same function, so what is stored is what was scope-checked.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    match = _TOOL_ANNOTATION.match(text)
    return match.group(1) if match else text


def _extract_host(target: str) -> str:
    """
    Extract the hostname or IP from a target string.

    Handles:
    - Plain hostnames:     api.example.com
    - Full URLs:           https://api.example.com/path?q=1
    - IPs:                 192.168.1.1
    - IPs with ports:      192.168.1.1:8080
    - Annotated tool output: https://api.example.com [192.168.1.1]
    """
    if not target:
        return ""
    if _unsafe_controls(target):
        return ""
    target = strip_tool_annotation(target)
    if not target:
        return ""

    # Python and HTTP clients disagree on backslashes, encoded hosts,
    # userinfo, control characters and malformed ports. Refuse these before
    # comparing either side, rather than guessing a destination.
    if any(ord(c) < 32 or ord(c) == 127 for c in target):
        return ""
    if "\\" in target.split("?", 1)[0].split("#", 1)[0]:
        return ""
    if target.startswith("http://") or target.startswith("https://"):
        try:
            parsed = urlparse(target)
            authority = parsed.netloc
            if not re.fullmatch(r"(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::[0-9]+)?", authority):
                return ""
            # Access validates both numeric form and range of the port.
            parsed.port
            host = parsed.hostname or ""
        except ValueError:
            # Unparseable authority: report no host so callers fail closed and
            # quarantine the value instead of aborting the whole run.
            return ""
        # Drop the DNS root label: "fab.com." is the same host as "fab.com",
        # and leaving it on matches neither the allow nor the exclusion list.
        return _safe_host(host)

    # Strip port
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", target):
        if int(target.rsplit(":", 1)[1]) > 65535:
            return ""
        target = target.rsplit(":", 1)[0]

    # Strip path/query that may have been passed without scheme
    if "/" in target:
        target = target.split("/")[0]

    return _safe_host(target)


def _safe_host(host: str) -> str:
    """Accept unambiguous ASCII DNS names and canonical IP literals only."""
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or not host.isascii() or "%" in host:
        return ""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    labels = host.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        return ""
    # WHATWG clients can interpret numeric-ending names as alternate IPv4.
    if labels[-1].isdigit() or re.fullmatch(r"0x[0-9a-f]+", labels[-1]):
        return ""
    return host


def scope_from_campaign(campaign_state: dict, strict: bool = True) -> ScopeValidator:
    """
    Build a ScopeValidator directly from a campaign.json state dict.

    Args:
        campaign_state: Dict loaded from campaign.json
        strict:         Raise on out-of-scope if True

    Returns:
        Populated ScopeValidator
    """
    program = campaign_state.get("campaign_id", "unknown").split("_")[0]
    validator = ScopeValidator.__new__(ScopeValidator)
    validator.program = program
    validator.strict = strict
    validator._entries = []
    validator._out_of_scope = []

    domains = campaign_state.get("scope", {}).get("domains", [])
    for domain in domains:
        validator.add_domain(domain)

    return validator
