"""
Scope Validator — Ensures recon and testing stays within program scope.

Supports:
  - Exact domains:         example.com
  - Wildcard domains:      *.example.com
  - URL patterns:          https://api.example.com/v1/*
  - CIDR ranges:           10.0.0.0/8, 192.168.1.0/24

Scope files are loaded from standard locations:
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
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

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

    def matches(self, target: str) -> bool:
        """
        Check if target matches this scope entry.

        Target can be a hostname, IP, or full URL.
        """
        if self._type == "comment":
            return False

        # Normalise target: extract hostname/IP from URL if needed
        host = _extract_host(target)
        if not host:
            return False

        if self._type == "domain":
            return host.lower() == self.raw.lower()

        if self._type == "wildcard":
            # *.example.com matches api.example.com, x.y.example.com
            base = self.raw[2:].lower()  # strip "*."
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
            return self._match_url_pattern(target, host)

        return False

    def _match_url_pattern(self, target: str, host: str) -> bool:
        """
        Match a URL pattern like https://api.example.com/v1/*.
        Supports * glob at end of path.
        """
        pattern_parsed = urlparse(self.raw)
        pattern_host = pattern_parsed.hostname or ""
        pattern_path = pattern_parsed.path.rstrip("*")

        # Host must match exactly or via wildcard prefix
        if host.lower() != pattern_host.lower():
            if not (pattern_host.startswith("*.") and
                    host.lower().endswith(pattern_host[1:].lower())):
                return False

        # Path check: only applies if target is a full URL
        if target.startswith("http://") or target.startswith("https://"):
            target_path = urlparse(target).path
            if pattern_path and not target_path.startswith(pattern_path):
                return False

        return True

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
      ~/Shared/bounty_recon/{program}/scope/in-scope.txt
      ~/Shared/bounty_recon/{program}/scope/domains.txt

    Supports: exact domains, wildcards (*.example.com), URL patterns,
    CIDR ranges, and inline comments (#).

    Args:
        program:  Bug bounty program slug (e.g. "superdrug")
        strict:   If True, validate_or_fail() raises; if False it warns.
                  Defaults to True.
    """

    RECON_BASE = Path.home() / "Shared" / "bounty_recon"

    # Standard scope file locations (tried in order)
    SCOPE_FILE_NAMES = [
        "scope/in-scope.txt",
        "scope/domains.txt",
        "scope/scope.txt",
        "recon/scope.txt",
    ]

    def __init__(self, program: str, strict: bool = True):
        self.program = program
        self.strict = strict
        self._entries: list[_ScopeEntry] = []
        self._out_of_scope: list[_ScopeEntry] = []
        self.load_scope()

    # ── Loading ───────────────────────────────────────────────────────────

    def load_scope(self) -> None:
        """
        Load scope entries from standard file locations.
        Silently skips missing files — call add_domain() to add manually.
        """
        program_dir = self.RECON_BASE / self.program
        loaded = False
        for rel in self.SCOPE_FILE_NAMES:
            path = program_dir / rel
            if path.exists():
                self._load_file(path, is_out_of_scope=False)
                loaded = True
                break

        # Also check for out-of-scope file
        out_of_scope_candidates = [
            program_dir / "scope/out-of-scope.txt",
            program_dir / "scope/excluded.txt",
        ]
        for path in out_of_scope_candidates:
            if path.exists():
                self._load_file(path, is_out_of_scope=True)
                break

    def _load_file(self, path: Path, is_out_of_scope: bool = False) -> None:
        """Parse a scope file and add its entries."""
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    entry = _ScopeEntry(line)
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
        entry = _ScopeEntry(domain.strip())
        if entry.entry_type == "comment":
            return
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

        target = target.strip()

        # Must match at least one in-scope entry
        in_scope = any(e.matches(target) for e in self._entries)
        if not in_scope:
            return False

        # Must not match any exclusion
        excluded = any(e.matches(target) for e in self._out_of_scope)
        return not excluded

    def is_out_of_scope(self, target: str) -> bool:
        """Return True if target is explicitly out of scope."""
        return not self.is_in_scope(target)

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

def _extract_host(target: str) -> str:
    """
    Extract the hostname or IP from a target string.

    Handles:
    - Plain hostnames:     api.example.com
    - Full URLs:           https://api.example.com/path?q=1
    - IPs:                 192.168.1.1
    - IPs with ports:      192.168.1.1:8080
    """
    if not target:
        return ""
    target = target.strip()

    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return (parsed.hostname or "").lower()

    # Strip port
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", target):
        return target.rsplit(":", 1)[0]

    # Strip path/query that may have been passed without scheme
    if "/" in target:
        target = target.split("/")[0]

    return target.lower()


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
