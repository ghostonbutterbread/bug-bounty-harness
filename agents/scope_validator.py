"""
Scope Validator — Ensures recon and testing stays within program scope.

Supports:
  - Exact domains:         example.com
  - Wildcard domains:      *.example.com
  - Host globs:            app*.example.com, customer.*.example.com
  - URL patterns:          https://api.example.com/v1/*, https://api-*.example.com/*
  - CIDR ranges:           10.0.0.0/8, 192.168.1.0/24

A leading "*." matches the base and any subdomain. Any other "*" in an allow
matches one or more characters inside one label; in an exclusion it may also
span dots, so exclusions err wide. Saved lines keep only the first " | "
column of platform exports; a description ending in a rule keeps that rule
("Infra - 192.0.2.0/24"), and pure prose lines are skipped (see
scope_seed_files.parse_scope_line). Rules are parsed once per validator.

CLI (read-only; never writes, pulls scope or uses the network):
    bbh agents/scope_validator.py classify <program> [--scopes-base DIR] --json
  reads {"targets": [...]} on stdin and prints one JSON verdict object; see
  docs/integrations/scope-check-ingest.md for the contract.

Authority spellings with percent escapes, userinfo, malformed ports, non-ASCII
hosts or backslashes are refused before comparison; an invalid exclusion can
therefore deny all targets. URL grants require a full URL, even at the root.
ASCII A-labels must pass IDNA2008 validation; this is intentionally stricter
than some browser URL parsers. Invalid exclusion authorities deny all targets.
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
  Both out-of-scope.txt and excluded.txt in the selected directory are read.
  Either canonical exclusion file, even empty, suppresses legacy fallback.
  Legacy fallback:
  ~/Shared/bounty_recon/{program}/scope/in-scope.txt
  ~/Shared/bounty_recon/{program}/scope/domains.txt
  ~/Shared/bounty_recon/{program}/scope/scope.txt
  ~/Shared/bounty_recon/{program}/recon/scope.txt

The first present allow file wins, including an empty one. Standard files that
are genuinely absent are optional; an unreadable or undecodable selected file
raises ScopeAllowReadError or ScopeExclusionReadError, both ScopeFileReadError
and OSError subclasses, with a chained cause and path. Dangling ancestor links
are not absence. Explicit load_from_file also raises on a missing file. Parse
failures use the same typed classes, with path, line number and chained cause;
manual additions identify the entry kind. Files commit entries only after full
read and parse, not as a transaction across all files. A caught failure poisons
that instance: scope checks refuse, and is_empty(), entry_count(), get_domains()
and get_wildcards() raise; reconstruct after correcting the source.
Optional host syntax expands at most eight groups (256 variants) and is limited
to 4096 characters for host patterns containing '('. Over-limit inputs raise,
including exclusions; they are never silently truncated or ignored. The shared
seed helper raises ValueError directly. URL patterns are not expanded.
Invalid allow authorities grant nothing; invalid exclusion authorities deny
all targets. These entry semantics are distinct from a file-read exception.

Callers must propagate or stop on scope-load failures, including when unscoped
operation is permitted; never turn a caught failure into empty scope. Import
ScopeValidator and its exception from the same module object. Python can load
this file as both scope_validator and agents.scope_validator, producing distinct
class identities. If the module identity is not guaranteed, catch OSError at
the construction/load boundary and abort (do not swallow or treat as absent).
This does not protect consumers that broadly catch Exception and continue.

Usage:
    from scope_validator import ScopeValidator

    validator = ScopeValidator(program="superdrug")
    validator.is_in_scope("api.superdrug.com")     # True
    validator.is_in_scope("evil.com")              # False
    validator.filter_in_scope(all_subs)            # returns only in-scope
    validator.validate_or_fail("api.target.com")   # raises if not in scope
"""

import hashlib
import ipaddress
import json
import re
import stat
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlsplit

import idna

try:
    from agents.scope_seed_files import optional_host_variants, parse_scope_line
except ModuleNotFoundError:
    from scope_seed_files import optional_host_variants, parse_scope_line

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class OutOfScopeError(Exception):
    """Raised by validate_or_fail() when a target is not in scope."""
    pass


class ScopeFileReadError(OSError):
    """A scope source could not be inspected, read, decoded, or parsed."""


class ScopeAllowReadError(ScopeFileReadError):
    """An allow file could not be read; callers must refuse the run."""


class ScopeExclusionReadError(ScopeFileReadError):
    """An exclusion file could not be read; callers must refuse the run."""


# ---------------------------------------------------------------------------
# Scope entry types
# ---------------------------------------------------------------------------

_HOST_IN_LABEL = "[a-z0-9-]+"
_HOST_ACROSS_LABELS = "[a-z0-9.-]+"


class _HostGlob:
    """Precompiled host glob with distinct allow and exclusion semantics.

    A leading ``*.`` keeps the caller's subdomain meaning. Any other ``*``
    matches one or more characters inside a single label for an allow, so an
    include stays narrow, and may also span dots for an exclusion, so a denial
    errs wide.
    """

    __slots__ = ("allow", "deny")

    def __init__(self, pattern: str, *, allow_base: bool, deny_base: bool = True):
        pattern = pattern.lower().rstrip(".")
        lead = pattern.startswith("*.")
        body = pattern[2:] if lead else pattern

        def compile_(star: str, base: bool) -> "re.Pattern[str]":
            core = "".join(star if ch == "*" else re.escape(ch) for ch in body)
            prefix = ""
            if lead:
                prefix = f"(?:{_HOST_ACROSS_LABELS}\\.)" + ("?" if base else "")
            return re.compile(prefix + core)

        self.allow = compile_(_HOST_IN_LABEL, allow_base)
        self.deny = compile_(_HOST_ACROSS_LABELS, deny_base)

    def matches(self, host: str, *, exclusion: bool) -> bool:
        return bool((self.deny if exclusion else self.allow).fullmatch(host))


def _glob_host_is_valid(pattern: str) -> bool:
    """A glob is usable when replacing each ``*`` with a letter yields a safe host."""
    pattern = pattern.lower().rstrip(".")
    lead = "*." if pattern.startswith("*.") else ""
    return bool(_safe_host("a." * bool(lead) + pattern[len(lead):].replace("*", "a")))


class _ScopeEntry:
    """
    Represents a single scope entry. Can be:
    - Exact domain:   example.com
    - Wildcard:       *.example.com
    - Host glob:      app*.example.com, customer.*.example.com
    - URL pattern:    https://api.example.com/v1/*
    - CIDR:           10.0.0.0/8

    Rules are parsed once at construction; matching reuses the parsed form.
    ``source`` is the rule text from the scope line before optional-group
    expansion, used to report which rule decided a verdict.
    """

    def __init__(self, raw: str, source: Optional[str] = None, *, exclusion: bool = False):
        self.raw = raw.strip()
        self.source = (source if source is not None else raw).strip()
        # Exclusion globs may be wide; allow globs must stay narrow.
        self.exclusion = exclusion
        self._type = self._classify()
        self._prepare()

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
        if "*" in (r[2:] if r.startswith("*.") else r):
            return "glob"
        if r.startswith("*."):
            return "wildcard"
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", r):
            return "ip"
        return "domain"

    def _prepare(self) -> None:
        self._invalid = False
        self._host = ""
        self._network = None
        self._glob: Optional[_HostGlob] = None
        self._url_parsed = None
        self._url_path = ""
        self._url_ambiguous = False
        kind = self._type
        if kind == "comment":
            return
        if kind == "cidr":
            self._network = ipaddress.ip_network(self.raw, strict=False)
        elif kind == "domain":
            self._host = _safe_host(self.raw)
            self._invalid = not self._host
        elif kind == "wildcard":
            self._host = _safe_host(self.raw[2:])
            self._invalid = not self._host
        elif kind == "ip":
            self._host = self.raw
            self._invalid = not _safe_host(self.raw)
        elif kind == "glob":
            self._invalid = not _glob_host_is_valid(self.raw)
            if not self._invalid:
                self._glob = _HostGlob(self.raw, allow_base=True)
        elif kind == "url_pattern":
            self._prepare_url()

    def _prepare_url(self) -> None:
        scheme, sep, rest = self.raw.partition("://")
        authority_end = len(rest)
        for ch in "/?#":
            index = rest.find(ch)
            if index != -1:
                authority_end = min(authority_end, index)
        authority = rest[:authority_end]
        # Validate the authority with each glob star replaced by a letter so
        # infix host globs are accepted while every other spelling rule holds.
        probe = scheme + sep + authority.replace("*", "a") + rest[authority_end:]
        if not _extract_host(probe):
            self._invalid = True
            return
        try:
            parsed = urlsplit(self.raw)
            raw_host = (parsed.hostname or "").rstrip(".")
            parsed.port
        except ValueError:
            self._invalid = True
            return
        self._url_parsed = parsed
        self._url_path = parsed.path.rstrip("*")
        self._url_ambiguous = _ambiguous_path(self._url_path) or any(
            ord(c) < 32 or ord(c) == 127 for c in self.raw
        )
        if "*" in raw_host:
            # An allow URL wildcard does not grant the bare base host; an
            # exclusion URL wildcard also covers it.
            self._glob = _HostGlob(raw_host, allow_base=False)
        else:
            self._host = _safe_host(raw_host)

    # ── Matching ──────────────────────────────────────────────────────────

    def matches(self, target: str, *, exclusion: bool = False) -> bool:
        """
        Check if target matches this scope entry.

        Target can be a hostname, IP, or full URL.
        """
        host = _extract_host(target) if self._type != "comment" and not self._invalid else ""
        return self._match(target, host, _ip_or_none(host), exclusion=exclusion)

    def _match(self, target: str, host: str, addr, *, exclusion: bool) -> bool:
        """Match with the target host (and parsed IP, if any) computed once by the caller."""
        if self._type == "comment":
            return False

        # An unparseable exclusion could name any destination after another
        # parser normalizes it. Do not silently discard it as a non-match.
        if self._invalid:
            return exclusion
        if not host:
            return exclusion

        if self._type == "url_pattern":
            return self._match_url_pattern(target, host, exclusion=exclusion)
        return self._match_host(host, addr, exclusion=exclusion)

    def _match_host(self, host: str, addr, *, exclusion: bool) -> bool:
        """Host-level comparison only; for URL rules this ignores scheme, port and path."""
        kind = self._type
        if kind in ("domain", "ip"):
            return host == self._host
        if kind == "wildcard":
            # *.example.com matches example.com, api.example.com, x.y.example.com
            return host == self._host or host.endswith("." + self._host)
        if kind == "cidr":
            return addr is not None and addr.version == self._network.version and addr in self._network
        if kind == "glob":
            return self._glob.matches(host, exclusion=exclusion)
        if kind == "url_pattern":
            if self._glob is not None:
                return self._glob.matches(host, exclusion=exclusion)
            return host == self._host
        return False

    def has_invalid_authority(self) -> bool:
        return self._invalid

    @property
    def path_limited(self) -> bool:
        """True for a URL rule restricted to a path below the root."""
        return self._type == "url_pattern" and self._url_path not in ("", "/")

    def _match_url_pattern(self, target: str, host: str, *, exclusion: bool) -> bool:
        """Match URL scope conservatively; a path exclusion wins ambiguity."""
        # Exclusions cover either HTTP scheme and every port; allows must not
        # infer permission for another origin.
        if not self._match_host(host, None, exclusion=exclusion):
            return False

        if self._url_ambiguous:
            return exclusion

        pattern_parsed = self._url_parsed
        pattern_path = self._url_path
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
        scopes_base, legacy_recon_base: override the canonical and legacy
                  roots (defaults: SCOPES_BASE and LEGACY_RECON_BASE).
        include_legacy: False reads only the canonical scope directory.
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

    def __init__(self, program: str, strict: bool = True, scopes_base: Path | None = None,
                 legacy_recon_base: Path | None = None, *, include_legacy: bool = True):
        self.program = program
        self.strict = strict
        self.scopes_base = scopes_base or self.SCOPES_BASE
        self.legacy_recon_base = legacy_recon_base or self.LEGACY_RECON_BASE
        self.include_legacy = include_legacy
        self.policy: dict = {}
        self.platform = "unknown"
        self.source_url = None
        self.source_brief_url = None
        self.blocked_or_sensitive_classes: list[str] = []
        self._entries: list[_ScopeEntry] = []
        self._out_of_scope: list[_ScopeEntry] = []
        # (kind, line) for saved lines skipped as prose, and for exclusion
        # lines whose rules were kept but prose remained ("lossy"). Callers
        # needing every line represented (the Recon-Ry handoff) refuse on both.
        self.skipped_scope_lines: list[tuple[str, str]] = []
        self.lossy_scope_lines: list[tuple[str, str]] = []
        self._scope_file_load_error: ScopeFileReadError | None = None
        self.load_scope()

    # ── Loading ───────────────────────────────────────────────────────────

    def load_scope(self) -> None:
        """
        Load scope entries from standard file locations.
        Missing standard files are optional. An unreadable allow or exclusion
        raises ScopeFileReadError; never convert it into unscoped permission.
        Call add_domain() to add entries manually.
        """
        canonical_dir = self.scopes_base / self.program
        legacy_program_dir = self.legacy_recon_base / self.program
        self._load_policy(canonical_dir / "rules-of-engagement.json")
        legacy_allow = [legacy_program_dir / rel for rel in self.SCOPE_FILE_NAMES] if self.include_legacy else []
        for path in [canonical_dir / "in-scope.txt", *legacy_allow]:
            if self._load_file(path, is_out_of_scope=False, optional=True):
                break

        # Canonical sources take precedence over legacy, including when empty.
        # Within the selected directory both names contribute exclusions.
        for directory in (canonical_dir, legacy_program_dir / "scope")[: 2 if self.include_legacy else 1]:
            present = False
            for name in ("out-of-scope.txt", "excluded.txt"):
                present = self._load_file(directory / name, is_out_of_scope=True, optional=True) or present
            if present:
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

    def _load_file(self, path: Path, is_out_of_scope: bool = False, *, optional: bool = False) -> bool:
        """Parse a scope file and add its entries."""
        line_number = 0
        opened = False
        try:
            entries = []
            skipped = []
            lossy = []
            f = open(path, encoding="utf-8")
            opened = True
            with f as source:
                for line_number, line in enumerate(source, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Annotations are whitespace-delimited; bare :: may be IPv6
                    # compression or part of a URL and must remain intact.
                    line = re.split(r"\s+::(?:\s+|$)", line, maxsplit=1)[0].strip()
                    # Platform-export columns (" | ") and prose descriptions
                    # are not rules; see parse_scope_line.
                    rules, status = parse_scope_line(line, exclusion=is_out_of_scope)
                    kind = "exclusion" if is_out_of_scope else "grant"
                    if status == "skipped":
                        skipped.append((kind, line))
                    elif status == "lossy":
                        lossy.append((kind, line))
                    for rule in rules:
                        for variant in optional_host_variants(rule):
                            entry = _ScopeEntry(variant, source=rule, exclusion=is_out_of_scope)
                            if entry.entry_type != "comment":
                                entries.append(entry)
            (self._out_of_scope if is_out_of_scope else self._entries).extend(entries)
            if skipped or lossy:
                for name, found in (("skipped_scope_lines", skipped), ("lossy_scope_lines", lossy)):
                    if not hasattr(self, name):
                        setattr(self, name, [])
                    getattr(self, name).extend(found)
            return True
        except FileNotFoundError as e:
            if optional and not opened:
                try:
                    path.lstat()
                except FileNotFoundError:
                    # A missing leaf can conceal a dangling ancestor symlink.
                    # Only genuine absence permits the legacy fallback.
                    try:
                        for ancestor in path.parents:
                            try:
                                info = ancestor.lstat()
                            except FileNotFoundError:
                                continue
                            if stat.S_ISLNK(info.st_mode):
                                ancestor.stat()
                    except FileNotFoundError:
                        pass  # report the original open error below
                    except OSError as stat_error:
                        kind = "exclusion" if is_out_of_scope else "allow"
                        error_type = ScopeExclusionReadError if is_out_of_scope else ScopeAllowReadError
                        error = error_type(f"could not inspect {kind} file {path}: {stat_error}")
                        self._scope_file_load_error = error
                        raise error from stat_error
                    else:
                        return False
                except OSError as stat_error:
                    kind = "exclusion" if is_out_of_scope else "allow"
                    error_type = ScopeExclusionReadError if is_out_of_scope else ScopeAllowReadError
                    error = error_type(f"could not inspect {kind} file {path}: {stat_error}")
                    self._scope_file_load_error = error
                    raise error from stat_error
            kind = "exclusion" if is_out_of_scope else "allow"
            error_type = ScopeExclusionReadError if is_out_of_scope else ScopeAllowReadError
            error = error_type(f"could not read {kind} file {path}: {e}")
            self._scope_file_load_error = error
            raise error from e
        except (OSError, UnicodeError) as e:
            kind = "exclusion" if is_out_of_scope else "allow"
            error_type = ScopeExclusionReadError if is_out_of_scope else ScopeAllowReadError
            error = error_type(f"could not read {kind} file {path}: {e}")
            self._scope_file_load_error = error
            raise error from e
        except Exception as e:
            kind = "exclusion" if is_out_of_scope else "allow"
            error_type = ScopeExclusionReadError if is_out_of_scope else ScopeAllowReadError
            error = error_type(f"could not parse {kind} file {path} at line {line_number}: {e}")
            self._scope_file_load_error = error
            raise error from e

    def load_from_file(self, path: str, is_out_of_scope: bool = False) -> None:
        """Load a file; read or parse failure poisons this validator and raises."""
        self._load_file(Path(path).expanduser(), is_out_of_scope=is_out_of_scope)

    def add_domain(self, domain: str, is_out_of_scope: bool = False) -> None:
        """Manually add a domain or pattern to scope."""
        try:
            entries = [
                _ScopeEntry(variant, source=domain.strip(), exclusion=is_out_of_scope)
                for variant in optional_host_variants(domain.strip())
            ]
            entries = [entry for entry in entries if entry.entry_type != "comment"]
            (self._out_of_scope if is_out_of_scope else self._entries).extend(entries)
        except Exception as e:
            kind = "exclusion" if is_out_of_scope else "allow"
            error_type = ScopeExclusionReadError if is_out_of_scope else ScopeAllowReadError
            error = error_type(f"could not parse manual {kind} entry: {e}")
            self._scope_file_load_error = error
            raise error from e

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

        if getattr(self, "_scope_file_load_error", None):
            return False

        host = _extract_host(target)
        addr = _ip_or_none(host)
        # Must match at least one in-scope entry
        in_scope = any(e._match(target, host, addr, exclusion=False) for e in self._entries)
        if not in_scope:
            return False

        # Must not match any exclusion
        excluded = any(e._match(target, host, addr, exclusion=True) for e in self._out_of_scope)
        return not excluded

    def is_out_of_scope(self, target: str) -> bool:
        """Return True if target is explicitly out of scope."""
        if getattr(self, "_scope_file_load_error", None):
            return True
        if not target or not target.strip():
            return False
        if _unsafe_controls(target):
            return bool(self._out_of_scope)
        target = target.strip()
        host = _extract_host(target)
        addr = _ip_or_none(host)
        return any(e._match(target, host, addr, exclusion=True) for e in self._out_of_scope)

    def is_wildcard_scope(self, domain: str) -> bool:
        """
        Check whether a valid wildcard root is declared and not wholly excluded.

        This is not authorization for each host or path under the root. Exact
        host, narrower wildcard, and path exclusions remain separately enforced
        by is_in_scope; consumers must check every target and redirect.

        Example:
            is_wildcard_scope("example.com") → True if *.example.com is in scope
        """
        if getattr(self, "_scope_file_load_error", None) or any(
            entry.has_invalid_authority() for entry in self._out_of_scope
        ):
            return False
        domain = _safe_host(domain.strip())
        if not domain:
            return False
        # Only exclusions covering the whole represented wildcard erase the
        # root. A narrower host, sub-wildcard or path remains a separate deny.
        for entry in self._out_of_scope:
            if entry.is_wildcard and entry.matches(domain, exclusion=True):
                return False
            if entry.entry_type == "url_pattern":
                parsed = urlsplit(entry.raw)  # authorities validated above
                path = parsed.path.rstrip("*")
                if (parsed.hostname or "").startswith("*.") and (
                    path in ("", "/") or _ambiguous_path(path)
                    or any(ord(c) < 32 or ord(c) == 127 for c in entry.raw)
                ) and entry.matches(domain, exclusion=True):
                    return False
        for entry in self._entries:
            if entry.is_wildcard and not entry.has_invalid_authority():
                base = _safe_host(entry.base_domain or "")
                if base == domain:
                    return True
        return False

    # ── Display classification ────────────────────────────────────────────

    def classify_target(self, target: str) -> tuple[str, Optional[str], str]:
        """Return ``(state, rule, reason)`` for one host or full http(s) URL.

        ``state`` is ``in``, ``out`` or ``partial``. A full URL is decided
        exactly with the same logic as is_in_scope. A bare host is ``partial``
        when its verdict depends on the path: only path-limited URL rules grant
        it, or a host rule grants it but a path-limited exclusion applies. A
        root URL rule (no path) grants its bare host here, because a host
        cannot carry the scheme or port the rule names; is_in_scope stays
        stricter for that case. ``rule`` is the deciding rule text or None.
        """
        if getattr(self, "_scope_file_load_error", None):
            raise self._scope_file_load_error
        text = str(target or "").strip()
        if not text:
            return "out", None, "empty target"
        if _unsafe_controls(text):
            return "out", None, "target contains control characters"
        for entry in self._out_of_scope:
            if entry.has_invalid_authority():
                return "out", entry.source, f"unusable exclusion {entry.source} refuses all targets"

        if strip_tool_annotation(text).startswith(("http://", "https://")):
            host = _extract_host(text)
            if not host:
                return "out", None, "not a valid host or URL"
            addr = _ip_or_none(host)
            for entry in self._out_of_scope:
                if entry._match(text, host, addr, exclusion=True):
                    return "out", entry.source, f"excluded by {entry.source}"
            for entry in self._entries:
                if entry._match(text, host, addr, exclusion=False):
                    return "in", entry.source, f"matches {entry.source}"
            return "out", None, "no in-scope rule matches"

        # Bare host; tolerate a trailing :port on a DNS name.
        port_match = re.fullmatch(r"([^:/\[\]]+):(\d{1,5})", text)
        if port_match and int(port_match.group(2)) <= 65535:
            text = port_match.group(1)
        host = _extract_host(text)
        if not host or "/" in text:
            return "out", None, "not a valid host or URL"
        addr = _ip_or_none(host)

        path_exclusion = None
        for entry in self._out_of_scope:
            if not entry._match_host(host, addr, exclusion=True):
                continue
            if entry.path_limited and not entry._url_ambiguous:
                path_exclusion = path_exclusion or entry
            else:
                return "out", entry.source, f"excluded by {entry.source}"

        path_include = None
        for entry in self._entries:
            if entry.has_invalid_authority() or entry.entry_type == "comment":
                continue
            if not entry._match_host(host, addr, exclusion=False):
                continue
            if entry.entry_type != "url_pattern" or not entry.path_limited:
                if path_exclusion is not None:
                    return (
                        "partial", entry.source,
                        f"in scope except paths under {path_exclusion._url_path} ({path_exclusion.source})",
                    )
                return "in", entry.source, f"matches {entry.source}"
            if not entry._url_ambiguous:
                path_include = path_include or entry
        if path_include is not None:
            return "partial", path_include.source, f"only paths under {path_include._url_path} are in scope"
        return "out", None, "no in-scope rule matches"

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
            reason = ""
            if getattr(self, "_scope_file_load_error", None):
                reason = f"Scope file read failed: {self._scope_file_load_error}. "
            elif any(e.has_invalid_authority() for e in self._out_of_scope):
                reason = "Unusable scope: invalid exclusion authority; refusing all targets. "
            elif any(e.has_invalid_authority() for e in self._entries):
                reason = "Unusable scope entry: invalid allow authority grants no access; correct the saved scope. "
            msg = (
                f"[scope] {target!r} is NOT in scope for program {self.program!r}. "
                f"{reason}"
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
        if getattr(self, "_scope_file_load_error", None):
            return "(unusable scope: load failed)"
        skipped = len(getattr(self, "skipped_scope_lines", []))
        note = f" ({skipped} saved scope line(s) skipped as prose)" if skipped else ""
        if not self._entries:
            return "(no scope loaded)" + note
        entries = [e.raw for e in self._entries[:10]]
        suffix = f" (+{len(self._entries)-10} more)" if len(self._entries) > 10 else ""
        return ", ".join(entries) + suffix + note

    def get_domains(self) -> list[str]:
        """Return all in-scope domain entries (exact + wildcard base domains)."""
        self.is_empty()  # A caught load failure must not expose partial grants.
        domains = []
        for entry in self._entries:
            base = entry.base_domain
            if base:
                domains.append(base)
        return list(dict.fromkeys(domains))  # dedup, preserve order

    def get_wildcards(self) -> list[str]:
        """Return all wildcard entries (raw form, e.g. '*.example.com')."""
        self.is_empty()
        return [e.raw for e in self._entries if e.is_wildcard]

    def entry_count(self) -> int:
        self.is_empty()
        return len(self._entries)

    def is_empty(self) -> bool:
        error = getattr(self, "_scope_file_load_error", None)
        if error is not None:
            raise error
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


def _ip_or_none(host: str):
    """Parse a canonical host string as an IP address once per target."""
    if not host or not (host[0].isdigit() or ":" in host):
        return None
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


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
    for label in labels:
        if label.startswith("xn--"):
            try:
                # IDNA2008 validation rejects malformed A-labels without the
                # legacy stdlib codec's transitional mapping of e.g. ß.
                idna.decode(label, uts46=True, std3_rules=True)
            except idna.IDNAError:
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


# ---------------------------------------------------------------------------
# classify CLI (read-only; never writes, pulls scope, or touches the network)
# ---------------------------------------------------------------------------

CLASSIFY_VERSION = 1
CLASSIFY_MAX_TARGETS = 50_000
_CLASSIFY_SCOPE_FILES = ("in-scope.txt", "out-of-scope.txt", "excluded.txt")


class ClassifyUsageError(ValueError):
    """Bad classify input; the CLI reports it on stderr and exits non-zero."""


def classify_program(program: str, targets: list, scopes_base: Path | None = None) -> dict:
    """Classify targets against one saved program scope for display filtering.

    Reads only ``<scopes_base>/<program>/`` (no legacy fallback). A missing
    scope directory or one without usable in-scope entries is not an error:
    every target is reported ``unchecked``. Read or parse failures of a present
    scope file raise ScopeFileReadError.
    """
    if not isinstance(program, str) or not program or program in (".", "..") or "/" in program or "\0" in program:
        raise ClassifyUsageError("program must be a single scope directory name")
    if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
        raise ClassifyUsageError('"targets" must be a list of strings')
    if len(targets) > CLASSIFY_MAX_TARGETS:
        raise ClassifyUsageError(f"too many targets: {len(targets)} > {CLASSIFY_MAX_TARGETS}")

    base = Path(scopes_base).expanduser() if scopes_base else ScopeValidator.SCOPES_BASE
    scope_dir = base / program
    digest = hashlib.sha256()
    validator = None
    if scope_dir.is_dir():
        scope_dir = scope_dir.resolve()
        for name in _CLASSIFY_SCOPE_FILES:
            path = scope_dir / name
            try:
                data = path.read_bytes()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ScopeFileReadError(f"could not read scope file {path}: {exc}") from exc
            digest.update(f"{name}\0{len(data)}\0".encode())
            digest.update(data)
        validator = ScopeValidator(
            scope_dir.name, strict=False, scopes_base=scope_dir.parent, include_legacy=False,
        )
        validator.is_empty()  # raises on a caught load failure
        usable = any(not entry.has_invalid_authority() for entry in validator._entries)
        state = "loaded" if usable else "empty"
    else:
        scope_dir = scope_dir.absolute()
        state = "missing"

    if state == "loaded":
        results = []
        for target in targets:
            verdict, rule, reason = validator.classify_target(target)
            results.append({"target": target, "state": verdict, "rule": rule, "reason": reason})
    else:
        results = [
            {"target": target, "state": "unchecked", "rule": None, "reason": "no scope on file"}
            for target in targets
        ]
    return {
        "version": CLASSIFY_VERSION,
        "program": program,
        "scope_dir": str(scope_dir),
        "scope_state": state,
        "signature": digest.hexdigest(),
        "entries": len(validator._entries) if validator else 0,
        "exclusions": len(validator._out_of_scope) if validator else 0,
        "skipped_lines": len(validator.skipped_scope_lines) if validator else 0,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="BBH scope validator tools")
    sub = parser.add_subparsers(dest="cmd", required=True)
    classify = sub.add_parser(
        "classify",
        help='Classify hosts/URLs read as {"targets": [...]} JSON on stdin; prints one JSON object.',
    )
    classify.add_argument("program", help="Scope directory name under --scopes-base")
    classify.add_argument("--scopes-base", type=Path, default=None,
                          help=f"Scope root (default: {ScopeValidator.SCOPES_BASE})")
    classify.add_argument("--json", action="store_true", help="Emit JSON (the only output format)")
    args = parser.parse_args(argv)

    try:
        try:
            payload = json.loads(sys.stdin.read())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ClassifyUsageError(f"stdin is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict) or "targets" not in payload:
            raise ClassifyUsageError('stdin must be a JSON object with a "targets" list')
        result = classify_program(args.program, payload["targets"], args.scopes_base)
    except ClassifyUsageError as exc:
        print(f"scope_validator classify: usage error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"scope_validator classify: {' '.join(str(exc).split())}", file=sys.stderr)
        return 1
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
