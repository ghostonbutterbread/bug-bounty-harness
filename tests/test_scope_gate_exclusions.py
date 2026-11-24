"""Scope gates honor explicit exclusions and refuse ambiguous authorities.

Synthetic scope files only; no DNS or HTTP. ScopeManager must agree with
ScopeValidator on exclusions, and every host gate must refuse an authority
that Python's ``urlparse`` and a request-issuing client read differently
(``https://login.example.com\\@api.example.com`` goes to ``login`` in a
browser; ``urlparse`` reports ``api``).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from agents.recon import asset_intelligence
from agents.scope_manager import ScopeManager
from agents.scope_validator import ScopeExclusionReadError, ScopeValidator
from harness_core import HarnessConstraints, HarnessViolation

PROGRAM = "synthetic"

AMBIGUOUS = [
    "https://login.example.com\\@api.example.com/",
    "https://evil.test\\.example.com/",
    "https://evil.test\\.example.com",
    "https://user@api.example.com/",
    "https://api.example.com@evil.test/",
    "https://api.example.com\t.evil.test/",
    "https://api.example.com\n/",
    "https://api.example.com%2eevil.test/",
    "https://api.example.com:99999/",
    "https://api.example.com:bad/",
    "login.example.com\\@api.example.com",
    "evil.test?x=.example.com",
    "evil.test#.example.com",
]


@pytest.fixture
def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    canonical = tmp_path / "scopes"
    legacy = tmp_path / "legacy"
    for cls in (ScopeManager, ScopeValidator):
        monkeypatch.setattr(cls, "SCOPES_BASE", canonical)
        monkeypatch.setattr(cls, "LEGACY_RECON_BASE", legacy)
    return canonical / PROGRAM, legacy / PROGRAM / "scope"


def _write(directory: Path, name: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(body, encoding="utf-8")


# --- ScopeManager exclusions ---------------------------------------------------

@pytest.mark.parametrize("filename", ["out-of-scope.txt", "excluded.txt"])
@pytest.mark.parametrize("exclusion", [
    "login.example.com",
    "LOGIN.example.com. :: third-party SSO",
    "*.login.example.com",
    "https://login.example.com/",
    "http://login.example.com/private/",
])
@pytest.mark.parametrize("target", [
    "login.example.com",
    "https://login.example.com/private/x",
    "https://LOGIN.example.com.:8443/private/x",
])
def test_excluded_host_under_allowed_wildcard_is_refused(roots, filename, exclusion, target):
    canonical, _ = roots
    _write(canonical, "in-scope.txt", "*.example.com\n")
    _write(canonical, filename, exclusion + "\n")

    manager = ScopeManager(PROGRAM)

    assert manager.is_in_scope(target) is False
    assert manager.is_in_scope("https://api.example.com/") is True


def test_path_exclusion_leaves_sibling_paths_like_scope_validator(roots):
    canonical, _ = roots
    _write(canonical, "in-scope.txt", "*.example.com\n")
    _write(canonical, "out-of-scope.txt", "http://login.example.com/private/\n")
    manager, validator = ScopeManager(PROGRAM), ScopeValidator(PROGRAM)

    for target, expected in (("https://login.example.com/", True),
                             ("https://login.example.com/PRIVATE", False),
                             ("login.example.com", False)):
        assert manager.is_in_scope(target) is expected is validator.is_in_scope(target), target


def test_legacy_exclusions_apply_only_without_canonical_exclusion_files(roots):
    canonical, legacy = roots
    _write(canonical, "in-scope.txt", "*.example.com\n")
    _write(legacy, "out-of-scope.txt", "legacy.example.com\n")
    assert ScopeManager(PROGRAM).is_in_scope("legacy.example.com") is False

    # A canonical exclusion file, even empty, supersedes legacy (ScopeValidator rule).
    _write(canonical, "excluded.txt", "")
    manager = ScopeManager(PROGRAM)
    assert manager.is_in_scope("legacy.example.com") is True
    assert ScopeValidator(PROGRAM).is_in_scope("legacy.example.com") is True


def test_missing_exclusion_files_leave_allow_behavior_unchanged(roots):
    canonical, legacy = roots
    _write(canonical, "in-scope.txt", "api.example.com\n*.example.net\nhttps://app.example.org\n")
    _write(legacy, "domains.txt", "legacy.example.io\n")

    manager = ScopeManager(PROGRAM)

    assert manager.domains == {"api.example.com", "*.example.net", "legacy.example.io"}
    assert manager.urls == {"https://app.example.org"}
    for target in ("api.example.com", "https://api.example.com/x", "example.net",
                   "https://deep.sub.example.net/", "legacy.example.io",
                   "https://app.example.org", "https://app.example.org/any/path"):
        assert manager.is_in_scope(target) is True, target
    for target in ("badexample.net", "https://other.example.com/", "https://example.org/"):
        assert manager.is_in_scope(target) is False, target


def test_invalid_exclusion_authority_denies_everything_like_scope_validator(roots):
    canonical, _ = roots
    _write(canonical, "in-scope.txt", "*.example.com\n")
    _write(canonical, "out-of-scope.txt", "login.example.com\\@api.example.com\n")

    assert ScopeManager(PROGRAM).is_in_scope("https://api.example.com/") is False
    assert ScopeValidator(PROGRAM).is_in_scope("https://api.example.com/") is False


def test_unreadable_exclusion_file_refuses_construction(roots):
    canonical, _ = roots
    _write(canonical, "in-scope.txt", "*.example.com\n")
    (canonical / "out-of-scope.txt").mkdir()

    with pytest.raises(ScopeExclusionReadError):
        ScopeManager(PROGRAM)


@pytest.mark.parametrize("target", [
    "api.example.com", "login.example.com", "deep.login.example.com",
    "https://api.example.com/", "https://login.example.com/x",
    "https://api.example.com/private/a", "http://api.example.com:8080/private/",
    "https://partner.example.com/", "partner.example.com", "example.com",
    "https://bücher.example.com/", "https://xn--bcher-kva.example.com/",
    *AMBIGUOUS,
])
def test_scope_manager_agrees_with_scope_validator(roots, target):
    canonical, _ = roots
    _write(canonical, "in-scope.txt", "*.example.com\nexample.com\n")
    _write(canonical, "out-of-scope.txt", "*.login.example.com\nlogin.example.com\n")
    _write(canonical, "excluded.txt", "https://api.example.com/private/*\nhttps://partner.example.com/\n")

    assert ScopeManager(PROGRAM).is_in_scope(target) is ScopeValidator(PROGRAM).is_in_scope(target)


# --- Ambiguous authorities -------------------------------------------------------

@pytest.mark.parametrize("target", AMBIGUOUS)
def test_scope_manager_refuses_ambiguous_authorities(roots, target):
    canonical, _ = roots
    _write(canonical, "in-scope.txt", "*.example.com\napi.example.com\nhttps://api.example.com\n")
    _write(canonical, "out-of-scope.txt", "login.example.com\n")

    assert ScopeManager(PROGRAM).is_in_scope(target) is False
    assert ScopeValidator(PROGRAM).is_in_scope(target) is False


@pytest.mark.parametrize("target", [
    "https://API.Example.COM/path?q=1",
    "https://api.example.com.:8443/x",
    "http://api.example.com:80",
    "api.example.com",
    "API.EXAMPLE.COM.",
    "https://xn--bcher-kva.example.com/",
    "https://api.example.com [192.0.2.1]",
])
def test_scope_manager_accepts_normal_spellings(roots, target):
    canonical, _ = roots
    _write(canonical, "in-scope.txt", "*.example.com\n")

    assert ScopeManager(PROGRAM).is_in_scope(target) is True


def test_scope_manager_normalizes_allow_entry_spelling(roots):
    canonical, _ = roots
    _write(canonical, "in-scope.txt", "API.Example.com.\n*.Example.NET.\n")
    manager = ScopeManager(PROGRAM)
    assert manager.is_in_scope("https://api.example.com/") is True
    assert manager.is_in_scope("https://www.example.net/") is True


# --- HarnessConstraints ----------------------------------------------------------

def _constraints(domains: list[str]) -> HarnessConstraints:
    return HarnessConstraints({
        "scope": {"domains": domains},
        "stats": {"max_requests_per_session": 10, "rate_limit_rpm": 60,
                  "requests_this_session": 0, "total_requests": 0},
    })


@pytest.mark.parametrize("url", [
    "https://evil.test\\.target.com/",
    "https://target.com\\@evil.test/",
    "https://user@api.target.com/",
    "https://api.target.com\t/",
    "https://evil.test#.target.com",
    "https://api.target.com:8443/",
    "api.target.com",
    "ftp://api.target.com/",
])
def test_harness_constraints_refuse_ambiguous_or_unsupported_urls(url):
    constraints = _constraints(["target.com"])
    assert constraints.is_in_scope(url) is False
    with pytest.raises(HarnessViolation):
        constraints.enforce(url)


@pytest.mark.parametrize("url", [
    "https://api.target.com/orders/1",
    "https://API.TARGET.COM:443/",
    "http://target.com:80/",
    "https://api.target.com./",
    "https://xn--bcher-kva.target.com/",
])
def test_harness_constraints_accept_normal_urls(url):
    assert _constraints(["Target.com."]).is_in_scope(url) is True


def test_harness_constraints_ip_suffix_is_not_a_domain_match():
    assert _constraints(["1.10"]).is_in_scope("http://192.168.1.10/") is False
    assert _constraints(["192.168.1.10"]).is_in_scope("http://192.168.1.10/") is True


# --- Asset-intelligence labels ---------------------------------------------------

@pytest.mark.parametrize("value", [
    "evil.test?x=.target.com",
    "evil.test#.target.com",
    "https://evil.test\\.target.com/",
    "evil.test\\.target.com",
    "user@api.target.com",
])
def test_asset_scope_label_refuses_ambiguous_values(value):
    assert asset_intelligence.scope_matches("*.target.com", value) is False


@pytest.mark.parametrize("value", [
    "api.target.com", "API.target.com.", "api.target.com:8443",
    "https://api.target.com/login", "target.com", "*.api.target.com",
])
def test_asset_scope_label_accepts_normal_values(value):
    assert asset_intelligence.scope_matches("*.target.com", value) is True


def test_asset_classify_does_not_relate_query_suffix_to_target():
    graph = asset_intelligence.AssetIntelligenceGraph(program=PROGRAM, target="target.com")
    graph.add_scope_pattern("*.target.com", in_scope=True)
    assert graph.classify_scope("evil.test?x=.target.com") == "unknown"
    assert graph.classify_scope("https://api.target.com/") == "in-scope"
