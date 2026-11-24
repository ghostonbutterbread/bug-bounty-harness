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
    "HTTPS://API.TARGET.COM/",
    "HtTp://target.com:80/",
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


def test_asset_unparseable_url_is_out_of_scope_when_exclusions_exist():
    graph = asset_intelligence.AssetIntelligenceGraph(program=PROGRAM, target="target.com")
    graph.add_scope_pattern("*.target.com", in_scope=True)
    graph.add_scope_pattern("admin.target.com", in_scope=False)
    assert graph.classify_scope("https://user@admin.target.com/") == "out-of-scope"
    assert graph.classify_scope("https://login.target.com\\@api.target.com/") == "out-of-scope"
    assert graph.classify_scope("HTTPS://api.target.com/") == "in-scope"
    # Non-host records keep their label rather than becoming blocked.
    assert graph.classify_scope("Example Corp, Inc.") == "unknown"

    allow_only = asset_intelligence.AssetIntelligenceGraph(program=PROGRAM, target="target.com")
    allow_only.add_scope_pattern("*.target.com", in_scope=True)
    assert allow_only.classify_scope("https://user@admin.target.com/") == "unknown"


# --- Fuzz campaign path (run_campaign -> FuzzAgent) -------------------------------

@pytest.fixture
def fuzz_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import program_config
    from agents import fuzz_runner

    scopes = tmp_path / "scopes"
    monkeypatch.setattr(fuzz_runner.ScopeValidator, "SCOPES_BASE", scopes)
    monkeypatch.setattr(fuzz_runner.ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    monkeypatch.setattr(program_config, "SCOPES_DIR", scopes)
    monkeypatch.setattr(program_config, "BASE_DIR", tmp_path / "web_bounty")

    class State:
        CAMPAIGNS_DIR = tmp_path / "campaigns"

    monkeypatch.setattr(fuzz_runner, "CampaignState", State)
    monkeypatch.setattr(fuzz_runner, "SubagentLogger", None)
    monkeypatch.setattr(fuzz_runner.subprocess, "Popen",
                        lambda *a, **k: pytest.fail("ffuf subprocess reached"))
    _write(scopes / PROGRAM, "in-scope.txt", "example.test\n")
    _write(scopes / PROGRAM, "out-of-scope.txt", "admin.example.test\n")
    return fuzz_runner


def test_fuzz_program_scope_refuses_excluded_target_domain_list_allows(fuzz_env):
    import io

    import program_config

    domains = program_config._load_in_scope_domains(PROGRAM)
    assert domains == ["example.test"]
    constraints = _constraints(domains)
    target = "https://admin.example.test"
    # The campaign's domain list alone cannot see the exclusion...
    assert constraints.check_scope(target) is True
    # ...so the program's saved scope must refuse it before any request.
    agent = fuzz_env.FuzzAgent("demo", PROGRAM)
    result = agent._run_target(campaign={}, constraints=constraints, fuzz_state={},
                               target=target, max_requests=10, raw_file=io.StringIO())
    assert result["requests_used"] == 0
    assert agent.is_in_scope("https://example.test/") is True


def test_fuzz_agent_without_program_fails_closed(fuzz_env):
    with pytest.raises(ValueError, match="program"):
        fuzz_env.FuzzAgent("demo")


def _run_stubbed_ffuf(fuzz_env, monkeypatch, tmp_path, *, allow, exclude, target, words):
    """Drive _run_target with ffuf stubbed; return the (-u URL, words) it received."""
    import io

    scope = tmp_path / "scopes" / PROGRAM
    _write(scope, "in-scope.txt", allow)
    _write(scope, "out-of-scope.txt", exclude)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("\n".join(words) + "\n", encoding="utf-8")
    received = []

    class FakeFfuf:
        def __init__(self, args, **kwargs):
            received.append((args[2], Path(args[4]).read_text(encoding="utf-8").split()))
            self.stdout = iter(())

        def wait(self):
            return 0

    monkeypatch.setattr(fuzz_env.subprocess, "Popen", FakeFfuf)
    constraints = HarnessConstraints({
        "scope": {"domains": ["example.test"]},
        "stats": {"max_requests_per_session": 100, "rate_limit_rpm": 600, "rate_limit_rps": 1000,
                  "requests_this_session": 0, "total_requests": 0},
    })
    fuzz_state = {"wordlist_paths": [str(wordlist)], "wordlist_idx": 0, "paths_tested": [],
                  "tested_pairs": [], "rate_limit_events": 0}
    agent = fuzz_env.FuzzAgent("demo", PROGRAM)
    agent._run_target(campaign={}, constraints=constraints, fuzz_state=fuzz_state,
                      target=target, max_requests=10, raw_file=io.StringIO())
    return received


def test_fuzz_never_sends_path_excluded_wordlist_entries(fuzz_env, monkeypatch, tmp_path):
    received = _run_stubbed_ffuf(
        fuzz_env, monkeypatch, tmp_path,
        allow="*.example.test\nexample.test\n",
        exclude="admin.example.test\nhttps://example.test/admin\n",
        target="https://example.test",
        words=["admin", "ADMIN", "admin/users", "ok"],
    )
    # ScopeValidator path exclusions are case-insensitive and cover sub-paths.
    assert received == [("https://example.test/FUZZ", ["ok"])]


def test_fuzz_skips_wordlist_when_every_entry_is_excluded(fuzz_env, monkeypatch, tmp_path):
    received = _run_stubbed_ffuf(
        fuzz_env, monkeypatch, tmp_path,
        allow="example.test\n", exclude="https://example.test/admin\n",
        target="https://example.test", words=["admin", "Admin/x"],
    )
    assert received == []


@pytest.mark.parametrize("target", ["https://example.test/api/v1?q", "https://example.test/api/v1#f",
                                    "https://example.test/api/v1/"])
def test_fuzz_template_stays_under_the_allowed_path(fuzz_env, monkeypatch, tmp_path, target):
    received = _run_stubbed_ffuf(
        fuzz_env, monkeypatch, tmp_path,
        allow="https://example.test/api/v1\n", exclude="",
        target=target, words=["users"],
    )
    assert received == [("https://example.test/api/v1/FUZZ", ["users"])]


def test_fuzz_run_refuses_empty_saved_scope(fuzz_env, tmp_path):
    (tmp_path / "scopes" / PROGRAM / "in-scope.txt").unlink()
    agent = fuzz_env.FuzzAgent("demo", PROGRAM)
    with pytest.raises(ValueError, match="no allow entries"):
        agent.run(max_requests=10)


def test_run_fuzz_passes_recorded_program_and_refuses_without(monkeypatch, capsys):
    import importlib.util
    import sys
    from types import SimpleNamespace

    if importlib.util.find_spec("bac_checks") is None:
        # External bounty-tools catalog imported by run_campaign; unused by fuzz.
        monkeypatch.setitem(sys.modules, "bac_checks",
                            SimpleNamespace(P0_TESTS=[], P1_TESTS=[], P2_TESTS=[]))
    import run_campaign

    calls = []

    class Agent:
        def __init__(self, campaign_id, program=""):
            calls.append((campaign_id, program))

        def run(self, max_requests):
            return {}

    monkeypatch.setattr(run_campaign, "FuzzAgent", Agent)
    args = SimpleNamespace(campaign="demo", max_requests=10)

    assert run_campaign.run_fuzz(args, {"program_config": {"program": PROGRAM}}, None) == 0
    assert calls == [("demo", PROGRAM)]
    for campaign in ({}, {"program_config": None}, {"program_config": {"program": ""}},
                     {"program_config": {"program": "../other"}}):
        assert run_campaign.run_fuzz(args, campaign, None) == 1
    assert calls == [("demo", PROGRAM)]
    out = capsys.readouterr().out
    assert "<new-id>" in out and "--force" in out


# --- program_init CLI boundary ----------------------------------------------------

def test_program_init_reports_unreadable_scope_without_traceback(tmp_path, monkeypatch, capsys):
    from scripts import program_init

    def unreadable(*args, **kwargs):
        raise ScopeExclusionReadError("could not read exclusion file /synthetic/out-of-scope.txt: denied")

    monkeypatch.setattr(program_init, "initialize_program", unreadable)
    code = program_init.main([PROGRAM, "--skip-scope", "--artifact-root", str(tmp_path / "artifacts")])

    out = capsys.readouterr().out
    assert code == 2
    assert "out-of-scope.txt" in out and "retry" in out
