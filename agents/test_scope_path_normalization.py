"""Offline regressions for scope path ambiguity; no requests are made."""

import pytest

from agents.scope_validator import OutOfScopeError, ScopeValidator


@pytest.fixture
def validator(tmp_path, monkeypatch):
    monkeypatch.setattr(ScopeValidator, "SCOPES_BASE", tmp_path)
    monkeypatch.setattr(ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = ScopeValidator("synthetic")
    scope.add_domain("*.example.test")
    scope.add_domain("https://api.example.test/private/", is_out_of_scope=True)
    return scope


def test_dot_segment_cannot_bypass_exclusion(validator):
    assert not validator.is_in_scope("https://api.example.test/public/../private/x")


@pytest.mark.parametrize("path", [
    "/%70rivate/x", "/public/%2e%2e/private/x", "/public%2f..%2fprivate/x",
    "/%2570rivate/x", "/%25252e%25252e/private", "/public/%2e./private/x",
    "/public/%2/private", "/public/%GG/private", "/public/%/private",
    "/public/./private", "/public//private", "/public\\..\\private",
    "/public;param/../private", "/pri\tvate/x", "/pub\tlic/x",
    "/public;param", "/ｐｒｉｖａｔｅ/x", "/public /x", "/private./x", "/private:stream/x",
])
def test_ambiguous_exclusion_paths_are_denied(validator, path):
    url = "https://api.example.test" + path
    assert not validator.is_in_scope(url)
    assert validator.is_out_of_scope(url)


def test_allow_path_is_not_inferred_from_host_or_prefix(validator):
    validator._entries.clear()
    validator.add_domain("https://api.example.test/public")
    assert validator.is_in_scope("https://api.example.test/public")
    assert validator.is_in_scope("https://api.example.test/public/x")
    assert not validator.is_in_scope("https://api.example.test/publicity")
    assert not validator.is_in_scope("api.example.test")
    assert not validator.is_in_scope("https://api.example.test/public/%2e%2e/other")


def test_safe_url_and_other_hosts_remain_usable(validator):
    assert validator.is_in_scope("https://api.example.test/public/x?encoded=%2f")
    assert validator.is_in_scope("https://else.example.test/%70ublic")
    assert not validator.is_in_scope("https://api.example.test/private")
    assert not validator.is_in_scope("http://api.example.test:8080/PRIVATE/x")
    assert validator.is_in_scope("https://api.example.test/privateer/x")
    assert not validator.is_in_scope("https://api.example.test.evil.test/public")


def test_invalid_exclusion_pattern_fails_closed_for_host(validator):
    validator._out_of_scope.clear()
    validator.add_domain("https://api.example.test/%70rivate/", is_out_of_scope=True)
    assert not validator.is_in_scope("https://api.example.test/public")
    assert validator.is_in_scope("https://other.example.test/public")


def test_wildcard_exclusion_and_port_are_conservative(validator):
    validator._out_of_scope.clear()
    validator.add_domain("https://*.example.test/private/*", is_out_of_scope=True)
    for url in ("https://api.example.test:9443/private/x", "http://deep.api.example.test/%70rivate/x"):
        assert not validator.is_in_scope(url)
    assert validator.is_in_scope("https://api.example.test/visible")
    assert not validator.is_in_scope("https://example.test/private/x")
    assert not validator.is_in_scope("https://example.test.evil.test/visible")


def test_exclusion_host_root_label_is_equivalent(validator):
    validator._out_of_scope.clear()
    validator.add_domain("https://api.example.test./private/", is_out_of_scope=True)
    assert not validator.is_in_scope("https://api.example.test/private/x")
    assert not validator.is_in_scope("https://api.example.test./private/x")
    assert validator.is_in_scope("https://api.example.test/public/x")


def test_allow_only_requires_safe_path_and_respects_explicit_glob(validator):
    validator._entries.clear()
    validator._out_of_scope.clear()
    validator.add_domain("https://api.example.test/public/*")
    assert validator.is_in_scope("https://api.example.test/public/x")
    assert not validator.is_in_scope("https://api.example.test/public%2fx")
    assert not validator.is_in_scope("https://api.example.test/public/../x")
    assert not validator.is_in_scope("https://api.example.test/publicity")
    assert not validator.is_in_scope("api.example.test/public/x")
    validator.add_domain("https://api.example.test/pre*")
    assert validator.is_in_scope("https://api.example.test/prefix")


def test_path_allow_does_not_widen_scheme_or_port(validator):
    validator._entries.clear()
    validator._out_of_scope.clear()
    validator.add_domain("https://api.example.test/public/")
    assert validator.is_in_scope("https://api.example.test:443/public/x")
    assert not validator.is_in_scope("http://api.example.test/public/x")
    assert not validator.is_in_scope("https://api.example.test:8443/public/x")
    validator._entries.clear()
    validator.add_domain("https://api.example.test:8443/public/")
    assert validator.is_in_scope("https://api.example.test:8443/public/x")
    assert not validator.is_in_scope("https://api.example.test/public/x")


def test_strict_guard_reports_refusal(validator):
    with pytest.raises(OutOfScopeError, match="unambiguous full URL"):
        validator.validate_or_fail("https://api.example.test/%70rivate")


def test_recon_consumers_enforce_saved_scope_offline(tmp_path, monkeypatch):
    from agents import recon_ry
    from agents.recon import bus

    scope_dir = tmp_path / "scopes" / "synthetic"
    scope_dir.mkdir(parents=True)
    (scope_dir / "in-scope.txt").write_text("*.example.test\n")
    (scope_dir / "out-of-scope.txt").write_text("https://api.example.test/private/\n")
    monkeypatch.setattr(ScopeValidator, "SCOPES_BASE", tmp_path / "scopes")
    monkeypatch.setattr(ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    monkeypatch.setattr(recon_ry, "ScopeValidator", ScopeValidator)
    monkeypatch.setattr(recon_ry, "OutOfScopeError", OutOfScopeError)
    monkeypatch.setattr(bus, "ScopeValidator", ScopeValidator)
    monkeypatch.setattr(bus, "SHARED_BASE", tmp_path / "shared")

    good = "https://api.example.test/public"
    denied = "https://api.example.test/public/../private/x"
    recon_ry.validate_start_scope("synthetic", good)
    with pytest.raises(SystemExit, match="NOT in scope"):
        recon_ry.validate_start_scope("synthetic", denied)
    assert bus.scope_violations("synthetic", "url", [good, denied]) == [denied]
