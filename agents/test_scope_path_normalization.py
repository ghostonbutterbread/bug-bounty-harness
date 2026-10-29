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


def test_invalid_alabel_wildcard_is_not_promotable(tmp_path, monkeypatch):
    from agents.recon import bus

    monkeypatch.setattr(bus, "SHARED_BASE", tmp_path / "web_bounty")
    monkeypatch.setattr(ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = tmp_path / "scopes" / "synthetic"
    scope.mkdir(parents=True)
    (scope / "in-scope.txt").write_text("*.xn--a.example.test\n")
    validator = ScopeValidator("synthetic", scopes_base=scope.parent)

    assert not validator.is_in_scope("child.xn--a.example.test")
    assert not validator.is_wildcard_scope("xn--a.example.test")
    assert bus.scope_violations("synthetic", "wild", ["xn--a.example.test"]) == ["xn--a.example.test"]


@pytest.mark.parametrize("denied", [
    "*.example.test", "*.EXAMPLE.TEST.", "*.test",
    "https://*.example.test/", "https://*.test/*", "https://*.example.test/%2f",
])
def test_fully_excluded_wildcard_cannot_be_promoted(tmp_path, monkeypatch, denied):
    from agents.recon import bus

    monkeypatch.setattr(bus, "SHARED_BASE", tmp_path / "web_bounty")
    monkeypatch.setattr(ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = tmp_path / "scopes" / "synthetic"
    scope.mkdir(parents=True)
    (scope / "in-scope.txt").write_text("*.Example.Test.\n")
    (scope / "out-of-scope.txt").write_text(denied + "\n")
    validator = ScopeValidator("synthetic", scopes_base=scope.parent)

    assert not validator.is_in_scope("child.example.test")
    assert not validator.is_wildcard_scope("example.test")
    assert bus.scope_violations("synthetic", "wild", ["*.EXAMPLE.TEST."]) == ["*.EXAMPLE.TEST."]


@pytest.mark.parametrize(("allow", "deny", "value"), [
    ("*.xn--a.example.test", "", "*.xn--a.example.test"),
    ("*.Example.Test.", "*.example.test", "example.test"),
])
def test_recon_bus_append_quarantines_nonpromotable_wildcard(tmp_path, monkeypatch, allow, deny, value):
    from agents.recon import bus

    shared = tmp_path / "web_bounty"
    monkeypatch.setattr(ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    scope = tmp_path / "scopes" / "synthetic"
    scope.mkdir(parents=True)
    (scope / "in-scope.txt").write_text(allow + "\n")
    (scope / "out-of-scope.txt").write_text(deny + "\n")
    args = bus.build_parser().parse_args([
        "append", "synthetic", "--kind", "wild", "--value", value,
        "--shared-base", str(shared), "--no-index",
    ])

    with pytest.raises(SystemExit, match="out-of-scope"):
        bus.append(args)
    recon = shared / "synthetic" / "web" / "recon"
    assert not (recon / "aggregated" / "wild.txt").exists()
    assert (recon / "quarantine" / "out_of_scope_wild.txt").read_text().splitlines() == [value]


@pytest.mark.parametrize(("deny", "blocked"), [
    ("api.xn--bcher-kva.example.test", "api.xn--bcher-kva.example.test"),
    ("xn--bcher-kva.example.test", "xn--bcher-kva.example.test"),
    ("*.blocked.xn--bcher-kva.example.test", "child.blocked.xn--bcher-kva.example.test"),
    ("https://*.xn--bcher-kva.example.test/private/", "https://api.xn--bcher-kva.example.test/private/x"),
])
def test_recon_bus_keeps_declared_root_with_subset_deny(tmp_path, monkeypatch, deny, blocked):
    from agents.recon import bus

    shared = tmp_path / "web_bounty"
    monkeypatch.setattr(ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    monkeypatch.setattr(bus, "find_tool", lambda *args, **kwargs: None)
    scope = tmp_path / "scopes" / "synthetic"
    scope.mkdir(parents=True)
    (scope / "in-scope.txt").write_text("*.XN--BCHER-KVA.Example.Test.\n")
    (scope / "out-of-scope.txt").write_text(deny + "\n")
    validator = ScopeValidator("synthetic", scopes_base=scope.parent)
    assert validator.is_wildcard_scope("xn--bcher-kva.example.test.")
    assert not validator.is_in_scope(blocked)
    assert validator.is_in_scope("https://good.xn--bcher-kva.example.test/public")

    value = "*.XN--BCHER-KVA.Example.Test."
    args = bus.build_parser().parse_args([
        "append", "synthetic", "--kind", "wild", "--value", value,
        "--shared-base", str(shared), "--no-index",
    ])
    assert bus.append(args)["status"] == "ok"
    assert (shared / "synthetic/web/recon/aggregated/wild.txt").read_text().splitlines() == [value]


@pytest.mark.parametrize("target", [
    "https://%61pi.example.test/private/x",
    "https://api.example.test\\@other.example.test/private/x",
    "https://api.example.test\\private/x",
    "https://api.example.test:invalid/private/x",
    "https://api.example.test:99999/private/x",
    "https://api.example.test\t.evil/private/x",
    "https://user@api.example.test/public",
    "https://аpi.example.test/public",
    "https://api.example.test/%5cprivate/x\\",
    "https://api.example.test./\\private/x",
])
def test_ambiguous_authority_never_authorizes(validator, target):
    assert not validator.is_in_scope(target)


@pytest.mark.parametrize("target", ["\thttps://api.example.test/public", "https://api.example.test/public\n"])
def test_outer_control_characters_never_authorize(validator, target):
    assert not validator.is_in_scope(target)


def test_ambiguous_exclusion_authority_fails_closed(validator):
    validator._out_of_scope.clear()
    validator.add_domain("https://%61pi.example.test/private/", is_out_of_scope=True)
    assert not validator.is_in_scope("https://api.example.test/private/x")


@pytest.mark.parametrize("target", [
    "https://[2001:db8::1]junk/public",
    "https://api.example.test:/public",
])
def test_malformed_authority_rejected_even_by_host_grant(validator, target):
    validator._out_of_scope.clear()
    validator.add_domain("2001:db8::1")
    assert not validator.is_in_scope(target)


def test_equivalent_ipv6_exclusion_cannot_be_bypassed(validator):
    validator._entries.clear()
    validator._out_of_scope.clear()
    validator.add_domain("2001:db8::1")
    validator.add_domain("https://[2001:0db8:0:0:0:0:0:1]/private/", is_out_of_scope=True)
    assert not validator.is_in_scope("https://[2001:db8::1]/private/x")
    assert validator.is_in_scope("https://[2001:db8::1]/public/x")


def test_wildcard_exclusion_root_label_cannot_bypass(validator):
    validator._out_of_scope.clear()
    validator.add_domain("*.example.test.", is_out_of_scope=True)
    assert not validator.is_in_scope("https://api.example.test/public")


def test_malformed_bare_exclusion_is_not_ignored(validator):
    validator._out_of_scope.clear()
    validator.add_domain("api.example.test/private", is_out_of_scope=True)
    assert not validator.is_in_scope("https://api.example.test/private/x")


@pytest.mark.parametrize("entry", ["https://api.example.test/", "https://api.example.test:8443/"])
def test_url_origin_allow_never_grants_bare_host(validator, entry):
    validator._entries.clear()
    validator._out_of_scope.clear()
    validator.add_domain(entry)
    assert not validator.is_in_scope("api.example.test")
    assert validator.is_in_scope(entry)
    assert not validator.is_in_scope("http://api.example.test/")
    validator.add_domain("api.example.test")
    assert validator.is_in_scope("api.example.test")


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
    denied = [
        "https://api.example.test/public/../private/x",
        "https://%61pi.example.test/private/x",
        "https://api.example.test\\@other.example.test/private/x",
        "https://api.example.test:/public",
    ]
    # Recon-Ry cannot enforce path restrictions downstream, so it refuses the
    # entire run; the validator and bus still reject each ambiguous spelling.
    validator = ScopeValidator(program="synthetic", strict=True)
    validator.validate_or_fail(good)
    for url in [good, *denied]:
        with pytest.raises(SystemExit, match="request-level containment"):
            recon_ry.validate_start_scope("synthetic", url)
    for url in denied:
        with pytest.raises(OutOfScopeError, match="NOT in scope"):
            validator.validate_or_fail(url)
    assert bus.scope_violations("synthetic", "url", [good, *denied]) == denied


def test_invalid_alabel_target_is_refused(validator):
    validator._out_of_scope.clear()
    assert not validator.is_in_scope("https://xn--a.example.test/public")


@pytest.mark.parametrize("entry", ["xn--a.example.test", "https://xn--a.example.test/private/"])
def test_invalid_alabel_exclusion_fails_closed_with_reason(validator, entry):
    validator._out_of_scope.clear()
    validator.add_domain(entry, is_out_of_scope=True)
    assert not validator.is_in_scope("https://api.example.test/public")
    with pytest.raises(OutOfScopeError, match="invalid exclusion authority"):
        validator.validate_or_fail("https://api.example.test/public")


def test_valid_alabel_dns_and_ip_keep_working(validator):
    validator._out_of_scope.clear()
    validator.add_domains(["xn--bcher-kva.example.test", "xn--zca.example.test", "192.0.2.1", "2001:db8::1"])
    for url in ("https://xn--bcher-kva.example.test/", "https://xn--zca.example.test/", "https://api.example.test/",
                "http://192.0.2.1/", "https://[2001:db8::1]/"):
        assert validator.is_in_scope(url)


def test_invalid_allow_authority_does_not_grant(validator):
    validator._entries.clear()
    validator._out_of_scope.clear()
    validator.add_domain("xn--a.example.test")
    assert not validator.is_in_scope("xn--a.example.test")
    with pytest.raises(OutOfScopeError, match="invalid allow authority"):
        validator.validate_or_fail("xn--a.example.test")


def test_invalid_exclusion_refuses_wildcard_promotion(validator):
    validator.add_domain("xn--a.example.test", is_out_of_scope=True)
    assert not validator.is_wildcard_scope("example.test")
