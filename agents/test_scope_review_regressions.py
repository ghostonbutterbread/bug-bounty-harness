"""Review regressions for feat/scope-check-ingest. The first block is the reviewer's repro file, copied verbatim (only mkdir(parents=True) added)."""
import pathlib

import pytest

from agents.recon_ry import validate_recon_scope_containment
from agents.scope_validator import ScopeValidator


def _v(tmp_path: pathlib.Path, inc: str, out: str = "") -> ScopeValidator:
    d = tmp_path / "p"
    d.mkdir(parents=True)
    (d / "in-scope.txt").write_text(inc)
    if out:
        (d / "out-of-scope.txt").write_text(out)
    return ScopeValidator("p", strict=False, scopes_base=tmp_path, legacy_recon_base=tmp_path / "none")


# F1: exclusion lines naming a host, followed by prose, are dropped entirely.
@pytest.mark.parametrize("line", [
    "admin.acme.example.test (legacy, do not test)",
    "admin.acme.example.test - payment endpoints",
    "Name: admin.acme.example.test (prod)",
    "admin.acme.example.test\tprod admin",
])
def test_exclusion_with_host_then_prose_still_excludes(tmp_path, line):
    v = _v(tmp_path, "*.acme.example.test\n", line + "\n")
    assert not v.is_in_scope("https://admin.acme.example.test/")


# F1b: only the trailing token of a multi-rule exclusion is kept.
def test_exclusion_keeps_every_named_range(tmp_path):
    v = _v(tmp_path, "10.0.0.0/8\n", "Corp - 10.1.0.0/16 and 10.2.0.0/16\n")
    assert not v.is_in_scope("http://10.1.2.3/")


def test_recon_ry_refuses_partially_represented_exclusion(tmp_path):
    v = _v(tmp_path, "*.acme.example.test\n", "Corp - 10.1.0.0/16 and 10.2.0.0/16\n")
    with pytest.raises(SystemExit):  # base refused this (invalid exclusion)
        validate_recon_scope_containment(v)


# F2: allow globs with '*' in the registrable label or TLD grant foreign domains.
@pytest.mark.parametrize("rule,target", [
    ("*.*", "https://anything.test/"),
    ("acme.*", "https://acme.evil/"),
    ("*acme.example.test", "https://evilacme.example.test/"),
    ("acme*.test", "https://acme-attacker.test/"),
    ("https://*acme.example.test/*", "https://evilacme.example.test/x"),
])
def test_allow_glob_does_not_cross_registrable_domain(tmp_path, rule, target):
    assert not _v(tmp_path, rule + "\n").is_in_scope(target)


# F3: grant prose ending in a host turns an exception into a grant.
def test_grant_prose_does_not_grant_excepted_host(tmp_path):
    v = _v(tmp_path, "All assets except admin.acme.example.test\n")
    assert not v.is_in_scope("https://admin.acme.example.test/")


# ── Additional regression coverage for the review fixes ───────────────────

from agents.scope_seed_files import parse_scope_line  # noqa: E402
from agents import scope_validator as SV  # noqa: E402


@pytest.mark.parametrize("line, exclusion, rules, status", [
    ("admin.acme.example.test (legacy, do not test)", True, ["admin.acme.example.test"], "lossy"),
    ("Name: admin.acme.example.test (prod)", True, ["admin.acme.example.test"], "lossy"),
    ("Corp - 10.1.0.0/16 and 10.2.0.0/16", True, ["10.1.0.0/16", "10.2.0.0/16"], "lossy"),
    ("3rd party services", True, [], "skipped"),
    ("a.acme.example.test, b.acme.example.test", True, ["a.acme.example.test", "b.acme.example.test"], "exact"),
    ("Acme Infrastructure - 192.0.2.0/28 | other | In Scope", False, ["192.0.2.0/28"], "exact"),
    ("All assets except admin.acme.example.test", False, [], "skipped"),
    ("admin.acme.example.test (prod)", False, [], "skipped"),
    ("Main - a.acme.example.test - b.acme.example.test", False, [], "skipped"),
    ("Mobile (iOS)", False, [], "skipped"),
    ("acme.example.test", False, ["acme.example.test"], "exact"),
])
def test_parse_scope_line_rules_and_status(line, exclusion, rules, status):
    assert parse_scope_line(line, exclusion=exclusion) == (rules, status)


def test_multi_rule_exclusion_excludes_each_range_and_keeps_others(tmp_path):
    v = _v(tmp_path, "10.0.0.0/8\n", "Corp - 10.1.0.0/16 and 10.2.0.0/16\n")
    assert not v.is_in_scope("http://10.2.9.9/")
    assert v.is_in_scope("http://10.3.0.1/")
    assert v.lossy_scope_lines == [("exclusion", "Corp - 10.1.0.0/16 and 10.2.0.0/16")]


@pytest.mark.parametrize("rule, target", [
    ("app*.hub.example.test", "https://app1.hub.example.test/"),
    ("api-*.acme.example.test", "https://api-eu.acme.example.test/"),
    ("*.acme.example.test", "https://a.acme.example.test/"),
    ("*.app*.acme.example.test", "https://x.app2.acme.example.test/"),
    ("https://api-*.acme.example.test/*", "https://api-eu.acme.example.test/x"),
    ("https://*.acme.example.test/*", "https://a.acme.example.test/x"),
])
def test_narrow_allow_globs_still_grant(tmp_path, rule, target):
    assert _v(tmp_path, rule + "\n").is_in_scope(target)


@pytest.mark.parametrize("rule", ["customer.*.acme.example.test", "app*.test", "*-x.acme.example.test"])
def test_broad_allow_globs_grant_nothing(tmp_path, rule):
    v = _v(tmp_path, rule + "\n")
    assert all(e.has_invalid_authority() for e in v._entries)


def test_exclusion_globs_stay_wide(tmp_path):
    v = _v(tmp_path, "*.acme.example.test\n", "*staging.acme.example.test\nacme.*\n")
    assert not v.is_in_scope("https://old-staging.acme.example.test/")
    assert not v.is_in_scope("https://acme.example.test/")  # acme.* spans the rest
    assert all(not e.has_invalid_authority() for e in v._out_of_scope)


def test_recon_ry_accepts_named_cidr_grant_and_refuses_skipped(tmp_path):
    ok = _v(tmp_path / "a", "Acme Infrastructure - 192.0.2.0/28 | other | In Scope\n")
    validate_recon_scope_containment(ok)
    skipped = _v(tmp_path / "b", "*.acme.example.test\nAll assets except admin.acme.example.test\n")
    with pytest.raises(SystemExit, match="unrepresentable"):
        validate_recon_scope_containment(skipped)


def test_skipped_lines_are_surfaced(tmp_path):
    v = _v(tmp_path, "*.acme.example.test\nStaging environments\n", "3rd party services\n")
    assert "2 saved scope line(s) skipped" in v.scope_summary()
    result = SV.classify_program("p", ["a.acme.example.test"], tmp_path)
    assert result["skipped_lines"] == 2
    assert result["results"][0]["state"] == "in"
