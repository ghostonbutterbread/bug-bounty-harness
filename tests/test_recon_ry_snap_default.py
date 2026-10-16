"""Recon-Ry snap is the ordinary broad launch, with full opt-in."""

import pytest

from agents import recon_ry


class WildcardScope:
    _entries = [type("Entry", (), {"entry_type": "wildcard", "raw": "*.example.test"})()]
    _out_of_scope = []

    def __init__(self, *args, **kwargs):
        pass

    def is_empty(self):
        return False

    def validate_or_fail(self, url):
        assert url == "example.test"


class ExactScope(WildcardScope):
    _entries = [type("Entry", (), {"entry_type": "domain", "raw": "example.test"})()]


class ExcludedWildcardScope(WildcardScope):
    _out_of_scope = [type("Entry", (), {"raw": "*.example.test"})()]


@pytest.mark.parametrize("profile,flag", [(None, "--profile snap"), ("full", "--full")])
def test_broad_launch_default_and_full_override(monkeypatch, capsys, profile, flag):
    monkeypatch.setattr(recon_ry, "ScopeValidator", WildcardScope)
    argv = ["start", "example", "--url", "example.test", "--dry-run"]
    if profile:
        argv += ["--profile", profile]
    args = recon_ry.build_parser().parse_args(argv)
    assert args.profile == (profile or "snap")
    args.func(args)
    out = capsys.readouterr().out
    assert flag in out
    assert "--url example.test" not in out  # wildcard roots, not the one seed, drive enumeration
    assert "wild.txt" in out and "example.test" in out


def test_snap_requires_wildcard_scope(monkeypatch):
    monkeypatch.setattr(recon_ry, "ScopeValidator", ExactScope)
    args = recon_ry.build_parser().parse_args(
        ["start", "example", "--url", "example.test", "--dry-run"]
    )
    with pytest.raises(SystemExit, match="requires wildcard targets"):
        args.func(args)


def test_snap_refuses_excluded_wildcard_roots(monkeypatch):
    monkeypatch.setattr(recon_ry, "ScopeValidator", ExcludedWildcardScope)
    args = recon_ry.build_parser().parse_args(
        ["start", "example", "--url", "example.test", "--dry-run"]
    )
    with pytest.raises(SystemExit, match="no eligible wildcard roots"):
        args.func(args)


def test_snap_rejects_credentialed_broad_launch(monkeypatch):
    monkeypatch.setattr(recon_ry, "ScopeValidator", WildcardScope)
    args = recon_ry.build_parser().parse_args(
        ["start", "example", "--url", "example.test", "--header", "X-Test: fake", "--dry-run"]
    )
    with pytest.raises(SystemExit, match="credentialed recon requires --profile exact-urls"):
        args.func(args)
