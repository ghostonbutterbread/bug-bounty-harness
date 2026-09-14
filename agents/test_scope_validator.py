from __future__ import annotations

from pathlib import Path

import pytest

from agents.scope_validator import ScopeValidator


@pytest.fixture(autouse=True)
def isolated_scope_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ScopeValidator, "SCOPES_BASE", tmp_path / "scopes")
    monkeypatch.setattr(ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy")


@pytest.mark.parametrize("exclusion", ["blocked.example.com", "*.blocked.example.com"])
@pytest.mark.parametrize("allow", ["blocked.example.com", "*.example.com"])
def test_annotated_exclusions_override_allows(tmp_path: Path, allow: str, exclusion: str) -> None:
    scope_dir = tmp_path / "synthetic"
    scope_dir.mkdir()
    (scope_dir / "in-scope.txt").write_text(allow + "\n")
    (scope_dir / "out-of-scope.txt").write_text(exclusion + " :: owned by a third party\n")
    validator = ScopeValidator("synthetic", scopes_base=tmp_path)

    assert validator.is_out_of_scope("blocked.example.com") is True
    assert validator.is_in_scope("blocked.example.com") is False


@pytest.mark.parametrize("suffix", ["", " :: policy note :: more detail", "\t::\tpolicy note", " ::"])
@pytest.mark.parametrize("excluded", [False, True])
@pytest.mark.parametrize(
    ("entry", "target"),
    [
        ("BLOCKED.example.com", "https://blocked.example.com/other"),
        ("*.blocked.example.com", "deep.api.blocked.example.com"),
        ("http://excluded.example/contact-us/", "excluded.example"),
        ("http://excluded.example/contact-us/", "https://excluded.example/contact-us/form"),
        ("https://*.example.com/private/*", "https://api.example.com/private/item"),
        ("192.0.2.1", "192.0.2.1:8080"),
        ("192.0.2.0/24", "192.0.2.3"),
        ("2001:db8::1", "2001:db8::1"),
        ("::1", "::1"),
        ("2001:db8::/32", "2001:db8::2"),
        ("http://[2001:db8::1]/contact-us/", "http://[2001:db8::1]/contact-us/form"),
        ("https://example.com/a::b", "https://example.com/a::b"),
    ],
)
def test_file_entries_preserve_matching_with_optional_annotations(
    tmp_path: Path, entry: str, target: str, suffix: str, excluded: bool
) -> None:
    path = tmp_path / "entries.txt"
    path.write_text("\n# file comment\n  " + entry + suffix + "\n")
    validator = ScopeValidator("synthetic")
    if excluded:
        validator.add_domain(entry)
    validator.load_from_file(str(path), is_out_of_scope=excluded)

    assert validator.is_out_of_scope(target) is excluded
    assert validator.is_in_scope(target) is not excluded
    assert validator.is_in_scope("unrelated.invalid") is False


def test_annotated_url_entries_retain_path_restrictions(tmp_path: Path) -> None:
    path = tmp_path / "entries.txt"
    path.write_text("http://excluded.example/contact-us/ :: no testing here\n")
    validator = ScopeValidator("synthetic")
    validator.add_domain("excluded.example")
    validator.load_from_file(str(path), is_out_of_scope=True)

    assert validator.is_in_scope("http://excluded.example/contact-us/form") is False
    assert validator.is_in_scope("http://excluded.example/other") is True
    assert validator.is_out_of_scope("excluded.example") is True


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("filename", ["out-of-scope.txt", "excluded.txt"])
def test_annotation_loading_from_standard_locations(
    tmp_path: Path, legacy: bool, filename: str
) -> None:
    if legacy:
        scope_dir = tmp_path / "legacy" / "synthetic" / "scope"
    else:
        scope_dir = tmp_path / "scopes" / "synthetic"
    scope_dir.mkdir(parents=True)
    (scope_dir / "in-scope.txt").write_text("*.example.com :: allowed estate\n")
    (scope_dir / filename).write_text("*.blocked.example.com :: third party\n")
    validator = ScopeValidator("synthetic")

    assert validator.is_in_scope("good.example.com") is True
    assert validator.is_in_scope("api.blocked.example.com") is False
    assert validator.is_out_of_scope("api.blocked.example.com") is True
    assert validator.is_in_scope("notblocked.example.com") is True
    assert validator.is_in_scope("example.com.invalid") is False


def test_scope_validator_is_out_of_scope_only_for_explicit_exclusions() -> None:
    validator = ScopeValidator.__new__(ScopeValidator)
    validator._entries = []
    validator._out_of_scope = []

    validator.add_domain("example.com")
    validator.add_domain("blocked.example.com", is_out_of_scope=True)

    assert validator.is_in_scope("example.com") is True
    assert validator.is_out_of_scope("blocked.example.com") is True
    assert validator.is_out_of_scope("unknown.example.com") is False
