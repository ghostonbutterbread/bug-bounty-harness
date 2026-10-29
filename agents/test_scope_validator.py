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
    # Bare hosts and other schemes cannot establish a path-restricted allow;
    # both are still conservatively covered by a path exclusion.
    incompatible_allow = entry == "http://excluded.example/contact-us/" and target in {
        "excluded.example", "https://excluded.example/contact-us/form"
    }
    assert validator.is_in_scope(target) is (not excluded and not incompatible_allow)
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


def test_optional_host_variants_are_consistent_for_allow_and_exclusion(tmp_path: Path) -> None:
    scope_dir = tmp_path / "scopes" / "synthetic"
    scope_dir.mkdir(parents=True)
    (scope_dir / "in-scope.txt").write_text("api(-eu1)?.example.com\n*.site(-eu1)?.example.net\n")
    (scope_dir / "out-of-scope.txt").write_text("*.blocked(-eu1)?.site.example.net\n")
    validator = ScopeValidator("synthetic")

    for host in ("api.example.com", "api-eu1.example.com", "sub.site.example.net", "sub.site-eu1.example.net"):
        assert validator.is_in_scope(host)
    for host in ("x.blocked.site.example.net", "x.blocked-eu1.site.example.net"):
        assert not validator.is_in_scope(host)
    assert not validator.is_in_scope("other.example.com")


def test_canonical_exclusion_files_are_combined_without_legacy(tmp_path: Path) -> None:
    canonical = tmp_path / "scopes" / "synthetic"
    legacy = tmp_path / "legacy" / "synthetic" / "scope"
    canonical.mkdir(parents=True)
    legacy.mkdir(parents=True)
    (canonical / "in-scope.txt").write_text("*.example.test\n")
    (canonical / "out-of-scope.txt").write_text("one.example.test\n")
    (canonical / "excluded.txt").write_text("two.example.test\n")
    (legacy / "out-of-scope.txt").write_text("legacy.example.test\n")
    validator = ScopeValidator("synthetic")
    assert not validator.is_in_scope("one.example.test")
    assert not validator.is_in_scope("two.example.test")
    assert validator.is_in_scope("legacy.example.test")
    assert validator.is_in_scope("good.example.test")


@pytest.mark.parametrize("primary", ["", "one.example.test\n"])
def test_empty_canonical_primary_does_not_hide_alternate(tmp_path: Path, primary: str) -> None:
    canonical = tmp_path / "scopes" / "synthetic"
    canonical.mkdir(parents=True)
    (canonical / "in-scope.txt").write_text("*.example.test\n")
    (canonical / "out-of-scope.txt").write_text(primary)
    (canonical / "excluded.txt").write_text("two.example.test\n")
    assert not ScopeValidator("synthetic").is_in_scope("two.example.test")


@pytest.mark.parametrize("filename", ["out-of-scope.txt", "excluded.txt"])
@pytest.mark.parametrize("error", [PermissionError("denied"), OSError("I/O failure")])
@pytest.mark.parametrize("other_content", [None, "", "other.example.test\n"])
def test_standard_exclusion_read_failure_is_not_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str, error: OSError, other_content: str | None
) -> None:
    import builtins
    canonical = tmp_path / "scopes" / "synthetic"
    canonical.mkdir(parents=True)
    (canonical / "in-scope.txt").write_text("*.example.test\n")
    denied_path = canonical / filename
    denied_path.write_text("denied.example.test\n")
    other = canonical / ("excluded.txt" if filename == "out-of-scope.txt" else "out-of-scope.txt")
    if other_content is not None:
        other.write_text(other_content)
    real_open = builtins.open
    def failing_open(path, *args, **kwargs):
        if Path(path) == denied_path:
            raise error
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", failing_open)
    with pytest.raises(OSError, match=filename):
        ScopeValidator("synthetic")


def test_missing_optional_files_do_not_reject(tmp_path: Path) -> None:
    canonical = tmp_path / "scopes" / "synthetic"
    canonical.mkdir(parents=True)
    (canonical / "in-scope.txt").write_text("*.example.test\n")
    assert ScopeValidator("synthetic").is_in_scope("ok.example.test")


def test_explicit_unreadable_exclusion_reports_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins
    validator = ScopeValidator("synthetic")
    path = tmp_path / "explicit.txt"
    path.write_text("denied.example.test\n")
    real_open = builtins.open
    def failing_open(candidate, *args, **kwargs):
        if Path(candidate) == path:
            raise PermissionError("denied")
        return real_open(candidate, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", failing_open)
    validator.add_domain("*.example.test")
    with pytest.raises(OSError, match="explicit.txt") as failure:
        validator.load_from_file(str(path), is_out_of_scope=True)
    assert isinstance(failure.value.__cause__, PermissionError)
    assert not validator.is_in_scope("ok.example.test")
    assert validator.is_out_of_scope("ok.example.test")
    assert not validator.is_wildcard_scope("example.test")


@pytest.mark.parametrize("primary", ["", "one.example.test\n"])
def test_legacy_both_exclusion_names_are_combined(tmp_path: Path, primary: str) -> None:
    legacy = tmp_path / "legacy" / "synthetic" / "scope"
    legacy.mkdir(parents=True)
    (legacy / "in-scope.txt").write_text("*.example.test\n")
    (legacy / "out-of-scope.txt").write_text(primary)
    (legacy / "excluded.txt").write_text("two.example.test\n")
    validator = ScopeValidator("synthetic")
    assert not validator.is_in_scope("two.example.test")
    assert validator.is_in_scope("good.example.test")


def test_missing_explicit_exclusion_is_an_error(tmp_path: Path) -> None:
    validator = ScopeValidator("synthetic")
    validator.add_domain("*.example.test")
    with pytest.raises(OSError, match="missing.txt") as failure:
        validator.load_from_file(str(tmp_path / "missing.txt"), is_out_of_scope=True)
    assert isinstance(failure.value.__cause__, FileNotFoundError)
    assert not validator.is_in_scope("good.example.test")


def test_dangling_exclusion_symlink_is_not_treated_as_absent(tmp_path: Path) -> None:
    canonical = tmp_path / "scopes" / "synthetic"
    canonical.mkdir(parents=True)
    (canonical / "in-scope.txt").write_text("*.example.test\n")
    (canonical / "excluded.txt").symlink_to(canonical / "missing-target.txt")
    with pytest.raises(OSError, match="excluded.txt"):
        ScopeValidator("synthetic")


def test_empty_canonical_prevents_legacy_fallback(tmp_path: Path) -> None:
    canonical = tmp_path / "scopes" / "synthetic"
    legacy = tmp_path / "legacy" / "synthetic" / "scope"
    canonical.mkdir(parents=True)
    legacy.mkdir(parents=True)
    (canonical / "in-scope.txt").write_text("*.example.test\n")
    (canonical / "out-of-scope.txt").write_text("")
    (legacy / "excluded.txt").write_text("old.example.test\n")
    assert ScopeValidator("synthetic").is_in_scope("old.example.test")


def test_consumer_start_rejects_exclusion_read_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins
    from agents import recon_ry
    from agents.scope_validator import ScopeExclusionReadError
    canonical = tmp_path / "scopes" / "synthetic"
    canonical.mkdir(parents=True)
    (canonical / "in-scope.txt").write_text("*.example.test\n")
    path = canonical / "excluded.txt"
    path.write_text("denied.example.test\n")
    real_open = builtins.open
    def failing_open(candidate, *args, **kwargs):
        if Path(candidate) == path:
            raise PermissionError("denied")
        return real_open(candidate, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", failing_open)
    monkeypatch.setattr(recon_ry, "ScopeValidator", ScopeValidator)
    with pytest.raises(ScopeExclusionReadError, match="excluded.txt"):
        recon_ry.validate_start_scope("synthetic", "https://good.example.test/", allow_unscoped=True)
