from __future__ import annotations

from pathlib import Path

import pytest

from agents.scope_validator import ScopeValidator


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


def test_scope_validator_is_out_of_scope_only_for_explicit_exclusions() -> None:
    validator = ScopeValidator.__new__(ScopeValidator)
    validator._entries = []
    validator._out_of_scope = []

    validator.add_domain("example.com")
    validator.add_domain("blocked.example.com", is_out_of_scope=True)

    assert validator.is_in_scope("example.com") is True
    assert validator.is_out_of_scope("blocked.example.com") is True
    assert validator.is_out_of_scope("unknown.example.com") is False
