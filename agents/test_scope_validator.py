from __future__ import annotations

from agents.scope_validator import ScopeValidator


def test_scope_validator_is_out_of_scope_only_for_explicit_exclusions() -> None:
    validator = ScopeValidator.__new__(ScopeValidator)
    validator._entries = []
    validator._out_of_scope = []

    validator.add_domain("example.com")
    validator.add_domain("blocked.example.com", is_out_of_scope=True)

    assert validator.is_in_scope("example.com") is True
    assert validator.is_out_of_scope("blocked.example.com") is True
    assert validator.is_out_of_scope("unknown.example.com") is False
