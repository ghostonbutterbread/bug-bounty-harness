from __future__ import annotations

from agents.scope_manager import ScopeManager


def test_scope_manager_wildcard_requires_subdomain_boundary() -> None:
    manager = ScopeManager.__new__(ScopeManager)
    manager.domains = {"*.example.com"}
    manager.urls = set()

    assert manager.is_in_scope("https://api.example.com") is True
    assert manager.is_in_scope("https://example.com") is True
    assert manager.is_in_scope("https://badexample.com") is False


def test_scope_manager_accepts_bare_host_inputs() -> None:
    manager = ScopeManager.__new__(ScopeManager)
    manager.domains = {"api.example.com", "*.example.com"}
    manager.urls = set()

    assert manager.is_in_scope("api.example.com") is True
    assert manager.is_in_scope("foo.example.com") is True
    assert manager.is_in_scope("badexample.com") is False
