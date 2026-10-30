"""Bypass-only scope tests extracted from 0c9a870."""
import asyncio

from pathlib import Path

import pytest

from agents import bypass_harness

@pytest.fixture
def scope_roots(tmp_path, monkeypatch):
    validator = bypass_harness.ScopeValidator
    monkeypatch.setattr(validator, "SCOPES_BASE", tmp_path / "scopes")
    monkeypatch.setattr(validator, "LEGACY_RECON_BASE", tmp_path / "legacy")
    directory = tmp_path / "scopes" / "synthetic"
    directory.mkdir(parents=True)
    return directory

@pytest.mark.parametrize("method", ["run_bypass", "run_sweep"])
def test_bypass_exclusion_only_denied_before_client(scope_roots, monkeypatch, method):
    (scope_roots / "out-of-scope.txt").write_text("blocked.example.test\n")
    def forbidden(*args, **kwargs):
        pytest.fail("network client constructed for denied target")
    monkeypatch.setattr(bypass_harness.httpx, "AsyncClient", forbidden)
    harness = bypass_harness.BypassOrchestrator(program="synthetic")
    async def collect():
        stream = (harness.run_bypass("https://blocked.example.test/", "403")
                  if method == "run_bypass" else harness.run_sweep("https://blocked.example.test/"))
        return [item async for item in stream]
    results = asyncio.run(collect())
    assert len(results) == 1 and results[0].technique == "scope_check"

def test_bypass_program_missing_scope_denies_but_no_program_is_explicit_unscoped(scope_roots):
    target = "https://unknown.example.test/"
    assert not bypass_harness.BypassOrchestrator(program="synthetic")._check_scope(target)
    assert bypass_harness.BypassOrchestrator()._check_scope(target)
    (scope_roots / "in-scope.txt").write_text("*.example.test\n")
    harness = bypass_harness.BypassOrchestrator(program="synthetic")
    assert harness._check_scope(target)
    assert not harness._check_scope("https://outside.invalid/")

def test_bypass_unreadable_scope_does_not_construct_client(scope_roots, monkeypatch):
    (scope_roots / "in-scope.txt").mkdir()
    monkeypatch.setattr(bypass_harness.httpx, "AsyncClient", lambda *a, **kw: pytest.fail("client constructed"))
    with pytest.raises(OSError):
        bypass_harness.BypassOrchestrator(program="synthetic")
