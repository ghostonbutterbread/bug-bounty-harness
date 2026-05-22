from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LEGACY_REPO_PATH = "/home/ryushe/workspace/bug_bounty_harness"
LEGACY_HELPER_PATH = "/home/ryushe/projects/bounty-tools"


def _load_module(module_path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop(module_name, None)


def test_recon_modules_use_repo_relative_import_bootstrap(monkeypatch) -> None:
    helper_env = PROJECT_ROOT / "missing-bounty-tools"
    monkeypatch.setenv("HOME", "/tmp/nonexistent-home")
    monkeypatch.setenv("BOUNTY_TOOLS_PATH", str(helper_env))

    modules = {
        "ai_recon_portable_test": PROJECT_ROOT / "agents" / "ai_recon.py",
        "autonomous_recon_portable_test": PROJECT_ROOT / "agents" / "autonomous_recon.py",
    }

    original_path = list(sys.path)
    sys.modules.pop("scope_validator", None)
    sys.modules.pop("rate_limiter", None)
    try:
        sys.path[:] = [
            entry
            for entry in original_path
            if str(entry) not in {LEGACY_REPO_PATH, LEGACY_HELPER_PATH}
        ]
        for module_name, module_path in modules.items():
            module = _load_module(module_path, module_name)
            assert module.ScopeValidator is not None
            assert module.RateLimiter is not None
        assert str(PROJECT_ROOT / "agents") in sys.path
        assert str(helper_env) not in sys.path
    finally:
        sys.path[:] = original_path
        sys.modules.pop("scope_validator", None)
        sys.modules.pop("rate_limiter", None)


def test_code_review_tolerates_missing_optional_helper_path(monkeypatch) -> None:
    helper_env = PROJECT_ROOT / "missing-bounty-tools"
    monkeypatch.setenv("HOME", "/tmp/nonexistent-home")
    monkeypatch.setenv("BOUNTY_TOOLS_PATH", str(helper_env))

    original_path = list(sys.path)
    sys.modules.pop("subagent_logger", None)
    try:
        sys.path[:] = [
            entry
            for entry in original_path
            if str(entry) not in {LEGACY_REPO_PATH, LEGACY_HELPER_PATH}
        ]
        module = _load_module(PROJECT_ROOT / "agents" / "code_review.py", "code_review_portable_test")
        assert module.SubagentLogger is None
        assert callable(module.compute_pte_lite)
        assert str(helper_env) not in sys.path
    finally:
        sys.path[:] = original_path
        sys.modules.pop("subagent_logger", None)
