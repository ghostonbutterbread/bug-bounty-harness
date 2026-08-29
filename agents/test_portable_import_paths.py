from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


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


def test_recon_modules_use_receipt_selected_helper_root() -> None:
    modules = {
        "ai_recon_portable_test": PROJECT_ROOT / "agents" / "ai_recon.py",
        "autonomous_recon_portable_test": PROJECT_ROOT / "agents" / "autonomous_recon.py",
    }

    original_path = list(sys.path)
    for name in ("scope_validator", "rate_limiter"):
        sys.modules.pop(name, None)
    try:
        for module_name, module_path in modules.items():
            module = _load_module(module_path, module_name)
            assert module.ScopeValidator is not None
            assert module.RateLimiter is not None
        assert str(PROJECT_ROOT / "agents") in sys.path
    finally:
        sys.path[:] = original_path
        for name in ("scope_validator", "rate_limiter"):
            sys.modules.pop(name, None)


def test_code_review_tolerates_absent_optional_bounty_tools() -> None:
    original_path = list(sys.path)
    sys.modules.pop("subagent_logger", None)
    try:
        module = _load_module(PROJECT_ROOT / "agents" / "code_review.py", "code_review_portable_test")
        assert module.SubagentLogger is None
        assert callable(module.compute_pte_lite)
    finally:
        sys.path[:] = original_path
        sys.modules.pop("subagent_logger", None)
