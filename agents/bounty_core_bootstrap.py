"""Import Bounty Core only from the receipt-selected external checkout."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Iterable

from agents.dependency_context import DependencyResolutionError, resolve_dependency_root


def ensure_bounty_core_importable(
    required_modules: str | Iterable[str] | None = None,
) -> None:
    """Bind Bounty Core imports to the active aiskillsync receipt.

    Conventional checkout paths, inherited environment variables, installed
    packages, and already-loaded foreign package trees are deliberately rejected.
    """
    required = _normalize_required_modules(required_modules)
    root = resolve_dependency_root("bounty_core", "bounty_core")
    _reject_foreign_preload(root)
    root_text = str(root)
    if root_text in sys.path:
        sys.path.remove(root_text)
    sys.path.insert(0, root_text)
    importlib.invalidate_caches()
    missing = [module for module in required if importlib.util.find_spec(module) is None]
    if missing:
        raise ModuleNotFoundError(f"bounty_core missing required module(s): {', '.join(missing)}")


def _normalize_required_modules(required_modules: str | Iterable[str] | None) -> list[str]:
    if required_modules is None:
        return []
    if isinstance(required_modules, str):
        return [required_modules]
    return [str(module) for module in required_modules]


def _reject_foreign_preload(root: Path) -> None:
    loaded = sys.modules.get("bounty_core")
    origin = getattr(loaded, "__file__", None)
    if origin and not Path(origin).resolve().is_relative_to(root):
        raise DependencyResolutionError("Preloaded bounty_core is outside the receipt-selected root")
