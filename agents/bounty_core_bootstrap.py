"""Import helper for the sibling bounty-core checkout."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Iterable


SIBLING_BOUNTY_CORE_CHECKOUT = Path(__file__).resolve().parents[2] / "bounty-core"


def ensure_bounty_core_importable(
    required_modules: str | Iterable[str] | None = None,
) -> None:
    """Make bounty_core importable, preferring the sibling checkout when needed.

    ``required_modules`` lets callers require submodules that may not exist in an
    older installed ``bounty_core`` package. When the sibling checkout contains
    the requested module, it is moved to the front of ``sys.path`` and added to
    an already-imported ``bounty_core`` package path before verification.
    """
    required = _normalize_required_modules(required_modules)
    if required and _sibling_satisfies(required):
        _prefer_sibling_checkout()
    elif importlib.util.find_spec("bounty_core") is None:
        _prefer_sibling_checkout()

    importlib.invalidate_caches()
    missing = [module for module in required if not _module_available(module)]
    if missing:
        joined = ", ".join(missing)
        raise ModuleNotFoundError(f"bounty_core missing required module(s): {joined}")


def _normalize_required_modules(
    required_modules: str | Iterable[str] | None,
) -> list[str]:
    if required_modules is None:
        return []
    if isinstance(required_modules, str):
        return [required_modules]
    return [str(module) for module in required_modules]


def _sibling_satisfies(required_modules: Iterable[str]) -> bool:
    package_dir = SIBLING_BOUNTY_CORE_CHECKOUT / "bounty_core"
    if not package_dir.is_dir():
        return False
    prefix = "bounty_core."
    for module in required_modules:
        if module == "bounty_core":
            continue
        if not module.startswith(prefix):
            return False
        relative = module.removeprefix(prefix).replace(".", "/")
        if not (package_dir / f"{relative}.py").is_file() and not (
            package_dir / relative / "__init__.py"
        ).is_file():
            return False
    return True


def _prefer_sibling_checkout() -> None:
    package_dir = SIBLING_BOUNTY_CORE_CHECKOUT / "bounty_core"
    if not package_dir.is_dir():
        return

    checkout = str(SIBLING_BOUNTY_CORE_CHECKOUT)
    if checkout in sys.path:
        sys.path.remove(checkout)
    sys.path.insert(0, checkout)

    loaded_package = sys.modules.get("bounty_core")
    package_path = getattr(loaded_package, "__path__", None)
    if package_path is None:
        return
    sibling_package = str(package_dir)
    try:
        if sibling_package in package_path:
            package_path.remove(sibling_package)
        package_path.insert(0, sibling_package)
    except AttributeError:
        loaded_package.__path__ = [
            sibling_package,
            *[path for path in package_path if path != sibling_package],
        ]


def _module_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, AttributeError, ValueError):
        return False
