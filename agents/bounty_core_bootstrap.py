"""Import helper for the sibling bounty-core checkout."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import Iterable


SIBLING_BOUNTY_CORE_CHECKOUT = Path(__file__).resolve().parents[2] / "bounty-core"
PROJECTS_BOUNTY_CORE_CHECKOUT = Path.home() / "projects" / "bounty-core"


def _bounty_core_checkouts() -> list[Path]:
    """Return approved local Core checkouts in preference order."""
    configured = os.environ.get("BOUNTY_CORE_ROOT")
    candidates = ([Path(configured).expanduser()] if configured else []) + [
        SIBLING_BOUNTY_CORE_CHECKOUT,
        PROJECTS_BOUNTY_CORE_CHECKOUT,
    ]
    unique: list[Path] = []
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        if resolved not in unique:
            unique.append(resolved)
    return unique


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
    package_dirs = [checkout / "bounty_core" for checkout in _bounty_core_checkouts()]
    for package_dir in package_dirs:
        if not package_dir.is_dir():
            continue
        prefix = "bounty_core."
        if all(
            module == "bounty_core"
            or (module.startswith(prefix) and ((package_dir / f"{module.removeprefix(prefix).replace('.', '/')}.py").is_file() or (package_dir / module.removeprefix(prefix).replace('.', '/') / "__init__.py").is_file()))
            for module in required_modules
        ):
            return True
    return False


def _prefer_sibling_checkout() -> None:
    checkout = next((candidate for candidate in _bounty_core_checkouts() if (candidate / "bounty_core").is_dir()), None)
    if checkout is None:
        return
    package_dir = checkout / "bounty_core"

    checkout_text = str(checkout)
    if checkout_text in sys.path:
        sys.path.remove(checkout_text)
    sys.path.insert(0, checkout_text)

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
