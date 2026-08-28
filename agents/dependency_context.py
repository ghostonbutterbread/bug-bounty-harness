"""Resolve lane-bound external Python dependencies from aiskillsync state.

This module intentionally has no environment-variable or conventional-checkout
fallback. Cross-repository source must be selected by the active aiskillsync
receipt or fail before a mixed-lane process can start.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


CONFIG_PATH = Path.home() / ".config" / "bug-bounty-harness" / "dependencies.json"
DEFAULT_ACTIVE_STACK = Path.home() / ".config" / "aiskillsync" / "active-stack.json"


class DependencyResolutionError(RuntimeError):
    """The selected lane does not provide a valid external dependency."""


def _config() -> dict[str, Any]:
    try:
        value = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DependencyResolutionError(
            f"Missing BBH dependency configuration: {CONFIG_PATH}. "
            "Configure logical dependency projects selected by aiskillsync."
        ) from exc
    except json.JSONDecodeError as exc:
        raise DependencyResolutionError(f"Invalid BBH dependency configuration: {CONFIG_PATH}") from exc
    if not isinstance(value, dict):
        raise DependencyResolutionError(f"BBH dependency configuration must be an object: {CONFIG_PATH}")
    return value


def resolve_dependency_root(logical_name: str, package_path: str) -> Path:
    """Return a receipt-validated root for one logical dependency."""
    config = _config()
    active_stack = Path(config.get("active_stack", DEFAULT_ACTIVE_STACK)).expanduser()
    project_name = (config.get("projects") or {}).get(logical_name)
    if not isinstance(project_name, str) or not project_name:
        raise DependencyResolutionError(f"No aiskillsync project mapping for dependency '{logical_name}'")
    try:
        receipt = json.loads(active_stack.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DependencyResolutionError(f"Missing aiskillsync active-stack receipt: {active_stack}") from exc
    except json.JSONDecodeError as exc:
        raise DependencyResolutionError(f"Invalid aiskillsync active-stack receipt: {active_stack}") from exc
    if receipt.get("version") != 1:
        raise DependencyResolutionError(f"Unsupported active-stack receipt version: {active_stack}")
    project = (receipt.get("projects") or {}).get(project_name)
    if not isinstance(project, dict):
        raise DependencyResolutionError(f"Active stack has no selected project '{project_name}'")
    root_text, revision = project.get("root"), project.get("revision")
    if not isinstance(root_text, str) or not root_text or not isinstance(revision, str) or not revision:
        raise DependencyResolutionError(f"Active stack project '{project_name}' lacks root or revision")
    root = Path(root_text).expanduser().resolve()
    if not (root / package_path).exists():
        raise DependencyResolutionError(f"Selected dependency '{logical_name}' lacks {package_path}: {root}")
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode or result.stdout.strip() != revision:
        raise DependencyResolutionError(f"Stale or invalid active-stack revision for '{logical_name}': {root}")
    return root


def ensure_bounty_tools_importable(required_module: str | None = None) -> Path:
    root = resolve_dependency_root("bounty_tools", ".")
    if required_module and importlib.util.find_spec(required_module) is None:
        # The lookup above occurs before adding the selected root, so only use it
        # to detect an already-loaded foreign module below.
        pass
    root_text = str(root)
    if root_text in sys.path:
        sys.path.remove(root_text)
    sys.path.insert(0, root_text)
    if required_module:
        loaded = sys.modules.get(required_module)
        origin = getattr(loaded, "__file__", None)
        if origin and not Path(origin).resolve().is_relative_to(root):
            raise DependencyResolutionError(f"Preloaded {required_module} is outside selected bounty_tools root")
    return root
