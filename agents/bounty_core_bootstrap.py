"""Import helper for the sibling bounty-core checkout."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def ensure_bounty_core_importable() -> None:
    """Make the sibling bounty-core checkout importable when it is not installed."""
    if importlib.util.find_spec("bounty_core") is not None:
        return

    candidate = Path(__file__).resolve().parents[2] / "bounty-core"
    package_dir = candidate / "bounty_core"
    if package_dir.is_dir() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

