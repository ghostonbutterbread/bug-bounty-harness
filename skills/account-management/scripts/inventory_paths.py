"""Canonical program-scoped paths for BBH account inventories.

Account metadata is scoped to the selected target program, not to a browser
lane or a process-wide inventory.  Keep this module dependency-free because
it is imported by direct-execution helper scripts.
"""

from __future__ import annotations

import os
from pathlib import Path


def program_key(program: str) -> str:
    """Return the stable directory key shared by every account consumer."""
    key = "".join(char.lower() if char.isalnum() or char in "._-" else "-" for char in program.strip())
    key = key.strip(".-")
    if not key:
        raise ValueError("program must contain at least one letter or number")
    return key


def shared_base() -> Path:
    return Path(os.environ.get("HARNESS_SHARED_BASE", "~/Shared/web_bounty")).expanduser()


def inventory_path(program: str) -> Path:
    return shared_base() / program_key(program) / "credentials" / "account_inventory.json"
