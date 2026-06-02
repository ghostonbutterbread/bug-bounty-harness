#!/usr/bin/env python3
"""CLI wrapper for the passive recon asset intelligence graph."""

from __future__ import annotations

from pathlib import Path
import sys

_AGENT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _AGENT_DIR.parent
for path in (str(_REPO_ROOT), str(_AGENT_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from agents.recon.asset_intelligence import main


if __name__ == "__main__":
    raise SystemExit(main())
