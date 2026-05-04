"""Compatibility facade for shared brainstorm spec helpers.

Existing harness imports from ``agents.brainstorm_spec`` remain supported while
the implementation lives in ``bounty_core.brainstorm_spec``.
"""

from __future__ import annotations

from agents.bounty_core_bootstrap import ensure_bounty_core_importable

ensure_bounty_core_importable("bounty_core.brainstorm_spec")

from bounty_core.brainstorm_spec import *  # noqa: F401,F403,E402
