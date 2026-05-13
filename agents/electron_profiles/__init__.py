"""Built-in beta Electron Team profiles."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ElectronHuntProfile:
    key: str
    title: str
    description: str
    surface: str
    entry_questions: tuple[str, ...]
    trust_boundary_questions: tuple[str, ...]
    sink_categories: tuple[str, ...]
    focus_globs: tuple[str, ...]
    code_patterns: tuple[str, ...]
    reasoning: str
    prompt_addendum: str = ""
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


from agents.electron_profiles.config_auditor import PROFILE as CONFIG_AUDITOR
from agents.electron_profiles.ipc_protocol_hunter import PROFILE as IPC_PROTOCOL_HUNTER
from agents.electron_profiles.preload_bridge_hunter import PROFILE as PRELOAD_BRIDGE_HUNTER


BUILTIN_PROFILES = [
    CONFIG_AUDITOR,
    PRELOAD_BRIDGE_HUNTER,
    IPC_PROTOCOL_HUNTER,
]

PROFILE_BY_KEY = {profile.key: profile for profile in BUILTIN_PROFILES}

__all__ = [
    "BUILTIN_PROFILES",
    "CONFIG_AUDITOR",
    "ElectronHuntProfile",
    "IPC_PROTOCOL_HUNTER",
    "PRELOAD_BRIDGE_HUNTER",
    "PROFILE_BY_KEY",
]
