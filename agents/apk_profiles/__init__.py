"""Built-in APK hunt profiles."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ApkHuntProfile:
    key: str
    title: str
    description: str
    surface_types: tuple[str, ...]
    entry_questions: tuple[str, ...]
    cross_questions: tuple[str, ...]
    sink_categories: tuple[str, ...]
    reasoning: str
    prompt_addendum: str = ""
    tags: tuple[str, ...] = ()


from agents.apk_profiles.broadcast_hijack_hunter import PROFILE as BROADCAST_HIJACK_HUNTER
from agents.apk_profiles.deep_link_hunter import PROFILE as DEEP_LINK_HUNTER
from agents.apk_profiles.ipc_surface_hunter import PROFILE as IPC_SURFACE_HUNTER
from agents.apk_profiles.manifest_audit import PROFILE as MANIFEST_AUDIT
from agents.apk_profiles.native_abuse_hunter import PROFILE as NATIVE_ABUSE_HUNTER
from agents.apk_profiles.provider_exploit_hunter import PROFILE as PROVIDER_EXPLOIT_HUNTER
from agents.apk_profiles.webview_rce_hunter import PROFILE as WEBVIEW_RCE_HUNTER


BUILTIN_PROFILES = [
    DEEP_LINK_HUNTER,
    WEBVIEW_RCE_HUNTER,
    IPC_SURFACE_HUNTER,
    NATIVE_ABUSE_HUNTER,
    PROVIDER_EXPLOIT_HUNTER,
    BROADCAST_HIJACK_HUNTER,
    MANIFEST_AUDIT,
]

PROFILE_BY_KEY = {profile.key: profile for profile in BUILTIN_PROFILES}

