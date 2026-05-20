from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from agents.hunt_pipeline.models import CategoryPack, CategoryPackPlan, HypothesisAgentPacket

_PRIORITY_SCORES = {
    "critical": 40.0,
    "high": 30.0,
    "medium": 20.0,
    "low": 10.0,
}
_ROLE_SCORES = {
    "entry": 5.0,
    "amplifier": 4.0,
    "chain": 3.0,
    "hardening": 2.0,
    "notes_only": 1.0,
}
_VULN_CLASS_MAP = {
    "file-ingestion-import": "file-import",
    "custom-protocol-deeplink": "deeplink",
    "ipc-bridge": "ipc",
    "hostrpc": "ipc",
    "preload-native-bridge": "ipc",
    "rendering-content-parser": "xss",
    "storage-cache-state": "storage",
    "navigation-popup": "navigation",
}
_EXPECTED_OUTPUTS = (
    "per-hypothesis verdicts",
    "distinct root-cause findings",
    "optional specialist follow-up requests",
)
_VERDICT_OPTIONS = (
    "confirmed-static",
    "rejected",
    "duplicate",
    "needs-specialist",
    "needs-dynamic-validation",
    "notes-only",
)
_TEXT_ROUTE_KEYS = (
    "route",
    "route_key",
    "endpoint",
    "endpoint_key",
    "operation_id",
    "handler",
    "graphql_resolver",
    "resolver",
)


@dataclass(frozen=True, slots=True)
class _PacketProfile:
    packet: HypothesisAgentPacket
    vuln_class: str
    subclass: str
    context_cluster_id: str
    route_or_endpoint_keys: tuple[str, ...]
    sink_types: tuple[str, ...]
    entry_paths: tuple[str, ...]
    policy_id: str | None
    evidence_ids: tuple[str, ...]
    source_files: tuple[str, ...]
    priority_score: float


@dataclass(slots=True)
class _CompatibilityCluster:
    members: list[_PacketProfile] = field(default_factory=list)
    route_or_endpoint_keys: tuple[str, ...] = ()
    entry_paths: tuple[str, ...] = ()

    def add(self, profile: _PacketProfile) -> None:
        self.members.append(profile)
        if not self.route_or_endpoint_keys and profile.route_or_endpoint_keys:
            self.route_or_endpoint_keys = profile.route_or_endpoint_keys
        if not self.entry_paths and profile.entry_paths:
            self.entry_paths = profile.entry_paths


def plan_category_packs(
    packets: Sequence[HypothesisAgentPacket],
    *,
    max_pack_size: int | None = None,
    mode: str = "auto",
) -> CategoryPackPlan:
    profiles = [_profile_packet(packet) for packet in packets]
    grouped: dict[tuple[str, ...], list[_PacketProfile]] = {}
    for profile in sorted(profiles, key=_profile_sort_key):
        key = _base_grouping_key(profile)
        grouped.setdefault(key, []).append(profile)

    cap = max(1, int(max_pack_size)) if max_pack_size is not None else None
    packs: list[CategoryPack] = []
    hypothesis_to_pack_id: dict[str, str] = {}
    pack_to_hypothesis_ids: dict[str, tuple[str, ...]] = {}

    for key in sorted(grouped):
        compatible_groups = _split_compatible_profiles(grouped[key])
        for members in compatible_groups:
            chunks = [members]
            if cap is not None and len(members) > cap:
                chunks = [members[index : index + cap] for index in range(0, len(members), cap)]
            total_chunks = len(chunks)
            for index, chunk in enumerate(chunks, start=1):
                pack = _build_pack(chunk, chunk_index=index, total_chunks=total_chunks)
                packs.append(pack)
                pack_to_hypothesis_ids[pack.pack_id] = pack.hypothesis_ids
                for hypothesis_id in pack.hypothesis_ids:
                    hypothesis_to_pack_id[hypothesis_id] = pack.pack_id

    return CategoryPackPlan(
        packs=tuple(packs),
        hypothesis_to_pack_id=hypothesis_to_pack_id,
        pack_to_hypothesis_ids=pack_to_hypothesis_ids,
        mode=str(mode or "auto").strip() or "auto",
        max_pack_size=cap,
    )


def pack_verdict_options() -> tuple[str, ...]:
    return _VERDICT_OPTIONS


def _build_pack(
    chunk: Sequence[_PacketProfile],
    *,
    chunk_index: int,
    total_chunks: int,
) -> CategoryPack:
    primary = chunk[0]
    source_files = _unique_text(item for profile in chunk for item in profile.source_files)
    route_keys = _unique_text(item for profile in chunk for item in profile.route_or_endpoint_keys)
    sink_types = _unique_text(item for profile in chunk for item in profile.sink_types)
    entry_paths = _unique_text(item for profile in chunk for item in profile.entry_paths)
    evidence_ids = _unique_text(item for profile in chunk for item in profile.evidence_ids)
    hypothesis_ids = tuple(profile.packet.id for profile in chunk)
    pack_id = _pack_id(
        primary,
        route_keys=route_keys,
        sink_types=sink_types,
        entry_paths=entry_paths,
        chunk_index=chunk_index,
        total_chunks=total_chunks,
    )
    reason = (
        f"Packed {len(chunk)} hypotheses by vuln_class={primary.vuln_class}, "
        f"subclass={primary.subclass}, context={primary.context_cluster_id}"
    )
    if primary.policy_id:
        reason += f", policy={primary.policy_id}"
    if route_keys:
        reason += f", routes={','.join(route_keys)}"
    if entry_paths:
        reason += f", entry_paths={','.join(entry_paths)}"
    return CategoryPack(
        pack_id=pack_id,
        vuln_class=primary.vuln_class,
        subclass=primary.subclass,
        surface_family=primary.packet.surface_family,
        context_cluster_id=primary.context_cluster_id,
        source_files=source_files,
        route_or_endpoint_keys=route_keys,
        sink_types=sink_types,
        entry_paths=entry_paths,
        policy_id=primary.policy_id,
        hypothesis_ids=hypothesis_ids,
        evidence_ids=evidence_ids,
        priority_score=max(profile.priority_score for profile in chunk),
        reason=reason,
        expected_outputs=_EXPECTED_OUTPUTS,
        specialist_followup_allowed=any(_specialist_followup_allowed(profile.packet) for profile in chunk),
    )


def _profile_packet(packet: HypothesisAgentPacket) -> _PacketProfile:
    vuln_class = _infer_vuln_class(packet)
    subclass = _infer_subclass(packet, vuln_class=vuln_class)
    context_cluster_id = _context_cluster_id(packet)
    route_keys = _route_or_endpoint_keys(packet)
    sink_types = _sink_types(packet, vuln_class=vuln_class, subclass=subclass)
    entry_paths = _entry_paths(packet, vuln_class=vuln_class, subclass=subclass)
    policy_id = _policy_id(packet, vuln_class=vuln_class)
    evidence_ids = _evidence_ids(packet)
    source_files = _source_files(packet)
    priority_score = _PRIORITY_SCORES.get(packet.priority, 0.0) + _ROLE_SCORES.get(packet.role, 0.0)
    return _PacketProfile(
        packet=packet,
        vuln_class=vuln_class,
        subclass=subclass,
        context_cluster_id=context_cluster_id,
        route_or_endpoint_keys=route_keys,
        sink_types=sink_types,
        entry_paths=entry_paths,
        policy_id=policy_id,
        evidence_ids=evidence_ids,
        source_files=source_files,
        priority_score=priority_score,
    )


def _infer_vuln_class(packet: HypothesisAgentPacket) -> str:
    family = str(packet.surface_family or "").strip().lower()
    return _VULN_CLASS_MAP.get(family, family or "unknown")


def _infer_subclass(packet: HypothesisAgentPacket, *, vuln_class: str) -> str:
    tokens = _signal_text(packet)
    if vuln_class == "xss":
        if _contains_any(tokens, "rich-text", "wysiwyg", "quill", "prosemirror", "markdown", "contenteditable"):
            return "rich-text-renderer-xss"
        if _contains_any(tokens, "dom-xss", "innerhtml", "outerhtml", "document.write", "location.hash", "location.search", "postmessage", "messageevent", "hash-based"):
            return "dom-xss"
        if _contains_any(tokens, "stored", "persist", "database", "saved", "comment", "draft", "offline", "cached", "workspace", "project"):
            return "stored-xss"
        if _contains_any(tokens, "reflected", "query", "searchparam", "url-param", "redirect", "returnto"):
            return "reflected-xss"
        return "renderer-xss"
    if vuln_class == "file-import":
        if _contains_any(tokens, "renderer", "render", "preview", "html", "markdown", "rich-text"):
            return "file-import-renderer-handoff"
        if _contains_any(tokens, "project", "config", "manifest", "template", "theme"):
            return "file-import-project-config"
        return "file-import-generic"
    if vuln_class == "ipc":
        if _contains_any(tokens, "filesystem", "file-open", "file-save", "openfile", "savefile", "readfile", "writefile", "download", "export", "path"):
            return "ipc-filesystem"
        if _contains_any(tokens, "window", "navigation", "loadurl", "openexternal", "popup", "browserwindow", "shell"):
            return "ipc-window-navigation"
        if _contains_any(tokens, "exec", "spawn", "process", "command"):
            return "ipc-execution"
        return "ipc-bridge"
    if vuln_class == "deeplink":
        if _contains_any(tokens, "oauth", "sso", "auth", "callback", "nonce", "state", "open-url", "second-instance"):
            return "deeplink-auth-callback"
        return "deeplink-generic"
    if vuln_class == "storage":
        if _contains_any(tokens, "offline", "cache", "indexeddb", "localstorage", "sessionstorage"):
            return "storage-offline-state"
        return "storage-state"
    if vuln_class == "navigation":
        if _contains_any(tokens, "external", "provider", "popup", "new-window"):
            return "navigation-external-provider"
        return "navigation-generic"
    return packet.surface_family or vuln_class or "generic"


def _context_cluster_id(packet: HypothesisAgentPacket) -> str:
    for value in (*packet.focus_files, *(_evidence_file(packet))):
        cleaned = str(value).strip()
        if cleaned:
            return cleaned
    for key in _TEXT_ROUTE_KEYS:
        cleaned = _metadata_text(packet, key)
        if cleaned:
            return cleaned
    return str(packet.surface_family or packet.key or packet.id or "unknown-context").strip()


def _route_or_endpoint_keys(packet: HypothesisAgentPacket) -> tuple[str, ...]:
    values: list[str] = []
    for key in _TEXT_ROUTE_KEYS:
        cleaned = _metadata_text(packet, key)
        if cleaned and cleaned not in values:
            values.append(cleaned)
    for item in packet.source_evidence:
        if not isinstance(item, Mapping):
            continue
        for key in ("name", "route", "endpoint", "handler"):
            cleaned = str(item.get(key) or "").strip()
            if cleaned and cleaned not in values:
                values.append(cleaned)
    return tuple(values)


def _sink_types(packet: HypothesisAgentPacket, *, vuln_class: str, subclass: str) -> tuple[str, ...]:
    values: list[str] = []
    for item in packet.source_evidence:
        if not isinstance(item, Mapping):
            continue
        for key in ("kind", "type", "sink", "sink_type"):
            cleaned = str(item.get(key) or "").strip().lower()
            if cleaned and cleaned not in values:
                values.append(cleaned)
    if vuln_class == "xss":
        if subclass == "dom-xss":
            values.append("dom-sink")
        elif subclass == "rich-text-renderer-xss":
            values.append("rich-text-renderer")
        else:
            values.append("renderer")
    elif vuln_class == "ipc":
        if subclass == "ipc-filesystem":
            values.append("filesystem")
        elif subclass == "ipc-window-navigation":
            values.append("window-navigation")
    return tuple(dict.fromkeys(values))


def _entry_paths(packet: HypothesisAgentPacket, *, vuln_class: str, subclass: str) -> tuple[str, ...]:
    values = _metadata_text_list(packet, "entry_paths")
    single = _metadata_text(packet, "entry_path")
    if single:
        values.append(single)
    if vuln_class == "xss":
        if subclass == "reflected-xss":
            values.append("query-string")
        elif subclass == "dom-xss":
            values.append("dom-runtime")
        elif subclass == "stored-xss":
            values.append("persisted-content")
        elif subclass == "rich-text-renderer-xss":
            values.append("rich-text-import")
    elif vuln_class == "file-import":
        values.append("imported-file")
    elif vuln_class == "ipc":
        values.append("renderer-ipc")
    elif vuln_class == "deeplink":
        values.append("deeplink")
    return tuple(dict.fromkeys(item for item in values if item))


def _policy_id(packet: HypothesisAgentPacket, *, vuln_class: str) -> str | None:
    for key in ("policy_id", "hunting_policy_id"):
        cleaned = _metadata_text(packet, key)
        if cleaned:
            return cleaned
    if packet.target_kind in {"electron", "desktop"} and vuln_class in {"ipc", "deeplink", "file-import", "navigation", "storage"}:
        return "electron-policy"
    return None


def _evidence_ids(packet: HypothesisAgentPacket) -> tuple[str, ...]:
    values: list[str] = []
    for item in packet.source_evidence:
        if not isinstance(item, Mapping):
            continue
        for key in ("id", "candidate_id", "source_id"):
            cleaned = str(item.get(key) or "").strip()
            if cleaned and cleaned not in values:
                values.append(cleaned)
                break
    return tuple(values)


def _source_files(packet: HypothesisAgentPacket) -> tuple[str, ...]:
    values = [str(item).strip() for item in packet.focus_files if str(item).strip()]
    for evidence_file in _evidence_file(packet):
        if evidence_file not in values:
            values.append(evidence_file)
    return tuple(values)


def _evidence_file(packet: HypothesisAgentPacket) -> tuple[str, ...]:
    values: list[str] = []
    for item in packet.source_evidence:
        if not isinstance(item, Mapping):
            continue
        cleaned = str(item.get("file") or item.get("path") or "").strip()
        if cleaned and cleaned not in values:
            values.append(cleaned)
    return tuple(values)


def _signal_text(packet: HypothesisAgentPacket) -> str:
    pieces: list[str] = [
        packet.surface_family,
        packet.role,
        packet.title,
        packet.priority,
        packet.target_kind,
        *packet.tags,
        *packet.reasons,
        *packet.evidence_requirements,
        *packet.chain_requirements,
    ]
    for key, value in sorted(packet.scheduler_metadata.items()):
        if isinstance(value, str):
            pieces.append(value)
        elif isinstance(value, (list, tuple)):
            pieces.extend(str(item) for item in value)
    for item in packet.source_evidence:
        if not isinstance(item, Mapping):
            continue
        for key in ("kind", "type", "name", "description", "role", "attacker_control"):
            cleaned = str(item.get(key) or "").strip()
            if cleaned:
                pieces.append(cleaned)
    return " ".join(piece.lower() for piece in pieces if str(piece).strip())


def _specialist_followup_allowed(packet: HypothesisAgentPacket) -> bool:
    return packet.role in {"entry", "chain", "amplifier"} and packet.priority in {"critical", "high", "medium"}


def _profile_sort_key(profile: _PacketProfile) -> tuple[Any, ...]:
    return (
        profile.vuln_class,
        profile.packet.surface_family,
        profile.subclass,
        profile.context_cluster_id,
        tuple(profile.sink_types),
        str(profile.policy_id or ""),
        0 if profile.route_or_endpoint_keys else 1,
        tuple(profile.route_or_endpoint_keys),
        0 if profile.entry_paths else 1,
        tuple(profile.entry_paths),
        -profile.priority_score,
        profile.packet.id,
        profile.packet.key,
    )


def _base_grouping_key(profile: _PacketProfile) -> tuple[str, ...]:
    return (
        profile.vuln_class,
        profile.packet.surface_family,
        profile.subclass,
        profile.context_cluster_id,
        "|".join(profile.sink_types),
        str(profile.policy_id or ""),
    )


def _split_compatible_profiles(members: Sequence[_PacketProfile]) -> list[list[_PacketProfile]]:
    clusters: list[_CompatibilityCluster] = []
    for profile in sorted(members, key=_profile_sort_key):
        matches = [cluster for cluster in clusters if _cluster_is_compatible(cluster, profile)]
        if matches:
            target = sorted(matches, key=lambda cluster: _cluster_sort_key(cluster, profile))[0]
            target.add(profile)
            continue
        cluster = _CompatibilityCluster()
        cluster.add(profile)
        clusters.append(cluster)
    return [sorted(cluster.members, key=_profile_sort_key) for cluster in sorted(clusters, key=_cluster_output_sort_key)]


def _cluster_is_compatible(cluster: _CompatibilityCluster, profile: _PacketProfile) -> bool:
    # Keep missing route/entry metadata in its own stable cluster so its pack_id
    # does not change when concrete siblings are added or removed nearby.
    route_compatible = _metadata_cluster_value_compatible(
        cluster.route_or_endpoint_keys,
        profile.route_or_endpoint_keys,
    )
    entry_compatible = _metadata_cluster_value_compatible(
        cluster.entry_paths,
        profile.entry_paths,
    )
    return route_compatible and entry_compatible


def _cluster_sort_key(cluster: _CompatibilityCluster, profile: _PacketProfile) -> tuple[Any, ...]:
    route_exact = int(
        bool(cluster.route_or_endpoint_keys and profile.route_or_endpoint_keys)
        and cluster.route_or_endpoint_keys == profile.route_or_endpoint_keys
    )
    entry_exact = int(bool(cluster.entry_paths and profile.entry_paths) and cluster.entry_paths == profile.entry_paths)
    return (
        -route_exact,
        -entry_exact,
        0 if cluster.route_or_endpoint_keys else 1,
        tuple(cluster.route_or_endpoint_keys),
        0 if cluster.entry_paths else 1,
        tuple(cluster.entry_paths),
        cluster.members[0].packet.id,
    )


def _cluster_output_sort_key(cluster: _CompatibilityCluster) -> tuple[Any, ...]:
    first = sorted(cluster.members, key=_profile_sort_key)[0]
    return (
        _profile_sort_key(first),
        tuple(cluster.route_or_endpoint_keys),
        tuple(cluster.entry_paths),
    )


def _metadata_cluster_value_compatible(
    cluster_values: tuple[str, ...],
    profile_values: tuple[str, ...],
) -> bool:
    if bool(cluster_values) != bool(profile_values):
        return False
    return not cluster_values or cluster_values == profile_values


def _pack_id(
    primary: _PacketProfile,
    *,
    route_keys: tuple[str, ...],
    sink_types: tuple[str, ...],
    entry_paths: tuple[str, ...],
    chunk_index: int,
    total_chunks: int,
) -> str:
    parts = [
        _slug(primary.vuln_class),
        f"family-{_slug(primary.packet.surface_family)}",
        _slug(primary.subclass),
        _slug(primary.context_cluster_id),
    ]
    if primary.policy_id:
        parts.append(f"policy-{_slug(primary.policy_id)}")
    if sink_types:
        parts.append(f"sink-{_slug_join(sink_types)}")
    if route_keys:
        parts.append(f"route-{_slug_join(route_keys)}")
    if entry_paths:
        parts.append(f"entry-{_slug_join(entry_paths)}")
    if total_chunks > 1:
        parts.append(f"chunk{chunk_index:03d}")
    return ".".join(part for part in parts if part)


def _metadata_text(packet: HypothesisAgentPacket, key: str) -> str:
    value = packet.scheduler_metadata.get(key)
    if isinstance(value, str):
        return value.strip()
    return ""


def _metadata_text_list(packet: HypothesisAgentPacket, key: str) -> list[str]:
    value = packet.scheduler_metadata.get(key)
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        cleaned = value.strip()
        return [cleaned] if cleaned else []
    return []


def _contains_any(haystack: str, *needles: str) -> bool:
    return any(needle in haystack for needle in needles)


def _unique_text(values: Sequence[str]) -> tuple[str, ...]:
    out: list[str] = []
    for value in values:
        cleaned = str(value).strip()
        if cleaned and cleaned not in out:
            out.append(cleaned)
    return tuple(out)


def _slug(value: str) -> str:
    cleaned = []
    for character in str(value or "").strip().lower():
        cleaned.append(character if character.isalnum() else "-")
    slug = "".join(cleaned).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "category-pack"


def _slug_join(values: Sequence[str]) -> str:
    return "--".join(_slug(value) for value in values if str(value).strip()) or "none"
