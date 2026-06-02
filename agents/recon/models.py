"""Plain JSON-compatible models for recon records."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


ASSET_SCHEMA_VERSION = 1
SURFACE_SCHEMA_VERSION = 1

ASSET_KINDS = {
    "asn",
    "certificate",
    "domain",
    "entity",
    "ip",
    "netblock",
    "provider",
    "service",
    "url",
}

SCOPE_STATUSES = {
    "in-scope",
    "out-of-scope",
    "needs-human-review",
    "unknown",
}

SURFACE_FAMILIES = {
    "auth-session-flow",
    "account-tenant-object",
    "api-endpoint-operation",
    "graphql-rpc-operation",
    "file-upload-ingestion",
    "media-avatar-profile",
    "url-fetch-import-webhook",
    "payment-gift-card-promo",
    "search-filter-query",
    "admin-support-impersonation",
    "notification-email-template",
    "storage-cache-export",
    "cdn-static-js-asset",
    "third-party-integration",
    "rate-limit-stateful-action",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(slots=True)
class EvidenceSource:
    """Where one graph record came from."""

    name: str
    source_type: str = "local-artifact"
    path: str | None = None
    field: str | None = None
    observed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(asdict(self))


@dataclass(slots=True)
class GraphEdge:
    """Relationship between graph records, by stable graph ids."""

    relation: str
    target_id: str
    source_id: str | None = None
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(asdict(self))


@dataclass(slots=True)
class AssetGraphRecord:
    """Normalized passive recon asset graph record.

    The record intentionally stays JSON-compatible so later surface-map,
    intel, and planner builders can consume JSONL without importing code.
    """

    kind: str
    value: str
    normalized_value: str
    scope_status: str = "unknown"
    graph_id: str = ""
    sources: list[EvidenceSource] = field(default_factory=list)
    confidence: float = 0.5
    labels: list[str] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = ASSET_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.kind not in ASSET_KINDS:
            raise ValueError(f"unsupported asset kind: {self.kind!r}")
        if self.scope_status not in SCOPE_STATUSES:
            raise ValueError(f"unsupported scope status: {self.scope_status!r}")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.labels = sorted(dict.fromkeys(str(label) for label in self.labels if label))
        if not self.graph_id:
            self.graph_id = make_graph_id(self.kind, self.normalized_value)

    def dedupe_key(self) -> tuple[str, str]:
        return self.kind, self.normalized_value

    def merge(self, other: "AssetGraphRecord") -> None:
        if self.dedupe_key() != other.dedupe_key():
            raise ValueError("cannot merge different graph records")
        self.sources = _dedupe_sources([*self.sources, *other.sources])
        self.labels = sorted(dict.fromkeys([*self.labels, *other.labels]))
        self.edges = _dedupe_edges([*self.edges, *other.edges])
        self.confidence = max(self.confidence, other.confidence)
        self.scope_status = _merge_scope_status(self.scope_status, other.scope_status)
        self.metadata = _merge_metadata(self.metadata, other.metadata)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["sources"] = [source.to_dict() for source in self.sources]
        payload["edges"] = [edge.to_dict() for edge in self.edges]
        return _drop_none(payload)


@dataclass(slots=True)
class ReconSurfaceRecord:
    """Normalized routeable Recon surface record.

    This intentionally stays JSON-compatible so future intel and planner
    builders can consume surface_map.jsonl without importing this package.
    """

    surface_id: str
    family: str
    entry_vector: str
    subtype: str = "unknown"
    attacker_influence: str = "unknown"
    auth_context: str = "unknown"
    reachable_evidence: list[str] = field(default_factory=list)
    source_artifact_path: str | None = None
    candidate_child_skills: list[str] = field(default_factory=list)
    http_method: str | None = None
    confidence: float = 0.5
    coverage_hints: list[str] = field(default_factory=lambda: ["untested"])
    scope_status: str = "unknown"
    sources: list[EvidenceSource] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = SURFACE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.family not in SURFACE_FAMILIES:
            raise ValueError(f"unsupported surface family: {self.family!r}")
        if self.scope_status not in SCOPE_STATUSES:
            raise ValueError(f"unsupported scope status: {self.scope_status!r}")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.reachable_evidence = sorted(dict.fromkeys(str(item) for item in self.reachable_evidence if item))
        self.candidate_child_skills = sorted(
            dict.fromkeys(str(item) for item in self.candidate_child_skills if item)
        )
        self.coverage_hints = sorted(dict.fromkeys(str(item) for item in self.coverage_hints if item))
        self.labels = sorted(dict.fromkeys(str(label) for label in self.labels if label))

    def dedupe_key(self) -> tuple[str, str, str]:
        return self.family, self.subtype, f"{self.http_method or ''} {self.entry_vector}".strip()

    def merge(self, other: "ReconSurfaceRecord") -> None:
        if self.dedupe_key() != other.dedupe_key():
            raise ValueError("cannot merge different surface records")
        self.sources = _dedupe_sources([*self.sources, *other.sources])
        self.reachable_evidence = sorted(dict.fromkeys([*self.reachable_evidence, *other.reachable_evidence]))
        self.candidate_child_skills = sorted(
            dict.fromkeys([*self.candidate_child_skills, *other.candidate_child_skills])
        )
        self.coverage_hints = sorted(dict.fromkeys([*self.coverage_hints, *other.coverage_hints]))
        self.labels = sorted(dict.fromkeys([*self.labels, *other.labels]))
        self.confidence = max(self.confidence, other.confidence)
        self.scope_status = _merge_scope_status(self.scope_status, other.scope_status)
        self.metadata = _merge_metadata(self.metadata, other.metadata)
        if not self.source_artifact_path and other.source_artifact_path:
            self.source_artifact_path = other.source_artifact_path

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["sources"] = [source.to_dict() for source in self.sources]
        return _drop_none(payload)


def make_graph_id(kind: str, normalized_value: str) -> str:
    cleaned = str(normalized_value or "").strip().lower()
    return f"{kind}:{cleaned}"


def _merge_scope_status(left: str, right: str) -> str:
    order = {
        "out-of-scope": 4,
        "in-scope": 3,
        "needs-human-review": 2,
        "unknown": 1,
    }
    return left if order.get(left, 0) >= order.get(right, 0) else right


def _merge_metadata(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = dict(left)
    for key, value in right.items():
        if key not in merged:
            merged[key] = value
        elif merged[key] == value:
            continue
        elif isinstance(merged[key], list):
            if value not in merged[key]:
                merged[key].append(value)
        else:
            merged[key] = [merged[key], value] if value != merged[key] else merged[key]
    return merged


def _dedupe_sources(sources: list[EvidenceSource]) -> list[EvidenceSource]:
    seen: set[tuple[str, str, str, str]] = set()
    result: list[EvidenceSource] = []
    for source in sources:
        key = (source.name, source.source_type, source.path or "", source.field or "")
        if key in seen:
            continue
        seen.add(key)
        result.append(source)
    return result


def _dedupe_edges(edges: list[GraphEdge]) -> list[GraphEdge]:
    seen: set[tuple[str, str, str]] = set()
    result: list[GraphEdge] = []
    for edge in edges:
        key = (edge.relation, edge.source_id or "", edge.target_id)
        if key in seen:
            continue
        seen.add(key)
        result.append(edge)
    return result


def _drop_none(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value is not None}
