"""BBH compatibility facade for Bounty Core evidence events.

Attempts are deliberate, append-only observations. Bounty Core owns their
product-neutral envelope, redaction, persistence, and bounded read mechanics;
BBH callers retain vulnerability-specific fields in the open ``details`` payload
or at the top level during the compatibility migration.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from agents.storage_resolver import WEB_FAMILY, resolve_storage


from bounty_core.evidence import (  # noqa: E402
    REQUIRED_EVENT_FIELDS,
    append_event,
    read_events,
    redact_event_value,
    utc_timestamp,
)

# Legacy names remain stable while BBH consumers migrate to the generic Core API.
REQUIRED_ATTEMPT_FIELDS = ("timestamp", "tool", "target", "outcome", "stop_reason")


def new_attempt_run_id() -> str:
    """Return a filesystem-safe identifier for one coherent attempt run."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"run-{stamp}-{uuid4().hex[:12]}"


def resolve_attempts_path(
    program: str,
    *,
    run_id: str,
    family: str = WEB_FAMILY,
    lane: str = "recon",
    root_override: str | Path | None = None,
) -> Path:
    """Return the generic run-owned Attempts stream for a resolved storage lane.

    Payload family, vulnerability class, target, and parameter remain event
    fields; the canonical filename is never class-specific.
    """
    normalized_run_id = str(run_id).strip()
    if (
        not normalized_run_id
        or normalized_run_id in {".", ".."}
        or "/" in normalized_run_id
        or "\\" in normalized_run_id
    ):
        raise ValueError("run_id must be a non-empty path-safe identifier")
    layout = resolve_storage(
        program,
        family=family,
        lane=lane,
        root_override=root_override,
        create=True,
    )
    return layout.lane_root / "attempts" / "_runs" / normalized_run_id / "attempts.jsonl"


def append_attempt(path: str | Path, attempt: Mapping[str, Any]) -> dict[str, Any]:
    """Append a BBH attempt through Bounty Core's canonical evidence writer.

    Preserve the pre-Core BBH required-field contract while Core normalizes the
    equivalent generic event envelope for shared readers.
    """
    missing = [field for field in REQUIRED_ATTEMPT_FIELDS if not str(attempt.get(field, "")).strip()]
    if missing:
        raise ValueError(f"attempt missing required fields: {', '.join(missing)}")
    event = dict(attempt)
    event_path = Path(path)
    if event_path.name == "attempts.jsonl" and event_path.parent.parent.name == "_runs":
        event.setdefault("run_id", event_path.parent.name)
    return append_event(event_path, event)


def read_attempts(
    path: str | Path,
    *,
    where: Mapping[str, Any] | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return bounded canonical attempts filtered by generic top-level fields."""
    return read_events(path, where=where, limit=limit)




def read_attempt_bucket(
    program: str,
    *,
    family: str = WEB_FAMILY,
    lane: str = "recon",
    root_override: str | Path | None = None,
    where: Mapping[str, Any] | None = None,
    limit: int = 100,
    run_limit: int = 100,
) -> list[dict[str, Any]]:
    """Read a bounded, newest-first view across generic Attempts run streams.

    The run JSONL files remain canonical. This is a read-time bucket query, not
    a second writable index or source of truth. Callers that need a specific
    run may continue to use :func:`read_attempts` with its exact path.
    """
    if limit < 1 or run_limit < 1:
        return []
    layout = resolve_storage(
        program,
        family=family,
        lane=lane,
        root_override=root_override,
        create=False,
    )
    runs_root = layout.lane_root / "attempts" / "_runs"
    if not runs_root.is_dir():
        return []

    events: list[dict[str, Any]] = []
    run_files = sorted(runs_root.glob("*/attempts.jsonl"), reverse=True)
    for run_file in run_files[:run_limit]:
        events.extend(read_attempts(run_file, where=where, limit=limit))

    events.sort(key=lambda event: str(event.get("timestamp", "")), reverse=True)
    return events[:limit]


def redact_attempt_value(value: Any, *, key: str = "") -> Any:
    """Preserve the historic BBH redaction helper name."""
    return redact_event_value(value, key=key)


__all__ = [
    "REQUIRED_ATTEMPT_FIELDS",
    "REQUIRED_EVENT_FIELDS",
    "append_attempt",
    "new_attempt_run_id",
    "read_attempts",
    "read_attempt_bucket",
    "redact_attempt_value",
    "resolve_attempts_path",
    "utc_timestamp",
]
