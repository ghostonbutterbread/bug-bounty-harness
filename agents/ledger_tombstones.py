"""Permanent deletion of archived lane findings, with minimal tombstones.

Archive (``status`` = ``archive``) is the only recoverable state; deleting an
archived finding is final. Deletion is a single critical section under the
same ``ledgers/ledger.lock`` and atomic ``ledger.json`` replacement that every
Bounty Core ledger writer uses, so a concurrent ``--edit-finding`` or import
either completes before the delete reads the ledger or waits for it.

Each delete appends one minimal ``deleted`` event to
``ledgers/deleted-findings.jsonl``: the FID, the Bounty Core identity key the
resurrection guard matches on, ``deleted_at`` and ``deleted_by``. No title,
description, evidence, or report content is kept. :class:`TombstoneGuard` lets
ledger-insert paths skip a deleted FID/identity instead of re-adding it.

BBH-generated artifacts of the deleted FID (a ``bounty-core-finding-report``
whose ``generated-checksum`` still matches, or an untouched create-only
``EVIDENCE.md`` template) are unlinked. Anything else, including human-edited
reports, Bunny reports, PoCs, and symlinks, is left in place and reported.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Same lock, atomic writer, and migration that patch_finding_by_fid and the
# other Bounty Core ledger writers use (pinned in requirements.txt). They are
# module-private upstream; see docs/integrations/ledger-delete-finding.md for
# the proposed upstream home of this operation.
from bounty_core.ledger import (  # noqa: E402
    _finding_key_for,
    _locked_payload,
    _timestamp_iso,
    _write_json_atomic,
    ledger_path as core_ledger_path,
)
from bounty_core.indexes import refresh_indexes
from bounty_core.reports import (
    EVIDENCE_FILENAME,
    EVIDENCE_ONLY,
    FINDING_REPORT_GENERATED_MARKER,
    META_DIRNAME,
    _candidate_paths_for_fid,
    _packet_dir,
    ensure_finding_evidence_packet,
    is_generated_safe_finding_report,
    refresh_report_indexes,
)
from bounty_core.storage import StorageLayout, resolve_storage

TOMBSTONE_FILENAME = "deleted-findings.jsonl"
TOMBSTONE_SCHEMA = "bbh-deleted-finding/2"
ARCHIVE_STATUS = "archive"
DEFAULT_ACTOR = "manual_hunter"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_PARTIAL = 3


class LedgerDeleteError(ValueError):
    """A delete was refused; nothing was written."""


class MalformedLedgerError(LedgerDeleteError):
    """The on-disk ledger cannot be parsed; refuse rather than overwrite it."""


@dataclass
class DeleteResult:
    fid: str
    ledger_path: Path
    tombstone_path: Path
    deleted_files: list[Path] = field(default_factory=list)
    kept: list[tuple[Path, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_status(value: Any) -> str:
    """Status normalization shared with Bounty Core ``_core_status_for``."""
    return str(value or "").strip().lower()


def finding_status(finding: dict[str, Any]) -> str:
    """Top-level ``status`` is canonical; ``current.status`` is its mirror.

    ``--edit-finding`` patches the top-level field and, because status is in
    the patch, mirrors it to ``current.status``. Fall back to the mirror only
    for a record that has no top-level status.
    """
    top = normalize_status(finding.get("status"))
    if top:
        return top
    current = finding.get("current")
    return normalize_status(current.get("status")) if isinstance(current, dict) else ""


def identity_key(finding: dict[str, Any]) -> list[Any]:
    """Bounty Core's dedupe key (file, line, class, type) as JSON-able list."""
    return list(_finding_key_for(finding))


def _layout(program: str, *, family: str | None, lane: str, root_override: str | Path | None) -> StorageLayout:
    return resolve_storage(program, family=family, lane=lane, root_override=root_override, create=False)


def tombstone_path_for(layout: StorageLayout) -> Path:
    return layout.ledgers_root / TOMBSTONE_FILENAME


# --------------------------------------------------------------------------
# Tombstone log
# --------------------------------------------------------------------------

class CorruptTombstoneLogError(LedgerDeleteError):
    """The tombstone log is unreadable; refuse rather than let deleted findings back in."""


def read_tombstone_events(path: Path) -> list[dict[str, Any]]:
    """Return events in file order; fail closed on a symlinked or corrupt log.

    A truncated or partially synced log must not silently disable the
    resurrection guard, so any non-empty line that is not a JSON object with a
    FID raises :class:`CorruptTombstoneLogError`.
    """
    if path.is_symlink():
        raise CorruptTombstoneLogError(f"tombstone log is a symlink; refusing to use it: {path}")
    if not path.exists():
        return []
    if not path.is_file():
        raise CorruptTombstoneLogError(f"tombstone log is not a regular file: {path}")
    events: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            event = None
        if not isinstance(event, dict) or not str(event.get("fid") or "").strip():
            raise CorruptTombstoneLogError(
                f"tombstone log line {number} is unreadable; repair {path} before ledger writes in this lane")
        events.append(event)
    return events


def active_tombstones(path: Path) -> dict[str, dict[str, Any]]:
    """Map upper-cased FID -> latest ``deleted`` event (a later ``delete_aborted`` clears it)."""
    latest: dict[str, dict[str, Any]] = {}
    for event in read_tombstone_events(path):
        latest[str(event["fid"]).strip().upper()] = event
    return {fid: event for fid, event in latest.items() if event.get("event") == "deleted"}


def _append_event(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise CorruptTombstoneLogError(f"refusing to append to symlinked tombstone log: {path}")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, (json.dumps(event, sort_keys=False, ensure_ascii=False) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _file_class(finding: dict[str, Any]) -> tuple[Any, Any]:
    key = _finding_key_for(finding)
    return key[0], key[2]


def _is_detailed(finding: dict[str, Any]) -> bool:
    """Bounty Core matches on (file, class) alone when line and type/title are absent."""
    return finding.get("line") is not None or (finding.get("type") or finding.get("title")) is not None


@dataclass
class TombstoneGuard:
    """Membership checks used by ledger-insert paths before adding a finding."""

    fids: set[str]
    path: Path
    keys: dict[tuple[Any, ...], str] = field(default_factory=dict)
    file_class: dict[tuple[Any, Any], str] = field(default_factory=dict)

    def match(self, finding: dict[str, Any]) -> str | None:
        """Return the tombstoned FID this candidate would resurrect, if any."""
        fid = str(finding.get("fid") or finding.get("harness_fid") or "").strip().upper()
        if fid and fid in self.fids:
            return fid
        hit = self.keys.get(tuple(_finding_key_for(finding)))
        if hit is None and not _is_detailed(finding):
            hit = self.file_class.get(_file_class(finding))
        return hit

    def __bool__(self) -> bool:
        return bool(self.fids)


def tombstone_guard_for_layout(layout: StorageLayout) -> TombstoneGuard:
    path = tombstone_path_for(layout)
    events = active_tombstones(path)
    guard = TombstoneGuard(fids=set(events), path=path)
    for fid, event in events.items():
        key = event.get("identity_key")
        if isinstance(key, list) and len(key) == 4:
            guard.keys[tuple(key)] = fid
            guard.file_class[(key[0], key[2])] = fid
    return guard


def tombstone_guard(
    program: str, *, family: str | None = None, lane: str, root_override: str | Path | None = None,
) -> TombstoneGuard:
    return tombstone_guard_for_layout(_layout(program, family=family, lane=lane, root_override=root_override))


def skip_message(fid: str, source: str) -> str:
    return f"Skipped tombstoned finding {fid} ({source}): it was permanently deleted from this lane"


# --------------------------------------------------------------------------
# Ledger validation and FID allocation safety
# --------------------------------------------------------------------------

def _assert_ledger_well_formed(path: Path) -> None:
    """Fail closed: Bounty Core reads a malformed ledger as empty and writes it back."""
    if not path.exists():
        return
    if path.is_symlink() or not path.is_file():
        raise MalformedLedgerError(f"ledger is not a regular file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedLedgerError(f"ledger is malformed; refusing to rewrite it: {path} ({exc.__class__.__name__})") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("findings", []), list):
        raise MalformedLedgerError(f"ledger has no findings list; refusing to rewrite it: {path}")


_FID_RE = re.compile(r"(.*?)(\d+)")


def _would_free_next_fid(fid: str, findings: Iterable[dict[str, Any]]) -> bool:
    """True when removing ``fid`` lets Bounty Core's ``_next_fid`` hand it out again.

    ``_next_fid`` allocates ``max(existing suffix for prefix) + 1`` from the
    findings list only, so deleting the highest FID of a prefix would let the
    next new finding reuse it. Keeping the highest FID present preserves the
    invariant that every deleted FID is below the allocation high-water mark.
    """
    match = _FID_RE.fullmatch(fid.strip())
    if not match:
        return False  # _next_fid only allocates <prefix><digits>; this FID cannot be handed out again
    prefix, number = match.group(1).upper(), int(match.group(2))
    highest_other = 0
    for finding in findings:
        other = str(finding.get("fid") or "").strip().upper()
        if other == fid.strip().upper() or not other.startswith(prefix):
            continue
        suffix = other[len(prefix):]
        if suffix.isdigit():
            highest_other = max(highest_other, int(suffix))
    return number > highest_other


# --------------------------------------------------------------------------
# Artifact classification
# --------------------------------------------------------------------------

def _inside(path: Path, root: Path) -> bool:
    try:
        return Path(os.path.abspath(path)).is_relative_to(Path(os.path.abspath(root))) and \
            path.resolve(strict=False).is_relative_to(root.resolve(strict=False))
    except (OSError, RuntimeError):
        return False


def _no_symlink_between(path: Path, root: Path) -> bool:
    """No component from ``root`` (exclusive) down to ``path`` is a symlink."""
    current = Path(os.path.abspath(path))
    stop = Path(os.path.abspath(root))
    while current != stop and current != current.parent:
        if current.is_symlink():
            return False
        current = current.parent
    return current == stop


def _pristine_evidence_template(layout: StorageLayout, finding: dict[str, Any]) -> bytes | None:
    """Render Bounty Core's create-only EVIDENCE.md for this record in scratch storage."""
    probe = {k: v for k, v in finding.items() if k not in {"report_dir", "report_path", "evidence_path", "finalized_report_path"}}
    try:
        with tempfile.TemporaryDirectory(prefix="bbh-evidence-probe-") as scratch:
            scratch_layout = resolve_storage(layout.program, family=layout.family, lane=layout.lane,
                                             root_override=scratch, create=True)
            return ensure_finding_evidence_packet(scratch_layout, probe).read_bytes()
    except (OSError, ValueError):
        return None


def _is_generated_report(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            first = handle.readline().strip()
    except OSError:
        return False
    return first == FINDING_REPORT_GENERATED_MARKER and is_generated_safe_finding_report(path)


def classify_artifacts(layout: StorageLayout, finding: dict[str, Any]) -> tuple[list[Path], list[tuple[Path, str]], Path | None]:
    """Return (delete, keep-with-reason, packet_dir) for one finding's files."""
    lane_root = layout.lane_root
    delete: list[Path] = []
    keep: list[tuple[Path, str]] = []
    seen: set[str] = set()

    def consider(path: Path, *, evidence_template: bytes | None = None) -> None:
        key = os.path.abspath(path)
        if key in seen:
            return
        seen.add(key)
        if path.is_symlink():
            keep.append((path, "symlink (not followed)"))
            return
        if not path.exists():
            return
        if not _inside(path, lane_root) or not _no_symlink_between(path, lane_root):
            keep.append((path, "outside lane or behind a symlink"))
            return
        if path.is_dir():
            keep.append((path, "directory with non-generated content"))
            return
        if not path.is_file():
            keep.append((path, "not a regular file"))
            return
        if path.name == EVIDENCE_FILENAME:
            if evidence_template is not None and path.read_bytes() == evidence_template:
                delete.append(path)
            else:
                keep.append((path, "evidence edited after creation"))
            return
        if _is_generated_report(path):
            delete.append(path)
            return
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            first = handle.readline().strip()
        keep.append((path, "generated report edited (checksum mismatch)" if first == FINDING_REPORT_GENERATED_MARKER
                     else "not BBH-generated"))

    packet: Path | None = None
    try:
        packet = _packet_dir(layout.reports_root, finding)
    except ValueError as exc:
        if finding.get("report_dir"):
            keep.append((Path(str(finding["report_dir"])).expanduser(), f"packet pointer rejected: {exc}"))
    if packet is not None and packet.is_symlink():
        keep.append((packet, "symlink (not followed)"))
        packet = None
    if packet is not None and packet.is_dir() and _inside(packet, lane_root) and _no_symlink_between(packet, lane_root):
        template = _pristine_evidence_template(layout, finding)
        for child in sorted(packet.iterdir()):
            if child.name == META_DIRNAME and child.is_dir() and not child.is_symlink():
                for meta in sorted(child.rglob("*")):
                    if meta.is_symlink() or meta.is_file():
                        consider(meta)
                continue
            consider(child, evidence_template=template if child.name == EVIDENCE_FILENAME else None)
    elif packet is not None and packet.exists():
        keep.append((packet, "packet is not a directory inside the lane"))
        packet = None
    else:
        packet = None

    try:
        # Bounty Core's own FID-ownership filter: report pointers that leave this
        # FID's packet (or its legacy lifecycle names) are never candidates.
        legacy = _candidate_paths_for_fid(layout, finding)
    except ValueError:
        legacy = []
    owned = {os.path.abspath(path) for path in legacy}
    for key in ("report_path", "finalized_report_path"):
        value = finding.get(key)
        if not value:
            continue
        pointer = Path(str(value)).expanduser()
        marker = os.path.abspath(pointer)
        if marker not in owned and marker not in seen and (pointer.exists() or pointer.is_symlink()):
            seen.add(marker)
            keep.append((pointer, f"{key} not owned by this FID"))
    for path in legacy:
        if packet is not None and os.path.abspath(path.parent) == os.path.abspath(packet):
            continue
        if path.is_symlink():
            consider(path)
        elif not _inside(path, layout.reports_root):
            if path.exists():
                key = os.path.abspath(path)
                if key not in seen:
                    seen.add(key)
                    keep.append((path, "outside the lane reports root"))
        else:
            consider(path)
    return delete, keep, packet


def _still_safe_to_unlink(path: Path, lane_root: Path, *, evidence_template: bytes | None) -> bool:
    """Re-check immediately before unlinking: same classification, no symlinks."""
    if path.is_symlink() or not path.is_file():
        return False
    if not _inside(path, lane_root) or not _no_symlink_between(path, lane_root):
        return False
    if path.name == EVIDENCE_FILENAME:
        return evidence_template is not None and path.read_bytes() == evidence_template
    return _is_generated_report(path)


def _prune_empty_dirs(packet: Path | None) -> None:
    if packet is None:
        return
    for directory in (packet / META_DIRNAME, packet):
        try:
            if directory.is_dir() and not directory.is_symlink():
                directory.rmdir()
        except OSError:
            pass


# --------------------------------------------------------------------------
# Delete
# --------------------------------------------------------------------------

def _refresh_and_persist(layout: StorageLayout, path: Path, payload: dict[str, Any]) -> None:
    """Refresh derived views as ``patch_finding_by_fid(refresh=True)`` does, still under the lock.

    The evidence-only refresh may fill packet pointers on the remaining
    findings, so the ledger is written again afterwards.
    """
    findings = payload["findings"]
    refresh_indexes(layout, findings)
    refresh_report_indexes(layout, findings, packet_mode=EVIDENCE_ONLY)
    _write_json_atomic(path, payload)


def delete_finding_by_fid(
    program: str,
    fid: str,
    *,
    family: str | None = None,
    lane: str,
    root_override: str | Path | None = None,
    deleted_by: str | None = None,
) -> DeleteResult:
    """Permanently remove one archived finding; raise LedgerDeleteError on refusal."""
    target = str(fid or "").strip()
    if not target:
        raise LedgerDeleteError("finding fid is required")
    layout = _layout(program, family=family, lane=lane, root_override=root_override)
    path = core_ledger_path(layout.program, lane=layout.lane, family=layout.family, root_override=root_override)
    tombstone = tombstone_path_for(layout)
    result = DeleteResult(fid=target, ledger_path=path, tombstone_path=tombstone)
    if not path.exists():
        raise LedgerDeleteError(f"no finding found for fid {target} (lane has no ledger: {path})")

    with _locked_payload(layout.program, exclusive=True, lane=layout.lane, family=layout.family,
                         root_override=root_override, auto_write=False) as payload:
        _assert_ledger_well_formed(path)
        read_tombstone_events(tombstone)  # fail closed before appending to a corrupt log
        findings = [item for item in payload.get("findings", []) if isinstance(item, dict)]
        index = next((i for i, item in enumerate(findings)
                      if str(item.get("fid") or "").strip().upper() == target.upper()), None)
        if index is None:
            raise LedgerDeleteError(f"no finding found for fid {target}")
        record = findings[index]
        target = str(record.get("fid")).strip()
        result.fid = target
        status = finding_status(record)
        if status != ARCHIVE_STATUS:
            raise LedgerDeleteError(
                f"refusing to delete {target}: status is {status or '(unset)'!r}, not 'archive'; "
                "archive it first (e.g. --edit-finding with {\"status\":\"archive\"})")
        if "_atomic_import_pending" in record:
            raise LedgerDeleteError(f"refusing to delete {target}: an import is pending on this finding")
        if _would_free_next_fid(target, findings):
            raise LedgerDeleteError(
                f"refusing to delete {target}: it is the highest FID of its prefix, so the next new finding "
                "would reuse it; delete it after a newer finding exists in this lane")

        delete_paths, keep, packet = classify_artifacts(layout, record)
        evidence_template = (_pristine_evidence_template(layout, record)
                             if any(p.name == EVIDENCE_FILENAME for p in delete_paths) else None)
        remaining = findings[:index] + findings[index + 1:]
        # Tombstone first: if the ledger write then fails, a delete_aborted event
        # clears it. Files are unlinked only after the ledger commit, because an
        # unlink cannot be undone.
        _append_event(tombstone, {
            "schema": TOMBSTONE_SCHEMA,
            "event": "deleted",
            "fid": target,
            "identity_key": identity_key(record),
            "deleted_at": _utc_iso(),
            "deleted_by": (deleted_by or "").strip() or DEFAULT_ACTOR,
        })
        try:
            payload["findings"] = remaining
            payload["updated_at"] = _timestamp_iso()
            _write_json_atomic(path, payload)
        except Exception:
            try:
                _append_event(tombstone, {"schema": TOMBSTONE_SCHEMA, "event": "delete_aborted",
                                          "fid": target, "at": _utc_iso()})
            except Exception:
                pass
            raise
        result.kept = keep
        for artifact in delete_paths:
            try:
                if _still_safe_to_unlink(artifact, layout.lane_root,
                                         evidence_template=evidence_template if artifact.name == EVIDENCE_FILENAME else None):
                    artifact.unlink()
                    result.deleted_files.append(artifact)
                else:
                    result.kept.append((artifact, "changed during delete; left in place"))
            except OSError as exc:
                result.kept.append((artifact, f"unlink failed: {exc.__class__.__name__}"))
                result.warnings.append(f"could not delete generated file {artifact}: {exc}")
        _prune_empty_dirs(packet)
        try:
            _refresh_and_persist(layout, path, payload)
        except Exception as exc:  # the delete itself is committed; surface the stale views
            result.warnings.append(f"navigation refresh failed after delete: {exc.__class__.__name__}: {exc}")
    return result


__all__ = [
    "ARCHIVE_STATUS",
    "CorruptTombstoneLogError",
    "DeleteResult",
    "LedgerDeleteError",
    "MalformedLedgerError",
    "TOMBSTONE_FILENAME",
    "TombstoneGuard",
    "active_tombstones",
    "classify_artifacts",
    "delete_finding_by_fid",
    "finding_status",
    "skip_message",
    "tombstone_guard",
    "tombstone_guard_for_layout",
    "tombstone_path_for",
]
