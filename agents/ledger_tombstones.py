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
    _core_identity,
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
    scrubbed: list[tuple[Path, int]] = field(default_factory=list)
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


def _split_jsonl(data: bytes) -> tuple[list[bytes], bytes]:
    """Split JSONL bytes on ``b"\\n"`` only: (terminated lines, unterminated tail).

    ``str.splitlines()`` also splits on U+0085, U+2028, U+2029, ``\\v``,
    ``\\f`` and ``\\x1c``-``\\x1e``, which may legitimately appear inside a
    JSON string written with ``ensure_ascii=False`` by another writer, so it is
    never used on JSONL here.
    """
    parts = data.split(b"\n")
    return parts[:-1], parts[-1]


def _parse_event(line: bytes) -> dict[str, Any] | None:
    try:
        event = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return event if isinstance(event, dict) and str(event.get("fid") or "").strip() else None


_EVENT_CACHE: dict[str, tuple[tuple[int, int, int], list[dict[str, Any]]]] = {}


def read_tombstone_events(path: Path) -> list[dict[str, Any]]:
    """Return committed events in file order; fail closed on a symlinked or corrupt log.

    Each event is one fsynced ``os.write`` ending in ``\\n`` and the ledger write
    happens only after it returns. A final line without ``\\n`` that parses as a
    complete event counts as committed (only the newline was lost); one that does
    not parse is a crash mid-append that never committed, and is ignored. Any
    other unreadable line raises :class:`CorruptTombstoneLogError`, so a damaged
    log never silently disables the resurrection guard. Parsed events are cached
    per (inode, size, mtime).
    """
    if path.is_symlink():
        raise CorruptTombstoneLogError(f"tombstone log is a symlink; refusing to use it: {path}")
    if not path.exists():
        return []
    if not path.is_file():
        raise CorruptTombstoneLogError(f"tombstone log is not a regular file: {path}")
    info = path.stat()
    stamp = (info.st_ino, info.st_size, info.st_mtime_ns)
    cached = _EVENT_CACHE.get(str(path))
    if cached is not None and cached[0] == stamp:
        return cached[1]
    lines, tail = _split_jsonl(path.read_bytes())
    events: list[dict[str, Any]] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        event = _parse_event(line)
        if event is None:
            raise CorruptTombstoneLogError(
                f"tombstone log line {number} is unreadable; repair {path} before ledger writes in this lane")
        events.append(event)
    tail_event = _parse_event(tail) if tail.strip() else None
    if tail_event is not None:
        events.append(tail_event)
    _EVENT_CACHE[str(path)] = (stamp, events)
    return events


def _repair_tail(path: Path) -> None:
    """Before appending (caller holds the ledger lock): terminate a complete final
    event that lost its newline, or truncate a partial one that never committed."""
    if not path.is_file() or path.is_symlink():
        return
    data = path.read_bytes()
    _lines, tail = _split_jsonl(data)
    if not tail:
        return
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
    try:
        if _parse_event(tail) is not None:
            os.write(fd, b"\n")
        else:
            os.ftruncate(fd, len(data) - len(tail))
        os.fsync(fd)
    finally:
        os.close(fd)


def active_tombstones(path: Path) -> dict[str, dict[str, Any]]:
    """Map upper-cased FID -> latest ``deleted`` event (a later ``delete_aborted`` clears it)."""
    latest: dict[str, dict[str, Any]] = {}
    for event in read_tombstone_events(path):
        latest[str(event["fid"]).strip().upper()] = event
    return {fid: event for fid, event in latest.items() if event.get("event") == "deleted"}


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _append_event(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise CorruptTombstoneLogError(f"refusing to append to symlinked tombstone log: {path}")
    created = not path.exists()
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        # ASCII-only JSON: no raw line/paragraph separators can reach the log.
        os.write(fd, (json.dumps(event, sort_keys=False, ensure_ascii=True) + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    if created:
        _fsync_dir(path.parent)


def _file_class(finding: dict[str, Any]) -> tuple[Any, Any]:
    key = _finding_key_for(finding)
    return key[0], key[2]


def _is_detailed(finding: dict[str, Any]) -> bool:
    """Bounty Core matches on (file, class) alone when line and type/title are absent."""
    return finding.get("line") is not None or (finding.get("type") or finding.get("title")) is not None


def _live_fids(ledger: Path) -> set[str] | None:
    """FIDs in the committed ledger (atomic replace gives a consistent snapshot); None if unreadable."""
    try:
        payload = json.loads(ledger.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    rows = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return None
    return {str(row.get("fid") or "").strip().upper() for row in rows if isinstance(row, dict)}


@dataclass
class TombstoneGuard:
    """Membership checks used by ledger-insert paths before adding a finding."""

    fids: set[str]
    path: Path
    ledger_path: Path | None = None
    keys: dict[tuple[Any, ...], str] = field(default_factory=dict)
    file_class: dict[tuple[Any, Any], str] = field(default_factory=dict)

    def match(self, finding: dict[str, Any], *, loose: bool = False) -> str | None:
        """Return the tombstoned FID this candidate would resurrect, if any.

        ``loose`` mirrors Bounty Core's (file, class)-only match for candidates
        with no line and no type/title; pass it only on paths whose Bounty Core
        lookup does the same (``ledger_check``/``check``, ``import_finding``,
        ``reserve_batch``). A tombstone whose FID is live in the ledger again
        (a crash between tombstone append and ledger write) never matches.
        """
        fid = str(finding.get("fid") or finding.get("harness_fid") or "").strip().upper()
        hit = fid if fid and fid in self.fids else None
        if hit is None:
            hit = self.keys.get(tuple(_finding_key_for(finding)))
        if hit is None and loose and not _is_detailed(finding):
            hit = self.file_class.get(_file_class(finding))
        if hit is not None and self.ledger_path is not None:
            live = _live_fids(self.ledger_path)
            if live is not None and hit.upper() in live:
                return None
        return hit

    def __bool__(self) -> bool:
        return bool(self.fids)


def tombstone_guard_for_layout(layout: StorageLayout) -> TombstoneGuard:
    path = tombstone_path_for(layout)
    events = active_tombstones(path)
    guard = TombstoneGuard(fids=set(events), path=path, ledger_path=layout.ledgers_root / "ledger.json")
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
    """Fail closed on a malformed ledger (Bounty Core before 5f5a66ac rewrote it as empty)."""
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
        try:
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
        except OSError as exc:
            keep.append((path, f"unreadable ({exc.__class__.__name__}); left in place"))
            return
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
    _write_ledger_durably(path, payload)


def _write_ledger_durably(path: Path, payload: dict[str, Any]) -> None:
    """Bounty Core's atomic replace, then fsync the file and its directory."""
    _write_json_atomic(path, payload)
    _fsync_ledger(path)


def _fsync_ledger(path: Path) -> None:
    """``_write_json_atomic`` does not fsync; syncing afterwards adds durability
    (matching the fsynced tombstone append) without changing its semantics."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(path.parent)


# Lane-local sidecars that copy per-FID finding text outside ledger.json.
# Both are JSONL; a row belongs to a FID through ``fid``/``harness_fid`` or a
# nested ``finding`` object (Bounty Core's ``finding_seen``/``finding_updated``).
FINDING_TEXT_SIDECARS = ("manual_comments.jsonl", "findings.jsonl")


def _row_matches(row: dict[str, Any], fid: str, identity: str) -> bool:
    """A row belongs to the FID by ``fid``/``harness_fid``, a nested ``finding``
    object, or Bounty Core's ``identity`` (``update_finding``'s ``finding_updated``)."""
    candidates = [row]
    if isinstance(row.get("finding"), dict):
        candidates.append(row["finding"])
    for item in candidates:
        if fid in {str(item.get(key) or "").strip().upper() for key in ("fid", "harness_fid")}:
            return True
        if str(item.get("identity") or "").strip() == identity:
            return True
    return False


def _scrub_bytes(data: bytes, fid: str, identity: str, path: Path) -> tuple[bytes, int]:
    """Return ``data`` without the FID's rows, every other byte preserved.

    Lines are split on ``b"\\n"`` only. A committed line that is not a JSON
    object raises; an unparseable unterminated tail is an append still in flight
    (Bounty Core appends some rows without the ledger lock) and is kept as-is.
    """
    lines, tail = _split_jsonl(data)
    kept: list[bytes] = []
    removed = 0
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            kept.append(line + b"\n")
            continue
        try:
            row = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            row = None
        if not isinstance(row, dict):
            raise LedgerDeleteError(
                f"refusing to delete: {path} line {number} is unreadable; repair it so {fid}'s rows can be removed")
        if _row_matches(row, fid, identity):
            removed += 1
        else:
            kept.append(line + b"\n")
    if tail.strip():
        try:
            tail_row = json.loads(tail.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            tail_row = None
        if isinstance(tail_row, dict) and _row_matches(tail_row, fid, identity):
            removed += 1
            tail = b""
    return b"".join(kept) + tail, removed


@dataclass
class _SidecarPlan:
    path: Path
    source: bytes
    fid: str
    identity: str
    removed: int


def _plan_sidecar_scrub(layout: StorageLayout, fid: str) -> list[_SidecarPlan]:
    """Parse each sidecar and plan a rewrite without the FID's rows; fail closed on damage.

    Called before the ledger commit, so an unreadable sidecar refuses the whole
    delete (nothing written) instead of leaving the finding's text behind or
    rewriting rows it cannot parse.
    """
    plans: list[_SidecarPlan] = []
    target = fid.strip().upper()
    identity = _core_identity(layout.program, layout.family, layout.lane, fid.strip())
    for name in FINDING_TEXT_SIDECARS:
        path = layout.ledgers_root / name
        if path.is_symlink():
            raise LedgerDeleteError(f"refusing to delete: {path} is a symlink; replace it with a regular file first")
        if not path.exists():
            continue
        if not path.is_file():
            raise LedgerDeleteError(f"refusing to delete: {path} is not a regular file")
        try:
            source = path.read_bytes()
        except OSError as exc:
            raise LedgerDeleteError(f"refusing to delete: cannot read {path} ({exc.__class__.__name__})") from exc
        _new, removed = _scrub_bytes(source, target, identity, path)
        if removed:
            plans.append(_SidecarPlan(path, source, target, identity, removed))
    return plans


def _apply_sidecar_scrub(plan: _SidecarPlan, lane_root: Path) -> int:
    """Atomically replace one sidecar; returns the number of rows removed.

    The file is re-read immediately before the replace and re-planned if it
    changed since planning (Bounty Core's lockless ``finding_seen`` append), so
    only the read-to-rename window remains. Same-dir temp file, original mode,
    fsync, no symlinks.
    """
    path = plan.path
    if path.is_symlink() or not path.is_file() or not _no_symlink_between(path, lane_root):
        raise LedgerDeleteError(f"{path} changed to a non-regular file during delete")
    current = path.read_bytes()
    new, removed = _scrub_bytes(current, plan.fid, plan.identity, path)
    if not removed:
        return 0
    mode = path.stat().st_mode & 0o777
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(new)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        if path.read_bytes() != current:  # grew while we wrote: re-plan once more
            new, removed = _scrub_bytes(path.read_bytes(), plan.fid, plan.identity, path)
            with open(temp_name, "wb") as handle:
                handle.write(new)
                handle.flush()
                os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise
    _fsync_dir(path.parent)
    return removed


def delete_finding_by_fid(
    program: str,
    fid: str,
    *,
    family: str | None = None,
    lane: str,
    root_override: str | Path | None = None,
    deleted_by: str | None = None,
) -> DeleteResult:
    """Permanently remove one archived finding.

    Raises :class:`LedgerDeleteError` for every failure before the ledger commit
    (nothing has been changed except, at most, a cleared tombstone). After the
    commit nothing raises: problems are returned in ``DeleteResult.warnings``.
    """
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
        try:
            record, remaining, plans, delete_paths, packet, evidence_template = _prepare_delete(
                layout, path, tombstone, payload, target, result)
            target = result.fid
            _repair_tail(tombstone)
            # Tombstone first: if the ledger write then fails, a delete_aborted
            # event clears it. Files and sidecars change only after the ledger
            # commit, because an unlink cannot be undone.
            _append_event(tombstone, {
                "schema": TOMBSTONE_SCHEMA,
                "event": "deleted",
                "fid": target,
                "identity_key": identity_key(record),
                "deleted_at": _utc_iso(),
                "deleted_by": (deleted_by or "").strip() or DEFAULT_ACTOR,
            })
            payload["findings"] = remaining
            payload["updated_at"] = _timestamp_iso()
            try:
                # Commit point: Bounty Core's writer ends in one rename, so if it
                # raises the old ledger is still in place.
                _write_json_atomic(path, payload)
            except BaseException:
                try:
                    _append_event(tombstone, {"schema": TOMBSTONE_SCHEMA, "event": "delete_aborted",
                                              "fid": target, "at": _utc_iso()})
                except Exception:
                    pass
                raise
        except LedgerDeleteError:
            raise
        except Exception as exc:
            raise LedgerDeleteError(f"delete of {target} failed before commit: {exc.__class__.__name__}: {exc}") from exc
        # Committed. Nothing below raises; problems become warnings (exit 3).
        try:
            _fsync_ledger(path)
        except Exception as exc:
            result.warnings.append(f"ledger fsync failed after commit: {exc.__class__.__name__}: {exc}")
        _finish_delete(layout, path, payload, result, plans, delete_paths, packet, evidence_template)
    return result


def _prepare_delete(layout, path, tombstone, payload, target, result):
    """Every refusal check and plan, before anything is written."""
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
    plans = _plan_sidecar_scrub(layout, target)
    delete_paths, keep, packet = classify_artifacts(layout, record)
    result.kept = keep
    evidence_template = (_pristine_evidence_template(layout, record)
                         if any(p.name == EVIDENCE_FILENAME for p in delete_paths) else None)
    remaining = findings[:index] + findings[index + 1:]
    return record, remaining, plans, delete_paths, packet, evidence_template


def _finish_delete(layout, path, payload, result, plans, delete_paths, packet, evidence_template) -> None:
    """Post-commit cleanup: never raises; every problem becomes a warning (exit 3)."""
    for plan in plans:
        try:
            removed = _apply_sidecar_scrub(plan, layout.lane_root)
            if removed:
                result.scrubbed.append((plan.path, removed))
        except Exception as exc:
            result.kept.append((plan.path, f"{plan.removed} row(s) for {result.fid} not removed"))
            result.warnings.append(f"could not remove {result.fid} rows from {plan.path}: {exc.__class__.__name__}: {exc}")
    for artifact in delete_paths:
        try:
            if _still_safe_to_unlink(artifact, layout.lane_root,
                                     evidence_template=evidence_template if artifact.name == EVIDENCE_FILENAME else None):
                artifact.unlink()
                result.deleted_files.append(artifact)
            else:
                result.kept.append((artifact, "changed during delete; left in place"))
        except Exception as exc:
            result.kept.append((artifact, f"unlink failed: {exc.__class__.__name__}"))
            result.warnings.append(f"could not delete generated file {artifact}: {exc}")
    try:
        _prune_empty_dirs(packet)
    except Exception as exc:
        result.warnings.append(f"could not prune empty packet directory: {exc.__class__.__name__}: {exc}")
    try:
        _refresh_and_persist(layout, path, payload)
    except Exception as exc:  # the delete itself is committed; surface the stale views
        result.warnings.append(f"navigation refresh failed after delete: {exc.__class__.__name__}: {exc}")


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
