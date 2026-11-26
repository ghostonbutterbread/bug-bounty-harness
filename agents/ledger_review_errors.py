"""Move oversized ``review_error`` values out of a lane ledger into the log folder.

Older BBH stored a failed review's full CLI output (megabytes of Codex session
text) in ``review_error``. ``manual_hunter --compact-review-errors`` finds
values longer than :data:`SUMMARY_CAP`; with ``apply=True`` it writes each full
value to ``review/<program>/<lane>/<id>-compacted-<UTC>-<rand>.log`` under the
review log root, re-reads and sha256-verifies it, then replaces the field with
the capped summary plus ``review_log``.

All ledger changes happen in one exclusive ``ledger.lock`` section through
Bounty Core's own lock and atomic writer (same pinned private imports as
``agents/ledger_report_dirs.py``). If the ledger bytes change while the lock is
held (a writer that ignores the lock) or any log write/verify fails, the
ledger is not written and the logs written by this run are removed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bounty_core.ledger import _locked_payload, _timestamp_iso, _write_json_atomic  # noqa: E402
from bounty_core.ledger import migrate_ledger_payload  # noqa: E402
from bounty_core.ledger import ledger_path as core_ledger_path  # noqa: E402
from bounty_core.storage import resolve_storage

from agents.base_team.review_logs import (
    SUMMARY_CAP,
    capped_summary,
    encode_log_text,
    finding_log_id,
    log_root,
    write_log,
)

try:  # Bounty Core >= 5f5a66ac refuses malformed ledgers with LedgerReadError.
    from bounty_core.ledger import LedgerReadError as _LedgerReadError  # noqa: E402
    _LEDGER_READ_ERRORS: tuple[type[BaseException], ...] = (_LedgerReadError,)
except ImportError:
    _LEDGER_READ_ERRORS = ()

# Split only at a CLI boundary so each CLI keeps its own prefix in the summary.
_CLI_BOUNDARY = re.compile(r"; (?=(?:claude|codex): )")


class CompactAborted(RuntimeError):
    """Nothing was written to the ledger."""


@dataclass
class CompactItem:
    fid: str
    original_bytes: int
    log_path: str | None = None


@dataclass
class CompactResult:
    ledger_path: Path
    ledger_bytes_before: int = 0
    ledger_bytes_after: int = 0  # estimated on dry run, actual after apply
    items: list[CompactItem] = field(default_factory=list)
    applied: bool = False

    @property
    def bytes_moved(self) -> int:
        return sum(item.original_bytes for item in self.items)


def is_oversized(finding: Any) -> bool:
    value = finding.get("review_error") if isinstance(finding, dict) else None
    return isinstance(value, str) and len(value) > SUMMARY_CAP


def compacted_summary(original: str, log_path: str) -> str:
    return capped_summary(_CLI_BOUNDARY.split(original), f" (full log: {log_path})")


def _serialized_size(payload: dict[str, Any]) -> int:
    # Same format as bounty_core.ledger._write_json_atomic.
    return len((json.dumps(payload, indent=2, sort_keys=False) + "\n").encode("utf-8", "surrogatepass"))


def _same_ledger(program: str, on_disk: Any, payload: dict[str, Any]) -> bool:
    """True when the bytes we read are the ledger Bounty Core loaded (after its migration)."""
    if not isinstance(on_disk, dict):
        return False
    migrated = migrate_ledger_payload(program, on_disk)
    migrated.pop("updated_at", None)  # migration may default a missing timestamp to now
    return migrated == {key: value for key, value in payload.items() if key != "updated_at"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact_review_errors(
    program: str,
    *,
    family: str | None = None,
    lane: str,
    root_override: str | Path | None = None,
    apply: bool = False,
) -> CompactResult:
    layout = resolve_storage(program, family=family, lane=lane, root_override=root_override, create=False)
    ledger_file = core_ledger_path(layout.program, lane=layout.lane, family=layout.family, root_override=root_override)
    result = CompactResult(ledger_path=ledger_file)
    if not ledger_file.is_file():
        raise ValueError(f"lane has no ledger: {ledger_file}")
    try:
        with _locked_payload(layout.program, exclusive=apply, lane=layout.lane, family=layout.family,
                             root_override=root_override, auto_write=False) as payload:
            raw = ledger_file.read_bytes()
            try:
                on_disk = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise CompactAborted(f"ledger is malformed; nothing written ({type(exc).__name__})") from None
            if not _same_ledger(layout.program, on_disk, payload):
                raise CompactAborted("ledger changed while it was being read; nothing written")
            result.ledger_bytes_before = len(raw)
            findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []
            targets = [finding for finding in findings if is_oversized(finding)]
            result.items = [
                CompactItem(str(f.get("fid") or finding_log_id(f)), len(encode_log_text(f["review_error"])))
                for f in targets
            ]
            if not targets:
                result.ledger_bytes_after = result.ledger_bytes_before
                return result
            if not apply:
                placeholder = str(log_root() / "review" / layout.program / layout.lane / "F0000-compacted-00000000T000000Z-000000.log")
                estimate = dict(payload)
                estimate["findings"] = [
                    {**f, "review_error": compacted_summary(f["review_error"], placeholder), "review_log": placeholder}
                    if is_oversized(f) else f
                    for f in findings
                ]
                result.ledger_bytes_after = _serialized_size(estimate)
                return result
            _apply_locked(payload, targets, result, raw, ledger_file, program=layout.program, lane=layout.lane)
    except _LEDGER_READ_ERRORS as exc:
        raise CompactAborted(f"ledger is malformed; nothing written: {exc}") from None
    return result


def _apply_locked(
    payload: dict[str, Any],
    targets: list[dict[str, Any]],
    result: CompactResult,
    raw: bytes,
    ledger_file: Path,
    *,
    program: str,
    lane: str,
) -> None:
    written: list[Path] = []
    try:
        for finding, item in zip(targets, result.items):
            original = finding["review_error"]
            expected = _sha256(encode_log_text(original))
            path = write_log(original, category="review", program=program, lane=lane,
                             name=f"{finding_log_id(finding)}-compacted")
            written.append(path)
            if _sha256(path.read_bytes()) != expected:
                raise CompactAborted(f"log verify failed for {item.fid}; nothing written")
            item.log_path = str(path)
        if _sha256(ledger_file.read_bytes()) != _sha256(raw):
            raise CompactAborted("ledger changed during compaction; nothing written")
    except Exception as exc:
        for path in written:
            path.unlink(missing_ok=True)
        for item in result.items:
            item.log_path = None
        if isinstance(exc, CompactAborted):
            raise
        raise CompactAborted(f"log write failed ({type(exc).__name__}: {exc}); nothing written") from None
    for finding, item in zip(targets, result.items):
        finding["review_error"] = compacted_summary(finding["review_error"], item.log_path)
        finding["review_log"] = item.log_path
    payload["updated_at"] = _timestamp_iso()
    _write_json_atomic(ledger_file, payload)
    result.applied = True
    result.ledger_bytes_after = ledger_file.stat().st_size
