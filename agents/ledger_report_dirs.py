"""Normalize legacy relative finding packet pointers to canonical absolute paths.

Bounty Core's packet guard (``bounty_core.reports._packet_dir``) accepts a
stored ``report_dir`` only when it is the absolute, exact-FID packet directly
inside the lane's ``reports_root``. A legacy record storing ``reports/<FID>``
therefore makes every refreshing write in its lane fail, because a refresh
preflights every finding. This module rewrites only pointers that resolve,
without ``..`` and without leaving ``reports_root``, to a path Bounty Core's own
guard accepts. Anything else is reported and left for manual review, so the
guard keeps failing closed on it.

Two entry points share one rule set:

* :func:`normalize_lane_packet_pointers` — the write hot path calls it before
  a refreshing Bounty Core write; it rewrites only safe values, under the same
  ``ledger.lock`` and atomic writer as Bounty Core, and only when something
  changes.
* :func:`repair_report_dirs` — ``manual_hunter --repair-report-dirs``: a
  dry-run listing by default, rewriting with ``apply=True``.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

# Same lock and atomic writer every Bounty Core ledger writer uses (see
# agents/ledger_tombstones.py for the same pinned-private-import rationale).
from bounty_core.ledger import _locked_payload, _timestamp_iso, _write_json_atomic  # noqa: E402
from bounty_core.ledger import ledger_path as core_ledger_path  # noqa: E402
from bounty_core.reports import _is_legacy_report_for_fid, _packet_dir, is_finding_packet_path  # noqa: E402
from bounty_core.storage import StorageLayout, resolve_storage

try:  # Bounty Core >= 5f5a66ac refuses malformed ledgers with LedgerReadError.
    from bounty_core.ledger import LedgerReadError as _LedgerReadError  # noqa: E402
    _LEDGER_READ_ERRORS: tuple[type[BaseException], ...] = (_LedgerReadError,)
except ImportError:  # older pins read a malformed ledger as empty
    _LEDGER_READ_ERRORS = ()

POINTER_KEYS = ("report_dir", "report_path", "evidence_path")


@dataclass(frozen=True)
class PointerIssue:
    fid: str
    key: str
    stored: str
    canonical: str | None  # None: not safely repairable; left for manual review
    reason: str

    @property
    def repairable(self) -> bool:
        return self.canonical is not None


@dataclass
class RepairResult:
    ledger_path: Path
    issues: list[PointerIssue] = field(default_factory=list)
    applied: bool = False

    @property
    def repairable(self) -> list[PointerIssue]:
        return [issue for issue in self.issues if issue.repairable]

    @property
    def unrepairable(self) -> list[PointerIssue]:
        return [issue for issue in self.issues if not issue.repairable]


def _fid(finding: dict[str, Any]) -> str:
    return str(finding.get("fid") or "").strip()


def _relative_parts(value: str) -> tuple[str, ...] | None:
    """Parts of a plain relative pointer, or None when it is absolute or unsafe."""
    text = value.replace("\\", "/")
    if not text or text.startswith("/") or text.startswith("~") or "\x00" in text:
        return None
    parts = tuple(part for part in PurePosixPath(text).parts if part not in ("", "."))
    if not parts or any(part == ".." for part in parts):
        return None
    return parts


def _accepted_report_dir(layout: StorageLayout, finding: dict[str, Any], candidate: Path) -> bool:
    try:
        return _packet_dir(layout.reports_root, {**finding, "report_dir": str(candidate)}) == candidate
    except (OSError, RuntimeError, ValueError):
        return False


def _canonical_report_dir(layout: StorageLayout, finding: dict[str, Any], stored: str) -> tuple[str | None, str]:
    parts = _relative_parts(stored)
    if parts is None:
        if os.path.isabs(stored) and ".." not in PurePosixPath(stored).parts:
            candidate = Path(os.path.normpath(stored))
            if _accepted_report_dir(layout, finding, candidate):
                return str(candidate), "absolute path not in normal form"
        return None, "not an exact-FID packet inside reports_root; review manually"
    # ``reports/<FID>`` is relative to the lane root; a bare ``<FID>`` to reports_root.
    for base in (layout.lane_root, layout.reports_root):
        candidate = base.joinpath(*parts)
        if _accepted_report_dir(layout, finding, candidate):
            return str(candidate), f"relative to {'lane root' if base == layout.lane_root else 'reports root'}"
    return None, "relative path does not resolve to an exact-FID packet inside reports_root; review manually"


def _owned_by(layout: StorageLayout, finding: dict[str, Any], candidate: Path) -> bool:
    """True only for a file in this finding's own packet or its legacy report file."""
    try:
        return (is_finding_packet_path(layout.reports_root, finding, candidate)
                or _is_legacy_report_for_fid(layout.reports_root, finding, candidate))
    except (OSError, RuntimeError, ValueError):
        return False


def _canonical_packet_file(layout: StorageLayout, finding: dict[str, Any], stored: str) -> tuple[str | None, str]:
    """A relative report_path/evidence_path that points into this finding's own packet.

    ``finding`` must carry the canonical ``report_dir`` (if any) so Bounty Core's
    ownership check can resolve the packet. A pointer into another finding's
    packet, ``raw/`` or anywhere else is left for manual review.
    """
    parts = _relative_parts(stored)
    if parts is None:
        return None, "relative path is unsafe; review manually"
    reports_root = layout.reports_root
    resolved_root = reports_root.resolve(strict=False)
    for base in (layout.lane_root, reports_root):
        candidate = base.joinpath(*parts)
        try:
            inside = candidate.is_relative_to(reports_root) and candidate.resolve(strict=False).is_relative_to(resolved_root)
        except (OSError, RuntimeError):
            inside = False
        if inside and candidate != reports_root and _owned_by(layout, finding, candidate):
            return str(candidate), f"relative to {'lane root' if base == layout.lane_root else 'reports root'}"
    return None, "relative path is not a file in this finding's own packet; review manually"


def find_pointer_issues(layout: StorageLayout, findings: Iterable[Any]) -> list[PointerIssue]:
    """List relative or non-normal packet pointers and their canonical form, if safe."""
    issues: list[PointerIssue] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        # report_dir is checked first (POINTER_KEYS order) so file pointers are
        # judged against the packet the finding will own after the rewrite.
        effective = dict(finding)
        for key in POINTER_KEYS:
            value = finding.get(key)
            if not value or not isinstance(value, str):
                continue
            if key == "report_dir":
                if os.path.isabs(value) and _accepted_report_dir(layout, finding, Path(value)):
                    continue
                canonical, reason = _canonical_report_dir(layout, finding, value)
                if canonical is not None:
                    effective["report_dir"] = canonical
            else:
                if os.path.isabs(value):
                    continue  # absolute file pointers are Bounty Core's to validate
                canonical, reason = _canonical_packet_file(layout, effective, value)
            issues.append(PointerIssue(_fid(finding), key, value, canonical, reason))
    return issues


def apply_pointer_issues(findings: Iterable[Any], issues: Iterable[PointerIssue]) -> int:
    """Rewrite repairable pointers in place; return the number changed."""
    fixes = {(issue.fid, issue.key, issue.stored): issue.canonical for issue in issues if issue.repairable}
    changed = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        for key in POINTER_KEYS:
            canonical = fixes.get((_fid(finding), key, finding.get(key)))
            if canonical is not None:
                finding[key] = canonical
                changed += 1
    return changed


def _layout(program: str, *, family: str | None, lane: str, root_override: str | Path | None) -> StorageLayout:
    return resolve_storage(program, family=family, lane=lane, root_override=root_override, create=False)


def normalize_lane_packet_pointers(
    program: str,
    *,
    family: str | None = None,
    lane: str,
    root_override: str | Path | None = None,
    storage_root: str | Path | None = None,
) -> int:
    """Persist safe canonical forms of legacy pointers before a refreshing write.

    Returns the number of rewritten pointers. A missing ledger is left alone.
    An unreadable one is never rewritten: older Bounty Core pins read it as
    empty (nothing to change), newer pins raise ``LedgerReadError``, which the
    caller's own write would raise anyway. Unsafe values are untouched so the
    subsequent Bounty Core call still refuses them.
    """
    root = root_override if root_override is not None else storage_root
    layout = _layout(program, family=family, lane=lane, root_override=root)
    ledger_file = core_ledger_path(layout.program, lane=layout.lane, family=layout.family, root_override=root)
    if not ledger_file.is_file():
        return 0
    with _locked_payload(layout.program, exclusive=True, lane=layout.lane, family=layout.family,
                         root_override=root, auto_write=False) as payload:
        findings = payload.get("findings")
        if not isinstance(findings, list):
            return 0
        changed = apply_pointer_issues(findings, find_pointer_issues(layout, findings))
        if changed:
            payload["updated_at"] = _timestamp_iso()
            _write_json_atomic(ledger_file, payload)
    if changed:
        print(f"[ledger] normalized {changed} legacy packet pointer(s) to canonical absolute paths "
              f"in {ledger_file}", file=sys.stderr)
    return changed


def repair_report_dirs(
    program: str,
    *,
    family: str | None = None,
    lane: str,
    root_override: str | Path | None = None,
    apply: bool = False,
) -> RepairResult:
    """List (and with ``apply``) rewrite relative/non-canonical packet pointers.

    The scan and the rewrite happen in one exclusive ``ledger.lock`` section;
    the ledger is replaced with Bounty Core's atomic writer only when a
    repairable pointer exists. A malformed ledger is refused, never rewritten.
    """
    from agents.ledger_tombstones import _assert_ledger_well_formed  # shared fail-closed reader

    layout = _layout(program, family=family, lane=lane, root_override=root_override)
    ledger_file = core_ledger_path(layout.program, lane=layout.lane, family=layout.family, root_override=root_override)
    result = RepairResult(ledger_path=ledger_file)
    if not ledger_file.is_file():
        raise ValueError(f"lane has no ledger: {ledger_file}")
    try:
        with _locked_payload(layout.program, exclusive=True, lane=layout.lane, family=layout.family,
                             root_override=root_override, auto_write=False) as payload:
            _assert_ledger_well_formed(ledger_file)
            findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []
            result.issues = find_pointer_issues(layout, findings)
            if apply and result.repairable:
                apply_pointer_issues(findings, result.issues)
                payload["updated_at"] = _timestamp_iso()
                _write_json_atomic(ledger_file, payload)
                result.applied = True
    except _LEDGER_READ_ERRORS as exc:
        # Newer Bounty Core pins refuse a malformed ledger inside _locked_payload
        # before our own check runs; report both the same way.
        raise ValueError(f"ledger is malformed; nothing written: {exc}") from None
    return result
