"""Artifact writing for live validation runs."""

from __future__ import annotations

import difflib
import json
import re
import shutil
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from agents.storage_resolver import StorageLayout

from .models import EvidenceRecord, ValidationTask, ValidationVerdict
from .report_layout import assert_no_legacy_status_first_dirs

EVIDENCE_SEGMENT_SANITIZER_RE = re.compile(r"[^A-Za-z0-9._ -]+")


def live_validation_root(storage: StorageLayout, run_id: str) -> Path:
    return storage.reports_root / "live_validation" / run_id


def live_validation_lock_root(storage: StorageLayout) -> Path:
    return storage.reports_root / "live_validation" / ".locks"


def _before_after_names(task: ValidationTask) -> tuple[str, str]:
    stem = task.fid or "finding"
    return f"{stem}.before.md", f"{stem}.after.md"


def _serialize_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _read_report_text(path: Path | None) -> str | None:
    if path is None or not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def _sanitize_evidence_name(name: str) -> Path:
    raw = str(name or "").strip().replace("\\", "/")
    if not raw or raw.startswith("/"):
        raise ValueError("evidence name must be a non-empty relative path")
    parts = PurePosixPath(raw).parts
    sanitized_parts: list[str] = []
    for part in parts:
        if part in {"", ".", "..", "/"}:
            raise ValueError(f"unsafe evidence name: {name}")
        sanitized = EVIDENCE_SEGMENT_SANITIZER_RE.sub("_", part).strip()
        if not sanitized or sanitized in {".", ".."}:
            raise ValueError(f"unsafe evidence name: {name}")
        sanitized_parts.append(sanitized)
    return Path(*sanitized_parts)


def _copy_or_write_evidence(evidence_dir: Path, record: EvidenceRecord) -> Path:
    evidence_root = evidence_dir.resolve(strict=False)
    relative_name = _sanitize_evidence_name(record.name)
    destination = (evidence_dir / relative_name).resolve(strict=False)
    try:
        destination.relative_to(evidence_root)
    except ValueError as exc:
        raise ValueError(f"evidence path escapes evidence root: {record.name}") from exc
    destination.parent.mkdir(parents=True, exist_ok=True)
    if record.path is not None and record.path.exists():
        shutil.copy2(record.path, destination)
        return destination
    if isinstance(record.data, (bytes, bytearray)):
        destination.write_bytes(bytes(record.data))
        return destination
    if isinstance(record.data, str):
        _write_text(destination, record.data)
        return destination
    if record.data is None:
        _write_text(destination, record.note or "")
        return destination
    _serialize_json(destination, record.data)
    return destination


def _diff_text(before_text: str | None, after_text: str | None, before_name: str, after_name: str) -> str:
    return "".join(
        difflib.unified_diff(
            (before_text or "").splitlines(keepends=True),
            (after_text or "").splitlines(keepends=True),
            fromfile=before_name,
            tofile=after_name,
        )
    )


def write_live_validation_artifacts(
    storage: StorageLayout,
    task: ValidationTask,
    verdict: ValidationVerdict,
    *,
    after_report_text: str | None = None,
) -> Path:
    root = live_validation_root(storage, task.run_id)
    input_dir = root / "input"
    output_dir = root / "output"
    evidence_dir = root / "evidence"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    before_name, after_name = _before_after_names(task)
    before_text = _read_report_text(task.report_path)
    if before_text is not None:
        _write_text(input_dir / before_name, before_text)

    final_after_text = after_report_text if after_report_text is not None else before_text
    if final_after_text is not None:
        _write_text(output_dir / after_name, final_after_text)

    persisted_evidence: list[EvidenceRecord] = []
    evidence_root = evidence_dir.resolve(strict=False)
    for record in verdict.evidence:
        destination = _copy_or_write_evidence(evidence_dir, record)
        relative_name = destination.relative_to(evidence_root).as_posix()
        persisted_evidence.append(
            EvidenceRecord(
                kind=record.kind,
                name=relative_name,
                path=destination,
                note=record.note,
            )
        )

    diff_text = _diff_text(before_text, final_after_text, before_name, after_name)
    _write_text(root / "diff.patch", diff_text)

    persisted_verdict = ValidationVerdict(
        state=verdict.state,
        summary=verdict.summary,
        run_id=verdict.run_id,
        fid=verdict.fid,
        report_path=verdict.report_path,
        dry_run=verdict.dry_run,
        evidence=persisted_evidence,
        policy_decisions=verdict.policy_decisions,
        metadata=verdict.metadata,
    )
    _serialize_json(root / "verdict.json", persisted_verdict.to_dict())
    assert_no_legacy_status_first_dirs(storage.reports_root)
    return root
