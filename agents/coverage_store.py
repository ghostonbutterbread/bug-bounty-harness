"""Snapshot-aware coverage persistence for class-based static analysis passes."""

from __future__ import annotations

import fcntl
import json
import logging
import re
import shutil
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agents.shared_brain import load_index


LOGGER = logging.getLogger(__name__)

COVERAGE_FILENAME = "coverage.json"
COVERAGE_VERSION = 1
VALID_STATUSES = {"done", "partial", "error", "manual-skip"}


def _timestamp_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _default_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sanitize_program_name(program: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(program).strip())
    return cleaned or "default_program"


def _shared_brain_index_path(program: str) -> Path:
    return (
        Path.home()
        / "Shared"
        / "bounty_recon"
        / program
        / "ghost"
        / "shared_brain"
        / "index.json"
    )


def _normalize_relpath(value: str) -> str:
    relpath = str(value or "").strip().replace("\\", "/")
    while relpath.startswith("./"):
        relpath = relpath[2:]
    return relpath


def _normalize_finding_fids(values: list[str] | None) -> list[str]:
    if not values:
        return []

    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        fid = str(value or "").strip()
        if not fid or fid in seen:
            continue
        seen.add(fid)
        normalized.append(fid)
    return normalized


class FileLock:
    """Minimal flock-based file lock mirroring the findings ledger pattern."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._handle: Any | None = None

    def __enter__(self) -> "FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._handle = self.path.open("a+", encoding="utf-8")
        fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._handle is None:
            return
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._handle = None


class CoverageStore:
    """Persistent per-snapshot file coverage for vulnerability-class passes."""

    def __init__(self, program_slug: str, target_dir: Path):
        self.program = _sanitize_program_name(program_slug)
        self.target_dir = Path(target_dir).expanduser().resolve(strict=False)
        self.coverage_dir = self.target_dir.parent / "ghost"
        self.path = self.coverage_dir / COVERAGE_FILENAME
        self.lock_path = Path(f"{self.path}.lock")
        self.backup_path = Path(f"{self.path}.bak")

        self.shared_brain = load_index(self.program)
        if self.shared_brain is None:
            shared_brain_path = _shared_brain_index_path(self.program)
            raise ValueError(
                f"shared_brain index not found for program {self.program!r}: {shared_brain_path}"
            )

        self.snapshot_id = self.get_snapshot_id()
        self._ensure_storage()

    def get_snapshot_id(self) -> str:
        snapshot_id = str(self.shared_brain.git_head or "").strip() or str(
            self.shared_brain.manifest_hash or ""
        ).strip()
        if not snapshot_id:
            raise ValueError(
                "coverage snapshot_id could not be determined from shared_brain; "
                "missing git_head and manifest_hash"
            )
        return snapshot_id

    def get_coverage(self, vuln_class: str, snapshot_id: str | None = None) -> dict[str, dict[str, Any]]:
        target_snapshot = self._resolve_snapshot_id(snapshot_id)
        normalized_class = _normalize_relpath(vuln_class)
        with FileLock(self.lock_path):
            payload = self._load_locked()
            return self._coverage_from_payload(payload, normalized_class, target_snapshot)

    def get_unexplored(self, vuln_class: str, candidates: list[str]) -> list[str]:
        coverage = self.get_coverage(vuln_class)
        explored = {
            relpath
            for relpath, entry in coverage.items()
            if str(entry.get("status", "")).strip() in {"done", "partial"}
        }

        unexplored: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            relpath = _normalize_relpath(candidate)
            if not relpath or relpath in seen:
                continue
            seen.add(relpath)
            if relpath not in explored:
                unexplored.append(relpath)
        return unexplored

    def mark_examined(
        self,
        vuln_class: str,
        files: list[str],
        method: str,
        status: str = "done",
        run_id: str | None = None,
        snapshot_id: str | None = None,
        version_label: str | None = None,
        finding_fids: list[str] | None = None,
        notes: str | None = None,
    ) -> None:
        normalized_class = _normalize_relpath(vuln_class)
        normalized_method = str(method or "").strip()
        normalized_status = str(status or "").strip()
        normalized_run_id = str(run_id or "").strip() or _default_run_id()
        normalized_snapshot_id = self._resolve_snapshot_id(snapshot_id)
        normalized_version_label = str(version_label or "").strip()
        normalized_notes = str(notes or "").strip()
        normalized_fids = _normalize_finding_fids(finding_fids)

        if not normalized_class:
            raise ValueError("vuln_class is required")
        if not normalized_method:
            raise ValueError("method is required")
        if normalized_status not in VALID_STATUSES:
            known = ", ".join(sorted(VALID_STATUSES))
            raise ValueError(f"invalid coverage status {status!r}; expected one of: {known}")

        checked_at = _timestamp_iso()

        with FileLock(self.lock_path):
            payload = self._load_locked()
            changed = self._ensure_snapshot_locked(
                payload,
                snapshot_id=normalized_snapshot_id,
                version_label=normalized_version_label,
            )
            snapshot = payload["snapshots"][normalized_snapshot_id]
            classes = snapshot.setdefault("classes", {})
            class_bucket = classes.setdefault(normalized_class, {"files": {}})
            class_files = class_bucket.setdefault("files", {})
            if not isinstance(class_files, dict):
                class_files = {}
                class_bucket["files"] = class_files
                changed = True

            for file_value in files:
                relpath = _normalize_relpath(file_value)
                if not relpath:
                    continue

                brain_record = self.shared_brain.files.get(relpath)
                if not isinstance(brain_record, dict):
                    warning = (
                        f"Skipping coverage mark for {relpath!r}; file is missing from shared_brain "
                        f"for snapshot {self.snapshot_id}"
                    )
                    if normalized_notes:
                        warning = f"{warning}. notes={normalized_notes}"
                    LOGGER.warning(warning)
                    continue

                sha1 = str(brain_record.get("sha1", "")).strip()
                if not sha1:
                    LOGGER.warning(
                        "Skipping coverage mark for %r; shared_brain entry has no sha1", relpath
                    )
                    continue

                entry: dict[str, Any] = {
                    "sha1": sha1,
                    "checked_at": checked_at,
                    "updated_at": checked_at,
                    "run_id": normalized_run_id,
                    "method": normalized_method,
                    "status": normalized_status,
                    "snapshot_id": normalized_snapshot_id,
                }
                if normalized_version_label:
                    entry["version_label"] = normalized_version_label
                if normalized_fids:
                    entry["finding_fids"] = list(normalized_fids)
                if normalized_notes:
                    entry["notes"] = normalized_notes

                class_files[relpath] = entry
                changed = True

            if changed:
                self._save_locked(payload)

    def list_classes(self, snapshot_id: str | None = None) -> list[str]:
        target_snapshot = self._resolve_snapshot_id(snapshot_id)
        with FileLock(self.lock_path):
            payload = self._load_locked()
            snapshot = payload.get("snapshots", {}).get(target_snapshot)
            if not isinstance(snapshot, dict):
                return []

            classes = snapshot.get("classes", {})
            if not isinstance(classes, dict):
                return []

            result = [
                vuln_class
                for vuln_class in sorted(classes)
                if self._coverage_from_payload(payload, vuln_class, target_snapshot)
            ]
            return result

    def get_all_examined(self, snapshot_id: str | None = None) -> dict[str, dict[str, Any]]:
        """Return examined class/file pairs for the current snapshot.

        `done`, `partial`, and `manual-skip` are treated as already reviewed.
        `error` remains eligible for re-hunting.
        """
        target_snapshot = self._resolve_snapshot_id(snapshot_id)
        examined: dict[str, dict[str, Any]] = {}
        for vuln_class in self.list_classes(target_snapshot):
            coverage = self.get_coverage(vuln_class, target_snapshot)
            for relpath, entry in sorted(coverage.items()):
                if str(entry.get("status", "")).strip() not in {"done", "partial", "manual-skip"}:
                    continue
                key = f"{relpath}::{vuln_class}"
                examined[key] = {
                    "file": relpath,
                    "class_name": vuln_class,
                    **entry,
                }
        return examined

    def get_candidates(self) -> dict[str, dict[str, Any]]:
        """Return candidate class/file pairs inferred from shared_brain signals."""
        candidates: dict[str, dict[str, Any]] = {}
        for relpath, record in sorted(self.shared_brain.files.items()):
            if not isinstance(record, dict):
                continue
            class_scores = record.get("signals", {}).get("class_scores", {})
            if not isinstance(class_scores, dict):
                continue
            for vuln_class, score in sorted(class_scores.items()):
                normalized_class = _normalize_relpath(vuln_class)
                if not normalized_class or int(score or 0) <= 0:
                    continue
                key = f"{relpath}::{normalized_class}"
                candidates[key] = {
                    "file": relpath,
                    "class_name": normalized_class,
                    "score": int(score),
                }
        return candidates

    def summary(self) -> dict[str, dict[str, Any]]:
        target_snapshot = self.snapshot_id
        with FileLock(self.lock_path):
            payload = self._load_locked()
            snapshot = payload.get("snapshots", {}).get(target_snapshot)
            if not isinstance(snapshot, dict):
                return {}

            classes = snapshot.get("classes", {})
            if not isinstance(classes, dict):
                return {}

            summary: dict[str, dict[str, Any]] = {}
            for vuln_class in sorted(classes):
                coverage = self._coverage_from_payload(payload, vuln_class, target_snapshot)
                if not coverage:
                    continue

                counts = Counter(str(entry.get("status", "")).strip() for entry in coverage.values())
                summary[vuln_class] = {
                    "examined": len(coverage),
                    "status": self._rollup_status(counts),
                    "statuses": {name: counts[name] for name in sorted(counts)},
                    "snapshot_id": target_snapshot,
                }
            return summary

    def _default_payload(self) -> dict[str, Any]:
        return {
            "version": COVERAGE_VERSION,
            "program": self.program,
            "target_id": self.snapshot_id,
            "snapshots": {},
        }

    def _default_snapshot(self, snapshot_id: str | None = None, version_label: str | None = None) -> dict[str, Any]:
        target_snapshot = self._resolve_snapshot_id(snapshot_id)
        return {
            "created_at": _timestamp_iso(),
            "git_head": self.shared_brain.git_head if target_snapshot == self.snapshot_id else None,
            "manifest_hash": self.shared_brain.manifest_hash if target_snapshot == self.snapshot_id else None,
            "version_label": str(version_label or "").strip(),
            "classes": {},
        }

    def _ensure_storage(self) -> None:
        self.coverage_dir.mkdir(parents=True, exist_ok=True)
        with FileLock(self.lock_path):
            payload = self._load_locked()
            if self._ensure_snapshot_locked(payload) or not self.path.exists():
                self._save_locked(payload)

    def _resolve_snapshot_id(self, snapshot_id: str | None) -> str:
        normalized = str(snapshot_id or "").strip()
        return normalized or self.snapshot_id

    def _ensure_snapshot_locked(
        self,
        payload: dict[str, Any],
        *,
        snapshot_id: str | None = None,
        version_label: str | None = None,
    ) -> bool:
        target_snapshot = self._resolve_snapshot_id(snapshot_id)
        changed = False
        if payload.get("version") != COVERAGE_VERSION:
            payload["version"] = COVERAGE_VERSION
            changed = True
        if payload.get("program") != self.program:
            payload["program"] = self.program
            changed = True
        if payload.get("target_id") != self.snapshot_id:
            payload["target_id"] = self.snapshot_id
            changed = True

        snapshots = payload.get("snapshots")
        if not isinstance(snapshots, dict):
            snapshots = {}
            payload["snapshots"] = snapshots
            changed = True

        snapshot = snapshots.get(target_snapshot)
        if not isinstance(snapshot, dict):
            snapshots[target_snapshot] = self._default_snapshot(
                snapshot_id=target_snapshot,
                version_label=version_label,
            )
            return True

        snapshot_version_label = str(version_label or "").strip()
        if not str(snapshot.get("created_at", "")).strip():
            snapshot["created_at"] = _timestamp_iso()
            changed = True
        expected_git_head = self.shared_brain.git_head if target_snapshot == self.snapshot_id else snapshot.get("git_head")
        if snapshot.get("git_head") != expected_git_head:
            snapshot["git_head"] = expected_git_head
            changed = True
        expected_manifest_hash = (
            self.shared_brain.manifest_hash
            if target_snapshot == self.snapshot_id
            else snapshot.get("manifest_hash")
        )
        if str(snapshot.get("manifest_hash", "")).strip() != str(expected_manifest_hash or "").strip():
            snapshot["manifest_hash"] = expected_manifest_hash
            changed = True
        if snapshot_version_label and str(snapshot.get("version_label", "")).strip() != snapshot_version_label:
            snapshot["version_label"] = snapshot_version_label
            changed = True
        classes = snapshot.get("classes")
        if not isinstance(classes, dict):
            snapshot["classes"] = {}
            changed = True
        return changed

    def _load_locked(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._default_payload()

        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            LOGGER.warning("Coverage JSON parse error in %s: %s", self.path, exc)
            self._backup_corrupt_file_locked()
            return self._default_payload()
        except OSError as exc:
            LOGGER.warning("Coverage read failed for %s: %s", self.path, exc)
            return self._default_payload()

        if not isinstance(payload, dict):
            LOGGER.warning("Coverage payload in %s is not a JSON object; recreating", self.path)
            self._backup_corrupt_file_locked()
            return self._default_payload()
        return payload

    def _save_locked(self, payload: dict[str, Any]) -> None:
        self.coverage_dir.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            shutil.copy2(self.path, self.backup_path)

        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.coverage_dir,
            prefix=f"{self.path.stem}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")

        temp_path.replace(self.path)

    def _backup_corrupt_file_locked(self) -> None:
        if self.path.exists():
            shutil.copy2(self.path, self.backup_path)

    def _coverage_from_payload(
        self,
        payload: dict[str, Any],
        vuln_class: str,
        snapshot_id: str,
    ) -> dict[str, dict[str, Any]]:
        snapshots = payload.get("snapshots", {})
        if not isinstance(snapshots, dict):
            return {}

        snapshot = snapshots.get(snapshot_id)
        if not isinstance(snapshot, dict):
            return {}

        classes = snapshot.get("classes", {})
        if not isinstance(classes, dict):
            return {}

        class_bucket = classes.get(vuln_class)
        if not isinstance(class_bucket, dict):
            return {}

        files = class_bucket.get("files", {})
        if not isinstance(files, dict):
            return {}

        coverage: dict[str, dict[str, Any]] = {}
        for relpath, entry in sorted(files.items()):
            if not self._entry_matches_current_sha1(relpath, entry):
                continue

            normalized_entry = self._normalize_entry(entry)
            if normalized_entry is None:
                continue
            coverage[relpath] = normalized_entry
        return coverage

    def _entry_matches_current_sha1(self, relpath: Any, entry: Any) -> bool:
        if not isinstance(entry, dict):
            return False

        normalized_relpath = _normalize_relpath(str(relpath))
        if not normalized_relpath:
            return False

        current_record = self.shared_brain.files.get(normalized_relpath)
        if not isinstance(current_record, dict):
            return False

        current_sha1 = str(current_record.get("sha1", "")).strip()
        stored_sha1 = str(entry.get("sha1", "")).strip()
        return bool(current_sha1) and current_sha1 == stored_sha1

    def _normalize_entry(self, entry: dict[str, Any]) -> dict[str, Any] | None:
        status = str(entry.get("status", "")).strip()
        if status not in VALID_STATUSES:
            return None

        normalized = {
            "sha1": str(entry.get("sha1", "")).strip(),
            "checked_at": str(entry.get("checked_at", "")).strip(),
            "updated_at": str(entry.get("updated_at", "")).strip()
            or str(entry.get("checked_at", "")).strip(),
            "run_id": str(entry.get("run_id", "")).strip(),
            "method": str(entry.get("method", "")).strip(),
            "status": status,
            "snapshot_id": str(entry.get("snapshot_id", "")).strip() or self.snapshot_id,
        }

        version_label = str(entry.get("version_label", "")).strip()
        if version_label:
            normalized["version_label"] = version_label

        finding_fids = _normalize_finding_fids(entry.get("finding_fids"))
        if finding_fids:
            normalized["finding_fids"] = finding_fids

        notes = str(entry.get("notes", "")).strip()
        if notes:
            normalized["notes"] = notes
        return normalized

    def _rollup_status(self, counts: Counter[str]) -> str:
        if counts.get("error"):
            return "error"
        if counts.get("partial"):
            return "partial"
        if counts.get("done") and counts.get("manual-skip"):
            return "partial"
        if counts.get("done"):
            return "done"
        if counts.get("manual-skip"):
            return "manual-skip"
        return "partial"
