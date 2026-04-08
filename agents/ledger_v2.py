"""Version-aware findings ledger with snapshot sightings."""

from __future__ import annotations

import fcntl
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from agents.snapshot_identity import get_snapshot_identity


LEDGER_VERSION = 2
DEFAULT_REVIEW_TIER = "PENDING_REVIEW"
DEFAULT_STATUS = "active"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp_iso() -> str:
    return _utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")


def _default_run_id() -> str:
    return _utc_now().strftime("%Y%m%dT%H%M%SZ")


def _normalize_program(program: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(program or "").strip())
    if not cleaned:
        raise ValueError("program is required")
    return cleaned


def _normalize_relpath(value: Any) -> str:
    relpath = str(value or "").strip().replace("\\", "/")
    while relpath.startswith("./"):
        relpath = relpath[2:]
    return relpath


def _normalize_class_name(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _ghost_root(program: str) -> Path:
    return Path.home() / "Shared" / "bounty_recon" / _normalize_program(program) / "ghost"


def ledger_path(program: str) -> Path:
    return _ghost_root(program) / "ledger.json"


def _lock_path(program: str) -> Path:
    return _ghost_root(program) / "ledger.lock"


def _default_payload(program: str) -> dict[str, Any]:
    return {
        "version": LEDGER_VERSION,
        "program": _normalize_program(program),
        "updated_at": _timestamp_iso(),
        "findings": [],
    }


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")
        temp_path = Path(handle.name)
    temp_path.replace(path)


@contextmanager
def _locked_payload(program: str, *, exclusive: bool) -> Iterator[dict[str, Any]]:
    program_slug = _normalize_program(program)
    path = ledger_path(program_slug)
    lock = _lock_path(program_slug)

    path.parent.mkdir(parents=True, exist_ok=True)
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.touch(exist_ok=True)

    mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    with lock.open("a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), mode)
        try:
            payload = _read_payload(path, program_slug)
            yield payload
            if exclusive:
                payload["updated_at"] = _timestamp_iso()
                _write_json_atomic(path, payload)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _read_payload(path: Path, program: str) -> dict[str, Any]:
    default = _default_payload(program)
    if not path.exists():
        return default

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default

    if not isinstance(payload, dict):
        return default

    migrated = migrate_ledger_payload(program, payload)
    return migrated if isinstance(migrated, dict) else default


def _next_fid(findings: list[dict[str, Any]], prefix: str) -> str:
    normalized_prefix = (prefix or "D").strip().upper() or "D"
    highest = 0
    for finding in findings:
        fid = str(finding.get("fid") or "").strip().upper()
        if not fid.startswith(normalized_prefix):
            continue
        suffix = fid[len(normalized_prefix) :]
        if suffix.isdigit():
            highest = max(highest, int(suffix))
    return f"{normalized_prefix}{highest + 1:02d}"


def _finding_key(file_value: Any, class_name: Any) -> tuple[str, str]:
    return (_normalize_relpath(file_value), _normalize_class_name(class_name))


def _review_tier_for(finding: dict[str, Any]) -> str:
    for key in ("review_tier", "tier"):
        value = str(finding.get(key) or "").strip()
        if value:
            return value.replace("-", "_").upper()
    status = str(finding.get("status") or "").strip().upper()
    if status and status not in {"ACTIVE", "FIXED", "REGRESSION", "HISTORICAL"}:
        return status.replace("-", "_")
    return DEFAULT_REVIEW_TIER


def _status_for(finding: dict[str, Any]) -> str:
    value = str(finding.get("status") or "").strip()
    return value or DEFAULT_STATUS


def _fid_prefix_for(finding: dict[str, Any]) -> str:
    explicit = str(finding.get("fid_prefix") or "").strip().upper()
    if explicit:
        return explicit
    category = str(finding.get("category") or "").strip().lower()
    class_name = _normalize_class_name(finding.get("class_name") or finding.get("vuln_class"))
    return "N" if category == "novel" or class_name == "novel" else "D"


def _normalize_sighting(sighting: Any) -> dict[str, Any] | None:
    if not isinstance(sighting, dict):
        return None

    normalized = {
        "snapshot_id": str(sighting.get("snapshot_id") or "").strip(),
        "version_label": str(sighting.get("version_label") or "").strip(),
        "run_id": str(sighting.get("run_id") or "").strip(),
        "seen_at": str(sighting.get("seen_at") or "").strip() or _timestamp_iso(),
        "status": str(sighting.get("status") or "").strip() or DEFAULT_STATUS,
        "review_tier": str(sighting.get("review_tier") or "").strip() or DEFAULT_REVIEW_TIER,
        "agent": str(sighting.get("agent") or "").strip(),
    }
    return normalized


def _current_from_sightings(sightings: list[dict[str, Any]]) -> dict[str, Any]:
    if not sightings:
        return {
            "review_tier": DEFAULT_REVIEW_TIER,
            "status": DEFAULT_STATUS,
            "version_label": "",
        }

    latest = sightings[-1]
    return {
        "review_tier": str(latest.get("review_tier") or DEFAULT_REVIEW_TIER),
        "status": str(latest.get("status") or DEFAULT_STATUS),
        "version_label": str(latest.get("version_label") or ""),
    }


def _top_level_base(entry: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    merged = dict(entry)
    merged["type"] = str(
        finding.get("type")
        or finding.get("title")
        or entry.get("type")
        or "Unknown finding"
    ).strip()
    merged["class_name"] = _normalize_class_name(
        finding.get("class_name") or finding.get("vuln_class") or entry.get("class_name")
    )
    merged["file"] = _normalize_relpath(finding.get("file") or entry.get("file"))
    merged["line"] = _safe_int(finding.get("line") if "line" in finding else entry.get("line"))
    merged["severity"] = str(finding.get("severity") or entry.get("severity") or "UNKNOWN").strip().upper()
    return merged


def _merge_extra_fields(entry: dict[str, Any], finding: dict[str, Any]) -> None:
    reserved = {
        "fid",
        "type",
        "class_name",
        "vuln_class",
        "file",
        "line",
        "severity",
        "first_seen",
        "first_snapshot",
        "last_seen",
        "last_snapshot",
        "sightings",
        "current",
        "snapshot_id",
        "version_label",
    }
    for key, value in finding.items():
        if key in reserved:
            continue
        entry[key] = value


def _normalize_entry(entry: Any) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        return None

    fid = str(entry.get("fid") or "").strip()
    if not fid:
        return None

    normalized = {
        "fid": fid,
        "type": str(entry.get("type") or entry.get("title") or "Unknown finding").strip(),
        "class_name": _normalize_class_name(entry.get("class_name") or entry.get("vuln_class")),
        "file": _normalize_relpath(entry.get("file")),
        "line": _safe_int(entry.get("line")),
        "severity": str(entry.get("severity") or "UNKNOWN").strip().upper(),
        "first_seen": str(entry.get("first_seen") or entry.get("discovered_date") or _timestamp_iso()).strip(),
        "first_snapshot": str(entry.get("first_snapshot") or "").strip(),
        "last_seen": str(entry.get("last_seen") or entry.get("first_seen") or _timestamp_iso()).strip(),
        "last_snapshot": str(entry.get("last_snapshot") or entry.get("first_snapshot") or "").strip(),
    }

    sightings: list[dict[str, Any]] = []
    for raw_sighting in entry.get("sightings", []):
        normalized_sighting = _normalize_sighting(raw_sighting)
        if normalized_sighting is not None:
            sightings.append(normalized_sighting)

    normalized["sightings"] = sightings
    current = entry.get("current")
    if not isinstance(current, dict):
        current = _current_from_sightings(sightings)
    normalized["current"] = {
        "review_tier": str(current.get("review_tier") or DEFAULT_REVIEW_TIER),
        "status": str(current.get("status") or DEFAULT_STATUS),
        "version_label": str(current.get("version_label") or ""),
    }

    for key, value in entry.items():
        if key not in normalized:
            normalized[key] = value
    return normalized


def migrate_legacy_finding(entry: dict[str, Any]) -> dict[str, Any]:
    timestamp = str(entry.get("added_at") or entry.get("first_seen") or _timestamp_iso())
    review_tier = str(entry.get("review_tier") or DEFAULT_REVIEW_TIER).replace("-", "_").upper()
    status = str(entry.get("status") or DEFAULT_STATUS).strip() or DEFAULT_STATUS
    snapshot_id = str(entry.get("snapshot_id") or entry.get("first_snapshot") or "legacy").strip()
    version_label = str(entry.get("version_label") or "").strip()
    agent = str(entry.get("agent") or "").strip()

    migrated = {
        "fid": str(entry.get("fid") or "").strip(),
        "type": str(entry.get("type") or entry.get("title") or "Unknown finding").strip(),
        "class_name": _normalize_class_name(entry.get("class_name") or entry.get("vuln_class")),
        "file": _normalize_relpath(entry.get("file")),
        "line": _safe_int(entry.get("line")),
        "severity": str(entry.get("severity") or "UNKNOWN").strip().upper(),
        "first_seen": timestamp,
        "first_snapshot": snapshot_id,
        "last_seen": str(entry.get("last_seen") or timestamp),
        "last_snapshot": str(entry.get("last_snapshot") or snapshot_id),
        "sightings": [
            {
                "snapshot_id": snapshot_id,
                "version_label": version_label,
                "run_id": str(entry.get("run_id") or "legacy").strip() or "legacy",
                "seen_at": str(entry.get("last_seen") or timestamp),
                "status": status,
                "review_tier": review_tier,
                "agent": agent,
            }
        ],
        "current": {
            "review_tier": review_tier,
            "status": status,
            "version_label": version_label,
        },
    }

    _merge_extra_fields(migrated, entry)
    return migrated


def migrate_ledger_payload(program: str, payload: dict[str, Any]) -> dict[str, Any]:
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    migrated_findings: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("sightings"), list):
            normalized = _normalize_entry(item)
            if normalized is not None:
                migrated_findings.append(normalized)
            continue
        migrated = migrate_legacy_finding(item)
        normalized = _normalize_entry(migrated)
        if normalized is not None:
            migrated_findings.append(normalized)

    return {
        "version": LEDGER_VERSION,
        "program": _normalize_program(program),
        "updated_at": str(payload.get("updated_at") or _timestamp_iso()),
        "findings": migrated_findings,
    }


def _find_existing(findings: list[dict[str, Any]], file_value: Any, class_name: Any) -> dict[str, Any] | None:
    target = _finding_key(file_value, class_name)
    for finding in findings:
        if _finding_key(finding.get("file"), finding.get("class_name")) == target:
            return finding
    return None


def _make_sighting(
    finding: dict[str, Any],
    snapshot_id: str,
    version_label: str,
    run_id: str,
    agent: str,
    *,
    seen_at: str | None = None,
) -> dict[str, Any]:
    return {
        "snapshot_id": str(snapshot_id or "").strip(),
        "version_label": str(version_label or "").strip(),
        "run_id": str(run_id or "").strip() or _default_run_id(),
        "seen_at": str(seen_at or finding.get("seen_at") or _timestamp_iso()),
        "status": _status_for(finding),
        "review_tier": _review_tier_for(finding),
        "agent": str(agent or finding.get("agent") or "").strip(),
    }


def _upsert_sighting(existing: dict[str, Any], sighting: dict[str, Any]) -> None:
    sightings = existing.setdefault("sightings", [])
    if not isinstance(sightings, list):
        sightings = []
        existing["sightings"] = sightings

    for current in sightings:
        if not isinstance(current, dict):
            continue
        if (
            str(current.get("snapshot_id") or "") == sighting["snapshot_id"]
            and str(current.get("run_id") or "") == sighting["run_id"]
        ):
            current.update(sighting)
            existing["current"] = _current_from_sightings(sightings)
            return

    sightings.append(sighting)
    existing["current"] = _current_from_sightings(sightings)


def _merge_finding(existing: dict[str, Any], finding: dict[str, Any], *, snapshot_id: str, sighting: dict[str, Any]) -> None:
    _top_level_base(existing, finding)
    updated = _top_level_base(existing, finding)
    existing.update(updated)
    _merge_extra_fields(existing, finding)
    existing["last_seen"] = sighting["seen_at"]
    existing["last_snapshot"] = snapshot_id
    if not str(existing.get("first_seen") or "").strip():
        existing["first_seen"] = sighting["seen_at"]
    if not str(existing.get("first_snapshot") or "").strip():
        existing["first_snapshot"] = snapshot_id
    _upsert_sighting(existing, sighting)


def _reserve_candidate(
    program: str,
    finding: dict[str, Any],
    snapshot_id: str,
    version_label: str,
    run_id: str,
    agent: str,
) -> tuple[bool, str]:
    with _locked_payload(program, exclusive=True) as payload:
        findings = payload.setdefault("findings", [])
        if not isinstance(findings, list):
            findings = []
            payload["findings"] = findings

        existing = _find_existing(findings, finding.get("file"), finding.get("class_name") or finding.get("vuln_class"))
        if existing is not None:
            return False, str(existing.get("fid") or "").strip()

        prefix = _fid_prefix_for(finding)
        fid = str(finding.get("fid") or "").strip() or _next_fid(findings, prefix)
        sighting = _make_sighting(finding, snapshot_id, version_label, run_id, agent)
        entry = {
            "fid": fid,
            "type": str(finding.get("type") or finding.get("title") or "Unknown finding").strip(),
            "class_name": _normalize_class_name(finding.get("class_name") or finding.get("vuln_class")),
            "file": _normalize_relpath(finding.get("file")),
            "line": _safe_int(finding.get("line")),
            "severity": str(finding.get("severity") or "UNKNOWN").strip().upper(),
            "first_seen": sighting["seen_at"],
            "first_snapshot": snapshot_id,
            "last_seen": sighting["seen_at"],
            "last_snapshot": snapshot_id,
            "sightings": [sighting],
            "current": _current_from_sightings([sighting]),
        }
        _merge_extra_fields(entry, finding)
        findings.append(entry)
        return True, fid


def ledger_add(
    program: str,
    finding: dict[str, Any],
    snapshot_id: str,
    version_label: str,
    run_id: str,
    agent: str,
) -> tuple[bool, str | None]:
    """Add or update a finding. Returns (is_new_fid, fid). Dedup is global across snapshots."""
    with _locked_payload(program, exclusive=True) as payload:
        findings = payload.setdefault("findings", [])
        if not isinstance(findings, list):
            findings = []
            payload["findings"] = findings

        existing = _find_existing(findings, finding.get("file"), finding.get("class_name") or finding.get("vuln_class"))
        sighting = _make_sighting(finding, snapshot_id, version_label, run_id, agent)

        if existing is not None:
            _merge_finding(existing, finding, snapshot_id=snapshot_id, sighting=sighting)
            return False, str(existing.get("fid") or "").strip()

        prefix = _fid_prefix_for(finding)
        fid = str(finding.get("fid") or "").strip() or _next_fid(findings, prefix)
        entry = {
            "fid": fid,
            "type": str(finding.get("type") or finding.get("title") or "Unknown finding").strip(),
            "class_name": _normalize_class_name(finding.get("class_name") or finding.get("vuln_class")),
            "file": _normalize_relpath(finding.get("file")),
            "line": _safe_int(finding.get("line")),
            "severity": str(finding.get("severity") or "UNKNOWN").strip().upper(),
            "first_seen": sighting["seen_at"],
            "first_snapshot": snapshot_id,
            "last_seen": sighting["seen_at"],
            "last_snapshot": snapshot_id,
            "sightings": [sighting],
            "current": _current_from_sightings([sighting]),
        }
        _merge_extra_fields(entry, finding)
        findings.append(entry)
        return True, fid


def ledger_check(
    program: str,
    file: str,
    class_name: str,
    snapshot_id: str | None = None,
) -> tuple[bool, str | None]:
    """Check if finding exists. Returns (exists, fid)."""
    with _locked_payload(program, exclusive=False) as payload:
        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            return False, None

        existing = _find_existing(findings, file, class_name)
        if existing is None:
            return False, None

        if snapshot_id:
            sightings = existing.get("sightings", [])
            if not any(str(item.get("snapshot_id") or "") == str(snapshot_id) for item in sightings if isinstance(item, dict)):
                return False, None
        return True, str(existing.get("fid") or "").strip() or None


def _snapshot_match_score(entry: dict[str, Any], snapshot_id: str | None, version_label: str | None) -> tuple[int, int]:
    sightings = entry.get("sightings", [])
    has_snapshot = 0
    has_version = 0
    if isinstance(sightings, list):
        for sighting in sightings:
            if not isinstance(sighting, dict):
                continue
            if snapshot_id and str(sighting.get("snapshot_id") or "") == str(snapshot_id):
                has_snapshot = 1
            if version_label and str(sighting.get("version_label") or "") == str(version_label):
                has_version = 1
    return has_snapshot, has_version


def _sort_sightings(sightings: list[dict[str, Any]], snapshot_id: str | None, version_label: str | None) -> list[dict[str, Any]]:
    def _key(item: dict[str, Any]) -> tuple[int, int, str]:
        snapshot_match = 1 if snapshot_id and str(item.get("snapshot_id") or "") == str(snapshot_id) else 0
        version_match = 1 if version_label and str(item.get("version_label") or "") == str(version_label) else 0
        return (-snapshot_match, -version_match, str(item.get("seen_at") or ""))

    return sorted((dict(item) for item in sightings), key=_key, reverse=False)


def ledger_list(
    program: str,
    snapshot_id: str | None = None,
    version_label: str | None = None,
) -> list[dict[str, Any]]:
    """List findings. If snapshot_id given, prioritize that snapshot's sightings."""
    with _locked_payload(program, exclusive=False) as payload:
        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            return []

        result: list[dict[str, Any]] = []
        for item in findings:
            normalized = _normalize_entry(item)
            if normalized is None:
                continue
            sightings = normalized.get("sightings", [])
            if isinstance(sightings, list):
                normalized["sightings"] = _sort_sightings(sightings, snapshot_id, version_label)
            result.append(normalized)

    def _key(entry: dict[str, Any]) -> tuple[int, int, str, str]:
        has_snapshot, has_version = _snapshot_match_score(entry, snapshot_id, version_label)
        return (-has_snapshot, -has_version, str(entry.get("last_seen") or ""), str(entry.get("fid") or ""))

    return sorted(result, key=_key, reverse=False)


def ledger_get(program: str, fid: str) -> dict[str, Any] | None:
    """Get a specific finding by FID."""
    target = str(fid or "").strip()
    if not target:
        return None

    with _locked_payload(program, exclusive=False) as payload:
        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            return None
        for finding in findings:
            if str(finding.get("fid") or "").strip() != target:
                continue
            return _normalize_entry(finding)
    return None


def ledger_sightings(program: str, fid: str) -> list[dict]:
    """Get all sightings for a finding."""
    finding = ledger_get(program, fid)
    if finding is None:
        return []
    sightings = finding.get("sightings", [])
    return [dict(item) for item in sightings if isinstance(item, dict)]


class VersionedFindingsLedger:
    """Compatibility wrapper for snapshot-aware ledger workflows."""

    def __init__(
        self,
        program: str,
        *,
        target_root: str | Path,
        version_label: str | None = None,
        snapshot_identity: dict[str, Any] | None = None,
        run_id: str | None = None,
        agent: str = "codex",
    ) -> None:
        self.program = _normalize_program(program)
        self.target_root = Path(target_root).expanduser().resolve(strict=False)
        self.snapshot_identity = snapshot_identity or get_snapshot_identity(
            self.target_root,
            version_label=version_label,
        )
        self.snapshot_id = str(self.snapshot_identity.get("snapshot_id") or "").strip()
        self.version_label = str(self.snapshot_identity.get("version_label") or "").strip()
        self.run_id = str(run_id or "").strip() or _default_run_id()
        self.agent = str(agent or "").strip() or "codex"
        self.path = ledger_path(self.program)

    def check(self, finding_dict: dict[str, Any]) -> tuple[bool, str | None, dict[str, Any]]:
        exists, fid = ledger_check(
            self.program,
            _normalize_relpath(finding_dict.get("file")),
            _normalize_class_name(finding_dict.get("class_name") or finding_dict.get("vuln_class")),
        )
        if exists and fid:
            current = ledger_get(self.program, fid) or {}
            merged = dict(finding_dict)
            merged.update({"fid": fid, **current})
            return True, fid, merged

        reserved, fid = _reserve_candidate(
            self.program,
            dict(finding_dict),
            self.snapshot_id,
            self.version_label,
            str(finding_dict.get("run_id") or self.run_id),
            str(finding_dict.get("agent") or self.agent),
        )
        merged = dict(finding_dict)
        if fid:
            merged["fid"] = fid
            merged["snapshot_id"] = self.snapshot_id
            merged["version_label"] = self.version_label
            merged["run_id"] = str(merged.get("run_id") or self.run_id)
        return (not reserved), fid, merged

    def update(self, finding_with_fid: dict[str, Any]) -> dict[str, Any]:
        _, fid = ledger_add(
            self.program,
            dict(finding_with_fid),
            self.snapshot_id,
            self.version_label,
            str(finding_with_fid.get("run_id") or self.run_id),
            str(finding_with_fid.get("agent") or self.agent),
        )
        entry = ledger_get(self.program, str(fid or finding_with_fid.get("fid") or ""))
        merged = dict(finding_with_fid)
        if entry:
            merged.update(entry)
        return merged

    def list_all(self) -> list[dict[str, Any]]:
        return ledger_list(
            self.program,
            snapshot_id=self.snapshot_id,
            version_label=self.version_label,
        )

    def get_class_context(self, vuln_class: str) -> str:
        target_class = _normalize_class_name(vuln_class)
        lines = [f"PRIOR FINDINGS FOR {target_class}:"]
        matches = [
            finding
            for finding in self.list_all()
            if _normalize_class_name(finding.get("class_name")) == target_class
        ]
        if not matches:
            lines.append("- None.")
            return "\n".join(lines)

        for finding in matches:
            current = finding.get("current", {})
            lines.append(
                f"- {finding.get('file', '')} | {finding.get('type', 'Unknown finding')} | "
                f"{current.get('version_label', '') or self.version_label} | {finding.get('last_seen', '')}"
            )
        return "\n".join(lines)
