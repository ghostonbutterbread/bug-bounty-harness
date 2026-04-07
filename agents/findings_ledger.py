"""Persistent per-program findings ledger for zero-day hunting workflows."""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import re
import shutil
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Self


LOGGER = logging.getLogger(__name__)

LEDGER_FILENAME = "findings_ledger.json"
LEDGER_VERSION = 1
DEFAULT_STATUS = "pending-review"
DEFAULT_CHAIN_STATUS = "unchained"

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FILE_LINE_RE = re.compile(r"^(?P<path>.+?)(?::(?P<line>\d+))(?::\d+)?$")
_STRING_LITERAL_RE = re.compile(
    r"""
    (?:
        "(?:\\.|[^"\\])*"
        |
        '(?:\\.|[^'\\])*'
        |
        `(?:\\.|[^`\\])*`
    )
    """,
    re.VERBOSE,
)
_NUMBER_LITERAL_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
_WHITESPACE_RE = re.compile(r"\s+")
_ASSIGNMENT_RE = re.compile(r"^(?P<lhs>[^=!<>]+?)\s*=\s*(?![=>])(?P<rhs>.+)$")
_CALL_RE = re.compile(r"^(?P<callee>[A-Za-z_][A-Za-z0-9_$.]*)\s*\((?P<args>.*)\)$")

_STABLE_SINK_ROOTS = {
    "axios",
    "child_process",
    "document",
    "fetch",
    "fs",
    "http",
    "https",
    "ipcmain",
    "ipcrenderer",
    "os",
    "path",
    "process",
    "subprocess",
    "url",
    "window",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _today_iso() -> str:
    return _utc_now().date().isoformat()


def _timestamp_iso() -> str:
    return _utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")


def _default_run_id() -> str:
    return _utc_now().strftime("%Y%m%dT%H%M%SZ")


def _sanitize_program_name(program: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(program).strip())
    return cleaned or "default_program"


def _normalize_label(value: Any, default: str) -> str:
    text = str(value or "").strip().lower()
    return text or default


def _normalize_date(value: Any, default: str) -> str:
    text = str(value or "").strip()
    return text if _DATE_RE.match(text) else default


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _split_file_reference(value: Any) -> tuple[str, int]:
    raw = str(value or "").strip()
    if not raw:
        return "", 0

    match = _FILE_LINE_RE.match(raw)
    if not match:
        return raw, 0

    path_part = match.group("path").strip()
    if not path_part:
        return raw, 0
    return path_part, _safe_int(match.group("line"))


def _canonicalize_symbol_chain(chain: str, keep_tail: int) -> str:
    parts = [part for part in chain.split(".") if part]
    if not parts:
        return chain
    if len(parts) <= keep_tail:
        return ".".join(parts)

    root = parts[0].lower()
    tail = ".".join(parts[-keep_tail:])
    if root in _STABLE_SINK_ROOTS:
        if len(parts) <= 3:
            return ".".join(parts)
        return f"{parts[0]}.{tail}"
    return f"<obj>.{tail}"


def _count_args(arg_text: str) -> int:
    stripped = arg_text.strip()
    if not stripped:
        return 0

    depth = 0
    in_quote: str | None = None
    escaped = False
    count = 1
    for char in stripped:
        if in_quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == in_quote:
                in_quote = None
            continue
        if char in {'"', "'", "`"}:
            in_quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            count += 1
    return count


@dataclass(slots=True)
class FindingEntry:
    """Canonical persisted representation of a finding in the ledger."""

    fid: str
    vuln_class: str
    file: str
    line: int
    sink: str
    title: str
    status: str
    chain_status: str
    discovered_date: str
    last_seen: str
    runs: list[str] = field(default_factory=list)
    fingerprint: str = ""
    category: str = "class"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Build a ledger entry from JSON-backed data."""
        fid = str(data.get("fid", "")).strip()
        if not fid:
            raise ValueError("finding entry is missing fid")

        discovered_date = _normalize_date(data.get("discovered_date"), _today_iso())
        last_seen = _normalize_date(data.get("last_seen"), discovered_date)

        runs = data.get("runs") or []
        if not isinstance(runs, list):
            runs = [str(runs)]

        return cls(
            fid=fid,
            vuln_class=_normalize_label(data.get("vuln_class"), "unknown"),
            file=str(data.get("file", "")).strip(),
            line=_safe_int(data.get("line")),
            sink=str(data.get("sink", "")).strip(),
            title=str(data.get("title", "")).strip() or "Untitled finding",
            status=_normalize_label(data.get("status"), DEFAULT_STATUS),
            chain_status=_normalize_label(data.get("chain_status"), DEFAULT_CHAIN_STATUS),
            discovered_date=discovered_date,
            last_seen=last_seen,
            runs=[str(item).strip() for item in runs if str(item).strip()],
            fingerprint=str(data.get("fingerprint", "")).strip(),
            category=_normalize_label(data.get("category"), "class"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the entry for JSON persistence."""
        return {
            "fid": self.fid,
            "vuln_class": self.vuln_class,
            "file": self.file,
            "line": self.line,
            "sink": self.sink,
            "title": self.title,
            "status": self.status,
            "chain_status": self.chain_status,
            "discovered_date": self.discovered_date,
            "last_seen": self.last_seen,
            "runs": list(self.runs),
            "fingerprint": self.fingerprint,
            "category": self.category,
        }


class FindingsLedger:
    """Persistent finding tracker with dedupe, context injection, and reporting."""

    def __init__(
        self,
        program: str,
        *,
        base_dir: str | Path | None = None,
        run_id: str | None = None,
    ) -> None:
        """Initialize the ledger for one program and create backing storage if needed."""
        self.program = _sanitize_program_name(program)
        self.base_dir = (
            Path(base_dir).expanduser().resolve(strict=False)
            if base_dir is not None
            else Path.cwd().resolve(strict=False)
        )
        provided_run_id = str(run_id or "").strip()
        self.run_id = provided_run_id or _default_run_id()
        self.ledger_dir = (
            Path.home() / "Shared" / "bounty_recon" / self.program / "ghost" / "ledger"
        )
        self.path = self.ledger_dir / LEDGER_FILENAME
        self.lock_path = Path(f"{self.path}.lock")
        self.backup_path = Path(f"{self.path}.bak")

        self._entries_by_fid: dict[str, FindingEntry] = {}
        self._fingerprint_to_fid: dict[str, str] = {}
        self._ensure_storage()

    def normalize_file_path(self, file_value: str) -> str:
        """Return the normalized file path used for dedupe fingerprints."""
        resolved_path, _ = self._resolve_file_reference(file_value)
        return str(resolved_path).lower()

    def normalize_sink(self, sink: str) -> str:
        """Return the normalized sink string used for dedupe fingerprints."""
        cleaned = _WHITESPACE_RE.sub(" ", str(sink or "").strip())
        if not cleaned:
            return ""

        cleaned = _STRING_LITERAL_RE.sub("<str>", cleaned)
        cleaned = _NUMBER_LITERAL_RE.sub("<num>", cleaned)
        cleaned = cleaned.lower()

        assignment_match = _ASSIGNMENT_RE.match(cleaned)
        if assignment_match:
            lhs = assignment_match.group("lhs").strip()
            return f"{_canonicalize_symbol_chain(lhs, keep_tail=1)} = <expr>"

        call_match = _CALL_RE.match(cleaned)
        if call_match:
            callee = _canonicalize_symbol_chain(call_match.group("callee").strip(), keep_tail=2)
            arg_count = _count_args(call_match.group("args"))
            args = ", ".join("<arg>" for _ in range(arg_count))
            return f"{callee}({args})"

        cleaned = re.sub(
            r"\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\b",
            lambda match: _canonicalize_symbol_chain(match.group(0), keep_tail=2),
            cleaned,
        )
        return _WHITESPACE_RE.sub(" ", cleaned).strip()

    def fingerprint_for(self, finding_dict: dict[str, Any]) -> str:
        """Compute the dedupe fingerprint for an incoming finding-like dict."""
        prepared = self._prepare_candidate(finding_dict)
        return prepared["fingerprint"]

    def check(self, finding_dict: dict[str, Any]) -> tuple[bool, str | None, dict[str, Any]]:
        """Check the ledger for duplicates and reserve a new FID when needed."""
        candidate = self._prepare_candidate(finding_dict)

        with self._locked_ledger():
            self._load_locked()
            fingerprint = candidate["fingerprint"]
            existing_fid = self._fingerprint_to_fid.get(fingerprint)
            if existing_fid is not None:
                entry = self._entries_by_fid[existing_fid]
                self._refresh_seen_fields(entry, candidate)
                self._save_locked()
                return True, entry.fid, self._merge_entry_into_finding(finding_dict, entry)

            fid = self._next_fid_locked(self._fid_prefix_for(candidate["category"]))
            entry = FindingEntry(
                fid=fid,
                vuln_class=candidate["vuln_class"],
                file=candidate["file"],
                line=candidate["line"],
                sink=candidate["sink"],
                title=candidate["title"],
                status=candidate["status"],
                chain_status=candidate["chain_status"],
                discovered_date=candidate["discovered_date"],
                last_seen=candidate["last_seen"],
                runs=list(candidate["runs"]),
                fingerprint=fingerprint,
                category=candidate["category"],
            )
            self._entries_by_fid[fid] = entry
            self._fingerprint_to_fid[fingerprint] = fid
            self._save_locked()
            return False, fid, self._merge_entry_into_finding(finding_dict, entry)

    def update(self, finding_with_fid: dict[str, Any]) -> dict[str, Any]:
        """Persist updated status or metadata for a previously reserved finding."""
        fid = str(finding_with_fid.get("fid", "")).strip()
        if not fid:
            raise ValueError("finding update requires fid")

        with self._locked_ledger():
            self._load_locked()
            if fid not in self._entries_by_fid:
                raise KeyError(f"unknown finding id: {fid}")

            entry = self._entries_by_fid[fid]
            merged_source = self._merge_entry_into_finding({}, entry)
            merged_source.update(finding_with_fid)
            candidate = self._prepare_candidate(merged_source)
            if entry.fingerprint != candidate["fingerprint"]:
                other_fid = self._fingerprint_to_fid.get(candidate["fingerprint"])
                if other_fid is not None and other_fid != fid:
                    raise ValueError(
                        f"updated finding collides with existing fingerprint owned by {other_fid}"
                    )
                self._fingerprint_to_fid.pop(entry.fingerprint, None)
                self._fingerprint_to_fid[candidate["fingerprint"]] = fid
                entry.fingerprint = candidate["fingerprint"]

            entry.vuln_class = candidate["vuln_class"]
            entry.file = candidate["file"]
            entry.line = candidate["line"]
            entry.sink = candidate["sink"]
            entry.title = candidate["title"]
            entry.status = candidate["status"]
            entry.chain_status = candidate["chain_status"]
            entry.category = candidate["category"]
            entry.discovered_date = _normalize_date(
                finding_with_fid.get("discovered_date"), entry.discovered_date
            )
            self._refresh_seen_fields(entry, candidate)
            self._save_locked()
            return self._merge_entry_into_finding(finding_with_fid, entry)

    def get_class_context(self, vuln_class: str) -> str:
        """Format prior findings for one vulnerability class for agent prompt injection."""
        target_class = _normalize_label(vuln_class, "unknown")
        with self._locked_ledger():
            self._load_locked()
            matches = [
                entry
                for entry in self._entries_by_fid.values()
                if entry.vuln_class == target_class
            ]

        lines = [f"PRIOR FINDINGS FOR {target_class}:"]
        if not matches:
            lines.append("- None.")
            return "\n".join(lines)

        for entry in sorted(matches, key=self._sort_key):
            lines.append(f"- {entry.file} | {entry.sink or 'unknown sink'} | {entry.discovered_date}")
        return "\n".join(lines)

    def get_by_status(self, status: str) -> list[dict[str, Any]]:
        """Return ledger findings whose status matches the provided value."""
        target_status = _normalize_label(status, DEFAULT_STATUS)
        with self._locked_ledger():
            self._load_locked()
            matches = [
                entry.to_dict()
                for entry in sorted(self._entries_by_fid.values(), key=self._sort_key)
                if entry.status == target_status
            ]
        return matches

    def list_all(self) -> list[dict[str, Any]]:
        """Return every persisted finding in stable display order."""
        with self._locked_ledger():
            self._load_locked()
            return [
                entry.to_dict()
                for entry in sorted(self._entries_by_fid.values(), key=self._sort_key)
            ]

    def summary(self) -> str:
        """Return a human-readable summary of the ledger contents."""
        with self._locked_ledger():
            self._load_locked()
            entries = sorted(self._entries_by_fid.values(), key=self._sort_key)

        lines = [
            f"Findings ledger for {self.program}",
            f"Path: {self.path}",
            f"Total findings: {len(entries)}",
        ]

        if not entries:
            lines.append("No findings recorded.")
            return "\n".join(lines)

        status_counts = Counter(entry.status for entry in entries)
        lines.append(
            "By status: "
            + ", ".join(f"{status}={count}" for status, count in sorted(status_counts.items()))
        )
        lines.append("")
        for entry in entries:
            location = f"{entry.file}:{entry.line}" if entry.line else entry.file
            lines.append(
                f"- {entry.fid} [{entry.status}/{entry.chain_status}] "
                f"{entry.vuln_class} :: {entry.title} :: {location}"
            )
        return "\n".join(lines)

    def export_markdown(self, path: str | Path) -> Path:
        """Export the full ledger as a markdown report and return the written path."""
        output_path = Path(path).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with self._locked_ledger():
            self._load_locked()
            entries = sorted(self._entries_by_fid.values(), key=self._sort_key)

        lines = [
            "# Findings Ledger",
            "",
            f"- Program: `{self.program}`",
            f"- Generated: `{_timestamp_iso()}`",
            f"- Total findings: `{len(entries)}`",
            "",
        ]

        if not entries:
            lines.append("No findings recorded.")
        else:
            for entry in entries:
                location = f"{entry.file}:{entry.line}" if entry.line else entry.file
                runs = ", ".join(entry.runs) if entry.runs else "None"
                lines.extend(
                    [
                        f"## {entry.fid} {entry.title}",
                        "",
                        f"- Vulnerability class: `{entry.vuln_class}`",
                        f"- Status: `{entry.status}`",
                        f"- Chain status: `{entry.chain_status}`",
                        f"- Category: `{entry.category}`",
                        f"- File: `{location}`",
                        f"- Sink: `{entry.sink or 'unknown sink'}`",
                        f"- Discovered: `{entry.discovered_date}`",
                        f"- Last seen: `{entry.last_seen}`",
                        f"- Runs: `{runs}`",
                        "",
                    ]
                )

        output_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        return output_path

    def _ensure_storage(self) -> None:
        self.ledger_dir.mkdir(parents=True, exist_ok=True)
        with self._locked_ledger():
            self._load_locked()
            if not self.path.exists():
                self._save_locked()

    @contextmanager
    def _locked_ledger(self) -> Iterator[None]:
        self.ledger_dir.mkdir(parents=True, exist_ok=True)
        self.lock_path.touch(exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def _load_locked(self) -> None:
        if not self.path.exists():
            self._entries_by_fid = {}
            self._fingerprint_to_fid = {}
            return

        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            LOGGER.warning("Ledger JSON parse error in %s: %s", self.path, exc)
            self._backup_corrupt_file_locked()
            self._entries_by_fid = {}
            self._fingerprint_to_fid = {}
            self._save_locked()
            return

        if not isinstance(payload, dict):
            LOGGER.warning("Ledger payload in %s is not a JSON object; recreating", self.path)
            self._backup_corrupt_file_locked()
            self._entries_by_fid = {}
            self._fingerprint_to_fid = {}
            self._save_locked()
            return

        raw_findings = payload.get("findings", [])
        if not isinstance(raw_findings, list):
            LOGGER.warning("Ledger findings array in %s is invalid; recreating", self.path)
            self._backup_corrupt_file_locked()
            self._entries_by_fid = {}
            self._fingerprint_to_fid = {}
            self._save_locked()
            return

        entries_by_fid: dict[str, FindingEntry] = {}
        fingerprint_to_fid: dict[str, str] = {}
        for index, item in enumerate(raw_findings, start=1):
            if not isinstance(item, dict):
                LOGGER.warning("Skipping malformed ledger entry %s[%d]", self.path, index)
                continue
            try:
                entry = FindingEntry.from_dict(item)
            except ValueError as exc:
                LOGGER.warning("Skipping invalid ledger entry %s[%d]: %s", self.path, index, exc)
                continue

            if not entry.fingerprint:
                entry.fingerprint = self._fingerprint_parts(
                    entry.vuln_class,
                    self.normalize_file_path(entry.file),
                    self.normalize_sink(entry.sink),
                )
            entries_by_fid[entry.fid] = entry
            fingerprint_to_fid[entry.fingerprint] = entry.fid

        self._entries_by_fid = entries_by_fid
        self._fingerprint_to_fid = fingerprint_to_fid

    def _save_locked(self) -> None:
        payload = {
            "version": LEDGER_VERSION,
            "program": self.program,
            "updated_at": _timestamp_iso(),
            "findings": [
                entry.to_dict()
                for entry in sorted(self._entries_by_fid.values(), key=self._sort_key)
            ],
        }

        self.ledger_dir.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            shutil.copy2(self.path, self.backup_path)

        temp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temp_path.replace(self.path)

    def _backup_corrupt_file_locked(self) -> None:
        if self.path.exists():
            shutil.copy2(self.path, self.backup_path)

    def _resolve_file_reference(self, file_value: Any) -> tuple[Path, int]:
        raw_path, inline_line = _split_file_reference(file_value)
        path = Path(raw_path).expanduser() if raw_path else self.base_dir
        if not path.is_absolute():
            path = self.base_dir / path
        return path.resolve(strict=False), inline_line

    def _extract_run_id(self, finding_dict: dict[str, Any]) -> str:
        for key in ("run_id", "run", "run_label", "session_id"):
            value = str(finding_dict.get(key, "")).strip()
            if value:
                return value
        return self.run_id

    def _prepare_candidate(self, finding_dict: dict[str, Any]) -> dict[str, Any]:
        resolved_file, inline_line = self._resolve_file_reference(
            finding_dict.get("resolved_file") or finding_dict.get("file", "")
        )
        explicit_line = _safe_int(finding_dict.get("line"))
        sink = str(finding_dict.get("sink", "")).strip()

        vuln_class = _normalize_label(
            finding_dict.get("vuln_class") or finding_dict.get("class_name") or finding_dict.get("category"),
            "unknown",
        )
        category = _normalize_label(finding_dict.get("category"), "class")
        if vuln_class == "novel":
            category = "novel"
        if category not in {"class", "novel"}:
            category = "class"

        status = self._derive_status(finding_dict, category)
        chain_status = self._derive_chain_status(finding_dict)
        discovered_date = _normalize_date(finding_dict.get("discovered_date"), _today_iso())
        last_seen = _normalize_date(finding_dict.get("last_seen"), _today_iso())
        run_id = self._extract_run_id(finding_dict)

        normalized_file = self.normalize_file_path(str(resolved_file))
        normalized_sink = self.normalize_sink(sink)
        fingerprint = self._fingerprint_parts(vuln_class, normalized_file, normalized_sink)

        return {
            "fid": str(finding_dict.get("fid", "")).strip(),
            "vuln_class": vuln_class,
            "file": str(resolved_file),
            "line": explicit_line or inline_line,
            "sink": sink,
            "title": self._derive_title(finding_dict),
            "status": status,
            "chain_status": chain_status,
            "discovered_date": discovered_date,
            "last_seen": last_seen,
            "runs": [run_id] if run_id else [],
            "fingerprint": fingerprint,
            "category": category,
        }

    def _derive_title(self, finding_dict: dict[str, Any]) -> str:
        for key in ("title", "type", "vulnerability_name"):
            value = str(finding_dict.get(key, "")).strip()
            if value:
                return value
        return "Untitled finding"

    def _derive_status(self, finding_dict: dict[str, Any], category: str) -> str:
        status = (
            finding_dict.get("status")
            or finding_dict.get("review_tier")
            or finding_dict.get("tier")
        )
        if status:
            return _normalize_label(status, DEFAULT_STATUS)
        if category == "novel":
            return "novel"
        return DEFAULT_STATUS

    def _derive_chain_status(self, finding_dict: dict[str, Any]) -> str:
        if finding_dict.get("chain_status"):
            return _normalize_label(finding_dict.get("chain_status"), DEFAULT_CHAIN_STATUS)
        if str(finding_dict.get("chain_requirements", "")).strip():
            return "needs-chain"
        return DEFAULT_CHAIN_STATUS

    def _refresh_seen_fields(self, entry: FindingEntry, candidate: dict[str, Any]) -> None:
        entry.last_seen = candidate["last_seen"]
        for run_id in candidate["runs"]:
            if run_id and run_id not in entry.runs:
                entry.runs.append(run_id)

    def _fingerprint_parts(
        self,
        vuln_class: str,
        normalized_file: str,
        normalized_sink: str,
    ) -> str:
        joined = "\n".join(
            (
                _normalize_label(vuln_class, "unknown"),
                normalized_file,
                normalized_sink,
            )
        )
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

    def _fid_prefix_for(self, category: str) -> str:
        return "N" if category == "novel" else "D"

    def _next_fid_locked(self, prefix: str) -> str:
        highest = 0
        for fid in self._entries_by_fid:
            if fid.startswith(prefix):
                highest = max(highest, _safe_int(fid[1:]))
        return f"{prefix}{highest + 1:02d}"

    def _merge_entry_into_finding(
        self,
        finding_dict: dict[str, Any],
        entry: FindingEntry,
    ) -> dict[str, Any]:
        merged = dict(finding_dict)
        merged.update(
            {
                "fid": entry.fid,
                "vuln_class": entry.vuln_class,
                "class_name": str(merged.get("class_name") or entry.vuln_class),
                "file": entry.file,
                "line": entry.line,
                "sink": entry.sink,
                "title": entry.title,
                "status": entry.status,
                "chain_status": entry.chain_status,
                "discovered_date": entry.discovered_date,
                "last_seen": entry.last_seen,
                "runs": list(entry.runs),
            }
        )
        return merged

    def _sort_key(self, entry: FindingEntry) -> tuple[str, int, str]:
        return entry.fid[:1], _safe_int(entry.fid[1:]), entry.title.lower()
