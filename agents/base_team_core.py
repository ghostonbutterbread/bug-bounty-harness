"""Shared base framework for team-based vulnerability hunting."""

from __future__ import annotations

import abc
import argparse
import fcntl
import json
import logging
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.base_team.findings import (
    extract_findings_from_log,
    finding_identity,
    normalize_finding,
    normalize_relpath,
    read_findings_jsonl,
    safe_int,
)
from agents.base_team.ledger import (
    load_ledger as shared_load_ledger,
    reserve_findings as shared_reserve_findings,
    update_coverage_state as shared_update_coverage_state,
    update_reviewed_findings as shared_update_reviewed_findings,
)
from agents.base_team.review import (
    build_review_prompt as shared_build_review_prompt,
    normalize_review_tier as shared_normalize_review_tier,
    review_single_finding as shared_review_single_finding,
    run_review_cli as shared_run_review_cli,
    stage2_review as shared_stage2_review,
)
from agents.base_team.runtime import (
    install_signal_handlers as shared_install_signal_handlers,
    orchestrate as shared_orchestrate,
    spawn_agent as shared_spawn_agent,
    wait_for_agents as shared_wait_for_agents,
    write_traces as shared_write_traces,
)
from agents.base_team.storage import resolve_team_storage
from agents.snapshot_identity import get_snapshot_identity
from agents.storage_resolver import resolve_family_lane


LOGGER = logging.getLogger(__name__)

LEDGER_VERSION = 2
DEFAULT_AGENT_TIMEOUT_SECONDS = 1800
DEFAULT_REVIEW_TIMEOUT_SECONDS = 600
FINDINGS_FILENAME = "findings.jsonl"
TEAM_TYPES = ("0day_team", "apk", "web")
REVIEW_TIERS = {"CONFIRMED", "DORMANT", "NOVEL", "INCONCLUSIVE"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp_iso() -> str:
    return _utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")


def _trace_timestamp() -> str:
    return _utc_now().strftime("%Y%m%dT%H%M%SZ")


def _slug(value: str, *, separator: str = "-") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", separator, str(value or "").strip().lower())
    cleaned = cleaned.strip(separator)
    return cleaned or "unnamed"


def _normalize_text_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _extract_json_object(text: str) -> dict[str, Any]:
    stripped = str(text or "").strip()
    if not stripped:
        raise ValueError("empty model output")

    fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", stripped, re.DOTALL)
    if fence_match:
        stripped = fence_match.group(1).strip()

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start < 0 or end < start:
        raise ValueError("model output did not contain a JSON object")
    payload = json.loads(stripped[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("model output was not a JSON object")
    return payload


@dataclass(slots=True)
class AgentSpec:
    key: str
    vuln_class: str
    surface: str
    prompt_template: str
    focus_globs: list[str]
    code_patterns: list[str]
    program: str
    created_at: str
    snapshot_id: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AgentSpec":
        return cls(
            key=str(payload.get("key") or "").strip(),
            vuln_class=str(payload.get("vuln_class") or "").strip(),
            surface=str(payload.get("surface") or "").strip(),
            prompt_template=str(payload.get("prompt_template") or "").rstrip(),
            focus_globs=_normalize_text_list(payload.get("focus_globs")),
            code_patterns=_normalize_text_list(payload.get("code_patterns")),
            program=str(payload.get("program") or "").strip(),
            created_at=str(payload.get("created_at") or "").strip() or _timestamp_iso(),
            snapshot_id=str(payload.get("snapshot_id") or "").strip(),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseTeam(abc.ABC):
    """Common orchestration framework for team-based hunting pipelines."""

    @staticmethod
    def _storage_family_lane(team_type: str) -> tuple[str, str]:
        return resolve_family_lane(hunt_type=team_type)

    def __init__(
        self,
        program: str,
        team_type: str,
        target_path: Path,
        output_root: Path | None = None,
        max_agents: int = 10,
    ) -> None:
        normalized_program = re.sub(r"[^A-Za-z0-9._-]+", "_", str(program or "").strip())
        if not normalized_program:
            raise ValueError("program is required")
        if team_type not in TEAM_TYPES:
            raise ValueError(f"unsupported team_type {team_type!r}; expected one of {TEAM_TYPES}")

        resolved_target = Path(target_path).expanduser().resolve(strict=False)
        if not resolved_target.exists():
            raise FileNotFoundError(f"target_path does not exist: {resolved_target}")

        self.program = normalized_program
        self.team_type = team_type
        self.target_path = resolved_target
        self.max_agents = max(1, int(max_agents))
        self.workdir = Path(__file__).resolve().parent.parent

        self.family, self.lane = self._storage_family_lane(team_type)
        self.storage = resolve_team_storage(
            self.program,
            team_type=team_type,
            output_root=output_root,
        )
        self.output_root = self.storage.program_root

        self.team_dir = self.storage.lane_root
        self.agents_dir = self.team_dir / "agents"
        self.findings_path = self.storage.ledgers_root / FINDINGS_FILENAME
        self.ledger_path = self.storage.ledgers_root / "ledger.json"
        self.ledger_lock_path = self.storage.ledgers_root / "ledger.lock"
        self.shared_brain_dir = self.storage.ledgers_root / "shared_brain"
        self.agent_registry_dir = self.storage.working_root / "agent_registry"
        self.traces_dir = self.storage.ledgers_root / "traces"

        self.agent_timeout = DEFAULT_AGENT_TIMEOUT_SECONDS
        self.review_timeout = DEFAULT_REVIEW_TIMEOUT_SECONDS
        self.run_id = _trace_timestamp()
        self.force_preflight = False

        self._sigterm_received = False
        self._active_handles: dict[str, subprocess.Popen[Any]] = {}
        self._partial_findings: list[dict[str, Any]] = []
        self._last_loaded_ledger: dict[str, Any] | None = None
        self._last_review_error: str | None = None
        self._signal_handlers_installed = False

        for path in (
            self.team_dir,
            self.agents_dir,
            self.shared_brain_dir,
            self.agent_registry_dir,
            self.traces_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    @abc.abstractmethod
    def get_static_profiles(self) -> list[AgentSpec]:
        """Return fixed built-in agent profiles for this team."""

    @abc.abstractmethod
    def generate_dynamic_from_surfaces(
        self,
        surfaces: Sequence[dict[str, Any]],
        *,
        snapshot_id: str,
    ) -> list[AgentSpec]:
        """Convert detected surfaces into team-specific dynamic agent specs."""

    def spawn_agent(self, prompt: str, agent_name: str, log_path: Path) -> subprocess.Popen[Any]:
        """Spawn a codex subprocess and capture its output to the provided log."""
        return shared_spawn_agent(
            prompt,
            agent_name,
            log_path,
            ensure_parent=self._ensure_parent,
            team_dir=self.team_dir,
            workdir=self.workdir,
            target_path=self.target_path,
            active_handles=self._active_handles,
            write_traces=self.write_traces,
            slug=lambda value: _slug(value, separator="_"),
        )

    def wait_for_agents(
        self,
        handles: dict[str, subprocess.Popen[Any]],
        timeout: int,
    ) -> dict[str, tuple[str, int]]:
        """Wait for spawned agents, respecting a global timeout."""
        return shared_wait_for_agents(
            handles,
            timeout,
            sigterm_received=lambda: self._sigterm_received,
            read_log_for_handle=self._read_log_for_handle,
            cleanup_handle=self._cleanup_handle,
            write_traces=self.write_traces,
        )

    def load_ledger(self) -> dict[str, Any]:
        """Load the team ledger or return an empty v2-compatible structure."""
        return shared_load_ledger(
            self.ledger_lock_path,
            ensure_parent=self._ensure_parent,
            read_ledger_unchecked=self._read_ledger_unchecked,
            set_last_loaded=lambda payload: setattr(self, "_last_loaded_ledger", payload),
        )

    def deduplicate_findings(
        self,
        raw_findings: list[dict[str, Any]],
        ledger: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Return new findings while updating sighting counts on existing entries."""
        return shared_reserve_findings(
            raw_findings,
            program=self.program,
            storage=self.storage,
            target_path=self.target_path,
            snapshot_identity=self._snapshot_identity(),
            run_id=self.run_id,
            agent="base-team",
            normalize_finding=self._normalize_finding,
            timestamp_iso=_timestamp_iso,
            team_type=self.team_type,
        )

    def update_reviewed_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Persist reviewed findings through the canonical ledger API."""
        if not findings:
            return []
        return shared_update_reviewed_findings(
            findings,
            program=self.program,
            storage=self.storage,
            target_path=self.target_path,
            snapshot_identity=self._snapshot_identity(),
            run_id=self.run_id,
            agent="base-team-review",
            team_type=self.team_type,
        )

    def generate_dynamic_agents(self, target_path: Path, force: bool = False) -> list[AgentSpec]:
        """Load or generate dynamic agent specs for the current snapshot."""
        snapshot = get_snapshot_identity(Path(target_path).expanduser().resolve(strict=False))
        snapshot_id = str(snapshot.get("snapshot_id") or "").strip()
        if not snapshot_id:
            raise ValueError("could not determine snapshot_id for target")

        cached_specs = self._load_cached_specs(snapshot_id=snapshot_id)
        if cached_specs and not force:
            return cached_specs

        from agents.brainstorm import brainstorm_agent_specs

        upstream_specs = brainstorm_agent_specs(
            target_path=self.target_path,
            tech_stack=None,
            app_version=snapshot_id,
            program_slug=self.program,
        )
        surfaces = [
            {
                "key": str(getattr(spec, "key", "")).strip(),
                "surface_type": str(getattr(spec, "surface_type", "")).strip(),
                "vuln_class": str(getattr(spec, "vuln_class", "")).strip(),
                "patterns": list(getattr(spec, "patterns", []) or []),
                "focus_files_glob": list(getattr(spec, "focus_files_glob", []) or []),
                "agent_prompt_template": str(getattr(spec, "agent_prompt_template", "")).rstrip(),
                "description": str(getattr(spec, "description", "")).strip(),
            }
            for spec in upstream_specs
        ]
        generated = self.generate_dynamic_from_surfaces(surfaces, snapshot_id=snapshot_id)
        for spec in generated:
            self._save_spec(spec)

        self.write_traces(
            [
                {
                    "event": "dynamic_agents_generated",
                    "snapshot_id": snapshot_id,
                    "count": len(generated),
                    "target_path": str(self.target_path),
                }
            ]
        )
        return generated

    def load_shared_brain(self) -> dict[str, Any]:
        """Load the shared brain index from team-local or legacy ghost storage."""
        candidates = [
            self.shared_brain_dir / "index.json",
            self.storage.ledgers_root / "shared_brain" / "index.json",
        ]
        default = {
            "version": 1,
            "generated_at": "",
            "target_root": str(self.target_path),
            "files": {},
            "frameworks": [],
            "inventories": {},
        }
        for candidate in candidates:
            if not candidate.exists():
                continue
            try:
                payload = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                return payload
        return default

    def update_coverage(self, agent_name: str, surface: str, finding_count: int) -> None:
        """Update coverage metadata for a single agent execution."""
        shared_update_coverage_state(
            program=self.program,
            storage=self.storage,
            agent_name=agent_name,
            surface=surface,
            finding_count=finding_count,
            set_last_loaded=lambda payload: setattr(self, "_last_loaded_ledger", payload),
        )

    def stage2_review(
        self,
        findings: list[dict[str, Any]],
        target_path: Path,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Review findings with Claude first and Codex as fallback."""
        return shared_stage2_review(
            findings,
            target_path,
            review_single_finding=self._review_single_finding,
            normalize_review_tier=self._normalize_review_tier,
            set_last_review_error=lambda value: setattr(self, "_last_review_error", value),
        )

    def write_traces(self, events: list[dict[str, Any]]) -> None:
        """Append JSONL trace events to a timestamped trace file."""
        shared_write_traces(
            events,
            traces_dir=self.traces_dir,
            ensure_parent=self._ensure_parent,
            trace_timestamp=_trace_timestamp,
            timestamp_iso=_timestamp_iso,
            program=self.program,
            team_type=self.team_type,
        )

    def orchestrate(
        self,
        parallel: bool = True,
        agents_mode: str = "all",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Run the full team lifecycle."""
        return shared_orchestrate(
            parallel=parallel,
            agents_mode=agents_mode,
            install_signal_handlers=self._install_signal_handlers,
            set_partial_findings=lambda findings: setattr(self, "_partial_findings", findings),
            get_static_profiles=self.get_static_profiles,
            generate_dynamic_agents=self.generate_dynamic_agents,
            target_path=self.target_path,
            force_preflight=self.force_preflight,
            select_specs=lambda static_specs, dynamic_specs: self._select_specs(
                static_specs,
                dynamic_specs,
                agents_mode=agents_mode,
            ),
            load_shared_brain=self.load_shared_brain,
            load_ledger=self.load_ledger,
            set_last_loaded_ledger=lambda ledger: setattr(self, "_last_loaded_ledger", ledger),
            findings_path=self.findings_path,
            write_traces=self.write_traces,
            snapshot_id=self._snapshot_id,
            spawn_agent=self.spawn_agent,
            agents_dir=self.agents_dir,
            slug=lambda value: _slug(value, separator="_"),
            trace_timestamp=_trace_timestamp,
            sigterm_received=lambda: self._sigterm_received,
            read_log_for_handle=self._read_log_for_handle,
            cleanup_handle=self._cleanup_handle,
            collect_agent_findings=self._collect_agent_findings,
            agent_timeout=self.agent_timeout,
            deduplicate_findings=self.deduplicate_findings,
            stage2_review=self.stage2_review,
            update_reviewed_findings=self.update_reviewed_findings,
            update_coverage=self.update_coverage,
            get_last_review_error=lambda: self._last_review_error,
            active_handles=self._active_handles,
            persist_partial_results=self._persist_partial_results,
            render_prompt=self._render_prompt,
        )

    def _select_specs(
        self,
        static_specs: Sequence[AgentSpec],
        dynamic_specs: Sequence[AgentSpec],
        *,
        agents_mode: str,
    ) -> list[AgentSpec]:
        if agents_mode == "static":
            return list(static_specs)[: self.max_agents]
        if agents_mode == "dynamic":
            return list(dynamic_specs)[: self.max_agents]

        mixed: list[AgentSpec] = []
        static_iter = iter(static_specs)
        dynamic_iter = iter(dynamic_specs)
        while len(mixed) < self.max_agents:
            added = False
            try:
                mixed.append(next(static_iter))
                added = True
            except StopIteration:
                pass
            if len(mixed) >= self.max_agents:
                break
            try:
                mixed.append(next(dynamic_iter))
                added = True
            except StopIteration:
                pass
            if not added:
                break
        return mixed

    def _render_prompt(self, spec: AgentSpec) -> str:
        context = {
            "program": self.program,
            "team_type": self.team_type,
            "target_path": str(self.target_path),
            "findings_path": str(self.findings_path),
            "shared_brain_dir": str(self.shared_brain_dir),
            "shared_brain_index": str(self.shared_brain_dir / "index.json"),
            "agent_registry_dir": str(self.agent_registry_dir),
            "ledger_path": str(self.ledger_path),
            "traces_dir": str(self.traces_dir),
            "snapshot_id": spec.snapshot_id or self._snapshot_id(),
            "focus_globs": "\n".join(f"- {item}" for item in spec.focus_globs) or "- **/*",
            "code_patterns": "\n".join(f"- {item}" for item in spec.code_patterns) or "- None provided",
            "surface": spec.surface,
            "vuln_class": spec.vuln_class,
            "agent_key": spec.key,
            "family": self.storage.family,
            "lane": self.storage.lane,
            "canonical_root": str(self.storage.lane_root),
            "reports_root": str(self.storage.reports_root),
            "reports_raw_root": str(self.storage.reports_root / "raw"),
            "reports_confirmed_root": str(self.storage.reports_root / "confirmed"),
            "reports_dormant_root": str(self.storage.reports_root / "dormant"),
            "reports_novel_root": str(self.storage.reports_root / "novel"),
            "reports_complete_root": str(self.storage.reports_root / "complete"),
            "reports_archive_root": str(self.storage.reports_root / "archive"),
            "context_root": str(self.storage.context_root),
            "target_profile_path": str(self.storage.context_root / "target_profile.json"),
            "me_context_path": str(self.storage.context_root / "me_context.md"),
            "session_handoff_path": str(self.storage.context_root / "session_handoff.md"),
            "notes_root": str(self.storage.notes_root),
            "working_root": str(self.storage.working_root),
            "shared_root": str(self.storage.shared_root),
        }
        return spec.prompt_template.format(**context).rstrip() + "\n"

    def _collect_agent_findings(self, spec: AgentSpec, log_path: Path | None) -> list[dict[str, Any]]:
        log_findings = self._extract_findings_from_log(log_path, default_agent=spec.key) if log_path else []

        combined: list[dict[str, Any]] = []
        seen: set[tuple[str, int, str, str]] = set()
        for finding in log_findings:
            normalized = self._normalize_finding(finding, default_agent=spec.key, default_class=spec.vuln_class)
            if normalized is None:
                continue
            key = (
                str(normalized.get("file") or ""),
                safe_int(normalized.get("line")),
                str(normalized.get("class_name") or ""),
                str(normalized.get("type") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            combined.append(normalized)
        return combined

    def _review_single_finding(self, finding: dict[str, Any], target_path: Path) -> dict[str, Any]:
        return shared_review_single_finding(
            finding,
            target_path,
            build_review_prompt=self._build_review_prompt,
            run_review_cli=self._run_review_cli,
            extract_json_object=_extract_json_object,
            normalize_review_tier=self._normalize_review_tier,
            review_timeout=self.review_timeout,
        )

    def _run_review_cli(self, cli_name: str, prompt: str, timeout: int) -> str:
        return shared_run_review_cli(cli_name, prompt, timeout, workdir=self.workdir)

    def _build_review_prompt(self, finding: dict[str, Any], target_path: Path) -> str:
        return shared_build_review_prompt(
            finding,
            target_path,
            resolve_source_path=self._resolve_source_path,
            source_excerpt=self._source_excerpt,
            safe_int=safe_int,
        )

    def _normalize_review_tier(self, value: Any) -> str:
        return shared_normalize_review_tier(value)

    def _read_findings_jsonl(self) -> list[dict[str, Any]]:
        return read_findings_jsonl(self.findings_path)

    def _extract_findings_from_log(self, log_path: Path, default_agent: str) -> list[dict[str, Any]]:
        return extract_findings_from_log(log_path, default_agent=default_agent)

    def _normalize_finding(
        self,
        raw: Any,
        *,
        default_agent: str = "unknown",
        default_class: str = "unknown",
    ) -> dict[str, Any] | None:
        return normalize_finding(raw, default_agent=default_agent, default_class=default_class)

    def _finding_identity(self, finding: dict[str, Any]) -> tuple[str, int, str, str]:
        return finding_identity(finding)

    def _resolve_source_path(self, file_value: Any) -> Path | None:
        relpath = _normalize_relpath(file_value)
        if not relpath:
            return None
        candidate = self.target_path / relpath
        if candidate.exists() and candidate.is_file():
            return candidate
        absolute = Path(relpath).expanduser()
        if absolute.is_absolute() and absolute.exists() and absolute.is_file():
            return absolute
        return None

    def _source_excerpt(self, path: Path, line_number: int, radius: int = 15) -> str:
        try:
            source_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "UNAVAILABLE"

        lines = source_text.splitlines()
        if not lines:
            return "UNAVAILABLE"
        if line_number <= 0:
            start = 0
            end = min(len(lines), (radius * 2) + 1)
        else:
            start = max(0, line_number - radius - 1)
            end = min(len(lines), line_number + radius)
        excerpt_lines = [f"{index + 1}: {lines[index]}" for index in range(start, end)]
        return "\n".join(excerpt_lines)

    def _load_cached_specs(self, *, snapshot_id: str) -> list[AgentSpec]:
        specs: list[AgentSpec] = []
        for path in sorted(self.agent_registry_dir.glob(f"*__{snapshot_id}.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            try:
                spec = AgentSpec.from_dict(payload)
            except Exception:
                continue
            if spec.key:
                specs.append(spec)
        return specs

    def _save_spec(self, spec: AgentSpec) -> None:
        filename = f"{_slug(spec.key, separator='_')}__{spec.snapshot_id}.json"
        path = self.agent_registry_dir / filename
        path.write_text(json.dumps(spec.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _default_ledger(self) -> dict[str, Any]:
        return {
            "version": LEDGER_VERSION,
            "program": self.program,
            "team_type": self.team_type,
            "updated_at": _timestamp_iso(),
            "coverage": {
                "surfaces_tested": [],
                "agents_run": {},
                "total_findings": 0,
            },
            "findings": [],
        }

    def _normalize_ledger_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = self._default_ledger()
        normalized["updated_at"] = _timestamp_iso()
        if isinstance(payload.get("findings"), list):
            normalized["findings"] = [item for item in payload["findings"] if isinstance(item, dict)]
        coverage = payload.get("coverage")
        if isinstance(coverage, dict):
            normalized["coverage"]["surfaces_tested"] = sorted(
                {
                    str(item).strip()
                    for item in (coverage.get("surfaces_tested") or [])
                    if str(item).strip()
                }
            )
            normalized["coverage"]["agents_run"] = {
                str(key).strip(): str(value).strip()
                for key, value in (coverage.get("agents_run") or {}).items()
                if str(key).strip()
            }
            normalized["coverage"]["total_findings"] = max(
                _safe_int(coverage.get("total_findings")),
                len(normalized["findings"]),
            )
        return normalized

    def _read_ledger_unchecked(self) -> dict[str, Any]:
        payload = self._default_ledger()
        if not self.ledger_path.exists():
            return payload

        try:
            loaded = json.loads(self.ledger_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return payload

        if not isinstance(loaded, dict):
            return payload
        payload = self._normalize_ledger_payload(loaded)
        payload["updated_at"] = str(loaded.get("updated_at") or payload["updated_at"])
        return payload

    def _merge_ledger(self, current: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
        merged = self._normalize_ledger_payload(current)
        payload = self._normalize_ledger_payload(incoming)

        by_identity: dict[tuple[str, int, str, str], dict[str, Any]] = {}
        findings: list[dict[str, Any]] = []
        for finding in merged.get("findings", []):
            record = dict(finding)
            identity = self._finding_identity(record)
            by_identity[identity] = record
            findings.append(record)

        for finding in payload.get("findings", []):
            record = dict(finding)
            identity = self._finding_identity(record)
            existing = by_identity.get(identity)
            if existing is None:
                by_identity[identity] = record
                findings.append(record)
                continue

            previous_first_seen = existing.get("first_seen")
            previous_last_seen = existing.get("last_seen")
            previous_sighting_count = existing.get("sighting_count")
            previous_sightings = list(existing.get("sightings") or [])

            existing.update(record)

            first_seen_values = [value for value in (previous_first_seen, record.get("first_seen")) if value]
            if first_seen_values:
                existing["first_seen"] = min(str(value) for value in first_seen_values)

            last_seen_values = [value for value in (previous_last_seen, record.get("last_seen")) if value]
            if last_seen_values:
                existing["last_seen"] = max(str(value) for value in last_seen_values)

            existing["sighting_count"] = max(
                _safe_int(previous_sighting_count, 1),
                _safe_int(record.get("sighting_count"), 1),
            )

            sightings: list[dict[str, Any]] = []
            seen_sightings: set[str] = set()
            for candidate in previous_sightings + list(record.get("sightings") or []):
                if not isinstance(candidate, dict):
                    continue
                signature = json.dumps(candidate, sort_keys=True)
                if signature in seen_sightings:
                    continue
                seen_sightings.add(signature)
                sightings.append(candidate)
            if sightings:
                existing["sightings"] = sightings

        merged["findings"] = findings

        coverage = merged.setdefault("coverage", {})
        incoming_coverage = payload.get("coverage") or {}
        surfaces = {
            str(item).strip()
            for item in list(coverage.get("surfaces_tested") or []) + list(incoming_coverage.get("surfaces_tested") or [])
            if str(item).strip()
        }
        coverage["surfaces_tested"] = sorted(surfaces)
        coverage["agents_run"] = {
            **{str(key).strip(): str(value).strip() for key, value in (coverage.get("agents_run") or {}).items() if str(key).strip()},
            **{
                str(key).strip(): str(value).strip()
                for key, value in (incoming_coverage.get("agents_run") or {}).items()
                if str(key).strip()
            },
        }
        coverage["total_findings"] = max(
            _safe_int(coverage.get("total_findings")),
            _safe_int(incoming_coverage.get("total_findings")),
            len(findings),
        )
        merged["updated_at"] = payload.get("updated_at") or _timestamp_iso()
        return merged

    def _snapshot_id(self) -> str:
        snapshot = get_snapshot_identity(self.target_path)
        return str(snapshot.get("snapshot_id") or "").strip()

    def _snapshot_identity(self) -> dict[str, Any]:
        return get_snapshot_identity(self.target_path)

    def _persist_partial_results(self) -> None:
        if not self._partial_findings:
            return
        try:
            ledger = self.load_ledger()
            new_findings = self.deduplicate_findings(list(self._partial_findings), ledger)
            self.write_traces(
                [
                    {
                        "event": "partial_results_saved",
                        "finding_count": len(new_findings),
                        "sigterm_received": self._sigterm_received,
                    }
                ]
            )
        except Exception as exc:
            LOGGER.exception("failed to persist partial results: %s", exc)

    def _install_signal_handlers(self) -> None:
        shared_install_signal_handlers(
            signal_handlers_installed=lambda: self._signal_handlers_installed,
            set_sigterm_received=lambda value: setattr(self, "_sigterm_received", value),
            persist_partial_results=self._persist_partial_results,
            set_signal_handlers_installed=lambda value: setattr(self, "_signal_handlers_installed", value),
            write_traces=self.write_traces,
        )

    def _ensure_parent(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

    def _read_log_for_handle(self, handle: subprocess.Popen[Any]) -> str:
        log_path = getattr(handle, "_bbh_log_path", "")
        if not log_path:
            return ""
        try:
            return Path(log_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _cleanup_handle(self, handle: subprocess.Popen[Any]) -> None:
        log_handle = getattr(handle, "_bbh_log_handle", None)
        if log_handle is not None:
            try:
                log_handle.close()
            except OSError:
                pass

        prompt_path = getattr(handle, "_bbh_prompt_path", "")
        if prompt_path:
            try:
                Path(prompt_path).unlink(missing_ok=True)
            except OSError:
                pass

        agent_name = getattr(handle, "_bbh_agent_name", "")
        if agent_name:
            self._active_handles.pop(agent_name, None)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a shared BaseTeam-derived hunting pipeline.")
    parser.add_argument("--program", required=True, help="Bug bounty program name.")
    parser.add_argument("--target-path", required=True, help="Target root path.")
    parser.add_argument("--team-type", required=True, choices=TEAM_TYPES, help="Team family to run.")
    parser.add_argument(
        "--output-root",
        default=None,
        help="Optional explicit local canonical root override. Defaults to Shared family roots via storage_resolver.",
    )
    parser.add_argument("--parallel", action=argparse.BooleanOptionalAction, default=True, help="Run agents in parallel.")
    parser.add_argument(
        "--agents",
        choices=("static", "dynamic", "all"),
        default="all",
        help="Which agent sets to run.",
    )
    parser.add_argument("--max-agents", type=int, default=10, help="Cap on parallel agents.")
    parser.add_argument(
        "--force-preflight",
        action="store_true",
        help="Force regeneration of dynamic agent specs for the current snapshot.",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Sequence[str] | None = None) -> int:
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    args = parse_args(argv)
    target_path = Path(args.target_path).expanduser()
    output_root = Path(args.output_root).expanduser() if args.output_root else None

    if args.team_type == "0day_team":
        from agents.zero_day_team import ZeroDayTeam

        team: BaseTeam = ZeroDayTeam(
            program=args.program,
            team_type=args.team_type,
            target_path=target_path,
            output_root=output_root,
            max_agents=args.max_agents,
        )
    elif args.team_type == "apk":
        from agents.apk_team import APKTeam

        team = APKTeam(
            program=args.program,
            team_type=args.team_type,
            target_path=target_path,
            output_root=output_root,
            max_agents=args.max_agents,
        )
    else:
        raise SystemExit("web team is not implemented yet")

    team.force_preflight = bool(args.force_preflight)
    confirmed, dormant, novel = team.orchestrate(parallel=args.parallel, agents_mode=args.agents)
    print(
        json.dumps(
            {
                "program": team.program,
                "team_type": team.team_type,
                "confirmed": len(confirmed),
                "dormant": len(dormant),
                "novel": len(novel),
                "ledger_path": str(team.ledger_path),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
