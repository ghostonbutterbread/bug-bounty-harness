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

from agents.snapshot_identity import get_snapshot_identity


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


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_relpath(value: Any) -> str:
    relpath = str(value or "").strip().replace("\\", "/")
    while relpath.startswith("./"):
        relpath = relpath[2:]
    return relpath


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

    def __init__(
        self,
        program: str,
        team_type: str,
        target_path: Path,
        output_root: Path = Path("~/Shared/bounty_recon").expanduser(),
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
        self.output_root = Path(output_root).expanduser().resolve(strict=False)
        self.max_agents = max(1, int(max_agents))
        self.workdir = Path(__file__).resolve().parent.parent

        self.team_dir = self.output_root / self.program / self.team_type
        self.agents_dir = self.team_dir / "agents"
        self.findings_path = self.team_dir / FINDINGS_FILENAME
        self.ledger_path = self.team_dir / "ledger.json"
        self.ledger_lock_path = self.team_dir / "ledger.lock"
        self.shared_brain_dir = self.team_dir / "shared_brain"
        self.agent_registry_dir = self.team_dir / "agent_registry"
        self.traces_dir = self.team_dir / "traces"

        self.agent_timeout = DEFAULT_AGENT_TIMEOUT_SECONDS
        self.review_timeout = DEFAULT_REVIEW_TIMEOUT_SECONDS
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
        self._ensure_parent(log_path)

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=self.team_dir,
            prefix=f".prompt_{_slug(agent_name, separator='_')}_",
            suffix=".txt",
            delete=False,
        ) as handle:
            handle.write(prompt)
            handle.write("\n")
            prompt_file = Path(handle.name)

        command = (
            "codex exec -s danger-full-access --skip-git-repo-check "
            f"-C {shlex.quote(str(self.workdir))} < {shlex.quote(str(prompt_file))}"
        )

        log_handle = log_path.open("ab")
        process = subprocess.Popen(
            ["bash", "-lc", command],
            cwd=str(self.workdir),
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
        setattr(process, "_bbh_log_path", str(log_path))
        setattr(process, "_bbh_prompt_path", str(prompt_file))
        setattr(process, "_bbh_agent_name", str(agent_name))
        setattr(process, "_bbh_log_handle", log_handle)
        self._active_handles[agent_name] = process

        self.write_traces(
            [
                {
                    "event": "spawn",
                    "agent_name": agent_name,
                    "log_path": str(log_path),
                    "prompt_path": str(prompt_file),
                    "pid": process.pid,
                    "command": command,
                    "target_path": str(self.target_path),
                }
            ]
        )
        return process

    def wait_for_agents(
        self,
        handles: dict[str, subprocess.Popen[Any]],
        timeout: int,
    ) -> dict[str, tuple[str, int]]:
        """Wait for spawned agents, respecting a global timeout."""
        deadline = time.monotonic() + max(1, int(timeout))
        pending = dict(handles)
        completed: dict[str, tuple[str, int]] = {}

        while pending:
            if self._sigterm_received:
                break

            for agent_name, handle in list(pending.items()):
                returncode = handle.poll()
                if returncode is None:
                    continue
                completed[agent_name] = (self._read_log_for_handle(handle), returncode)
                self._cleanup_handle(handle)
                pending.pop(agent_name, None)

            if not pending:
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.2)

        for agent_name, handle in pending.items():
            try:
                handle.terminate()
                handle.wait(timeout=5)
            except subprocess.TimeoutExpired:
                handle.kill()
                handle.wait(timeout=5)
            except OSError:
                pass
            completed[agent_name] = (self._read_log_for_handle(handle), -9)
            self._cleanup_handle(handle)
            self.write_traces(
                [
                    {
                        "event": "timeout",
                        "agent_name": agent_name,
                        "pid": handle.pid,
                        "timeout_seconds": int(timeout),
                    }
                ]
            )

        return completed

    def load_ledger(self) -> dict[str, Any]:
        """Load the team ledger or return an empty v2-compatible structure."""
        self._ensure_parent(self.ledger_lock_path)
        self.ledger_lock_path.touch(exist_ok=True)
        with self.ledger_lock_path.open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                payload = self._read_ledger_unchecked()
                self._last_loaded_ledger = payload
                return payload
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def save_ledger(self, ledger: dict[str, Any]) -> None:
        """Persist the ledger atomically under an exclusive lock."""
        payload = self._normalize_ledger_payload(ledger)
        self._ensure_parent(self.ledger_path)
        self._ensure_parent(self.ledger_lock_path)
        self.ledger_lock_path.touch(exist_ok=True)

        with self.ledger_lock_path.open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                current = self._read_ledger_unchecked()
                merged = self._merge_ledger(current, payload)
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=self.ledger_path.parent,
                    prefix=f".{self.ledger_path.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as handle:
                    json.dump(merged, handle, indent=2, sort_keys=False)
                    handle.write("\n")
                    temp_path = Path(handle.name)
                temp_path.replace(self.ledger_path)
                self._last_loaded_ledger = merged
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def deduplicate_findings(
        self,
        raw_findings: list[dict[str, Any]],
        ledger: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Return new findings while updating sighting counts on existing entries."""
        findings = ledger.setdefault("findings", [])
        seen: dict[tuple[str, int, str, str], dict[str, Any]] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            seen[self._finding_identity(finding)] = finding

        new_findings: list[dict[str, Any]] = []
        now = _timestamp_iso()
        for raw in raw_findings:
            finding = self._normalize_finding(raw)
            if finding is None:
                continue
            identity = self._finding_identity(finding)
            existing = seen.get(identity)
            if existing is not None:
                existing["last_seen"] = now
                existing["sighting_count"] = _safe_int(existing.get("sighting_count"), 1) + 1
                sightings = existing.get("sightings")
                if not isinstance(sightings, list):
                    sightings = []
                    existing["sightings"] = sightings
                sightings.append(
                    {
                        "seen_at": now,
                        "agent": str(finding.get("agent") or ""),
                        "team_type": self.team_type,
                    }
                )
                continue

            finding["first_seen"] = now
            finding["last_seen"] = now
            finding["sighting_count"] = 1
            finding["snapshot_id"] = self._snapshot_id()
            seen[identity] = finding
            new_findings.append(finding)

        coverage = ledger.setdefault("coverage", {})
        coverage["total_findings"] = max(
            _safe_int(coverage.get("total_findings")),
            len(findings) + len(new_findings),
        )
        return new_findings

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
            self.output_root / self.program / "ghost" / "shared_brain" / "index.json",
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
        ledger = self.load_ledger()
        coverage = ledger.setdefault("coverage", {})
        agents_run = coverage.setdefault("agents_run", {})
        surfaces_tested = coverage.setdefault("surfaces_tested", [])

        agents_run[str(agent_name)] = _timestamp_iso()
        normalized_surface = str(surface or "").strip()
        if normalized_surface and normalized_surface not in surfaces_tested:
            surfaces_tested.append(normalized_surface)
            surfaces_tested.sort()

        coverage["total_findings"] = max(
            _safe_int(coverage.get("total_findings")),
            len(ledger.get("findings") or []),
            max(0, int(finding_count)),
        )
        self.save_ledger(ledger)

    def stage2_review(
        self,
        findings: list[dict[str, Any]],
        target_path: Path,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Review findings with Claude first and Codex as fallback."""
        confirmed: list[dict[str, Any]] = []
        dormant: list[dict[str, Any]] = []
        novel: list[dict[str, Any]] = []
        self._last_review_error = None

        for finding in findings:
            try:
                reviewed = self._review_single_finding(finding, target_path)
            except Exception as exc:
                reviewed = dict(finding)
                reviewed["review_tier"] = "INCONCLUSIVE"
                reviewed["review_error"] = str(exc)
                self._last_review_error = str(exc)

            category = str(reviewed.get("category") or "").strip().lower()
            tier = self._normalize_review_tier(reviewed.get("review_tier"))
            reviewed["review_tier"] = tier

            if tier == "INCONCLUSIVE":
                # Inconclusive findings go to dormant but keep their tier flag
                dormant.append(reviewed)
            elif category == "novel" or tier == "NOVEL":
                novel.append(reviewed)
            elif tier == "CONFIRMED":
                confirmed.append(reviewed)
            else:
                dormant.append(reviewed)

        return confirmed, dormant, novel

    def write_traces(self, events: list[dict[str, Any]]) -> None:
        """Append JSONL trace events to a timestamped trace file."""
        if not events:
            return
        trace_path = self.traces_dir / f"{_trace_timestamp()}.jsonl"
        self._ensure_parent(trace_path)
        with trace_path.open("a", encoding="utf-8") as handle:
            for event in events:
                payload = dict(event)
                payload.setdefault("timestamp", _timestamp_iso())
                payload.setdefault("program", self.program)
                payload.setdefault("team_type", self.team_type)
                handle.write(json.dumps(payload, sort_keys=True))
                handle.write("\n")

    def orchestrate(
        self,
        parallel: bool = True,
        agents_mode: str = "all",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Run the full team lifecycle."""
        if agents_mode not in {"static", "dynamic", "all"}:
            raise ValueError("agents_mode must be one of: static, dynamic, all")

        self._install_signal_handlers()
        self._partial_findings = []

        static_specs = self.get_static_profiles() if agents_mode in {"static", "all"} else []
        dynamic_specs = (
            self.generate_dynamic_agents(self.target_path, force=self.force_preflight)
            if agents_mode in {"dynamic", "all"}
            else []
        )
        selected_specs = self._select_specs(static_specs, dynamic_specs, agents_mode=agents_mode)
        shared_brain = self.load_shared_brain()
        ledger = self.load_ledger()
        self._last_loaded_ledger = ledger
        self.findings_path.write_text("", encoding="utf-8")

        self.write_traces(
            [
                {
                    "event": "preflight",
                    "agents_mode": agents_mode,
                    "parallel": bool(parallel),
                    "static_count": len(static_specs),
                    "dynamic_count": len(dynamic_specs),
                    "selected_count": len(selected_specs),
                    "snapshot_id": self._snapshot_id(),
                    "shared_brain_files": len((shared_brain.get("files") or {})),
                }
            ]
        )

        raw_findings: list[dict[str, Any]] = []
        findings_by_agent: dict[str, list[dict[str, Any]]] = {}

        try:
            if parallel:
                handles: dict[str, subprocess.Popen[Any]] = {}
                log_paths: dict[str, Path] = {}
                for spec in selected_specs:
                    rendered = self._render_prompt(spec)
                    timestamp = _trace_timestamp()
                    log_path = self.agents_dir / f"agent_{_slug(spec.key, separator='_')}_{timestamp}.log"
                    log_paths[spec.key] = log_path
                    handles[spec.key] = self.spawn_agent(rendered, spec.key, log_path)

                # Poll agents and collect findings as they complete (not just at the end)
                # This ensures partial findings are saved on SIGTERM during the wait
                pending = dict(handles)
                completed: dict[str, tuple[str, int]] = {}
                deadline = time.monotonic() + max(1, int(self.agent_timeout))

                while pending:
                    if self._sigterm_received:
                        break

                    for agent_name, handle in list(pending.items()):
                        returncode = handle.poll()
                        if returncode is None:
                            continue
                        completed[agent_name] = (self._read_log_for_handle(handle), returncode)
                        self._cleanup_handle(handle)
                        pending.pop(agent_name, None)

                        # Collect findings immediately when each agent finishes
                        spec = next((s for s in selected_specs if s.key == agent_name), None)
                        if spec is not None:
                            agent_findings = self._collect_agent_findings(spec, log_paths.get(agent_name))
                            findings_by_agent[agent_name] = agent_findings
                            raw_findings.extend(agent_findings)
                            self._partial_findings = list(raw_findings)
                            self.write_traces(
                                [
                                    {
                                        "event": "agent_complete",
                                        "agent_name": agent_name,
                                        "surface": spec.surface,
                                        "returncode": returncode,
                                        "finding_count": len(agent_findings),
                                    }
                                ]
                            )

                    if not pending:
                        break
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.2)

                # Handle timed-out agents
                for agent_name, handle in pending.items():
                    try:
                        handle.terminate()
                        handle.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        handle.kill()
                        handle.wait(timeout=5)
                    except OSError:
                        pass
                    completed[agent_name] = (self._read_log_for_handle(handle), -9)
                    self._cleanup_handle(handle)

                    spec = next((s for s in selected_specs if s.key == agent_name), None)
                    if spec is not None:
                        agent_findings = self._collect_agent_findings(spec, log_paths.get(agent_name))
                        findings_by_agent[agent_name] = agent_findings
                        raw_findings.extend(agent_findings)
                        self._partial_findings = list(raw_findings)
                        self.write_traces(
                            [
                                {
                                    "event": "timeout",
                                    "agent_name": agent_name,
                                    "surface": spec.surface,
                                    "pid": handle.pid,
                                    "timeout_seconds": int(self.agent_timeout),
                                    "finding_count": len(agent_findings),
                                }
                            ]
                        )
            else:
                for spec in selected_specs:
                    if self._sigterm_received:
                        break
                    rendered = self._render_prompt(spec)
                    timestamp = _trace_timestamp()
                    log_path = self.agents_dir / f"agent_{_slug(spec.key, separator='_')}_{timestamp}.log"
                    handle = self.spawn_agent(rendered, spec.key, log_path)
                    self.wait_for_agents({spec.key: handle}, timeout=self.agent_timeout)
                    agent_findings = self._collect_agent_findings(spec, log_path)
                    findings_by_agent[spec.key] = agent_findings
                    raw_findings.extend(agent_findings)
                    self._partial_findings = list(raw_findings)
                    self.write_traces(
                        [
                            {
                                "event": "agent_complete",
                                "agent_name": spec.key,
                                "surface": spec.surface,
                                "returncode": handle.returncode,
                                "finding_count": len(agent_findings),
                            }
                        ]
                    )

            self._partial_findings = list(raw_findings)
            new_findings = self.deduplicate_findings(raw_findings, ledger)
            confirmed, dormant, novel = self.stage2_review(new_findings, self.target_path)
            reviewed_findings = confirmed + dormant + novel
            ledger.setdefault("findings", []).extend(reviewed_findings)
            ledger.setdefault("coverage", {})["total_findings"] = len(ledger.get("findings") or [])
            self.save_ledger(ledger)

            for spec in selected_specs:
                self.update_coverage(
                    agent_name=spec.key,
                    surface=spec.surface,
                    finding_count=len(findings_by_agent.get(spec.key, [])),
                )

            self.write_traces(
                [
                    {
                        "event": "review_complete",
                        "confirmed": len(confirmed),
                        "dormant": len(dormant),
                        "novel": len(novel),
                        "review_error": self._last_review_error,
                    }
                ]
            )
            return confirmed, dormant, novel
        except SystemExit:
            raise
        except BaseException:
            self._persist_partial_results()
            raise
        finally:
            for handle in list(self._active_handles.values()):
                if handle.poll() is None:
                    try:
                        handle.terminate()
                    except OSError:
                        pass
                self._cleanup_handle(handle)
            self._active_handles.clear()

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
                _safe_int(normalized.get("line")),
                str(normalized.get("class_name") or ""),
                str(normalized.get("type") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            combined.append(normalized)
        return combined

    def _review_single_finding(self, finding: dict[str, Any], target_path: Path) -> dict[str, Any]:
        prompt = self._build_review_prompt(finding, target_path)
        review_data: dict[str, Any] | None = None
        errors: list[str] = []

        for cli_name in ("claude", "codex"):
            try:
                output = self._run_review_cli(cli_name, prompt, timeout=self.review_timeout)
                try:
                    review_data = _extract_json_object(output)
                except Exception as exc:
                    errors.append(f"{cli_name}: {exc}")
                    continue
                if not review_data:
                    errors.append(f"{cli_name}: empty review result")
                    review_data = None
                    continue
                break
            except Exception as exc:
                errors.append(f"{cli_name}: {exc}")

        if review_data is None:
            reviewed = dict(finding)
            reviewed["review_tier"] = "INCONCLUSIVE"
            reviewed["review_error"] = "; ".join(errors) if errors else "All review CLIs failed"
            return reviewed

        reviewed = dict(finding)
        tier = self._normalize_review_tier(review_data.get("tier") or review_data.get("review_tier"))
        reviewed["review_tier"] = tier
        reviewed["review_notes"] = str(review_data.get("review_notes") or "").strip()
        reviewed["blocked_reason"] = str(review_data.get("blocked_reason") or "").strip()
        reviewed["impact"] = str(review_data.get("impact") or "").strip()
        reviewed["remediation"] = str(review_data.get("remediation") or "").strip()
        reviewed["review_model"] = str(review_data.get("model") or "").strip()
        return reviewed

    def _run_review_cli(self, cli_name: str, prompt: str, timeout: int) -> str:
        if cli_name == "claude":
            command = ["claude", "--print", "--permission-mode", "bypassPermissions"]
        elif cli_name == "codex":
            command = [
                "codex",
                "exec",
                "-s",
                "danger-full-access",
                "--skip-git-repo-check",
                "-C",
                str(self.workdir),
            ]
        else:
            raise ValueError(f"unsupported review CLI {cli_name!r}")

        process = subprocess.Popen(
            command,
            cwd=str(self.workdir),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout_text, stderr_text = process.communicate(prompt, timeout=max(1, int(timeout)))
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.communicate(timeout=5)
            raise TimeoutError(f"{cli_name} review timed out") from exc
        if process.returncode != 0 and not (stdout_text or "").strip():
            raise RuntimeError(stderr_text.strip() or f"{cli_name} exited with {process.returncode}")
        return stdout_text.strip() or stderr_text.strip()

    def _build_review_prompt(self, finding: dict[str, Any], target_path: Path) -> str:
        source_path = self._resolve_source_path(finding.get("file"))
        excerpt = self._source_excerpt(source_path, _safe_int(finding.get("line"))) if source_path else "UNAVAILABLE"
        return f"""Review this single vulnerability-hunting finding.

Return only one JSON object. No markdown and no prose outside JSON.
Allowed tiers: CONFIRMED, DORMANT, NOVEL, INCONCLUSIVE.

JSON schema:
{{"tier":"CONFIRMED|DORMANT|NOVEL|INCONCLUSIVE","impact":"...","blocked_reason":"...","remediation":"...","review_notes":"...","model":"{{
optional
}}"}}

Target path: {target_path}
Resolved source path: {source_path or "UNRESOLVED"}

Finding:
{json.dumps(finding, indent=2, sort_keys=True)}

Source excerpt:
{excerpt}
"""

    def _normalize_review_tier(self, value: Any) -> str:
        tier = str(value or "").strip().upper().replace("-", "_")
        if tier in {"DORMANT_ACTIVE", "DORMANT_HYPOTHETICAL"}:
            tier = "DORMANT"
        if tier not in REVIEW_TIERS:
            return "INCONCLUSIVE"
        return tier

    def _read_findings_jsonl(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not self.findings_path.exists():
            return findings
        try:
            with self.findings_path.open("r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(payload, dict):
                        findings.append(payload)
        except OSError:
            return []
        return findings

    def _extract_findings_from_log(self, log_path: Path, default_agent: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not log_path.exists():
            return findings
        try:
            with log_path.open("r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    normalized = self._normalize_finding(payload, default_agent=default_agent)
                    if normalized is not None:
                        findings.append(normalized)
        except OSError:
            return []
        return findings

    def _normalize_finding(
        self,
        raw: Any,
        *,
        default_agent: str = "unknown",
        default_class: str = "unknown",
    ) -> dict[str, Any] | None:
        if not isinstance(raw, dict):
            return None
        file_path = _normalize_relpath(raw.get("file"))
        if not file_path:
            return None

        category = str(raw.get("category") or "class").strip().lower()
        if category not in {"class", "novel"}:
            category = "class"

        class_name = str(raw.get("class_name") or raw.get("vuln_class") or default_class).strip().lower()
        if not class_name:
            class_name = default_class

        finding_type = str(raw.get("type") or raw.get("title") or "").strip()
        if not finding_type:
            return None

        return {
            "agent": str(raw.get("agent") or default_agent).strip() or default_agent,
            "category": category,
            "class_name": class_name,
            "type": finding_type,
            "file": file_path,
            "line": _safe_int(raw.get("line")),
            "description": str(raw.get("description") or "").strip(),
            "severity": str(raw.get("severity") or "UNKNOWN").strip().upper() or "UNKNOWN",
            "context": str(raw.get("context") or "").strip(),
            "source": str(raw.get("source") or "").strip(),
            "trust_boundary": str(raw.get("trust_boundary") or "").strip(),
            "flow_path": str(raw.get("flow_path") or "").strip(),
            "sink": str(raw.get("sink") or "").strip(),
            "exploitability": str(raw.get("exploitability") or "").strip(),
        }

    def _finding_identity(self, finding: dict[str, Any]) -> tuple[str, int, str, str]:
        return (
            _normalize_relpath(finding.get("file")),
            _safe_int(finding.get("line")),
            str(finding.get("class_name") or "").strip().lower(),
            str(finding.get("type") or "").strip().lower(),
        )

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

    def _persist_partial_results(self) -> None:
        if not self._partial_findings:
            return
        try:
            ledger = self.load_ledger()
            new_findings = self.deduplicate_findings(list(self._partial_findings), ledger)
            for finding in new_findings:
                finding.setdefault("review_tier", "INCONCLUSIVE")
            ledger.setdefault("findings", []).extend(new_findings)
            ledger.setdefault("coverage", {})["total_findings"] = len(ledger.get("findings") or [])
            self.save_ledger(ledger)
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
        if self._signal_handlers_installed:
            return

        def _handle_sigterm(signum: int, _frame: Any) -> None:
            self._sigterm_received = True
            self.write_traces([{"event": "signal", "signal": signum}])
            self._persist_partial_results()
            raise SystemExit(143)

        signal.signal(signal.SIGTERM, _handle_sigterm)
        self._signal_handlers_installed = True

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
        default=str(Path("~/Shared/bounty_recon").expanduser()),
        help="Output root. Default: ~/Shared/bounty_recon",
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
    output_root = Path(args.output_root).expanduser()

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
