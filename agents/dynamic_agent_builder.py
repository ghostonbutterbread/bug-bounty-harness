"""Dynamic agent generation and persistence for zero_day_team."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import math
import re
import sys
import time
from pathlib import Path
from typing import Any, Iterable

_AGENT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _AGENT_DIR.parent
if _PROJECT_ROOT.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _PROJECT_ROOT.as_posix())
_BOUNTY_TOOLS_ROOT = Path.home() / "projects" / "bounty-tools"
if _BOUNTY_TOOLS_ROOT.as_posix() not in (p.as_posix() for p in map(Path, sys.path)):
    sys.path.insert(0, _BOUNTY_TOOLS_ROOT.as_posix())

from agents.snapshot_identity import get_snapshot_identity

try:
    from subagent_logger import SubagentLogger, compute_pte_lite
except ImportError:  # pragma: no cover
    SubagentLogger = None

    def compute_pte_lite(**kwargs: Any) -> int:
        return (
            int(kwargs.get("prompt_tokens") or 0)
            + int(kwargs.get("completion_tokens") or 0)
            + int(kwargs.get("tool_output_tokens") or 0)
        )


def _timestamp_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sanitize_program_name(program: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(program or "").strip())
    return cleaned or "default_program"


def _estimate_tokens_from_text(text: str | bytes | None) -> int:
    if text is None:
        return 0
    if isinstance(text, bytes):
        size = len(text)
    else:
        size = len(str(text).encode("utf-8", errors="replace"))
    return max(0, math.ceil(size / 4))


def _safe_log_span(logger: SubagentLogger | None, **fields: Any) -> None:
    if logger is None:
        return
    try:
        logger.log_span(**fields)
    except Exception:
        pass


def _version_token(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    return cleaned or "unversioned"


def _key_token(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip().lower())
    return cleaned.strip("-") or "dynamic-agent"


@dataclass
class AgentSpec:
    key: str
    name: str
    description: str
    surface_type: str
    vuln_class: str
    patterns: list[str]
    focus_files_glob: list[str]
    ignore_files_glob: list[str]
    agent_prompt_template: str
    parent_keys: list[str]
    created_by: str
    version: str
    created_at: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AgentSpec":
        return cls(
            key=str(payload.get("key", "")).strip(),
            name=str(payload.get("name", "")).strip(),
            description=str(payload.get("description", "")).strip(),
            surface_type=str(payload.get("surface_type", "")).strip(),
            vuln_class=str(payload.get("vuln_class", "")).strip(),
            patterns=[str(item).strip() for item in (payload.get("patterns") or []) if str(item).strip()],
            focus_files_glob=[
                str(item).strip() for item in (payload.get("focus_files_glob") or []) if str(item).strip()
            ],
            ignore_files_glob=[
                str(item).strip() for item in (payload.get("ignore_files_glob") or []) if str(item).strip()
            ],
            agent_prompt_template=str(payload.get("agent_prompt_template", "")).rstrip(),
            parent_keys=[str(item).strip() for item in (payload.get("parent_keys") or []) if str(item).strip()],
            created_by=str(payload.get("created_by", "")).strip() or "brainstorm",
            version=str(payload.get("version", "")).strip(),
            created_at=str(payload.get("created_at", "")).strip() or _timestamp_iso(),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AgentRegistry:
    """Persistent program-local registry for dynamic agent specifications."""

    def __init__(self, program: str):
        self.program = _sanitize_program_name(program)
        self.reg_dir = (
            Path.home()
            / "Shared"
            / "bounty_recon"
            / self.program
            / "ghost"
            / "agent_registry"
        )

    def _ensure_dir(self) -> None:
        self.reg_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, key: str, version: str) -> Path:
        return self.reg_dir / f"{_key_token(key)}__{_version_token(version)}.json"

    def save(self, spec: AgentSpec) -> None:
        self._ensure_dir()
        path = self._path_for(spec.key, spec.version)
        path.write_text(json.dumps(spec.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def load(self, key: str, version: str | None = None) -> AgentSpec | None:
        candidates = [
            spec
            for spec in self.list_all()
            if spec.key == str(key or "").strip() and (version is None or spec.version == str(version).strip())
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda item: (item.version, item.created_at, item.key))
        return candidates[-1]

    def list_all(self) -> list[AgentSpec]:
        self._ensure_dir()
        specs: list[AgentSpec] = []
        for path in sorted(self.reg_dir.glob("*.json")):
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
        specs.sort(key=lambda item: (item.version, item.key, item.created_at))
        return specs

    def list_for_version(self, app_version: str) -> list[AgentSpec]:
        version = str(app_version or "").strip()
        return [spec for spec in self.list_all() if spec.version == version]

    def needs_refresh(self, app_version: str, force_refresh: bool = False) -> bool:
        if force_refresh:
            return True
        return not bool(self.list_for_version(app_version))


class DynamicAgentBuilder:
    """Generate and cache application-specific agent specs."""

    def __init__(self, program: str, logger: SubagentLogger | None = None):
        self.program = _sanitize_program_name(program)
        self.registry = AgentRegistry(self.program)
        self.logger = logger
        self._owns_logger = False
        if self.logger is None and SubagentLogger is not None:
            try:
                self.logger = SubagentLogger(
                    "dynamic_agent_builder",
                    self.program,
                    f"dab_{int(time.time())}",
                )
                self._owns_logger = True
            except Exception:
                self.logger = None

    def run(
        self,
        target_path: str | Path,
        program_slug: str | None = None,
        force_refresh: bool = False,
        app_version: str | None = None,
    ) -> list[AgentSpec]:
        if program_slug:
            normalized = _sanitize_program_name(program_slug)
            if normalized != self.program:
                self.program = normalized
                self.registry = AgentRegistry(self.program)
        resolved_target = Path(target_path).expanduser().resolve()
        version = self._resolve_app_version(resolved_target, app_version=app_version)
        success = False

        if self._owns_logger and self.logger is not None:
            try:
                self.logger.start(target=str(resolved_target), mode="brainstorm")
            except Exception:
                pass

        try:
            if not self.registry.needs_refresh(version, force_refresh=force_refresh):
                cached = self.registry.list_for_version(version)
                self._log_registry_result(
                    message=f"Reused {len(cached)} dynamic agent spec(s)",
                    target=resolved_target,
                    version=version,
                    generated=False,
                    specs=cached,
                )
                return cached

            started = time.time()
            from agents.brainstorm import brainstorm_agent_specs

            specs = brainstorm_agent_specs(
                target_path=resolved_target,
                tech_stack=None,
                app_version=version,
                program_slug=self.program,
                logger=self.logger,
            )
            unique_specs = self._dedupe_specs(specs)
            for spec in unique_specs:
                self.registry.save(spec)
            self._log_registry_result(
                message=f"Generated {len(unique_specs)} dynamic agent spec(s)",
                target=resolved_target,
                version=version,
                generated=True,
                specs=unique_specs,
                started=started,
            )
            success = True
            return unique_specs
        finally:
            if self._owns_logger and self.logger is not None:
                try:
                    self.logger.finish(success=success)
                except Exception:
                    pass

    def _resolve_app_version(self, target_path: Path, app_version: str | None) -> str:
        explicit = str(app_version or "").strip()
        if explicit:
            return explicit
        snapshot = get_snapshot_identity(target_path)
        return (
            str(snapshot.get("version_label") or "").strip()
            or str(snapshot.get("git_head") or "").strip()
            or str(snapshot.get("manifest_hash") or "").strip()
            or "unversioned"
        )

    def _dedupe_specs(self, specs: Iterable[AgentSpec]) -> list[AgentSpec]:
        chosen: dict[str, AgentSpec] = {}
        for spec in specs:
            if not spec.key:
                continue
            chosen[spec.key] = spec
        return [chosen[key] for key in sorted(chosen)]

    def _log_registry_result(
        self,
        *,
        message: str,
        target: Path,
        version: str,
        generated: bool,
        specs: list[AgentSpec],
        started: float | None = None,
    ) -> None:
        payload = json.dumps(
            {
                "target": str(target),
                "version": version,
                "generated": generated,
                "keys": [spec.key for spec in specs],
            },
            sort_keys=True,
        )
        prompt_tokens = _estimate_tokens_from_text(payload)
        completion_tokens = 0
        tool_output_tokens = _estimate_tokens_from_text("\n".join(spec.key for spec in specs))
        context_tokens_after = prompt_tokens + completion_tokens
        _safe_log_span(
            self.logger,
            span_type="tool",
            phase="preflight",
            level="RESULT",
            message=message,
            tool_name="agent_registry",
            tool_category="dynamic_agents",
            target=str(target),
            params={"version": version, "generated": generated},
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            tool_output_tokens=tool_output_tokens,
            context_tokens_before=prompt_tokens,
            context_tokens_after=context_tokens_after,
            pte_lite=compute_pte_lite(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                tool_output_tokens=tool_output_tokens,
                context_tokens_after=context_tokens_after,
            ),
            latency_ms=0 if started is None else int((time.time() - started) * 1000),
            input_bytes=len(payload.encode("utf-8", errors="replace")),
            output_bytes=len("\n".join(spec.key for spec in specs).encode("utf-8", errors="replace")),
            success=True,
        )
