"""Thin Bug Bounty Harness adapter for the standalone Hunter Memory Loop.

The core learning-loop package intentionally lives outside this repo. This
adapter keeps Bug Bounty Harness integration narrow: create per-agent memory
scaffolds, inject compact instructions, and harvest structured attempt rows
from read-only agent logs.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

DEFAULT_CORE_ROOT = Path.home() / "projects" / "hunter-memory-loop"
DEFAULT_MEMORY_ROOT = Path.home() / "Shared" / "bounty_recon"
ATTEMPT_FENCE_RE = re.compile(
    r"```(?:hunter-memory-attempts|hunter_memory_attempts)\s*(.*?)```",
    re.DOTALL | re.IGNORECASE,
)
CLAIM_FENCE_RE = re.compile(
    r"```(?:hunter-memory-claims|hunter_memory_claims)\s*(.*?)```",
    re.DOTALL | re.IGNORECASE,
)
MAX_FIELD_CHARS = 2000
MAX_ROWS_PER_AGENT = 100
SENSITIVE_PATTERNS = (
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(cookie|authorization|x-api-key|api[_-]?key|token|secret|password)\s*[:=]\s*[^,\s;]+"),
    re.compile(r"(?i)\b(sessionid|sid|jwt|access[_-]?token|refresh[_-]?token)=([^;\s]+)"),
)


@dataclass(frozen=True)
class HunterMemoryRef:
    """Parent-owned pointer to one agent's hunter-memory storage."""

    enabled: bool
    run_path: Path | None = None
    agent_path: Path | None = None
    agent_key: str = ""
    prompt: str = ""
    unavailable_reason: str = ""


def build_hunter_memory_ref(
    *,
    program: str,
    agent_key: str,
    vulnerability: str,
    surface: str,
    goal: str,
    target: str | Path | None = None,
    provider: str = "codex",
    root: str | Path | None = None,
) -> HunterMemoryRef:
    """Create a memory run/agent and return prompt text for a child agent."""

    try:
        _ensure_core_importable()
        from hunter_memory import HunterMemory
        from hunter_memory.prompts import learning_loop_prompt

        memory = HunterMemory(root or DEFAULT_MEMORY_ROOT)
        run = memory.create_run(
            program=program,
            vulnerability=vulnerability or "general",
            surface=surface or agent_key,
            goal=goal,
            target=str(target) if target is not None else None,
        )
        agent = run.create_agent(agent_key, provider=provider)
        prompt = _render_prompt(learning_loop_prompt(str(agent.path)), agent.path)
        return HunterMemoryRef(
            enabled=True,
            run_path=run.path,
            agent_path=agent.path,
            agent_key=agent_key,
            prompt=prompt,
        )
    except Exception as exc:  # pragma: no cover - defensive best-effort boundary
        return HunterMemoryRef(enabled=False, agent_key=agent_key, unavailable_reason=str(exc))


def harvest_hunter_memory_from_log(log_path: Path, ref: HunterMemoryRef | None) -> dict[str, Any]:
    """Append structured attempt/claim rows emitted by an agent log."""

    if ref is None or not ref.enabled or ref.agent_path is None:
        return {"enabled": False, "attempts": 0, "claims": 0, "errors": []}
    if not log_path.exists():
        return {"enabled": True, "attempts": 0, "claims": 0, "errors": [f"log missing: {log_path}"]}

    try:
        _ensure_core_importable()
        from hunter_memory.cli import _run_from_path

        run = _run_from_path(ref.run_path, "codex") if ref.run_path is not None else None
        agent = run.create_agent(ref.agent_key, "codex") if run is not None else None
    except Exception as exc:
        return {"enabled": True, "attempts": 0, "claims": 0, "errors": [f"core load failed: {exc}"]}

    text = log_path.read_text(encoding="utf-8", errors="replace")
    attempts = _parse_fenced_jsonl(text, ATTEMPT_FENCE_RE)
    claims = _parse_fenced_jsonl(text, CLAIM_FENCE_RE)
    errors: list[str] = []
    written_attempts = 0
    written_claims = 0

    for row in attempts[:MAX_ROWS_PER_AGENT]:
        if not isinstance(row, dict):
            continue
        try:
            agent.append_attempt(
                goal=_clean_field(row.get("goal")),
                action=_clean_field(row.get("action")),
                result=_clean_field(row.get("result")),
                observation=_clean_field(row.get("observation")),
                interpretation=_clean_field(row.get("interpretation")),
                learning=_clean_field(row.get("learning")),
                next_action=_clean_field(row.get("next_action")),
                evidence_refs=_clean_list(row.get("evidence_refs")),
            )
            written_attempts += 1
        except Exception as exc:
            errors.append(f"attempt row skipped: {exc}")

    if ref.run_path is not None and claims:
        try:
            run = _run_from_path(ref.run_path, "codex")
            for row in claims[:MAX_ROWS_PER_AGENT]:
                if not isinstance(row, dict):
                    continue
                run.append_claim(
                    agent_id=ref.agent_key,
                    claim=_clean_field(row.get("claim")),
                    status=_clean_field(row.get("status") or "in_progress"),
                    confidence=_clean_field(row.get("confidence") or "medium"),
                )
                written_claims += 1
        except Exception as exc:
            errors.append(f"claim rows skipped: {exc}")

    return {"enabled": True, "attempts": written_attempts, "claims": written_claims, "errors": errors}


def _ensure_core_importable() -> None:
    core_root = Path(os.environ.get("HUNTER_MEMORY_LOOP_ROOT") or DEFAULT_CORE_ROOT).expanduser()
    if core_root.as_posix() not in sys.path:
        sys.path.insert(0, core_root.as_posix())


def _render_prompt(base_prompt: str, agent_path: Path) -> str:
    return f"""{base_prompt.rstrip()}

Because this BBH child agent may run in a read-only subprocess, also emit a
structured harvest block in your final log output. The parent orchestrator will
append these rows to:
{agent_path}

Use this exact fenced JSONL block for meaningful attempts:
```hunter-memory-attempts
{{"goal":"what you were trying to learn","action":"what you tried","result":"success|failed|blocked|inconclusive","observation":"what happened","interpretation":"what it probably means","learning":"constraint or behavior learned","next_action":"what should change next","evidence_refs":[]}}
```

Optional claim block when you learned a reusable conclusion:
```hunter-memory-claims
{{"claim":"short reusable conclusion","status":"confirmed|in_progress|rejected","confidence":"low|medium|high"}}
```

Keep rows concise. Do not include raw cookies, tokens, API keys, credentials,
private headers, or secret material.
""".rstrip()


def _parse_fenced_jsonl(text: str, pattern: re.Pattern[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for match in pattern.finditer(text):
        block = match.group(1)
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def _clean_field(value: Any) -> str:
    text = str(value or "").replace("\x00", "").strip()
    for pattern in SENSITIVE_PATTERNS:
        text = pattern.sub(lambda match: f"{match.group(1) if match.groups() else 'secret'}=[REDACTED]", text)
    if len(text) > MAX_FIELD_CHARS:
        text = text[:MAX_FIELD_CHARS].rstrip() + " [truncated]"
    return text


def _clean_list(value: Any) -> list[str]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, dict)):
        return []
    cleaned: list[str] = []
    for item in list(value)[:50]:
        text = _clean_field(item)
        if text:
            cleaned.append(text)
    return cleaned
