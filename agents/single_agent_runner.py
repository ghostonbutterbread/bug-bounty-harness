#!/usr/bin/env python3
"""Run one focused BaseTeam-backed hunting agent."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.base_team import AgentSpec, BaseTeam  # noqa: E402
from agents.hunting_policy import resolve_policy_selection  # noqa: E402


DEFAULT_TEAM_TYPE = "0day_team"
DEFAULT_FAMILY = "binaries"
DEFAULT_LANE = "exe"
DEFAULT_TARGET_KIND = "exe"
DEFAULT_AGENT_KEY = "single-focused-agent"
DEFAULT_VULN_CLASS = "goal-focused"
DEFAULT_SURFACE = "targeted-surface"
MAX_CONTEXT_CHARS = 12_000


@dataclass(frozen=True, slots=True)
class ContextExcerpt:
    label: str
    path: Path
    text: str
    truncated: bool = False
    missing: bool = False

    def render(self) -> str:
        if self.missing:
            return f"### {self.label}: {self.path}\nMISSING: context file was not available.\n"
        suffix = "\n[truncated]\n" if self.truncated else "\n"
        return f"### {self.label}: {self.path}\n```text\n{self.text.rstrip()}{suffix}```\n"


def _timestamp_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip().lower()).strip("-")
    return cleaned or "single-focused-agent"


def _read_text_excerpt(path: Path, *, max_chars: int = MAX_CONTEXT_CHARS) -> tuple[str, bool]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        text = handle.read(max_chars + 1)
    if len(text) > max_chars:
        return text[:max_chars], True
    return text, False


def _format_literal(value: str) -> str:
    """Escape injected user/context text before BaseTeam .format() renders paths."""
    return str(value).replace("{", "{{").replace("}", "}}")


def load_context_excerpts(
    context_files: Sequence[str | Path],
    *,
    allow_missing: bool = False,
    label: str = "context",
) -> list[ContextExcerpt]:
    excerpts: list[ContextExcerpt] = []
    for index, raw_path in enumerate(context_files, start=1):
        path = Path(raw_path).expanduser().resolve(strict=False)
        item_label = f"{label}-{index}"
        if not path.exists():
            if allow_missing:
                excerpts.append(ContextExcerpt(item_label, path, "", missing=True))
                continue
            raise FileNotFoundError(f"context file does not exist: {path}")
        if not path.is_file():
            raise ValueError(f"context path is not a file: {path}")
        text, truncated = _read_text_excerpt(path)
        excerpts.append(ContextExcerpt(item_label, path, text, truncated=truncated))
    return excerpts


def build_goal(goal: str | None, goal_file: str | Path | None) -> str:
    parts: list[str] = []
    if goal:
        parts.append(str(goal).strip())
    if goal_file:
        path = Path(goal_file).expanduser().resolve(strict=False)
        if not path.exists():
            raise FileNotFoundError(f"goal file does not exist: {path}")
        if not path.is_file():
            raise ValueError(f"goal path is not a file: {path}")
        text, truncated = _read_text_excerpt(path)
        header = f"Goal file: {path}"
        if truncated:
            header += " (truncated)"
        parts.append(f"{header}\n{text.strip()}")
    combined = "\n\n".join(part for part in parts if part).strip()
    if not combined:
        raise ValueError("goal is required; provide --goal or --goal-file")
    return combined


class SingleAgentTeam(BaseTeam):
    """A one-agent BaseTeam subclass for sequential dynamic or desktop work."""

    def __init__(
        self,
        program: str,
        target_path: Path,
        goal: str,
        *,
        agent_key: str = DEFAULT_AGENT_KEY,
        vuln_class: str = DEFAULT_VULN_CLASS,
        surface: str = DEFAULT_SURFACE,
        context_excerpts: Sequence[ContextExcerpt] | None = None,
        hypothesis_id: str | None = None,
        brainstorm_spec: str | Path | None = None,
        output_root: Path | None = None,
        family: str = DEFAULT_FAMILY,
        lane: str = DEFAULT_LANE,
        target_kind: str = DEFAULT_TARGET_KIND,
        team_type: str = DEFAULT_TEAM_TYPE,
        hunting_policy: str | None = "off",
        policy_config: str | Path | None = None,
        fresh: bool = False,
    ) -> None:
        self.goal = str(goal).strip()
        self.agent_key = _slug(agent_key)
        self.vuln_class = str(vuln_class or DEFAULT_VULN_CLASS).strip() or DEFAULT_VULN_CLASS
        self.surface = str(surface or DEFAULT_SURFACE).strip() or DEFAULT_SURFACE
        self.context_excerpts = list(context_excerpts or [])
        self.hypothesis_id = str(hypothesis_id or "").strip()
        self.brainstorm_spec = str(brainstorm_spec or "").strip()
        self.fresh = bool(fresh)

        super().__init__(
            program=program,
            team_type=team_type,
            target_path=target_path,
            output_root=output_root,
            max_agents=1,
            family=family,
            lane=lane,
            target_kind=target_kind,
            intent_text=self.goal,
            hunting_policy=hunting_policy,
            policy_config=policy_config,
        )

    def get_static_profiles(self) -> list[AgentSpec]:
        snapshot_id = self._snapshot_id() or "unspecified"
        return [
            AgentSpec(
                key=self.agent_key,
                vuln_class=self.vuln_class,
                surface=self.surface,
                prompt_template=self._single_agent_prompt_template(),
                focus_globs=["**/*"],
                code_patterns=[],
                program=self.program,
                created_at=_timestamp_iso(),
                snapshot_id=snapshot_id,
            )
        ]

    def generate_dynamic_from_surfaces(
        self,
        surfaces: Sequence[dict[str, Any]],
        *,
        snapshot_id: str,
    ) -> list[AgentSpec]:
        return []

    def render_single_prompt(self) -> str:
        specs = self.get_static_profiles()
        if len(specs) != 1:
            raise RuntimeError(f"SingleAgentTeam expected one profile, got {len(specs)}")
        return self._render_prompt(specs[0])

    def _extract_findings_from_log(self, log_path: Path, default_agent: str) -> list[dict[str, Any]]:
        findings = super()._extract_findings_from_log(log_path, default_agent)
        if not log_path.exists():
            return findings
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        for match in re.finditer(r"```(?:json)?\s*(?P<payload>[\[{].*?[\]}])\s*```", text, re.DOTALL):
            try:
                payload = json.loads(match.group("payload"))
            except json.JSONDecodeError:
                continue
            candidates = payload if isinstance(payload, list) else [payload]
            for candidate in candidates:
                normalized = self._normalize_finding(
                    candidate,
                    default_agent=default_agent,
                    default_class=self.vuln_class,
                )
                if normalized is not None:
                    findings.append(normalized)
        return findings

    def _single_agent_prompt_template(self) -> str:
        context_block = _format_literal(self._context_block())
        hypothesis_block = _format_literal(self._hypothesis_block())
        goal = _format_literal(self.goal)
        fresh_line = "- Treat prior coverage as advisory only; start from the supplied goal and current target state." if self.fresh else "- Use prior ledger and coverage as coordination inputs before adding findings."
        return f"""You are the only active Bug Bounty Harness agent for this run.

Program: {{program}}
Team type: {{team_type}}
Family/lane: {{family}}/{{lane}}
Target path: {{target_path}}
Snapshot id: {{snapshot_id}}
Agent key: {{agent_key}}
Vulnerability class: {{vuln_class}}
Surface: {{surface}}

Storage and coordination paths:
- Findings JSONL: {{findings_path}}
- Ledger: {{ledger_path}}
- Shared brain index: {{shared_brain_index}}
- Agent registry: {{agent_registry_dir}}
- Reports root: {{reports_root}}
- Raw reports: {{reports_raw_root}}
- Confirmed reports: {{reports_confirmed_root}}
- Dormant reports: {{reports_dormant_root}}
- Novel reports: {{reports_novel_root}}
- Context root: {{context_root}}
- Notes root: {{notes_root}}
- Traces root: {{traces_dir}}

Goal:
{goal}

Operational constraints:
- Run as one focused agent only. Do not ask for or start parallel subagents.
- Respect single-resource sequencing for VM, desktop, dynamic instrumentation, and Ghidra work; assume only one Ghidra instance is available.
- Use the injected ledger, report, notes, and trace paths for coordination and evidence.
- Check existing ledger/coverage before treating a result as new.
- Do not fabricate findings. If there is no concrete issue, exit with concise notes and no finding JSON.
- For Canva or other live testing, do not publish, spam, purchase, send invites or messages, perform mass actions, or mutate vendor/customer data.
{fresh_line}

Finding output contract:
- When you find an issue, print a JSON fenced object/array or raw one-line JSON object that BaseTeam can extract.
- Include these fields where possible: title, type, severity, file, line, class_name, description, evidence, repro_steps, recommendation.
- Also include agent="{self.agent_key}", category="class" or "novel", and class_name="{self.vuln_class}" unless a more exact class is justified.
- Prefer one well-supported finding over speculative lists.

Focus globs:
{{focus_globs}}

Relevant code patterns:
{{code_patterns}}

{hypothesis_block}
Additional context:
{context_block}

Hunting policy:
{{hunting_policy_snippet}}
"""

    def _context_block(self) -> str:
        if not self.context_excerpts:
            return "- None provided."
        return "\n".join(excerpt.render().rstrip() for excerpt in self.context_excerpts)

    def _hypothesis_block(self) -> str:
        lines: list[str] = []
        if self.hypothesis_id:
            lines.append(f"- Hypothesis id: {self.hypothesis_id}")
        if self.brainstorm_spec:
            lines.append(f"- Brainstorm spec: {self.brainstorm_spec}")
        if not lines:
            return "Hypothesis references:\n- None provided.\n"
        return "Hypothesis references:\n" + "\n".join(lines) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one focused BaseTeam-backed Bug Bounty Harness agent.")
    parser.add_argument("program", help="Bug bounty program name.")
    parser.add_argument("--target", required=True, help="Target root, binary, extracted app, or workspace path.")
    parser.add_argument("--goal", help="Focused objective for the single agent.")
    parser.add_argument("--goal-file", help="Read additional or replacement goal text from a file.")
    parser.add_argument("--agent-key", default=DEFAULT_AGENT_KEY, help="Stable key/name for the single agent.")
    parser.add_argument("--vuln-class", default=DEFAULT_VULN_CLASS, help="Default vulnerability class for emitted findings.")
    parser.add_argument("--surface", default=DEFAULT_SURFACE, help="Coverage surface label for this run.")
    parser.add_argument("--context-file", action="append", default=[], help="Additional context file to excerpt into the prompt. Repeatable.")
    parser.add_argument("--appmap-context", action="append", default=[], dest="appmap_context", help="Alias for --context-file for AppMap artifacts. Repeatable.")
    parser.add_argument("--allow-missing-context", action="store_true", help="Include missing context-file references as notes instead of failing.")
    parser.add_argument("--hypothesis-id", help="Optional AppMap or brainstorm hypothesis id.")
    parser.add_argument("--brainstorm-spec", help="Optional brainstorm spec path or reference.")
    parser.add_argument("--output-dir", help="Optional explicit canonical storage root.")
    parser.add_argument("--timeout", type=int, default=None, help="Single-agent timeout in seconds.")
    parser.add_argument("--fresh", action="store_true", help="Tell the agent to start fresh while still using storage paths.")
    parser.add_argument("--family", default=DEFAULT_FAMILY, help=f"Storage family. Default: {DEFAULT_FAMILY}.")
    parser.add_argument("--lane", default=DEFAULT_LANE, help=f"Storage lane. Default: {DEFAULT_LANE}.")
    parser.add_argument("--target-kind", default=DEFAULT_TARGET_KIND, help=f"Target kind hint. Default: {DEFAULT_TARGET_KIND}.")
    parser.add_argument("--hunting-policy", default="off", help="Hunting policy id: off, auto, or a configured policy id. Default: off.")
    parser.add_argument("--policy-config", help="Optional JSON hunting policy config override.")
    parser.add_argument("--dry-run-prompt", action="store_true", help="Print the rendered prompt without spawning Codex or mutating the ledger.")
    return parser.parse_args(list(argv) if argv is not None else None)


def build_team_from_args(args: argparse.Namespace) -> SingleAgentTeam:
    context_paths = list(args.context_file or []) + list(args.appmap_context or [])
    context_excerpts = load_context_excerpts(
        context_paths,
        allow_missing=bool(args.allow_missing_context),
        label="context",
    )

    brainstorm_spec = str(args.brainstorm_spec or "").strip()
    if brainstorm_spec:
        spec_path = Path(brainstorm_spec).expanduser().resolve(strict=False)
        if spec_path.exists() and spec_path.is_file():
            context_excerpts.extend(
                load_context_excerpts([spec_path], allow_missing=False, label="brainstorm-spec")
            )
            brainstorm_spec = str(spec_path)
        elif Path(brainstorm_spec).suffix:
            if args.allow_missing_context:
                context_excerpts.append(ContextExcerpt("brainstorm-spec-1", spec_path, "", missing=True))
            else:
                raise FileNotFoundError(f"brainstorm spec file does not exist: {spec_path}")

    goal = build_goal(args.goal, args.goal_file)
    policy_selection = resolve_policy_selection(args.hunting_policy)
    team = SingleAgentTeam(
        program=args.program,
        target_path=Path(args.target).expanduser(),
        goal=goal,
        agent_key=args.agent_key,
        vuln_class=args.vuln_class,
        surface=args.surface,
        context_excerpts=context_excerpts,
        hypothesis_id=args.hypothesis_id,
        brainstorm_spec=brainstorm_spec,
        output_root=Path(args.output_dir).expanduser() if args.output_dir else None,
        family=args.family,
        lane=args.lane,
        target_kind=args.target_kind,
        hunting_policy=policy_selection,
        policy_config=args.policy_config,
        fresh=bool(args.fresh),
    )
    if args.timeout is not None:
        team.agent_timeout = max(1, int(args.timeout))
    return team


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    team = build_team_from_args(args)

    if args.dry_run_prompt:
        print(team.render_single_prompt(), end="")
        return 0

    confirmed, dormant, novel = team.orchestrate(parallel=False, agents_mode="static")
    output: dict[str, Any] = {
        "program": team.program,
        "team_type": team.team_type,
        "agent_key": team.agent_key,
        "family": team.family,
        "lane": team.lane,
        "confirmed": len(confirmed),
        "dormant": len(dormant),
        "novel": len(novel),
        "ledger_path": str(team.ledger_path),
        "findings_path": str(team.findings_path),
    }
    if team.hunting_policy.enabled:
        output["hunting_policy"] = team.hunting_policy.to_dict()
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
