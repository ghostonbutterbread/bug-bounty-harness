from __future__ import annotations

import sys
from pathlib import Path

import pytest

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents import single_agent_runner as runner  # noqa: E402


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.asar").write_text("placeholder\n", encoding="utf-8")
    return target


def test_single_agent_profile_and_prompt_include_goal_storage_safety_context_and_refs(tmp_path: Path) -> None:
    target = _target(tmp_path)
    context_file = tmp_path / "appmap.md"
    context_file.write_text("AppMap context: renderer route reaches import flow.\n", encoding="utf-8")
    brainstorm = tmp_path / "brainstorm.md"
    brainstorm.write_text("Hypothesis H-7: validate parser boundary.\n", encoding="utf-8")
    excerpts = runner.load_context_excerpts([context_file])
    excerpts.extend(runner.load_context_excerpts([brainstorm], label="brainstorm-spec"))

    team = runner.SingleAgentTeam(
        program="Canva Desktop",
        target_path=target,
        goal="Validate the file import parser boundary.",
        agent_key="ghidra-parser",
        vuln_class="memory-unsafe-parser",
        surface="desktop-import",
        context_excerpts=excerpts,
        hypothesis_id="H-7",
        brainstorm_spec=brainstorm,
        output_root=tmp_path / "storage",
        hunting_policy="off",
    )

    specs = team.get_static_profiles()
    prompt = team.render_single_prompt()

    assert len(specs) == 1
    assert specs[0].key == "ghidra-parser"
    assert "Validate the file import parser boundary." in prompt
    assert str(team.ledger_path) in prompt
    assert str(team.findings_path) in prompt
    assert "Respect single-resource sequencing" in prompt
    assert "only one Ghidra instance is available" in prompt
    assert "do not publish, spam, purchase" in prompt
    assert "AppMap context: renderer route reaches import flow." in prompt
    assert "Hypothesis id: H-7" in prompt
    assert f"Brainstorm spec: {brainstorm}" in prompt


def test_missing_context_rejects_by_default_and_can_be_allowed(tmp_path: Path) -> None:
    missing = tmp_path / "missing.md"

    with pytest.raises(FileNotFoundError):
        runner.load_context_excerpts([missing])

    excerpts = runner.load_context_excerpts([missing], allow_missing=True)

    assert len(excerpts) == 1
    assert excerpts[0].missing is True
    assert "MISSING: context file was not available" in excerpts[0].render()


def test_goal_file_is_combined_with_inline_goal(tmp_path: Path) -> None:
    goal_file = tmp_path / "goal.md"
    goal_file.write_text("Trace native image decoding.\n", encoding="utf-8")

    goal = runner.build_goal("Start from drag-and-drop import.", goal_file)

    assert "Start from drag-and-drop import." in goal
    assert "Trace native image decoding." in goal
    assert str(goal_file) in goal


def test_cli_dry_run_prints_prompt_without_spawning_or_writing_ledger(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = _target(tmp_path)
    context_file = tmp_path / "context.md"
    context_file.write_text("Context from AppMap lane.\n", encoding="utf-8")
    output_root = tmp_path / "storage"

    rc = runner.main(
        [
            "Canva Desktop",
            "--target",
            str(target),
            "--goal",
            "Inspect desktop auth redirect handling.",
            "--context-file",
            str(context_file),
            "--hypothesis-id",
            "AUTH-1",
            "--output-dir",
            str(output_root),
            "--hunting-policy",
            "off",
            "--dry-run-prompt",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 0
    assert "Inspect desktop auth redirect handling." in captured.out
    assert "Context from AppMap lane." in captured.out
    assert "Hypothesis id: AUTH-1" in captured.out
    assert "Findings JSONL:" in captured.out
    assert not list(output_root.rglob("findings.jsonl"))


def test_fenced_json_findings_are_extractable(tmp_path: Path) -> None:
    target = _target(tmp_path)
    team = runner.SingleAgentTeam(
        program="demo",
        target_path=target,
        goal="Confirm one parser issue.",
        vuln_class="memory-unsafe-parser",
        output_root=tmp_path / "storage",
        hunting_policy="off",
    )
    log_path = tmp_path / "agent.log"
    log_path.write_text(
        """notes
```json
[
  {
    "title": "Unsafe parser boundary",
    "type": "Unsafe parser boundary",
    "severity": "HIGH",
    "file": "src/parser.cc",
    "line": 12,
    "description": "Reachable native parser trusts length."
  }
]
```
""",
        encoding="utf-8",
    )

    findings = team._extract_findings_from_log(log_path, default_agent="single")

    assert len(findings) == 1
    assert findings[0]["type"] == "Unsafe parser boundary"
    assert findings[0]["class_name"] == "memory-unsafe-parser"
