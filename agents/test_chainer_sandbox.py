from __future__ import annotations

import subprocess

from agents import chainer
from agents.chainer import ChainFinding


def test_codex_develop_chain_uses_scoped_workspace_write(monkeypatch, tmp_path):
    captured = {}
    source_root = tmp_path / "source"
    output_dir = tmp_path / "reports"
    source_root.mkdir()
    output_dir.mkdir()
    (source_root / "demo.py").write_text("print('demo')\n", encoding="utf-8")

    finding = ChainFinding(
        fid="D001",
        title="Demo Chain",
        vuln_class="rce",
        file_ref="demo.py",
        description="demo",
        source="user input",
        sink="exec",
        trust_boundary="network",
        flow_path="input -> exec",
        blocked_reason="needs trigger",
        chain_requirements="trigger",
        impact="code execution",
        remediation="validate",
    )

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="""# D001 - Demo Chain

## Verdict
NEEDS MORE RESEARCH

**Severity:** MEDIUM

## Why It's Dangerous
Demo.

## Exploit Scenario
Needs a trigger.

## PoC Code
```code
Requires prior trigger.
```

## What's Still Missing
Trigger.

## Estimated CVSS
N/A

## Technical Notes
Demo.
""",
            stderr="",
        )

    monkeypatch.setattr(chainer.subprocess, "run", fake_run)

    chainer._codex_develop_chain(finding, source_root, output_dir)

    command = captured["command"]
    assert command[:5] == ["codex", "exec", "-s", "workspace-write", "--skip-git-repo-check"]
    assert "danger-full-access" not in command
    assert "--cd" in command
    assert str(source_root) in command
    assert "--add-dir" in command
    assert str(output_dir.resolve()) in command


def test_markdown_placeholder_poc_is_not_chain_viable() -> None:
    finding = ChainFinding(
        fid="D002",
        title="Placeholder Chain",
        vuln_class="xss",
        file_ref="demo.js",
        description="demo",
        source="input",
        sink="sink",
        trust_boundary="renderer",
        flow_path="input -> sink",
        blocked_reason="needs xss",
        chain_requirements="prior XSS",
        impact="impact",
        remediation="fix",
    )

    parsed = chainer._parse_markdown_report(
        """# D002 - Placeholder Chain

## Verdict
NEEDS MORE RESEARCH

## Exploit Scenario
This requires prior XSS.

## PoC Code
```code
Requires prior XSS to trigger.
```

## What's Still Missing
An entry point.
""",
        finding,
    )

    assert parsed["chain_viable"] is False
    assert parsed["hypothetical_prereq"]
