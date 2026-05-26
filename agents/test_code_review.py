import subprocess

from agents import code_review


def test_review_with_codex_uses_module_system_prompt(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, stdout="review output", stderr="")

    monkeypatch.setattr(code_review.subprocess, "run", fake_run)

    result = code_review.review_with_codex("print('demo')", "demo.py")

    assert result == "review output"
    assert captured["command"][:7] == [
        "codex",
        "exec",
        "-s",
        "read-only",
        "--skip-git-repo-check",
        "--cd",
        str(code_review.Path.cwd()),
    ]
    assert code_review.SYSTEM_PROMPT in captured["command"][7]
    assert "ReviewAgent" not in captured["command"][7]
    assert captured["kwargs"]["timeout"] == 120


def test_review_with_claude_does_not_bypass_permissions(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            command,
            0,
            stdout='{"completion":"review output"}',
            stderr="",
        )

    monkeypatch.setattr(code_review.subprocess, "run", fake_run)

    result = code_review.review_with_claude("print('demo')", "demo.py")

    assert result == "review output"
    assert "--permission-mode" in captured["command"]
    assert "bypassPermissions" not in captured["command"]
    assert "plan" in captured["command"]
    assert captured["kwargs"]["timeout"] == 120


def test_review_with_claude_accepts_plan_mode_result_field(monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout='{"type":"result","subtype":"success","result":"review output"}',
            stderr="",
        )

    monkeypatch.setattr(code_review.subprocess, "run", fake_run)

    assert code_review.review_with_claude("print('demo')", "demo.py") == "review output"
