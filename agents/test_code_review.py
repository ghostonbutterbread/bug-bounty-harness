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
    assert code_review.SYSTEM_PROMPT in captured["command"][2]
    assert "ReviewAgent" not in captured["command"][2]
    assert captured["kwargs"]["timeout"] == 120
