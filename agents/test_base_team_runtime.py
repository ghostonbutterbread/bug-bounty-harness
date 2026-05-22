"""Focused tests for shared BaseTeam runtime and review CLI sandboxing."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from agents.base_team import AgentSpec, BaseTeam
from agents.base_team.findings import normalize_finding
from agents.base_team.review import run_review_cli
from agents.base_team.runtime import spawn_agent


class DummyTeam(BaseTeam):
    def get_static_profiles(self) -> list[AgentSpec]:
        return []

    def generate_dynamic_from_surfaces(
        self,
        surfaces: list[dict],
        *,
        snapshot_id: str,
    ) -> list[AgentSpec]:
        return []


class _FakeReviewProcess:
    def __init__(self) -> None:
        self.returncode = 0

    def communicate(self, prompt: str, timeout: int | None = None) -> tuple[str, str]:
        self.prompt = prompt
        self.timeout = timeout
        return ('{"tier":"DORMANT","safety_assumption":"trusted input"}', "")


class _FakeSpawnProcess:
    def __init__(self) -> None:
        self.pid = 4242


def test_run_review_cli_uses_read_only_codex_with_cd_flag(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    captured: dict[str, object] = {}
    fake_process = _FakeReviewProcess()

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return fake_process

    with patch("agents.base_team.review.subprocess.Popen", side_effect=fake_popen):
        output = run_review_cli("codex", "review prompt", 7, workdir=target)

    assert output == '{"tier":"DORMANT","safety_assumption":"trusted input"}'
    assert captured["command"] == [
        "codex",
        "exec",
        "-s",
        "read-only",
        "--skip-git-repo-check",
        "--cd",
        str(target),
    ]
    assert "danger-full-access" not in captured["command"]
    assert fake_process.prompt == "review prompt"
    assert fake_process.timeout == 7


def test_normalize_finding_preserves_phased_testing_fields() -> None:
    normalized = normalize_finding(
        {
            "agent": "agent-1",
            "category": "class",
            "class_name": "ipc-bridge",
            "type": "HostRpc branch",
            "file": "src/main.js",
            "line": 10,
            "finding_role": "amplifier",
            "entry_status": "missing",
            "reportability": "hold_for_chain",
            "required_entry_primitives": ["renderer_xss"],
            "chain_handles": ["HostRpc.DownloadService"],
            "unlocked_amplifiers": ["download"],
        },
        default_agent="agent-1",
    )

    assert normalized is not None
    assert normalized["finding_role"] == "amplifier"
    assert normalized["entry_status"] == "missing"
    assert normalized["reportability"] == "hold_for_chain"
    assert normalized["required_entry_primitives"] == ["renderer_xss"]
    assert normalized["chain_handles"] == ["HostRpc.DownloadService"]
    assert normalized["unlocked_amplifiers"] == ["download"]


def test_spawn_agent_uses_read_only_codex_with_prompt_file_stdin(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    team_dir = tmp_path / "team"
    team_dir.mkdir()
    workdir = tmp_path / "repo"
    workdir.mkdir()
    log_path = tmp_path / "logs" / "agent.log"
    traces: list[dict[str, object]] = []
    active_handles: dict[str, _FakeSpawnProcess] = {}
    captured: dict[str, object] = {}
    fake_process = _FakeSpawnProcess()

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return fake_process

    with patch("agents.base_team.runtime.subprocess.Popen", side_effect=fake_popen):
        process = spawn_agent(
            "prompt body",
            "static-review",
            log_path,
            ensure_parent=lambda path: path.parent.mkdir(parents=True, exist_ok=True),
            team_dir=team_dir,
            workdir=workdir,
            target_path=target,
            active_handles=active_handles,
            write_traces=lambda events: traces.extend(events),
            slug=lambda value: value.replace("-", "_"),
        )

    assert process is fake_process
    assert captured["command"][0:2] == ["bash", "-lc"]
    shell_command = str(captured["command"][2])
    assert "codex exec -s read-only --skip-git-repo-check --cd" in shell_command
    assert "danger-full-access" not in shell_command
    assert " < " in shell_command
    assert active_handles["static-review"] is fake_process
    assert "env" in captured["kwargs"]
    assert "CODEX_HOME" not in captured["kwargs"]["env"]
    prompt_path = Path(str(getattr(fake_process, "_bbh_prompt_path")))
    assert prompt_path.is_file()
    assert prompt_path.read_text(encoding="utf-8") == "prompt body\n"
    assert traces[0]["command"] == shell_command

    log_handle = getattr(fake_process, "_bbh_log_handle", None)
    if log_handle is not None:
        log_handle.close()


def test_spawn_agent_drops_inherited_openclaw_codex_home(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CODEX_HOME", "/home/ryushe/.openclaw/agents/main/agent/codex-home")
    target = tmp_path / "target"
    target.mkdir()
    team_dir = tmp_path / "team"
    team_dir.mkdir()
    workdir = tmp_path / "repo"
    workdir.mkdir()
    log_path = tmp_path / "logs" / "agent.log"
    active_handles: dict[str, _FakeSpawnProcess] = {}
    captured: dict[str, object] = {}
    fake_process = _FakeSpawnProcess()

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return fake_process

    with patch("agents.base_team.runtime.subprocess.Popen", side_effect=fake_popen):
        process = spawn_agent(
            "prompt body",
            "static-review",
            log_path,
            ensure_parent=lambda path: path.parent.mkdir(parents=True, exist_ok=True),
            team_dir=team_dir,
            workdir=workdir,
            target_path=target,
            active_handles=active_handles,
            write_traces=lambda events: None,
            slug=lambda value: value.replace("-", "_"),
        )

    assert process is fake_process
    assert "CODEX_HOME" not in captured["kwargs"]["env"]

    log_handle = getattr(fake_process, "_bbh_log_handle", None)
    if log_handle is not None:
        log_handle.close()


def test_spawn_agent_artifact_write_mode_scopes_codex_to_artifact_dir(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    team_dir = tmp_path / "team"
    team_dir.mkdir()
    workdir = tmp_path / "repo"
    workdir.mkdir()
    artifacts = tmp_path / "artifacts"
    log_path = tmp_path / "logs" / "agent.log"
    traces: list[dict[str, object]] = []
    active_handles: dict[str, _FakeSpawnProcess] = {}
    captured: dict[str, object] = {}
    fake_process = _FakeSpawnProcess()

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return fake_process

    with patch("agents.base_team.runtime.subprocess.Popen", side_effect=fake_popen):
        process = spawn_agent(
            "prompt body",
            "poc-writer",
            log_path,
            ensure_parent=lambda path: path.parent.mkdir(parents=True, exist_ok=True),
            team_dir=team_dir,
            workdir=workdir,
            target_path=target,
            active_handles=active_handles,
            write_traces=lambda events: traces.extend(events),
            slug=lambda value: value.replace("-", "_"),
            sandbox_mode="artifact-write",
            writable_artifact_dir=artifacts,
        )

    assert process is fake_process
    shell_command = str(captured["command"][2])
    assert "codex exec -s workspace-write --skip-git-repo-check --cd" in shell_command
    assert str(artifacts) in shell_command
    assert "danger-full-access" not in shell_command
    assert artifacts.is_dir()
    assert traces[0]["command"] == shell_command

    log_handle = getattr(fake_process, "_bbh_log_handle", None)
    if log_handle is not None:
        log_handle.close()


def test_base_team_review_prompt_uses_shared_normalize_relpath(tmp_path: Path) -> None:
    target = tmp_path / "target"
    src = target / "src"
    src.mkdir(parents=True)
    source_file = src / "main.js"
    source_file.write_text("console.log('demo');\n", encoding="utf-8")

    team = DummyTeam(
        "demo",
        "0day_team",
        target,
        output_root=tmp_path / "storage",
        max_agents=1,
        hunting_policy="off",
    )

    prompt = team._build_review_prompt(
        {
            "agent": "dom-xss",
            "category": "class",
            "class_name": "dom-xss",
            "type": "hash reaches html sink",
            "file": "./src\\main.js",
            "line": 1,
            "description": "User-controlled hash reaches an HTML interpretation sink.",
            "severity": "HIGH",
        },
        target,
    )

    assert f"Resolved source path: {source_file}" in prompt
    assert "Source excerpt:" in prompt
    assert "1: console.log('demo');" in prompt
