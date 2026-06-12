from __future__ import annotations

import base64
import json
from pathlib import Path

from agents import hybrid_runner as hybrid


def test_default_config_uses_gpt55_planner_opencode_worker_and_unlimited_requests() -> None:
    config = hybrid.load_config(None)

    assert config.planner.engine == "codex"
    assert config.planner.model == "gpt-5.5"
    assert config.worker.engine == "opencode"
    assert config.worker.model == "deepseek/deepseek-v4-pro"
    assert config.max_requests_per_worker == 0
    assert config.monitor_workers is True


def test_environment_overrides_default_models(monkeypatch) -> None:
    monkeypatch.setenv("BBH_HYBRID_PLANNER_MODEL", "gpt-5.5")
    monkeypatch.setenv("BBH_HYBRID_WORKER_MODEL", "deepseek/deepseek-v4-pro")

    config = hybrid.load_config(None)

    assert config.planner.model == "gpt-5.5"
    assert config.worker.model == "deepseek/deepseek-v4-pro"


def test_plan_classifies_urls_and_writes_worker_packets(tmp_path: Path) -> None:
    source = tmp_path / "params.txt"
    source.write_text(
        "\n".join(
            [
                "https://www.canva.com/search/templates?q=test&category=logos",
                "https://api.canva.com/_spi/presentation/_oembed?url=https%3A%2F%2Fwww.canva.com%2Fdesign%2Fabc%2Fview&format=json",
                "https://docs.canva.tech/auth?next=/api",
                "https://www.canva.com/design?template=.%2FABC12345&type=poster",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "hybrid-run"

    plan = hybrid.build_plan(
        program="canva",
        objective="Hybrid deep dive recon into params.txt",
        input_path=source,
        output_root=output,
        config=hybrid.HybridConfig(worker_limit=8),
    )

    lanes = {packet["lane"] for packet in plan["worker_packets"]}
    assert {"xss", "ssrf", "api", "auth", "object"} <= lanes
    assert plan["records"] == 4
    assert plan["clusters"] == 4
    assert Path(plan["planner_packet"]).exists()
    assert (output / "plan.json").exists()
    assert (output / "monitor_state.json").exists()
    assert "max_requests_per_worker" in (output / "config.resolved.json").read_text(encoding="utf-8")

    packet_prompt = (output / "worker_packets" / "W001-xss.md").read_text(encoding="utf-8")
    assert "0 means no arbitrary hard cap" in packet_prompt
    assert "challenge/fingerprint/browser-only cases only" in packet_prompt
    assert "These artifacts are mandatory" in packet_prompt
    assert "Auth/session logging rule" in packet_prompt
    assert "cookie/header names and counts" in packet_prompt
    assert "framework/JS/API clues" in packet_prompt
    assert "XSS deep default" in packet_prompt
    assert "source-to-sink mapping before payload volume" in packet_prompt
    assert "payload family, source, sink/context" in packet_prompt


def test_cli_overrides_worker_model_and_request_cap(tmp_path: Path, capsys) -> None:
    source = tmp_path / "urls.txt"
    source.write_text("https://www.canva.com/search/templates?q=test\n", encoding="utf-8")
    output = tmp_path / "out"

    rc = hybrid.main(
        [
            "deep-dive",
            "recon",
            "canva",
            "--input",
            str(source),
            "--output-dir",
            str(output),
            "--worker",
            "opencode",
            "--worker-model",
            "deepseek/deepseek-v4-pro",
            "--planner-model",
            "gpt-5.5",
            "--max-requests-per-worker",
            "25",
            "--worker-limit",
            "1",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 0
    assert payload["execute"] is False
    assert payload["worker"]["model"] == "deepseek/deepseek-v4-pro"
    assert payload["max_requests_per_worker"] == 25
    assert payload["worker_packets"] == 1


def test_command_for_supported_engines_quotes_prompt_and_model(tmp_path: Path) -> None:
    prompt = tmp_path / "packet file.md"
    prompt.write_text("packet", encoding="utf-8")
    workdir = tmp_path / "work dir"

    opencode = hybrid.command_for_engine(
        hybrid.EngineConfig("opencode", "deepseek/deepseek-v4-pro"),
        prompt_path=prompt,
        workdir=workdir,
        title="Worker 1",
    )
    codex = hybrid.command_for_engine(
        hybrid.EngineConfig("codex", "gpt-5.5"),
        prompt_path=prompt,
        workdir=workdir,
        title="Planner",
    )

    assert "opencode run" in opencode
    assert "--model deepseek/deepseek-v4-pro" in opencode
    assert "--file" in opencode
    assert "codex exec" in codex
    assert "--model gpt-5.5" in codex


def test_execute_plan_updates_monitor_state_and_runs_planner_after_workers(tmp_path: Path) -> None:
    source = tmp_path / "urls.txt"
    source.write_text("https://www.canva.com/search/templates?q=test\n", encoding="utf-8")
    output = tmp_path / "run"
    config = hybrid.HybridConfig(
        planner=hybrid.EngineConfig(
            "opencode",
            "planner-test",
            command_template="python3 -c \"from pathlib import Path; Path('planner-ran').write_text('ok')\"",
        ),
        worker=hybrid.EngineConfig(
            "opencode",
            "worker-test",
            command_template="python3 -c \"from pathlib import Path; Path('summary.md').write_text('ok')\"",
        ),
        worker_limit=1,
    )
    plan = hybrid.build_plan(
        program="canva",
        objective="test",
        input_path=source,
        output_root=output,
        config=config,
    )

    statuses = hybrid.execute_plan(plan, include_planner=True)
    monitor = json.loads((output / "monitor_state.json").read_text(encoding="utf-8"))

    assert statuses["W001-xss"] == "completed"
    assert statuses["planner"] == "completed"
    assert monitor["worker_status"]["W001-xss"] == "completed"
    assert monitor["worker_status"]["planner"] == "completed"
    assert (output / "workers" / "W001-xss" / "summary.md").exists()
    assert (output / "planner-ran").exists()


def test_execute_plan_redacts_sensitive_worker_log_output(tmp_path: Path) -> None:
    source = tmp_path / "urls.txt"
    source.write_text("https://www.canva.com/search/templates?q=test\n", encoding="utf-8")
    output = tmp_path / "run"
    config = hybrid.HybridConfig(
        worker=hybrid.EngineConfig(
            "opencode",
            "worker-test",
            command_template=(
                "python3 -c \"print('location: https://example.test/cb?nonce=abcdef1234567890'); "
                "print('cookie: session=secret-cookie; theme=blue'); "
                "print('set-cookie: SESSION=secret; Path=/'); "
                "print('Authorization: Bearer secret-token-value')\""
            ),
        ),
        worker_limit=1,
    )
    plan = hybrid.build_plan(
        program="canva",
        objective="test",
        input_path=source,
        output_root=output,
        config=config,
    )

    statuses = hybrid.execute_plan(plan)
    log_text = (output / "logs" / "w001-xss.log").read_text(encoding="utf-8")

    assert statuses["W001-xss"] == "completed"
    assert "nonce=REDACTED" in log_text
    assert "cookie: REDACTED" in log_text
    assert "set-cookie: REDACTED" in log_text
    assert "Authorization: Bearer REDACTED" in log_text
    assert "abcdef1234567890" not in log_text
    assert "secret-cookie" not in log_text
    assert "SESSION=secret" not in log_text
    assert "secret-token-value" not in log_text


def test_execute_plan_redacts_sensitive_worker_artifacts(tmp_path: Path) -> None:
    source = tmp_path / "urls.txt"
    source.write_text("https://docs.canva.tech/auth?next=/api\n", encoding="utf-8")
    output = tmp_path / "run"
    artifact_payload = (
        '{"req_headers":{"Cookie":"TOKEN=testvalue123"},'
        '"resp_headers_of_interest":["set-cookie: TOKEN=(clear)",'
        '"set-cookie: NONCE=abcdef1234567890; HttpOnly"],'
        '"url":"https://docs.canva.tech/auth?next=/api&nonce=abcdef1234567890"}\n'
    )
    artifact_b64 = base64.b64encode(artifact_payload.encode("utf-8")).decode("ascii")
    config = hybrid.HybridConfig(
        worker=hybrid.EngineConfig(
            "opencode",
            "worker-test",
            command_template=(
                "python3 -c "
                + repr(
                    "import base64; "
                    "from pathlib import Path; "
                    f"Path('attempts.jsonl').write_bytes(base64.b64decode('{artifact_b64}'))"
                )
            ),
        ),
        worker_limit=1,
    )
    plan = hybrid.build_plan(
        program="canva",
        objective="test",
        input_path=source,
        output_root=output,
        config=config,
    )

    statuses = hybrid.execute_plan(plan)
    artifact_path = next((output / "workers").rglob("attempts.jsonl"))
    artifact_text = artifact_path.read_text(encoding="utf-8")

    assert set(statuses.values()) == {"completed"}
    assert '"Cookie":"REDACTED"' in artifact_text
    assert "set-cookie: REDACTED" in artifact_text
    assert "nonce=REDACTED" in artifact_text
    assert "testvalue123" not in artifact_text
    assert "abcdef1234567890" not in artifact_text
