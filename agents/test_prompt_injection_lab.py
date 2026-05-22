from __future__ import annotations

from urllib.error import URLError

import pytest

from agents.prompt_injection_lab import (
    CANARY,
    RunningLab,
    _request_json,
    port_is_open,
    run_lab_eval,
)


def test_prompt_injection_lab_eval_covers_expected_boundaries() -> None:
    with RunningLab(port=0) as lab:
        report = run_lab_eval(lab.base_url)

    assert report["passed"] is True
    assert {item["name"] for item in report["checks"]} == {
        "lab_health",
        "map_inputs_and_tools",
        "direct_injection_leaks_context",
        "indirect_content_controls_summary",
        "decision_pipeline_manipulation",
        "tool_authority_boundary",
        "persistence_canary",
        "output_sink_markdown",
    }


def test_prompt_injection_lab_indirect_content_and_tool_log_are_vulnerable() -> None:
    with RunningLab(port=0) as lab:
        indirect = _request_json(
            "POST",
            f"{lab.base_url}/api/summarize",
            {"page_id": "indirect-canary", "viewer_role": "victim"},
        )
        tool = _request_json(
            "POST",
            f"{lab.base_url}/api/summarize",
            {"page_id": "tool-poison", "viewer_role": "victim"},
        )
        log = _request_json("GET", f"{lab.base_url}/api/tool-log")

    assert CANARY in indirect["summary"]
    assert indirect["source_contains_instruction"] is True
    assert tool["tool_plan"]["tool"] == "edit_page"
    assert log["tool_log"][0]["tool_plan"]["tool"] == "edit_page"


def test_prompt_injection_lab_shutdown_closes_local_port() -> None:
    with RunningLab(port=0) as lab:
        host, port = lab.server.server_address
        assert port_is_open(host, port)

    assert not port_is_open(host, port)
    with pytest.raises(URLError):
        _request_json("GET", f"http://{host}:{port}/health", timeout=0.2)
